// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! Cimiento criptográfico del proveedor OIDC de Bachué (veta mindalá #1, **rebanada 1**).
//!
//! Un proveedor OIDC firma el `id_token` con una clave **asimétrica** para que cualquier
//! Relying Party lo verifique contra la clave pública publicada en el **JWKS** —bachue-sesion
//! firma las cookies con HMAC (simétrico), que no sirve para eso—. Aquí vive esa pieza y solo
//! esa: emitir un `id_token` (JWT) firmado **ES256 (ECDSA P-256)** y publicar la clave pública
//! como **JWK/JWKS**. Se elige ES256 (no RS256) por coherencia: es la curva y la dep
//! (`p256` de RustCrypto) que ya usa `bachue-passkey-es256`.
//!
//! **PURO e INERTE**: no toca axum, ni la base de datos, ni ninguna ruta viva. Las rutas del
//! provider (`/.well-known/openid-configuration`, `/jwks`, `/authorize`, `/token`) son la
//! rebanada siguiente y NO se exponen hasta que el diseño se cierre y pase el concilio (bachue
//! es repo sensible, D25). Mientras tanto este crate se puede mergear sin abrir nada.
//!
//! Diseño del provider completo (fases): ver el estudio
//! `conocimiento/proyectos/mindala/estudios/bachue-iam-oidc.md`.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
// p256 0.14: `to_encoded_point` sobre AffinePoint vive en el trait `sec1::ToSec1Point`.
use p256::elliptic_curve::sec1::ToSec1Point;
use sha2::{Digest, Sha256};

/// RNG del sistema para generar claves con el stack p256 0.14 / crypto-common 0.2.2.
/// Reenvía a `getrandom` (el CSPRNG del SO, la misma fuente que usa `tunjo`): el ecosistema
/// `rand` aún no expone un `OsRng` para `rand_core` 0.10, así que se adapta `getrandom`
/// directamente. CERO lógica criptográfica propia — solo bytes del sistema operativo.
struct RngDelSo;
impl p256::elliptic_curve::rand_core::TryRng for RngDelSo {
    type Error = getrandom::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst)
    }
}
impl p256::elliptic_curve::rand_core::TryCryptoRng for RngDelSo {}

/// Alfabeto base64url (RFC 4648 §5), sin relleno — el que exige JOSE (RFC 7515).
const ALFA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Codifica en base64url SIN relleno.
#[must_use]
pub fn base64url(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for trozo in data.chunks(3) {
        let b0 = u32::from(trozo[0]);
        let b1 = u32::from(*trozo.get(1).unwrap_or(&0));
        let b2 = u32::from(*trozo.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALFA[(n >> 18 & 63) as usize] as char);
        out.push(ALFA[(n >> 12 & 63) as usize] as char);
        if trozo.len() > 1 {
            out.push(ALFA[(n >> 6 & 63) as usize] as char);
        }
        if trozo.len() > 2 {
            out.push(ALFA[(n & 63) as usize] as char);
        }
    }
    out
}

/// Huella corta de una clave pública para usar como `kid`: los primeros 8 bytes de
/// `SHA-256(punto SEC1)` en hex. Estable por clave y opaca al RP (solo la empareja con el
/// header del token).
fn huella(vk: &VerifyingKey) -> String {
    let punto = vk.as_affine().to_sec1_point(false);
    let h = Sha256::digest(punto.as_bytes());
    h[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Decodifica base64url SIN relleno. `None` si hay un carácter fuera del alfabeto.
fn base64url_dec(s: &str) -> Option<Vec<u8>> {
    let mut acc = 0u32;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for c in s.bytes() {
        let v = ALFA.iter().position(|&a| a == c)? as u32;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

/// Verifica la firma **ES256** de un JWT compacto con una clave pública y devuelve sus
/// claims; `None` si la firma no valida o el formato es inválido. NO comprueba `exp`/`iss`/
/// `aud` —eso es política del receptor (lo hace el llamador)—. Sirve al RP para verificar el
/// `id_token`, y al IdP para verificar su propio `access_token`.
#[must_use]
pub fn verificar_es256(token: &str, vk: &VerifyingKey) -> Option<serde_json::Value> {
    let mut it = token.split('.');
    let (h, p, s) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() {
        return None; // un JWT compacto tiene EXACTAMENTE tres partes
    }
    let firma = Signature::from_slice(&base64url_dec(s)?).ok()?;
    vk.verify(format!("{h}.{p}").as_bytes(), &firma).ok()?;
    serde_json::from_slice(&base64url_dec(p)?).ok()
}

/// Valida un `id_token` **como DEBE hacerlo un Relying Party**: firma **y** `aud` **y** `iss`
/// **y** `exp`. Devuelve los claims solo si las cuatro pasan; `None` si cualquiera falla.
///
/// Existe porque [`verificar_es256`] comprueba SOLO la firma —a propósito—, y eso deja al RP
/// la parte más fácil de olvidar, que es justo la peligrosa. El incidente OpenAI→Hugging Face
/// (2026) fue en su núcleo una **confusión de audiencia**: una credencial emitida para una
/// audiencia fue aceptada por otra que no validó `aud`. Un `id_token` de bachue lleva
/// `aud = client_id` del RP; si un RP acepta un token sin comprobar que ese `aud` es el SUYO,
/// cualquier otro RP del mismo IdP puede reusar su token contra él (CWE-863). Este helper cierra
/// eso por construcción: el **primer RP real que integre bachue lo llama** en vez de
/// reimplementar la validación y arriesgarse a omitir el `aud`.
///
/// `ahora_unix` (segundos epoch) se pasa —no se lee un reloj oculto— para que la caducidad sea
/// comprobable en pruebas (mismo estilo que [`claims_id_token`]).
///
/// LÍMITE CONSCIENTE (el concilio lo señaló, opus+sonnet+fable): `aud` se compara como STRING.
/// OIDC permite `aud` multivaluado (array); aquí un `aud` array cae en `as_str() == None` y el
/// token se RECHAZA (falla cerrado, D20). Hoy es correcto —`claims_id_token` siempre emite `aud`
/// string—, pero el día que un RP necesite audiencia múltiple, ESTE helper hay que ampliarlo
/// (aceptar que `aud_esperado` esté CONTENIDO en el array, y entonces exigir `azp`); no es un
/// descubrimiento para la integración, es una decisión a tomar aquí.
#[must_use]
pub fn validar_id_token(
    token: &str,
    vk: &VerifyingKey,
    aud_esperado: &str,
    iss_esperado: &str,
    ahora_unix: u64,
) -> Option<serde_json::Value> {
    let claims = verificar_es256(token, vk)?; // 1) firma
    // 2) audiencia: el bug del incidente. El `aud` del token DEBE ser este RP.
    if claims.get("aud").and_then(serde_json::Value::as_str) != Some(aud_esperado) {
        return None;
    }
    // 3) emisor: el token DEBE venir de nuestro IdP, no de otro que comparta formato.
    if claims.get("iss").and_then(serde_json::Value::as_str) != Some(iss_esperado) {
        return None;
    }
    // 4) caducidad: un token expirado no vale (sin `exp` tampoco se acepta, D20).
    let exp = claims.get("exp").and_then(serde_json::Value::as_u64)?;
    if ahora_unix >= exp {
        return None;
    }
    Some(claims)
}

/// La clave de firma del EMISOR (el IdP). Guarda el escalar privado P-256 y el `kid` que
/// identifica la clave en el JWKS (para la rotación: varias claves conviven, el `kid` del
/// header dice cuál verificar).
pub struct ClaveEmisor {
    sk: SigningKey,
    kid: String,
}

impl ClaveEmisor {
    /// Genera una clave de emisor nueva con el RNG del sistema.
    #[must_use]
    pub fn generar(kid: impl Into<String>) -> Self {
        use p256::elliptic_curve::Generate;
        // p256 0.14 / ecdsa 0.17: `random` quedó deprecated; el idioma es el trait
        // `Generate` con un `TryCryptoRng`. Si el RNG del SO falla, generar una clave es
        // irrecuperable, así que se propaga con expect (no se inventa entropía dudosa).
        let sk = SigningKey::try_generate_from_rng(&mut RngDelSo).expect("el RNG del sistema falló");
        ClaveEmisor { sk, kid: kid.into() }
    }

    /// Reconstruye la clave desde su escalar de 32 bytes (persistencia). `None` si no es un
    /// escalar válido. Se guarda el escalar crudo, no PKCS#8, para no traer esa feature.
    #[must_use]
    pub fn desde_escalar(bytes: &[u8], kid: impl Into<String>) -> Option<Self> {
        SigningKey::from_slice(bytes).ok().map(|sk| ClaveEmisor { sk, kid: kid.into() })
    }

    /// DERIVA la clave del emisor de un `secreto` maestro con una `etiqueta` de DOMINIO
    /// (p.ej. el `BACHUE_IDP_SECRETO`, etiqueta `"bachue-idp/oidc-firma-v1"`). Determinista:
    /// el mismo secreto reproduce la MISMA clave al rearrancar, sin gestor de claves aparte.
    /// Y como NO vive en la BD, el robo de la BD sin el secreto no da la clave de firma
    /// —el mismo modelo que el TOTP en reposo de bachue-idp—. El `kid` es la HUELLA de la
    /// clave pública, así rota solo si la clave cambia. El escalar sale de `SHA-256(secreto ‖
    /// etiqueta ‖ contador)`, subiendo el contador en el caso astronómico de un escalar
    /// inválido (>= orden de la curva, ~2⁻¹²⁸).
    #[must_use]
    pub fn derivar(secreto: &[u8], etiqueta: &str) -> Self {
        for c in 0u8..=255 {
            let mut h = Sha256::new();
            h.update(secreto);
            h.update(etiqueta.as_bytes());
            h.update([c]);
            let escalar = h.finalize();
            if let Ok(sk) = SigningKey::from_slice(&escalar) {
                let kid = huella(sk.verifying_key());
                return ClaveEmisor { sk, kid };
            }
        }
        // Inalcanzable en la práctica: la fracción de escalares inválidos es ~2⁻¹²⁸, así que
        // 256 contadores no se agotan jamás. Se falla ruidoso (D20) en vez de una clave falsa.
        panic!("bachue-oidc::derivar: no salió un escalar P-256 válido en 256 intentos");
    }

    /// El escalar privado de 32 bytes, para persistir la clave (¡es secreto!).
    #[must_use]
    pub fn escalar(&self) -> [u8; 32] {
        self.sk.to_bytes().into()
    }

    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// La clave pública, para verificar (y para el JWK).
    #[must_use]
    pub fn verificador(&self) -> VerifyingKey {
        *self.sk.verifying_key()
    }

    /// La clave pública como **JWK** (RFC 7517/7518): `kty=EC`, `crv=P-256`, `x`/`y` en
    /// base64url, `use=sig`, `alg=ES256`, y el `kid`.
    #[must_use]
    pub fn jwk(&self) -> serde_json::Value {
        let punto = self.sk.verifying_key().as_affine().to_sec1_point(false);
        let bytes = punto.as_bytes(); // 0x04 ‖ x(32) ‖ y(32)
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64url(&bytes[1..33]),
            "y": base64url(&bytes[33..65]),
            "use": "sig",
            "alg": "ES256",
            "kid": self.kid,
        })
    }

    /// El **JWKS** que sirve el endpoint `/jwks`: `{ "keys": [ <jwk> ] }`. Es una lista para
    /// que la rotación pueda publicar la clave nueva y la anterior a la vez.
    #[must_use]
    pub fn jwks(&self) -> serde_json::Value {
        serde_json::json!({ "keys": [self.jwk()] })
    }

    /// Firma un `id_token` (JWT compacto, RFC 7519) con los `claims` dados. El header lleva
    /// `alg=ES256`, `typ=JWT` y el `kid`. La firma ES256 es la forma **cruda `r‖s`** de 64
    /// bytes que exige JWS (RFC 7518 §3.4), no DER. Infalible: `Value` se serializa siempre.
    #[must_use]
    pub fn firmar_id_token(&self, claims: &serde_json::Value) -> String {
        let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid });
        let entrada = format!(
            "{}.{}",
            base64url(header.to_string().as_bytes()),
            base64url(claims.to_string().as_bytes())
        );
        let firma: Signature = self.sk.sign(entrada.as_bytes());
        format!("{entrada}.{}", base64url(&firma.to_bytes()))
    }
}

/// Un `code`/token aleatorio de 256 bits en base64url (para el authorization_code y afines):
/// imposible de adivinar, url-safe. Usa el RNG del sistema.
#[must_use]
pub fn codigo_aleatorio() -> String {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("el RNG del sistema falló");
    base64url(&b)
}

/// Verifica un desafío **PKCE S256** (RFC 7636 §4.6): el `code_challenge` que el cliente
/// presentó en `/authorize` debe ser `base64url(SHA-256(code_verifier))` del `code_verifier`
/// que presenta en `/token`. Cierra el robo del `code` (quien intercepta el código sin el
/// verifier no puede canjearlo). El `challenge` no es secreto (viajó en la URL), así que la
/// comparación normal de cadenas no filtra nada útil: forjar un verifier que case es romper
/// la preimagen de SHA-256, no un ataque de tiempo.
#[must_use]
pub fn pkce_s256_ok(code_verifier: &str, code_challenge: &str) -> bool {
    base64url(&Sha256::digest(code_verifier.as_bytes())) == code_challenge
}

/// Construye los `claims` estándar de un `id_token` OIDC. `ahora` y `dur` en segundos epoch;
/// `nonce` opcional (se incluye si el `authorize` lo trajo, RFC OIDC §2). El emisor (`iss`),
/// el sujeto (`sub`) y la audiencia (`aud`, el `client_id`) los pone el llamador.
#[must_use]
pub fn claims_id_token(
    iss: &str,
    sub: &str,
    aud: &str,
    ahora: i64,
    dur: i64,
    nonce: Option<&str>,
) -> serde_json::Value {
    let mut c = serde_json::json!({
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "iat": ahora,
        "exp": ahora + dur,
    });
    if let Some(n) = nonce {
        c["nonce"] = serde_json::Value::String(n.to_string());
    }
    c
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // `base64url_dec` y `verificar_es256` (verificación como un RP) están promovidos al módulo
    // y llegan por `use super::*`.

    #[test]
    fn base64url_va_y_vuelve_sin_relleno() {
        for muestra in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar", &[0xff, 0x00, 0x80]] {
            let e = base64url(muestra);
            assert!(!e.contains('='), "sin relleno");
            assert!(!e.contains('+') && !e.contains('/'), "alfabeto url-safe");
            assert_eq!(base64url_dec(&e).unwrap(), muestra, "va y vuelve");
        }
    }

    #[test]
    fn id_token_firmado_lo_verifica_un_rp_con_la_clave_publica() {
        let emisor = ClaveEmisor::generar("k1");
        let claims = claims_id_token("https://idp.xiliux", "usuario-7", "app-abc", 1_700_000_000, 3600, Some("n0nce"));
        let token = emisor.firmar_id_token(&claims);

        // Un RP con la clave pública verifica y recupera los claims.
        let recuperado = verificar_es256(&token, &emisor.verificador()).expect("el id_token verifica");
        assert_eq!(recuperado["iss"], "https://idp.xiliux");
        assert_eq!(recuperado["sub"], "usuario-7");
        assert_eq!(recuperado["aud"], "app-abc");
        assert_eq!(recuperado["nonce"], "n0nce");
        assert_eq!(recuperado["exp"], 1_700_003_600i64);

        // El header lleva alg/typ/kid correctos.
        let header: serde_json::Value =
            serde_json::from_slice(&base64url_dec(token.split('.').next().unwrap()).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], "k1");
    }

    #[test]
    fn el_jwk_publicado_es_la_clave_del_emisor_y_cierra_el_lazo() {
        // El JWK del JWKS tiene que ser LA clave con la que se firmó: se reconstruye la clave
        // pública desde (x,y) del JWK y con ella se verifica un token del emisor (cierre del
        // lazo, como en chuspa). Si el JWK publicara otra clave, un RP no podría verificar.
        let emisor = ClaveEmisor::generar("rot-2026");
        let jwk = emisor.jwk();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["kid"], "rot-2026");

        let x = base64url_dec(jwk["x"].as_str().unwrap()).unwrap();
        let y = base64url_dec(jwk["y"].as_str().unwrap()).unwrap();
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
        let mut sec1 = vec![0x04u8];
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        let vk_del_jwk = VerifyingKey::from_sec1_bytes(&sec1).expect("(x,y) es un punto P-256");

        let token = emisor.firmar_id_token(&serde_json::json!({"sub": "s"}));
        assert!(verificar_es256(&token, &vk_del_jwk).is_some(), "el JWK publicado ES la clave de firma");

        // Y el kid del JWKS coincide con el del header del token.
        let jwks = emisor.jwks();
        assert_eq!(jwks["keys"][0]["kid"], "rot-2026");
    }

    #[test]
    fn caso_rojo_payload_manipulado_no_verifica() {
        // Discriminación (D33): si se altera el payload manteniendo la firma, la verificación
        // DEBE fallar. Sin esto, `firmar_id_token` podría no firmar de verdad y nadie lo notaría.
        let emisor = ClaveEmisor::generar("k1");
        let token = emisor.firmar_id_token(&claims_id_token("iss", "victima", "app", 1000, 60, None));
        let partes: Vec<&str> = token.split('.').collect();

        // Reemplaza el payload por otro ("sub":"admin") y conserva la firma original.
        let payload_falso = base64url(serde_json::json!({"iss":"iss","sub":"admin","aud":"app","iat":1000,"exp":1060}).to_string().as_bytes());
        let token_forjado = format!("{}.{}.{}", partes[0], payload_falso, partes[2]);
        assert!(
            verificar_es256(&token_forjado, &emisor.verificador()).is_none(),
            "un payload manipulado NO verifica: la firma cubre el payload"
        );
    }

    // Clase «bypass de verificación de firma» (lección SAML/JWT, PortSwigger «the hacker
    // always wins»; idea mindalá). bachue la vence POR CONSTRUCCIÓN —`verificar_es256` no
    // despacha por el `alg` del header, siempre exige firma ES256—; estas dos pruebas FIJAN
    // el invariante: si un refactor introdujera despacho por `alg`, se ponen rojas.
    #[test]
    fn alg_none_no_verifica() {
        let emisor = ClaveEmisor::generar("k1");
        let h = base64url(br#"{"alg":"none","typ":"JWT"}"#);
        let p = base64url(br#"{"sub":"admin"}"#);
        let token = format!("{h}.{p}."); // alg:none: sin firma
        assert!(
            verificar_es256(&token, &emisor.verificador()).is_none(),
            "alg:none sin firma NO verifica"
        );
    }

    /// HMAC-SHA256 (RFC 2104) con el `sha2` ya presente — evita una dep solo para la prueba.
    /// Reproduce el secreto del vector de confusión: la clave pública como clave MAC.
    fn hmac_sha256(clave: &[u8], msg: &[u8]) -> [u8; 32] {
        let mut k = [0u8; 64];
        if clave.len() > 64 {
            k[..32].copy_from_slice(&Sha256::digest(clave));
        } else {
            k[..clave.len()].copy_from_slice(clave);
        }
        let mut inner = Sha256::new();
        inner.update(k.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
        inner.update(msg);
        let hi = inner.finalize();
        let mut outer = Sha256::new();
        outer.update(k.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>());
        outer.update(hi);
        outer.finalize().into()
    }

    #[test]
    fn confusion_de_alg_no_verifica() {
        // Confusión de algoritmo (SAML/JWT, familia CVE-2015-9235): el atacante afirma HS256
        // y firma con la clave PÚBLICA (bytes SEC1) como secreto HMAC. Esta prueba EJERCE el
        // vector: si un refactor añadiera una rama HS256 que compara contra
        // HMAC-SHA256(clave_pública, "{h}.{p}"), la aceptaría y esta prueba se pondría ROJA.
        // Hoy `verificar_es256` verifica siempre ES256 e ignora `alg`, así que el HMAC no es
        // firma ES256 válida y se rechaza. [Antes metía 64 bytes de basura → pasaba VACUA sin
        // discriminar (D33); lo cazó el concilio 2026-09-28 (sonnet+fable) mutando a HS256 real.]
        let emisor = ClaveEmisor::generar("k1");
        let vk = emisor.verificador();
        let sec1 = vk.as_affine().to_sec1_point(false); // el secreto que usaría el refactor vulnerable
        let h = base64url(br#"{"alg":"HS256","typ":"JWT"}"#);
        let p = base64url(br#"{"sub":"admin"}"#);
        let mac = hmac_sha256(sec1.as_bytes(), format!("{h}.{p}").as_bytes());
        let token = format!("{h}.{p}.{}", base64url(&mac));
        assert!(
            verificar_es256(&token, &vk).is_none(),
            "confusión de alg (HMAC con la clave pública) NO verifica"
        );
    }

    #[test]
    fn validar_id_token_exige_aud_iss_y_exp_no_solo_firma() {
        // El arreglo del incidente OpenAI→Hugging Face (confusión de audiencia). Cada caso rojo
        // falla por SU vía real, no por el arnés (D33): mismo emisor, mismo token bien firmado,
        // y lo único que cambia es lo que el RP debe rechazar.
        let idp = ClaveEmisor::generar("k1");
        let iss = "https://idp.xiliux";
        let ahora = 1_700_000_000u64;
        let token = idp.firmar_id_token(&claims_id_token(iss, "usuario-7", "app-mia", ahora as i64, 3600, None));

        // VERDE: firma buena + aud propio + iss propio + no caducado → entra.
        assert!(
            validar_id_token(&token, &idp.verificador(), "app-mia", iss, ahora + 10).is_some(),
            "un id_token válido para este RP DEBE entrar"
        );

        // ROJO 1 — audiencia ajena: el token es de "app-mia", otro RP ("app-otra") lo rechaza.
        // ESTE es el bug del incidente; sin la comprobación de `aud`, pasaría.
        assert!(
            validar_id_token(&token, &idp.verificador(), "app-otra", iss, ahora + 10).is_none(),
            "un token emitido para OTRO RP no puede entrar aquí (confusión de audiencia)"
        );

        // ROJO 2 — emisor distinto.
        assert!(
            validar_id_token(&token, &idp.verificador(), "app-mia", "https://idp.impostor", ahora + 10).is_none(),
            "un token de otro emisor no entra"
        );

        // ROJO 3 — caducado (exp = ahora+3600; se comprueba en ahora+4000).
        assert!(
            validar_id_token(&token, &idp.verificador(), "app-mia", iss, ahora + 4000).is_none(),
            "un token caducado no entra"
        );

        // ROJO 4 — firma de otro IdP: aud/iss correctos pero clave equivocada.
        let otro_idp = ClaveEmisor::generar("k2");
        assert!(
            validar_id_token(&token, &otro_idp.verificador(), "app-mia", iss, ahora + 10).is_none(),
            "una firma que no es de nuestra clave no entra, aunque los claims cuadren"
        );
    }

    #[test]
    fn pkce_s256_contra_el_vector_del_rfc_7636() {
        // Vector oficial del RFC 7636 Apéndice B (artefacto, no aguja inventada, D33).
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(pkce_s256_ok(verifier, challenge), "el verifier del RFC casa su challenge");
        // CASO ROJO: un verifier distinto NO casa (si casara, PKCE no protegería nada).
        assert!(!pkce_s256_ok("otro-verifier-cualquiera", challenge));
        // Y un challenge manipulado tampoco.
        assert!(!pkce_s256_ok(verifier, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cX"));
    }

    #[test]
    fn derivar_es_determinista_y_separada_por_dominio() {
        let secreto = b"un-secreto-maestro-de-al-menos-32-bytes!!";
        // Mismo secreto + etiqueta → MISMA clave (mismo kid, misma firma verificable).
        let a = ClaveEmisor::derivar(secreto, "bachue-idp/oidc-firma-v1");
        let b = ClaveEmisor::derivar(secreto, "bachue-idp/oidc-firma-v1");
        assert_eq!(a.kid(), b.kid(), "determinista: mismo kid");
        assert_eq!(a.escalar(), b.escalar(), "determinista: mismo escalar");

        // Etiqueta distinta → clave DISTINTA (dominio-separada): la de OIDC no es la de sesión.
        let otra = ClaveEmisor::derivar(secreto, "bachue-idp/otra-cosa");
        assert_ne!(a.escalar(), otra.escalar(), "etiqueta distinta ⇒ clave distinta");

        // Secreto distinto → clave distinta.
        let z = ClaveEmisor::derivar(b"OTRO-secreto-maestro-de-32-bytes-abcdef!", "bachue-idp/oidc-firma-v1");
        assert_ne!(a.escalar(), z.escalar(), "secreto distinto ⇒ clave distinta");

        // El kid es la huella de la clave publicada en el JWK.
        assert_eq!(a.jwk()["kid"], a.kid());
    }

    #[test]
    fn la_clave_persiste_por_su_escalar() {
        // Guardar/cargar por el escalar reproduce la MISMA clave (misma firma verificable).
        let emisor = ClaveEmisor::generar("k1");
        let escalar = emisor.escalar();
        let cargada = ClaveEmisor::desde_escalar(&escalar, "k1").expect("escalar válido");
        let token = cargada.firmar_id_token(&serde_json::json!({"sub": "s"}));
        assert!(verificar_es256(&token, &emisor.verificador()).is_some(), "la clave cargada es la misma");
    }
}
