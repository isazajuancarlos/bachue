// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **Banco E2E de passkeys (F3, directiva 28).** Arranca el BINARIO real del IdP con las
//! passkeys ACTIVADAS y le habla por HTTP como lo haría el navegador, usando un AUTENTICADOR
//! DE SOFTWARE (un par ES256 real que firma los retos y arma el attestationObject/assertion
//! byte a byte). Prueba el camino SERVIDOR entero de las dos ceremonias:
//! endpoints → reto de un solo uso en BD → verificación cripto → persistencia → sesión.
//!
//! Lo que ESTE banco NO prueba, y por qué: el JavaScript del navegador (el puente a
//! `navigator.credentials`) y el DIBUJO de la pantalla. Eso exige un navegador de verdad; se
//! verifica con Chromium + autenticador virtual (ver `tests/README-e2e-navegador.md`). Aquí el
//! "navegador" es este arnés, que produce exactamente los mismos bytes.
//!
//! Discrimina (D33): el ciclo feliz es el CONTROL POSITIVO —si no abriera, un servidor que
//! dijera "no" a todo pasaría los rojos—; cada rojo cambia UNA cosa del feliz y debe fallar por
//! SU vía (reto gastado, credencial ajena, origen ajeno, sin sesión, contador que no avanza).

use std::process::{Child, Command};
use std::time::Duration;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToSec1Point; // p256 0.14: to_encoded_point sobre AffinePoint
use p256::elliptic_curve::Generate; // p256 0.14: key-gen vía el trait Generate
use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// La contraseña de las cuentas de prueba. El enrolamiento/borrado de passkey exige esta
/// misma como step-up (igual que el 2FA), así que el ciclo feliz la manda.
const CLAVE: &str = "contrasena-larga-y-no-predecible-1";
/// Secreto compartido de `/seguridad/2fa/reset` en las pruebas (≥ 32 bytes, como en prod).
const SECRETO_APROV: &str = "secreto-de-aprovisionamiento-de-prueba-32!!";

// ───────────────────────── arnés ─────────────────────────

/// Arranca el binario con passkeys ACTIVADAS (RP ID `localhost`, origen `http://localhost:PORT`)
/// y el registro abierto (para crear la cuenta de prueba por `/registrarse`). Devuelve el
/// proceso, la URL base, la ruta de la BD, el `origen` y el `rp_id`.
async fn arrancar() -> (Child, String, std::path::PathBuf, String, String) {
    let puerto = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let unico = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    );
    let bd = std::env::temp_dir().join(format!("bachue-idp-passkey-{unico}.db"));
    let rp_id = "localhost".to_string();
    let origen = format!("http://localhost:{puerto}");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bachue-idp"));
    cmd.env("BACHUE_IDP_SECRETO", "secreto-de-prueba-de-32-bytes-minimo!!")
        .env("BACHUE_IDP_PUERTO", puerto.to_string())
        .env("BACHUE_IDP_DB", format!("sqlite://{}", bd.display()))
        .env("BACHUE_IDP_INSEGURO", "1")
        .env("BACHUE_IDP_REGISTRO_ABIERTO", "1")
        .env("BACHUE_IDP_RP_ID", &rp_id)
        .env("BACHUE_IDP_PASSKEY_ORIGEN", &origen)
        // Habilita el reset de operador (`/seguridad/2fa/reset`) para el caso rojo de que la
        // remediación por compromiso borra las passkeys.
        .env("BACHUE_IDP_APROVISIONAR_SECRETO", SECRETO_APROV)
        .env("RUST_LOG", "warn");
    let hijo = cmd.spawn().expect("arranca el binario");

    let base = format!("http://127.0.0.1:{puerto}");
    let sonda = Client::new();
    let fin = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if sonda.get(format!("{base}/entrar")).send().await.map(|r| r.status().is_success()).unwrap_or(false) {
            break;
        }
        assert!(std::time::Instant::now() < fin, "el IdP no arrancó a tiempo");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    (hijo, base, bd, origen, rp_id)
}

/// Arranca el binario SIN RP ID (passkeys desactivadas), para probar el 404 de la capa apagada.
async fn arrancar_sin_passkey() -> (Child, String, std::path::PathBuf) {
    let puerto = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let unico = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    );
    let bd = std::env::temp_dir().join(format!("bachue-idp-nopk-{unico}.db"));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bachue-idp"));
    cmd.env("BACHUE_IDP_SECRETO", "secreto-de-prueba-de-32-bytes-minimo!!")
        .env("BACHUE_IDP_PUERTO", puerto.to_string())
        .env("BACHUE_IDP_DB", format!("sqlite://{}", bd.display()))
        .env("BACHUE_IDP_INSEGURO", "1")
        .env("RUST_LOG", "warn");
    let hijo = cmd.spawn().expect("arranca el binario");
    let base = format!("http://127.0.0.1:{puerto}");
    let sonda = Client::new();
    let fin = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if sonda.get(format!("{base}/entrar")).send().await.map(|r| r.status().is_success()).unwrap_or(false) {
            break;
        }
        assert!(std::time::Instant::now() < fin, "el IdP no arrancó a tiempo");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    (hijo, base, bd)
}

fn cliente() -> Client {
    Client::builder().redirect(Policy::none()).cookie_store(true).build().unwrap()
}

fn b64url(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for t in bytes.chunks(3) {
        let b0 = t[0];
        s.push(T[(b0 >> 2) as usize] as char);
        match t.len() {
            1 => s.push(T[((b0 & 0b11) << 4) as usize] as char),
            2 => {
                let b1 = t[1];
                s.push(T[(((b0 & 0b11) << 4) | (b1 >> 4)) as usize] as char);
                s.push(T[((b1 & 0b1111) << 2) as usize] as char);
            }
            _ => {
                let (b1, b2) = (t[1], t[2]);
                s.push(T[(((b0 & 0b11) << 4) | (b1 >> 4)) as usize] as char);
                s.push(T[(((b1 & 0b1111) << 2) | (b2 >> 6)) as usize] as char);
                s.push(T[(b2 & 0b111111) as usize] as char);
            }
        }
    }
    s
}

// ───────────────────────── autenticador de software ─────────────────────────

/// Un par ES256 real que firma como un autenticador WebAuthn. Reproduce lo que haría una
/// passkey de plataforma: entrega su clave pública como COSE_Key al registrar, y firma
/// `authData ‖ SHA-256(clientData)` en DER al iniciar sesión.
struct Autenticador {
    sk: SigningKey,
    cred_id: Vec<u8>,
    rp_id: String,
    origen: String,
}

/// RNG del sistema para la prueba E2E: reenvía a `getrandom` (el ecosistema `rand` aún no
/// expone OsRng para rand_core 0.10). Solo bytes del SO, cero lógica cripto propia.
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

impl Autenticador {
    fn nuevo(rp_id: &str, origen: &str) -> Self {
        let mut cred_id = vec![0u8; 16];
        getrandom::fill(&mut cred_id).expect("RNG del sistema");
        Self {
            sk: SigningKey::try_generate_from_rng(&mut RngDelSo).expect("RNG del sistema"),
            cred_id,
            rp_id: rp_id.into(),
            origen: origen.into(),
        }
    }

    fn cose_key(&self) -> Vec<u8> {
        let punto = VerifyingKey::from(&self.sk).as_affine().to_sec1_point(false);
        let x: [u8; 32] = punto.x().unwrap().as_slice().try_into().unwrap();
        let y: [u8; 32] = punto.y().unwrap().as_slice().try_into().unwrap();
        let mut cose = vec![0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01];
        cose.extend_from_slice(&[0x21, 0x58, 0x20]);
        cose.extend_from_slice(&x);
        cose.extend_from_slice(&[0x22, 0x58, 0x20]);
        cose.extend_from_slice(&y);
        cose
    }

    fn client_data(&self, tipo: &str, challenge_b64: &str, origen: &str) -> Vec<u8> {
        format!("{{\"type\":\"{tipo}\",\"challenge\":\"{challenge_b64}\",\"origin\":\"{origen}\"}}")
            .into_bytes()
    }

    /// Arma la respuesta de `create()` para un `challenge` dado: `(clientDataJSON, attestationObject)`.
    fn registrar(&self, challenge_b64: &str) -> (Vec<u8>, Vec<u8>) {
        let cose = self.cose_key();
        let mut ad = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        ad.push(0b0100_0101); // UP|UV|AT
        ad.extend_from_slice(&0u32.to_be_bytes()); // signCount inicial
        ad.extend_from_slice(&[0u8; 16]); // aaguid
        ad.extend_from_slice(&u16::try_from(self.cred_id.len()).unwrap().to_be_bytes());
        ad.extend_from_slice(&self.cred_id);
        ad.extend_from_slice(&cose);
        let mut ao = vec![0xA3];
        ao.extend_from_slice(&[0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e']);
        ao.extend_from_slice(&[0x67, b'a', b't', b't', b'S', b't', b'm', b't', 0xA0]);
        ao.extend_from_slice(&[0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a']);
        ao.push(0x58);
        ao.push(u8::try_from(ad.len()).unwrap());
        ao.extend_from_slice(&ad);
        (self.client_data("webauthn.create", challenge_b64, &self.origen), ao)
    }

    /// Arma la respuesta de `get()` para un `challenge` con el `contador` dado y, opcionalmente,
    /// un `origen` distinto (para el caso rojo de origen ajeno): `(clientDataJSON, authenticatorData, firma_der)`.
    fn login(&self, challenge_b64: &str, contador: u32, origen: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut ad = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        ad.push(0b0000_0101); // UP|UV
        ad.extend_from_slice(&contador.to_be_bytes());
        let cd = self.client_data("webauthn.get", challenge_b64, origen);
        let mut mensaje = ad.clone();
        mensaje.extend_from_slice(Sha256::digest(&cd).as_slice());
        let firma: Signature = self.sk.sign(&mensaje);
        (cd, ad, firma.to_der().as_bytes().to_vec())
    }
}

// ───────────────────────── ayudantes HTTP ─────────────────────────

/// Crea la cuenta `usuario` por `/registrarse` y deja la sesión abierta en `cli`.
async fn registrar_cuenta(cli: &Client, base: &str, usuario: &str) {
    let r = cli
        .post(format!("{base}/registrarse"))
        .form(&[("usuario", usuario), ("contrasena", CLAVE)])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER, "el registro abre sesión y redirige");
}

async fn post_json(cli: &Client, url: &str, cuerpo: Value) -> reqwest::Response {
    cli.post(url).json(&cuerpo).send().await.unwrap()
}

/// Registra una passkey del `aut` en la sesión de `cli`. Devuelve el status del `/fin`.
async fn enrolar_passkey(cli: &Client, base: &str, aut: &Autenticador) -> StatusCode {
    let ini = post_json(cli, &format!("{base}/passkey/registrar/inicio"), json!({ "contrasena": CLAVE })).await;
    assert_eq!(ini.status(), StatusCode::OK, "inicio de registro OK con sesión y contraseña");
    let o: Value = ini.json().await.unwrap();
    let challenge = o["challenge"].as_str().unwrap().to_string();
    let (cdj, ao) = aut.registrar(&challenge);
    let fin = post_json(
        cli,
        &format!("{base}/passkey/registrar/fin"),
        json!({
            "challenge": challenge,
            "id": b64url(&aut.cred_id),
            "clientDataJSON": b64url(&cdj),
            "attestationObject": b64url(&ao),
            "apodo": "llave de prueba",
        }),
    )
    .await;
    fin.status()
}

// ───────────────────────── pruebas ─────────────────────────

/// **CONTROL POSITIVO (D28/D33): el ciclo completo abre.** Registrar cuenta → enrolar passkey →
/// (cliente NUEVO, sin contraseña ni sesión) iniciar sesión SOLO con la passkey → el panel.
#[tokio::test]
async fn ciclo_registro_y_login_passwordless_abre() {
    let (mut hijo, base, bd, origen, rp_id) = arrancar().await;
    let aut = Autenticador::nuevo(&rp_id, &origen);

    // Enrolar con sesión.
    let sesion = cliente();
    registrar_cuenta(&sesion, &base, "ana").await;
    assert_eq!(enrolar_passkey(&sesion, &base, &aut).await, StatusCode::OK);

    // Login PASSWORDLESS desde un cliente limpio (ni contraseña ni sesión previa).
    let limpio = cliente();
    let ini = post_json(&limpio, &format!("{base}/passkey/login/inicio"), json!({})).await;
    assert_eq!(ini.status(), StatusCode::OK);
    let o: Value = ini.json().await.unwrap();
    let challenge = o["challenge"].as_str().unwrap().to_string();
    assert!(o["allowCredentials"].as_array().unwrap().is_empty(), "login discoverable: allowCredentials vacío (no enumera)");
    let (cdj, ad, firma) = aut.login(&challenge, 1, &origen);
    let fin = post_json(
        &limpio,
        &format!("{base}/passkey/login/fin"),
        json!({
            "challenge": challenge,
            "id": b64url(&aut.cred_id),
            "clientDataJSON": b64url(&cdj),
            "authenticatorData": b64url(&ad),
            "signature": b64url(&firma),
        }),
    )
    .await;
    assert_eq!(fin.status(), StatusCode::OK, "la passkey inicia sesión");
    let cuerpo: Value = fin.json().await.unwrap();
    assert_eq!(cuerpo["ok"], json!(true));

    // La cookie de sesión del `/fin` abre el panel.
    let panel = limpio.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(panel.status(), StatusCode::OK);
    assert!(panel.text().await.unwrap().contains("ana"), "el panel saluda al usuario de la passkey");

    let _ = hijo.kill();
    let _ = std::fs::remove_file(&bd);
}

/// **Replay: el reto es de un solo uso.** Una assertion correcta reusada (mismo reto) se
/// rechaza la segunda vez — el CAS del reto lo gastó.
#[tokio::test]
async fn el_reto_de_login_es_de_un_solo_uso() {
    let (mut hijo, base, bd, origen, rp_id) = arrancar().await;
    let aut = Autenticador::nuevo(&rp_id, &origen);
    let sesion = cliente();
    registrar_cuenta(&sesion, &base, "beto").await;
    enrolar_passkey(&sesion, &base, &aut).await;

    let limpio = cliente();
    let o: Value = post_json(&limpio, &format!("{base}/passkey/login/inicio"), json!({})).await.json().await.unwrap();
    let challenge = o["challenge"].as_str().unwrap().to_string();
    let (cdj, ad, firma) = aut.login(&challenge, 1, &origen);
    let cuerpo = json!({
        "challenge": challenge, "id": b64url(&aut.cred_id),
        "clientDataJSON": b64url(&cdj), "authenticatorData": b64url(&ad), "signature": b64url(&firma),
    });
    let primera = post_json(&limpio, &format!("{base}/passkey/login/fin"), cuerpo.clone()).await;
    assert_eq!(primera.status(), StatusCode::OK, "la primera abre (control)");
    let segunda = post_json(&cliente(), &format!("{base}/passkey/login/fin"), cuerpo).await;
    assert_eq!(segunda.status(), StatusCode::UNAUTHORIZED, "el replay del mismo reto se rechaza");

    let _ = hijo.kill();
    let _ = std::fs::remove_file(&bd);
}

/// **Credencial desconocida → no genérico.** Un `cred_id` que no está en la base no abre, e
/// (anti-enumeración) es indistinguible de una firma mala.
#[tokio::test]
async fn una_credencial_desconocida_no_abre() {
    let (mut hijo, base, bd, origen, rp_id) = arrancar().await;
    let aut = Autenticador::nuevo(&rp_id, &origen); // nunca se registra
    let limpio = cliente();
    let o: Value = post_json(&limpio, &format!("{base}/passkey/login/inicio"), json!({})).await.json().await.unwrap();
    let challenge = o["challenge"].as_str().unwrap().to_string();
    let (cdj, ad, firma) = aut.login(&challenge, 1, &origen);
    let fin = post_json(
        &limpio,
        &format!("{base}/passkey/login/fin"),
        json!({
            "challenge": challenge, "id": b64url(&aut.cred_id),
            "clientDataJSON": b64url(&cdj), "authenticatorData": b64url(&ad), "signature": b64url(&firma),
        }),
    )
    .await;
    assert_eq!(fin.status(), StatusCode::UNAUTHORIZED);

    let _ = hijo.kill();
    let _ = std::fs::remove_file(&bd);
}

/// **Origen ajeno → se rechaza.** Una respuesta firmada para otro `origin` (phishing) no abre,
/// aunque el reto y la firma sean consistentes entre sí.
#[tokio::test]
async fn un_origen_ajeno_se_rechaza() {
    let (mut hijo, base, bd, origen, rp_id) = arrancar().await;
    let aut = Autenticador::nuevo(&rp_id, &origen);
    let sesion = cliente();
    registrar_cuenta(&sesion, &base, "caro").await;
    enrolar_passkey(&sesion, &base, &aut).await;

    let limpio = cliente();
    let o: Value = post_json(&limpio, &format!("{base}/passkey/login/inicio"), json!({})).await.json().await.unwrap();
    let challenge = o["challenge"].as_str().unwrap().to_string();
    // El autenticador firma para un origen de phishing, no el nuestro.
    let (cdj, ad, firma) = aut.login(&challenge, 1, "https://phishing.example");
    let fin = post_json(
        &limpio,
        &format!("{base}/passkey/login/fin"),
        json!({
            "challenge": challenge, "id": b64url(&aut.cred_id),
            "clientDataJSON": b64url(&cdj), "authenticatorData": b64url(&ad), "signature": b64url(&firma),
        }),
    )
    .await;
    assert_eq!(fin.status(), StatusCode::UNAUTHORIZED, "una assertion de otro origen no abre");

    let _ = hijo.kill();
    let _ = std::fs::remove_file(&bd);
}

/// **Enrolar EXIGE sesión.** Sin cookie de sesión, el inicio de registro responde 401.
#[tokio::test]
async fn enrolar_sin_sesion_es_401() {
    let (mut hijo, base, bd, _origen, _rp_id) = arrancar().await;
    let anon = cliente();
    let ini = post_json(&anon, &format!("{base}/passkey/registrar/inicio"), json!({})).await;
    assert_eq!(ini.status(), StatusCode::UNAUTHORIZED);
    let _ = hijo.kill();
    let _ = std::fs::remove_file(&bd);
}

/// **El contador anti-clonación debe AVANZAR.** Tras un login con contador 5, otro con un
/// contador que no supera 5 se rechaza (posible clon / replay); uno con 6 abre.
#[tokio::test]
async fn el_contador_debe_avanzar() {
    let (mut hijo, base, bd, origen, rp_id) = arrancar().await;
    let aut = Autenticador::nuevo(&rp_id, &origen);
    let sesion = cliente();
    registrar_cuenta(&sesion, &base, "dani").await;
    enrolar_passkey(&sesion, &base, &aut).await; // contador registrado = 0

    let login = |contador: u32| {
        let base = base.clone();
        let origen = origen.clone();
        let aut = &aut;
        async move {
            let c = cliente();
            let o: Value = post_json(&c, &format!("{base}/passkey/login/inicio"), json!({})).await.json().await.unwrap();
            let challenge = o["challenge"].as_str().unwrap().to_string();
            let (cdj, ad, firma) = aut.login(&challenge, contador, &origen);
            post_json(
                &c,
                &format!("{base}/passkey/login/fin"),
                json!({
                    "challenge": challenge, "id": b64url(&aut.cred_id),
                    "clientDataJSON": b64url(&cdj), "authenticatorData": b64url(&ad), "signature": b64url(&firma),
                }),
            )
            .await
            .status()
        }
    };

    assert_eq!(login(5).await, StatusCode::OK, "contador 5 > 0 abre");
    assert_eq!(login(5).await, StatusCode::UNAUTHORIZED, "contador 5 no supera el guardado 5: posible clon");
    assert_eq!(login(6).await, StatusCode::OK, "contador 6 > 5 abre");

    let _ = hijo.kill();
    let _ = std::fs::remove_file(&bd);
}

/// **Capa desactivada → 404.** Sin RP ID, las dos ceremonias no existen (D20: no se encienden
/// solas, y no se anuncia lo que no está).
#[tokio::test]
async fn sin_rp_id_las_ceremonias_son_404() {
    let (mut hijo, base, bd) = arrancar_sin_passkey().await;
    let c = cliente();
    assert_eq!(post_json(&c, &format!("{base}/passkey/login/inicio"), json!({})).await.status(), StatusCode::NOT_FOUND);
    assert_eq!(post_json(&c, &format!("{base}/passkey/registrar/inicio"), json!({})).await.status(), StatusCode::NOT_FOUND);
    let _ = hijo.kill();
    let _ = std::fs::remove_file(&bd);
}

/// **STEP-UP: enrolar con contraseña mala NO emite reto.** Con la sesión abierta pero la
/// contraseña incorrecta, `/registrar/inicio` responde 401 y NO entrega reto, así que el
/// `create()` del navegador nunca se dispara (no deja passkey huérfana) y nada se persiste —
/// una cookie robada no basta para plantar un acceso passwordless permanente (concilio F3, UX-a).
/// Rojo por la vía real: el único cambio frente al ciclo feliz (helper con `CLAVE`) es la contraseña.
#[tokio::test]
async fn enrolar_con_contrasena_mala_no_emite_reto() {
    let (mut hijo, base, bd, _origen, _rp_id) = arrancar().await;
    let sesion = cliente();
    registrar_cuenta(&sesion, &base, "fede").await;

    let ini = post_json(&sesion, &format!("{base}/passkey/registrar/inicio"), json!({ "contrasena": "contrasena-equivocada" })).await;
    assert_eq!(ini.status(), StatusCode::UNAUTHORIZED, "contraseña mala no emite reto");
    // Y no EMITIÓ reto: el 401 no trae `challenge`. (Que NO quede una passkey plantada lo cubre
    // `un_reto_de_otro_usuario_no_enrola_en_esta_sesion`; un login passwordless de una credencial
    // que aquí nunca se intentó registrar sería tautológico — observación del concilio, fable.)
    let cuerpo: Value = ini.json().await.unwrap_or(json!({}));
    assert!(cuerpo.get("challenge").is_none(), "el 401 no debe traer reto");

    let _ = hijo.kill();
    let _ = std::fs::remove_file(&bd);
}

/// **REMEDIACIÓN: el reset de operador borra las passkeys.** Una passkey abre; tras un reset por
/// compromiso (`/seguridad/2fa/reset`) deja de abrir, porque `limpiar_2fa` la eliminó. Cierra el
/// acceso passwordless permanente que sobrevivía a la rotación de sesión (concilio F3).
#[tokio::test]
async fn el_reset_de_operador_borra_las_passkeys() {
    let (mut hijo, base, bd, origen, rp_id) = arrancar().await;
    let aut = Autenticador::nuevo(&rp_id, &origen);
    let sesion = cliente();
    registrar_cuenta(&sesion, &base, "gabo").await;
    assert_eq!(enrolar_passkey(&sesion, &base, &aut).await, StatusCode::OK);

    let intentar_login = |contador: u32| {
        let base = base.clone();
        let origen = origen.clone();
        let aut = &aut;
        async move {
            let c = cliente();
            let o: Value = post_json(&c, &format!("{base}/passkey/login/inicio"), json!({})).await.json().await.unwrap();
            let challenge = o["challenge"].as_str().unwrap().to_string();
            let (cdj, ad, firma) = aut.login(&challenge, contador, &origen);
            post_json(
                &c,
                &format!("{base}/passkey/login/fin"),
                json!({
                    "challenge": challenge, "id": b64url(&aut.cred_id),
                    "clientDataJSON": b64url(&cdj), "authenticatorData": b64url(&ad), "signature": b64url(&firma),
                }),
            )
            .await
            .status()
        }
    };

    assert_eq!(intentar_login(1).await, StatusCode::OK, "control: la passkey abre antes del reset");

    let reset = cliente()
        .post(format!("{base}/seguridad/2fa/reset"))
        .header("x-aprovisionar-secreto", SECRETO_APROV)
        .json(&json!({ "usuario": "gabo" }))
        .send()
        .await
        .unwrap();
    assert_eq!(reset.status(), StatusCode::OK, "el reset de operador responde OK");

    assert_eq!(intentar_login(2).await, StatusCode::UNAUTHORIZED, "el reset borró la passkey");

    let _ = hijo.kill();
    let _ = std::fs::remove_file(&bd);
}

/// **STEP-UP en BORRAR: contraseña mala NO quita la passkey; la buena SÍ.** Con sesión pero
/// contraseña incorrecta, `/seguridad/passkey/borrar` responde 401 y la credencial sigue viva
/// (el login passwordless con ella abre); con la contraseña correcta, 200 y deja de abrir. El par
/// discrimina (D33): el único cambio entre el rojo y el verde es la contraseña.
#[tokio::test]
async fn borrar_exige_contrasena() {
    let (mut hijo, base, bd, origen, rp_id) = arrancar().await;
    let aut = Autenticador::nuevo(&rp_id, &origen);
    let sesion = cliente();
    registrar_cuenta(&sesion, &base, "hugo").await;
    assert_eq!(enrolar_passkey(&sesion, &base, &aut).await, StatusCode::OK);

    // La primera (y única) passkey de la BD limpia del test es el rowid 1.
    let login_abre = |contador: u32| {
        let base = base.clone();
        let origen = origen.clone();
        let aut = &aut;
        async move {
            let c = cliente();
            let o: Value = post_json(&c, &format!("{base}/passkey/login/inicio"), json!({})).await.json().await.unwrap();
            let challenge = o["challenge"].as_str().unwrap().to_string();
            let (cdj, ad, firma) = aut.login(&challenge, contador, &origen);
            post_json(
                &c,
                &format!("{base}/passkey/login/fin"),
                json!({
                    "challenge": challenge, "id": b64url(&aut.cred_id),
                    "clientDataJSON": b64url(&cdj), "authenticatorData": b64url(&ad), "signature": b64url(&firma),
                }),
            )
            .await
            .status()
        }
    };

    // Contraseña mala → 401 y la passkey sigue abriendo.
    let mala = post_json(&sesion, &format!("{base}/seguridad/passkey/borrar"), json!({ "id": 1, "contrasena": "contrasena-equivocada" })).await;
    assert_eq!(mala.status(), StatusCode::UNAUTHORIZED, "contraseña mala no borra");
    assert_eq!(login_abre(1).await, StatusCode::OK, "control: la passkey sigue viva tras el borrado rechazado");

    // Contraseña correcta → 200 y deja de abrir.
    let buena = post_json(&sesion, &format!("{base}/seguridad/passkey/borrar"), json!({ "id": 1, "contrasena": CLAVE })).await;
    assert_eq!(buena.status(), StatusCode::OK, "contraseña correcta sí borra");
    assert_eq!(login_abre(2).await, StatusCode::UNAUTHORIZED, "la passkey borrada ya no abre");

    let _ = hijo.kill();
    let _ = std::fs::remove_file(&bd);
}

/// **[revisión fable] B1 tras UX-a: un reto de registro de OTRO usuario no enrola sobre esta
/// sesión.** Con el step-up fuera de `/fin`, la ÚNICA puerta que le queda a una cookie robada es
/// que `/fin` exija un reto `registro` ligado a ESTE usuario. Eva (cuenta propia, su contraseña)
/// obtiene un reto legítimo; con la cookie de Vic lo presenta en `/fin`: debe ser 400 y Vic
/// no debe tener passkey. Mutante: quitar `consumido.usuario_id != Some(usuario.id)`.
#[tokio::test]
async fn un_reto_de_otro_usuario_no_enrola_en_esta_sesion() {
    let (mut hijo, base, bd, origen, rp_id) = arrancar().await;
    let aut = Autenticador::nuevo(&rp_id, &origen);
    let eva = cliente();
    registrar_cuenta(&eva, &base, "eva").await;
    let ini = post_json(&eva, &format!("{base}/passkey/registrar/inicio"), json!({ "contrasena": CLAVE })).await;
    assert_eq!(ini.status(), StatusCode::OK, "eva obtiene SU reto con SU contraseña");
    let o: Value = ini.json().await.unwrap();
    let challenge = o["challenge"].as_str().unwrap().to_string();

    let vic = cliente();
    registrar_cuenta(&vic, &base, "vic").await;
    let (cdj, ao) = aut.registrar(&challenge);
    let fin = post_json(
        &vic,
        &format!("{base}/passkey/registrar/fin"),
        json!({
            "challenge": challenge, "id": b64url(&aut.cred_id),
            "clientDataJSON": b64url(&cdj), "attestationObject": b64url(&ao), "apodo": "intruso",
        }),
    )
    .await;
    assert_eq!(fin.status(), StatusCode::BAD_REQUEST, "el reto de eva no enrola sobre la sesión de vic");

    let limpio = cliente();
    let o: Value = post_json(&limpio, &format!("{base}/passkey/login/inicio"), json!({})).await.json().await.unwrap();
    let challenge = o["challenge"].as_str().unwrap().to_string();
    let (cdj, ad, firma) = aut.login(&challenge, 1, &origen);
    let login = post_json(
        &limpio,
        &format!("{base}/passkey/login/fin"),
        json!({
            "challenge": challenge, "id": b64url(&aut.cred_id),
            "clientDataJSON": b64url(&cdj), "authenticatorData": b64url(&ad), "signature": b64url(&firma),
        }),
    )
    .await;
    assert_eq!(login.status(), StatusCode::UNAUTHORIZED, "no quedó passkey en ninguna cuenta");

    let _ = hijo.kill();
    let _ = std::fs::remove_file(&bd);
}

/// **[revisión fable] El freno del step-up SÍ cuenta en `/registrar/inicio`.** Cinco contraseñas
/// malas → 401; la sexta → 429 + Retry-After; y con el cubo lleno, la contraseña BUENA tampoco
/// emite reto (el freno va antes del Argon2). Sin esto, el `/inicio` sería un oráculo de
/// contraseña sin freno para quien ya tiene la cookie.
#[tokio::test]
async fn el_freno_del_stepup_cuenta_en_inicio() {
    let (mut hijo, base, bd, _origen, _rp_id) = arrancar().await;
    let sesion = cliente();
    registrar_cuenta(&sesion, &base, "lola").await;
    for i in 0..5 {
        let r = post_json(&sesion, &format!("{base}/passkey/registrar/inicio"), json!({ "contrasena": "mala" })).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "intento {i}: 401 sin frenar");
    }
    let r = post_json(&sesion, &format!("{base}/passkey/registrar/inicio"), json!({ "contrasena": "mala" })).await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS, "el sexto frena");
    assert!(r.headers().get("retry-after").is_some());
    let r = post_json(&sesion, &format!("{base}/passkey/registrar/inicio"), json!({ "contrasena": CLAVE })).await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS, "frenado, ni la buena emite reto");
    let _ = hijo.kill();
    let _ = std::fs::remove_file(&bd);
}
