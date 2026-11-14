// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **Banco de extremo a extremo (directiva 28).** Arranca el BINARIO real del IdP y le
//! habla como el mundo: HTTP con cookies. Los formularios son planos (no dependen de
//! JavaScript), así que hablar HTTP prueba el producto de verdad —la vía crítica del
//! login no pasa por htmx—. Un realce htmx futuro necesitaría un navegador; hoy no lo hay.

use std::process::{Child, Command};
use std::time::Duration;

use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode};

/// Secreto compartido de /aprovisionar en las pruebas (≥ 32 bytes, como en prod).
const SECRETO_APROV: &str = "secreto-de-aprovisionamiento-de-prueba-32!!";
/// Semilla OIDC de las pruebas (≥ 32 bytes): raíz de la clave de firma, separada del secreto.
const SEMILLA_OIDC: &str = "semilla-oidc-de-prueba-de-32-bytes-min!!";

/// Arranca el binario con el REGISTRO ABIERTO (las pruebas de login/2FA/validar crean sus
/// cuentas por `/registrarse`). El aprovisionamiento no se configura aquí.
async fn arrancar() -> (Child, String, std::path::PathBuf) {
    arrancar_con(true, false).await
}

/// Arranca el binario en un puerto libre, con una BD temporal fresca, y espera a que
/// responda. `registro_abierto` decide si `/registrarse` funciona; `con_aprovisionar`
/// activa `/aprovisionar` con [`SECRETO_APROV`]. Devuelve el proceso y la URL base.
async fn arrancar_con(registro_abierto: bool, con_aprovisionar: bool) -> (Child, String, std::path::PathBuf) {
    arrancar_full(registro_abierto, con_aprovisionar, None).await
}

/// Como [`arrancar_con`], pero además fija `BACHUE_IDP_2FA` al `modo` (off|gracia|estricto)
/// para probar la obligatoriedad del segundo factor.
async fn arrancar_full(
    registro_abierto: bool,
    con_aprovisionar: bool,
    modo_2fa: Option<&str>,
) -> (Child, String, std::path::PathBuf) {
    // Puerto libre: se pide uno al SO y se suelta (ventana de carrera mínima).
    let puerto = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let unico = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    );
    let bd = std::env::temp_dir().join(format!("bachue-idp-test-{unico}.db"));

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bachue-idp"));
    cmd.env("BACHUE_IDP_SECRETO", "secreto-de-prueba-de-32-bytes-minimo!!")
        .env("BACHUE_IDP_PUERTO", puerto.to_string())
        .env("BACHUE_IDP_DB", format!("sqlite://{}", bd.display()))
        .env("BACHUE_IDP_INSEGURO", "1") // http local: cookies sin Secure/__Host-
        // OIDC (veta #1): un cliente estático + issuer, para las pruebas de authorize/token.
        .env(
            "BACHUE_IDP_OIDC_CLIENTES",
            r#"[{"client_id":"app-prueba","redirect_uris":["https://rp.ejemplo/cb"]}]"#,
        )
        .env("BACHUE_IDP_EMISOR", "https://idp.prueba")
        .env("BACHUE_IDP_OIDC_SEMILLA", SEMILLA_OIDC)
        .env("RUST_LOG", "warn");
    if registro_abierto {
        cmd.env("BACHUE_IDP_REGISTRO_ABIERTO", "1");
    }
    if con_aprovisionar {
        cmd.env("BACHUE_IDP_APROVISIONAR_SECRETO", SECRETO_APROV);
    }
    if let Some(modo) = modo_2fa {
        cmd.env("BACHUE_IDP_2FA", modo);
    }
    let hijo = cmd.spawn().expect("arranca el binario");

    let base = format!("http://127.0.0.1:{puerto}");
    // Espera a que sirva (con tope, directiva 39): quien hace verdadera la condición es
    // el propio binario que acaba de arrancar.
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

fn loc(r: &reqwest::Response) -> String {
    r.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}

/// El valor de un parámetro de la query de una URL (sin arrastrar la crate `url`).
fn param_url(url: &str, clave: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    q.split('&').find_map(|par| {
        let (k, v) = par.split_once('=')?;
        (k == clave).then(|| v.to_string())
    })
}

/// Decodifica base64url sin relleno (para leer el payload/header del id_token en las pruebas).
fn b64url_dec(s: &str) -> Vec<u8> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let (mut acc, mut nb, mut out) = (0u32, 0u32, Vec::new());
    for c in s.bytes() {
        let v = A.iter().position(|&a| a == c).unwrap() as u32;
        acc = (acc << 6) | v;
        nb += 6;
        if nb >= 8 {
            nb -= 8;
            out.push((acc >> nb) as u8);
        }
    }
    out
}

/// El TOTP de la ventana ACTUAL EXACTA (contador = ahora/30). Se fija al contador exacto
/// —no a cualquiera que el skew ±1 acepte— para no devolver el de una ventana ya gastada
/// por el enrolamiento, que el servidor rechazaría como replay (causa del flake inicial).
fn codigo_totp(secreto: &str) -> String {
    let ahora = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let contador = ahora / 30;
    (0..1_000_000u32)
        .map(|n| format!("{n:06}"))
        .find(|c| matches!(
            bachue::dosfactores::verificar(secreto, c, ahora, None),
            bachue::dosfactores::Veredicto::Correcto { contador: k } if k == contador
        ))
        .expect("existe un código válido para la ventana actual")
}

fn secreto_de_html(html: &str) -> String {
    let abre = "<code class=\"secreto\">";
    let i = html.find(abre).expect("hay un secreto en la página") + abre.len();
    let j = html[i..].find("</code>").expect("cierra el code") + i;
    html[i..j].to_string()
}

/// Arranca el IdP con una BD y una GENERACIÓN OIDC dadas (para probar la rotación reusando la
/// misma BD/secreto/semilla). Mismo secreto y semilla que `arrancar_con`.
async fn spawn_idp(bd: &std::path::Path, generacion: u32) -> (Child, String) {
    let puerto = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bachue-idp"));
    cmd.env("BACHUE_IDP_SECRETO", "secreto-de-prueba-de-32-bytes-minimo!!")
        .env("BACHUE_IDP_PUERTO", puerto.to_string())
        .env("BACHUE_IDP_DB", format!("sqlite://{}", bd.display()))
        .env("BACHUE_IDP_INSEGURO", "1")
        .env("BACHUE_IDP_REGISTRO_ABIERTO", "1")
        .env("BACHUE_IDP_OIDC_CLIENTES", r#"[{"client_id":"app-prueba","redirect_uris":["https://rp.ejemplo/cb"]}]"#)
        .env("BACHUE_IDP_EMISOR", "https://idp.prueba")
        .env("BACHUE_IDP_OIDC_SEMILLA", SEMILLA_OIDC)
        .env("BACHUE_IDP_OIDC_GEN", generacion.to_string())
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
    (hijo, base)
}

/// Arranca el IdP sobre una BD dada con `BACHUE_IDP_2FA=<modo>` (para probar la política de
/// obligatoriedad, incluso reusando una BD con usuarios creados antes de activarla).
async fn spawn_idp_2fa(bd: &std::path::Path, modo: &str) -> (Child, String) {
    let puerto = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bachue-idp"));
    cmd.env("BACHUE_IDP_SECRETO", "secreto-de-prueba-de-32-bytes-minimo!!")
        .env("BACHUE_IDP_PUERTO", puerto.to_string())
        .env("BACHUE_IDP_DB", format!("sqlite://{}", bd.display()))
        .env("BACHUE_IDP_INSEGURO", "1")
        .env("BACHUE_IDP_REGISTRO_ABIERTO", "1")
        .env("BACHUE_IDP_APROVISIONAR_SECRETO", SECRETO_APROV)
        .env("BACHUE_IDP_2FA", modo)
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
    (hijo, base)
}

struct Guardia(Child, std::path::PathBuf);
impl Drop for Guardia {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = std::fs::remove_file(&self.1);
    }
}

/// OIDC (veta #1, rebanada 2): el binario real publica el JWKS, y es EXACTAMENTE la clave
/// que `bachue-oidc` deriva del mismo secreto+etiqueta que usa el IdP. Cruza la frontera del
/// programa (D28): no es un `assert` sobre `jwks()` en proceso, es el HTTP del binario.
#[tokio::test]
async fn jwks_publica_la_clave_del_emisor_derivada_del_secreto() {
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);

    let r = cliente().get(format!("{base}/jwks")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "el JWKS responde 200");
    let cuerpo = r.text().await.unwrap();
    let jwks: serde_json::Value = serde_json::from_str(&cuerpo).expect("el JWKS es JSON");
    let clave = &jwks["keys"][0];
    assert_eq!(clave["kty"], "EC");
    assert_eq!(clave["crv"], "P-256");
    assert_eq!(clave["alg"], "ES256");
    assert_eq!(clave["use"], "sig");

    // El binario publica LA clave que bachue-oidc deriva del secreto del arnés y la etiqueta
    // del IdP (si el IdP usara otro secreto/etiqueta, el kid no casaría → rojo).
    let esperada = bachue_oidc::ClaveEmisor::derivar(SEMILLA_OIDC.as_bytes(), "bachue-idp/oidc-firma-v1");
    assert_eq!(clave["kid"], esperada.kid(), "el kid es la huella de la clave derivada del secreto");
    assert_eq!(clave["x"], esperada.jwk()["x"], "x de la clave publicada = derivada");
    assert_eq!(clave["y"], esperada.jwk()["y"], "y de la clave publicada = derivada");
}

/// CONCILIO (hallazgo sonnet/opus/fable, D33): rotar la generación NO debe invalidar un
/// access_token vigente en `/userinfo`. Antes del arreglo, `/userinfo` verificaba solo con la
/// clave ACTIVA → un token de la generación anterior daba 401 tras rotar. Cruza la frontera
/// (D28): dos arranques del binario real sobre la MISMA BD/secreto/semilla, GEN 1 → GEN 2.
#[tokio::test]
async fn rotar_la_generacion_no_invalida_un_access_token_vigente() {
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let bd = std::env::temp_dir().join(format!(
        "bachue-idp-rot-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));

    // GEN 1: un usuario obtiene un access_token.
    let (mut c1, base1) = spawn_idp(&bd, 1).await;
    let c = cliente();
    c.post(format!("{base1}/registrarse"))
        .form(&[("usuario", "rita"), ("contrasena", "contraseña-larga-y-buena")])
        .send().await.unwrap();
    let r = c.get(format!(
        "{base1}/authorize?response_type=code&client_id=app-prueba\
         &redirect_uri=https%3A%2F%2Frp.ejemplo%2Fcb&code_challenge={CHALLENGE}&code_challenge_method=S256"
    )).send().await.unwrap();
    let code = param_url(&loc(&r), "code").expect("code");
    let tok: serde_json::Value = serde_json::from_str(
        &c.post(format!("{base1}/token"))
            .form(&[
                ("grant_type", "authorization_code"), ("code", &code),
                ("redirect_uri", "https://rp.ejemplo/cb"), ("client_id", "app-prueba"),
                ("code_verifier", VERIFIER),
            ]).send().await.unwrap().text().await.unwrap(),
    ).unwrap();
    let access = tok["access_token"].as_str().expect("access_token").to_string();
    // Control positivo (D33): el token sirve en GEN 1.
    assert_eq!(
        cliente().get(format!("{base1}/userinfo")).bearer_auth(&access).send().await.unwrap().status(),
        StatusCode::OK, "control: el access_token fresco sirve en su propia generación"
    );
    let _ = c1.kill();

    // GEN 2 (misma BD/secreto/semilla): ROTA. El JWKS publica 2 claves, y el access_token de
    // GEN 1 —aún vigente— DEBE seguir sirviendo en /userinfo.
    let (mut c2, base2) = spawn_idp(&bd, 2).await;
    let jwks: serde_json::Value = serde_json::from_str(
        &cliente().get(format!("{base2}/jwks")).send().await.unwrap().text().await.unwrap(),
    ).unwrap();
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 2, "GEN 2 publica activa + anterior (rotó)");
    let r = cliente().get(format!("{base2}/userinfo")).bearer_auth(&access).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "rotar NO invalida un access_token vigente de la generación anterior");
    let ui: serde_json::Value = serde_json::from_str(&r.text().await.unwrap()).unwrap();
    assert_eq!(ui["sub"], "rita");
    let _ = c2.kill();
    let _ = std::fs::remove_file(&bd);
}

/// CONCILIO (hallazgo fable): `prompt=none` sin sesión NO muestra login; devuelve
/// `login_required` al RP (OIDC Core §3.1.2.1). Antes se ignoraba `prompt` en silencio.
#[tokio::test]
async fn oidc_prompt_none_sin_sesion_devuelve_login_required() {
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let r = cliente().get(format!(
        "{base}/authorize?response_type=code&client_id=app-prueba\
         &redirect_uri=https%3A%2F%2Frp.ejemplo%2Fcb&code_challenge={CHALLENGE}&code_challenge_method=S256&prompt=none&state=st"
    )).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER, "prompt=none no muestra UI: redirige al RP");
    let l = loc(&r);
    assert!(l.starts_with("https://rp.ejemplo/cb?"), "va al RP registrado: {l}");
    assert_eq!(param_url(&l, "error").as_deref(), Some("login_required"), "sin sesión → login_required");
    assert_eq!(param_url(&l, "state").as_deref(), Some("st"), "conserva el state");
}

/// CONCILIO (hallazgo fable): `prompt=login` fuerza reautenticación aunque HAYA sesión —no se
/// entrega una identidad vieja como fresca—, y el `next` no reintroduce `prompt` (sin bucle).
#[tokio::test]
async fn oidc_prompt_login_fuerza_reautenticacion() {
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();
    c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "tom"), ("contrasena", "contraseña-larga-y-buena")])
        .send().await.unwrap();
    let r = c.get(format!(
        "{base}/authorize?response_type=code&client_id=app-prueba\
         &redirect_uri=https%3A%2F%2Frp.ejemplo%2Fcb&code_challenge={CHALLENGE}&code_challenge_method=S256&prompt=login"
    )).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let l = loc(&r);
    assert!(l.starts_with("/entrar?"), "prompt=login con sesión fuerza reauth: {l}");
    let next = param_url(&l, "next").expect("next");
    assert!(!next.contains("prompt"), "el next no reintroduce prompt (sin bucle): {next}");
}

/// OIDC discovery (veta #1): el documento `/.well-known/openid-configuration` anuncia los
/// endpoints reales y solo lo implementado (code + PKCE S256 + ES256).
#[tokio::test]
async fn oidc_discovery_anuncia_los_endpoints_reales() {
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let r = cliente().get(format!("{base}/.well-known/openid-configuration")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let d: serde_json::Value = serde_json::from_str(&r.text().await.unwrap()).unwrap();
    assert_eq!(d["issuer"], "https://idp.prueba");
    assert_eq!(d["authorization_endpoint"], "https://idp.prueba/authorize");
    assert_eq!(d["token_endpoint"], "https://idp.prueba/token");
    assert_eq!(d["jwks_uri"], "https://idp.prueba/jwks");
    assert_eq!(d["id_token_signing_alg_values_supported"][0], "ES256");
    assert_eq!(d["code_challenge_methods_supported"][0], "S256");
    assert_eq!(d["response_types_supported"][0], "code");
}

/// OIDC (veta #1, rebanadas 3/4): el flujo completo contra el BINARIO real (D28).
/// Registro → sesión → GET /authorize (PKCE S256) → code → POST /token (verifier) → id_token,
/// con los claims correctos y el `kid` que casa el JWKS. Vector PKCE del RFC 7636.
#[tokio::test]
async fn flujo_oidc_authorize_token_emite_id_token() {
    // Par verifier/challenge del RFC 7636 Apéndice B (artefacto, no inventado).
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    // Usuario + sesión.
    let r = c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "dora"), ("contrasena", "contraseña-larga-y-buena")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);

    // /authorize → code.
    let auth = format!(
        "{base}/authorize?response_type=code&client_id=app-prueba\
         &redirect_uri=https%3A%2F%2Frp.ejemplo%2Fcb\
         &code_challenge={CHALLENGE}&code_challenge_method=S256&state=st123&nonce=n1"
    );
    let r = c.get(&auth).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER, "authorize redirige al RP");
    let l = loc(&r);
    assert!(l.starts_with("https://rp.ejemplo/cb?"), "vuelve al redirect_uri exacto: {l}");
    assert!(l.contains("state=st123"), "conserva el state");
    let code = param_url(&l, "code").expect("hay code en la redirección");

    // /token → id_token.
    let r = c.post(format!("{base}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://rp.ejemplo/cb"),
            ("client_id", "app-prueba"),
            ("code_verifier", VERIFIER),
        ])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "el token endpoint responde 200");
    let tok: serde_json::Value = serde_json::from_str(&r.text().await.unwrap()).unwrap();
    let id_token = tok["id_token"].as_str().expect("hay id_token");
    assert_eq!(tok["token_type"], "Bearer");

    // Claims del id_token.
    let claims: serde_json::Value =
        serde_json::from_slice(&b64url_dec(id_token.split('.').nth(1).unwrap())).unwrap();
    assert_eq!(claims["iss"], "https://idp.prueba", "issuer");
    assert_eq!(claims["aud"], "app-prueba", "audiencia = client_id");
    assert_eq!(claims["sub"], "dora", "sujeto = usuario autenticado");
    assert_eq!(claims["nonce"], "n1", "nonce del RP viaja al id_token");

    // El `kid` del header casa el del JWKS: un RP lo verifica con la clave publicada.
    let header: serde_json::Value =
        serde_json::from_slice(&b64url_dec(id_token.split('.').next().unwrap())).unwrap();
    let jwks: serde_json::Value = serde_json::from_str(
        &cliente().get(format!("{base}/jwks")).send().await.unwrap().text().await.unwrap(),
    ).unwrap();
    assert_eq!(header["kid"], jwks["keys"][0]["kid"], "el id_token lo verifica el JWKS publicado");

    // /userinfo con el access_token → { sub }.
    let access = tok["access_token"].as_str().expect("hay access_token");
    let r = c.get(format!("{base}/userinfo")).bearer_auth(access).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "userinfo acepta el access_token");
    let ui: serde_json::Value = serde_json::from_str(&r.text().await.unwrap()).unwrap();
    assert_eq!(ui["sub"], "dora", "userinfo devuelve el sujeto");

    // ROJO: el id_token NO vale como bearer en /userinfo (typ != "at").
    let r = c.get(format!("{base}/userinfo")).bearer_auth(id_token).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "un id_token no sirve de access_token");
    // ROJO: sin bearer → 401.
    let r = c.get(format!("{base}/userinfo")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "userinfo sin token → 401");

    // ROJO (un solo uso): el MISMO code no se canjea dos veces.
    let r = c.post(format!("{base}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://rp.ejemplo/cb"),
            ("client_id", "app-prueba"),
            ("code_verifier", VERIFIER),
        ])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "replay del code → invalid_grant");
}

/// **El access_token OIDC NO sobrevive al logout.** Se emite por authorize→token, se comprueba
/// que sirve en `/userinfo`, se hace `/salir` (que sube `version`), y el MISMO access_token —aún
/// no caducado— pasa a dar 401 en `/userinfo`. CASO ROJO (lo que el concilio 2026-10-18 cerró):
/// antes `/userinfo` solo miraba firma+typ+exp, así que el token sobrevivía al logout hasta su
/// `exp`. Mutante: sin la comparación de `ver`, el userinfo final daría 200.
#[tokio::test]
async fn el_access_token_oidc_no_sobrevive_al_logout() {
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "nora"), ("contrasena", "contraseña-larga-y-buena")])
        .send().await.unwrap();
    let auth = format!(
        "{base}/authorize?response_type=code&client_id=app-prueba\
         &redirect_uri=https%3A%2F%2Frp.ejemplo%2Fcb\
         &code_challenge={CHALLENGE}&code_challenge_method=S256&state=st&nonce=n1"
    );
    let code = param_url(&loc(&c.get(&auth).send().await.unwrap()), "code").expect("hay code");
    let r = c.post(format!("{base}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://rp.ejemplo/cb"),
            ("client_id", "app-prueba"),
            ("code_verifier", VERIFIER),
        ])
        .send().await.unwrap();
    let tok: serde_json::Value = serde_json::from_str(&r.text().await.unwrap()).unwrap();
    let access = tok["access_token"].as_str().expect("hay access_token").to_string();

    // Control: antes de salir, el access_token recién emitido SÍ sirve.
    let r = c.get(format!("{base}/userinfo")).bearer_auth(&access).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "control: el access_token recién emitido sirve");

    // Salir sube `version` (revoca las sesiones del usuario server-side).
    c.post(format!("{base}/salir")).send().await.unwrap();

    // El MISMO access_token, aún no caducado, ya NO sirve: su `ver` quedó por debajo de la
    // version actual del usuario. (Antes seguía dando 200 hasta `exp`.)
    let r = c.get(format!("{base}/userinfo")).bearer_auth(&access).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "tras salir, el access_token OIDC queda invalidado");
}

/// **Un authorization_code tampoco sobrevive al logout.** Se pide `/authorize` (code), se hace
/// `/salir` (sube `version`), y canjear el code en `/token` —aún dentro de sus 60 s— da
/// invalid_grant (400), no un access_token con la version post-logout. CASO ROJO (hallazgo
/// fable del concilio 2026-10-18): antes `/token` leía la version ACTUAL al canjear, así que un
/// code emitido ANTES del logout producía un bearer que lo sobrevivía. El fix guarda la version
/// en el code al autorizar y la exige igual a la actual al canjear. Mutante: sin
/// `cod.ver != Some(version)`, este canje daría 200.
#[tokio::test]
async fn el_codigo_oidc_no_sobrevive_al_logout() {
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();
    c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "omar"), ("contrasena", "contraseña-larga-y-buena")])
        .send().await.unwrap();
    let auth = format!(
        "{base}/authorize?response_type=code&client_id=app-prueba\
         &redirect_uri=https%3A%2F%2Frp.ejemplo%2Fcb\
         &code_challenge={CHALLENGE}&code_challenge_method=S256&state=s&nonce=n"
    );
    let code = param_url(&loc(&c.get(&auth).send().await.unwrap()), "code").expect("hay code");

    // Salir ANTES de canjear sube `version`.
    c.post(format!("{base}/salir")).send().await.unwrap();

    // El code, aún dentro de sus 60 s, ya NO se canjea: invalid_grant (antes daba un token).
    let r = c.post(format!("{base}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://rp.ejemplo/cb"),
            ("client_id", "app-prueba"),
            ("code_verifier", VERIFIER),
        ])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "un code emitido antes del logout no se canjea tras salir");
}

/// OIDC red cases (D33): PKCE incorrecto y redirect_uri no registrada se rechazan.
#[tokio::test]
async fn oidc_pkce_malo_y_redirect_no_registrado_se_rechazan() {
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();
    c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "eli"), ("contrasena", "contraseña-larga-y-buena")])
        .send().await.unwrap();

    // redirect_uri NO registrada → 400 (no se emite código ni se redirige a ella).
    let r = c.get(format!(
        "{base}/authorize?response_type=code&client_id=app-prueba\
         &redirect_uri=https%3A%2F%2Fmalo.ejemplo%2Fcb&code_challenge={CHALLENGE}&code_challenge_method=S256"
    )).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "redirect_uri no registrada se rechaza");

    // Código válido pero code_verifier EQUIVOCADO → invalid_grant (PKCE protege el code).
    let r = c.get(format!(
        "{base}/authorize?response_type=code&client_id=app-prueba\
         &redirect_uri=https%3A%2F%2Frp.ejemplo%2Fcb&code_challenge={CHALLENGE}&code_challenge_method=S256"
    )).send().await.unwrap();
    let code = param_url(&loc(&r), "code").expect("hay code");
    let r = c.post(format!("{base}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://rp.ejemplo/cb"),
            ("client_id", "app-prueba"),
            ("code_verifier", "verifier-EQUIVOCADO-no-casa-el-challenge"),
        ])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "PKCE incorrecto → invalid_grant");
}

#[tokio::test]
async fn flujo_contrasena_de_punta_a_punta() {
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    // Registro → sesión → panel.
    let r = c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "ana"), ("contrasena", "contraseña-buena-larga")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER, "el registro redirige");
    assert_eq!(loc(&r), "/");
    let panel = c.get(format!("{base}/")).send().await.unwrap().text().await.unwrap();
    assert!(panel.contains("Hola, ana"), "el panel saluda a ana");

    // Salir → la sesión se corta.
    let r = c.post(format!("{base}/salir")).send().await.unwrap();
    assert_eq!(loc(&r), "/entrar");
    let r = c.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(loc(&r), "/entrar", "sin sesión, la raíz manda al login");

    // Contraseña incorrecta: NO redirige, muestra el aviso.
    let r = c.post(format!("{base}/entrar"))
        .form(&[("usuario", "ana"), ("contrasena", "MALA"), ("next", "/")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.text().await.unwrap().contains("incorrectos"));

    // Contraseña correcta (sin 2FA) → sesión directa.
    let r = c.post(format!("{base}/entrar"))
        .form(&[("usuario", "ana"), ("contrasena", "contraseña-buena-larga"), ("next", "/")])
        .send().await.unwrap();
    assert_eq!(loc(&r), "/", "login correcto va al destino");

    // Redirect abierto BLOQUEADO: un next a otro host se ignora y cae a "/".
    let r = c.post(format!("{base}/entrar"))
        .form(&[("usuario", "ana"), ("contrasena", "contraseña-buena-larga"), ("next", "//evil.com")])
        .send().await.unwrap();
    assert_eq!(loc(&r), "/", "el next a otro host se descarta (defensas::redireccion)");
}

/// El puente `auth_request` para servicios detrás de bachue-idp (tunjo-saas):
/// sin sesión → 401; con sesión válida → 200 y `X-Usuario-Autenticado: <usuario>`.
#[tokio::test]
async fn validar_es_el_puente_de_auth_request() {
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    // Sin sesión → 401 y sin cabecera de identidad.
    let r = c.get(format!("{base}/validar")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "sin sesión /validar es 401");
    assert!(r.headers().get("x-usuario-autenticado").is_none());

    // Registro → sesión en el cookie store del cliente.
    c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "ana"), ("contrasena", "contraseña-buena-larga")])
        .send().await.unwrap();

    // Con sesión → 200 y la identidad en la cabecera que nginx copiará al upstream.
    let r = c.get(format!("{base}/validar")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "con sesión /validar es 200");
    assert_eq!(
        r.headers().get("x-usuario-autenticado").and_then(|v| v.to_str().ok()),
        Some("ana"),
        "la cabecera lleva el usuario autenticado"
    );

    // Tras salir, vuelve a 401.
    c.post(format!("{base}/salir")).send().await.unwrap();
    let r = c.get(format!("{base}/validar")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "tras salir, /validar es 401");
}

/// Concilio (Sonnet): la guardia CSRF rechaza un POST cross-site (cierra el login-CSRF
/// que SameSite no cubre), y deja pasar el de primera parte.
#[tokio::test]
async fn la_guardia_csrf_rechaza_el_post_cross_site() {
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    // Registro previo (sin Sec-Fetch-Site: cliente no-navegador, se permite).
    c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "cleo"), ("contrasena", "contraseña-de-cleo-larga")])
        .send().await.unwrap();

    // POST con Sec-Fetch-Site: cross-site → 403 (el login-CSRF queda cerrado).
    let r = c.post(format!("{base}/entrar"))
        .header("Sec-Fetch-Site", "cross-site")
        .form(&[("usuario", "cleo"), ("contrasena", "contraseña-de-cleo-larga"), ("next", "/")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "un POST cross-site se rechaza");

    // same-site (subdominio hermano) también se rechaza: un IdP exige mismo ORIGEN.
    let r = c.post(format!("{base}/entrar"))
        .header("Sec-Fetch-Site", "same-site")
        .form(&[("usuario", "cleo"), ("contrasena", "contraseña-de-cleo-larga"), ("next", "/")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "same-site (subdominio) también se rechaza");

    // same-origin (el formulario propio) sí pasa.
    let r = c.post(format!("{base}/entrar"))
        .header("Sec-Fetch-Site", "same-origin")
        .form(&[("usuario", "cleo"), ("contrasena", "contraseña-de-cleo-larga"), ("next", "/")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER, "el POST de primera parte pasa");
    assert_eq!(loc(&r), "/");
}

/// La CSP estricta viaja en toda respuesta del IdP, y NO lleva `'unsafe-inline'`
/// (esa negativa es el punto: el frontend es todo de origen propio, así que
/// `script-src 'self'` cierra el XSS de verdad). Cruza la frontera real (D28):
/// pide al binario vivo y lee la cabecera que devuelve.
#[tokio::test]
async fn la_csp_estricta_viaja_en_las_respuestas() {
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    let r = c.get(format!("{base}/entrar")).send().await.unwrap();
    let csp = r
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(csp.contains("script-src 'self'"), "la CSP fija script-src 'self': {csp}");
    assert!(csp.contains("frame-ancestors 'none'"), "la CSP prohíbe el enmarcado: {csp}");
    // font-src 'self' data: — sin él, las tipografías @font-face embebidas como
    // data: en boi.css se bloquean (font-src NO hereda de img-src; hallazgo del
    // concilio). Este candado impide que la directiva vuelva a caerse.
    assert!(csp.contains("font-src 'self' data:"), "la CSP permite las fuentes data: de boi.css: {csp}");
    // discriminante: si algún día se cuela un inline y alguien abre la CSP con
    // 'unsafe-inline', esta prueba lo caza — sería volver a permitir el XSS.
    assert!(!csp.contains("unsafe-inline"), "la CSP NO debe llevar 'unsafe-inline': {csp}");
    // y aplica también a los assets servidos (no solo a las páginas).
    let r = c.get(format!("{base}/boi.css")).send().await.unwrap();
    assert!(
        r.headers().get("content-security-policy").is_some(),
        "la CSP también va en la respuesta de los assets"
    );
}

/// boi.js se sirve como MÓDULO ES: cargado como script clásico, su `export` de
/// nivel superior es un SyntaxError y el archivo no ejecuta (regresión real que
/// el concilio destapó). Este candado exige el `type="module"` en la página.
#[tokio::test]
async fn boi_js_se_carga_como_modulo() {
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let html = cliente().get(format!("{base}/entrar")).send().await.unwrap().text().await.unwrap();
    assert!(
        html.contains("type=\"module\" src=\"/boi.js\"") || html.contains("src=\"/boi.js\" type=\"module\""),
        "boi.js debe cargarse como módulo ES, no como script clásico"
    );
}

/// Extrae el `token` del JSON de `/aprovisionar` sin arrastrar serde_json al dev-dep.
fn token_de_json(body: &str) -> Option<String> {
    let abre = "\"token\":\"";
    let i = body.find(abre)? + abre.len();
    let j = body[i..].find('"')? + i;
    Some(body[i..j].to_string())
}

/// **Registro cerrado (pago primero): `/registrarse` NO crea cuenta.** GET y POST devuelven
/// 404, y la cuenta que se intentó registrar NO puede entrar después (no se creó). El caso
/// verde correlativo —que con el registro ABIERTO sí crea— lo cubren los otros flujos, que
/// arrancan con `arrancar()` (registro abierto): esa es la pareja de esta sonda (D33).
#[tokio::test]
async fn registro_cerrado_no_crea_cuenta() {
    let (hijo, base, bd) = arrancar_con(false, true).await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    // GET /registrarse → 404 (no ofrece formulario de alta).
    let r = c.get(format!("{base}/registrarse")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND, "con registro cerrado, GET /registrarse es 404");

    // POST /registrarse → 404 y NO crea la cuenta.
    let r = c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "colada"), ("contrasena", "contraseña-que-no-debe-entrar")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND, "POST /registrarse tampoco crea (404)");

    // La cuenta NO existe: intentar entrar da el aviso de credenciales, no una sesión.
    let r = c.post(format!("{base}/entrar"))
        .form(&[("usuario", "colada"), ("contrasena", "contraseña-que-no-debe-entrar"), ("next", "/")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "sin cuenta, el login no redirige");
    assert!(r.text().await.unwrap().contains("incorrectos"), "no se creó cuenta por /registrarse");
}

/// **`/aprovisionar` exige el secreto compartido.** Sin cabecera → 401; con el secreto
/// equivocado → 401; y sin secreto CONFIGURADO en el servidor → 503 (fail-closed, no un
/// secreto por defecto). El verde (secreto correcto) lo prueba el flujo de punta a punta.
#[tokio::test]
async fn aprovisionar_exige_el_secreto_compartido() {
    // Servidor CON aprovisionamiento configurado.
    let (hijo, base, bd) = arrancar_con(false, true).await;
    let _g = Guardia(hijo, bd);
    let c = cliente();
    let cuerpo = r#"{"usuario":"nuevo@x","referencia":"sub_1"}"#;

    // Sin cabecera del secreto → 401.
    let r = c.post(format!("{base}/aprovisionar"))
        .header("content-type", "application/json")
        .body(cuerpo)
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "sin secreto → 401");

    // Secreto equivocado → 401.
    let r = c.post(format!("{base}/aprovisionar"))
        .header("content-type", "application/json")
        .header("x-aprovisionar-secreto", "un-secreto-equivocado-de-32-bytes-x!!")
        .body(cuerpo)
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "secreto equivocado → 401");

    // Servidor SIN aprovisionamiento configurado → 503 aunque se mande un secreto.
    let (hijo2, base2, bd2) = arrancar_con(false, false).await;
    let _g2 = Guardia(hijo2, bd2);
    let r = c.post(format!("{base2}/aprovisionar"))
        .header("content-type", "application/json")
        .header("x-aprovisionar-secreto", SECRETO_APROV)
        .body(cuerpo)
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE, "sin secreto configurado → 503");
}

/// **Pago primero, de punta a punta.** aprovisionar (con secreto) → token de reclamo →
/// `/establecer` fija la contraseña y deja sesión iniciada → el panel saluda. Y las dos
/// parejas rojas por la vía real: el token de un solo uso NO se puede REUSAR (segundo canje
/// rechazado), y un token INVENTADO no vale.
#[tokio::test]
async fn flujo_pago_primero_de_punta_a_punta() {
    let (hijo, base, bd) = arrancar_con(false, true).await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    // 1) Aprovisionar: devuelve el token de reclamo.
    let r = c.post(format!("{base}/aprovisionar"))
        .header("content-type", "application/json")
        .header("x-aprovisionar-secreto", SECRETO_APROV)
        .body(r#"{"usuario":"perito@x","referencia":"sub_9"}"#)
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "aprovisionar con secreto bueno → 200");
    let token = token_de_json(&r.text().await.unwrap()).expect("hay token en la respuesta");

    // 2) GET /establecer con el token → 200 y el formulario de fijar contraseña.
    let g = c.get(format!("{base}/establecer")).query(&[("token", token.as_str())]).send().await.unwrap();
    assert_eq!(g.status(), StatusCode::OK, "el token válido abre el formulario");
    assert!(g.text().await.unwrap().contains("Fija tu contraseña"));

    // 3) POST /establecer: fija la contraseña → sesión iniciada (redirige a "/").
    let r = c.post(format!("{base}/establecer"))
        .form(&[("token", token.as_str()), ("contrasena", "contraseña-del-perito-larga")])
        .send().await.unwrap();
    assert_eq!(loc(&r), "/", "al fijar la contraseña, sesión iniciada");
    let panel = c.get(format!("{base}/")).send().await.unwrap().text().await.unwrap();
    assert!(panel.contains("Hola, perito@x"), "el panel saluda a la cuenta recién reclamada");

    // 4) ROJO — REUSO: el mismo token no se puede canjear otra vez (un solo uso).
    let dos = cliente(); // cliente limpio (sin la cookie de sesión del paso 3)
    let r = dos.post(format!("{base}/establecer"))
        .form(&[("token", token.as_str()), ("contrasena", "otra-contraseña-larga-distinta")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "reusar el token → rechazado");
    assert!(r.text().await.unwrap().contains("no es válido"), "el reclamo repetido no vale");

    // 5) ROJO — token inventado: no vale.
    let r = dos.get(format!("{base}/establecer")).query(&[("token", "token-inventado.sin.firma")]).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "un token inventado no abre el formulario");
}

#[tokio::test]
async fn flujo_segundo_factor_de_punta_a_punta() {
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    // Registro + activar 2FA.
    c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "beto"), ("contrasena", "contraseña-de-beto-larga")])
        .send().await.unwrap();
    // Abrir la pantalla de activación (sólo sesión; el secreto no tiene efecto aún).
    let html = c.post(format!("{base}/seguridad/2fa"))
        .send().await.unwrap().text().await.unwrap();
    let secreto = secreto_de_html(&html);

    // STEP-UP ROJO (hallazgo de la revisión): confirmar el 2FA con la contraseña EQUIVOCADA
    // —o con un secreto del atacante y sesión secuestrada— NO persiste nada. El gate está en
    // el endpoint que ESCRIBE, no en el que muestra el secreto.
    let mala = c.post(format!("{base}/seguridad/2fa/confirmar"))
        .form(&[("secreto", secreto.as_str()), ("codigo", codigo_totp(&secreto).as_str()), ("contrasena", "MALA")])
        .send().await.unwrap();
    assert_eq!(mala.status(), StatusCode::OK, "contraseña mala: no redirige (no activa)");
    assert!(mala.text().await.unwrap().contains("Contraseña incorrecta"), "muestra el aviso de step-up");
    // Y el 2FA sigue SIN activar tras el intento fallido.
    let panel0 = c.get(format!("{base}/")).send().await.unwrap().text().await.unwrap();
    assert!(panel0.contains("sin activar"), "el 2FA no quedó activado por el intento con contraseña mala");

    // Step-up VERDE: confirmar con código bueno Y la contraseña actual → muestra los
    // códigos de recuperación UNA vez (200), ya no redirige directo al panel.
    let r = c.post(format!("{base}/seguridad/2fa/confirmar"))
        .form(&[("secreto", secreto.as_str()), ("codigo", codigo_totp(&secreto).as_str()), ("contrasena", "contraseña-de-beto-larga")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "confirmar 2FA muestra los códigos de recuperación");
    assert!(r.text().await.unwrap().contains("recuperación"), "la pantalla trae los códigos");
    let panel = c.get(format!("{base}/")).send().await.unwrap().text().await.unwrap();
    assert!(panel.contains("activo"), "el panel muestra el 2FA activo");

    // Salir y volver a entrar: la contraseña ya NO basta, pide segundo factor.
    c.post(format!("{base}/salir")).send().await.unwrap();
    let r = c.post(format!("{base}/entrar"))
        .form(&[("usuario", "beto"), ("contrasena", "contraseña-de-beto-larga"), ("next", "/")])
        .send().await.unwrap();
    assert!(loc(&r).starts_with("/segundo-factor"), "con 2FA, la contraseña lleva al segundo factor: {}", loc(&r));

    // El segundo factor necesita un código de una ventana DISTINTA a la del enrolamiento
    // (el contador gastado no se reutiliza — anti-replay). Se espera a la ventana siguiente.
    let ahora = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    tokio::time::sleep(Duration::from_secs(31 - (ahora % 30))).await;

    let r = c.post(format!("{base}/segundo-factor"))
        .form(&[("codigo", codigo_totp(&secreto).as_str()), ("next", "/")])
        .send().await.unwrap();
    assert_eq!(loc(&r), "/", "el TOTP correcto completa el login");
    let panel = c.get(format!("{base}/")).send().await.unwrap().text().await.unwrap();
    assert!(panel.contains("Hola, beto"), "tras el 2FA, el panel saluda a beto");
}

/// **El freno por (usuario, origen) responde `429 Too Many Requests` con `Retry-After`**,
/// no un `200` como un login fallido más. La espera se calculaba desde siempre y no se
/// emitía como código/cabecera HTTP. (El freno anti-rociado por origen se DESCARTÓ en el
/// concilio del 2026-09-30: bloqueaba también logins correctos y era un DoS weaponizable
/// sobre IPs compartidas; la respuesta al rociado entre cuentas es el 2FA — ver guaca::freno.)
#[tokio::test]
async fn el_freno_por_cuenta_emite_429_y_retry_after() {
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "ana"), ("contrasena", "contraseña-buena-larga")])
        .send().await.unwrap();
    c.post(format!("{base}/salir")).send().await.unwrap();

    // Los cinco primeros fallos son 200 con el aviso: no frenan todavía.
    for _ in 0..5 {
        let r = c.post(format!("{base}/entrar"))
            .form(&[("usuario", "ana"), ("contrasena", "MALA"), ("next", "/")])
            .send().await.unwrap();
        assert_eq!(r.status(), StatusCode::OK, "los cinco primeros no frenan");
    }
    // El sexto choca con el freno: 429 + Retry-After.
    let r = c.post(format!("{base}/entrar"))
        .form(&[("usuario", "ana"), ("contrasena", "MALA"), ("next", "/")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS, "el sexto frena con 429");
    assert!(r.headers().get("retry-after").is_some(), "el freno emite Retry-After");
}

/// **El STEP-UP (reautenticación con la contraseña sobre una sesión ya abierta)
/// tiene su PROPIO cubo de freno, aparte del login (B1).** Dos mitades:
///  - tras cinco contraseñas malas en `/seguridad/2fa/confirmar`, el sexto frena
///    con 429: antes el step-up NO se frenaba (oráculo de contraseña online para
///    quien ya tiene la cookie).
///  - con el cubo del step-up lleno, el LOGIN del mismo usuario sigue ABIERTO:
///    los fallos de step-up no cayeron en el cubo del login. El mutante que lo
///    valida es `ORIGEN_STEPUP` = el origen real del cliente: mezcla los cubos y
///    pone este login en 429.
#[tokio::test]
async fn el_step_up_tiene_cubo_de_freno_aparte_del_login() {
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    // Registro + abrir la pantalla de enrolar 2FA (deja sesión plena).
    c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "caro"), ("contrasena", "contraseña-de-caro-larga")])
        .send().await.unwrap();
    let html = c.post(format!("{base}/seguridad/2fa"))
        .send().await.unwrap().text().await.unwrap();
    let secreto = secreto_de_html(&html);

    // Cinco contraseñas MALAS en el confirmar (step-up): 200 con aviso, sin frenar.
    for _ in 0..5 {
        let r = c.post(format!("{base}/seguridad/2fa/confirmar"))
            .form(&[("secreto", secreto.as_str()), ("codigo", "000000"), ("contrasena", "MALA")])
            .send().await.unwrap();
        assert_eq!(r.status(), StatusCode::OK, "los cinco primeros step-up no frenan");
    }
    // El sexto step-up malo choca con el freno del step-up: 429 + Retry-After.
    let r = c.post(format!("{base}/seguridad/2fa/confirmar"))
        .form(&[("secreto", secreto.as_str()), ("codigo", "000000"), ("contrasena", "MALA")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS, "el sexto step-up frena con 429");
    assert!(r.headers().get("retry-after").is_some(), "el freno del step-up emite Retry-After");

    // SEPARACIÓN (el discriminador): con el cubo del step-up lleno, el LOGIN del
    // mismo usuario sigue abierto. Si los cubos se mezclaran, la contraseña
    // correcta devolvería 429 en vez de entrar.
    c.post(format!("{base}/salir")).send().await.unwrap();
    let r = c.post(format!("{base}/entrar"))
        .form(&[("usuario", "caro"), ("contrasena", "contraseña-de-caro-larga"), ("next", "/")])
        .send().await.unwrap();
    assert_ne!(
        r.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "el login NO hereda el freno del step-up (cubos aparte)"
    );
}

/// **El freno del step-up resiste una RÁFAGA CONCURRENTE (hallazgo del concilio
/// 2026-10-06, medido).** Antes era check-then-act sin exclusión: N peticiones
/// simultáneas con la misma cookie leían el cubo vacío antes de que ninguna
/// anotara el fallo, y pasaban las N (medido entonces: 40/40 con 200). Ahora la
/// sección crítica «comprobar freno + anotar intento» va bajo un lock de proceso
/// (`comprobar_stepup`), así que la ráfaga se cuenta intento a intento y, pasado
/// el umbral, choca con 429. CASO ROJO: quitando el lock, `frenadas` vuelve a 0.
#[tokio::test]
async fn el_freno_del_step_up_resiste_una_rafaga_concurrente() {
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "dani"), ("contrasena", "contraseña-de-dani-larga")])
        .send().await.unwrap();
    let html = c.post(format!("{base}/seguridad/2fa"))
        .send().await.unwrap().text().await.unwrap();
    let secreto = secreto_de_html(&html);

    // N step-ups con contraseña MALA, SIMULTÁNEOS (misma sesión, cookie compartida
    // por el jar del cliente clonado).
    let n: usize = 20;
    let mut tareas = Vec::with_capacity(n);
    for _ in 0..n {
        let (c, base, secreto) = (c.clone(), base.clone(), secreto.clone());
        tareas.push(tokio::spawn(async move {
            c.post(format!("{base}/seguridad/2fa/confirmar"))
                .form(&[("secreto", secreto.as_str()), ("codigo", "000000"), ("contrasena", "MALA")])
                .send()
                .await
                .unwrap()
                .status()
        }));
    }
    let mut frenadas = 0usize;
    for t in tareas {
        if t.await.unwrap() == StatusCode::TOO_MANY_REQUESTS {
            frenadas += 1;
        }
    }
    // Umbral 5: a lo sumo ~5 pasan el freno; el resto (≥ n-6) choca con 429. Sin
    // el lock, las N pasaban y `frenadas` era 0.
    assert!(
        frenadas >= n - 6,
        "la ráfaga concurrente debe frenarse tras el umbral; frenadas={frenadas} de {n}"
    );
}

/// **El freno del LOGIN resiste una ráfaga CONCURRENTE (carrera check-then-act).** N logins
/// con contraseña MALA simultáneos sobre la misma cuenta/origen: a lo sumo ~umbral pasan, el
/// resto choca con 429. CASO ROJO (el patrón que el concilio 2026-10-18 cerró en `entrar_post`):
/// sin `FRENO_LOCK` —leer `frenado` + Argon2 + anotar, sin exclusión— las N leían el cubo bajo
/// umbral antes de que ninguna escribiera (el Argon2 ENSANCHA la ventana) y pasaban todas,
/// `frenadas=0`. El provisional anotado bajo lock las cuenta intento a intento.
#[tokio::test]
async fn el_freno_del_login_resiste_una_rafaga_concurrente() {
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();
    c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "dani"), ("contrasena", "contraseña-de-dani-larga")])
        .send().await.unwrap();

    // N logins con contraseña MALA, SIMULTÁNEOS. El freno es por (usuario, origen): todos
    // tecleamos "dani" desde 127.0.0.1, así que comparten cubo; clientes distintos (sin jar
    // compartido) para que ninguno arrastre sesión. La contraseña mala responde 200 (vista con
    // error) y, pasado el umbral, 429 (frenada).
    let n: usize = 20;
    let mut tareas = Vec::with_capacity(n);
    for _ in 0..n {
        let base = base.clone();
        tareas.push(tokio::spawn(async move {
            cliente()
                .post(format!("{base}/entrar"))
                .form(&[("usuario", "dani"), ("contrasena", "MALA"), ("next", "/")])
                .send()
                .await
                .unwrap()
                .status()
        }));
    }
    let mut frenadas = 0usize;
    for t in tareas {
        if t.await.unwrap() == StatusCode::TOO_MANY_REQUESTS {
            frenadas += 1;
        }
    }
    assert!(
        frenadas >= n - 6,
        "la ráfaga concurrente de login debe frenarse tras el umbral; frenadas={frenadas} de {n}"
    );
}

/// **«Salir» REVOCA la sesión en el servidor, no solo borra la cookie.** Tras
/// `/salir`, reenviar el token VIEJO (la cookie de antes) da 401: subir `version`
/// lo invalida. CASO ROJO: con el `salir_post` anterior (solo borraba la cookie)
/// el token viejo seguía validando y `/validar` daba 200. Se maneja la cookie a
/// mano (sin jar) para poder reenviar el token después de salir.
#[tokio::test]
async fn salir_revoca_el_token_no_solo_borra_la_cookie() {
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = Client::builder().redirect(Policy::none()).build().unwrap();

    let r = c
        .post(format!("{base}/registrarse"))
        .form(&[("usuario", "eva"), ("contrasena", "contraseña-de-eva-larga")])
        .send()
        .await
        .unwrap();
    // `sesion=<token>` (modo inseguro de prueba: cookie sin prefijo `__Host-`).
    let cookie = r
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|s| s.starts_with("sesion="))
        .map(|s| s.split(';').next().unwrap().to_string())
        .expect("registrarse emite la cookie de sesión");

    // El token recién emitido valida en /validar (lo que consume nginx).
    let r = c.get(format!("{base}/validar")).header("cookie", &cookie).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "el token recién emitido valida");

    // Salir CON ese token: sube `version` → revoca todas las sesiones.
    let r = c.post(format!("{base}/salir")).header("cookie", &cookie).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER, "salir redirige (303)");

    // El MISMO token viejo ya NO valida: 401. No solo se borró del navegador: se revocó.
    let r = c.get(format!("{base}/validar")).header("cookie", &cookie).send().await.unwrap();
    assert_eq!(
        r.status(),
        StatusCode::UNAUTHORIZED,
        "tras salir, el token viejo queda REVOCADO (no solo borrada la cookie)"
    );
}

/// **El freno del SEGUNDO FACTOR también emite `429` + `Retry-After`.** Cubre el envoltorio
/// que `sin-caso-rojo` marcó sin caso rojo (`segundo_factor_post`): tras cinco códigos TOTP
/// malos, el sexto intento choca con el freno por (usuario, origen) del segundo paso.
#[tokio::test]
async fn el_freno_del_segundo_factor_emite_429_y_retry_after() {
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    // Registro + activar 2FA (step-up con la contraseña correcta).
    c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "beto"), ("contrasena", "contraseña-de-beto-larga")])
        .send().await.unwrap();
    let html = c.post(format!("{base}/seguridad/2fa"))
        .send().await.unwrap().text().await.unwrap();
    let secreto = secreto_de_html(&html);
    let r = c.post(format!("{base}/seguridad/2fa/confirmar"))
        .form(&[("secreto", secreto.as_str()), ("codigo", codigo_totp(&secreto).as_str()), ("contrasena", "contraseña-de-beto-larga")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "2FA activado (muestra códigos de recuperación)");

    // Entrar con contraseña correcta → pantalla de segundo factor (deja token pendiente).
    c.post(format!("{base}/salir")).send().await.unwrap();
    let r = c.post(format!("{base}/entrar"))
        .form(&[("usuario", "beto"), ("contrasena", "contraseña-de-beto-larga"), ("next", "/")])
        .send().await.unwrap();
    assert!(loc(&r).starts_with("/segundo-factor"), "la contraseña lleva al segundo factor");

    // Cinco códigos MALOS: 200 con aviso, sin frenar aún.
    for _ in 0..5 {
        let r = c.post(format!("{base}/segundo-factor"))
            .form(&[("codigo", "000000"), ("next", "/")])
            .send().await.unwrap();
        assert_eq!(r.status(), StatusCode::OK, "los cinco códigos malos no frenan");
    }
    // El sexto choca con el freno del segundo factor: 429 + Retry-After.
    let r = c.post(format!("{base}/segundo-factor"))
        .form(&[("codigo", "000000"), ("next", "/")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS, "el sexto código malo frena con 429");
    assert!(r.headers().get("retry-after").is_some(), "el freno del 2FA emite Retry-After");
}

/// **El registro rechaza una contraseña PREDECIBLE** (caminata de teclado ≥12) con el
/// motivo REAL, no un «demasiado corta» falso (directiva 20), y no crea la cuenta. Cruza
/// el binario (D28): la política de `bachue-clave` está cableada en el endpoint real.
#[tokio::test]
async fn el_registro_rechaza_una_contrasena_predecible() {
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    let r = c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "walker"), ("contrasena", "qwertyuiopas")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "no redirige: no se creó la cuenta");
    assert!(r.text().await.unwrap().contains("predecible"), "avisa del motivo real, no 'corta'");

    // La cuenta no existe: no se puede entrar con ella.
    let r = c.post(format!("{base}/entrar"))
        .form(&[("usuario", "walker"), ("contrasena", "qwertyuiopas"), ("next", "/")])
        .send().await.unwrap();
    assert!(r.text().await.unwrap().contains("incorrectos"), "la cuenta predecible no se creó");
}

/// **`/establecer` (fijar contraseña por token) también rechaza una PREDECIBLE**, con el
/// motivo real, y el rechazo NO consume el token (cierra el hunk que `sin-caso-rojo` marcó
/// en esa rama). Cruza el binario (D28).
#[tokio::test]
async fn establecer_rechaza_una_contrasena_predecible() {
    let (hijo, base, bd) = arrancar_con(false, true).await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    let r = c.post(format!("{base}/aprovisionar"))
        .header("content-type", "application/json")
        .header("x-aprovisionar-secreto", SECRETO_APROV)
        .body(r#"{"usuario":"perito2@x","referencia":"sub_10"}"#)
        .send().await.unwrap();
    let token = token_de_json(&r.text().await.unwrap()).expect("hay token");

    // Clave predecible → 200 con el aviso, NO fija.
    let r = c.post(format!("{base}/establecer"))
        .form(&[("token", token.as_str()), ("contrasena", "qwertyuiopas")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "no redirige: no se fijó");
    assert!(r.text().await.unwrap().contains("predecible"), "motivo real, no 'corta'");

    // El rechazo NO consumió el token: una clave buena sí fija.
    let r = c.post(format!("{base}/establecer"))
        .form(&[("token", token.as_str()), ("contrasena", "contraseña-del-perito-larga")])
        .send().await.unwrap();
    assert_eq!(loc(&r), "/", "el rechazo no consumió el token; la buena fija");
}

/// **Un código de recuperación abre el segundo factor por su vía, y es de un solo uso.** La
/// red de seguridad que hace posible exigir 2FA sin fabricar cuentas muertas. Cruza el
/// binario (D28): enrola, captura un código de la pantalla que se muestra una vez, entra con
/// él, y comprueba que reutilizarlo ya no abre.
#[tokio::test]
async fn un_codigo_de_recuperacion_abre_el_segundo_factor_y_no_se_reutiliza() {
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    // Registro + enrolar 2FA.
    c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "cleo"), ("contrasena", "contraseña-de-cleo-larga")])
        .send().await.unwrap();
    let html = c.post(format!("{base}/seguridad/2fa")).send().await.unwrap().text().await.unwrap();
    let secreto = secreto_de_html(&html);
    // El confirmar exitoso muestra los códigos: capturo el primero (un `code.secreto`).
    let cods = c.post(format!("{base}/seguridad/2fa/confirmar"))
        .form(&[("secreto", secreto.as_str()), ("codigo", codigo_totp(&secreto).as_str()), ("contrasena", "contraseña-de-cleo-larga")])
        .send().await.unwrap().text().await.unwrap();
    let codigo_rec = secreto_de_html(&cods);
    assert!(codigo_rec.contains('-'), "un código de recuperación es ocho-guion-ocho: {codigo_rec}");

    // Entrar con contraseña → pantalla de segundo factor.
    c.post(format!("{base}/salir")).send().await.unwrap();
    let r = c.post(format!("{base}/entrar"))
        .form(&[("usuario", "cleo"), ("contrasena", "contraseña-de-cleo-larga"), ("next", "/")])
        .send().await.unwrap();
    assert!(loc(&r).starts_with("/segundo-factor"), "la contraseña lleva al segundo factor");

    // Usar el CÓDIGO DE RECUPERACIÓN en MINÚSCULAS → abre igual (se normaliza a mayúsculas,
    // el caso del que lo dicta por teléfono; obs. del concilio).
    let r = c.post(format!("{base}/segundo-factor"))
        .form(&[("codigo", codigo_rec.to_lowercase().as_str()), ("next", "/")])
        .send().await.unwrap();
    assert_eq!(loc(&r), "/", "el código de recuperación abre por su vía (insensible a mayúsculas)");
    let panel = c.get(format!("{base}/")).send().await.unwrap().text().await.unwrap();
    assert!(panel.contains("Hola, cleo"), "tras la recuperación, sesión plena");

    // REUSO: el mismo código ya no abre (un solo uso).
    c.post(format!("{base}/salir")).send().await.unwrap();
    c.post(format!("{base}/entrar"))
        .form(&[("usuario", "cleo"), ("contrasena", "contraseña-de-cleo-larga"), ("next", "/")])
        .send().await.unwrap();
    let r = c.post(format!("{base}/segundo-factor"))
        .form(&[("codigo", codigo_rec.as_str()), ("next", "/")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "reusar el código no redirige");
    assert!(r.text().await.unwrap().contains("incorrecto"), "un código de recuperación gastado no vuelve a abrir");
}

/// **Un acierto de contraseña NO reinicia el freno del segundo factor** (hallazgo del
/// concilio). Antes, `entrar_post` registraba el acierto de contraseña como éxito y borraba
/// la cuenta de fallos, así que quien tiene la contraseña (el adversario exacto del 2FA)
/// estrenaba un cubo por ciclo y el retroceso exponencial nunca escalaba. Se comprueba sin
/// esperar la ventana: intercalando un login correcto, los fallos del 2FA deben SEGUIR
/// sumando hasta frenar.
#[tokio::test]
async fn el_acierto_de_contrasena_no_reinicia_el_freno_del_segundo_factor() {
    let (hijo, base, bd) = arrancar().await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    // Registro + 2FA.
    c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "deto"), ("contrasena", "contraseña-de-deto-larga")])
        .send().await.unwrap();
    let html = c.post(format!("{base}/seguridad/2fa")).send().await.unwrap().text().await.unwrap();
    let secreto = secreto_de_html(&html);
    c.post(format!("{base}/seguridad/2fa/confirmar"))
        .form(&[("secreto", secreto.as_str()), ("codigo", codigo_totp(&secreto).as_str()), ("contrasena", "contraseña-de-deto-larga")])
        .send().await.unwrap();

    // Login → segundo factor.
    c.post(format!("{base}/salir")).send().await.unwrap();
    let r = c.post(format!("{base}/entrar"))
        .form(&[("usuario", "deto"), ("contrasena", "contraseña-de-deto-larga"), ("next", "/")])
        .send().await.unwrap();
    assert!(loc(&r).starts_with("/segundo-factor"));

    // Cuatro códigos malos (por debajo del umbral de 5: aún no frena).
    for _ in 0..4 {
        let r = c.post(format!("{base}/segundo-factor")).form(&[("codigo", "000000"), ("next", "/")]).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::OK, "cuatro fallos no frenan todavía");
    }
    // Intercalar un LOGIN CORRECTO (acierto de contraseña). Con el defecto, esto reiniciaba
    // el freno; con el arreglo, no cuenta como éxito y los fallos siguen sumando.
    let r = c.post(format!("{base}/entrar"))
        .form(&[("usuario", "deto"), ("contrasena", "contraseña-de-deto-larga"), ("next", "/")])
        .send().await.unwrap();
    assert!(loc(&r).starts_with("/segundo-factor"), "el login correcto lleva de nuevo al 2FA");
    // Un quinto fallo: el contador llega a 5 (no se reinició).
    let r = c.post(format!("{base}/segundo-factor")).form(&[("codigo", "000000"), ("next", "/")]).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "el quinto fallo aún responde (se registra)");
    // El siguiente choca con el freno: prueba de que el acierto NO reinició la cuenta.
    let r = c.post(format!("{base}/segundo-factor")).form(&[("codigo", "000000"), ("next", "/")]).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS, "el freno del 2FA acumuló pese al login correcto intercalado");
}

/// **`estricto` fuerza a un usuario EXISTENTE sin 2FA a enrolarse en el próximo login** (la
/// migración de los legados). Se crea el usuario con la política en `off`, se reinicia el IdP
/// en `estricto` sobre la MISMA BD, y el login con contraseña correcta lleva a enrolar sin dar
/// sesión plena.
#[tokio::test]
async fn estricto_fuerza_a_un_usuario_existente_sin_2fa() {
    let (mut hijo, base, bd) = arrancar().await; // off
    let c = cliente();
    let r = c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "legado"), ("contrasena", "contraseña-de-legado-larga")])
        .send().await.unwrap();
    assert_eq!(loc(&r), "/", "en off, el registro da sesión directa");
    hijo.kill().ok(); // parar el servidor OFF

    // Reiniciar en ESTRICTO sobre la misma BD.
    let (hijo2, base2) = spawn_idp_2fa(&bd, "estricto").await;
    let _g = Guardia(hijo2, bd);
    let c2 = cliente();
    let r = c2.post(format!("{base2}/entrar"))
        .form(&[("usuario", "legado"), ("contrasena", "contraseña-de-legado-larga"), ("next", "/")])
        .send().await.unwrap();
    assert_eq!(loc(&r), "/seguridad/2fa", "estricto fuerza a enrolar al usuario existente");
    // Sin 2FA no hay sesión plena: la raíz manda al login.
    let r = c2.get(format!("{base2}/")).send().await.unwrap();
    assert_eq!(loc(&r), "/entrar", "el token de enrolamiento NO es una sesión plena");
}

/// **`estricto` fuerza a enrolar al REGISTRAR, y completar el enrolamiento da la sesión plena.**
/// Cubre la maquinaria nueva: token de enrolamiento forzado → `/seguridad/2fa` (GET) → confirmar
/// emite la sesión.
#[tokio::test]
async fn estricto_fuerza_al_registrar_y_el_enrolamiento_da_sesion() {
    let (hijo, base, bd) = arrancar_full(true, false, Some("estricto")).await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    let r = c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "nuevo"), ("contrasena", "contraseña-de-nuevo-larga")])
        .send().await.unwrap();
    assert_eq!(loc(&r), "/seguridad/2fa", "bajo estricto, el registro fuerza a enrolar (sin sesión)");
    let r = c.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(loc(&r), "/entrar", "aún sin sesión plena");

    // Enrolar con el token pendiente: GET da el secreto; confirmar da códigos + sesión.
    let html = c.get(format!("{base}/seguridad/2fa")).send().await.unwrap().text().await.unwrap();
    let secreto = secreto_de_html(&html);
    let r = c.post(format!("{base}/seguridad/2fa/confirmar"))
        .form(&[("secreto", secreto.as_str()), ("codigo", codigo_totp(&secreto).as_str()), ("contrasena", "contraseña-de-nuevo-larga")])
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "el confirmar forzado muestra los códigos de recuperación");
    assert_eq!(
        r.headers().get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "la pantalla de códigos no se cachea",
    );
    assert!(r.text().await.unwrap().contains("recuperación"));
    let panel = c.get(format!("{base}/")).send().await.unwrap().text().await.unwrap();
    assert!(panel.contains("Hola, nuevo"), "tras enrolar, sesión plena");
}

/// **El operador puede resetear el 2FA** (rompe-cristales para el doble-extravío), autenticado
/// con el secreto M2M; sin él, 401. Tras el reset, el usuario entra sin segundo factor.
#[tokio::test]
async fn el_operador_puede_resetear_el_2fa() {
    let (hijo, base, bd) = arrancar_full(true, true, None).await; // off, con aprovisionar
    let _g = Guardia(hijo, bd);
    let c = cliente();

    // Registrar + activar 2FA (opt-in).
    c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "opix"), ("contrasena", "contraseña-de-opix-larga")])
        .send().await.unwrap();
    let html = c.post(format!("{base}/seguridad/2fa")).send().await.unwrap().text().await.unwrap();
    let secreto = secreto_de_html(&html);
    c.post(format!("{base}/seguridad/2fa/confirmar"))
        .form(&[("secreto", secreto.as_str()), ("codigo", codigo_totp(&secreto).as_str()), ("contrasena", "contraseña-de-opix-larga")])
        .send().await.unwrap();
    // Con 2FA, el login pide segundo factor.
    c.post(format!("{base}/salir")).send().await.unwrap();
    let r = c.post(format!("{base}/entrar"))
        .form(&[("usuario", "opix"), ("contrasena", "contraseña-de-opix-larga"), ("next", "/")])
        .send().await.unwrap();
    assert!(loc(&r).starts_with("/segundo-factor"), "antes del reset, pide 2FA");

    // Reset SIN secreto → 401.
    let op = cliente();
    let r = op.post(format!("{base}/seguridad/2fa/reset"))
        .header("content-type", "application/json").body(r#"{"usuario":"opix"}"#)
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "el reset sin secreto se rechaza");
    // Reset CON secreto → 200.
    let r = op.post(format!("{base}/seguridad/2fa/reset"))
        .header("content-type", "application/json").header("x-aprovisionar-secreto", SECRETO_APROV)
        .body(r#"{"usuario":"opix"}"#).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "el operador resetea con el secreto M2M");

    // Ahora el login ya NO pide 2FA (reseteado).
    let c3 = cliente();
    let r = c3.post(format!("{base}/entrar"))
        .form(&[("usuario", "opix"), ("contrasena", "contraseña-de-opix-larga"), ("next", "/")])
        .send().await.unwrap();
    assert_eq!(loc(&r), "/", "tras el reset, la contraseña basta (2FA borrado)");
}

/// **Bajo `gracia`, un usuario NUEVO NO hereda la ventana de 7 días** (hallazgo del concilio):
/// nace con la ventana ya vencida, así que si abandona el enrolamiento y reloguea, sigue
/// forzado — no obtiene sesión plena. (El legado sí tiene ventana: ver la prueba siguiente.)
#[tokio::test]
async fn un_usuario_nuevo_bajo_gracia_no_hereda_la_ventana() {
    let (hijo, base, bd) = arrancar_full(true, false, Some("gracia")).await;
    let _g = Guardia(hijo, bd);
    let c = cliente();

    let r = c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "novato"), ("contrasena", "contraseña-de-novato-larga")])
        .send().await.unwrap();
    assert_eq!(loc(&r), "/seguridad/2fa", "el nuevo bajo gracia va a enrolar");

    // Abandona y reloguea (cliente limpio): NO hereda los 7 días.
    let c2 = cliente();
    let r = c2.post(format!("{base}/entrar"))
        .form(&[("usuario", "novato"), ("contrasena", "contraseña-de-novato-larga"), ("next", "/")])
        .send().await.unwrap();
    assert_eq!(loc(&r), "/seguridad/2fa", "el nuevo no evade el enrolamiento relogueando");
    let r = c2.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(loc(&r), "/entrar", "sigue sin sesión plena");
}

/// **Bajo `gracia`, un usuario EXISTENTE (legado) entra dentro de su ventana** — no se le
/// fuerza en el primer login tras activar la política (esto distingue `gracia` de `estricto`).
#[tokio::test]
async fn un_legado_bajo_gracia_entra_dentro_de_la_ventana() {
    let (mut hijo, base, bd) = arrancar().await; // off
    let c = cliente();
    let r = c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "veterano"), ("contrasena", "contraseña-de-veterano-larga")])
        .send().await.unwrap();
    assert_eq!(loc(&r), "/", "en off, sesión directa");
    hijo.kill().ok();

    let (hijo2, base2) = spawn_idp_2fa(&bd, "gracia").await;
    let _g = Guardia(hijo2, bd);
    let c2 = cliente();
    let r = c2.post(format!("{base2}/entrar"))
        .form(&[("usuario", "veterano"), ("contrasena", "contraseña-de-veterano-larga"), ("next", "/")])
        .send().await.unwrap();
    assert_eq!(loc(&r), "/", "el legado entra dentro de la ventana de gracia (aún no forzado)");
}

/// **El reset del operador INVALIDA la sesión viva del usuario** (sube `version`, que
/// `usuario_de_sesion` compara): un reset por compromiso no deja abierta la sesión que quizá
/// abrió el atacante.
#[tokio::test]
async fn el_reset_del_operador_invalida_la_sesion_viva() {
    let (hijo, base, bd) = arrancar_full(true, true, None).await; // off, con aprovisionar
    let _g = Guardia(hijo, bd);
    let c = cliente();

    // Registrar → sesión viva (sin 2FA hace falta para esta prueba).
    c.post(format!("{base}/registrarse"))
        .form(&[("usuario", "revu"), ("contrasena", "contraseña-de-revu-larga")])
        .send().await.unwrap();
    let panel = c.get(format!("{base}/")).send().await.unwrap().text().await.unwrap();
    assert!(panel.contains("Hola, revu"), "hay sesión viva antes del reset");

    // El operador resetea el 2FA de revu (M2M).
    let op = cliente();
    let r = op.post(format!("{base}/seguridad/2fa/reset"))
        .header("content-type", "application/json").header("x-aprovisionar-secreto", SECRETO_APROV)
        .body(r#"{"usuario":"revu"}"#).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "reset OK");

    // La sesión que tenía revu ya NO vale: la raíz lo manda al login.
    let r = c.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(loc(&r), "/entrar", "el reset invalidó la sesión viva (bump de version)");
}
