// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **Passkeys / WebAuthn (F3): las dos ceremonias cableadas a HTTP + DB.**
//!
//! El IdP no reimplementa WebAuthn: lo ORQUESTA. El andamiaje (parseo, retos, banderas,
//! contador) vive en [`bachue_passkey`] y la cripto de firma en `bachue_passkey_es256`; aquí
//! solo se hace lo que es del SERVICIO —generar y PERSISTIR el reto de un solo uso, ligar la
//! credencial a un usuario, emitir la sesión— tal como pide el contrato del crate.
//!
//! # El modelo: passwordless DISCOVERABLE (opción A, decisión de Juan 2026-09-30)
//!
//! - **Registro** (enrolar): el usuario YA tiene sesión; `create()` acuña una passkey
//!   RESIDENTE (resident key) ligada a su cuenta. El reto se liga a ese usuario.
//! - **Login**: el usuario NO teclea su nombre. `get()` con `allowCredentials` vacío deja que
//!   el autenticador ofrezca sus credenciales residentes; la que firma trae su `cred_id`, y
//!   por él —ÚNICO en todo el sistema— se identifica al dueño. Por eso el reto de login NO se
//!   liga a un usuario: es la credencial la que lo revela. Esto además NO ENUMERA: no hay
//!   nombre que teclear ni `allowCredentials` que delate quién tiene passkeys.
//!
//! Un login por passkey con verificación de usuario (PIN/biometría) es multifactor en un solo
//! gesto —posesión + inherencia— y es MÁS fuerte que contraseña+TOTP: la firma va ligada al
//! origen, así que un sitio de phishing no puede reusarla. La contraseña permanece como
//! respaldo (recuperación si se pierde el autenticador).
//!
//! # El contrato de estado (lo que exige `bachue_passkey`)
//!
//! 1. **El reto es de un solo uso** y lo garantiza el servicio: se guarda en
//!    `desafios_passkey` y se CONSUME con compare-and-swap (`db::consumir_desafio_passkey`).
//!    Ese CAS es la defensa de replay PRIMARIA: una respuesta repetida trae el mismo reto, ya
//!    `usado`, y cae antes de verificar nada.
//! 2. **El contador anti-clonación se PERSISTE** (`db::actualizar_contador_passkey`, CAS): es
//!    la única defensa contra un autenticador CLONADO.
//! 3. **La credencial se carga por su `cred_id`** y el usuario sale de la fila, no de nada que
//!    el cliente afirme.

use axum::extract::{Json, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use bachue_passkey::registro::{verificar_registro, Registro};
use bachue_passkey::{
    verificar_assertion, Algoritmo, Assertion, ClavePublicaCose, Credencial, Desafio, Politica,
};
use bachue_passkey_es256::VerificadorEs256;

use crate::db;
use crate::error::Resultado;
use crate::estado::Estado;
use crate::rutas::{comprobar_stepup, cookie_de_sesion, next_seguro, registrar_stepup, usuario_de_sesion};

/// Ventana de vida de un reto de ceremonia: 5 min, como el token pendiente de 2FA. La ceremonia
/// (toque + PIN/biometría) ocurre en segundos; una ventana corta reduce el margen de un reto
/// capturado antes de que el CAS lo invalide igual al usarse.
const TTL_DESAFIO_SEG: i64 = 5 * 60;
/// Tope del apodo opcional de una passkey (etiqueta cosmética; no entra en la cripto).
const APODO_MAX: usize = 64;
/// COSE alg −7: ES256 (ECDSA P-256), el único algoritmo que hoy se registra y verifica.
const COSE_ES256: i64 = -7;

// ───────────────────────── ayudantes ─────────────────────────

fn ahora_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// base64url (RFC 4648 §5) SIN relleno — como WebAuthn codifica los buffers. Es lo que el JS
/// del navegador recibe y devuelve.
fn b64url_enc(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for trozo in bytes.chunks(3) {
        let b0 = trozo[0];
        s.push(T[(b0 >> 2) as usize] as char);
        match trozo.len() {
            1 => s.push(T[((b0 & 0b11) << 4) as usize] as char),
            2 => {
                let b1 = trozo[1];
                s.push(T[(((b0 & 0b11) << 4) | (b1 >> 4)) as usize] as char);
                s.push(T[((b1 & 0b1111) << 2) as usize] as char);
            }
            _ => {
                let (b1, b2) = (trozo[1], trozo[2]);
                s.push(T[(((b0 & 0b11) << 4) | (b1 >> 4)) as usize] as char);
                s.push(T[(((b1 & 0b1111) << 2) | (b2 >> 6)) as usize] as char);
                s.push(T[(b2 & 0b111111) as usize] as char);
            }
        }
    }
    s
}

/// Decodifica base64url, tolerando relleno `=` (algún cliente lo añade). Alfabeto URL
/// ESTRICTO: cualquier carácter fuera de él devuelve `None` (D20: ante lo que no sabe leer, no
/// inventa). También acepta el alfabeto estándar (`+`/`/`) por robustez de entrada.
fn b64url_dec(s: &str) -> Option<Vec<u8>> {
    fn valor(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'-' | b'+' => Some(62),
            b'_' | b'/' => Some(63),
            _ => None,
        }
    }
    let (mut acc, mut nb, mut out) = (0u32, 0u32, Vec::with_capacity(s.len() / 4 * 3));
    for c in s.bytes() {
        if c == b'=' {
            break; // relleno: fin de los datos
        }
        let v = valor(c)?;
        acc = (acc << 6) | v;
        nb += 6;
        if nb >= 8 {
            nb -= 8;
            out.push((acc >> nb) as u8);
        }
    }
    Some(out)
}

/// El `userHandle` de WebAuthn, estable por usuario y derivado del secreto: no revela el
/// nombre de usuario (no es reversible sin el secreto) y no exige una columna nueva. Rotar el
/// secreto lo cambia, pero el login carga por `cred_id` y nunca compara el handle, así que el
/// único efecto es que una re-inscripción tras rotar cree una credencial residente nueva en
/// vez de reemplazar — inocuo.
fn derivar_handle(secreto: &[u8], usuario_id: i64) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(secreto);
    h.update(b"|bachue-idp/passkey-handle-v1|");
    h.update(usuario_id.to_le_bytes());
    h.finalize().to_vec()
}

fn alg_de_cose(cose: i64) -> Option<Algoritmo> {
    match cose {
        COSE_ES256 => Some(Algoritmo::Es256),
        -8 => Some(Algoritmo::EdDSA),
        -257 => Some(Algoritmo::Rs256),
        _ => None,
    }
}

fn cose_de_alg(alg: Algoritmo) -> i64 {
    match alg {
        Algoritmo::Es256 => COSE_ES256,
        Algoritmo::EdDSA => -8,
        Algoritmo::Rs256 => -257,
    }
}

/// Respuesta JSON uniforme de las ceremonias: al cliente, un "sí" o un "no" genérico (el
/// motivo fino va al log del servidor, no al navegador — igual que `Assertion`/`Registro`).
fn ok_json(valor: serde_json::Value) -> Response {
    (StatusCode::OK, Json(valor)).into_response()
}
fn no(codigo: StatusCode) -> Response {
    (codigo, Json(json!({ "ok": false }))).into_response()
}

/// Freno en un endpoint JSON (fetch): `429` + `Retry-After`, cuerpo `{ok:false}`
/// con los segundos que faltan. La espera es pública (backoff determinista, AGPL)
/// y ya viaja en texto en el resto del flujo: no filtra nada nuevo.
fn frenado_json(seg: u64) -> Response {
    let mut resp =
        (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "ok": false, "espera": seg }))).into_response();
    if let Ok(v) = HeaderValue::from_str(&seg.to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
    resp
}

// ───────────────────────── registro (create) ─────────────────────────

/// Cuerpo de `POST /passkey/registrar/inicio`: la contraseña actual (STEP-UP). Se verifica
/// AQUÍ, antes de emitir el reto, para que el reto —un-solo-uso, ligado a este usuario y de
/// TTL corto— sea la prueba de la reautenticación, y para que el `create()` del navegador NO
/// se dispare con una contraseña mala dejando una passkey HUÉRFANA en el llavero del usuario.
#[derive(Deserialize)]
pub struct RegistroInicio {
    #[serde(default)]
    contrasena: String,
}

/// `POST /passkey/registrar/inicio` — arranca el enrolamiento de una passkey. Exige SESIÓN
/// (enrola sobre la cuenta ya autenticada, lo que liga la credencial a ese usuario) y STEP-UP
/// (la contraseña actual del cuerpo, ver `RegistroInicio`). Consume el freno por-usuario,
/// genera y persiste el reto, y devuelve las opciones que el JS pasa a
/// `navigator.credentials.create()`.
pub async fn registrar_inicio(
    State(estado): State<Estado>,
    headers: HeaderMap,
    Json(f): Json<RegistroInicio>,
) -> Resultado<Response> {
    if !estado.cfg.passkey_activo() {
        return Ok(no(StatusCode::NOT_FOUND));
    }
    let Some(usuario) = usuario_de_sesion(&estado, &headers).await? else {
        return Ok(no(StatusCode::UNAUTHORIZED));
    };
    // STEP-UP con FRENO (B1): enrolar un factor exige la contraseña actual, para que una
    // sesión robada no plante una passkey passwordless permanente. El par de contraseña es
    // un oráculo de fuerza bruta para quien ya tiene la cookie → freno por-usuario, aparte
    // del login. Va en `/inicio` (no en `/fin`) por UX-a: falla antes del `create()`.
    if let Some(seg) = comprobar_stepup(&estado, &usuario.usuario).await? {
        return Ok(frenado_json(seg));
    }
    if !bachue::clave::autenticar(Some(&usuario.hash), &f.contrasena) {
        // El fallo provisional ya quedó anotado en `comprobar_stepup`.
        return Ok(no(StatusCode::UNAUTHORIZED));
    }
    registrar_stepup(&estado, &usuario.usuario, true).await?;

    let desafio = Desafio::nuevo();
    db::crear_desafio_passkey(
        &estado.pool,
        desafio.bytes(),
        "registro",
        Some(usuario.id),
        ahora_unix() + TTL_DESAFIO_SEG,
    )
    .await?;

    // excludeCredentials: lo que el usuario ya tiene, para no duplicar en el mismo autenticador.
    let excluir: Vec<serde_json::Value> = db::cred_ids_de_usuario(&estado.pool, usuario.id)
        .await?
        .iter()
        .map(|id| json!({ "type": "public-key", "id": b64url_enc(id) }))
        .collect();

    let handle = derivar_handle(&estado.cfg.secreto, usuario.id);
    Ok(ok_json(json!({
        "challenge": desafio.como_b64url(),
        "rp": { "id": estado.cfg.passkey_rp_id, "name": "Bachué" },
        "user": {
            "id": b64url_enc(&handle),
            "name": usuario.usuario,
            "displayName": usuario.usuario,
        },
        // Solo ES256 (−7): es lo único que el verificador y el registro soportan hoy (D20: no
        // se anuncia lo que no se puede verificar).
        "pubKeyCredParams": [{ "type": "public-key", "alg": COSE_ES256 }],
        // Resident key OBLIGATORIA: sin ella no hay login discoverable (passwordless). UV
        // requerida: la passkey debe ser multifactor en un gesto (su razón de ser aquí).
        "authenticatorSelection": {
            "residentKey": "required",
            "requireResidentKey": true,
            "userVerification": "required",
        },
        "excludeCredentials": excluir,
        "timeout": TTL_DESAFIO_SEG * 1000,
        "attestation": "none",
    })))
}

/// Cuerpo de `POST /passkey/registrar/fin`: lo que el JS extrae de la respuesta de `create()`,
/// todo en base64url. `challenge` se envía explícito para localizar el reto en la BD sin
/// re-parsear el `clientDataJSON` en el servidor; `verificar_registro` comprueba de todos modos
/// que el reto firmado coincide (si el cliente mintiera, `DesafioNoCoincide`).
#[derive(Deserialize)]
pub struct RegistroFin {
    challenge: String,
    id: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "attestationObject")]
    attestation_object: String,
    #[serde(default)]
    apodo: String,
}

/// `POST /passkey/registrar/fin` — termina el enrolamiento: consume el reto, verifica la
/// respuesta y guarda la credencial ligada al usuario de la sesión.
pub async fn registrar_fin(
    State(estado): State<Estado>,
    headers: HeaderMap,
    Json(f): Json<RegistroFin>,
) -> Resultado<Response> {
    if !estado.cfg.passkey_activo() {
        return Ok(no(StatusCode::NOT_FOUND));
    }
    let Some(usuario) = usuario_de_sesion(&estado, &headers).await? else {
        return Ok(no(StatusCode::UNAUTHORIZED));
    };
    // El step-up (contraseña) se verificó en `/registrar/inicio`: el reto que se consume a
    // continuación —un-solo-uso, ligado a ESTE usuario— es la prueba de esa reautenticación.
    // Re-pedir la contraseña aquí sería el mecanismo redundante (D1).
    let (Some(reto), Some(cred_id), Some(cdj), Some(ao)) = (
        b64url_dec(&f.challenge),
        b64url_dec(&f.id),
        b64url_dec(&f.client_data_json),
        b64url_dec(&f.attestation_object),
    ) else {
        return Ok(no(StatusCode::BAD_REQUEST));
    };

    // Consumir el reto (CAS un-solo-uso) y comprobar que era de ESTA ceremonia de registro de
    // ESTE usuario. Un reto ligado a otro usuario, o de login, no sirve.
    let Some(consumido) = db::consumir_desafio_passkey(&estado.pool, &reto, "registro", ahora_unix()).await?
    else {
        return Ok(no(StatusCode::BAD_REQUEST));
    };
    if consumido.usuario_id != Some(usuario.id) {
        return Ok(no(StatusCode::BAD_REQUEST));
    }

    let desafio = Desafio::desde_bytes(reto);
    let r = verificar_registro(
        &desafio,
        &estado.cfg.passkey_origen,
        &estado.cfg.passkey_rp_id,
        &cdj,
        &ao,
        &Politica::default(),
    );
    let Registro::Aceptado(cred) = r else {
        tracing::info!("registro de passkey rechazado: {r:?}");
        return Ok(no(StatusCode::BAD_REQUEST));
    };
    // La credencialId del navegador debe ser la que firma el registro (coherencia del enlace
    // JS→cripto): el `id` del cuerpo tiene que ser el `cred.id` extraído del authData.
    if cred.id != cred_id {
        return Ok(no(StatusCode::BAD_REQUEST));
    }

    let apodo = {
        let a = f.apodo.trim();
        (!a.is_empty()).then(|| a.chars().take(APODO_MAX).collect::<String>())
    };
    let creado = chrono::Utc::now().to_rfc3339();
    match db::crear_credencial_passkey(
        &estado.pool,
        usuario.id,
        &cred.id,
        &cred.clave.0,
        cose_de_alg(cred.alg),
        i64::from(cred.contador),
        apodo.as_deref(),
        &creado,
    )
    .await?
    {
        Some(_) => Ok(ok_json(json!({ "ok": true }))),
        // cred_id ya registrado (UNIQUE): no se re-registra sobre otra.
        None => Ok(no(StatusCode::CONFLICT)),
    }
}

// ───────────────────────── login (get) ─────────────────────────

/// `POST /passkey/login/inicio` — arranca un login passwordless. NO exige sesión ni nombre de
/// usuario: genera un reto de login (sin ligar a nadie) y lo devuelve con `allowCredentials`
/// vacío, para que el autenticador ofrezca sus credenciales residentes (discoverable).
pub async fn login_inicio(State(estado): State<Estado>) -> Resultado<Response> {
    if !estado.cfg.passkey_activo() {
        return Ok(no(StatusCode::NOT_FOUND));
    }
    let desafio = Desafio::nuevo();
    db::crear_desafio_passkey(&estado.pool, desafio.bytes(), "login", None, ahora_unix() + TTL_DESAFIO_SEG)
        .await?;
    Ok(ok_json(json!({
        "challenge": desafio.como_b64url(),
        "rpId": estado.cfg.passkey_rp_id,
        "allowCredentials": [],
        "userVerification": "required",
        "timeout": TTL_DESAFIO_SEG * 1000,
    })))
}

/// Cuerpo de `POST /passkey/login/fin`: lo que el JS extrae de la respuesta de `get()`, en
/// base64url, más el `next` opcional (destino post-login, saneado a ruta relativa propia).
#[derive(Deserialize)]
pub struct LoginFin {
    challenge: String,
    id: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    signature: String,
    #[serde(default)]
    next: String,
}

/// `POST /passkey/login/fin` — verifica la assertion y, si abre, emite la sesión plena. El
/// usuario sale de la credencial (`cred_id` → fila), no de nada que el cliente afirme.
pub async fn login_fin(
    State(estado): State<Estado>,
    Json(f): Json<LoginFin>,
) -> Resultado<Response> {
    if !estado.cfg.passkey_activo() {
        return Ok(no(StatusCode::NOT_FOUND));
    }
    let (Some(reto), Some(cred_id), Some(cdj), Some(ad), Some(firma)) = (
        b64url_dec(&f.challenge),
        b64url_dec(&f.id),
        b64url_dec(&f.client_data_json),
        b64url_dec(&f.authenticator_data),
        b64url_dec(&f.signature),
    ) else {
        return Ok(no(StatusCode::BAD_REQUEST));
    };

    // Consumir el reto de login (CAS). None = desconocido/usado/caducado/otro propósito.
    if db::consumir_desafio_passkey(&estado.pool, &reto, "login", ahora_unix()).await?.is_none() {
        return Ok(no(StatusCode::UNAUTHORIZED));
    }
    // La credencial, por su cred_id (único) → de aquí sale el usuario. Un cred_id desconocido
    // es un "no" genérico, indistinguible de una firma mala (no se enumera).
    let Some(fila) = db::credencial_passkey_por_cred_id(&estado.pool, &cred_id).await? else {
        return Ok(no(StatusCode::UNAUTHORIZED));
    };
    let Some(alg) = alg_de_cose(fila.algoritmo) else {
        // Un algoritmo guardado que no sabemos verificar (no debería pasar: solo se registra
        // ES256). Fail-closed, y al log.
        tracing::error!("credencial passkey {} con algoritmo COSE no soportado: {}", fila.id, fila.algoritmo);
        return Ok(no(StatusCode::UNAUTHORIZED));
    };
    let cred = Credencial {
        id: fila.cred_id.clone(),
        clave: ClavePublicaCose(fila.clave_sec1.clone()),
        alg,
        contador: u32::try_from(fila.contador).unwrap_or(u32::MAX),
    };

    let desafio = Desafio::desde_bytes(reto);
    let veredicto = verificar_assertion(
        &cred,
        &desafio,
        &estado.cfg.passkey_origen,
        &estado.cfg.passkey_rp_id,
        &cdj,
        &ad,
        &firma,
        &Politica::default(),
        &VerificadorEs256,
    );
    let Assertion::Aceptada { contador_nuevo } = veredicto else {
        tracing::info!("assertion de passkey rechazada (cred {}): {veredicto:?}", fila.id);
        return Ok(no(StatusCode::UNAUTHORIZED));
    };

    // Avanzar el contador anti-clonación (CAS). `false` = otra petición concurrente ya lo
    // avanzó con esta misma firma: replay en vuelo, se rechaza (defensa en profundidad; el
    // reto de un solo uso ya cerró el replay secuencial).
    if !db::actualizar_contador_passkey(&estado.pool, fila.id, i64::from(contador_nuevo)).await? {
        return Ok(no(StatusCode::UNAUTHORIZED));
    }

    let Some(usuario) = db::usuario_por_id(&estado.pool, fila.usuario_id).await? else {
        // La fila de credencial apunta a un usuario borrado: no debería ocurrir (sin ON DELETE
        // CASCADE la FK lo impide), pero fail-closed si pasara.
        return Ok(no(StatusCode::UNAUTHORIZED));
    };
    let galleta = cookie_de_sesion(&estado, &usuario);
    let mut resp = ok_json(json!({ "ok": true, "next": next_seguro(&f.next) }));
    if let Ok(v) = axum::http::HeaderValue::from_str(&galleta) {
        resp.headers_mut().append(axum::http::header::SET_COOKIE, v);
    }
    Ok(resp)
}

// ───────────────────────── gestión (panel) ─────────────────────────

/// Cuerpo de `POST /seguridad/passkey/borrar`: el `id` (rowid) de la passkey a quitar.
#[derive(Deserialize)]
pub struct BorrarPasskey {
    id: i64,
    /// Contraseña actual: STEP-UP, igual que al enrolar. Quitar un factor con una cookie
    /// robada también es un ataque (deja a la víctima sin su passkey legítima).
    #[serde(default)]
    contrasena: String,
}

/// `POST /seguridad/passkey/borrar` — quita una passkey del usuario autenticado. Exige sesión;
/// borra solo si la credencial es SUYA (`db::borrar_passkey` filtra por `usuario_id`).
pub async fn borrar(
    State(estado): State<Estado>,
    headers: HeaderMap,
    Json(b): Json<BorrarPasskey>,
) -> Resultado<Response> {
    if !estado.cfg.passkey_activo() {
        return Ok(no(StatusCode::NOT_FOUND));
    }
    let Some(usuario) = usuario_de_sesion(&estado, &headers).await? else {
        return Ok(no(StatusCode::UNAUTHORIZED));
    };
    // STEP-UP con FRENO (B1): quitar un factor exige la contraseña actual, igual
    // que enrolarlo. Mismo cubo por-usuario del step-up, aparte del login.
    if let Some(seg) = comprobar_stepup(&estado, &usuario.usuario).await? {
        return Ok(frenado_json(seg));
    }
    let clave_ok = bachue::clave::autenticar(Some(&usuario.hash), &b.contrasena);
    if !clave_ok {
        // El fallo provisional ya quedó anotado en `comprobar_stepup`.
        return Ok(no(StatusCode::UNAUTHORIZED));
    }
    registrar_stepup(&estado, &usuario.usuario, true).await?;
    if db::borrar_passkey(&estado.pool, b.id, usuario.id).await? {
        Ok(ok_json(json!({ "ok": true })))
    } else {
        Ok(no(StatusCode::NOT_FOUND))
    }
}
