// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! Los handlers: aquí la librería (capa 1) se cablea a HTTP. El IdP no reimplementa
//! autenticación —la orquesta—: `clave` verifica la contraseña, `segundopaso` el TOTP,
//! `sesion` firma el token, `defensas` da la IP del freno y valida el reenvío.

use axum::extract::{ConnectInfo, Form, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use subtle::ConstantTimeEq;

use bachue::defensas::red::{ip_de_reenvio, Confianza};
use bachue::defensas::redireccion::{ruta_relativa_segura, Destino};
use bachue::sesion::Tipo;

use crate::db::{self, Usuario};
use crate::error::Resultado;
use crate::estado::{Config, Estado};
use crate::vista;

const TTL_SESION_MIN: i64 = 12 * 60; // 12 h
const TTL_PENDIENTE_MIN: i64 = 5;
/// El token de reclamo de cuenta ("fija tu contraseña") dura 7 días: el usuario acaba de
/// pagar y puede fijar la clave más tarde. Su caducidad la sostiene la firma del token.
const TTL_RECLAMO_MIN: i64 = 7 * 24 * 60;

// ───────────────────────── formularios ─────────────────────────

#[derive(Deserialize)]
pub struct FormEntrar {
    usuario: String,
    contrasena: String,
    #[serde(default)]
    next: String,
}

#[derive(Deserialize)]
pub struct FormCodigo {
    codigo: String,
    #[serde(default)]
    next: String,
}

#[derive(Deserialize)]
pub struct FormRegistro {
    usuario: String,
    contrasena: String,
}

/// Petición de `POST /aprovisionar` (máquina-a-máquina desde tunjo-saas tras un pago).
#[derive(Deserialize)]
pub struct AprovisionarPeticion {
    usuario: String,
    #[serde(default)]
    referencia: String,
}

/// Respuesta de `POST /aprovisionar`: el `token` de reclamo va solo cuando hay algo que
/// reclamar (no cuando el usuario ya tenía cuenta).
#[derive(Serialize)]
pub struct AprovisionarRespuesta {
    estado: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

/// `POST /establecer`: el usuario canjea el token de reclamo y fija su contraseña.
#[derive(Deserialize)]
pub struct FormEstablecer {
    token: String,
    contrasena: String,
}

#[derive(Deserialize)]
pub struct ConToken {
    #[serde(default)]
    token: String,
}

#[derive(Deserialize)]
pub struct FormConfirmar2fa {
    secreto: String,
    codigo: String,
    /// Step-up: la contraseña actual, exigida para PERSISTIR el cambio de 2FA.
    contrasena: String,
}

#[derive(Deserialize)]
pub struct ConNext {
    #[serde(default)]
    next: String,
}

// ───────────────────────── guardia CSRF ─────────────────────────

/// ¿La petición es de PRIMERA PARTE? Bloquea el CSRF, **incluido el login-CSRF** que
/// `SameSite=Lax` NO cubre —porque no necesita la cookie de la víctima: el atacante
/// aporta SUS credenciales y el servidor fija una cookie nueva, y un `Set-Cookie` de
/// primera parte se honra aunque la petición venga de fuera— (hallazgo del concilio).
///
/// Se apoya en `Sec-Fetch-Site`, que TODO navegador moderno envía y el atacante no puede
/// suprimir (es cabecera prohibida para JavaScript). Criterio: `same-origin` y `none`
/// (navegación directa / marcador) pasan; `same-site` (un subdominio hermano, que
/// SameSite trataría como propio) y `cross-site` se RECHAZAN —un IdP exige mismo ORIGEN,
/// no sólo mismo sitio—. **Ausente** = cliente NO-navegador (curl, otro servicio): se
/// permite, porque el CSRF es un ataque de navegador y esos clientes no lo montan.
fn primera_parte(headers: &HeaderMap) -> bool {
    // Ausente (no-navegador), `same-origin` o `none` (navegación directa) pasan; el resto
    // —`same-site` (subdominio) y `cross-site`— se rechaza.
    matches!(
        headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()),
        None | Some("same-origin" | "none")
    )
}

/// Middleware: CSP estricta en TODA respuesta. bachue-idp sirve htmx, boi.js,
/// boi.css y estilo.css como ARCHIVOS (rutas `/htmx.min.js`…), sin un solo bloque
/// ni atributo inline, así que `script-src 'self'` no rompe nada y cierra el XSS
/// —lo que importa en el núcleo de auth, donde se teclean credenciales—. Las demás
/// cabeceras (X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy) las
/// añade el proxy (snippet `cabeceras-seguridad.conf`); aquí solo va la CSP para no
/// duplicarlas. `frame-ancestors 'none'` = nadie enmarca el login (anti-clickjacking).
pub async fn cabeceras_seguridad(req: Request, siguiente: Next) -> Response {
    let mut r = siguiente.run(req).await;
    r.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            // `font-src 'self' data:` NO es redundante con `img-src`: es una directiva
            // de fetch INDEPENDIENTE que solo hereda de `default-src` (= 'self', sin
            // data:). Sin ella, las 7 tipografías `@font-face` embebidas en boi.css
            // como `src:url(data:font/woff2;…)` se bloquean y la interfaz cae al
            // font del sistema (hallazgo del concilio 2026-09-20, cazado por Sonnet).
            "default-src 'self'; script-src 'self'; style-src 'self'; \
             img-src 'self' data:; font-src 'self' data:; connect-src 'self'; \
             object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    r
}

/// Middleware: rechaza TODO POST que no sea de primera parte. Va como capa —la REGLA,
/// no un chequeo por handler que se pueda olvidar en el próximo endpoint (directiva 23)—.
/// Sólo mira POST. NOTA (concilio 2026-09-24): `GET /authorize` SÍ muta estado (inserta un
/// `oidc_codigo`) usando la cookie de sesión; hoy es inocuo porque el código va SIEMPRE a una
/// `redirect_uri` registrada (first-party) y el RP lo neutraliza con `state`+PKCE —un
/// login-CSRF entregaría al navegador de la víctima un código de SÍ MISMA hacia un RP
/// legítimo—. Si algún día se registra un cliente de menor confianza o un `redirect_uri` con
/// open-redirect, este GET necesitaría su propia guarda (`Sec-Fetch-Site`).
pub async fn guardia_csrf(req: Request, siguiente: Next) -> Response {
    if req.method() == Method::POST && !primera_parte(req.headers()) {
        return (StatusCode::FORBIDDEN, "origen no permitido").into_response();
    }
    siguiente.run(req).await
}

// ───────────────────────── ayudantes ─────────────────────────

/// Hex de ida y vuelta, para guardar el blob binario de `reposo` (secreto TOTP cifrado)
/// en la columna TEXT sin arrastrar una dependencia de base64.
fn a_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}
fn de_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// Cifra el secreto TOTP para guardarlo en reposo (`guaca::reposo`: Argon2→AEAD→Padmé).
fn cifrar_totp(secreto_b32: &str, frase: &str) -> String {
    a_hex(&bachue::reposo::cifrar(secreto_b32.as_bytes(), frase))
}
/// Descifra el secreto TOTP guardado. `None` si el blob está corrupto o la frase no casa.
fn descifrar_totp(guardado: &str, frase: &str) -> Option<String> {
    let bytes = de_hex(guardado)?;
    let claro = bachue::reposo::descifrar(&bytes, frase).ok()?;
    String::from_utf8(claro).ok()
}

fn ahora_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// La IP del cliente para la clave del freno. Sin proxy, la del socket; con proxy, la
/// creíble de `X-Forwarded-For` según el nº de saltos (nunca el extremo izquierdo que el
/// cliente falsea) — [`defensas::red`](bachue::defensas::red).
fn origen(headers: &HeaderMap, socket: SocketAddr, cfg: &Config) -> String {
    if cfg.proxies == 0 {
        return socket.ip().to_string();
    }
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    ip_de_reenvio(xff, Confianza::con_saltos(cfg.proxies)).como_origen()
}

/// El destino post-login, sólo si es una ruta relativa segura de nuestro sitio; si no,
/// la raíz (fail-closed) — [`defensas::redireccion`](bachue::defensas::redireccion).
pub(crate) fn next_seguro(next: &str) -> String {
    match ruta_relativa_segura(next) {
        Destino::Relativo(s) => s,
        _ => "/".to_string(),
    }
}

fn nombre_sesion(cfg: &Config) -> &'static str {
    if cfg.seguro { "__Host-sesion" } else { "sesion" }
}
fn nombre_pendiente(cfg: &Config) -> &'static str {
    if cfg.seguro { "__Host-pendiente" } else { "pendiente" }
}

fn cookie(headers: &HeaderMap, nombre: &str) -> Option<String> {
    let bruto = headers.get(header::COOKIE)?.to_str().ok()?;
    bruto.split(';').find_map(|par| {
        let (k, v) = par.trim().split_once('=')?;
        (k == nombre).then(|| v.to_string())
    })
}

fn fijar_cookie(nombre: &str, valor: &str, cfg: &Config, max_age_seg: i64) -> String {
    let mut c = format!("{nombre}={valor}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_seg}");
    if cfg.seguro {
        c.push_str("; Secure");
    }
    c
}
fn borrar_cookie(nombre: &str, cfg: &Config) -> String {
    fijar_cookie(nombre, "", cfg, 0)
}

/// Un redirect 303 (See Other: POST → GET) con las cookies que se quieran fijar.
/// Una respuesta de freno: el mismo cuerpo de la pantalla, pero con `429 Too Many
/// Requests` y `Retry-After`. El código y la cabecera son la señal HTTP correcta para
/// un cliente o un automatismo; hasta hoy el freno devolvía `200` y `segundos_restantes`
/// se calculaba para una cabecera `Retry-After` que nunca se emitía. No filtra nada
/// nuevo: la espera ya viajaba en el texto del aviso, y el backoff es determinista y
/// público (AGPL), así que un atacante lo deriva igual.
fn frenada(cuerpo: impl IntoResponse, seg: u64) -> Response {
    let mut resp = cuerpo.into_response();
    *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    if let Ok(v) = HeaderValue::from_str(&seg.to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
    resp
}

fn redir(location: &str, cookies: &[String]) -> Response {
    let mut h = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(location) {
        h.insert(header::LOCATION, v);
    }
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            h.append(header::SET_COOKIE, v);
        }
    }
    (StatusCode::SEE_OTHER, h).into_response()
}

/// El usuario de la sesión vigente, o `None`. Comprueba la firma del token Y que su
/// `version` siga siendo la del usuario: subir la versión revoca TODAS sus sesiones.
pub(crate) async fn usuario_de_sesion(estado: &Estado, headers: &HeaderMap) -> Resultado<Option<Usuario>> {
    let Some(token) = cookie(headers, nombre_sesion(&estado.cfg)) else {
        return Ok(None);
    };
    let Some(s) = bachue::sesion::verificar(Tipo::Sesion, &estado.cfg.secreto, &token) else {
        return Ok(None);
    };
    let Some(u) = db::usuario_por_id(&estado.pool, s.usuario_id).await? else {
        return Ok(None);
    };
    if u.version != s.version {
        return Ok(None);
    }
    Ok(Some(u))
}

/// `GET /validar` — objetivo de `auth_request` de nginx para servicios que están
/// DETRÁS de bachue-idp (p. ej. tunjo-saas). Valida la cookie de sesión y, si es
/// buena, devuelve 200 con la cabecera `X-Usuario-Autenticado: <usuario>` que nginx
/// copia hacia el upstream; si no, 401 (nginx lo traduce en redirección al login).
/// No cambia estado, así que la guardia CSRF (solo POST) no aplica.
/// OIDC (veta #1, rebanada 2): publica la clave pública del emisor como **JWKS** para que
/// un Relying Party verifique el `id_token`. Read-only y sin secretos: es la clave PÚBLICA.
/// `Cache-Control` corto — el JWKS es estable pero un RP debe poder ver una rotación.
pub async fn jwks(State(estado): State<Estado>) -> Response {
    // Publica TODAS las generaciones (activa + anteriores): rotación sin invalidar tokens.
    let keys: Vec<serde_json::Value> = estado.oidc_generaciones.iter().map(|c| c.jwk()).collect();
    (
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        axum::Json(serde_json::json!({ "keys": keys })),
    )
        .into_response()
}

/// `GET /.well-known/openid-configuration` — documento de descubrimiento OIDC (veta #1). Ya
/// es honesto (D20): anuncia SOLO lo implementado —authorize, token, jwks, `code` + PKCE
/// S256, ES256—. 404 si OIDC no está configurado (sin issuer no hay proveedor). Read-only.
pub async fn descubrimiento(State(estado): State<Estado>) -> Response {
    let iss = &estado.cfg.emisor_oidc;
    if iss.trim().is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let doc = serde_json::json!({
        "issuer": iss,
        "authorization_endpoint": format!("{iss}/authorize"),
        "token_endpoint": format!("{iss}/token"),
        "userinfo_endpoint": format!("{iss}/userinfo"),
        "jwks_uri": format!("{iss}/jwks"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid"],
        "token_endpoint_auth_methods_supported": ["none"],
    });
    (
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        Json(doc),
    )
        .into_response()
}

/// Añade parámetros a una URL con codificación correcta (no se concatena a mano: `state` y
/// `code` pueden llevar caracteres que romperían la query).
fn con_parametros(base: &str, pares: &[(&str, &str)]) -> String {
    let q = serde_urlencoded::to_string(pares).unwrap_or_default();
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{base}{sep}{q}")
}

/// Reconstruye la URL de `/authorize` con sus parámetros PERO sin `prompt`/`max_age`: es el
/// `next` del rebote de reautenticación, para que tras el re-login no se vuelva a pedir reauth
/// (bucle). Conserva PKCE, `state`, `nonce`, etc.
fn autorizar_sin_reauth(q: &PeticionAutorizar) -> String {
    let mut pares: Vec<(&str, &str)> = vec![
        ("response_type", q.response_type.as_str()),
        ("client_id", q.client_id.as_str()),
        ("redirect_uri", q.redirect_uri.as_str()),
        ("code_challenge", q.code_challenge.as_str()),
    ];
    if let Some(m) = &q.code_challenge_method {
        pares.push(("code_challenge_method", m));
    }
    if let Some(s) = &q.state {
        pares.push(("state", s));
    }
    if let Some(n) = &q.nonce {
        pares.push(("nonce", n));
    }
    con_parametros("/authorize", &pares)
}

/// Parámetros de `GET /authorize` (endpoint de autorización OIDC).
#[derive(Deserialize)]
pub struct PeticionAutorizar {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    /// `prompt` OIDC (space-delimited): `none` (sin UI), `login` (reautenticar). Si no se
    /// maneja, un RP que pide step-up creería que hubo reautenticación sin haberla (concilio,
    /// hallazgo fable).
    #[serde(default)]
    pub prompt: Option<String>,
    /// `max_age` OIDC: antigüedad máxima admisible de la autenticación, en segundos.
    #[serde(default)]
    pub max_age: Option<String>,
}

/// `GET /authorize` — endpoint de autorización OIDC (veta #1, rebanada 3). Config estática:
/// valida `client_id` y `redirect_uri` (coincidencia EXACTA) ANTES de cualquier redirect
/// —así un `redirect_uri` no registrado no se usa jamás (anti open-redirect / robo de
/// código)—. PKCE S256 OBLIGATORIO (clientes públicos). Exige SESIÓN: si no hay, manda al
/// login y vuelve a esta misma URL. Emite un `code` de un solo uso (60 s) y redirige al RP.
pub async fn autorizar(
    State(estado): State<Estado>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    Query(q): Query<PeticionAutorizar>,
) -> Resultado<Response> {
    // 1) Cliente + redirect_uri, antes de nada. Un fallo aquí NO redirige (no hay URI de
    //    confianza todavía): se muestra el error directo.
    let Some(cliente) = estado.cfg.cliente_oidc(&q.client_id) else {
        return Ok((StatusCode::BAD_REQUEST, "client_id desconocido").into_response());
    };
    if !cliente.redirect_uris.iter().any(|u| u == &q.redirect_uri) {
        return Ok((StatusCode::BAD_REQUEST, "redirect_uri no registrada").into_response());
    }
    // Desde aquí el redirect_uri es de CONFIANZA: los errores se devuelven por él (RFC 6749).
    if q.response_type != "code" {
        let mut p = vec![("error", "unsupported_response_type")];
        if let Some(s) = &q.state { p.push(("state", s.as_str())); }
        return Ok(redir(&con_parametros(&q.redirect_uri, &p), &[]));
    }
    if q.code_challenge_method.as_deref() != Some("S256") || q.code_challenge.is_empty() {
        // PKCE S256 obligatorio: sin él, el robo del código sería explotable.
        let mut p = vec![("error", "invalid_request")];
        if let Some(s) = &q.state { p.push(("state", s.as_str())); }
        return Ok(redir(&con_parametros(&q.redirect_uri, &p), &[]));
    }
    // 2) Sesión + prompt/max_age (OIDC Core §3.1.2). Un RP que pide reautenticación (prompt=
    //    login o max_age) NO debe recibir una identidad vieja como si fuera fresca; uno que
    //    pide prompt=none NO debe ver interfaz.
    let prompts: Vec<&str> = q.prompt.as_deref().unwrap_or("").split_whitespace().collect();
    let pide_none = prompts.contains(&"none");
    // `max_age` no se puede satisfar mirando la antigüedad (la sesión no lleva `auth_time`);
    // se satisface CONSERVADORAMENTE forzando reautenticación, que siempre la cumple. `login`
    // igual. (El claim `auth_time` en el id_token queda como mejora posterior.)
    let pide_reauth = prompts.contains(&"login") || q.max_age.is_some();
    let sesion = usuario_de_sesion(&estado, &headers).await?;

    // prompt=none Y reautenticación son contradictorios: no se puede reautenticar sin UI.
    if pide_none && pide_reauth {
        let mut p = vec![("error", "interaction_required")];
        if let Some(s) = &q.state {
            p.push(("state", s.as_str()));
        }
        return Ok(redir(&con_parametros(&q.redirect_uri, &p), &[]));
    }

    let usuario = if pide_reauth {
        // Fuerza reautenticación: al login con `next` = este authorize SIN prompt/max_age, para
        // que tras reautenticarse no vuelva a disparar el reauth (evita el bucle). El re-login
        // en `/entrar` crea una sesión nueva = autenticación fresca.
        let next = autorizar_sin_reauth(&q);
        return Ok(redir(&con_parametros("/entrar", &[("next", next.as_str())]), &[]));
    } else if let Some(u) = sesion {
        u
    } else if pide_none {
        // prompt=none sin sesión: NO se muestra login; se devuelve el error al RP.
        let mut p = vec![("error", "login_required")];
        if let Some(s) = &q.state {
            p.push(("state", s.as_str()));
        }
        return Ok(redir(&con_parametros(&q.redirect_uri, &p), &[]));
    } else {
        // Camino normal: sin sesión, al login y de vuelta a este mismo authorize.
        let aqui = uri.path_and_query().map_or("/authorize", |pq| pq.as_str());
        return Ok(redir(&con_parametros("/entrar", &[("next", aqui)]), &[]));
    };
    // 3) Emitir el código de un solo uso.
    let codigo = bachue_oidc::codigo_aleatorio();
    let expira = chrono::Utc::now().timestamp() + 60;
    db::crear_codigo_oidc(
        &estado.pool,
        &codigo,
        &q.client_id,
        &q.redirect_uri,
        &q.code_challenge,
        &usuario.usuario,
        q.nonce.as_deref(),
        expira,
        usuario.version,
    )
    .await?;
    // 4) De vuelta al RP con `code` (+ `state` si vino).
    let mut p = vec![("code", codigo.as_str())];
    if let Some(s) = &q.state {
        p.push(("state", s.as_str()));
    }
    Ok(redir(&con_parametros(&q.redirect_uri, &p), &[]))
}

/// Cuerpo de `POST /token`.
#[derive(Deserialize)]
pub struct PeticionToken {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub code_verifier: String,
}

#[derive(Serialize)]
struct RespuestaToken {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    id_token: String,
    scope: &'static str,
}

/// Error de `/token` en JSON (RFC 6749 §5.2): 400 + `no-store`.
fn error_token(code: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({ "error": code })),
    )
        .into_response()
}

/// `POST /token` — canjea `code` + PKCE por un `id_token` (veta #1, rebanada 4). Es
/// server-to-server (el guardián CSRF permite POST sin `Sec-Fetch-Site`). Canjea el código
/// de un solo uso, comprueba que es de ESTE cliente y ESTA `redirect_uri`, verifica PKCE, y
/// firma el `id_token` con la clave del emisor. Un `access_token` opaco acompaña (userinfo
/// es una rebanada posterior).
pub async fn token(State(estado): State<Estado>, Form(t): Form<PeticionToken>) -> Response {
    if t.grant_type != "authorization_code" {
        return error_token("unsupported_grant_type");
    }
    if estado.cfg.cliente_oidc(&t.client_id).is_none() {
        return error_token("invalid_client");
    }
    let ahora = chrono::Utc::now().timestamp();
    // Canje de UN SOLO USO (CAS): no existe / ya usado / caducado → invalid_grant.
    let cod = match db::canjear_codigo_oidc(&estado.pool, &t.code, ahora).await {
        Ok(Some(c)) => c,
        _ => return error_token("invalid_grant"),
    };
    // El código tiene que ser de ESTE cliente y ESTA redirect_uri (RFC 6749 §4.1.3).
    if cod.cliente != t.client_id || cod.redirect_uri != t.redirect_uri {
        return error_token("invalid_grant");
    }
    // PKCE: el verifier debe casar el challenge guardado (si no, el código robado no vale).
    if !bachue_oidc::pkce_s256_ok(&t.code_verifier, &cod.code_challenge) {
        return error_token("invalid_grant");
    }
    let claims = bachue_oidc::claims_id_token(
        &estado.cfg.emisor_oidc,
        &cod.sub,
        &t.client_id,
        ahora,
        3600,
        cod.nonce.as_deref(),
    );
    // Versión del usuario al emitir: `/userinfo` la comparará con la versión ACTUAL, de modo
    // que `salir` (que sube `version`) invalide también el access_token OIDC, no solo la
    // cookie de sesión. Si el usuario se borró entre authorize y token, invalid_grant
    // (fail-closed): no se emite un token que apunte a un sujeto inexistente.
    let version = match db::usuario_por_nombre(&estado.pool, &cod.sub).await {
        Ok(Some(u)) => u.version,
        _ => return error_token("invalid_grant"),
    };
    // El código se emitió en `/authorize` con la `version` de entonces; si cambió —p. ej.
    // `salir` subió `version` entre `/authorize` y `/token`— el código pendiente YA NO vale:
    // invalid_grant. Así el logout invalida también los códigos en vuelo, no solo las sesiones
    // y los tokens ya emitidos (concilio 2026-10-18, hallazgo fable; `ver` nulo de un código
    // pre-migración también cae aquí, fail-closed).
    if cod.ver != Some(version) {
        return error_token("invalid_grant");
    }
    // El access_token es un JWT ES256 auto-contenido (sin estado en BD): `typ:"at"` lo
    // distingue del id_token, así un id_token NO vale como bearer en /userinfo. Lo verifica
    // el propio IdP con su clave pública. `ver` liga el token a la generación de sesión del
    // usuario para que el logout lo pueda invalidar en `/userinfo`.
    let at_claims = serde_json::json!({
        "iss": estado.cfg.emisor_oidc,
        "sub": cod.sub,
        "iat": ahora,
        "exp": ahora + 3600,
        "scope": "openid",
        "typ": "at",
        "ver": version,
    });
    let resp = RespuestaToken {
        access_token: estado.oidc_activa().firmar_id_token(&at_claims),
        token_type: "Bearer",
        expires_in: 3600,
        id_token: estado.oidc_activa().firmar_id_token(&claims),
        scope: "openid",
    };
    (StatusCode::OK, [(header::CACHE_CONTROL, "no-store")], Json(resp)).into_response()
}

/// `GET /userinfo` — endpoint UserInfo OIDC (veta #1). Autentica por `Authorization: Bearer
/// <access_token>` (JWT ES256 auto-contenido), verifica firma + `exp` + `typ:"at"` (un
/// id_token NO vale como bearer), y devuelve los claims del sujeto. Read-only.
pub async fn userinfo(State(estado): State<Estado>, headers: HeaderMap) -> Response {
    let no_autorizado = |motivo: &str| {
        let reto = if motivo.is_empty() {
            "Bearer".to_string()
        } else {
            format!("Bearer error=\"{motivo}\"")
        };
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, reto)],
            Json(serde_json::json!({ "error": if motivo.is_empty() { "invalid_request" } else { motivo } })),
        )
            .into_response()
    };

    let Some(bearer) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    else {
        return no_autorizado("");
    };
    // Verifica contra CUALQUIER generación publicada (activa + anteriores): un access_token
    // firmado antes de rotar sigue siendo válido mientras su clave se publique (concilio D33).
    let Some(claims) = estado
        .oidc_generaciones
        .iter()
        .find_map(|c| bachue_oidc::verificar_es256(bearer, &c.verificador()))
    else {
        return no_autorizado("invalid_token"); // firma inválida con ninguna clave, o formato roto
    };
    // Debe ser un ACCESS token (no un id_token reusado) y no estar caducado.
    if claims.get("typ").and_then(|v| v.as_str()) != Some("at") {
        return no_autorizado("invalid_token");
    }
    let ahora = chrono::Utc::now().timestamp();
    if claims.get("exp").and_then(serde_json::Value::as_i64).unwrap_or(0) <= ahora {
        return no_autorizado("invalid_token");
    }
    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or_default();
    // El token lleva la `ver` del usuario al emitirse; se compara con la version ACTUAL, de
    // modo que `salir` (que sube `version`) invalide el access_token aunque no haya caducado.
    // Fail-closed: sin `ver` en el token, o si el usuario ya no existe, o si la versión no
    // coincide (sesiones revocadas / logout), es invalid_token. Esto cierra el hueco de que
    // un access_token OIDC sobreviva al logout (antes solo se miraba firma+typ+exp).
    let ver_token = claims.get("ver").and_then(serde_json::Value::as_i64);
    let version_actual = match db::usuario_por_nombre(&estado.pool, sub).await {
        Ok(Some(u)) => u.version,
        _ => return no_autorizado("invalid_token"),
    };
    if ver_token != Some(version_actual) {
        return no_autorizado("invalid_token");
    }
    Json(serde_json::json!({ "sub": sub })).into_response()
}

pub async fn validar(State(estado): State<Estado>, headers: HeaderMap) -> Resultado<Response> {
    match usuario_de_sesion(&estado, &headers).await? {
        Some(u) => match HeaderValue::from_str(&u.usuario) {
            Ok(valor) => {
                let mut resp = StatusCode::OK.into_response();
                resp.headers_mut().insert("x-usuario-autenticado", valor);
                Ok(resp)
            }
            // Un usuario cuyo nombre no cabe en una cabecera no se puede transmitir
            // con seguridad: se niega en vez de emitir una identidad ambigua.
            Err(_) => Ok(StatusCode::UNAUTHORIZED.into_response()),
        },
        None => Ok(StatusCode::UNAUTHORIZED.into_response()),
    }
}

/// ¿Frenado el par (usuario, origen)? Devuelve los segundos que faltan, si lo está.
async fn frenado(estado: &Estado, usuario: &str, origen: &str) -> Resultado<Option<u64>> {
    let ahora = chrono::Utc::now();
    let corte = bachue::freno::corte_retencion(ahora).to_rfc3339();
    let filas = db::intentos_desde(&estado.pool, usuario, origen, &corte).await?;
    let intentos: Vec<bachue::freno::Intento> = filas
        .iter()
        .map(|(m, e)| bachue::freno::Intento { momento: m, exito: *e })
        .collect();
    let est = bachue::freno::evaluar(&intentos, ahora);
    Ok(est.frenado().then(|| est.segundos_restantes()))
}

/// Origen SENTINELA del cubo de freno del STEP-UP (reautenticación con la
/// contraseña sobre una sesión YA abierta: enrolar/borrar una passkey, confirmar
/// el 2FA). Es un cubo POR USUARIO, aparte del login, por el modelo de amenaza:
/// quien ataca el step-up YA tiene la cookie, así que rota su IP a voluntad y un
/// freno por `(usuario, IP)` no frenaría nada; y un cepo de step-up no debe poder
/// bloquear el LOGIN del titular, ni al revés. El valor no colisiona nunca con un
/// origen real —una IP o un host, que jamás empiezan por `@`—, así que comparte
/// la misma tabla `intentos` sin mezclarse con el cubo del login (D32: el origen
/// es la CLAVE del cubo, y éste es un cubo global legítimo del usuario).
pub(crate) const ORIGEN_STEPUP: &str = "@step-up";

/// Serializa la sección crítica «comprobar freno + anotar intento» de TODA puerta con
/// freno (login, segundo factor y step-up). El motor del freno es check-then-act
/// (SELECT → decidir → INSERT); sin exclusión, una ráfaga concurrente pasa el umbral
/// entero, porque todas leen el cubo por debajo del umbral antes de que ninguna escriba
/// (una verificación cara entre medias —Argon2— ENSANCHA la ventana). bachue-idp es UN
/// proceso con un pool a un único SQLite, así que un Mutex de proceso cierra la carrera
/// sin transacciones: dos peticiones no pueden ver ambas el cubo por debajo del umbral.
/// La verificación (Argon2, TOTP) queda FUERA del lock (la sección crítica son dos
/// consultas rápidas), así que serializarla no cuesta nada medible. (Hallazgo del
/// concilio 2026-10-06, medido: 40 peticiones simultáneas pasaban 40/40 sin este lock.)
static FRENO_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

/// ATÓMICO bajo `FRENO_LOCK`: si `(usuario, origen)` NO está frenado, anota un intento
/// PROVISIONAL de fallo y devuelve `Ok(id)` del provisional (sigue el flujo); si está
/// frenado, no anota nada y devuelve `Err(seg)`. Anotar el fallo DENTRO de la sección
/// crítica —antes de la verificación cara, que corre fuera— es lo que cierra la carrera:
/// una ráfaga concurrente se cuenta intento a intento, y la 6.ª ve el cubo lleno.
/// Después, el llamante resuelve el provisional según el resultado: lo DEJA si fue fallo,
/// registra un acierto (que `freno::evaluar` usa para reiniciar) si fue éxito pleno, o lo
/// BORRA por `id` si el intento no debe contar NI reiniciar (acierto de contraseña sobre
/// una cuenta con 2FA: el reinicio dejaría al que ya tiene la contraseña resetear el cubo
/// del segundo factor, y el provisional dejaría un fallo espurio contra el titular).
pub(crate) async fn comprobar_freno(
    estado: &Estado,
    usuario: &str,
    origen: &str,
) -> Resultado<Result<i64, u64>> {
    let _guard = FRENO_LOCK.lock().await;
    if let Some(seg) = frenado(estado, usuario, origen).await? {
        return Ok(Err(seg));
    }
    let momento = chrono::Utc::now().to_rfc3339();
    let id = db::registrar_intento_prov(&estado.pool, usuario, origen, &momento).await?;
    Ok(Ok(id))
}

/// Puerta de freno del step-up (reautenticación con contraseña sobre una sesión ya
/// abierta: enrolar/borrar passkey, confirmar 2FA). Envuelve `comprobar_freno` sobre el
/// cubo `@step-up`; descarta el `id` porque el step-up resuelve el provisional por la vía
/// simple (acierto → `registrar_stepup(.., true)` reinicia; fallo → se queda).
pub(crate) async fn comprobar_stepup(estado: &Estado, usuario: &str) -> Resultado<Option<u64>> {
    match comprobar_freno(estado, usuario, ORIGEN_STEPUP).await? {
        Ok(_id) => Ok(None),
        Err(seg) => Ok(Some(seg)),
    }
}

/// Anota en el cubo de step-up el resultado de una reautenticación. Se llama con
/// `true` tras un ACIERTO de contraseña: `freno::evaluar` reinicia el retroceso
/// ante un acierto legible, así que borra el fallo provisional que dejó
/// `comprobar_stepup`. (El fallo ya quedó anotado dentro de la sección crítica;
/// quien NO acierta no llama aquí y el provisional se queda, que es lo que cuenta.)
pub(crate) async fn registrar_stepup(estado: &Estado, usuario: &str, ok: bool) -> Resultado<()> {
    let momento = chrono::Utc::now().to_rfc3339();
    db::registrar_intento(&estado.pool, usuario, ORIGEN_STEPUP, &momento, ok).await
}

// ───────────────────────── handlers ─────────────────────────

/// `/` — el panel si hay sesión; si no, al login.
pub async fn index(State(estado): State<Estado>, headers: HeaderMap) -> Resultado<Response> {
    match usuario_de_sesion(&estado, &headers).await? {
        Some(u) => {
            let passkeys = if estado.cfg.passkey_activo() {
                db::passkeys_de_usuario(&estado.pool, u.id).await?
            } else {
                Vec::new()
            };
            Ok(vista::panel(&u.usuario, u.tiene_2fa(), &passkeys, estado.cfg.passkey_activo()).into_response())
        }
        None => Ok(redir("/entrar", &[])),
    }
}

pub async fn entrar_get(State(estado): State<Estado>, Query(q): Query<ConNext>) -> Response {
    vista::entrar(None, &next_seguro(&q.next), estado.cfg.registro_abierto, estado.cfg.passkey_activo()).into_response()
}

pub async fn entrar_post(
    State(estado): State<Estado>,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(f): Form<FormEntrar>,
) -> Resultado<Response> {
    let cfg = &estado.cfg;
    let next = next_seguro(&f.next);
    let origen = origen(&headers, socket, cfg);
    // `trim` como en el registro: `" ana"` y `"ana"` son la misma cuenta, y así comparten
    // cubo de freno en vez de darle al atacante uno nuevo por cada espacio añadido.
    let tecleado = f.usuario.trim();

    // Freno ANTES de gastar un Argon2, con CIERRE DE CARRERA (concilio 2026-10-18): el
    // provisional de fallo se anota atómicamente bajo `FRENO_LOCK` antes del Argon2, así una
    // ráfaga concurrente se cuenta intento a intento en vez de pasar el umbral entera. Si ya
    // está frenado, ni se intenta.
    let prov = match comprobar_freno(&estado, tecleado, &origen).await? {
        Ok(id) => id,
        Err(seg) => {
            let msg = format!("Demasiados intentos. Espera {seg} s.");
            return Ok(frenada(vista::entrar(Some(&msg), &next, cfg.registro_abierto, cfg.passkey_activo()), seg));
        }
    };

    let usuario = db::usuario_por_nombre(&estado.pool, tecleado).await?;
    // `clave::autenticar` SIEMPRE corre un Argon2 (real o de descarte): un usuario que no
    // existe cuesta lo mismo que uno que sí (anti-enumeración por tiempo).
    let ok = bachue::clave::autenticar(usuario.as_ref().map(|u| u.hash.as_str()), &f.contrasena);

    // Resolver el provisional:
    //  - FALLO (`!ok`): se DEJA → cuenta para el retroceso (fuerza bruta de contraseña), con
    //    o sin 2FA.
    //  - ACIERTO sin 2FA: autenticación plena → se registra un ÉXITO que `freno::evaluar` usa
    //    para reiniciar el cubo (el provisional, anterior al éxito, queda tapado).
    //  - ACIERTO con 2FA: NO se registra éxito —reiniciar le daría a quien ya tiene la
    //    contraseña un cubo nuevo por ciclo y el retroceso nunca escalaría para el segundo
    //    factor—, pero el provisional tampoco debe contar contra el titular legítimo, así que
    //    se BORRA. El éxito de la PAREJA lo registra `segundo_factor_post` al pasar el 2FA.
    let con_2fa = usuario.as_ref().is_some_and(|u| u.tiene_2fa());
    if ok && !con_2fa {
        let momento = chrono::Utc::now().to_rfc3339();
        db::registrar_intento(&estado.pool, tecleado, &origen, &momento, true).await?;
    } else if ok && con_2fa {
        db::borrar_intento(&estado.pool, prov).await?;
    }

    if !ok {
        return Ok(vista::entrar(Some("Usuario o contraseña incorrectos."), &next, cfg.registro_abierto, cfg.passkey_activo()).into_response());
    }
    let usuario = usuario.expect("autenticar sólo es true con un usuario real");

    if usuario.tiene_2fa() {
        // Falta el segundo factor: token PENDIENTE (no una sesión plena) + a la pantalla.
        let pend = bachue::sesion::emitir(
            Tipo::PendienteSegundoFactor,
            &cfg.secreto,
            usuario.id,
            usuario.version,
            TTL_PENDIENTE_MIN,
        );
        let galleta = fijar_cookie(nombre_pendiente(cfg), &pend, cfg, TTL_PENDIENTE_MIN * 60);
        let destino = format!("/segundo-factor?next={}", pct(&next));
        Ok(redir(&destino, &[galleta]))
    } else if debe_forzar_enrolar_2fa(&estado, &usuario).await? {
        // La política EXIGE 2FA y este usuario no lo tiene (estricto, o gracia vencida): a la
        // pantalla de enrolamiento con un token de media autenticación, sin sesión plena hasta
        // que active el segundo factor (el confirmar emitirá la sesión).
        Ok(redir("/seguridad/2fa", &[cookie_enrolamiento_forzado(&estado, &usuario)]))
    } else {
        Ok(redir(&next, &[cookie_de_sesion(&estado, &usuario)]))
    }
}

pub async fn segundo_factor_get(
    State(estado): State<Estado>,
    headers: HeaderMap,
    Query(q): Query<ConNext>,
) -> Resultado<Response> {
    if pendiente_valido(&estado, &headers).await?.is_none() {
        return Ok(redir("/entrar", &[]));
    }
    Ok(vista::segundo_factor(None, &next_seguro(&q.next)).into_response())
}

pub async fn segundo_factor_post(
    State(estado): State<Estado>,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(f): Form<FormCodigo>,
) -> Resultado<Response> {
    let cfg = &estado.cfg;
    let Some(usuario) = pendiente_valido(&estado, &headers).await? else {
        return Ok(redir("/entrar", &[]));
    };
    let Some(guardado) = usuario.totp_secret.clone() else {
        // Sin secreto no hay segundo paso que dar: de vuelta al login.
        return Ok(redir("/entrar", &[]));
    };
    let Some(secreto_totp) = descifrar_totp(&guardado, &estado.cfg.frase_totp) else {
        // El secreto guardado no descifra: BD corrupta o frase de despliegue equivocada.
        // Es un error de servidor (no del usuario), y así se registra.
        return Err(crate::error::Error::Interno("el secreto TOTP guardado no descifra".into()));
    };
    let next = next_seguro(&f.next);
    let origen = origen(&headers, socket, cfg);

    // Freno con cierre de carrera (concilio 2026-10-18): el provisional de fallo se anota
    // bajo `FRENO_LOCK` antes de verificar el código, igual que el login. El id se descarta
    // porque aquí no hay «acierto que no debe contar»: el éxito del 2º factor reinicia y el
    // fallo deja el provisional.
    if let Err(seg) = comprobar_freno(&estado, &usuario.usuario, &origen).await? {
        let msg = format!("Demasiados intentos. Espera {seg} s.");
        return Ok(frenada(vista::segundo_factor(Some(&msg), &next), seg));
    }

    // Los códigos de recuperación VIVOS entran en la decisión: un `SuperadoRecuperacion`
    // deja entrar por su vía a quien perdió el autenticador. `segundo_paso` enruta según el
    // formato (ocho-guion-ocho) y devuelve el `indice` del código gastado para retirarlo.
    let hashes = db::codigos_recuperacion_vivos(&estado.pool, usuario.id).await?;
    let enrol = bachue::segundopaso::Enrolamiento {
        secreto_totp_b32: &secreto_totp,
        ultimo_contador: usuario.totp_contador.map(|c| c as u64),
        hashes_recuperacion: &hashes,
    };
    // Normalizar a MAYÚSCULAS: guaca genera los códigos en A–Z2–7, y quien lo dicta por
    // teléfono puede teclearlo en minúsculas; sin esto un código válido se rechazaría y
    // CONTARÍA como fallo del freno (obs. del concilio). El TOTP son dígitos: no lo toca.
    let tecleado = f.codigo.trim().to_uppercase();
    let resol = bachue::segundopaso::segundo_paso(&enrol, &tecleado, ahora_unix());

    // Resolver el provisional: ÉXITO del 2º factor → se registra un acierto que
    // `freno::evaluar` usa para reiniciar el cubo (tapa el provisional); FALLO → el
    // provisional ya anotado se queda y cuenta para el retroceso.
    if resol.abre() {
        let momento = chrono::Utc::now().to_rfc3339();
        db::registrar_intento(&estado.pool, &usuario.usuario, &origen, &momento, true).await?;
    } else {
        return Ok(vista::segundo_factor(Some("Código incorrecto."), &next).into_response());
    }
    // Anti-replay por las DOS vías (TOCTOU): el compare-and-swap devuelve `false` si otra
    // petición concurrente ya gastó este código — el contador del TOTP, o el de recuperación.
    // `true` = ya estaba gastado → se trata como replay.
    let ya_gastado = match resol {
        bachue::segundopaso::Resolucion::SuperadoTotp { contador } => {
            !db::actualizar_contador_totp(&estado.pool, usuario.id, contador as i64).await?
        }
        // Retira EXACTAMENTE el código de recuperación gastado (un solo uso), por su hash y
        // usuario — no por un rowid reciclable (concilio).
        bachue::segundopaso::Resolucion::SuperadoRecuperacion { indice } => {
            !db::marcar_codigo_recuperacion_usado(&estado.pool, usuario.id, &hashes[indice]).await?
        }
        _ => false,
    };
    if ya_gastado {
        return Ok(vista::segundo_factor(Some("Código ya utilizado."), &next).into_response());
    }

    // Sesión PLENA; se borra el token pendiente.
    Ok(redir(
        &next,
        &[cookie_de_sesion(&estado, &usuario), borrar_cookie(nombre_pendiente(cfg), cfg)],
    ))
}

/// El aviso al USUARIO que elige una contraseña rechazada — honesto sobre el motivo (un
/// «demasiado corta» ante una predecible sería un dato falso, directiva 20). El match es
/// exhaustivo a propósito: una variante nueva de `Rechazo` no compila hasta darle su texto.
fn aviso_de_rechazo(motivo: &bachue::clave::Rechazo) -> String {
    match motivo {
        bachue::clave::Rechazo::DemasiadoCorta { minimo } => {
            format!("La contraseña debe tener al menos {minimo} caracteres.")
        }
        bachue::clave::Rechazo::Predecible => {
            "La contraseña es demasiado predecible: evita repeticiones, secuencias o teclas seguidas.".to_string()
        }
    }
}

pub async fn registrarse_get(State(estado): State<Estado>) -> Response {
    if !estado.cfg.registro_abierto {
        return (StatusCode::NOT_FOUND, vista::registro_cerrado()).into_response();
    }
    vista::registro(None, "").into_response()
}

pub async fn registrarse_post(
    State(estado): State<Estado>,
    Form(f): Form<FormRegistro>,
) -> Resultado<Response> {
    // Registro cerrado (pago primero): el POST tampoco crea cuenta. La guardia va aquí, en
    // el endpoint que ESCRIBE, no solo en la pantalla (directiva 23: la regla, no el caso).
    if !estado.cfg.registro_abierto {
        return Ok((StatusCode::NOT_FOUND, vista::registro_cerrado()).into_response());
    }
    let usuario = f.usuario.trim();
    if usuario.is_empty() || usuario.len() > 64 {
        return Ok(vista::registro(Some("El usuario debe tener entre 1 y 64 caracteres."), usuario).into_response());
    }
    // Política de contraseña (bachue::clave). Un rechazo se DIBUJA, no es un `Error`.
    if let Err(motivo) = bachue::clave::Politica::default().admite(&f.contrasena) {
        return Ok(vista::registro(Some(&aviso_de_rechazo(&motivo)), usuario).into_response());
    }
    let Some(hash) = bachue::clave::hashear(&f.contrasena) else {
        return Ok(vista::registro(Some("No se pudo procesar la contraseña."), usuario).into_response());
    };
    let creado = chrono::Utc::now().to_rfc3339();
    match db::crear_usuario(&estado.pool, usuario, &hash, &creado).await? {
        None => Ok(vista::registro(Some("Ese usuario ya existe."), usuario).into_response()),
        Some(id) => {
            let u = Usuario {
                id,
                usuario: usuario.to_string(),
                hash,
                version: 0,
                totp_secret: None,
                totp_contador: None,
                enrolar_2fa_antes_de: None,
            };
            // Usuario NUEVO: si la política exige 2FA, nace CON él. La ventana de gracia queda
            // YA vencida (= creación), así que si abandona el enrolamiento y reloguea, se le
            // fuerza igual y NO hereda los 7 días de un legado (hallazgo del concilio: sin esto,
            // `gracia` regalaba la ventana a los nuevos).
            if estado.cfg.dos_factor.exige() {
                db::fijar_limite_enrolar_2fa(&estado.pool, id, &creado).await?;
                Ok(redir("/seguridad/2fa", &[cookie_enrolamiento_forzado(&estado, &u)]))
            } else {
                Ok(redir("/", &[cookie_de_sesion(&estado, &u)]))
            }
        }
    }
}

pub async fn salir_post(State(estado): State<Estado>, headers: HeaderMap) -> Response {
    // REVOCA la sesión en el servidor, no solo borra la cookie del navegador:
    // subir `version` invalida el token stateless (un token copiado antes de salir
    // deja de validar). Revoca TODOS los dispositivos del usuario, que es el cierre
    // de sesión correcto para un IdP. Si no hay sesión válida (cookie ausente o ya
    // caducada) no hay a quién revocar y se limpia la cookie igual. Un fallo de BD
    // al revocar NO impide borrar la cookie —degrada al comportamiento anterior
    // (cookie borrada sin revocar), no a algo peor—.
    if let Ok(Some(usuario)) = usuario_de_sesion(&estado, &headers).await
        && let Err(e) = db::revocar_sesiones(&estado.pool, usuario.id).await
    {
        // Un logout que NO revocó se ve igual que uno que sí: que el operador lo
        // vea (D20/D30). No filtra secreto —solo el id del usuario—; la cookie se
        // borra igual (degrada al comportamiento anterior, no a algo peor).
        tracing::warn!(usuario_id = usuario.id, error = %e, "salir: no se pudo revocar la sesión; se borra la cookie igual");
    }
    redir("/entrar", &[borrar_cookie(nombre_sesion(&estado.cfg), &estado.cfg)])
}

/// Compara el secreto compartido en TIEMPO CONSTANTE. Longitudes distintas no son secreto
/// (y `ct_eq` de `subtle` ya las descarta en tiempo constante); el contenido se compara sin
/// filtrar por el primer byte que difiere.
fn secreto_coincide(esperado: &[u8], presentado: &[u8]) -> bool {
    esperado.ct_eq(presentado).into()
}

/// `POST /aprovisionar` — máquina-a-máquina: tunjo-saas la llama tras verificar un pago de
/// Paddle. Autenticada por el SECRETO COMPARTIDO en la cabecera `X-Aprovisionar-Secreto`
/// (tiempo constante); sin él → 401; sin secreto configurado → 503 (fail-closed, no un
/// secreto por defecto). Crea el reclamo y devuelve el token de "fija tu contraseña".
/// NO fija contraseña ni crea la cuenta con clave: eso lo hace el USUARIO en `/establecer`.
pub async fn aprovisionar_post(
    State(estado): State<Estado>,
    headers: HeaderMap,
    Json(p): Json<AprovisionarPeticion>,
) -> Resultado<Response> {
    let Some(esperado) = estado.cfg.secreto_aprovisionar.as_deref() else {
        return Ok((StatusCode::SERVICE_UNAVAILABLE, "aprovisionamiento no configurado").into_response());
    };
    let presentado = headers.get("x-aprovisionar-secreto").map(|v| v.as_bytes());
    if !presentado.map(|b| secreto_coincide(esperado, b)).unwrap_or(false) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let usuario = p.usuario.trim();
    if usuario.is_empty() || usuario.len() > 64 {
        return Ok((StatusCode::BAD_REQUEST, "usuario inválido").into_response());
    }
    let creado = chrono::Utc::now().to_rfc3339();
    let resp = match db::aprovisionar(&estado.pool, usuario, &p.referencia, &creado).await? {
        db::Aprovisionamiento::Pendiente { id, version } => {
            let token = bachue::sesion::emitir(
                Tipo::Recuperacion,
                &estado.cfg.secreto,
                id,
                version,
                TTL_RECLAMO_MIN,
            );
            (
                StatusCode::OK,
                Json(AprovisionarRespuesta { estado: "provisionado", token: Some(token) }),
            )
                .into_response()
        }
        db::Aprovisionamiento::YaTieneCuenta => (
            StatusCode::OK,
            Json(AprovisionarRespuesta { estado: "ya_tiene_cuenta", token: None }),
        )
            .into_response(),
        db::Aprovisionamiento::YaReclamada => (
            StatusCode::CONFLICT,
            Json(AprovisionarRespuesta { estado: "ya_reclamada", token: None }),
        )
            .into_response(),
    };
    Ok(resp)
}

/// Petición de `POST /seguridad/2fa/reset` (máquina-a-máquina, OPERADOR).
#[derive(Deserialize)]
pub struct Reset2faPeticion {
    usuario: String,
}

/// `POST /seguridad/2fa/reset` — reseteo de 2FA por OPERADOR, autenticado con el MISMO secreto
/// M2M que `/aprovisionar` (mismo nivel de confianza: el backend). Borra el secreto TOTP, el
/// contador, la ventana de gracia y los códigos de recuperación del usuario. Es la salida de
/// emergencia para el doble-extravío (autenticador + códigos); sin ella, el 2FA obligatorio
/// fabricaría cuentas muertas. NO emite sesión: el usuario vuelve a entrar y a enrolar.
pub async fn reset_2fa_post(
    State(estado): State<Estado>,
    headers: HeaderMap,
    Json(p): Json<Reset2faPeticion>,
) -> Resultado<Response> {
    let Some(esperado) = estado.cfg.secreto_aprovisionar.as_deref() else {
        return Ok((StatusCode::SERVICE_UNAVAILABLE, "operación no configurada").into_response());
    };
    let presentado = headers.get("x-aprovisionar-secreto").map(|v| v.as_bytes());
    if !presentado.map(|b| secreto_coincide(esperado, b)).unwrap_or(false) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let usuario = p.usuario.trim();
    if usuario.is_empty() || usuario.len() > 64 {
        return Ok((StatusCode::BAD_REQUEST, "usuario inválido").into_response());
    }
    let Some(u) = db::usuario_por_nombre(&estado.pool, usuario).await? else {
        return Ok((StatusCode::NOT_FOUND, "usuario no encontrado").into_response());
    };
    db::limpiar_2fa(&estado.pool, u.id).await?;
    Ok((StatusCode::OK, "2fa reseteado").into_response())
}

/// `GET /establecer?token=…` — la pantalla para fijar la contraseña. Valida la FIRMA del
/// token antes de dibujar el formulario (un enlace vencido no ofrece un formulario muerto).
pub async fn establecer_get(State(estado): State<Estado>, Query(q): Query<ConToken>) -> Response {
    match bachue::sesion::verificar(Tipo::Recuperacion, &estado.cfg.secreto, &q.token) {
        Some(_) => vista::establecer(&q.token, None).into_response(),
        None => (StatusCode::BAD_REQUEST, vista::establecer_no_vale()).into_response(),
    }
}

/// `POST /establecer` — canjea el token (un solo uso) y crea la cuenta con la contraseña
/// que el usuario eligió. Al terminar, sesión iniciada.
pub async fn establecer_post(
    State(estado): State<Estado>,
    Form(f): Form<FormEstablecer>,
) -> Resultado<Response> {
    // El token: firmado, dominio Recuperacion, no vencido (la caducidad está en la firma).
    let Some(s) = bachue::sesion::verificar(Tipo::Recuperacion, &estado.cfg.secreto, &f.token) else {
        return Ok((StatusCode::BAD_REQUEST, vista::establecer_no_vale()).into_response());
    };
    // Política de contraseña: un rechazo se DIBUJA (no es un Error de servidor).
    if let Err(motivo) = bachue::clave::Politica::default().admite(&f.contrasena) {
        return Ok(vista::establecer(&f.token, Some(&aviso_de_rechazo(&motivo))).into_response());
    }
    let Some(hash) = bachue::clave::hashear(&f.contrasena) else {
        return Ok(vista::establecer(&f.token, Some("No se pudo procesar la contraseña.")).into_response());
    };
    let creado = chrono::Utc::now().to_rfc3339();
    match db::reclamar_provision(&estado.pool, s.usuario_id, &hash, &creado).await? {
        db::Reclamo::Creada { id, usuario, version } => {
            let u = Usuario {
                id,
                usuario,
                hash,
                version,
                totp_secret: None,
                totp_contador: None,
                enrolar_2fa_antes_de: None,
            };
            // Usuario NUEVO: si la política exige 2FA, nace CON él. La ventana de gracia queda YA
            // vencida (= creación): si abandona el enrolamiento y reloguea, se le fuerza igual y
            // no hereda los 7 días de un legado (hallazgo del concilio).
            if estado.cfg.dos_factor.exige() {
                db::fijar_limite_enrolar_2fa(&estado.pool, id, &creado).await?;
                Ok(redir("/seguridad/2fa", &[cookie_enrolamiento_forzado(&estado, &u)]))
            } else {
                Ok(redir("/", &[cookie_de_sesion(&estado, &u)]))
            }
        }
        // La cuenta ya existía (carrera): el token quedó gastado; a entrar con normalidad.
        db::Reclamo::YaExistia => Ok(redir("/entrar", &[])),
        db::Reclamo::NoVale => {
            Ok((StatusCode::BAD_REQUEST, vista::establecer_no_vale()).into_response())
        }
    }
}

/// Arranca la activación del segundo factor: genera un secreto y lo muestra a enrolar.
pub async fn seguridad_2fa_post(
    State(estado): State<Estado>,
    headers: HeaderMap,
) -> Resultado<Response> {
    // Sólo GENERA y muestra un secreto: sin efecto de estado, así que basta con sesión —o con
    // el token de ENROLAMIENTO forzado (aún sin sesión plena). El step-up (contraseña) va en
    // `/confirmar`, que es donde el 2FA se PERSISTE.
    if usuario_para_enrolar(&estado, &headers).await?.is_none() {
        return Ok(redir("/entrar", &[]));
    }
    let secreto = bachue::dosfactores::generar_secreto();
    Ok(vista::activar_2fa(&secreto, None).into_response())
}

/// Confirma la activación: sólo si el código valida contra el secreto recién mostrado se
/// guarda (así no se activa un 2FA que el usuario no configuró bien y se autobloquea).
pub async fn seguridad_2fa_confirmar_post(
    State(estado): State<Estado>,
    headers: HeaderMap,
    Form(f): Form<FormConfirmar2fa>,
) -> Resultado<Response> {
    let Some((usuario, forzado)) = usuario_para_enrolar(&estado, &headers).await? else {
        return Ok(redir("/entrar", &[]));
    };
    // Un token de enrolamiento FORZADO no re-enrola a quien YA tiene 2FA (p. ej. un token
    // viejo presentado tras un enrolamiento posterior): que entre por el segundo factor, no que
    // sobrescriba el TOTP del titular (defensa en profundidad, concilio). El re-enrolamiento
    // legítimo es el VOLUNTARIO, con sesión plena.
    if forzado && usuario.tiene_2fa() {
        return Ok(redir("/entrar", &[]));
    }
    // STEP-UP en el endpoint que ESCRIBE el 2FA (hallazgo de la revisión: el gate iba en la
    // pantalla de solo-lectura). Una sesión secuestrada no puede persistir/sobrescribir el
    // segundo factor sin la contraseña actual. Va ANTES de validar el código o guardar nada.
    // Vale también para el enrolamiento FORZADO: el usuario acaba de teclear la contraseña en
    // `/entrar`, así que exigirla aquí no le cuesta y cierra el mismo hueco de sesión robada.
    // FRENO del step-up (B1): el par contraseña actual es un oráculo de fuerza
    // bruta para quien ya tiene la cookie. Cubo por-usuario, aparte del login.
    if let Some(seg) = comprobar_stepup(&estado, &usuario.usuario).await? {
        let msg = format!("Demasiados intentos. Espera {seg} s.");
        return Ok(frenada(vista::activar_2fa(&f.secreto, Some(&msg)), seg));
    }
    let clave_ok = bachue::clave::autenticar(Some(&usuario.hash), &f.contrasena);
    if !clave_ok {
        // El fallo provisional ya quedó anotado en `comprobar_stepup`; basta salir.
        return Ok(vista::activar_2fa(&f.secreto, Some("Contraseña incorrecta.")).into_response());
    }
    registrar_stepup(&estado, &usuario.usuario, true).await?;
    let enrol = bachue::segundopaso::Enrolamiento {
        secreto_totp_b32: &f.secreto,
        ultimo_contador: None,
        hashes_recuperacion: &[],
    };
    let resol = bachue::segundopaso::segundo_paso(&enrol, f.codigo.trim(), ahora_unix());
    // En el confirmar `hashes_recuperacion` es `&[]`, así que sólo abre el TOTP; extraer su
    // contador para grabarlo como anti-replay (ese mismo código no se podrá repetir).
    let bachue::segundopaso::Resolucion::SuperadoTotp { contador } = resol else {
        return Ok(vista::activar_2fa(&f.secreto, Some("Código incorrecto; revisa la app.")).into_response());
    };
    // Se guarda CIFRADO en reposo (guaca::reposo): el robo de la BD sin la frase de despliegue
    // no da el secreto TOTP.
    let cifrado = cifrar_totp(&f.secreto, &estado.cfg.frase_totp);
    // La red de seguridad: 10 códigos de un solo uso, mostrados UNA vez. Sin esto, exigir el
    // 2FA sería fabricar cuentas muertas.
    let codigos = bachue::dosfactores::generar_codigos_recuperacion(10);
    let hashes: Vec<String> = codigos.iter().filter_map(|c| bachue::clave::hashear(c)).collect();
    if hashes.len() != codigos.len() {
        return Err(crate::error::Error::Interno(
            "no se pudo hashear un código de recuperación".into(),
        ));
    }
    // TOTP + contador + códigos en UNA transacción (concilio): un fallo parcial no deja el 2FA
    // activo sin su red de recuperación.
    db::activar_2fa(&estado.pool, usuario.id, &cifrado, contador as i64, &hashes).await?;

    let mut resp = vista::codigos_recuperacion(&codigos).into_response();
    // Los códigos van en claro en este cuerpo: que no queden en cachés ni en el bfcache.
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if forzado {
        // Enrolamiento FORZADO por la política: ahora que el 2FA está puesto, se emite la
        // sesión plena y se borra el token de enrolamiento pendiente. El voluntario ya traía
        // sesión, así que no se toca.
        for galleta in [
            cookie_de_sesion(&estado, &usuario),
            borrar_cookie(nombre_pendiente(&estado.cfg), &estado.cfg),
        ] {
            if let Ok(v) = HeaderValue::from_str(&galleta) {
                resp.headers_mut().append(header::SET_COOKIE, v);
            }
        }
    }
    Ok(resp)
}

// ── piezas internas ──

pub(crate) fn cookie_de_sesion(estado: &Estado, usuario: &Usuario) -> String {
    let token = bachue::sesion::emitir(
        Tipo::Sesion,
        &estado.cfg.secreto,
        usuario.id,
        usuario.version,
        TTL_SESION_MIN,
    );
    fijar_cookie(nombre_sesion(&estado.cfg), &token, &estado.cfg, TTL_SESION_MIN * 60)
}

/// El usuario de un token PENDIENTE válido, o `None`. Comprueba la firma Y el `version`
/// —igual que la sesión plena—: la revocación por versión pertenece a AMBOS tipos de
/// token, o un pendiente en vuelo acuñaría una sesión fresca saltándose una revocación
/// (hallazgo del concilio).
async fn pendiente_valido(estado: &Estado, headers: &HeaderMap) -> Resultado<Option<Usuario>> {
    let Some(token) = cookie(headers, nombre_pendiente(&estado.cfg)) else {
        return Ok(None);
    };
    let Some(s) = bachue::sesion::verificar(Tipo::PendienteSegundoFactor, &estado.cfg.secreto, &token) else {
        return Ok(None);
    };
    let Some(u) = db::usuario_por_id(&estado.pool, s.usuario_id).await? else {
        return Ok(None);
    };
    if u.version != s.version {
        return Ok(None);
    }
    Ok(Some(u))
}

/// El usuario autorizado a ENROLAR el 2FA, y si el enrolamiento es FORZADO. Dos vías:
/// - sesión plena → enrolamiento VOLUNTARIO (`forzado = false`);
/// - token [`Tipo::PendienteEnrolamiento2fa`] (media autenticación tras la contraseña, cuando
///   la política lo exige y el usuario no tiene 2FA) → FORZADO (`forzado = true`): el
///   confirmar exitoso emitirá la sesión plena.
///
/// Comprueba la firma Y la `version` (revocación), igual que [`pendiente_valido`].
async fn usuario_para_enrolar(
    estado: &Estado,
    headers: &HeaderMap,
) -> Resultado<Option<(Usuario, bool)>> {
    if let Some(u) = usuario_de_sesion(estado, headers).await? {
        return Ok(Some((u, false)));
    }
    let Some(token) = cookie(headers, nombre_pendiente(&estado.cfg)) else {
        return Ok(None);
    };
    let Some(s) =
        bachue::sesion::verificar(Tipo::PendienteEnrolamiento2fa, &estado.cfg.secreto, &token)
    else {
        return Ok(None);
    };
    let Some(u) = db::usuario_por_id(&estado.pool, s.usuario_id).await? else {
        return Ok(None);
    };
    if u.version != s.version {
        return Ok(None);
    }
    Ok(Some((u, true)))
}

/// ¿Hay que FORZAR ahora el enrolamiento de 2FA a este usuario (que aún no lo tiene)? Según
/// [`Modo2fa`]: `off` nunca; `estricto` siempre; `gracia` cuando su ventana venció —y en su
/// PRIMER login bajo `gracia` le fija la ventana y lo deja pasar—. Una marca de límite
/// ilegible se trata como vencida (conservador, D20). El llamante ya comprobó que NO tiene 2FA.
async fn debe_forzar_enrolar_2fa(estado: &Estado, usuario: &Usuario) -> Resultado<bool> {
    match estado.cfg.dos_factor {
        crate::estado::Modo2fa::Off => Ok(false),
        crate::estado::Modo2fa::Estricto => Ok(true),
        crate::estado::Modo2fa::Gracia => {
            let ahora = chrono::Utc::now();
            match usuario.enrolar_2fa_antes_de.as_deref() {
                None => {
                    let limite = (ahora
                        + chrono::Duration::days(crate::estado::GRACIA_2FA_DIAS))
                    .to_rfc3339();
                    db::fijar_limite_enrolar_2fa(&estado.pool, usuario.id, &limite).await?;
                    Ok(false)
                }
                Some(limite) => Ok(chrono::DateTime::parse_from_rfc3339(limite)
                    .map(|t| ahora > t.with_timezone(&chrono::Utc))
                    .unwrap_or(true)),
            }
        }
    }
}

/// Emite el token de ENROLAMIENTO forzado y la cookie que lo lleva, para mandar a `/seguridad/2fa`
/// a un usuario al que la política le exige el 2FA. Media autenticación: no es sesión plena.
fn cookie_enrolamiento_forzado(estado: &Estado, usuario: &Usuario) -> String {
    let pend = bachue::sesion::emitir(
        Tipo::PendienteEnrolamiento2fa,
        &estado.cfg.secreto,
        usuario.id,
        usuario.version,
        TTL_PENDIENTE_MIN,
    );
    fijar_cookie(nombre_pendiente(&estado.cfg), &pend, &estado.cfg, TTL_PENDIENTE_MIN * 60)
}

/// Codifica lo mínimo para meter una ruta en un query param (`next`).
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
