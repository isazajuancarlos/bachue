// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **Bachué IdP (F7, capa 2).** Un binario axum + SQLite + maud/htmx que USA la librería
//! y expone la autenticación como servicio: registro, login por contraseña, segundo
//! factor TOTP y sesión, con las defensas de borde cableadas. Imagen Docker mínima.
//!
//! NO reimplementa nada de auth —la orquesta—: `bachue::clave` verifica la contraseña,
//! `bachue::segundopaso` el TOTP, `bachue::sesion` firma el token, `bachue::defensas` da
//! la IP del freno y valida el reenvío. OAuth2/OIDC es una capa opcional y posterior.
//!
//! Config por entorno: `BACHUE_IDP_SECRETO` (obligatorio, ≥32 B), `BACHUE_IDP_DB`,
//! `BACHUE_IDP_PUERTO`, `BACHUE_IDP_PROXIES`, `BACHUE_IDP_INSEGURO` (sólo dev sobre http),
//! `BACHUE_IDP_2FA` (`off`|`gracia`|`estricto`, default `off`: obligatoriedad del 2FA),
//! `BACHUE_IDP_RP_ID` (dominio de las passkeys; vacío = passkeys desactivadas) y
//! `BACHUE_IDP_PASSKEY_ORIGEN` (el `origin` esperado; por defecto `https://{rp_id}`).

mod db;
mod error;
mod estado;
mod passkey;
mod rutas;
mod vista;

use axum::routing::{get, post};
use axum::Router;
use estado::{Config, Estado};
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .init();

    if let Err(e) = correr().await {
        tracing::error!("bachue-idp no arrancó: {e}");
        std::process::exit(1);
    }
}

async fn correr() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::desde_entorno()?;
    let url = std::env::var("BACHUE_IDP_DB").unwrap_or_else(|_| "sqlite://bachue-idp.db".to_string());
    let puerto: u16 = std::env::var("BACHUE_IDP_PUERTO")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8090);
    // Dirección de escucha. Por defecto LOOPBACK: el IdP va SIEMPRE detrás de un
    // proxy inverso (TLS), nunca expuesto directo. Antes fijaba `0.0.0.0`, lo que
    // dejaba `:puerto` alcanzable desde fuera saltándose nginx/TLS.
    let direccion =
        std::env::var("BACHUE_IDP_DIRECCION").unwrap_or_else(|_| "127.0.0.1".to_string());

    let pool = db::abrir(&url).await?;
    // Las claves de firma OIDC se DERIVAN de la SEMILLA OIDC (no de la BD, ni del secreto de
    // sesión): todas las generaciones 1..=activa. La última firma; todas verifican y se
    // publican (rotación sin invalidar tokens). Deterministas.
    let generaciones = estado::claves_oidc(&cfg.oidc_semilla, cfg.oidc_generacion);
    let estado = Estado {
        pool,
        cfg: Arc::new(cfg),
        oidc_generaciones: Arc::new(generaciones),
    };

    let escucha = tokio::net::TcpListener::bind((direccion.as_str(), puerto)).await?;
    tracing::info!("bachue-idp sirviendo en {}", escucha.local_addr()?);
    // `ConnectInfo` da la IP del socket, que el freno usa cuando no hay proxy delante.
    axum::serve(escucha, ruteador(estado).into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

fn ruteador(estado: Estado) -> Router {
    Router::new()
        .route("/", get(rutas::index))
        .route("/entrar", get(rutas::entrar_get).post(rutas::entrar_post))
        .route(
            "/segundo-factor",
            get(rutas::segundo_factor_get).post(rutas::segundo_factor_post),
        )
        .route("/registrarse", get(rutas::registrarse_get).post(rutas::registrarse_post))
        .route("/salir", post(rutas::salir_post))
        // Puente para `auth_request` de servicios detrás de bachue-idp (tunjo-saas).
        .route("/validar", get(rutas::validar))
        // OIDC (veta #1): JWKS (rebanada 2, read-only) + authorize/token (rebanadas 3/4).
        // `/token` es POST server-to-server (el guardián CSRF permite POST sin Sec-Fetch-Site).
        // Discovery `/.well-known/openid-configuration` es rebanada posterior.
        .route("/.well-known/openid-configuration", get(rutas::descubrimiento))
        .route("/jwks", get(rutas::jwks))
        .route("/authorize", get(rutas::autorizar))
        .route("/token", post(rutas::token))
        .route("/userinfo", get(rutas::userinfo))
        // Aprovisionamiento "pago primero": tunjo-saas crea el reclamo (máquina-a-máquina,
        // secreto compartido), el usuario fija su contraseña en /establecer.
        .route("/aprovisionar", post(rutas::aprovisionar_post))
        .route("/establecer", get(rutas::establecer_get).post(rutas::establecer_post))
        // GET además de POST: el enrolamiento FORZADO llega por redirect (303→GET); mostrar
        // el secreto no cambia estado (el step-up con contraseña va en `/confirmar`).
        .route("/seguridad/2fa", get(rutas::seguridad_2fa_post).post(rutas::seguridad_2fa_post))
        .route("/seguridad/2fa/confirmar", post(rutas::seguridad_2fa_confirmar_post))
        .route("/seguridad/2fa/reset", post(rutas::reset_2fa_post))
        // Passkeys / WebAuthn (F3): las dos ceremonias (registro + login discoverable) y el
        // borrado desde el panel. Todo POST (un `fetch` de primera parte pasa la guardia CSRF);
        // si no hay RP ID configurado, cada handler devuelve 404 (capa desactivada, D20).
        .route("/passkey/registrar/inicio", post(passkey::registrar_inicio))
        .route("/passkey/registrar/fin", post(passkey::registrar_fin))
        .route("/passkey/login/inicio", post(passkey::login_inicio))
        .route("/passkey/login/fin", post(passkey::login_fin))
        .route("/seguridad/passkey/borrar", post(passkey::borrar))
        .route("/passkey.js", get(vista::passkey_js))
        .route("/htmx.min.js", get(vista::htmx_js))
        .route("/boi.js", get(vista::boi_js))
        .route("/boi.css", get(vista::boi_css))
        .route("/estilo.css", get(vista::estilo_css))
        .with_state(estado)
        // Guardia CSRF: rechaza todo POST que no sea de primera parte (cierra el
        // login-CSRF que SameSite no cubre). Va como capa para no olvidarlo en ningún
        // endpoint futuro (directiva 23).
        .layer(axum::middleware::from_fn(rutas::guardia_csrf))
        // CSP estricta en toda respuesta (todo el frontend es de origen propio).
        .layer(axum::middleware::from_fn(rutas::cabeceras_seguridad))
        .layer(tower_http::compression::CompressionLayer::new())
        .layer(tower_http::trace::TraceLayer::new_for_http())
}
