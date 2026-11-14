// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! Un error interno que NO filtra su detalle al cliente: se registra en el log y al
//! navegador le llega un 500 escueto. Los errores de negocio (contraseña mala, usuario
//! repetido) NO son esto — se dibujan en la pantalla, no son `Error`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub type Resultado<T> = Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Bd(sqlx::Error),
    Interno(String),
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Error::Bd(e)
    }
}

impl From<sqlx::migrate::MigrateError> for Error {
    fn from(e: sqlx::migrate::MigrateError) -> Self {
        Error::Interno(format!("migración: {e}"))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Bd(e) => write!(f, "base de datos: {e}"),
            Error::Interno(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        tracing::error!("error interno: {self:?}");
        (StatusCode::INTERNAL_SERVER_ERROR, "error interno").into_response()
    }
}
