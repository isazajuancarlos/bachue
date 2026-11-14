// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **Bachué F2 — sesiones y tipos de token.**
//!
//! El token firmado lo hace [`guaca::sesion`] (`id|version|caducidad` con HMAC y un
//! DOMINIO de firma que entra en el MAC pero no viaja). Aquí vive la decisión de qué
//! DOMINIO usa cada tipo de token, y la garantía —por tipos— de que un token de un tipo
//! NUNCA vale como otro.
//!
//! # La lección que este módulo encarna
//!
//! Un token que sirve para un propósito no puede reciclarse para otro. En medico, el
//! token *pendiente de segundo factor* presentado como sesión plena FALLA la firma —no
//! porque alguien recuerde mirar un campo, sino porque está firmado en otro dominio—. Y
//! es la lección de LiteLLM/MCP SDK: una cookie de UI y un token de cliente son tipos
//! distintos, no intercambiables. Aquí, cada [`Tipo`] tiene su dominio, y
//! [`verificar`] solo acepta el dominio del tipo que se le pide: pasar un token de otro
//! tipo devuelve `None`, sin que dependa de recordar comprobar nada.
//!
//! La revocación selectiva (por `version`) y la caducidad las da guaca; el llamante
//! compara la `version` del token contra la fresca de su base (subir el entero cierra
//! todas las sesiones de esa persona sin guardar estado de sesión en el servidor).

#![forbid(unsafe_code)]

pub use guaca::sesion::Sesion;

/// El TIPO de un token. Cada uno firma en un DOMINIO distinto, así que la separación
/// no depende de mirar un campo: un token de un tipo no verifica como otro (la firma
/// no casa). Añadir un tipo es añadir un brazo con un dominio nuevo y distinto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tipo {
    /// La sesión plena, tras entrar del todo. Usa el dominio vacío = la sesión "normal"
    /// de guaca (compatibilidad con `guaca::sesion::emitir`/`verificar`).
    Sesion,
    /// El paso intermedio entre la contraseña correcta y el segundo factor. Vida corta
    /// y en su propia cookie: presentado como [`Tipo::Sesion`] no abre nada.
    PendienteSegundoFactor,
    /// Un enlace de recuperación de cuenta. Su propio dominio: un token de recuperación
    /// no es una sesión ni un pendiente.
    Recuperacion,
    /// El paso intermedio entre la contraseña correcta y el ENROLAMIENTO forzado del 2FA
    /// (cuando la política lo exige y el usuario aún no lo tiene). Como
    /// [`PendienteSegundoFactor`](Tipo::PendienteSegundoFactor): media autenticación, en su
    /// propia cookie y dominio; presentado como [`Tipo::Sesion`] no abre nada. Solo habilita
    /// las pantallas de enrolamiento, no una sesión plena.
    PendienteEnrolamiento2fa,
}

impl Tipo {
    /// El dominio de firma de este tipo. Son cadenas DISTINTAS entre sí; guaca antepone
    /// su longitud en el MAC, así que no hay ambigüedad de prefijo entre dominios.
    fn dominio(self) -> &'static str {
        match self {
            Tipo::Sesion => "",
            Tipo::PendienteSegundoFactor => "bachue:pendiente-2fa",
            Tipo::Recuperacion => "bachue:recuperacion",
            Tipo::PendienteEnrolamiento2fa => "bachue:pendiente-enrolar-2fa",
        }
    }
}

/// Emite un token del `tipo` dado para `usuario_id`, con su `version` (para revocación
/// selectiva) y una caducidad en `minutos`. El `secreto` es la clave HMAC del servicio.
pub fn emitir(tipo: Tipo, secreto: &[u8], usuario_id: i64, version: i64, minutos: i64) -> String {
    guaca::sesion::emitir_en(secreto, tipo.dominio(), usuario_id, version, minutos)
}

/// Verifica un token EXIGIENDO que sea del `tipo` dado. `None` si la firma no casa (que
/// incluye el caso de un token de OTRO tipo), si el formato es raro o si caducó. Un solo
/// `None` para las tres cosas: a quien presenta un token malo no se le dice en qué falló.
pub fn verificar(tipo: Tipo, secreto: &[u8], token: &str) -> Option<Sesion> {
    guaca::sesion::verificar_en(secreto, tipo.dominio(), token)
}

/// Atributos de una cookie de sesión servida por HTTPS, con el máximo blindaje del
/// navegador: `__Host-` (exige `Secure`, `Path=/` y SIN `Domain` — la cookie más acotada
/// que existe), `HttpOnly` (invisible a JavaScript) y `SameSite=Strict` (fuera de toda
/// petición cross-site). El `Secure` lo exige `__Host-`, así que en claro no cuaja: es a
/// propósito, una sesión no viaja por HTTP.
pub fn cookie_de_sesion(nombre: &str, valor: &str, minutos: i64) -> String {
    format!(
        "__Host-{nombre}={valor}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
        minutos * 60
    )
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const SECRETO: &[u8] = b"secreto-hmac-de-prueba-de-al-menos-32-bytes!!";

    /// **EL EDGE DE F2 (directiva 33): un token de un TIPO no vale como otro.** Se emite
    /// una sesión y se verifica: como sesión ABRE; como recuperación o como pendiente,
    /// NO —la firma está en otro dominio—. Sin la pareja verde, un `verificar` que
    /// devuelve `None` siempre pasaría; sin los casos rojos, un token que vale para
    /// cualquier tipo (el bug de reciclar un token) pasaría el verde.
    #[test]
    fn un_token_de_un_tipo_no_vale_como_otro() {
        let t = emitir(Tipo::Sesion, SECRETO, 42, 0, 60);
        // VERDE: como su propio tipo, abre y trae los datos.
        let s = verificar(Tipo::Sesion, SECRETO, &t).expect("la sesión verifica como sesión");
        assert_eq!(s.usuario_id, 42);
        assert_eq!(s.version, 0);
        // ROJO por la vía real (dominio distinto → firma no casa): otro tipo NO abre.
        assert!(verificar(Tipo::Recuperacion, SECRETO, &t).is_none());
        assert!(verificar(Tipo::PendienteSegundoFactor, SECRETO, &t).is_none());

        // Y al revés: un pendiente no vale como sesión (el caso medico).
        let p = emitir(Tipo::PendienteSegundoFactor, SECRETO, 42, 0, 5);
        assert!(verificar(Tipo::Sesion, SECRETO, &p).is_none());
        assert!(verificar(Tipo::PendienteSegundoFactor, SECRETO, &p).is_some());
    }

    /// Un token verificado con OTRO secreto no abre (control del HMAC).
    #[test]
    fn otro_secreto_no_verifica() {
        let t = emitir(Tipo::Sesion, SECRETO, 7, 3, 60);
        assert!(verificar(Tipo::Sesion, b"otro-secreto-completamente-distinto!!", &t).is_none());
    }

    /// La cookie de sesión lleva los cuatro blindajes, y su pareja: NO deja el token a
    /// merced de JavaScript ni de peticiones cross-site.
    #[test]
    fn la_cookie_de_sesion_va_blindada() {
        let c = cookie_de_sesion("sid", "el-valor", 30);
        assert!(c.starts_with("__Host-sid=el-valor"), "prefijo __Host- y valor: {c}");
        for flag in ["Path=/", "Secure", "HttpOnly", "SameSite=Strict", "Max-Age=1800"] {
            assert!(c.contains(flag), "falta {flag} en la cookie: {c}");
        }
        // La pareja: NO lleva Domain (lo que __Host- prohíbe y lo que amplía el alcance).
        assert!(!c.to_lowercase().contains("domain="), "una cookie de sesión no lleva Domain");
    }
}
