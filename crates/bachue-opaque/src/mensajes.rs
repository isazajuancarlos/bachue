// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! Los mensajes del protocolo y el registro que el servidor persiste. Son datos planos;
//! la lógica vive en [`super::cliente`] y [`super::servidor`].
//!
//! Serializar/deserializar al formato de cable (CBOR, longitud-valor, lo que use el
//! transporte) es del integrador: aquí son structs de Rust, para que el protocolo se
//! pruebe sin arrastrar un códec.

/// El **sobre** (envelope): lo que el servidor guarda para poder desafiar al cliente,
/// y que el cliente usa para reconstruir y verificar sus claves. No contiene nada
/// invertible a la contraseña: un `salt` público y una etiqueta de autenticación.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sobre {
    /// Salt de Argon2id, generado al registrar. Público.
    pub salt: [u8; 16],
    /// Etiqueta que autentica el sobre: liga `salt`, la clave pública OPRF del servidor,
    /// su identidad y la clave pública del cliente. El cliente la recomputa al abrir; si
    /// no casa, la contraseña es incorrecta o algo se manipuló.
    pub etiqueta_auth: [u8; 32],
}

// ───────────────────────── Registro ─────────────────────────

/// Cliente → servidor: arranca el registro con la contraseña ya CIEGA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IniciarRegistro {
    pub usuario: String,
    /// Elemento ciego del VOPRF (ristretto255 comprimido).
    pub elemento_ciego: [u8; 32],
}

/// Servidor → cliente: la evaluación OPRF ciega, con su prueba DLEQ y la clave pública
/// del servidor para verificarla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespuestaRegistro {
    pub evaluado: [u8; 32],
    pub prueba: [u8; 64],
    pub oprf_pub: [u8; 32],
}

/// Cliente → servidor: el sobre construido y la clave pública del cliente a guardar. La
/// contraseña, `rwd` y la clave privada ya se descartaron en el cliente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistroFinal {
    pub usuario: String,
    pub sobre: Sobre,
    pub clave_publica_cliente: Vec<u8>,
}

/// Lo que el servidor PERSISTE por usuario. La clave OPRF NO se guarda aquí: se
/// re-deriva de la semilla maestra + usuario en cada login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistroGuardado {
    pub usuario: String,
    pub sobre: Sobre,
    pub clave_publica_cliente: Vec<u8>,
}

// ───────────────────────── Login ─────────────────────────

/// Cliente → servidor: arranca el login con la contraseña ciega.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IniciarLogin {
    pub usuario: String,
    pub elemento_ciego: [u8; 32],
}

/// Servidor → cliente: evaluación OPRF + el sobre guardado + la identidad del servidor +
/// un reto fresco que el cliente tendrá que firmar (anti-repetición).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespuestaLogin {
    pub evaluado: [u8; 32],
    pub prueba: [u8; 64],
    pub oprf_pub: [u8; 32],
    pub sobre: Sobre,
    pub identidad_servidor: Vec<u8>,
    pub reto_servidor: [u8; 32],
}

/// Cliente → servidor: la prueba de que conoce la contraseña — una firma sobre el
/// transcript del login con la clave derivada de `rwd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginFinal {
    pub prueba_cliente: Vec<u8>,
}

/// El veredicto del servidor al verificar el login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Veredicto {
    /// La firma valida contra la clave pública guardada: es quien dice ser.
    Autenticado { usuario: String },
    /// No valida: contraseña incorrecta, usuario inexistente (señuelo) o manipulación.
    /// El motivo NO se distingue a propósito, para no dar oráculo.
    Rechazado,
}

impl Veredicto {
    #[must_use]
    pub fn autenticado(&self) -> bool {
        matches!(self, Self::Autenticado { .. })
    }
}
