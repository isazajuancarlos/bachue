// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **Bachué — credencial tipo OPAQUE (F6).** Registro y login donde **el servidor
//! nunca ve la contraseña ni un hash reversible de ella**, y el cliente nunca la envía.
//!
//! _Es el "diferenciador PQ": la prueba de identidad del login es una firma híbrida
//! Ed25519 + ML-DSA-87 (`quipu::pqsign`)._
//!
//! # La idea, en tres piezas
//!
//! 1. **VOPRF** (`quipu::voprf`, RFC 9497). El cliente CIEGA su contraseña, el servidor
//!    la evalúa con una clave OPRF por-usuario que sólo él conoce, y el cliente
//!    DESCIEGA verificando la prueba DLEQ. Resultado: 64 bytes (`oprf_out`) que dependen
//!    de la contraseña Y de la clave del servidor, sin que el servidor haya visto la
//!    contraseña ni el cliente la clave. Un atacante sin la clave del servidor no puede
//!    PRECOMPUTAR nada antes de comprometerlo.
//! 2. **Endurecimiento** (`quipu::kdf`, Argon2id). `rwd = Argon2id(contraseña, salt,
//!    pepper = oprf_out)`. Memory-hard: encarece cada intento de diccionario, también
//!    el de un servidor comprometido (que sí puede intentarlo —tiene la clave OPRF—,
//!    pero pagando Argon2id por conjetura, que es lo que un buen hash de contraseña da).
//! 3. **Sobre + prueba asimétrica.** De `rwd` se derivan (a) un par de firma
//!    determinista y (b) una etiqueta que autentica el sobre. El servidor guarda sólo
//!    `{sobre, clave_pública_del_cliente}` —nada invertible a contraseña—; el cliente
//!    prueba que conoce la contraseña FIRMANDO un reto fresco, y el servidor verifica
//!    con la clave pública. Como es asimétrica, comprometer el almacén no da forjar
//!    logins sin, además, romper la contraseña por Argon2id.
//!
//! # Lo que ESTE crate hace y lo que NO (alcance F6, decidido por Juan 2026-08-31)
//!
//! Es la **credencial**: el mecanismo de registro/login sobre VOPRF + sobre. **NO** es
//! el AKE completo de OPAQUE (los 3 mensajes con DH efímero que además acuerdan una
//! clave de sesión con secreto hacia adelante). La clave de sesión tras el login la
//! sigue emitiendo [`bachue_sesion`](../bachue_sesion/index.html) — este crate termina
//! en "autenticado / rechazado", no en una clave de sesión.
//!
//! # Propiedades y sus límites, dichos de frente
//!
//! - **El servidor nunca ve la contraseña ni un hash reversible.** Sí guarda la clave
//!   OPRF (por-usuario, derivada de una semilla maestra) y una clave pública. Con eso,
//!   un servidor comprometido PUEDE montar un ataque de diccionario offline —cualquier
//!   esquema basado en contraseña lo permite—, pero acotado por el coste de Argon2id
//!   por conjetura, y **no puede precomputar** antes del compromiso (la clave OPRF era
//!   secreta). Esto es exactamente lo que OPAQUE promete; ni más, ni menos.
//! - **Anti-enumeración de usuarios**: [`servidor::Servidor::responder_login`] produce
//!   una respuesta de forma idéntica para un usuario que no existe (sobre-señuelo
//!   determinista), para no filtrar quién está registrado. El login luego falla en la
//!   verificación. La constancia de TIEMPO de extremo a extremo es responsabilidad del
//!   integrador (que debe ejecutar el mismo trabajo Argon2id/verificación en los dos
//!   caminos).
//! - **Enmascarado del sobre (masking de RFC 9807)**: no incluido; es un endurecimiento
//!   adicional contra un espía de red que observe la respuesta. Anotado como extensión.
//!
//! # Contrato del integrador (lo que el crate NO puede forzar)
//!
//! - **Un `EstadoLoginServidor` es de UN SOLO USO.** La frescura anti-repetición vive en
//!   el `reto_servidor`, que se genera nuevo en cada [`servidor::Servidor::responder_login`].
//!   El integrador debe abrir un login nuevo (reto nuevo) por intento y NO verificar dos
//!   `LoginFinal` contra el mismo estado.
//! - **Constancia de TIEMPO de extremo a extremo.** El servidor debe ejecutar el mismo
//!   trabajo (evaluación OPRF + respuesta) para un usuario que existe y uno que no, o el
//!   tiempo delata el registro pese al sobre-señuelo.
//! - **La identidad del servidor no se "pinnea" en el login.** En el registro el cliente
//!   la fija como parámetro; en el login llega en el mensaje, pero queda AUTENTICADA por
//!   la etiqueta del sobre ANTES de que el cliente firme (una identidad distinta a la del
//!   registro ⇒ el sobre no abre). No hay que añadir un pinneo aparte ni confiar en
//!   `resp.identidad_servidor` antes de que la etiqueta case: el protocolo ya lo hace.
//! - **El re-registro SOBRESCRIBE.** `guardar_registro` no distingue un alta nueva de un
//!   re-registro de un usuario ya existente: persistir el resultado reemplaza la
//!   credencial anterior. El integrador debe decidir su política —rechazar el alta si el
//!   usuario existe, o exigir un login previo antes de re-registrar—; el crate es la
//!   credencial, no el flujo de cuentas.
//! - **La canonicalización del `usuario` es del llamante.** A diferencia de la
//!   contraseña (que el crate normaliza NFKC), el `usuario` se usa tal cual: `"Ana"` y
//!   `"ana"`, o dos formas Unicode del mismo nombre, son cuentas DISTINTAS (clave OPRF
//!   distinta). Si quieres nombres insensibles a mayúsculas/forma, normalízalos antes de
//!   llamar. No es un hueco de seguridad —nadie suplanta a otro—, sino coherencia de app.
//!
//! # Por qué NFKC y no NFC en la contraseña
//!
//! La contraseña se normaliza **NFKC**, no NFC —aunque RFC 8265 (PRECIS `OpaqueString`)
//! prescriba NFC para contraseñas—, y es OBLIGADO, no una preferencia: el KDF de quipu
//! (`derive_master_key`) normaliza NFKC por dentro, así que la capa OPRF DEBE usar la
//! misma forma o las dos capas volverían a divergir (el mismo hueco que este crate cerró:
//! blind vería una forma y Argon2id otra). El precio de NFKC es que hace *compatibility
//! folding* (ligaduras `ﬁ`→`fi`, ancho completo, superíndices…), colapsando al mismo
//! valor contraseñas que usen esos caracteres raros —entropía marginalmente menor en ese
//! subconjunto—. Cambiar a NFC exigiría cambiarlo TAMBIÉN en quipu; hasta entonces, NFKC
//! consistente es correcto y NFC sería un defecto.
//!
//! # Mapa
//!
//! | Módulo | Qué es |
//! |---|---|
//! | [`firma`] | el esquema de firma de la prueba de login, tras un trait (por defecto híbrido PQ) |
//! | [`mensajes`] | los mensajes que cruzan el cable, y el registro que el servidor persiste |
//! | [`cliente`] | el lado del cliente (tiene la contraseña; nunca la envía) |
//! | [`servidor`] | el lado del servidor (tiene la semilla OPRF; nunca ve la contraseña) |

#![forbid(unsafe_code)]

pub mod cliente;
pub mod firma;
pub mod mensajes;
pub mod servidor;

/// El coste Argon2id, re-exportado para que un consumidor configure el protocolo sin
/// depender de `quipu` directamente. Usa `KdfParams::FUERTE` (256 MiB) para secretos de
/// alto valor o `KdfParams::EQUILIBRADO` (64 MiB) por defecto; cliente y servidor deben
/// acordar el MISMO, o `rwd` no coincide.
pub use quipu::kdf::KdfParams;

/// Etiquetas de separación de dominio, versionadas. Cambiar el protocolo cambia `v1`.
pub(crate) mod etiquetas {
    pub const AUTH_KEY: &[u8] = b"bachue-opaque/v1 auth-key";
    pub const EXPORT_KEY: &[u8] = b"bachue-opaque/v1 export-key";
    pub const SIGN_SEED: &[u8] = b"bachue-opaque/v1 sign-seed";
    pub const SOBRE: &[u8] = b"bachue-opaque/v1 envelope-tag";
    pub const LOGIN: &[u8] = b"bachue-opaque/v1 login-proof";
    pub const SENUELO: &[u8] = b"bachue-opaque/v1 decoy-envelope";
}

/// Concatenación CANÓNICA con longitudes: cada campo va precedido de su longitud en
/// 8 bytes big-endian. Mata la ambigüedad de codificación —`("ab","c")` y `("a","bc")`
/// producen cadenas DISTINTAS— que de otro modo sostiene ataques de confusión de campos
/// (la misma clase que anota `quipu::kdf::derive_master_key`). Se usa para TODA entrada
/// a un MAC o a una firma en este crate.
pub(crate) fn con_longitudes(campos: &[&[u8]]) -> Vec<u8> {
    let total: usize = campos.iter().map(|c| 8 + c.len()).sum();
    let mut v = Vec::with_capacity(total);
    for c in campos {
        v.extend_from_slice(&(c.len() as u64).to_be_bytes());
        v.extend_from_slice(c);
    }
    v
}

/// Comparación en TIEMPO CONSTANTE de dos etiquetas de 32 bytes (los tags del sobre).
/// No corta al primer byte distinto: un `==` de slices daría un oráculo de temporización
/// sobre el tag. Sin dependencia: es un XOR acumulado.
pub(crate) fn iguales_ct(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut dif = 0u8;
    for i in 0..32 {
        dif |= a[i] ^ b[i];
    }
    dif == 0
}

#[cfg(test)]
mod pruebas_ct {
    use super::*;

    #[test]
    fn con_longitudes_no_es_ambigua() {
        assert_ne!(
            con_longitudes(&[b"ab", b"c"]),
            con_longitudes(&[b"a", b"bc"]),
            "la concatenación con longitudes distingue la frontera de campos"
        );
    }

    #[test]
    fn iguales_ct_discrimina() {
        let a = [7u8; 32];
        let mut b = a;
        assert!(iguales_ct(&a, &b));
        b[31] ^= 1;
        assert!(!iguales_ct(&a, &b), "un solo bit distinto ⇒ no iguales");
    }
}
