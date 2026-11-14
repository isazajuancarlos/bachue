// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **El lado del cliente.** Es quien tiene la contraseña, y quien NUNCA la envía: la
//! ciega para el VOPRF y la endurece con Argon2id, y de ahí deriva todo.

use quipu::kdf::{self, KdfParams};
use quipu::voprf::rfc9497 as voprf;
use unicode_normalization::UnicodeNormalization;

use crate::etiquetas;
use crate::firma::EsquemaDeFirma;
use crate::mensajes::{IniciarLogin, IniciarRegistro, LoginFinal, RegistroFinal, RespuestaLogin, RespuestaRegistro, Sobre};
use crate::{con_longitudes, iguales_ct};

/// Estado del cliente entre los dos pasos del registro. Guarda la contraseña y el
/// estado de cegado hasta que llega la respuesta del servidor.
pub struct EstadoRegistro {
    usuario: String,
    contrasena: String,
    blind: voprf::BlindState,
}

/// Estado del cliente entre los dos pasos del login.
pub struct EstadoLogin {
    usuario: String,
    contrasena: String,
    blind: voprf::BlindState,
}

/// Lo que el cliente obtiene al terminar el login, además del mensaje a enviar: la
/// `export_key`, una clave de 32 B derivada de la contraseña que la app puede usar para
/// cifrar datos del usuario en el cliente (cifrado de notas, etc.). No sale al servidor.
#[derive(Debug, Clone)]
pub struct SalidaLogin {
    pub mensaje: LoginFinal,
    pub export_key: [u8; 32],
}

/// Lo que el cliente obtiene al terminar el registro.
#[derive(Debug, Clone)]
pub struct SalidaRegistro {
    pub mensaje: RegistroFinal,
    pub export_key: [u8; 32],
}

/// Por qué falló el login en el cliente. `ContrasenaIncorrecta` cubre también un sobre
/// manipulado: no se distingue a propósito (no dar oráculo de cuál de las dos fue).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorLogin {
    /// La prueba DLEQ del VOPRF no validó: el servidor usó otra clave o hubo manipulación.
    PruebaOprfInvalida,
    /// La etiqueta del sobre no casa: contraseña incorrecta o sobre manipulado.
    ContrasenaIncorrecta,
    /// Fallo interno (RNG sin entropía, derivación de clave imposible).
    ErrorInterno,
}

/// Credencial derivada de la contraseña (una vez desciegado el OPRF). Toda la
/// derivación simétrica del protocolo pasa por aquí, para que cliente-registro y
/// cliente-login la computen IDÉNTICA.
struct Credencial {
    publica: Vec<u8>,
    privada: Vec<u8>,
    export_key: [u8; 32],
    etiqueta_auth: [u8; 32],
}

/// El contexto público que se liga en la etiqueta del sobre. Agruparlo evita una firma
/// con demasiados parámetros y deja claro qué queda atado a la credencial.
struct ContextoSobre<'a> {
    usuario: &'a [u8],
    salt: &'a [u8; 16],
    oprf_pub: &'a [u8; 32],
    identidad_servidor: &'a [u8],
}

/// `oprf_out` → Argon2id → `rwd` → (par de firma determinista, export_key, etiqueta del
/// sobre). La etiqueta liga `usuario`, `salt`, la clave pública OPRF del servidor, su
/// identidad y la clave pública del cliente, todo con longitudes canónicas.
///
/// `oprf_out` se recibe como `&[u8; 64]` A PROPÓSITO: la no-ambigüedad de la
/// concatenación `NFKC(pw) ‖ pepper` en `derive_master_key` depende de que el pepper sea
/// de longitud FIJA, así que el invariante se garantiza por TIPO, no por comentario.
fn derivar(
    contrasena: &str,
    oprf_out: &[u8; 64],
    ctx: &ContextoSobre,
    esquema: &impl EsquemaDeFirma,
    params: &KdfParams,
) -> Option<Credencial> {
    // Endurecimiento: memory-hard sobre la contraseña (ya NFKC-normalizada en
    // `iniciar_*`), con el OPRF como pepper (ata `rwd` a la clave del servidor).
    let rwd = kdf::derive_master_key(contrasena, ctx.salt, oprf_out, params);

    let auth_key = kdf::derive_subkey(&rwd, etiquetas::AUTH_KEY);
    let export_key = kdf::derive_subkey(&rwd, etiquetas::EXPORT_KEY);

    // Semilla del par de firma, del tamaño que pida el esquema, derivada de `rwd`.
    let mut semilla = vec![0u8; esquema.bytes_de_semilla()];
    kdf::derive_stream(&rwd, etiquetas::SIGN_SEED, &mut semilla);
    let par = esquema.derivar(&semilla)?;

    // La etiqueta liga `usuario` EXPLÍCITAMENTE (no sólo de forma transitiva vía la clave
    // OPRF por-usuario): cierra la dependencia en "DeriveKeyPair no colisiona" (rev. D25).
    let etiqueta_auth = kdf::derive_subkey(
        &auth_key,
        &con_longitudes(&[
            etiquetas::SOBRE,
            ctx.usuario,
            ctx.salt,
            ctx.oprf_pub,
            ctx.identidad_servidor,
            &par.publica,
        ]),
    );

    Some(Credencial {
        publica: par.publica,
        privada: par.privada,
        export_key,
        etiqueta_auth,
    })
}

/// El transcript que el cliente firma y el servidor verifica en el login. Liga usuario,
/// identidad del servidor, clave pública del cliente y el reto fresco (anti-repetición).
pub(crate) fn transcript_login(
    usuario: &str,
    identidad_servidor: &[u8],
    clave_publica_cliente: &[u8],
    reto_servidor: &[u8; 32],
) -> Vec<u8> {
    con_longitudes(&[
        etiquetas::LOGIN,
        usuario.as_bytes(),
        identidad_servidor,
        clave_publica_cliente,
        reto_servidor,
    ])
}

// ───────────────────────── Registro ─────────────────────────

/// Normaliza la contraseña a NFKC — la MISMA transformación que `derive_master_key`
/// aplica por dentro, para que la capa OPRF (que ciega bytes) y la capa Argon2id traten
/// "la misma contraseña" idéntica. Sin esto, dos codificaciones Unicode equivalentes de
/// la misma tilde serían credenciales distintas (rev. D25).
fn normalizar(contrasena: &str) -> String {
    contrasena.nfkc().collect()
}

/// Paso 1 del registro: ciega la contraseña (ya normalizada) y prepara el arranque.
pub fn iniciar_registro(usuario: &str, contrasena: &str) -> Option<(EstadoRegistro, IniciarRegistro)> {
    let contrasena = normalizar(contrasena);
    let (blind, elemento_ciego) = voprf::blind(contrasena.as_bytes())?;
    Some((
        EstadoRegistro {
            usuario: usuario.to_string(),
            contrasena,
            blind,
        },
        IniciarRegistro {
            usuario: usuario.to_string(),
            elemento_ciego,
        },
    ))
}

/// Paso 2 del registro: descegar el OPRF (verifica la prueba DLEQ), generar un `salt`
/// nuevo, construir el sobre y la clave pública a guardar. `None` si la prueba no valida
/// o falla la derivación.
pub fn terminar_registro(
    estado: &EstadoRegistro,
    resp: &RespuestaRegistro,
    identidad_servidor: &[u8],
    esquema: &impl EsquemaDeFirma,
    params: &KdfParams,
) -> Option<SalidaRegistro> {
    terminar_registro_con(estado, resp, identidad_servidor, esquema, params, salt_aleatorio()?)
}

/// Como [`terminar_registro`] pero con el `salt` dado — para pruebas deterministas.
pub fn terminar_registro_con(
    estado: &EstadoRegistro,
    resp: &RespuestaRegistro,
    identidad_servidor: &[u8],
    esquema: &impl EsquemaDeFirma,
    params: &KdfParams,
    salt: [u8; 16],
) -> Option<SalidaRegistro> {
    let oprf_out = voprf::finalize(
        estado.contrasena.as_bytes(),
        &estado.blind,
        &resp.evaluado,
        &resp.prueba,
        &resp.oprf_pub,
    )?;
    let cred = derivar(
        &estado.contrasena,
        &oprf_out,
        &ContextoSobre {
            usuario: estado.usuario.as_bytes(),
            salt: &salt,
            oprf_pub: &resp.oprf_pub,
            identidad_servidor,
        },
        esquema,
        params,
    )?;
    Some(SalidaRegistro {
        mensaje: RegistroFinal {
            usuario: estado.usuario.clone(),
            sobre: Sobre { salt, etiqueta_auth: cred.etiqueta_auth },
            clave_publica_cliente: cred.publica,
        },
        export_key: cred.export_key,
    })
}

// ───────────────────────── Login ─────────────────────────

/// Paso 1 del login: ciega la contraseña (ya normalizada, igual que en el registro).
pub fn iniciar_login(usuario: &str, contrasena: &str) -> Option<(EstadoLogin, IniciarLogin)> {
    let contrasena = normalizar(contrasena);
    let (blind, elemento_ciego) = voprf::blind(contrasena.as_bytes())?;
    Some((
        EstadoLogin {
            usuario: usuario.to_string(),
            contrasena,
            blind,
        },
        IniciarLogin {
            usuario: usuario.to_string(),
            elemento_ciego,
        },
    ))
}

/// Paso 2 del login: desciega el OPRF, reconstruye la credencial, VERIFICA el sobre
/// (en tiempo constante) y firma el transcript. Un sobre que no casa ⇒
/// `ContrasenaIncorrecta`, sin llegar a firmar.
pub fn terminar_login(
    estado: &EstadoLogin,
    resp: &RespuestaLogin,
    esquema: &impl EsquemaDeFirma,
    params: &KdfParams,
) -> Result<SalidaLogin, ErrorLogin> {
    let oprf_out = voprf::finalize(
        estado.contrasena.as_bytes(),
        &estado.blind,
        &resp.evaluado,
        &resp.prueba,
        &resp.oprf_pub,
    )
    .ok_or(ErrorLogin::PruebaOprfInvalida)?;

    let cred = derivar(
        &estado.contrasena,
        &oprf_out,
        &ContextoSobre {
            usuario: estado.usuario.as_bytes(),
            salt: &resp.sobre.salt,
            oprf_pub: &resp.oprf_pub,
            identidad_servidor: &resp.identidad_servidor,
        },
        esquema,
        params,
    )
    .ok_or(ErrorLogin::ErrorInterno)?;

    // ¿La contraseña abre el sobre? Comparación en tiempo constante.
    if !iguales_ct(&cred.etiqueta_auth, &resp.sobre.etiqueta_auth) {
        return Err(ErrorLogin::ContrasenaIncorrecta);
    }

    let transcript = transcript_login(&estado.usuario, &resp.identidad_servidor, &cred.publica, &resp.reto_servidor);
    let firma = esquema.firmar(&cred.privada, &transcript).ok_or(ErrorLogin::ErrorInterno)?;

    Ok(SalidaLogin {
        mensaje: LoginFinal { prueba_cliente: firma },
        export_key: cred.export_key,
    })
}

fn salt_aleatorio() -> Option<[u8; 16]> {
    let mut s = [0u8; 16];
    quipu::aleatorio::llenar(&mut s).ok()?;
    Some(s)
}
