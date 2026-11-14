// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **El lado del servidor.** Tiene la semilla OPRF maestra y las identidades; nunca ve
//! la contraseña. Deriva la clave OPRF por-usuario al vuelo, guarda `{sobre, clave
//! pública}` y verifica la firma del login.

use quipu::kdf::{self, KdfParams};
use quipu::voprf::rfc9497 as voprf;

use crate::cliente::transcript_login;
use crate::etiquetas;
use crate::firma::EsquemaDeFirma;
use crate::mensajes::{
    IniciarLogin, IniciarRegistro, LoginFinal, RegistroFinal, RegistroGuardado, RespuestaLogin,
    RespuestaRegistro, Sobre, Veredicto,
};
use crate::con_longitudes;

/// El servidor de credenciales. Config, no estado por-usuario: la clave OPRF de cada
/// usuario se re-deriva de `semilla_oprf` + usuario, y los registros los persiste la app.
#[derive(Debug, Clone)]
pub struct Servidor {
    semilla_oprf: [u8; 32],
    identidad: Vec<u8>,
    params: KdfParams,
}

/// Estado del servidor entre los dos pasos del login: a quién desafió, con qué reto, y
/// con qué clave pública verificar (o `None` si el usuario no existe y se respondió con
/// un señuelo).
#[derive(Debug, Clone)]
pub struct EstadoLoginServidor {
    usuario: String,
    reto: [u8; 32],
    clave_publica_cliente: Option<Vec<u8>>,
}

impl Servidor {
    /// `semilla_oprf`: 32 B secretos, la raíz de las claves OPRF por-usuario (guardarlos
    /// como cualquier secreto maestro). `identidad`: el nombre del servidor que se liga
    /// en el sobre y el login (p. ej. `b"cuenta.xiliux.com"`). `params`: coste Argon2id.
    #[must_use]
    pub fn nuevo(semilla_oprf: [u8; 32], identidad: Vec<u8>, params: KdfParams) -> Self {
        Self { semilla_oprf, identidad, params }
    }

    /// El coste Argon2id configurado — el cliente debe usar el MISMO al derivar, o `rwd`
    /// no coincidirá. Se expone para que el servidor se lo comunique.
    #[must_use]
    pub fn params(&self) -> &KdfParams {
        &self.params
    }

    /// La identidad del servidor, tal como se liga en sobre y login.
    #[must_use]
    pub fn identidad(&self) -> &[u8] {
        &self.identidad
    }

    /// Deriva el servidor OPRF por-usuario. Determinista: mismo usuario ⇒ misma clave.
    fn oprf_de(&self, usuario: &str) -> Option<voprf::Server> {
        voprf::Server::from_seed(&self.semilla_oprf, usuario.as_bytes())
    }

    /// Registro, paso servidor: evalúa el OPRF ciego con la clave del usuario.
    pub fn responder_registro(&self, ini: &IniciarRegistro) -> Option<RespuestaRegistro> {
        let srv = self.oprf_de(&ini.usuario)?;
        let (evaluado, prueba) = srv.blind_evaluate(&ini.elemento_ciego)?;
        Some(RespuestaRegistro {
            evaluado,
            prueba,
            oprf_pub: srv.public_key(),
        })
    }

    /// Convierte el mensaje final del cliente en el registro a PERSISTIR, RECHAZANDO
    /// (ruidoso, directiva 20) una clave pública malformada en vez de guardarla y diferir
    /// el fallo a un login mudo. `None` = la clave no deserializa. Requiere el `esquema`
    /// porque la forma válida de la clave es específica del esquema de firma.
    pub fn guardar_registro(
        &self,
        fin: RegistroFinal,
        esquema: &impl EsquemaDeFirma,
    ) -> Option<RegistroGuardado> {
        if !esquema.clave_publica_valida(&fin.clave_publica_cliente) {
            return None;
        }
        Some(RegistroGuardado {
            usuario: fin.usuario,
            sobre: fin.sobre,
            clave_publica_cliente: fin.clave_publica_cliente,
        })
    }

    /// Login, paso servidor: evalúa el OPRF, genera un reto fresco y devuelve el sobre.
    ///
    /// `registro` = `Some(r)` para un usuario existente; `None` para uno que no existe,
    /// y entonces se responde con un **sobre-señuelo determinista** (misma forma, mismo
    /// tamaño) para no filtrar quién está registrado — el login fallará luego en la
    /// verificación. La constancia de TIEMPO de los dos caminos es del integrador.
    pub fn responder_login(
        &self,
        ini: &IniciarLogin,
        registro: Option<&RegistroGuardado>,
    ) -> Option<(RespuestaLogin, EstadoLoginServidor)> {
        let srv = self.oprf_de(&ini.usuario)?;
        let (evaluado, prueba) = srv.blind_evaluate(&ini.elemento_ciego)?;
        let mut reto = [0u8; 32];
        quipu::aleatorio::llenar(&mut reto).ok()?;

        let (sobre, clave_publica_cliente) = match registro {
            Some(r) => (r.sobre.clone(), Some(r.clave_publica_cliente.clone())),
            None => (self.sobre_senuelo(&ini.usuario), None),
        };

        let resp = RespuestaLogin {
            evaluado,
            prueba,
            oprf_pub: srv.public_key(),
            sobre,
            identidad_servidor: self.identidad.clone(),
            reto_servidor: reto,
        };
        let estado = EstadoLoginServidor {
            usuario: ini.usuario.clone(),
            reto,
            clave_publica_cliente,
        };
        Some((resp, estado))
    }

    /// Login, verificación: ¿la firma del cliente valida contra la clave pública
    /// guardada, sobre el transcript que ligó usuario, identidad, clave y reto? Un
    /// usuario inexistente (señuelo, sin clave guardada) ⇒ `Rechazado`.
    #[must_use]
    pub fn verificar_login(
        &self,
        estado: &EstadoLoginServidor,
        fin: &LoginFinal,
        esquema: &impl EsquemaDeFirma,
    ) -> Veredicto {
        let Some(publica) = &estado.clave_publica_cliente else {
            return Veredicto::Rechazado;
        };
        let transcript = transcript_login(&estado.usuario, &self.identidad, publica, &estado.reto);
        if esquema.verificar(publica, &transcript, &fin.prueba_cliente) {
            Veredicto::Autenticado { usuario: estado.usuario.clone() }
        } else {
            Veredicto::Rechazado
        }
    }

    /// Sobre-señuelo DETERMINISTA para un usuario inexistente: mismo usuario ⇒ mismo
    /// sobre (si cambiara en cada intento, la variación delataría al no registrado). Se
    /// deriva de la semilla maestra, así que es indistinguible de uno real sin la clave.
    fn sobre_senuelo(&self, usuario: &str) -> Sobre {
        // La semilla maestra entra en HKDF UNA sola vez, con etiqueta fija, para una raíz
        // DEDICADA al señuelo; lo por-usuario cuelga de esa raíz, no de la semilla cruda.
        // Así ningún byte de la maestra entra crudo en dos algoritmos distintos —aquí y en
        // `Server::from_seed` del OPRF— (separación de dominio, directiva 1).
        let raiz_senuelo = kdf::derive_subkey(&self.semilla_oprf, etiquetas::SENUELO);
        let raiz = kdf::derive_subkey(&raiz_senuelo, &con_longitudes(&[usuario.as_bytes()]));
        let salt_full = kdf::derive_subkey(&raiz, b"salt");
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_full[..16]);
        let etiqueta_auth = kdf::derive_subkey(&raiz, b"tag");
        Sobre { salt, etiqueta_auth }
    }
}
