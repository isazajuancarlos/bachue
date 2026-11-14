// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! El estado compartido del servidor y su configuración.

use sqlx::SqlitePool;
use std::sync::Arc;

#[derive(Clone)]
pub struct Estado {
    pub pool: SqlitePool,
    pub cfg: Arc<Config>,
    /// TODAS las generaciones de la clave OIDC (v1..=activa), en orden. La ÚLTIMA firma; el
    /// resto se conservan para VERIFICAR (concilio 2026-09-24, hallazgo sonnet): así al rotar,
    /// un access_token firmado por una generación anterior aún se valida en `/userinfo`
    /// —«rotación sin invalidar tokens» de verdad, no solo para el id_token vía JWKS—. Derivadas
    /// de la SEMILLA OIDC (no de la BD, y no del secreto de sesión: D32, hallazgo fable).
    pub oidc_generaciones: Arc<Vec<bachue_oidc::ClaveEmisor>>,
}

impl Estado {
    /// La clave ACTIVA (la de la generación mayor): la que FIRMA id_token y access_token.
    #[must_use]
    pub fn oidc_activa(&self) -> &bachue_oidc::ClaveEmisor {
        self.oidc_generaciones.last().expect("siempre hay ≥1 generación")
    }
}

/// Etiqueta de DOMINIO de la generación con la que se deriva la clave OIDC de la SEMILLA OIDC.
/// La generación permite ROTAR: se sube, la clave nueva firma y las anteriores se siguen
/// publicando/verificando hasta que caduquen sus tokens.
#[must_use]
pub fn etiqueta_oidc(generacion: u32) -> String {
    format!("bachue-idp/oidc-firma-v{generacion}")
}

/// Deriva TODAS las claves OIDC de la `semilla` para la generación activa `generacion`: las de
/// `1..=generacion` en orden (la última es la ACTIVA que firma; todas se usan para verificar y
/// publicar en el JWKS). La semilla es la RAÍZ propia de OIDC, independiente del secreto de
/// sesión (D32): rotar el secreto de sesión no rota estas claves, y viceversa.
#[must_use]
pub fn claves_oidc(semilla: &[u8], generacion: u32) -> Vec<bachue_oidc::ClaveEmisor> {
    (1..=generacion.max(1))
        .map(|g| bachue_oidc::ClaveEmisor::derivar(semilla, &etiqueta_oidc(g)))
        .collect()
}

/// La política de obligatoriedad del segundo factor (`BACHUE_IDP_2FA`). Cascada (D19):
/// - `off` — opt-in; cada quien lo activa si quiere (compatibilidad hacia atrás; es el default).
/// - `gracia` — se EXIGE, pero un usuario sin 2FA tiene una ventana ([`GRACIA_2FA_DIAS`]) para
///   enrolarse; pasada, se le fuerza. Los usuarios NUEVOS se enrolan al reclamar, sin ventana.
/// - `estricto` — se exige YA: un usuario sin 2FA es forzado a enrolar en el próximo login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modo2fa {
    Off,
    Gracia,
    Estricto,
}

impl Modo2fa {
    /// ¿Exige el 2FA (con ventana o sin ella)? `Off` no; los otros sí.
    #[must_use]
    pub fn exige(self) -> bool {
        !matches!(self, Modo2fa::Off)
    }
}

/// Días de ventana en modo `gracia` antes de forzar el enrolamiento de un usuario existente.
pub const GRACIA_2FA_DIAS: i64 = 7;

pub struct Config {
    /// Secreto HMAC de las sesiones (`bachue::sesion`). ≥ 32 bytes.
    pub secreto: Vec<u8>,
    /// Cuántos proxies inversos de confianza hay delante (para `defensas::red`): fija de
    /// dónde se cree la IP del cliente. 0 = sin proxy, se usa la IP del socket.
    pub proxies: usize,
    /// `true` = cookies `__Host-` con `Secure` (producción, tras TLS). Solo se relaja a
    /// mano para desarrollo local sobre http.
    pub seguro: bool,
    /// Frase para cifrar el secreto TOTP en reposo (`guaca::reposo`). Derivada del secreto
    /// maestro con una etiqueta de DOMINIO distinta de la firma de sesión: el robo de la
    /// BD sin esta frase no da los secretos TOTP.
    ///
    /// **CAVEAT OPERATIVO (revisión D25):** al derivarse de `BACHUE_IDP_SECRETO`, rotar ese
    /// secreto cambia la frase y **ningún secreto TOTP ya guardado descifra** — cada login
    /// con 2FA caerá en error 500 (fail-closed) hasta que esos usuarios **re-enrolen** el
    /// segundo factor. Rotar el secreto ya invalida las sesiones (reversible: se re-entra),
    /// pero además exige re-enrolar el 2FA. Si eso no es aceptable, dale al TOTP su propia
    /// clave rotable aparte (directiva 32: un valor con dos usos son dos campos).
    pub frase_totp: String,
    /// ¿Está ABIERTO el registro público (`/registrarse`)? Por defecto NO: en el modelo
    /// "pago primero" el alta es por suscripción (webhook → `/aprovisionar` → `/establecer`),
    /// no por un formulario de registro que cualquiera rellena. Se abre a mano para un
    /// despliegue que sí quiera registro libre (`BACHUE_IDP_REGISTRO_ABIERTO=1`).
    pub registro_abierto: bool,
    /// Secreto compartido que autentica a `POST /aprovisionar` (la llamada máquina-a-máquina
    /// desde tunjo-saas tras un pago verificado). `None` = endpoint DESHABILITADO (503), igual
    /// que el webhook de Paddle sin secreto: se falla CERRADO, nunca con un secreto por defecto
    /// (directiva 20). Se compara en tiempo constante.
    pub secreto_aprovisionar: Option<Vec<u8>>,
    /// Clientes OIDC registrados (config ESTÁTICA, decisión de Juan 2026-09-24): cada uno con
    /// su `client_id` y su lista EXACTA de `redirect_uris` permitidas. Vacío = OIDC
    /// authorize/token deshabilitados (no hay a quién emitir). Son clientes PÚBLICOS (PKCE
    /// obligatorio, sin `client_secret`).
    pub clientes_oidc: Vec<ClienteOidc>,
    /// URL PÚBLICA del IdP (el `issuer` OIDC, `iss` del id_token: p.ej.
    /// `https://idp.xiliux.com`). El IdP va detrás de un proxy, así que no puede deducirla; se
    /// declara. OBLIGATORIA si hay clientes OIDC (un id_token con `iss` vacío lo rechaza todo
    /// RP, D20). `String` vacío cuando OIDC está apagado.
    pub emisor_oidc: String,
    /// Generación ACTIVA de la clave de firma OIDC (`BACHUE_IDP_OIDC_GEN`, por defecto 1). Se
    /// sube a mano para ROTAR: la clave nueva firma, las anteriores se siguen publicando.
    pub oidc_generacion: u32,
    /// RAÍZ (semilla) de la que se deriva la clave de firma OIDC —`BACHUE_IDP_OIDC_SEMILLA`,
    /// SEPARADA del secreto de sesión (D32, hallazgo del concilio fable): así rotar el secreto
    /// de sesión (para cerrar sesiones) NO rota la clave OIDC ni rompe el JWKS, y un compromiso
    /// del secreto de sesión no da la clave del emisor. Obligatoria (≥32 B) si hay clientes
    /// OIDC; vacía cuando OIDC está apagado.
    pub oidc_semilla: Vec<u8>,
    /// Política de obligatoriedad del 2FA (`BACHUE_IDP_2FA`). Default [`Modo2fa::Off`] (D20/D36:
    /// un knob nuevo no cambia el comportamiento del despliegue vivo en silencio). Cada
    /// despliegue elige su nivel donde se lee.
    pub dos_factor: Modo2fa,
    /// RP ID de WebAuthn/passkeys (`BACHUE_IDP_RP_ID`): el dominio registrable al que se atan
    /// las credenciales (p.ej. `cuenta.xiliux.com`). VACÍO = passkeys DESACTIVADAS (los
    /// endpoints devuelven 404), igual que OIDC sin clientes: una capa opcional no se enciende
    /// sola (D20/D36). No se deduce del issuer: el RP ID gobierna a qué dominios sirve la
    /// credencial y es una decisión de despliegue, no una derivación.
    pub passkey_rp_id: String,
    /// El `origin` EXACTO que el navegador pondrá en el `clientDataJSON` y que la ceremonia
    /// compara por igualdad (`BACHUE_IDP_PASSKEY_ORIGEN`; por defecto `https://{rp_id}`). Va
    /// aparte del RP ID porque no siempre coinciden (puerto, o un subdominio que comparte el
    /// RP ID registrable). Vacío cuando las passkeys están desactivadas.
    pub passkey_origen: String,
}

impl Config {
    /// ¿Están ACTIVADAS las passkeys en este despliegue? Lo decide tener un RP ID.
    #[must_use]
    pub fn passkey_activo(&self) -> bool {
        !self.passkey_rp_id.is_empty()
    }
}

/// Un cliente (Relying Party) OIDC registrado estáticamente.
#[derive(Clone, serde::Deserialize)]
pub struct ClienteOidc {
    pub client_id: String,
    /// URIs de retorno permitidas. La coincidencia es EXACTA (byte a byte): un `redirect_uri`
    /// que no esté aquí se rechaza — es la barrera contra el open-redirect / robo de código.
    pub redirect_uris: Vec<String>,
}

impl Config {
    /// El cliente OIDC con ese `client_id`, si está registrado.
    #[must_use]
    pub fn cliente_oidc(&self, client_id: &str) -> Option<&ClienteOidc> {
        self.clientes_oidc.iter().find(|c| c.client_id == client_id)
    }
}

impl Config {
    /// Lee la config del entorno. FALLA RUIDOSO (directiva 20) si falta el secreto o es
    /// corto: un IdP sin secreto de sesión no debe arrancar —firmaría con basura—, y uno
    /// que se inventara un secreto al azar en cada arranque invalidaría todas las sesiones
    /// vivas sin decir por qué.
    pub fn desde_entorno() -> Result<Self, String> {
        let secreto = std::env::var("BACHUE_IDP_SECRETO")
            .map_err(|_| "falta BACHUE_IDP_SECRETO (secreto HMAC de sesión, ≥ 32 bytes)".to_string())?;
        if secreto.len() < 32 {
            return Err(format!(
                "BACHUE_IDP_SECRETO mide {} bytes; se exigen ≥ 32",
                secreto.len()
            ));
        }
        let proxies = std::env::var("BACHUE_IDP_PROXIES")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        let seguro = std::env::var("BACHUE_IDP_INSEGURO").is_err();
        let frase_totp = format!("{secreto}|bachue-idp/totp-reposo-v1");
        // Registro público: CERRADO por defecto (pago primero). Se abre con "1"/"true".
        let registro_abierto = std::env::var("BACHUE_IDP_REGISTRO_ABIERTO")
            .map(|v| matches!(v.trim(), "1" | "true" | "TRUE"))
            .unwrap_or(false);
        // Secreto de aprovisionamiento: si está, se exige ≥ 32 bytes (misma vara que el de
        // sesión); si falta, el endpoint queda deshabilitado (503), no se inventa uno.
        let secreto_aprovisionar = match std::env::var("BACHUE_IDP_APROVISIONAR_SECRETO") {
            Ok(s) if s.len() >= 32 => Some(s.into_bytes()),
            Ok(s) if !s.is_empty() => {
                return Err(format!(
                    "BACHUE_IDP_APROVISIONAR_SECRETO mide {} bytes; se exigen ≥ 32",
                    s.len()
                ));
            }
            _ => None,
        };
        // Clientes OIDC: JSON `[{"client_id":"...","redirect_uris":["..."]}]` en
        // BACHUE_IDP_OIDC_CLIENTES. Ausente/vacío = OIDC deshabilitado (no se inventa un
        // cliente por defecto, D20). Malformado = FALLA RUIDOSO (no arranca a medias).
        let clientes_oidc = match std::env::var("BACHUE_IDP_OIDC_CLIENTES") {
            Ok(s) if !s.trim().is_empty() => serde_json::from_str::<Vec<ClienteOidc>>(&s)
                .map_err(|e| format!("BACHUE_IDP_OIDC_CLIENTES no es un JSON válido de clientes: {e}"))?,
            _ => Vec::new(),
        };
        // El issuer: obligatorio si hay clientes OIDC (un id_token sin `iss` no vale, D20).
        let emisor_oidc = std::env::var("BACHUE_IDP_EMISOR").unwrap_or_default();
        if !clientes_oidc.is_empty() && emisor_oidc.trim().is_empty() {
            return Err("hay clientes OIDC pero falta BACHUE_IDP_EMISOR (el issuer, p.ej. https://idp.xiliux.com)".to_string());
        }
        // Generación activa de la clave OIDC (rotación). Por defecto 1; nunca 0.
        let oidc_generacion = std::env::var("BACHUE_IDP_OIDC_GEN")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(1)
            .max(1);
        // Semilla OIDC: raíz PROPIA de la firma del emisor, separada del secreto de sesión
        // (D32). Obligatoria (≥32 B) si hay clientes; si no, vacía. Falla ruidoso (D20).
        let oidc_semilla = match std::env::var("BACHUE_IDP_OIDC_SEMILLA") {
            Ok(s) if s.len() >= 32 => s.into_bytes(),
            Ok(s) if !s.is_empty() => {
                return Err(format!("BACHUE_IDP_OIDC_SEMILLA mide {} bytes; se exigen ≥ 32", s.len()));
            }
            _ if !clientes_oidc.is_empty() => {
                return Err("hay clientes OIDC pero falta BACHUE_IDP_OIDC_SEMILLA (la raíz de la clave de firma, ≥32 B, SEPARADA del secreto de sesión)".to_string());
            }
            _ => Vec::new(),
        };

        // Política de 2FA. Default off (no sorprende al despliegue vivo, D36). Un valor
        // inválido falla RUIDOSO (D20), nunca cae a un default silencioso.
        let dos_factor = match std::env::var("BACHUE_IDP_2FA").as_deref() {
            Ok("off") | Err(_) => Modo2fa::Off,
            Ok("gracia") => Modo2fa::Gracia,
            Ok("estricto") => Modo2fa::Estricto,
            Ok(otro) => {
                return Err(format!("BACHUE_IDP_2FA='{otro}' no es válido (off|gracia|estricto)"));
            }
        };

        // Passkeys (F3): el RP ID enciende la capa. Vacío = desactivadas (D20/D36: no se
        // encienden solas). El origen por defecto es `https://{rp_id}`; se puede fijar aparte
        // para un puerto o subdominio distinto, o para dev sobre http (localhost).
        let passkey_rp_id = std::env::var("BACHUE_IDP_RP_ID").unwrap_or_default().trim().to_string();
        let passkey_origen = if passkey_rp_id.is_empty() {
            String::new()
        } else {
            std::env::var("BACHUE_IDP_PASSKEY_ORIGEN")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("https://{passkey_rp_id}"))
        };

        Ok(Config {
            secreto: secreto.into_bytes(),
            proxies,
            seguro,
            frase_totp,
            registro_abierto,
            secreto_aprovisionar,
            clientes_oidc,
            emisor_oidc,
            oidc_generacion,
            oidc_semilla,
            dos_factor,
            passkey_rp_id,
            passkey_origen,
        })
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn rotacion_publica_activa_mas_anteriores() {
        let secreto = b"un-secreto-maestro-de-al-menos-32-bytes!!";
        // Gen 1: una sola clave, y la activa es la v1.
        let g1 = claves_oidc(secreto, 1);
        assert_eq!(g1.len(), 1, "generacion 1: una clave");
        let (activa1, jwks1): (&bachue_oidc::ClaveEmisor, Vec<serde_json::Value>) =
            (g1.last().unwrap(), g1.iter().map(bachue_oidc::ClaveEmisor::jwk).collect());
        assert_eq!(jwks1[0]["kid"], activa1.kid());

        // Gen 3: la activa es la v3 (firma), y se conservan v1, v2, v3 (los tokens viejos
        // siguen verificando). La activa es la ÚLTIMA.
        let g3 = claves_oidc(secreto, 3);
        assert_eq!(g3.len(), 3, "generacion 3: activa + 2 anteriores");
        assert_eq!(g3[2].kid(), g3.last().unwrap().kid(), "la activa es la generación mayor");
        // La v1 de generacion 3 es la MISMA que la activa de generacion 1 (determinismo).
        assert_eq!(g3[0].kid(), activa1.kid(), "las anteriores no cambian al rotar");
        // Gen 0 se trata como 1 (nunca vacío).
        assert_eq!(claves_oidc(secreto, 0).len(), 1);
    }
}
