// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **Bachué F3.b.2 — el REGISTRO de una passkey (WebAuthn *attestation*, `create()`).**
//!
//! El alta: convierte la respuesta de `navigator.credentials.create()` en una
//! [`crate::Credencial`] guardable —id, clave pública, algoritmo y contador inicial—, que
//! es justo lo que el login ([`crate::verificar_assertion`]) necesita después. Cierra el
//! ciclo: sin registro no hay credencial que verificar.
//!
//! # Qué valida (WebAuthn §7.1) y qué NO
//!
//! Valida lo que ata la nueva clave a ESTA ceremonia y a ESTE servicio: `clientDataJSON`
//! (`type == "webauthn.create"`, reto, origen), y del `authenticatorData` el hash del RP,
//! la presencia de usuario (y la verificación, según [`crate::Politica`]) y que traiga
//! datos de credencial. Extrae la clave pública del `COSE_Key` y la deja en **SEC1 sin
//! comprimir** (`0x04 ‖ x ‖ y`), que es lo que espera el verificador de firma —así el
//! parseo CBOR/COSE ocurre UNA vez, aquí, y no en cada login—.
//!
//! **NO verifica la cadena de *attestation* (el `attStmt`: `packed`, `tpm`, `x5c`…).** Para
//! el modelo de passkey de consumidor es lo estándar: los autenticadores de plataforma
//! (Apple, Google) usan `none` o no ofrecen una attestation verificable, y la seguridad del
//! alta la dan el reto, el origen y que la ceremonia ocurre DENTRO de una sesión ya
//! autenticada del usuario —el servicio liga la credencial a ese usuario—. Verificar la
//! cadena (para exigir un modelo/AAGUID concreto, caso empresarial) es una capa de política
//! aparte; se deja anotada, no implementada, en vez de fingirla.
//!
//! # Alcance de cripto de esta sub-fase
//!
//! Se extrae la clave **EC2 / P-256 / ES256** (COSE alg −7), la de la decisión de Juan y la
//! de la mayoría de las passkeys. Un `COSE_Key` de otra familia se rechaza con
//! [`MotivoRegistro::ClaveNoSoportada`] (fail-closed), no se adivina.
//!
//! **La clave NO se valida en-curva aquí, y es a propósito.** Comprobar que `(x,y)` está en
//! la curva P-256 exige aritmética de curva, que vive en el verificador (`p256`), no en este
//! andamiaje —que no arrastra esa dependencia—. Una clave off-curve se registra pero queda
//! inservible en el PRIMER login: `from_sec1_bytes` la rechaza y da `FirmaInvalida`. No abre
//! nada (el servidor solo verifica ECDSA; nunca hace ECDH con secreto contra este punto, así
//! que no hay ataque de curva inválida). Si un producto quisiera fallar en el alta con un
//! motivo claro, valida el SEC1 con su verificador antes de guardar; el motor no lo impone.
//!
//! # Por qué el parseo del `clientDataJSON` es seguro AQUÍ (y el argumento no es el del login)
//!
//! El login se apoya en que el `clientDataJSON` va cubierto por la firma (el mismo buffer se
//! hashea y se firma). **En el registro con attestation `none` ese argumento NO aplica**: el
//! `clientDataJSON` no está ligado a ninguna firma que se verifique. La seguridad de esta
//! ruta la dan otras dos cosas: el `origin` se compara por igualdad exacta (un phishing lo
//! delata: el navegador pone el origin REAL), y el `challenge` es un secreto de un solo uso
//! que solo existe en la ceremonia de la víctima. Una confusión del parser de subcadenas
//! seguiría siendo inerte —quien inyecta bytes directos escribe JSON limpio de todos modos y
//! necesita el reto, que el parseo no le da—. Se deja dicho para no heredar del login una
//! justificación que en esta ruta no se sostiene.

use sha2::{Digest, Sha256};

use crate::cbor::{self, Valor, entero};
use crate::{Algoritmo, ClavePublicaCose, Credencial, Desafio, Politica, iguales_en_tiempo_constante, parsear_datos_cliente};

/// El resultado de registrar. `Aceptado` trae la credencial lista para guardar (ligándola
/// al usuario autenticado, que es trabajo del servicio).
#[derive(Debug, Clone)]
pub enum Registro {
    /// El registro es válido; guarda esta credencial para el usuario en curso.
    Aceptado(Credencial),
    /// No se acepta, por este motivo (diagnóstico para el log; al cliente, respuesta uniforme).
    Rechazado(MotivoRegistro),
}

impl Registro {
    /// La credencial, si el registro fue aceptado.
    pub fn credencial(&self) -> Option<&Credencial> {
        match self {
            Registro::Aceptado(c) => Some(c),
            Registro::Rechazado(_) => None,
        }
    }
}

/// Por qué se rechazó un registro. Cada variante es un paso de §7.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MotivoRegistro {
    /// El `clientDataJSON` o el `attestationObject`/`authData` no se pudieron leer.
    DatosIlegibles,
    /// `clientData.type` no es `"webauthn.create"` (es un registro; `.get` es login).
    TipoIncorrecto,
    /// El reto firmado no es el que se emitió para esta ceremonia.
    DesafioNoCoincide,
    /// El `origin` no es el del servicio.
    OrigenNoCoincide,
    /// El hash del RP no casa: el alta se produjo para otro dominio.
    RpIdNoCoincide,
    /// No hubo gesto de presencia (bit UP en cero).
    UsuarioNoPresente,
    /// La política exigía verificación (PIN/biometría) y el bit UV está en cero.
    UsuarioNoVerificado,
    /// El `authData` no trae datos de credencial (bit AT en cero, o truncados): no hay clave
    /// que registrar.
    SinDatosDeCredencial,
    /// La clave pública no es una EC2 / P-256 / ES256 legible (otra familia, o corrupta).
    ClaveNoSoportada,
}

// Etiquetas COSE (RFC 9052/9053) que se leen del COSE_Key EC2.
const COSE_KTY: i64 = 1; // tipo de clave
const COSE_ALG: i64 = 3; // algoritmo
const COSE_CRV: i64 = -1; // curva (para EC2/OKP)
const COSE_X: i64 = -2; // coordenada x
const COSE_Y: i64 = -3; // coordenada y
const KTY_EC2: i64 = 2; // tipo EC2
const ALG_ES256: i64 = -7; // ECDSA P-256 / SHA-256
const CRV_P256: i64 = 1; // curva P-256

// Banderas del authenticatorData.
const FLAG_UP: u8 = 0b0000_0001; // usuario presente
const FLAG_UV: u8 = 0b0000_0100; // usuario verificado
const FLAG_AT: u8 = 0b0100_0000; // vienen datos de credencial (attested credential data)

/// **Verifica una respuesta de registro y, si cuadra, extrae la [`Credencial`].** Fail-closed:
/// cualquier paso que no encaje devuelve [`Registro::Rechazado`] con su motivo.
///
/// `attestation_object` son los bytes CBOR de `response.attestationObject`;
/// `client_data_json`, los de `response.clientDataJSON`. El contador inicial de la credencial
/// es el `signCount` del `authData` (que el login exigirá que avance).
pub fn verificar_registro(
    desafio_esperado: &Desafio,
    origen_esperado: &str,
    rp_id: &str,
    client_data_json: &[u8],
    attestation_object: &[u8],
    politica: &Politica,
) -> Registro {
    use MotivoRegistro::*;
    macro_rules! no {
        ($m:expr) => {
            return Registro::Rechazado($m)
        };
    }

    // 1) clientData: mismas comprobaciones que el login, pero el tipo es "webauthn.create".
    let Some(cliente) = parsear_datos_cliente(client_data_json) else { no!(DatosIlegibles) };
    if cliente.tipo != "webauthn.create" {
        no!(TipoIncorrecto)
    }
    if !iguales_en_tiempo_constante(cliente.desafio_b64.as_bytes(), desafio_esperado.como_b64url().as_bytes()) {
        no!(DesafioNoCoincide)
    }
    if cliente.origen != origen_esperado {
        no!(OrigenNoCoincide)
    }

    // 2) attestationObject (CBOR): { fmt, authData, attStmt }. Solo se necesita authData;
    //    el attStmt no se verifica (ver la cabecera del módulo).
    let Some(att) = cbor::parsear(attestation_object) else { no!(DatosIlegibles) };
    let Some(auth_data) = att.campo_texto("authData").and_then(Valor::como_bytes) else {
        no!(DatosIlegibles)
    };

    // 3) authData: rpIdHash[32] ‖ flags[1] ‖ signCount[4] ‖ attestedCredentialData…
    if auth_data.len() < 37 {
        no!(DatosIlegibles)
    }
    if auth_data[0..32] != Sha256::digest(rp_id.as_bytes())[..] {
        no!(RpIdNoCoincide)
    }
    let flags = auth_data[32];
    if flags & FLAG_UP == 0 {
        no!(UsuarioNoPresente)
    }
    if politica.exigir_verificacion_usuario && flags & FLAG_UV == 0 {
        no!(UsuarioNoVerificado)
    }
    if flags & FLAG_AT == 0 {
        no!(SinDatosDeCredencial)
    }
    let contador = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);

    // 4) attestedCredentialData: aaguid[16] ‖ credIdLen[2] ‖ credId[L] ‖ COSE_Key ‖ ext…
    let acd = &auth_data[37..];
    if acd.len() < 18 {
        no!(SinDatosDeCredencial)
    }
    let cred_id_len = usize::from(u16::from_be_bytes([acd[16], acd[17]]));
    let Some(cred_id) = acd.get(18..18 + cred_id_len) else { no!(SinDatosDeCredencial) };
    let resto = &acd[18 + cred_id_len..];

    // 5) COSE_Key (con las extensiones detrás, si las hay): leer UN valor y quedarse con él.
    let Some((cose, _consumidos)) = cbor::parsear_prefijo(resto) else { no!(ClaveNoSoportada) };
    let Some((alg, sec1)) = clave_ec2_a_sec1(&cose) else { no!(ClaveNoSoportada) };

    Registro::Aceptado(Credencial {
        id: cred_id.to_vec(),
        clave: ClavePublicaCose(sec1),
        alg,
        contador,
    })
}

/// Extrae de un `COSE_Key` EC2/P-256/ES256 el algoritmo y la clave pública en SEC1 sin
/// comprimir (`0x04 ‖ x ‖ y`). `None` si no es exactamente esa familia o si `x`/`y` no son
/// dos cadenas de 32 bytes (fail-closed: no se adivina una curva).
fn clave_ec2_a_sec1(cose: &Valor) -> Option<(Algoritmo, Vec<u8>)> {
    // Tiene que ser EC2, P-256 y ES256 — los tres, o no es lo que este verificador espera.
    if cose.campo_int(COSE_KTY).and_then(entero) != Some(KTY_EC2) {
        return None;
    }
    if cose.campo_int(COSE_ALG).and_then(entero) != Some(ALG_ES256) {
        return None;
    }
    if cose.campo_int(COSE_CRV).and_then(entero) != Some(CRV_P256) {
        return None;
    }
    let x = cose.campo_int(COSE_X).and_then(Valor::como_bytes)?;
    let y = cose.campo_int(COSE_Y).and_then(Valor::como_bytes)?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04); // punto sin comprimir
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    Some((Algoritmo::Es256, sec1))
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const RP_ID: &str = "cuenta.xiliux.com";
    const ORIGEN: &str = "https://cuenta.xiliux.com";

    fn client_data(tipo: &str, desafio_b64: &str, origen: &str) -> Vec<u8> {
        format!("{{\"type\":\"{tipo}\",\"challenge\":\"{desafio_b64}\",\"origin\":\"{origen}\"}}").into_bytes()
    }

    /// Codifica un COSE_Key EC2/P-256/ES256 con las coordenadas dadas (CBOR a mano, como lo
    /// haría el autenticador).
    fn cose_ec2(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
        let mut c = vec![0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01]; // {1:2, 3:-7, -1:1,
        c.extend_from_slice(&[0x21, 0x58, 0x20]); // -2: bstr(32)
        c.extend_from_slice(x);
        c.extend_from_slice(&[0x22, 0x58, 0x20]); // -3: bstr(32)
        c.extend_from_slice(y);
        c
    }

    /// Arma un attestationObject `{fmt:"none", attStmt:{}, authData:<bstr>}` con el authData
    /// dado.
    fn attestation(auth_data: &[u8]) -> Vec<u8> {
        // Mapa de 3: fmt/attStmt/authData.
        let mut c = vec![0xA3];
        c.extend_from_slice(&[0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e']); // "fmt":"none"
        c.extend_from_slice(&[0x67, b'a', b't', b't', b'S', b't', b'm', b't', 0xA0]); // "attStmt":{}
        c.extend_from_slice(&[0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a']); // "authData":
        // bstr con la longitud del auth_data.
        c.push(0x58);
        c.push(u8::try_from(auth_data.len()).expect("authData de prueba < 256"));
        c.extend_from_slice(auth_data);
        c
    }

    /// authData de registro: rpIdHash ‖ flags ‖ signCount ‖ (aaguid ‖ credIdLen ‖ credId ‖ cose).
    fn auth_data_registro(flags: u8, contador: u32, cred_id: &[u8], cose: &[u8]) -> Vec<u8> {
        let mut a = Sha256::digest(RP_ID.as_bytes()).to_vec();
        a.push(flags);
        a.extend_from_slice(&contador.to_be_bytes());
        a.extend_from_slice(&[0u8; 16]); // aaguid
        a.extend_from_slice(&u16::try_from(cred_id.len()).unwrap().to_be_bytes());
        a.extend_from_slice(cred_id);
        a.extend_from_slice(cose);
        a
    }

    /// **Un registro honesto se acepta y extrae la credencial con la clave en SEC1** — el
    /// positivo de control de todos los rechazos.
    #[test]
    fn un_registro_honesto_extrae_la_credencial_en_sec1() {
        let x = [0xAA; 32];
        let y = [0xBB; 32];
        let cose = cose_ec2(&x, &y);
        let ad = auth_data_registro(FLAG_UP | FLAG_UV | FLAG_AT, 5, b"mi-credencial", &cose);
        let ao = attestation(&ad);
        let desafio = Desafio::nuevo();
        let cd = client_data("webauthn.create", &desafio.como_b64url(), ORIGEN);

        let r = verificar_registro(&desafio, ORIGEN, RP_ID, &cd, &ao, &Politica::default());
        let cred = r.credencial().expect("registro aceptado");
        assert_eq!(cred.id, b"mi-credencial");
        assert_eq!(cred.alg, Algoritmo::Es256);
        assert_eq!(cred.contador, 5);
        // La clave quedó en SEC1: 0x04 ‖ x ‖ y.
        let mut esperada = vec![0x04];
        esperada.extend_from_slice(&x);
        esperada.extend_from_slice(&y);
        assert_eq!(cred.clave.0, esperada);
    }

    // El ciclo COMPLETO registro→login con una firma ES256 REAL vive en el crate
    // `bachue-passkey-es256` (`registro_y_login_con_firma_es256_real`), que es quien tiene
    // el verificador de cripto real; aquí el registro se prueba con COSE construido a mano.

    /// Cada rechazo por su motivo, cada uno cambiando UNA cosa respecto del registro honesto
    /// (directiva 33: no un banco de solo-rojos sobre datos que igual fallan).
    #[test]
    fn cada_rechazo_tiene_su_motivo() {
        let cose = cose_ec2(&[0xAA; 32], &[0xBB; 32]);
        let desafio = Desafio::nuevo();
        let ok_flags = FLAG_UP | FLAG_UV | FLAG_AT;
        let reg = |cd: &[u8], ao: &[u8], pol: &Politica| verificar_registro(&desafio, ORIGEN, RP_ID, cd, ao, pol);

        let ad = auth_data_registro(ok_flags, 0, b"c", &cose);
        let ao = attestation(&ad);
        let cd_ok = client_data("webauthn.create", &desafio.como_b64url(), ORIGEN);

        // tipo de login en vez de registro
        let cd = client_data("webauthn.get", &desafio.como_b64url(), ORIGEN);
        assert!(matches!(reg(&cd, &ao, &Politica::default()), Registro::Rechazado(MotivoRegistro::TipoIncorrecto)));

        // reto ajeno
        let cd = client_data("webauthn.create", &Desafio::nuevo().como_b64url(), ORIGEN);
        assert!(matches!(reg(&cd, &ao, &Politica::default()), Registro::Rechazado(MotivoRegistro::DesafioNoCoincide)));

        // origen ajeno
        let cd = client_data("webauthn.create", &desafio.como_b64url(), "https://malo.example");
        assert!(matches!(reg(&cd, &ao, &Politica::default()), Registro::Rechazado(MotivoRegistro::OrigenNoCoincide)));

        // rpId ajeno (authData con otro hash)
        let mut ad_rp = ad; // último uso de ad (ao ya está construido): se mueve
        ad_rp[0..32].copy_from_slice(Sha256::digest(b"otra.example".as_slice()).as_slice());
        assert!(matches!(reg(&cd_ok, &attestation(&ad_rp), &Politica::default()), Registro::Rechazado(MotivoRegistro::RpIdNoCoincide)));

        // sin UP
        let ad_up = auth_data_registro(FLAG_UV | FLAG_AT, 0, b"c", &cose);
        assert!(matches!(reg(&cd_ok, &attestation(&ad_up), &Politica::default()), Registro::Rechazado(MotivoRegistro::UsuarioNoPresente)));

        // sin UV con política que lo exige, y su pareja: con política flexible, ese mismo abre
        let ad_uv = auth_data_registro(FLAG_UP | FLAG_AT, 0, b"c", &cose);
        assert!(matches!(reg(&cd_ok, &attestation(&ad_uv), &Politica::default()), Registro::Rechazado(MotivoRegistro::UsuarioNoVerificado)));
        let flexible = Politica { exigir_verificacion_usuario: false };
        assert!(reg(&cd_ok, &attestation(&ad_uv), &flexible).credencial().is_some());

        // sin AT (no trae datos de credencial)
        let ad_at = auth_data_registro(FLAG_UP | FLAG_UV, 0, b"c", &cose);
        // Sin el bit AT, aunque los bytes estén, se rechaza por bandera.
        assert!(matches!(reg(&cd_ok, &attestation(&ad_at), &Politica::default()), Registro::Rechazado(MotivoRegistro::SinDatosDeCredencial)));

        // clave no soportada: un COSE con alg RS256 (−257) en vez de ES256
        let mut cose_rs = vec![0xA5, 0x01, 0x02, 0x03, 0x39, 0x01, 0x00, 0x20, 0x01]; // 3:-257
        cose_rs.extend_from_slice(&[0x21, 0x58, 0x20]);
        cose_rs.extend_from_slice(&[0xAA; 32]);
        cose_rs.extend_from_slice(&[0x22, 0x58, 0x20]);
        cose_rs.extend_from_slice(&[0xBB; 32]);
        let ad_rs = auth_data_registro(ok_flags, 0, b"c", &cose_rs);
        assert!(matches!(reg(&cd_ok, &attestation(&ad_rs), &Politica::default()), Registro::Rechazado(MotivoRegistro::ClaveNoSoportada)));

        // attestationObject basura
        assert!(matches!(reg(&cd_ok, b"no-es-cbor", &Politica::default()), Registro::Rechazado(MotivoRegistro::DatosIlegibles)));

        // y el control: el honesto abre
        assert!(reg(&cd_ok, &ao, &Politica::default()).credencial().is_some());
    }

    /// Una credencialId más larga de lo que trae el authData se rechaza sin pánico (longitud
    /// mentirosa en el attestedCredentialData).
    #[test]
    fn una_longitud_de_credencial_mentirosa_no_revienta() {
        let cose = cose_ec2(&[1; 32], &[2; 32]);
        // authData con credIdLen declarado enorme.
        let mut a = Sha256::digest(RP_ID.as_bytes()).to_vec();
        a.push(FLAG_UP | FLAG_UV | FLAG_AT);
        a.extend_from_slice(&0u32.to_be_bytes());
        a.extend_from_slice(&[0u8; 16]); // aaguid
        a.extend_from_slice(&0xFFFFu16.to_be_bytes()); // credIdLen = 65535 (mentira)
        a.extend_from_slice(b"corto");
        a.extend_from_slice(&cose);
        let desafio = Desafio::nuevo();
        let cd = client_data("webauthn.create", &desafio.como_b64url(), ORIGEN);
        assert!(matches!(
            verificar_registro(&desafio, ORIGEN, RP_ID, &cd, &attestation(&a), &Politica::default()),
            Registro::Rechazado(MotivoRegistro::SinDatosDeCredencial)
        ));
    }
}
