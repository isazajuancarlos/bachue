// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **El esquema de firma de la prueba de login**, tras un trait — el mismo patrón que
//! `bachue-passkey` puso la firma tras `VerificadorDeFirma`: el PROTOCOLO no fija la
//! primitiva, y así la elección (híbrida PQ hoy, otra mañana) es una decisión aparte.
//!
//! La clave del cliente se deriva DETERMINÍSTICAMENTE de una semilla que sale de `rwd`,
//! así que no se guarda cifrada ni se transmite: el cliente la reconstruye en cada
//! login a partir de su contraseña. Por eso el trait deriva de una semilla, no genera
//! al azar.

use quipu::pqsign;

/// Un par de firma ya derivado: bytes serializados de la privada y de la pública.
#[derive(Debug, Clone)]
pub struct ParDeFirma {
    /// Clave privada serializada (el cliente la usa y la descarta; nunca sale).
    pub privada: Vec<u8>,
    /// Clave pública serializada (el servidor la guarda en el registro).
    pub publica: Vec<u8>,
}

/// El esquema de firma que prueba el login. Determinista desde semilla, para que el
/// cliente reconstruya su clave a partir de `rwd` sin almacenarla.
pub trait EsquemaDeFirma {
    /// Cuántos bytes de semilla necesita [`derivar`](EsquemaDeFirma::derivar). El
    /// cliente expande exactamente esos de `rwd`.
    fn bytes_de_semilla(&self) -> usize;

    /// Deriva el par de firma de una semilla de EXACTAMENTE
    /// [`bytes_de_semilla`](EsquemaDeFirma::bytes_de_semilla) bytes. `None` si la
    /// semilla no tiene la longitud debida o no forma una clave válida.
    fn derivar(&self, semilla: &[u8]) -> Option<ParDeFirma>;

    /// Firma `mensaje` con la privada serializada. `None` si la privada es inválida.
    fn firmar(&self, privada: &[u8], mensaje: &[u8]) -> Option<Vec<u8>>;

    /// Verifica `firma` sobre `mensaje` contra la pública serializada. `false` ante
    /// cualquier cosa que no valide (clave o firma malformada incluidas): fail-closed.
    fn verificar(&self, publica: &[u8], mensaje: &[u8], firma: &[u8]) -> bool;

    /// ¿La clave pública serializada está BIEN FORMADA (deserializa a una clave usable)?
    /// Sirve para RECHAZAR en el registro una clave basura en vez de diferirlo a un login
    /// mudo (directiva 20: fallar ruidoso donde se puede). Una clave malformada sólo
    /// auto-inutiliza la cuenta del propio cliente —no afecta a terceros—, pero un error
    /// temprano y claro es mejor que un `Rechazado` inexplicable meses después.
    fn clave_publica_valida(&self, publica: &[u8]) -> bool;
}

/// El esquema por defecto: firma **híbrida Ed25519 + ML-DSA-87** (`quipu::pqsign`).
/// Verifica sólo si AMBAS mitades validan, así que una firma vale mientras cualquiera
/// de las dos primitivas siga en pie —el sentido de la hibridación post-cuántica—.
///
/// La semilla son 64 bytes = semilla Ed25519 (32) ‖ semilla ML-DSA (32); las dos son
/// semillas, así que cualesquiera 64 bytes uniformes forman un par válido y
/// determinista (`SigningKey::from_bytes`).
#[derive(Debug, Clone, Copy, Default)]
pub struct FirmaHibridaPq;

impl EsquemaDeFirma for FirmaHibridaPq {
    fn bytes_de_semilla(&self) -> usize {
        pqsign::SIGNING_KEY_LEN // 64
    }

    fn derivar(&self, semilla: &[u8]) -> Option<ParDeFirma> {
        let sk = pqsign::SigningKey::from_bytes(semilla)?;
        let publica = sk.verifying_key().to_bytes();
        Some(ParDeFirma {
            privada: sk.to_bytes().to_vec(),
            publica,
        })
    }

    fn firmar(&self, privada: &[u8], mensaje: &[u8]) -> Option<Vec<u8>> {
        let sk = pqsign::SigningKey::from_bytes(privada)?;
        Some(sk.sign(mensaje))
    }

    fn verificar(&self, publica: &[u8], mensaje: &[u8], firma: &[u8]) -> bool {
        match pqsign::VerifyingKey::from_bytes(publica) {
            Some(vk) => vk.verify(mensaje, firma),
            None => false,
        }
    }

    fn clave_publica_valida(&self, publica: &[u8]) -> bool {
        pqsign::VerifyingKey::from_bytes(publica).is_some()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn deriva_determinista_desde_semilla() {
        let e = FirmaHibridaPq;
        let semilla = [3u8; 64];
        let a = e.derivar(&semilla).expect("64 bytes derivan par");
        let b = e.derivar(&semilla).expect("otra vez");
        assert_eq!(a.publica, b.publica, "misma semilla ⇒ misma pública");
        assert_eq!(a.privada, b.privada, "misma semilla ⇒ misma privada");
    }

    #[test]
    fn semilla_de_otra_longitud_no_deriva() {
        let e = FirmaHibridaPq;
        assert!(e.derivar(&[0u8; 32]).is_none(), "32 bytes no es la longitud (64)");
        assert!(e.derivar(&[0u8; 65]).is_none());
    }

    #[test]
    fn firma_valida_y_una_ajena_no() {
        let e = FirmaHibridaPq;
        let par = e.derivar(&[9u8; 64]).unwrap();
        let msg = b"reto del servidor";
        let firma = e.firmar(&par.privada, msg).unwrap();
        assert!(e.verificar(&par.publica, msg, &firma), "la firma honesta valida");
        // Otro mensaje no valida.
        assert!(!e.verificar(&par.publica, b"otro", &firma));
        // Otra clave pública no valida.
        let otra = e.derivar(&[10u8; 64]).unwrap();
        assert!(!e.verificar(&otra.publica, msg, &firma), "clave ajena no valida");
    }

    #[test]
    fn entradas_malformadas_fallan_cerrado() {
        let e = FirmaHibridaPq;
        assert!(e.firmar(b"privada corta", b"m").is_none());
        assert!(!e.verificar(b"publica corta", b"m", b"firma"));
        let par = e.derivar(&[1u8; 64]).unwrap();
        assert!(!e.verificar(&par.publica, b"m", b"firma corta"));
    }
}
