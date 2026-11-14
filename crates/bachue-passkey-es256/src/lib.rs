// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **Bachué F3.b — el verificador de firma de passkeys ES256 (ECDSA sobre P-256).**
//!
//! La `impl` concreta de [`bachue_passkey::VerificadorDeFirma`] que faltaba: la que sabe
//! comprobar la firma de la mayoría de las passkeys (COSE alg −7). Es la pieza de cripto
//! que quipu no tiene —quipu firma híbrido Ed25519+ML-DSA-87—, y por decisión de Juan
//! (2026-08-30) se apoya en `p256` de RustCrypto (auditada) antes que reimplementar P-256.
//!
//! Va en un crate APARTE del andamiaje ([`bachue_passkey`]) para que la dependencia `p256`
//! solo la pague quien use passkeys ES256: el andamiaje sigue sin cripto de curva.
//!
//! # El formato de la clave y de la firma
//!
//! - **La clave** ([`bachue_passkey::ClavePublicaCose`]) se interpreta aquí como un punto
//!   **SEC1** —sin comprimir (`0x04 ‖ x ‖ y`, 65 bytes) como lo produce el registro;
//!   `p256` acepta además la forma comprimida (`0x02/0x03 ‖ x`), que decodifica a la MISMA
//!   clave, así que es inocuo—. El autenticador la entrega en el registro como un COSE_Key
//!   (mapa CBOR); convertir COSE_Key→SEC1 es trabajo del REGISTRO (F3.b.2), que ocurre una
//!   vez, no en cada login. Aquí, en el camino caliente de la assertion, se recibe ya el
//!   punto y se verifica —sin un parser CBOR en la ruta de cada inicio de sesión—.
//! - **La firma** llega en **DER** (ASN.1 `SEQUENCE { r INTEGER, s INTEGER }`), que es como
//!   WebAuthn transporta las firmas ES256. `p256` la parsea.
//!
//! # Qué comprueba, y qué NO
//!
//! ECDSA-P256 con SHA-256 sobre el `mensaje` que arma el andamiaje
//! (`authenticatorData ‖ SHA-256(clientDataJSON)`); `p256` le aplica el SHA-256 interno que
//! pide alg −7. Devuelve `false` —nunca entra en pánico ni acepta— ante un algoritmo que no
//! sea ES256, una clave SEC1 ilegible, una firma DER malformada, o una firma que no casa.
//! Es fail-closed, que es lo que el andamiaje espera del trait.
//!
//! **Lo que NO hace, y por qué es inocuo aquí**: no normaliza la maleabilidad de ECDSA —una
//! firma y su gemela `(r, n−s)` verifican las dos—. No abre nada: la unicidad de la firma
//! NO es lo que impide un replay en Bachué; lo impiden el reto de un solo uso (que el
//! servicio borra tras usarlo) y el contador anti-clonación. Si algún día la firma se usara
//! como identificador único o clave de idempotencia, ESE día habría que exigir `s` baja.

#![forbid(unsafe_code)]

use bachue_passkey::{Algoritmo, ClavePublicaCose, VerificadorDeFirma};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};

/// El verificador de firmas ES256. Sin estado: una unidad que se pasa a
/// [`bachue_passkey::verificar_assertion`].
pub struct VerificadorEs256;

impl VerificadorDeFirma for VerificadorEs256 {
    fn verificar(&self, alg: Algoritmo, clave: &ClavePublicaCose, mensaje: &[u8], firma: &[u8]) -> bool {
        // Este verificador es SOLO ES256. Otro algoritmo no es "inválido": es "no es mío",
        // y devolver false es correcto (fail-closed) — quien mezcle EdDSA usará otro
        // verificador. No se afirma nada sobre una firma que este código no comprueba.
        if alg != Algoritmo::Es256 {
            return false;
        }
        // La clave, como punto SEC1 sin comprimir. Una clave ilegible ⇒ no verifica.
        let Ok(vk) = VerifyingKey::from_sec1_bytes(&clave.0) else {
            return false;
        };
        // La firma, en DER. Malformada ⇒ no verifica.
        let Ok(sig) = Signature::from_der(firma) else {
            return false;
        };
        // ECDSA-P256/SHA-256 sobre el mensaje entero (p256 aplica el SHA-256 de alg −7).
        vk.verify(mensaje, &sig).is_ok()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::sec1::ToSec1Point; // p256 0.14: to_encoded_point sobre AffinePoint
    use p256::elliptic_curve::Generate; // p256 0.14: key-gen vía el trait Generate

    /// RNG del sistema para la prueba: reenvía a `getrandom` (el ecosistema `rand` aún no
    /// expone OsRng para rand_core 0.10). Solo bytes del SO, cero lógica cripto propia.
    struct RngDelSo;
    impl p256::elliptic_curve::rand_core::TryRng for RngDelSo {
        type Error = getrandom::Error;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut b = [0u8; 4];
            getrandom::fill(&mut b)?;
            Ok(u32::from_le_bytes(b))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut b = [0u8; 8];
            getrandom::fill(&mut b)?;
            Ok(u64::from_le_bytes(b))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            getrandom::fill(dst)
        }
    }
    impl p256::elliptic_curve::rand_core::TryCryptoRng for RngDelSo {}

    /// Un "autenticador" de prueba: un par P-256 real. Devuelve la clave pública en SEC1
    /// (como la guardaría el registro) y firma en DER (como la entrega WebAuthn).
    struct Autenticador {
        sk: SigningKey,
    }
    impl Autenticador {
        fn nuevo() -> Self {
            Self { sk: SigningKey::try_generate_from_rng(&mut RngDelSo).expect("RNG del sistema") }
        }
        fn clave_sec1(&self) -> ClavePublicaCose {
            let vk = VerifyingKey::from(&self.sk);
            ClavePublicaCose(vk.as_affine().to_sec1_point(false).as_bytes().to_vec())
        }
        fn firmar_der(&self, mensaje: &[u8]) -> Vec<u8> {
            let sig: Signature = self.sk.sign(mensaje);
            sig.to_der().as_bytes().to_vec()
        }
    }

    /// **Una firma ES256 REAL verifica, y una de otro mensaje no** (directiva 33: la
    /// pareja). Sin el verde, un verificador que dijera `false` a todo pasaría el rojo;
    /// sin el rojo, uno que dijera `true` a todo pasaría el verde.
    #[test]
    fn una_firma_es256_real_verifica_y_una_ajena_no() {
        let a = Autenticador::nuevo();
        let clave = a.clave_sec1();
        let mensaje = b"authData||sha256(clientData) de prueba";
        let firma = a.firmar_der(mensaje);

        assert!(VerificadorEs256.verificar(Algoritmo::Es256, &clave, mensaje, &firma), "la firma buena verifica");
        // Firma de OTRO mensaje: no vale para éste.
        let firma_otro = a.firmar_der(b"otro mensaje distinto");
        assert!(!VerificadorEs256.verificar(Algoritmo::Es256, &clave, mensaje, &firma_otro), "una firma de otro mensaje no");
    }

    /// La firma de OTRA clave no verifica (control de la clave, no solo del mensaje).
    #[test]
    fn la_firma_de_otra_clave_no_verifica() {
        let a = Autenticador::nuevo();
        let b = Autenticador::nuevo();
        let mensaje = b"mensaje";
        let firma_de_b = b.firmar_der(mensaje);
        // Se presenta la firma de B contra la clave de A.
        assert!(!VerificadorEs256.verificar(Algoritmo::Es256, &a.clave_sec1(), mensaje, &firma_de_b));
    }

    /// Entradas malformadas ⇒ `false`, nunca pánico: algoritmo ajeno, clave basura, firma
    /// basura. Cada una por su vía.
    #[test]
    fn lo_malformado_falla_cerrado_sin_panico() {
        let a = Autenticador::nuevo();
        let clave = a.clave_sec1();
        let mensaje = b"m";
        let firma = a.firmar_der(mensaje);

        // Algoritmo que no es el de este verificador.
        assert!(!VerificadorEs256.verificar(Algoritmo::EdDSA, &clave, mensaje, &firma));
        assert!(!VerificadorEs256.verificar(Algoritmo::Rs256, &clave, mensaje, &firma));
        // Clave SEC1 ilegible.
        assert!(!VerificadorEs256.verificar(Algoritmo::Es256, &ClavePublicaCose(vec![0x04, 1, 2, 3]), mensaje, &firma));
        assert!(!VerificadorEs256.verificar(Algoritmo::Es256, &ClavePublicaCose(vec![]), mensaje, &firma));
        // Firma DER malformada.
        assert!(!VerificadorEs256.verificar(Algoritmo::Es256, &clave, mensaje, b"no-es-der"));
        assert!(!VerificadorEs256.verificar(Algoritmo::Es256, &clave, mensaje, &[]));
    }

    /// **Cruce de la frontera (directiva 28): una passkey ES256 REAL verificada de punta a
    /// punta por el andamiaje de `bachue_passkey`.** Se arma un `authenticatorData` y un
    /// `clientDataJSON` reales, se firma `authData ‖ SHA-256(clientData)` con P-256 en DER,
    /// y `verificar_assertion` —con ESTE verificador— acepta. Es la prueba de que el
    /// mensaje que arma el andamiaje y el que este verificador comprueba son el mismo.
    #[test]
    fn una_passkey_es256_real_pasa_el_andamiaje_entero() {
        use sha2::{Digest, Sha256};

        let a = Autenticador::nuevo();
        let rp_id = "cuenta.xiliux.com";
        let origen = "https://cuenta.xiliux.com";
        let cred = bachue_passkey::Credencial {
            id: b"c1".to_vec(),
            clave: a.clave_sec1(),
            alg: Algoritmo::Es256,
            contador: 10,
        };
        let desafio = bachue_passkey::Desafio::nuevo();

        // authenticatorData: rpIdHash ‖ flags(UP|UV) ‖ contador=11.
        let mut ad = Sha256::digest(rp_id.as_bytes()).to_vec();
        ad.push(0b0000_0101);
        ad.extend_from_slice(&11u32.to_be_bytes());
        let cd = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{origen}\"}}",
            desafio.como_b64url()
        )
        .into_bytes();

        // El autenticador firma authData ‖ SHA-256(clientData), en DER.
        let mut mensaje = ad.clone();
        mensaje.extend_from_slice(Sha256::digest(&cd).as_slice());
        let firma = a.firmar_der(&mensaje);

        let r = bachue_passkey::verificar_assertion(
            &cred, &desafio, origen, rp_id, &cd, &ad, &firma,
            &bachue_passkey::Politica::default(), &VerificadorEs256,
        );
        assert_eq!(r, bachue_passkey::Assertion::Aceptada { contador_nuevo: 11 });

        // Y la pareja: si el autenticador firmara con otra clave, el andamiaje lo rechaza
        // por FirmaInvalida (no por otra cosa: todo lo demás está bien).
        let impostor = Autenticador::nuevo();
        let firma_falsa = impostor.firmar_der(&mensaje);
        let r2 = bachue_passkey::verificar_assertion(
            &cred, &desafio, origen, rp_id, &cd, &ad, &firma_falsa,
            &bachue_passkey::Politica::default(), &VerificadorEs256,
        );
        assert_eq!(r2, bachue_passkey::Assertion::Rechazada(bachue_passkey::Motivo::FirmaInvalida));
    }

    /// **EL CICLO COMPLETO (D28): REGISTRO → LOGIN con una clave ES256 real.** El
    /// autenticador registra su clave pública (COSE_Key en el attestationObject); el
    /// registro la extrae a SEC1; y una assertion firmada por la MISMA clave privada, con la
    /// credencial que salió del registro, verifica. Es la prueba de que la conversión
    /// COSE→SEC1 del registro y el `from_sec1_bytes` del verificador hablan de la misma
    /// clave — la frontera que el andamiaje y la firma comparten.
    #[test]
    fn registro_y_login_con_firma_es256_real() {
        use bachue_passkey::registro::{verificar_registro, Registro};
        use bachue_passkey::{Assertion, Desafio, Politica};
        use sha2::{Digest, Sha256};

        let rp_id = "cuenta.xiliux.com";
        let origen = "https://cuenta.xiliux.com";
        let a = Autenticador::nuevo();
        // El COSE_Key EC2/P-256/ES256 de este autenticador (x,y del punto público).
        let punto = VerifyingKey::from(&a.sk).as_affine().to_sec1_point(false);
        let x: [u8; 32] = punto.x().unwrap().as_slice().try_into().unwrap();
        let y: [u8; 32] = punto.y().unwrap().as_slice().try_into().unwrap();
        let mut cose = vec![0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01];
        cose.extend_from_slice(&[0x21, 0x58, 0x20]);
        cose.extend_from_slice(&x);
        cose.extend_from_slice(&[0x22, 0x58, 0x20]);
        cose.extend_from_slice(&y);

        // authData de registro: rpIdHash ‖ flags(UP|UV|AT) ‖ signCount=0 ‖ aaguid ‖ credIdLen ‖ credId ‖ COSE.
        let mut ad_reg = Sha256::digest(rp_id.as_bytes()).to_vec();
        ad_reg.push(0b0100_0101); // UP|UV|AT
        ad_reg.extend_from_slice(&0u32.to_be_bytes());
        ad_reg.extend_from_slice(&[0u8; 16]);
        ad_reg.extend_from_slice(&(4u16).to_be_bytes());
        ad_reg.extend_from_slice(b"cred");
        ad_reg.extend_from_slice(&cose);
        // attestationObject {fmt:"none", attStmt:{}, authData:<ad_reg>}.
        let mut ao = vec![0xA3];
        ao.extend_from_slice(&[0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e']);
        ao.extend_from_slice(&[0x67, b'a', b't', b't', b'S', b't', b'm', b't', 0xA0]);
        ao.extend_from_slice(&[0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a']);
        // authData suele pasar de 255 bytes (COSE ~77 + 55 ≈ 132 < 256 aquí, cabe en un byte).
        ao.push(0x58);
        ao.push(u8::try_from(ad_reg.len()).unwrap());
        ao.extend_from_slice(&ad_reg);

        let desafio_reg = Desafio::nuevo();
        let cd_reg = format!(
            "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"{origen}\"}}",
            desafio_reg.como_b64url()
        )
        .into_bytes();
        let Registro::Aceptado(cred) =
            verificar_registro(&desafio_reg, origen, rp_id, &cd_reg, &ao, &Politica::default())
        else {
            panic!("el registro debe aceptar la passkey");
        };
        assert_eq!(cred.id, b"cred");

        // LOGIN con la credencial recién registrada: assertion firmada por el mismo par.
        let desafio_login = Desafio::nuevo();
        let mut ad_login = Sha256::digest(rp_id.as_bytes()).to_vec();
        ad_login.push(0b0000_0101); // UP|UV
        ad_login.extend_from_slice(&1u32.to_be_bytes()); // contador 1 > 0 del registro
        let cd_login = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{origen}\"}}",
            desafio_login.como_b64url()
        )
        .into_bytes();
        let mut mensaje = ad_login.clone();
        mensaje.extend_from_slice(Sha256::digest(&cd_login).as_slice());
        let firma = a.firmar_der(&mensaje);

        let r = bachue_passkey::verificar_assertion(
            &cred, &desafio_login, origen, rp_id, &cd_login, &ad_login, &firma, &Politica::default(), &VerificadorEs256,
        );
        assert_eq!(r, Assertion::Aceptada { contador_nuevo: 1 }, "la passkey registrada inicia sesión");
    }
}
