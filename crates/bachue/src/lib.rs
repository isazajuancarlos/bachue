// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **Bachué — la fachada de identidad.** El punto de entrada único de la librería.
//!
//! _Bachué es la deidad muisca del ORIGEN de la humanidad: la fuente de la identidad._
//!
//! # Qué junta, y qué NO copia
//!
//! Una librería de identidad necesita dos cosas: los PRIMITIVOS de autenticación
//! (hashear una contraseña, emitir una sesión, frenar la fuerza bruta, un segundo
//! factor, cifrar un secreto en reposo) y un MOTOR de autorización (quién puede qué).
//!
//! - **Los primitivos NO se reimplementan ni se copian** (directiva 1: un solo sitio
//!   donde vive la regla). Viven en [`guaca`], que ya nació justamente porque medico e
//!   informes los copiaban y las copias habían DIVERGIDO —una mejora de seguridad se
//!   quedó en un solo lado—. Aquí se **re-exportan** bajo la superficie de Bachué:
//!   siguen siendo un solo árbol, se auditan una vez y se arreglan una vez.
//! - **El MOTOR de autorización es de Bachué** ([`autz`], crate `bachue-autz`): es la
//!   pieza que NO existía extraída (medico e informes la reescribían a mano), y su
//!   diseño está calibrado contra los modos de fallo reales del corpus de objetivos
//!   (`conocimiento/objetivos/`): una sola puerta (Discourse), contra el dueño del
//!   recurso (Zitadel), fail-closed sin actor (Authentik/midPoint), acción+ámbito
//!   (Grafana).
//!
//! # Mapa de la superficie
//!
//! | Módulo | Origen | Qué da |
//! |---|---|---|
//! | [`autz`] | Bachué (`bachue-autz`) | el motor único de autorización |
//! | [`clave`] | Bachué (`bachue-clave`) | el FLUJO de autenticación (hash de descarte, política) |
//! | [`claves`] | guaca | hash/verificación de contraseña (Argon2), primitivo |
//! | [`sesion`] | Bachué (`bachue-sesion`) | TIPOS de token (sesión / pendiente-2FA / recuperación), sobre guaca::sesion |
//! | [`segundopaso`] | Bachué (`bachue-segundopaso`) | el FLUJO del segundo factor (TOTP + recuperación), veredicto unificado |
//! | [`passkey`] | Bachué (`bachue-passkey`) | login por passkey (WebAuthn assertion); la firma tras un trait (decisión de cripto aparte) |
//! | [`freno`] | guaca | freno al ensayo de contraseñas por (correo, origen) |
//! | [`dosfactores`] | guaca | segundo factor TOTP (con anti-replay), el PRIMITIVO |
//! | [`reposo`] | guaca | cifrado en reposo de secretos (el TOTP, p. ej.) |
//! | [`firma`] | guaca | firma post-cuántica no repudiable |
//! | [`auditoria`] | guaca | bitácora encadenada a prueba de manipulación |
//! | [`defensas`] | Bachué (`bachue-defensas`) | defensas de borde: IP de cliente confiable (para el freno), validación de redirects, saneo de entorno |
//! | [`opaque`] | Bachué (`bachue-opaque`) | credencial tipo OPAQUE: registro/login sobre VOPRF, el servidor nunca ve la contraseña; prueba de login PQ |
//! | [`password`] | Bachué (`bachue-password`) | cadena de esquemas de contraseña + upgrade oportunista (absorbe tumbaga); escritura Argon2id, legado bcrypt verify-only tras `legado` |
//!
//! Lo que Bachué añadirá encima (plan F1+): el **flujo orquestado** de login
//! —verificar credencial + freno en los dos pasos + hash de descarte anti-timing +
//! emitir sesión + segundo paso 2FA + renovar hash— que hoy medico e informes
//! reescriben cada uno, y el PAKE tipo OPAQUE sobre `quipu-voprf`.

#![forbid(unsafe_code)]

/// El motor único de autorización (ver la cabecera de [`bachue_autz`]).
pub use bachue_autz as autz;
/// El flujo de autenticación por contraseña (ver [`bachue_clave`]).
pub use bachue_clave as clave;
/// Sesiones y tipos de token, sobre `guaca::sesion` (ver [`bachue_sesion`]).
pub use bachue_sesion as sesion;
/// El segundo paso del login: TOTP + códigos de recuperación (ver [`bachue_segundopaso`]).
pub use bachue_segundopaso as segundopaso;
/// Login por passkey (WebAuthn assertion), la firma tras un trait (ver [`bachue_passkey`]).
pub use bachue_passkey as passkey;
/// Defensas transversales de borde: IP de cliente confiable, redirects, entorno (ver [`bachue_defensas`]).
pub use bachue_defensas as defensas;
/// Credencial tipo OPAQUE: login passwordless-blind sobre VOPRF, prueba PQ (ver [`bachue_opaque`]).
pub use bachue_opaque as opaque;
/// Cadena de esquemas de contraseña + upgrade oportunista (absorbe tumbaga): escritura
/// Argon2id, lectores de legado verify-only tras la feature `legado` (ver [`bachue_password`]).
pub use bachue_password as password;

// ── Primitivos de autenticación: RE-EXPORTADOS de guaca, no copiados. ──
pub use guaca::auditoria;
pub use guaca::claves;
pub use guaca::dosfactores;
pub use guaca::firma;
pub use guaca::freno;
pub use guaca::reposo;

#[cfg(test)]
mod pruebas {
    //! Prueba de INTEGRACIÓN de la fundación: que los primitivos de guaca y el motor
    //! de authz de Bachué se usan juntos por la fachada, con una identidad coherente.
    //! No re-mide guaca (tiene su propio banco); mide que la costura existe.
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Op {
        Leer,
    }

    /// Autenticar (guaca::claves) y AUTORIZAR (bachue-autz) por la misma fachada:
    /// se verifica la contraseña y, con el actor resultante, se decide el acceso a
    /// un recurso de su propio ámbito. El caso rojo —recurso de OTRO ámbito— sigue
    /// negado aunque la contraseña sea correcta: autenticar no es autorizar.
    #[test]
    fn autenticar_y_autorizar_por_la_misma_fachada() {
        // 1) Autenticación: el hash lo produce y verifica guaca::claves (Argon2).
        let hash = claves::hashear("secreta-de-prueba").expect("hashea");
        assert!(claves::verificar("secreta-de-prueba", &hash), "la buena entra");
        assert!(!claves::verificar("otra", &hash), "una mala no entra");

        // 2) Autorización: con el actor autenticado (ámbito 10), el motor de Bachué.
        let actor = autz::Actor::nuevo(
            1,
            vec![autz::Concesion { accion: Op::Leer, alcance: autz::Alcance::De(10i64) }],
        );
        // VERDE: recurso de su ámbito.
        assert!(autz::autorizar(&actor, &Op::Leer, &autz::Duenio::De(10i64)).permitido());
        // ROJO: recurso de otro ámbito — aunque la contraseña era correcta (Zitadel).
        assert!(!autz::autorizar(&actor, &Op::Leer, &autz::Duenio::De(20i64)).permitido());
    }

    /// **El flujo de login de DOS pasos, compuesto por la fachada.** Contraseña correcta
    /// (F1) → token PENDIENTE de segundo factor (F2, dominio propio) → segundo paso con
    /// TOTP (F3.a) → recién ahí una sesión PLENA. El caso rojo por el medio: el token
    /// pendiente NO abre nada como sesión plena (la firma está en otro dominio), así que
    /// tener la contraseña sin el segundo factor no basta.
    #[test]
    fn login_de_dos_pasos_por_la_fachada() {
        const HMAC: &[u8] = b"secreto-hmac-del-servicio-32-bytes-min!!";
        let usuario_id = 7;

        // Paso 1 — contraseña. Correcta ⇒ se emite un token PENDIENTE (no una sesión).
        let hash = claves::hashear("mi-contraseña-larga").expect("hashea");
        assert!(clave::autenticar(Some(&hash), "mi-contraseña-larga"));
        let pendiente = sesion::emitir(sesion::Tipo::PendienteSegundoFactor, HMAC, usuario_id, 0, 5);

        // El pendiente NO vale como sesión plena (dominio de firma distinto): con solo la
        // contraseña no se entra.
        assert!(sesion::verificar(sesion::Tipo::Sesion, HMAC, &pendiente).is_none());
        // Sí es un pendiente válido, y trae de quién.
        let p = sesion::verificar(sesion::Tipo::PendienteSegundoFactor, HMAC, &pendiente).expect("pendiente válido");
        assert_eq!(p.usuario_id, usuario_id);

        // Paso 2 — segundo factor. Se enrola un secreto y se busca el TOTP de la ventana.
        let secreto = dosfactores::generar_secreto();
        let ahora = 1_770_000_120;
        let codigo = (0..1_000_000u32)
            .map(|n| format!("{n:06}"))
            .find(|c| matches!(
                dosfactores::verificar(&secreto, c, ahora, None),
                dosfactores::Veredicto::Correcto { .. }
            ))
            .expect("alguno casa");

        let enrol = segundopaso::Enrolamiento {
            secreto_totp_b32: &secreto,
            ultimo_contador: None,
            hashes_recuperacion: &[],
        };
        let r = segundopaso::segundo_paso(&enrol, &codigo, ahora);
        assert!(r.abre(), "el TOTP correcto supera el segundo paso: {r:?}");

        // Recién ahora, con los DOS pasos superados, se emite la sesión PLENA.
        let plena = sesion::emitir(sesion::Tipo::Sesion, HMAC, p.usuario_id, 0, 60);
        let s = sesion::verificar(sesion::Tipo::Sesion, HMAC, &plena).expect("sesión plena");
        assert_eq!(s.usuario_id, usuario_id);
    }

    /// El login por passkey es alcanzable POR LA FACHADA (`bachue::passkey`): se arma un
    /// verificador de firma cualquiera, se genera un reto, y una assertion coherente con
    /// él se acepta. No re-mide `bachue-passkey` (tiene su banco); prueba que la costura de
    /// la fachada existe y que el tipo del trait se puede satisfacer desde fuera.
    #[test]
    fn el_login_por_passkey_es_alcanzable_por_la_fachada() {
        use sha2::{Digest, Sha256};

        // Un verificador de firma de juguete (la impl real es la decisión de cripto): acepta
        // si la firma es SHA-256(clave ‖ mensaje). Demuestra que el trait se implementa desde
        // un consumidor de la fachada.
        struct V;
        impl passkey::VerificadorDeFirma for V {
            fn verificar(&self, _a: passkey::Algoritmo, k: &passkey::ClavePublicaCose, m: &[u8], f: &[u8]) -> bool {
                let mut h = Sha256::new();
                h.update(&k.0);
                h.update(m);
                f == h.finalize().as_slice()
            }
        }

        let rp_id = "cuenta.xiliux.com";
        let origen = "https://cuenta.xiliux.com";
        let cred = passkey::Credencial {
            id: b"c".to_vec(),
            clave: passkey::ClavePublicaCose(b"k".to_vec()),
            alg: passkey::Algoritmo::Es256,
            contador: 0,
        };
        let desafio = passkey::Desafio::nuevo();

        // authenticatorData de 37 bytes: rpIdHash ‖ flags(UP|UV) ‖ contador=1.
        let mut ad = Sha256::digest(rp_id.as_bytes()).to_vec();
        ad.push(0b0000_0101);
        ad.extend_from_slice(&1u32.to_be_bytes());
        let cd = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{origen}\"}}",
            desafio.como_b64url()
        )
        .into_bytes();
        // La firma que V aceptará: SHA-256(clave ‖ authData ‖ SHA-256(clientData)).
        let mut mensaje = ad.clone();
        mensaje.extend_from_slice(Sha256::digest(&cd).as_slice());
        let mut h = Sha256::new();
        h.update(&cred.clave.0);
        h.update(&mensaje);
        let firma = h.finalize().to_vec();

        let r = passkey::verificar_assertion(
            &cred, &desafio, origen, rp_id, &cd, &ad, &firma, &passkey::Politica::default(), &V,
        );
        assert_eq!(r, passkey::Assertion::Aceptada { contador_nuevo: 1 });
    }

    /// **Las defensas de borde, por la fachada, en su costura con el resto (F5).** La IP
    /// del cliente que sale de `defensas::red` es lo que alimenta el `origen` con el que
    /// el `freno` (guaca) frena la fuerza bruta; y el destino post-login se valida antes
    /// de reenviar. El caso rojo del medio: un `X-Forwarded-For` falseado por el atacante
    /// NO cambia el origen —así no se estrena un cubo de freno en cada intento— y un
    /// `//evil.com` como "a dónde ir tras entrar" se rechaza.
    #[test]
    fn defensas_de_borde_por_la_fachada() {
        use defensas::red::{ip_de_reenvio, Confianza, IpCliente};
        use defensas::redireccion::{ruta_relativa_segura, Destino};

        // Un proxy de confianza. El atacante prefija una IP falsa; el origen del freno
        // es la IP REAL (la que añadió el proxy), no la falsa: dos intentos suyos caen
        // en el MISMO cubo y suman hacia el umbral, en vez de evadirlo.
        let real = ip_de_reenvio(Some("9.9.9.9, 203.0.113.7"), Confianza::con_saltos(1));
        assert_eq!(real, IpCliente::Conocida("203.0.113.7".parse().unwrap()));
        let origen_freno = real.como_origen();
        assert_eq!(origen_freno, "203.0.113.7", "el freno frena por la IP real, no la falseada");

        // Tras autenticar, el reenvío: una ruta relativa de nuestro sitio pasa; un salto
        // a otro host disfrazado de ruta, no.
        assert!(matches!(ruta_relativa_segura("/inicio"), Destino::Relativo(_)));
        assert_eq!(ruta_relativa_segura("//evil.com").seguro(), None);
    }

    /// **La credencial tipo OPAQUE, por la fachada (`bachue::opaque`), de punta a punta.**
    /// Registro y login completos: el servidor nunca recibe la contraseña (viaja cegada),
    /// y la prueba de login es una firma híbrida PQ. El caso rojo del medio: la contraseña
    /// incorrecta no abre el sobre y ni siquiera firma.
    #[test]
    fn credencial_opaque_por_la_fachada() {
        use opaque::cliente::{self, ErrorLogin};
        use opaque::firma::FirmaHibridaPq;
        use opaque::servidor::Servidor;
        use opaque::KdfParams;

        let params = KdfParams { mem_kib: 32, iterations: 1, parallelism: 1 }; // barato: es una prueba
        let srv = Servidor::nuevo([5u8; 32], b"cuenta.xiliux.com".to_vec(), params);
        let esquema = FirmaHibridaPq;

        // Registro.
        let (est_r, ini_r) = cliente::iniciar_registro("juan", "contraseña-de-la-fachada").unwrap();
        assert_ne!(&ini_r.elemento_ciego[..], "contraseña-de-la-fachada".as_bytes(), "no viaja en claro");
        let resp_r = srv.responder_registro(&ini_r).unwrap();
        let sal_r = cliente::terminar_registro(&est_r, &resp_r, srv.identidad(), &esquema, srv.params()).unwrap();
        let registro = srv.guardar_registro(sal_r.mensaje, &esquema).unwrap();

        // Login VERDE.
        let (est_l, ini_l) = cliente::iniciar_login("juan", "contraseña-de-la-fachada").unwrap();
        let (resp_l, est_s) = srv.responder_login(&ini_l, Some(&registro)).unwrap();
        let sal_l = cliente::terminar_login(&est_l, &resp_l, &esquema, srv.params()).unwrap();
        assert!(srv.verificar_login(&est_s, &sal_l.mensaje, &esquema).autenticado());

        // Login ROJO: contraseña incorrecta.
        let (est_m, ini_m) = cliente::iniciar_login("juan", "contraseña-MALA").unwrap();
        let (resp_m, _s) = srv.responder_login(&ini_m, Some(&registro)).unwrap();
        assert_eq!(
            cliente::terminar_login(&est_m, &resp_m, &esquema, srv.params()).err(),
            Some(ErrorLogin::ContrasenaIncorrecta)
        );
    }
}
