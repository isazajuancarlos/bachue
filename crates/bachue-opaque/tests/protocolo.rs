// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! Banco de extremo a extremo del protocolo: registro + login completos, por la API
//! pública, con los casos rojo que discriminan (directiva 33) y una simulación
//! (directiva 8). Cruza la frontera cliente↔servidor con mensajes reales (directiva 28).

use bachue_opaque::cliente::{self, ErrorLogin};
use bachue_opaque::firma::FirmaHibridaPq;
use bachue_opaque::mensajes::{RegistroGuardado, Veredicto};
use bachue_opaque::servidor::Servidor;
use quipu::kdf::KdfParams;

/// Argon2id BARATO, solo para pruebas: el protocolo lo llama dos veces por login y no se
/// mide su coste aquí (eso es de quipu). Producción usa `KdfParams::FUERTE`/`EQUILIBRADO`.
fn params_baratos() -> KdfParams {
    KdfParams { mem_kib: 32, iterations: 1, parallelism: 1 }
}

fn servidor() -> Servidor {
    Servidor::nuevo([9u8; 32], b"cuenta.xiliux.com".to_vec(), params_baratos())
}

/// Registra a `usuario`/`contrasena` contra `srv` y devuelve el registro persistido.
fn registrar(srv: &Servidor, usuario: &str, contrasena: &str) -> RegistroGuardado {
    let esquema = FirmaHibridaPq;
    let (estado, ini) = cliente::iniciar_registro(usuario, contrasena).expect("cegar");
    let resp = srv.responder_registro(&ini).expect("evaluar OPRF");
    let salida = cliente::terminar_registro(&estado, &resp, srv.identidad(), &esquema, srv.params())
        .expect("terminar registro");
    srv.guardar_registro(salida.mensaje, &esquema).expect("guardar")
}

/// Concilio (Haiku/Fable): una clave pública malformada se RECHAZA en el registro
/// (fallo ruidoso, D20), en vez de guardarse y diferir el fallo a un login mudo.
#[test]
fn clave_publica_malformada_se_rechaza_en_el_registro() {
    let srv = servidor();
    let esquema = FirmaHibridaPq;
    for basura in [vec![0x01u8], vec![], vec![0u8; 100]] {
        let (estado, ini) = cliente::iniciar_registro("u", "contraseña-larga-buena").unwrap();
        let resp = srv.responder_registro(&ini).unwrap();
        let mut salida =
            cliente::terminar_registro(&estado, &resp, srv.identidad(), &esquema, srv.params()).unwrap();
        salida.mensaje.clave_publica_cliente = basura;
        assert!(srv.guardar_registro(salida.mensaje, &esquema).is_none(), "clave malformada rechazada");
    }
    // Control: la clave BIEN formada del flujo normal sí se guarda.
    let reg = registrar(&srv, "u", "contraseña-larga-buena");
    assert!(!reg.clave_publica_cliente.is_empty());
}

/// Corre un login completo y devuelve el veredicto del servidor + la export_key del
/// cliente (o el error del cliente).
fn login(
    srv: &Servidor,
    registro: Option<&RegistroGuardado>,
    usuario: &str,
    contrasena: &str,
) -> Result<(Veredicto, [u8; 32]), ErrorLogin> {
    let esquema = FirmaHibridaPq;
    let (estado_c, ini) = cliente::iniciar_login(usuario, contrasena).expect("cegar");
    let (resp, estado_s) = srv.responder_login(&ini, registro).expect("responder login");
    let salida = cliente::terminar_login(&estado_c, &resp, &esquema, srv.params())?;
    let veredicto = srv.verificar_login(&estado_s, &salida.mensaje, &esquema);
    Ok((veredicto, salida.export_key))
}

#[test]
fn registro_y_login_honesto_autentica() {
    let srv = servidor();
    let reg = registrar(&srv, "juan", "una-contraseña-larga-y-buena");
    let (ver, export) = login(&srv, Some(&reg), "juan", "una-contraseña-larga-y-buena").expect("login ok");
    assert!(ver.autenticado(), "la contraseña correcta autentica");
    assert_ne!(export, [0u8; 32], "hay export_key");
}

/// La export_key es ESTABLE entre logins (misma contraseña ⇒ misma clave para cifrar
/// datos del usuario en el cliente).
#[test]
fn export_key_estable_entre_logins() {
    let srv = servidor();
    let reg = registrar(&srv, "ana", "clave-de-ana-123456");
    let (_, e1) = login(&srv, Some(&reg), "ana", "clave-de-ana-123456").unwrap();
    let (_, e2) = login(&srv, Some(&reg), "ana", "clave-de-ana-123456").unwrap();
    assert_eq!(e1, e2, "misma contraseña ⇒ misma export_key");
}

/// ROJO: contraseña incorrecta. El cliente lo detecta al abrir el sobre y ni siquiera
/// firma (no da un login forjable al servidor).
#[test]
fn contrasena_incorrecta_no_autentica() {
    let srv = servidor();
    let reg = registrar(&srv, "juan", "la-buena-contraseña");
    let r = login(&srv, Some(&reg), "juan", "la-MALA-contraseña");
    assert_eq!(r.err(), Some(ErrorLogin::ContrasenaIncorrecta));
}

/// ROJO: la prueba DLEQ del OPRF manipulada ⇒ finalize no valida.
#[test]
fn prueba_oprf_manipulada_falla() {
    let srv = servidor();
    let reg = registrar(&srv, "juan", "contraseña-para-oprf");
    let esquema = FirmaHibridaPq;
    let (estado_c, ini) = cliente::iniciar_login("juan", "contraseña-para-oprf").unwrap();
    let (mut resp, _estado_s) = srv.responder_login(&ini, Some(&reg)).unwrap();
    resp.prueba[0] ^= 0xFF; // manipular la prueba
    let r = cliente::terminar_login(&estado_c, &resp, &esquema, srv.params());
    assert_eq!(r.err(), Some(ErrorLogin::PruebaOprfInvalida));
}

/// ROJO: sobre manipulado (etiqueta) ⇒ el cliente no lo abre. Indistinguible de
/// contraseña incorrecta a propósito.
#[test]
fn sobre_manipulado_falla() {
    let srv = servidor();
    let reg = registrar(&srv, "juan", "contraseña-del-sobre");
    let esquema = FirmaHibridaPq;
    let (estado_c, ini) = cliente::iniciar_login("juan", "contraseña-del-sobre").unwrap();
    let (mut resp, _s) = srv.responder_login(&ini, Some(&reg)).unwrap();
    resp.sobre.etiqueta_auth[0] ^= 0x01;
    let r = cliente::terminar_login(&estado_c, &resp, &esquema, srv.params());
    assert_eq!(r.err(), Some(ErrorLogin::ContrasenaIncorrecta));
}

/// ROJO: repetición. Una prueba firmada para el reto A no vale contra un estado de
/// servidor con el reto B (el transcript liga el reto fresco).
#[test]
fn una_prueba_no_se_reusa_con_otro_reto() {
    let srv = servidor();
    let reg = registrar(&srv, "juan", "contraseña-anti-replay");
    let esquema = FirmaHibridaPq;

    // Login legítimo: capturamos la prueba del cliente (para el reto de ESTA respuesta).
    let (estado_c, ini) = cliente::iniciar_login("juan", "contraseña-anti-replay").unwrap();
    let (resp_a, _estado_a) = srv.responder_login(&ini, Some(&reg)).unwrap();
    let salida = cliente::terminar_login(&estado_c, &resp_a, &esquema, srv.params()).unwrap();

    // El servidor abre OTRA sesión de login (reto nuevo) y le presentamos la prueba vieja.
    let (_estado_c2, ini2) = cliente::iniciar_login("juan", "contraseña-anti-replay").unwrap();
    let (_resp_b, estado_b) = srv.responder_login(&ini2, Some(&reg)).unwrap();
    let ver = srv.verificar_login(&estado_b, &salida.mensaje, &esquema);
    assert!(!ver.autenticado(), "la prueba del reto A no vale para el reto B");
}

/// ROJO: usuario inexistente. La respuesta tiene la MISMA forma (sobre-señuelo
/// determinista) y el login se rechaza.
#[test]
fn usuario_inexistente_responde_uniforme_y_rechaza() {
    let srv = servidor();
    let esquema = FirmaHibridaPq;

    let (estado_c, ini) = cliente::iniciar_login("fantasma", "lo-que-sea-larga").unwrap();
    let (resp1, estado_s) = srv.responder_login(&ini, None).unwrap();
    // El sobre-señuelo es determinista: otra consulta del mismo usuario da el mismo sobre.
    let (_e2, ini2) = cliente::iniciar_login("fantasma", "lo-que-sea-larga").unwrap();
    let (resp2, _s2) = srv.responder_login(&ini2, None).unwrap();
    assert_eq!(resp1.sobre, resp2.sobre, "el señuelo no cambia entre intentos");

    // El cliente incluso 'abre' su propio sobre-señuelo con su contraseña (no puede
    // distinguirlo sin la clave del servidor), firma, y el servidor RECHAZA (sin clave
    // guardada no hay contra qué verificar).
    let salida = cliente::terminar_login(&estado_c, &resp1, &esquema, srv.params());
    if let Ok(s) = salida {
        let ver = srv.verificar_login(&estado_s, &s.mensaje, &esquema);
        assert!(!ver.autenticado(), "usuario inexistente nunca autentica");
    }
}

/// ROJO: una prueba honesta de un usuario NO vale para otro (el transcript liga usuario,
/// identidad y clave; y además cada usuario tiene su clave OPRF).
#[test]
fn la_prueba_de_un_usuario_no_pasa_por_otro() {
    let srv = servidor();
    let reg_a = registrar(&srv, "ana", "clave-de-ana-larga");
    let reg_b = registrar(&srv, "beto", "clave-de-beto-larga");
    let esquema = FirmaHibridaPq;

    // Ana hace un login honesto.
    let (estado_c, ini) = cliente::iniciar_login("ana", "clave-de-ana-larga").unwrap();
    let (resp, _estado_ana) = srv.responder_login(&ini, Some(&reg_a)).unwrap();
    let salida = cliente::terminar_login(&estado_c, &resp, &esquema, srv.params()).unwrap();

    // Se intenta colar la prueba de Ana en una sesión de login de Beto.
    let (_e, ini_b) = cliente::iniciar_login("beto", "clave-de-beto-larga").unwrap();
    let (_r, estado_beto) = srv.responder_login(&ini_b, Some(&reg_b)).unwrap();
    let ver = srv.verificar_login(&estado_beto, &salida.mensaje, &esquema);
    assert!(!ver.autenticado(), "la prueba de Ana no autentica a Beto");
}

/// ROJO: si el cliente usa un coste Argon2id DISTINTO al del registro, `rwd` difiere y el
/// sobre no abre. (Muestra que el coste debe acordarse; el servidor lo comunica.)
#[test]
fn params_distintos_no_abren_el_sobre() {
    let srv = servidor();
    let reg = registrar(&srv, "juan", "contraseña-con-coste");
    let esquema = FirmaHibridaPq;
    let (estado_c, ini) = cliente::iniciar_login("juan", "contraseña-con-coste").unwrap();
    let (resp, _s) = srv.responder_login(&ini, Some(&reg)).unwrap();
    let otros = KdfParams { mem_kib: 64, iterations: 2, parallelism: 1 };
    let r = cliente::terminar_login(&estado_c, &resp, &esquema, &otros);
    assert_eq!(r.err(), Some(ErrorLogin::ContrasenaIncorrecta));
}

/// ROJO: un servidor que presenta OTRA identidad en el login que la del registro no abre
/// el sobre (la identidad va ligada en la etiqueta). Frena la sustitución de servidor.
#[test]
fn identidad_de_servidor_distinta_no_abre() {
    let srv = servidor();
    let reg = registrar(&srv, "juan", "contraseña-con-identidad");
    let esquema = FirmaHibridaPq;

    // Un servidor 'gemelo' con la MISMA semilla OPRF (para que el OPRF valide) pero OTRA
    // identidad — el ataque de sustitución.
    let gemelo = Servidor::nuevo([9u8; 32], b"malo.example".to_vec(), params_baratos());
    let (estado_c, ini) = cliente::iniciar_login("juan", "contraseña-con-identidad").unwrap();
    let (resp, _s) = gemelo.responder_login(&ini, Some(&reg)).unwrap();
    let r = cliente::terminar_login(&estado_c, &resp, &esquema, srv.params());
    assert_eq!(r.err(), Some(ErrorLogin::ContrasenaIncorrecta), "identidad distinta ⇒ sobre no abre");
}

/// El servidor nunca recibe la contraseña: el elemento que viaja está CEGADO, distinto de
/// la contraseña. (Comprobación estructural del invariante central.)
#[test]
fn lo_que_viaja_esta_cegado() {
    let (_estado, ini) = cliente::iniciar_login("juan", "secreto-en-claro").unwrap();
    assert_ne!(&ini.elemento_ciego[..], b"secreto-en-claro", "no viaja la contraseña");
    // Cegar dos veces la misma contraseña da elementos distintos (blind aleatorio).
    let (_e2, ini2) = cliente::iniciar_login("juan", "secreto-en-claro").unwrap();
    assert_ne!(ini.elemento_ciego, ini2.elemento_ciego, "el cegado usa aleatoriedad fresca");
}

/// Rev. D25: dos codificaciones Unicode EQUIVALENTES de la misma contraseña son la MISMA
/// credencial (registro con una forma, login con la otra ⇒ autentica). "é" como un solo
/// codepoint (U+00E9, NFC) vs "e" + tilde combinante (U+0065 U+0301, NFD): NFKC las une.
#[test]
fn codificaciones_unicode_equivalentes_son_la_misma_credencial() {
    let srv = servidor();
    let nfc = "cafe\u{00e9}-clave-larga"; // ...é precompuesta
    let nfd = "cafee\u{0301}-clave-larga"; // ...e + ´ combinante
    assert_ne!(nfc, nfd, "son cadenas distintas byte a byte");
    let reg = registrar(&srv, "u", nfc);
    let (ver, _e) = login(&srv, Some(&reg), "u", nfd).expect("login con la otra forma");
    assert!(ver.autenticado(), "NFKC hace equivalentes las dos codificaciones");
}

/// Simulación (directiva 8): 40 usuarios distintos, cada uno registro + login honesto
/// (verde) y un login con contraseña mala (rojo). Todos deben autenticar en el verde y
/// ser rechazados en el rojo, sin cruces.
#[test]
fn simulacion_40_usuarios_verde_y_rojo() {
    let srv = servidor();
    for n in 0..40u32 {
        let usuario = format!("usuario_{n}");
        let buena = format!("contraseña-buena-de-{n}-larga");
        let reg = registrar(&srv, &usuario, &buena);

        let (ver, _e) = login(&srv, Some(&reg), &usuario, &buena).expect("verde");
        assert!(ver.autenticado(), "{usuario}: la buena autentica");

        let mala = format!("contraseña-MALA-de-{n}");
        let r = login(&srv, Some(&reg), &usuario, &mala);
        assert_eq!(r.err(), Some(ErrorLogin::ContrasenaIncorrecta), "{usuario}: la mala se rechaza");
    }
}
