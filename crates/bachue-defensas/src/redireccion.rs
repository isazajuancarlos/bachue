// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **A dónde se puede reenviar tras el login.** Fail-closed (directiva 20/21): si no se
//! puede PROBAR que un destino es seguro, se rechaza.
//!
//! El destino de un `next` / `redirect_to` / `redirect_uri` lo suele controlar quien
//! inicia el flujo, así que un reenvío mal validado manda al usuario (con su sesión
//! recién abierta, o con un token OAuth) a un sitio del atacante. Las dos formas
//! seguras, y sólo esas:
//!
//! - una **ruta relativa** de nuestro propio sitio (empieza por un solo `/`), o
//! - una **URL absoluta registrada de antemano**, comparada por IGUALDAD EXACTA.
//!
//! Lo que NO se hace es "aceptar si la URL contiene nuestro dominio": un match por
//! substring deja pasar `https://malo.com/nuestro.com`, y la lección deriv —una regex
//! `/qa/` sin anclar que casa en cualquier posición (`qa.atacante.com`)— es ese mismo
//! error visto desde la expresión regular. Tampoco se parsea la URL para comparar su
//! host: parsear-para-comparar abre la clase de fallo por DIFERENCIA de parser (lo que
//! el validador ve como host no es lo que el navegador resuelve). La igualdad exacta
//! contra una lista registrada es, además, como OAuth manda comparar `redirect_uri`.

/// El destino de una redirección, ya juzgado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destino {
    /// Seguro: una ruta relativa de NUESTRO sitio (`/inicio?x=1`).
    Relativo(String),
    /// Seguro: una URL absoluta que coincide EXACTAMENTE con una registrada.
    AbsolutoRegistrado(String),
    /// Rechazado, con el motivo (para la bitácora; al usuario no se le explica).
    Rechazado(Motivo),
}

impl Destino {
    /// La cadena a poner en `Location`, sólo si el destino es seguro.
    #[must_use]
    pub fn seguro(&self) -> Option<&str> {
        match self {
            Self::Relativo(s) | Self::AbsolutoRegistrado(s) => Some(s),
            Self::Rechazado(_) => None,
        }
    }
}

/// Por qué se rechazó un destino. Enumera CADA causa en vez de un "otro": una razón
/// nombrada es auditable y separa el ataque (`EsquemaRelativo`) del error del usuario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Motivo {
    /// Cadena vacía.
    Vacio,
    /// `//host` o `/\host`: relativa al protocolo, el navegador va a OTRO host.
    EsquemaRelativo,
    /// No empieza por `/`: es absoluta (o basura) y no está en la lista registrada.
    NoRelativa,
    /// Contiene un carácter de control (`\r`, `\n`, `\0`…): parte cabeceras.
    CaracterDeControl,
    /// Contiene un espacio en blanco.
    Espacio,
    /// Contiene `\`: el navegador lo normaliza a `/`, así que `/\x` == `//x`.
    Retroceso,
    /// Absoluta que no coincide exactamente con ninguna registrada.
    NoRegistrado,
}

/// Valida un `next` / `redirect_to` que DEBE ser una ruta relativa de nuestro sitio.
/// Es la política más segura y cubre casi todo el flujo de login. Acepta sólo lo que
/// empieza por un ÚNICO `/` y no puede reabrirse a otro host.
#[must_use]
pub fn ruta_relativa_segura(destino: &str) -> Destino {
    if let Some(m) = defecto_estructural(destino) {
        return Destino::Rechazado(m);
    }
    let bytes = destino.as_bytes();
    // Debe empezar por '/', pero NO por '//' (relativa-al-protocolo → otro host).
    if bytes[0] != b'/' {
        return Destino::Rechazado(Motivo::NoRelativa);
    }
    if bytes.len() >= 2 && bytes[1] == b'/' {
        return Destino::Rechazado(Motivo::EsquemaRelativo);
    }
    Destino::Relativo(destino.to_string())
}

/// Valida una redirección ABSOLUTA (p. ej. el `redirect_uri` de OAuth) por IGUALDAD
/// EXACTA contra una lista registrada. Sin parsear: byte a byte.
#[must_use]
pub fn absoluto_registrado(destino: &str, registrados: &[&str]) -> Destino {
    if destino.is_empty() {
        return Destino::Rechazado(Motivo::Vacio);
    }
    if registrados.contains(&destino) {
        Destino::AbsolutoRegistrado(destino.to_string())
    } else {
        Destino::Rechazado(Motivo::NoRegistrado)
    }
}

/// La cascada habitual (directiva 19): primero intenta ruta relativa; si no lo es,
/// prueba la lista de absolutas registradas. Un solo punto de decisión para el
/// llamante que admite las dos formas.
///
/// Un defecto estructural (control, espacio, `\`, `//`) descalifica en la vía relativa
/// y NO se rescata por la absoluta, aunque el destino esté registrado: la dirección es
/// fail-closed. Consecuencia práctica: las URLs registradas deben ir ya percent-encoded
/// (sin espacios ni bytes de control crudos), o `validar` las rechazará —usa
/// [`absoluto_registrado`] directo si necesitas admitir una registrada con esos bytes—.
#[must_use]
pub fn validar(destino: &str, registrados: &[&str]) -> Destino {
    match ruta_relativa_segura(destino) {
        rel @ Destino::Relativo(_) => rel,
        // No es una ruta relativa; puede aún ser una absoluta registrada.
        Destino::Rechazado(Motivo::NoRelativa) => absoluto_registrado(destino, registrados),
        // Un defecto estructural (control, espacio, `\`, `//`) descalifica también la
        // vía absoluta: no se le da una segunda oportunidad a algo malformado.
        otro => otro,
    }
}

/// Defectos que descalifican CUALQUIER destino, sea relativo o absoluto: vacío,
/// caracteres de control, espacios y el backslash. Se comprueban una sola vez.
fn defecto_estructural(destino: &str) -> Option<Motivo> {
    if destino.is_empty() {
        return Some(Motivo::Vacio);
    }
    if destino.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Some(Motivo::CaracterDeControl);
    }
    if destino.bytes().any(|b| b == b' ' || b == b'\t') {
        return Some(Motivo::Espacio);
    }
    if destino.contains('\\') {
        return Some(Motivo::Retroceso);
    }
    None
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn ruta_relativa_normal_pasa() {
        assert_eq!(
            ruta_relativa_segura("/inicio?x=1"),
            Destino::Relativo("/inicio?x=1".to_string())
        );
        assert_eq!(ruta_relativa_segura("/"), Destino::Relativo("/".to_string()));
    }

    /// El caso ROJO central (directiva 33): `//evil.com` es una URL relativa al
    /// protocolo —el navegador la resuelve a `https://evil.com`— y DEBE rechazarse.
    /// Un validador que sólo comprobara "empieza por `/`" la dejaría pasar.
    #[test]
    fn doble_barra_es_otro_host() {
        assert_eq!(
            ruta_relativa_segura("//evil.com"),
            Destino::Rechazado(Motivo::EsquemaRelativo)
        );
        assert_eq!(
            ruta_relativa_segura("//evil.com/robar"),
            Destino::Rechazado(Motivo::EsquemaRelativo)
        );
    }

    #[test]
    fn backslash_equivale_a_doble_barra() {
        // El navegador normaliza `\` a `/`, así que `/\evil.com` va a otro host.
        assert_eq!(ruta_relativa_segura("/\\evil.com"), Destino::Rechazado(Motivo::Retroceso));
        assert_eq!(ruta_relativa_segura("\\\\evil.com"), Destino::Rechazado(Motivo::Retroceso));
    }

    #[test]
    fn control_y_espacio_parten_cabeceras() {
        assert_eq!(
            ruta_relativa_segura("/inicio\r\nSet-Cookie: x=1"),
            Destino::Rechazado(Motivo::CaracterDeControl)
        );
        assert_eq!(ruta_relativa_segura("/con espacio"), Destino::Rechazado(Motivo::Espacio));
    }

    #[test]
    fn absoluta_no_es_ruta_relativa() {
        assert_eq!(
            ruta_relativa_segura("https://cuenta.xiliux.com/cb"),
            Destino::Rechazado(Motivo::NoRelativa)
        );
    }

    /// La igualdad EXACTA discrimina lo que un match por substring dejaría pasar
    /// (directiva 33): la registrada legítima entra; una que la CONTIENE como
    /// substring (`…@evil.com`, o `evil.com/…cuenta.xiliux.com`) NO.
    #[test]
    fn registrado_exacto_no_por_substring() {
        let reg = ["https://cuenta.xiliux.com/cb"];
        assert_eq!(
            absoluto_registrado("https://cuenta.xiliux.com/cb", &reg),
            Destino::AbsolutoRegistrado("https://cuenta.xiliux.com/cb".to_string())
        );
        // userinfo: el host real es evil.com.
        assert_eq!(
            absoluto_registrado("https://cuenta.xiliux.com@evil.com/cb", &reg),
            Destino::Rechazado(Motivo::NoRegistrado)
        );
        // el dominio bueno aparece como substring en el path del malo.
        assert_eq!(
            absoluto_registrado("https://evil.com/https://cuenta.xiliux.com/cb", &reg),
            Destino::Rechazado(Motivo::NoRegistrado)
        );
        // sufijo/prefijo pegado: no es igualdad exacta.
        assert_eq!(
            absoluto_registrado("https://cuenta.xiliux.com/cb.evil.com", &reg),
            Destino::Rechazado(Motivo::NoRegistrado)
        );
    }

    #[test]
    fn cascada_validar() {
        let reg = ["https://cuenta.xiliux.com/cb"];
        // relativa buena
        assert!(matches!(validar("/inicio", &reg), Destino::Relativo(_)));
        // absoluta registrada
        assert!(matches!(validar("https://cuenta.xiliux.com/cb", &reg), Destino::AbsolutoRegistrado(_)));
        // absoluta NO registrada
        assert_eq!(validar("https://evil.com", &reg), Destino::Rechazado(Motivo::NoRegistrado));
        // `//evil.com` no se rescata por la vía absoluta: el defecto manda.
        assert_eq!(validar("//evil.com", &reg), Destino::Rechazado(Motivo::EsquemaRelativo));
        // malformada con control tampoco.
        assert_eq!(validar("/x\r\n", &reg), Destino::Rechazado(Motivo::CaracterDeControl));
    }

    #[test]
    fn vacio_se_rechaza() {
        assert_eq!(ruta_relativa_segura(""), Destino::Rechazado(Motivo::Vacio));
        assert_eq!(absoluto_registrado("", &["x"]), Destino::Rechazado(Motivo::Vacio));
    }

    #[test]
    fn seguro_devuelve_la_cadena_solo_si_lo_es() {
        assert_eq!(ruta_relativa_segura("/ok").seguro(), Some("/ok"));
        assert_eq!(ruta_relativa_segura("//evil.com").seguro(), None);
    }
}
