// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **Un lector de CBOR MÍNIMO — solo lo que WebAuthn usa, y nada más.**
//!
//! El `attestationObject` y el `COSE_Key` de una passkey son CBOR (RFC 8949). No se trae un
//! parser CBOR completo: se lee exactamente el subconjunto que CTAP2 produce —enteros,
//! cadenas de bytes y de texto, arreglos y mapas de longitud DEFINIDA— y **todo lo demás se
//! rechaza** (longitud indefinida, tags, floats, `simple`). Rechazar de más es fail-closed:
//! un registro con una codificación exótica no se acepta a medias, se rechaza y se reintenta.
//!
//! Reglas que lo hacen seguro con entrada hostil (el autenticador es dato, no confianza):
//! - **cero pánico**: toda lectura va por un cursor que comprueba los límites y devuelve
//!   `None` en vez de indexar fuera de rango;
//! - **profundidad acotada**: el anidamiento se limita para que un CBOR malicioso no agote
//!   la pila;
//! - **sin asignación guiada por una longitud no leída**: la longitud declarada de un
//!   arreglo/mapa/cadena se comprueba contra los bytes que quedan ANTES de reservar, así que
//!   `bstr(len=4GiB)` sobre 20 bytes falla en vez de intentar reservar 4 GiB.
//!
//! # Dos laxitudes conocidas, inocuas para el uso de hoy
//!
//! No se verifica que la codificación sea CANÓNICA (CTAP2): un entero en forma no mínima
//! (`0x18 0x00` por `0x00`) se acepta. Y un mapa con **claves duplicadas** no se rechaza:
//! [`Valor::campo_int`]/[`Valor::campo_texto`] devuelven la PRIMERA. Las dos son inofensivas
//! mientras el CBOR solo se lea por valor (que es como lo usa el registro: el `COSE_Key` es
//! del propio autenticador que se da de alta, sin cruce de confianza). **El día que se
//! compare o se hashee el `attestationObject` byte a byte** —dedupe, anti-replay de la
//! respuesta— habría que exigir codificación canónica y rechazar claves duplicadas.

/// Un valor CBOR del subconjunto soportado. Los mapas conservan el orden de aparición y
/// admiten claves enteras (COSE) o de texto (`attestationObject`).
#[derive(Debug, Clone, PartialEq)]
pub enum Valor {
    /// Entero sin signo (major 0).
    Uint(u64),
    /// Entero negativo (major 1). Se guarda su valor real (p. ej. −7 para ES256).
    Nint(i64),
    /// Cadena de bytes (major 2).
    Bytes(Vec<u8>),
    /// Cadena de texto UTF-8 (major 3).
    Texto(String),
    /// Arreglo (major 4).
    Array(Vec<Valor>),
    /// Mapa (major 5), como pares en orden de aparición.
    Mapa(Vec<(Valor, Valor)>),
}

impl Valor {
    /// Si es un mapa, busca el valor de una clave entera (las claves COSE son enteras).
    pub fn campo_int(&self, clave: i64) -> Option<&Valor> {
        let Valor::Mapa(pares) = self else { return None };
        pares.iter().find_map(|(k, v)| (entero(k) == Some(clave)).then_some(v))
    }

    /// Si es un mapa, busca el valor de una clave de texto (las del `attestationObject`).
    pub fn campo_texto(&self, clave: &str) -> Option<&Valor> {
        let Valor::Mapa(pares) = self else { return None };
        pares.iter().find_map(|(k, v)| matches!(k, Valor::Texto(t) if t == clave).then_some(v))
    }

    /// Los bytes, si es una cadena de bytes.
    pub fn como_bytes(&self) -> Option<&[u8]> {
        match self {
            Valor::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

/// El valor entero (positivo o negativo) de un `Valor`, para leer claves y `alg`/`crv`.
pub fn entero(v: &Valor) -> Option<i64> {
    match v {
        Valor::Uint(u) => i64::try_from(*u).ok(),
        Valor::Nint(n) => Some(*n),
        _ => None,
    }
}

/// Profundidad máxima de anidamiento. El `attestationObject` de WebAuthn no pasa de un mapa
/// con un mapa (`attStmt`) que contiene un arreglo (`x5c`) de cadenas: 3 niveles. 16 deja
/// margen de sobra y corta un CBOR malicioso muy anidado antes de que agote la pila.
const PROFUNDIDAD_MAX: usize = 16;

/// **Parsea UN valor CBOR del subconjunto soportado, exigiendo consumir TODO.** `None` si
/// los bytes no son un CBOR válido de ese subconjunto, si sobran bytes al final (un
/// `attestationObject` es UN valor, no un flujo), o si se pasa de [`PROFUNDIDAD_MAX`].
pub fn parsear(bytes: &[u8]) -> Option<Valor> {
    let (v, n) = parsear_prefijo(bytes)?;
    // Debe consumir TODO: un `attestationObject` con cola es un error, no un valor con basura.
    (n == bytes.len()).then_some(v)
}

/// Parsea UN valor y devuelve además cuántos bytes consumió, PERMITIENDO cola. Lo necesita
/// el `authData` de registro: el `COSE_Key` va seguido —opcionalmente— de las extensiones,
/// así que hay que leer la clave y saber dónde termina, no exigir que sea el último byte.
pub fn parsear_prefijo(bytes: &[u8]) -> Option<(Valor, usize)> {
    let mut lector = Lector { b: bytes, i: 0 };
    let v = lector.valor(0)?;
    Some((v, lector.i))
}

struct Lector<'a> {
    b: &'a [u8],
    i: usize,
}

impl Lector<'_> {
    /// Lee un byte y avanza, o `None` si no queda.
    fn byte(&mut self) -> Option<u8> {
        let x = *self.b.get(self.i)?;
        self.i += 1;
        Some(x)
    }

    /// Lee `n` bytes y avanza, comprobando que existen ANTES (no reserva sobre una longitud
    /// mentirosa).
    fn tomar(&mut self, n: usize) -> Option<&[u8]> {
        let fin = self.i.checked_add(n)?;
        let trozo = self.b.get(self.i..fin)?;
        self.i = fin;
        Some(trozo)
    }

    /// Lee el argumento de un ítem CBOR según los 5 bits bajos del byte inicial. Rechaza la
    /// longitud INDEFINIDA (31) y los reservados (28–30): CTAP2 usa codificación definida.
    fn argumento(&mut self, info: u8) -> Option<u64> {
        match info {
            0..=23 => Some(u64::from(info)),
            24 => self.byte().map(u64::from),
            25 => self.tomar(2).map(|b| u64::from(u16::from_be_bytes([b[0], b[1]]))),
            26 => self.tomar(4).map(|b| u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))),
            27 => self.tomar(8).map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])),
            _ => None, // 28..=31: reservado o indefinido → rechazado
        }
    }

    /// Lee un valor completo, controlando la profundidad.
    fn valor(&mut self, profundidad: usize) -> Option<Valor> {
        if profundidad >= PROFUNDIDAD_MAX {
            return None;
        }
        let inicial = self.byte()?;
        let major = inicial >> 5;
        let info = inicial & 0x1f;
        match major {
            0 => Some(Valor::Uint(self.argumento(info)?)),
            1 => {
                // Valor real = −1 − arg. Se rechaza si no cabe en i64 (los usados son pequeños).
                let arg = self.argumento(info)?;
                let n = i64::try_from(arg).ok()?;
                Some(Valor::Nint(-1 - n))
            }
            2 => {
                let n = usize::try_from(self.argumento(info)?).ok()?;
                Some(Valor::Bytes(self.tomar(n)?.to_vec()))
            }
            3 => {
                let n = usize::try_from(self.argumento(info)?).ok()?;
                let t = core::str::from_utf8(self.tomar(n)?).ok()?;
                Some(Valor::Texto(t.to_string()))
            }
            4 => {
                let n = usize::try_from(self.argumento(info)?).ok()?;
                // No se reserva `n` a ciegas: cada elemento consume al menos un byte, así que
                // `n` mayor que los bytes restantes no puede completarse y `valor` fallará —
                // pero además se acota la reserva inicial a lo que cabe. `saturating_sub` (no
                // `len - i`) para que la cota NO dependa del invariante `i <= len`: aunque un
                // refactor futuro lo rompiera, esto no haría underflow (igual que el mapa).
                let mut v = Vec::with_capacity(n.min(self.b.len().saturating_sub(self.i)));
                for _ in 0..n {
                    v.push(self.valor(profundidad + 1)?);
                }
                Some(Valor::Array(v))
            }
            5 => {
                let n = usize::try_from(self.argumento(info)?).ok()?;
                let mut pares = Vec::with_capacity(n.min(self.b.len().saturating_sub(self.i)));
                for _ in 0..n {
                    let k = self.valor(profundidad + 1)?;
                    let val = self.valor(profundidad + 1)?;
                    pares.push((k, val));
                }
                Some(Valor::Mapa(pares))
            }
            _ => None, // major 6 (tag) y 7 (float/simple): fuera del subconjunto → rechazado
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn enteros_positivos_y_negativos() {
        assert_eq!(parsear(&[0x00]), Some(Valor::Uint(0)));
        assert_eq!(parsear(&[0x17]), Some(Valor::Uint(23)));
        assert_eq!(parsear(&[0x18, 0x18]), Some(Valor::Uint(24)));
        assert_eq!(parsear(&[0x19, 0x01, 0x00]), Some(Valor::Uint(256)));
        // −7 (ES256): major 1, arg 6 → 0x26.
        assert_eq!(parsear(&[0x26]), Some(Valor::Nint(-7)));
        // −257 (RS256): major 1, arg 256 → 0x39 0x01 0x00.
        assert_eq!(parsear(&[0x39, 0x01, 0x00]), Some(Valor::Nint(-257)));
    }

    #[test]
    fn cadenas_y_mapas() {
        // {"fmt": "none"} → A1 63 666D74 64 6E6F6E65
        let cbor = [0xA1, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e'];
        let v = parsear(&cbor).expect("mapa válido");
        assert_eq!(v.campo_texto("fmt"), Some(&Valor::Texto("none".to_string())));
        // clave entera: {1: 2} → A1 01 02
        let m = parsear(&[0xA1, 0x01, 0x02]).expect("mapa int");
        assert_eq!(m.campo_int(1).and_then(entero), Some(2));
    }

    #[test]
    fn un_cose_key_ec2_de_prueba_se_lee() {
        // {1:2, 3:-7, -1:1, -2:h'AA..(32)', -3:h'BB..(32)'} — el COSE_Key EC2/P-256.
        let mut cbor = vec![0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01];
        cbor.extend_from_slice(&[0x21, 0x58, 0x20]);
        cbor.extend_from_slice(&[0xAA; 32]);
        cbor.extend_from_slice(&[0x22, 0x58, 0x20]);
        cbor.extend_from_slice(&[0xBB; 32]);
        let v = parsear(&cbor).expect("cose key");
        assert_eq!(v.campo_int(1).and_then(entero), Some(2), "kty EC2");
        assert_eq!(v.campo_int(3).and_then(entero), Some(-7), "alg ES256");
        assert_eq!(v.campo_int(-1).and_then(entero), Some(1), "crv P-256");
        assert_eq!(v.campo_int(-2).and_then(Valor::como_bytes), Some(&[0xAA; 32][..]));
        assert_eq!(v.campo_int(-3).and_then(Valor::como_bytes), Some(&[0xBB; 32][..]));
    }

    /// **Robustez (la razón de ser del parser): la entrada hostil falla cerrado, sin pánico.**
    #[test]
    fn lo_malformado_da_none_sin_panico() {
        assert_eq!(parsear(&[]), None, "vacío");
        // bstr que declara 32 bytes y no los trae.
        assert_eq!(parsear(&[0x58, 0x20, 0x01, 0x02]), None, "longitud mentirosa");
        // longitud INDEFINIDA (0x5f = bstr indefinido) → rechazada.
        assert_eq!(parsear(&[0x5f, 0xff]), None, "longitud indefinida");
        // tag (major 6) → rechazado.
        assert_eq!(parsear(&[0xc0, 0x00]), None, "tag");
        // float/simple (major 7) → rechazado.
        assert_eq!(parsear(&[0xf9, 0x00, 0x00]), None, "float");
        // cola sobrante: dos enteros seguidos no son UN valor.
        assert_eq!(parsear(&[0x00, 0x00]), None, "cola sobrante");
        // mapa que promete 4 pares y trae uno.
        assert_eq!(parsear(&[0xA4, 0x01, 0x02]), None, "mapa incompleto");
        // texto no-UTF8.
        assert_eq!(parsear(&[0x62, 0xff, 0xfe]), None, "texto no utf8");
    }

    /// Un anidamiento más profundo que el límite se rechaza en vez de agotar la pila. Se
    /// construye un arreglo anidado 20 veces (`0x81` = arreglo de 1) — supera los 16.
    #[test]
    fn el_anidamiento_excesivo_se_corta() {
        let mut cbor = vec![0x81; 20];
        cbor.push(0x00); // el valor del fondo
        assert_eq!(parsear(&cbor), None, "más de PROFUNDIDAD_MAX niveles");
        // Y su pareja: justo por debajo del límite SÍ se lee.
        let mut ok = vec![0x81; 5];
        ok.push(0x00);
        assert!(parsear(&ok).is_some(), "pocos niveles se leen");
    }

    /// Una longitud gigantesca no intenta reservar esa memoria: falla porque los bytes no
    /// están (control del `min` en `with_capacity` y del `tomar`).
    #[test]
    fn una_longitud_gigante_no_revienta_la_memoria() {
        // array que declara 2^32 elementos (0x9a = array con arg de 4 bytes).
        assert_eq!(parsear(&[0x9a, 0xff, 0xff, 0xff, 0xff]), None);
        // bstr que declara 2^63 bytes.
        assert_eq!(parsear(&[0x5b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), None);
    }
}
