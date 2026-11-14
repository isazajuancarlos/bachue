// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **Bachué F1 — autenticación por contraseña.**
//!
//! El FLUJO alrededor del Argon2, que hoy medico e informes reescriben cada uno. El
//! hash en sí lo hace [`guaca::claves`] (una sola implementación, auditada una vez);
//! aquí vive lo que guaca no puede saber: qué hacer cuando la cuenta NO existe, y qué
//! exige una contraseña para admitirse.
//!
//! # La lección que este módulo encarna
//!
//! **Un correo inexistente tiene que costar lo mismo que uno existente.** Si el camino
//! "no hay cuenta" respondiera al instante (&lt;1 ms) mientras el camino con hash tarda lo
//! que tarda un Argon2 (~35 ms), ese reloj diría qué correos existen —un oráculo de
//! enumeración gratis—. Por eso [`autenticar`] verifica SIEMPRE contra un Argon2, real
//! o de descarte. Es la misma pieza que en medico protege
//! `un_correo_inexistente_cuesta_lo_mismo_que_uno_existente`.
//!
//! # Lo que NO está aquí todavía (F1.b, siguiente)
//!
//! La **renovación de hash sin abaratar** (`renovar_si_hace_falta`): reescribir el hash
//! de quien entra si la política subió, con la regla delicada «nunca se reescribe un
//! hash que cueste MÁS trabajo `m×t`» —la que en informes destruía hashes buenos si se
//! escribía mal (un `m=2GiB t=1` rebajado a `m=19MiB t=2`, 53× menos trabajo, en
//! silencio)—. Es una pieza que merece su propio banco; se hace aparte.

#![forbid(unsafe_code)]

use std::sync::OnceLock;

use argon2::password_hash::PasswordHash;
use argon2::{Algorithm, Params};

/// Hashea una contraseña (Argon2, vía guaca — una sola implementación en el universo).
/// `None` solo si el propio Argon2 falla; el llamante lo trata como fallo, no lo ignora.
pub fn hashear(clave: &str) -> Option<String> {
    guaca::claves::hashear(clave)
}

/// El hash de DESCARTE: un Argon2 real de un valor fijo que ninguna contraseña casa,
/// para gastar el MISMO tiempo cuando la cuenta no existe. Se computa una sola vez
/// (perezoso) y su único trabajo es costar lo que cuesta un hash de verdad — por eso
/// se genera con el mismo `guaca::claves::hashear`, no con parámetros rebajados.
fn hash_descarte() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| {
        guaca::claves::hashear("descarte::no-es-una-cuenta::bachue")
            .expect("el hash de descarte se genera al arrancar")
    })
}

/// **Autentica una contraseña contra el hash GUARDADO de una cuenta, o `None` si no
/// existe.** Devuelve `true` solo si la cuenta existe Y la contraseña casa.
///
/// El camino `None` (cuenta inexistente o desactivada) verifica IGUALMENTE contra el
/// [`hash_descarte`]: sin eso, el tiempo de respuesta delata qué cuentas existen. El
/// llamante debe pasar `None` también para una cuenta desactivada —no cortocircuitar
/// antes—, para que "existe pero inactiva" y "no existe" sean indistinguibles.
pub fn autenticar(hash_guardado: Option<&str>, clave: &str) -> bool {
    match hash_guardado {
        Some(h) => guaca::claves::verificar(clave, h),
        None => {
            // Se descarta el resultado A PROPÓSITO: el trabajo es el punto, no el valor.
            let _ = guaca::claves::verificar(clave, hash_descarte());
            false
        }
    }
}

/// Qué exige una contraseña para admitirse al fijarla (registro / cambio).
///
/// Longitud mínima, sin reglas de complejidad forzada (NIST SP 800-63B: la longitud
/// protege, la complejidad obligatoria empuja a patrones predecibles). El llamante
/// puede subir el mínimo; no puede bajarlo de un piso sensato salvo declarándolo.
#[derive(Debug, Clone, Copy)]
pub struct Politica {
    pub longitud_minima: usize,
}

impl Default for Politica {
    fn default() -> Self {
        // 12 caracteres: piso razonable para una contraseña humana en 2026.
        Self { longitud_minima: 12 }
    }
}

/// Por qué se rechaza una contraseña al fijarla. Es para el usuario que la elige, no
/// para el que la adivina (que recibe siempre lo mismo, ver [`autenticar`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rechazo {
    /// Más corta que el mínimo (que se incluye para poder decírselo al usuario).
    DemasiadoCorta { minimo: usize },
    /// Estructuralmente DEGENERADA aunque cumpla la longitud: repetición de un patrón
    /// corto (`abcabcabcabc`), una secuencia (`abcdefghijkl`, `123456789012`) o una
    /// caminata de teclado (`qwertyuiopas`).
    ///
    /// **Alcance HONESTO (medido en el concilio del 2026-09-30, directiva 16):** es un
    /// PISO DE HIGIENE que caza sólo las estructuras más perezosas — NO un filtro de
    /// contraseñas débiles. `Password2026!`, `Welcome2026!` o `1qaz2wsx3edc` PASAN. La
    /// defensa real contra el rociado sigue siendo el mínimo de 12 (que ya rechaza casi
    /// toda lista de comunes: 10 de 10 000 del «10k-most-common» llegan a 12) más el
    /// 2FA; esto sólo elimina lo indefendible. Subir la cobertura a patrones
    /// GENERATIVOS (palabra+año) exigiría un estimador de fuerza (zxcvbn), que es otra
    /// decisión — no se finge aquí (el error simétrico sería aparentar más de lo que mide).
    Predecible,
}

impl Politica {
    /// ¿Admite esta contraseña? Se cuenta por CARACTERES (no bytes): una contraseña
    /// con acentos o emoji no vale menos por ocupar más bytes.
    pub fn admite(&self, clave: &str) -> Result<(), Rechazo> {
        let chars: Vec<char> = clave.chars().collect();
        if chars.len() < self.longitud_minima {
            return Err(Rechazo::DemasiadoCorta { minimo: self.longitud_minima });
        }
        // Predecibilidad estructural (sólo importa en las que YA pasan la longitud): tres
        // reglas de altísima precisión, para no rechazar contraseñas fuertes (directiva 21).
        if es_repeticion(&chars) || es_secuencia(&chars) || es_caminata_de_teclado(clave) {
            return Err(Rechazo::Predecible);
        }
        Ok(())
    }
}

/// Repetición de un patrón corto: la clave es una unidad repetida.
///
/// **×3 o más** de CUALQUIER unidad (`aaaaaaaaaaaa`, `abcabcabcabc`) → predecible. **×2**
/// sólo si la unidad es ELLA MISMA predecible (`qwertyqwerty`, `123456123456`): duplicar
/// una mitad legítima no basta (`caballocaballo`, `áéíóúñáéíóúñ` → pasan). Es la
/// corrección del concilio (directiva 23): el umbral en ×3 dejaba pasar ×2 de una unidad
/// que ya era caminata o secuencia — el arreglo va en la regla, no en el caso.
fn es_repeticion(chars: &[char]) -> bool {
    let n = chars.len();
    for p in 1..=n / 2 {
        if n % p != 0 || !(p..n).all(|i| chars[i] == chars[i - p]) {
            continue; // no es unidad repetida con este periodo
        }
        let repeticiones = n / p;
        if repeticiones >= 3 {
            return true;
        }
        // repeticiones == 2: sólo si la unidad, sola, ya es predecible. No hace falta
        // `es_repeticion(unidad)`: una unidad internamente repetida ya cae antes, como
        // ×≥3 de su periodo menor en este mismo bucle ascendente (verificado, concilio).
        let unidad = &chars[..p];
        let unidad_txt: String = unidad.iter().collect();
        if es_secuencia(unidad) || es_caminata_de_teclado(&unidad_txt) {
            return true;
        }
    }
    false
}

/// Secuencia aritmética de paso ±1 en TODO el largo: `abcdefghijkl`, `lkjihgfedcba`. Se
/// exige que TODOS los saltos sean iguales a +1 o todos a −1 —máxima precisión: una clave
/// real no es una escalera entera—. La secuencia numérica con VUELTA (`123456789012`, que
/// aquí rompe en 9→0) la caza [`es_caminata_de_teclado`] con el ciclo de dígitos.
fn es_secuencia(chars: &[char]) -> bool {
    if chars.len() < 2 {
        return false;
    }
    let paso = chars[1] as i32 - chars[0] as i32;
    (paso == 1 || paso == -1)
        && chars.windows(2).all(|w| w[1] as i32 - w[0] as i32 == paso)
}

/// Caminata de teclado o de dígitos: la clave (en minúsculas) es un tramo contiguo de las
/// filas del teclado encadenadas, o del ciclo de dígitos, hacia delante o hacia atrás
/// (`qwertyuiopas`, `mnbvcxzlkj`, `123456789012`). Un tramo ≥12 de esas cadenas exactas es,
/// en la práctica, siempre pereza, no una contraseña elegida. El ciclo de dígitos
/// (`…8901234…`) cierra la vuelta 9→0 que [`es_secuencia`] no ve.
fn es_caminata_de_teclado(clave: &str) -> bool {
    // Filas del teclado encadenadas, y el ciclo de dígitos (repetido para cubrir la vuelta).
    const CAMINOS: [&str; 2] = ["1234567890qwertyuiopasdfghjklzxcvbnm", "12345678901234567890"];
    let baja = clave.to_lowercase();
    if baja.chars().count() < 4 {
        return false;
    }
    CAMINOS.iter().any(|camino| {
        let reves: String = camino.chars().rev().collect();
        camino.contains(baja.as_str()) || reves.contains(baja.as_str())
    })
}

// ── F1.b — RENOVACIÓN DE HASH SIN ABARATAR ──
//
// La pieza delicada: reescribir el hash de quien entra si la política subió, SIN
// rebajarlo jamás. Es la regla que en informes destruía hashes buenos —un
// `m=2GiB t=1` (primera opción del RFC 9106) rebajado a `m=19MiB t=2` porque `t=1<2`,
// 53× menos trabajo, en silencio y sin vuelta atrás—. El fallo estaba en la REGLA,
// no en un caso: preguntaba cada eje por separado unidos por un OR (directiva 23).

/// El perfil de COSTE de un hash Argon2, para decidir si renovarlo.
#[derive(Clone, Copy)]
struct Perfil {
    /// Trabajo = `m_cost × t_cost`. `p` NO entra: reparte el mismo trabajo, no lo sube.
    trabajo: u64,
    /// Modernidad de la variante: Argon2d=0 < Argon2i=1 < Argon2id=2.
    rango_variante: u8,
    /// Versión del formato: `0x10` (vieja) vs `0x13` (la de hoy).
    version: u32,
}

fn rango_variante(a: Algorithm) -> u8 {
    match a {
        Algorithm::Argon2d => 0,
        Algorithm::Argon2i => 1,
        Algorithm::Argon2id => 2,
    }
}

/// El perfil de un PHC de Argon2, o `None` si no es Argon2 legible (no se toca a ciegas).
fn perfil(phc: &str) -> Option<Perfil> {
    let h = PasswordHash::new(phc).ok()?;
    let p = Params::try_from(&h).ok()?;
    let variante = Algorithm::try_from(h.algorithm).ok()?;
    Some(Perfil {
        trabajo: u64::from(p.m_cost()) * u64::from(p.t_cost()),
        rango_variante: rango_variante(variante),
        // Sin versión declarada se asume la vieja (0x10): fail-hacia-renovar, no al revés.
        version: h.version.unwrap_or(0x10),
    })
}

/// La política de HOY, DERIVADA de `guaca::claves::hashear` (no hardcodeada): "al día"
/// = "lo que guaca produce ahora". Anclada al artefacto (directiva 31): si guaca sube
/// sus parámetros, esto los sigue solo. Se computa una vez por proceso.
fn perfil_de_hoy() -> Perfil {
    static P: OnceLock<Perfil> = OnceLock::new();
    *P.get_or_init(|| {
        let dummy = guaca::claves::hashear("perfil::hoy::bachue")
            .expect("guaca produce un hash Argon2");
        perfil(&dummy).expect("el hash de guaca es Argon2 legible")
    })
}

/// **Renueva el hash de quien ACABA de entrar si la política de hoy es más fuerte —
/// SIN abaratarlo jamás.** `Some(nuevo)` si hay que reescribir; `None` si ya está al
/// día, es MÁS fuerte, o es ilegible.
///
/// La regla, en UNA frase (y tiene que seguir siéndolo): nunca se reescribe un hash que
/// cueste MÁS trabajo (`m×t`); se reescribe si cuesta MENOS, o lo MISMO y su variante o
/// versión es anticuada. `p` no cuenta; la variante sola no justifica rebajar el trabajo.
///
/// Solo se llama en el ACIERTO (se tiene `clave` en claro). El llamante NO sube
/// `token_version` por esto: no es un cambio de contraseña, es la misma escrita mejor.
pub fn renovar_si_hace_falta(hash_actual: &str, clave: &str) -> Option<String> {
    let actual = perfil(hash_actual)?;
    let hoy = perfil_de_hoy();
    let renovar = match actual.trabajo.cmp(&hoy.trabajo) {
        std::cmp::Ordering::Greater => false, // cuesta MÁS: nunca abaratar
        std::cmp::Ordering::Less => true,     // cuesta menos: subir
        // Mismo trabajo: solo por variante o versión anticuada.
        std::cmp::Ordering::Equal => {
            actual.rango_variante < hoy.rango_variante || actual.version < hoy.version
        }
    };
    renovar.then(|| guaca::claves::hashear(clave)).flatten()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const BUENA: &str = "contraseña-de-prueba-larga";

    /// La buena entra; una mala no; y su pareja: la cuenta inexistente tampoco.
    #[test]
    fn la_buena_entra_la_mala_y_la_inexistente_no() {
        let h = hashear(BUENA).expect("hashea");
        assert!(autenticar(Some(&h), BUENA), "la contraseña correcta entra");
        assert!(!autenticar(Some(&h), "otra-cosa"), "una contraseña mala no entra");
        assert!(!autenticar(None, BUENA), "sin cuenta no se entra ni con una clave válida");
    }

    /// **CONTROL ANTI-TIMING (la razón de ser del módulo, directiva 33).** El camino
    /// de la cuenta INEXISTENTE debe costar lo mismo que el de una cuenta real —los dos
    /// corren un Argon2—. Si alguien quita el hash de descarte (`None` retorna sin
    /// verificar), el camino inexistente se vuelve casi instantáneo y este test lo caza:
    /// se exige que el tiempo del inexistente sea AL MENOS el 40 % del tiempo real
    /// (con señuelo es ~100 %; sin señuelo sería ~2 %, muy por debajo del umbral). El
    /// margen es amplio a propósito, para no ser frágil ante el ruido del planificador.
    #[test]
    fn un_correo_inexistente_cuesta_lo_mismo_que_uno_existente() {
        use std::time::Instant;
        let h = hashear(BUENA).expect("hashea");
        // Calienta el hash de descarte (su generación perezosa) fuera de la medición.
        let _ = autenticar(None, "x");

        let medir = |f: &dyn Fn()| -> u128 {
            let mut mejor = u128::MAX;
            for _ in 0..3 {
                let t = Instant::now();
                f();
                mejor = mejor.min(t.elapsed().as_micros());
            }
            mejor
        };
        let existente = medir(&|| {
            assert!(!autenticar(Some(&h), "clave-incorrecta"));
        });
        let inexistente = medir(&|| {
            assert!(!autenticar(None, "clave-incorrecta"));
        });
        assert!(
            inexistente * 100 >= existente * 40,
            "el camino inexistente ({inexistente} µs) es demasiado rápido frente al \
             existente ({existente} µs): ¿se saltó el hash de descarte?"
        );
    }

    /// La política admite lo largo y rechaza lo corto — con su pareja, para que no sea
    /// un validador que diga que sí (o que no) a todo.
    #[test]
    fn la_politica_rechaza_lo_corto_y_admite_lo_largo() {
        let p = Politica::default();
        assert_eq!(p.admite("corta"), Err(Rechazo::DemasiadoCorta { minimo: 12 }));
        assert!(p.admite("esta-si-es-suficientemente-larga").is_ok());
        // Se cuenta por CARACTERES: 12 acentuadas admiten aunque ocupen más bytes.
        assert!(Politica { longitud_minima: 12 }.admite("áéíóúñáéíóúñ").is_ok());
    }

    /// Repetición: la roja y su casi (directiva 33). El umbral es ×3, así que ×2 pasa.
    #[test]
    fn rechaza_repeticion_pero_admite_el_casi() {
        let p = Politica::default();
        assert_eq!(p.admite("abcabcabcabc"), Err(Rechazo::Predecible), "unidad de 3, ×4");
        assert_eq!(p.admite("xyxyxyxyxyxy"), Err(Rechazo::Predecible), "unidad de 2, ×6");
        assert_eq!(p.admite("nananananana"), Err(Rechazo::Predecible), "×6");
        // ×2 SÍ se rechaza si la unidad ya es predecible (corrección del concilio, D23).
        assert_eq!(p.admite("qwertyqwerty"), Err(Rechazo::Predecible), "×2 de una caminata");
        assert_eq!(p.admite("123456123456"), Err(Rechazo::Predecible), "×2 de una secuencia");
        // Casi: la repetición se rompe en el último carácter → NO es repetición.
        assert!(p.admite("abcabcabcabx").is_ok(), "un patrón roto al final no es repetición");
        // Duplicar una mitad LEGÍTIMA (×2) NO basta: es un pilar de passphrase.
        assert!(p.admite("caballocaballo").is_ok(), "×2 de una unidad no predecible pasa");
    }

    /// Secuencia aritmética ±1: la roja y su casi.
    #[test]
    fn rechaza_secuencia_pero_admite_el_casi() {
        let p = Politica::default();
        assert_eq!(p.admite("abcdefghijkl"), Err(Rechazo::Predecible), "ascendente");
        assert_eq!(p.admite("lkjihgfedcba"), Err(Rechazo::Predecible), "descendente");
        // Numérica con vuelta 9→0: la caza el ciclo de dígitos de la caminata (hueco del concilio).
        assert_eq!(p.admite("123456789012"), Err(Rechazo::Predecible), "dígitos con vuelta");
        // Casi: el último salto se rompe → no es una escalera entera.
        assert!(p.admite("abcdefghijkx").is_ok(), "una secuencia rota no es secuencia");
        // Paso 2 (no ±1) NO se rechaza: la regla es de máxima precisión a propósito.
        assert!(p.admite("acegikmoqsuw").is_ok(), "paso 2 no es la regla");
    }

    /// Caminata de teclado: la roja (incluida en mayúsculas y al revés) y su casi.
    #[test]
    fn rechaza_caminata_de_teclado_pero_admite_el_casi() {
        let p = Politica::default();
        assert_eq!(p.admite("qwertyuiopas"), Err(Rechazo::Predecible), "cruza filas");
        assert_eq!(p.admite("asdfghjklzxc"), Err(Rechazo::Predecible), "fila media a baja");
        assert_eq!(p.admite("QWERTYUIOPAS"), Err(Rechazo::Predecible), "mayúsculas igual");
        assert_eq!(p.admite("mnbvcxzlkjhg"), Err(Rechazo::Predecible), "al revés");
        // Casi: una letra fuera de la caminata → pasa.
        assert!(p.admite("qwertyuiopXk").is_ok(), "una caminata interrumpida pasa");
    }

    /// Control de falsos positivos (directiva 16): contraseñas FUERTES —incluidas las que
    /// se parecen a un patrón sin serlo— NO se rechazan. Si esto se pone rojo, la regla
    /// está cerrando de más (directiva 21).
    #[test]
    fn no_rechaza_contrasenas_fuertes() {
        let p = Politica::default();
        for fuerte in [
            "correct-horse-battery",
            "Tr0ub4dor&3x-largo",
            "café-con-leche-y-pan-2026",
            "esta-si-es-suficientemente-larga",
            "áéíóúñáéíóúñ",
            "MedellínLluviaAbril",
            "caballocaballo",
        ] {
            assert!(p.admite(fuerte).is_ok(), "contraseña fuerte rechazada: {fuerte}");
        }
    }

    /// Construye un hash Argon2 con parámetros ELEGIDOS (para los casos de renovación).
    /// Usa argon2 directo A PROPÓSITO —es un arnés, no producción—: los hashes de
    /// verdad los sigue haciendo guaca.
    fn hash_con(alg: Algorithm, m: u32, t: u32) -> String {
        use argon2::password_hash::{PasswordHasher, SaltString};
        use argon2::{Argon2, Version};
        let sal = SaltString::from_b64("c2FsdHNhbHRzYWx0").expect("sal de prueba válida");
        Argon2::new(alg, Version::V0x13, Params::new(m, t, 1, None).expect("params"))
            .hash_password(b"no-importa", &sal)
            .expect("hashea")
            .to_string()
    }

    /// **EL CASO EMBLEMÁTICO (directiva 33): un hash MÁS FUERTE EN CONJUNTO no se
    /// rebaja, aunque sea más flojo en un eje.** `m=64 MiB, t=1` cuesta 65536 de
    /// trabajo (> los 38912 de hoy) pero tiene `t=1 < 2`; la regla mala (mirar `t`)
    /// lo rebajaría 53×, la buena (`m×t`) lo deja intacto. Su PAREJA discriminante: un
    /// hash de verdad débil SÍ se sube —sin ella, un "renovar que nunca renueva"
    /// pasaría el caso rojo—.
    #[test]
    fn un_hash_mas_fuerte_en_conjunto_no_se_rebaja_pero_uno_debil_si() {
        let fuerte = hash_con(Algorithm::Argon2id, 65536, 1);
        assert!(
            renovar_si_hace_falta(&fuerte, "clave").is_none(),
            "un hash más caro en conjunto NUNCA se rebaja, aunque t sea menor"
        );
        let debil = hash_con(Algorithm::Argon2id, 8, 1);
        assert!(
            renovar_si_hace_falta(&debil, "clave").is_some(),
            "un hash más barato sí se sube a la política de hoy"
        );
    }

    /// Un hash producido con la política de HOY (el de guaca) no se toca.
    #[test]
    fn un_hash_al_dia_no_se_toca() {
        let hoy = hashear(BUENA).expect("hashea");
        assert!(renovar_si_hace_falta(&hoy, BUENA).is_none());
    }

    /// Misma fuerza (`m×t`) pero variante VIEJA (`argon2i < argon2id`): se renueva.
    /// Prueba que la regla del "mismo trabajo" mira la variante, no solo el coste.
    #[test]
    fn una_variante_anticuada_con_mismo_trabajo_se_renueva() {
        let anticuada = hash_con(Algorithm::Argon2i, 19456, 2);
        assert!(
            renovar_si_hace_falta(&anticuada, "clave").is_some(),
            "misma fuerza pero argon2i (menos moderno que argon2id): se renueva"
        );
    }

    /// Un hash ilegible NO se toca a ciegas (es otra avería, se maneja aparte).
    #[test]
    fn un_hash_ilegible_no_se_toca() {
        assert!(renovar_si_hace_falta("esto-no-es-un-phc", "clave").is_none());
    }

    /// Y cuando SÍ renueva, el hash nuevo deja entrar con la clave y ya está al día.
    /// Sin esto, `renovar` podría devolver basura que nadie verifica.
    #[test]
    fn el_hash_renovado_verifica_la_clave_y_ya_no_pide_renovarse() {
        let debil = hash_con(Algorithm::Argon2id, 8, 1);
        let nuevo = renovar_si_hace_falta(&debil, BUENA).expect("un débil se renueva");
        assert!(autenticar(Some(&nuevo), BUENA), "el renovado deja entrar con la clave");
        assert!(renovar_si_hace_falta(&nuevo, BUENA).is_none(), "y ya no pide renovarse");
    }
}
