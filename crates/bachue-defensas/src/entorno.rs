// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **Qué variables de entorno pueden llegar a un proceso hijo.**
//!
//! Ciertos nombres de variable cambian CÓMO ejecuta código el hijo —el enlazador
//! dinámico (`LD_PRELOAD`, `LD_AUDIT`…), el shell (`BASH_ENV`, `ENV`), los intérpretes
//! (`PYTHONPATH`, `RUBYOPT`, `PERL5OPT`, `NODE_OPTIONS`, `JAVA_TOOL_OPTIONS`…)—. Fijar
//! uno de ellos con un valor controlado NO es configuración: es ejecución de código.
//! Por eso, cuando un valor de origen no del todo confiable (un "secreto" de una
//! herramienta de config, un campo de la base) se va a inyectar como entorno de un
//! `Command`, hay que sanearlo primero.
//!
//! La lección Doppler, entera:
//! 1. **Se ELIMINAN, no se advierten.** Su denylist sólo registraba un aviso para la
//!    mayoría (`LogWarning`, sin abortar), y ese aviso iba al stderr del EJECUTOR, no
//!    del que escribió el valor → inútil en CI. Aquí se quitan del entorno.
//! 2. **Consistencia.** Doppler eliminaba `PATH` pero a `LD_PRELOAD` sólo lo advertía;
//!    aquí todos los nombres peligrosos reciben el mismo trato.
//! 3. **Completitud, con su prueba.** La denylist de Doppler estaba incompleta
//!    (faltaban `BASH_ENV`, `ENV`, `LD_AUDIT`, `PYTHONPATH`, `JAVA_TOOL_OPTIONS`…). La
//!    de aquí cubre esos, y su prueba de completitud falla si alguno se cae.
//!
//! **La vía PREFERIDA no es esta resta.** Una denylist es "todo lo demás pasa"
//! (directiva 23), y ningún catálogo de nombres peligrosos es exhaustivo —cada
//! intérprete nuevo trae ganchos nuevos—. Cuando el llamante PUEDE enumerar sus
//! claves de config, usa [`entorno_solo`] (allowlist: enumera lo que SÍ, descarta el
//! resto). [`entorno_saneado`] es la red para cuando no se pueden enumerar.

/// Nombres de variable de entorno que alteran la ejecución de un proceso hijo. NO es
/// exhaustiva por naturaleza (ver la cabecera del módulo); su completitud sobre los
/// vectores conocidos la fija la prueba `denylist_cubre_los_vectores_conocidos`.
///
/// La comparación es sensible a mayúsculas y exacta, que es como los honra el sistema:
/// el enlazador busca `LD_PRELOAD`, no `ld_preload`. Un servidor Linux es el objetivo;
/// en un entorno con nombres de env insensibles a mayúsculas hay que endurecer aparte.
const PELIGROSAS: &[&str] = &[
    // ── Enlazador dinámico (glibc / musl) ──
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_ORIGIN_PATH",
    "LD_PROFILE",
    "LD_CONFIG",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_ASSUME_KERNEL",
    "LD_BIND_NOW",
    "LD_DYNAMIC_WEAK",
    "LD_PROFILE_OUTPUT",
    // glibc: carga de MÓDULOS o DATOS por ruta controlada. `GCONV_PATH` es el primo
    // directo de `LD_PRELOAD`: un `gconv-modules` propio hace `dlopen` de un `.so` del
    // atacante en la primera conversión de charset (ubicua vía locale) → RCE nativo,
    // y glibc lo honra en binarios no privilegiados igual que `LD_AUDIT`. `LOCPATH` y
    // `NLSPATH` cargan datos de locale/mensajes desde ruta arbitraria (misma familia,
    // con historial de format-string).
    "GCONV_PATH",
    "LOCPATH",
    "NLSPATH",
    // ── Enlazador dinámico (macOS dyld) ──
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FALLBACK_FRAMEWORK_PATH",
    // ── Shell (sh / bash) ──
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "BASHOPTS",
    "PS1",
    "PS2",
    "PS4",
    "PROMPT_COMMAND",
    "GLOBIGNORE",
    // ── Shell zsh / ksh: sourcean archivos por ruta, también en modo NO interactivo
    //    (el equivalente zsh de `BASH_ENV`), y `FPATH` fija de dónde autocargan
    //    funciones. Sólo alcanza si el hijo es zsh/ksh, poco común en servidor, pero
    //    es ejecución de código y la resta es barata. ──
    "ZDOTDIR",
    "FPATH",
    // ── Python ──
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
    "PYTHONHOME",
    "PYTHONWARNINGS",
    // ── Ruby ──
    "RUBYOPT",
    "RUBYLIB",
    // ── Perl ──
    "PERL5OPT",
    "PERL5LIB",
    "PERLLIB",
    "PERL5DB",
    // ── Node ──
    "NODE_OPTIONS",
    "NODE_PATH",
    // ── Java / JVM ──
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "CLASSPATH",
    // ── Git (arranca diff/pager/ssh externos) ──
    "GIT_EXTERNAL_DIFF",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_PAGER",
    "GIT_EDITOR",
    // ── Rutas de ejecución y separadores generales ──
    "PATH",
    "IFS",
    "CDPATH",
];

/// ¿El nombre altera la ejecución de un proceso hijo?
///
/// Dos vías, porque una lista de nombres literales no basta: hay vectores cuyo nombre
/// es DINÁMICO. La pertenencia exacta a [`PELIGROSAS`], y además una comprobación por
/// FORMA (ver [`forma_peligrosa`]) que atrapa lo que ningún literal puede —las
/// funciones exportadas de bash `BASH_FUNC_<x>%%` y, defensivamente, cualquier nombre
/// que no sea un identificador normal, porque meter estructura por el nombre no es
/// configurar—.
#[must_use]
pub fn es_peligrosa(nombre: &str) -> bool {
    PELIGROSAS.contains(&nombre) || forma_peligrosa(nombre)
}

/// Nombres peligrosos por su FORMA, no por figurar en una lista.
///
/// - `BASH_FUNC_<nombre>%%`: bash (post-Shellshock) IMPORTA como función cualquier
///   variable así llamada con valor `() { … }`, y un hijo `bash -c` la define y la
///   puede ejecutar. El nombre lleva prefijo y sufijo variables, así que ningún
///   literal lo cubre jamás — sólo el patrón.
/// - Un nombre de variable de configuración NORMAL es un identificador
///   `[A-Za-z_][A-Za-z0-9_]*`. Cualquier otra cosa (`%`, `(`, un espacio…) es un
///   intento de colar estructura por el nombre; `Command::envs` lo aceptaría, así que
///   se descarta (directiva 20/23: fail-closed hacia lo que no es config plana).
fn forma_peligrosa(nombre: &str) -> bool {
    if nombre.starts_with("BASH_FUNC_") {
        return true;
    }
    !es_identificador(nombre)
}

/// ¿`nombre` es un identificador de shell normal `[A-Za-z_][A-Za-z0-9_]*`? Una cadena
/// vacía no lo es (y se trata como peligrosa: no es un nombre de config legítimo).
fn es_identificador(nombre: &str) -> bool {
    let mut cs = nombre.chars();
    match cs.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    cs.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Devuelve el entorno SIN las variables que alteran la ejecución (las ELIMINA, no las
/// advierte). Red de seguridad para cuando el llamante no puede enumerar sus claves; si
/// puede, prefiere [`entorno_solo`].
///
/// **Sanea sólo lo que le pasas, no el entorno AMBIENTE.** `std::process::Command`
/// HEREDA por defecto todo el entorno del padre, así que un `LD_PRELOAD` que ya esté en
/// el proceso padre llega al hijo aunque no venga en `vars`. Por eso el uso correcto
/// LIMPIA primero y luego inyecta lo saneado:
///
/// ```no_run
/// # use std::process::Command;
/// # use bachue_defensas::entorno::entorno_saneado;
/// # let vars: Vec<(String, String)> = vec![];
/// Command::new("./script.sh")
///     .env_clear() // corta la herencia del entorno ambiente
///     .envs(entorno_saneado(vars))
///     .spawn()?;
/// # Ok::<(), std::io::Error>(())
/// ```
#[must_use]
pub fn entorno_saneado<I, K, V>(vars: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    vars.into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .filter(|(k, _)| !es_peligrosa(k))
        .collect()
}

/// La vía PREFERIDA cuando el llamante conoce sus claves: conserva SÓLO las permitidas.
/// Así ninguna variable inesperada —peligrosa o no— llega al hijo (directiva 20/23:
/// enumerar lo que SÍ significa algo y mandar el resto fuera).
#[must_use]
pub fn entorno_solo<I, K, V>(vars: I, permitidas: &[&str]) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    vars.into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .filter(|(k, _)| permitidas.contains(&k.as_str()))
        .collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// El POSITIVO DE CONTROL de la lección (directiva 30/33): cada vector que el
    /// hallazgo Doppler enumeró —los que estaban Y los que FALTABAN en su denylist—
    /// tiene que ser peligroso aquí. Un mutante que borre cualquiera de estos de
    /// `PELIGROSAS` pone roja esta prueba.
    #[test]
    fn denylist_cubre_los_vectores_conocidos() {
        let conocidos = [
            // los que Doppler SÍ tenía
            "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "NODE_OPTIONS",
            "PERL5OPT", "PROMPT_COMMAND", "PATH", "PS1",
            // los que a Doppler le FALTABAN (el corazón del hallazgo)
            "BASH_ENV", "ENV", "LD_AUDIT", "PYTHONPATH", "JAVA_TOOL_OPTIONS",
            "_JAVA_OPTIONS", "CLASSPATH", "RUBYOPT", "RUBYLIB", "GIT_EXTERNAL_DIFF",
            "GLOBIGNORE", "PYTHONSTARTUP",
            // los que cazó la revisión D25 de esta misma fase (completitud, glibc/zsh)
            "GCONV_PATH", "LOCPATH", "NLSPATH", "ZDOTDIR", "FPATH", "LD_PROFILE_OUTPUT",
        ];
        for n in conocidos {
            assert!(es_peligrosa(n), "{n} debe estar en la denylist (vector conocido de RCE)");
        }
    }

    /// El caso ROJO por la vía real (directiva 33): `entorno_saneado` ELIMINA la
    /// peligrosa. Y el control que discrimina "es el NOMBRE, no el valor" —igual que el
    /// oráculo diferencial de Doppler—: una variable BENIGNA con el MISMO valor
    /// sobrevive; la peligrosa con ese valor se va.
    #[test]
    fn saneado_quita_por_nombre_no_por_valor() {
        let entrada = vec![
            ("BASH_ENV", "/tmp/rce.sh"),   // peligrosa → fuera
            ("MI_CONFIG", "/tmp/rce.sh"),  // mismo valor, nombre benigno → se queda
            ("API_KEY", "secreto"),        // benigna → se queda
            ("LD_PRELOAD", "/tmp/x.so"),   // peligrosa → fuera
        ];
        let salida = entorno_saneado(entrada);
        let nombres: Vec<&str> = salida.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!nombres.contains(&"BASH_ENV"), "la peligrosa se elimina");
        assert!(!nombres.contains(&"LD_PRELOAD"), "la peligrosa se elimina");
        assert!(nombres.contains(&"MI_CONFIG"), "mismo valor, nombre benigno: se queda (es el NOMBRE)");
        assert!(nombres.contains(&"API_KEY"), "la benigna se queda");
        assert_eq!(salida.len(), 2);
    }

    /// La allowlist descarta TODO lo no enumerado, peligroso o no.
    #[test]
    fn solo_conserva_lo_permitido() {
        let entrada = vec![
            ("API_KEY", "s"),
            ("BASH_ENV", "/tmp/x"),
            ("OTRA", "v"),
        ];
        let salida = entorno_solo(entrada, &["API_KEY"]);
        assert_eq!(salida, vec![("API_KEY".to_string(), "s".to_string())]);
    }

    #[test]
    fn benignas_no_se_marcan() {
        for n in ["API_KEY", "DATABASE_URL", "MI_CONFIG", "HOME", "USER", "LANG", "_", "X1"] {
            assert!(!es_peligrosa(n), "{n} no debe marcarse peligrosa");
        }
    }

    /// H2 de la revisión D25: las funciones exportadas de bash tienen NOMBRE dinámico
    /// (`BASH_FUNC_<x>%%`), así que ninguna entrada literal las coge — sólo el patrón.
    /// Caso rojo: si `forma_peligrosa` no marcara el prefijo, `BASH_FUNC_ls%%` se colaría
    /// y un `bash -c` del hijo ejecutaría la función inyectada.
    #[test]
    fn funciones_exportadas_de_bash_se_marcan_por_patron() {
        assert!(es_peligrosa("BASH_FUNC_ls%%"), "función exportada de bash con sufijo %%");
        assert!(es_peligrosa("BASH_FUNC_foo"), "el prefijo BASH_FUNC_ basta");
        // Y se ELIMINAN por la vía real (no sólo se detectan).
        let salida = entorno_saneado(vec![
            ("BASH_FUNC_id%%", "() { id; }"),
            ("API_KEY", "s"),
        ]);
        let nombres: Vec<&str> = salida.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(nombres, vec!["API_KEY"], "la función bash se elimina, la config se queda");
    }

    /// Cualquier nombre que NO sea un identificador normal es estructura colada por el
    /// nombre y se descarta (fail-closed). El `%` del sufijo bash cae también por aquí,
    /// además del prefijo.
    #[test]
    fn nombres_no_identificador_se_marcan() {
        for n in ["MI%VAR", "con espacio", "a(b)", "", "1EMPIEZA_CON_DIGITO", "a-b", "a.b"] {
            assert!(es_peligrosa(n), "{n:?} no es identificador → peligroso");
        }
    }

    /// H1 de la revisión D25: `GCONV_PATH` es RCE de glibc (dlopen vía gconv) y estaba
    /// ausente; con sus compañeros de familia. Caso rojo por si alguno se cae de la lista.
    #[test]
    fn vectores_glibc_y_zsh_de_la_revision_estan() {
        for n in ["GCONV_PATH", "LOCPATH", "NLSPATH", "ZDOTDIR", "FPATH", "LD_PROFILE_OUTPUT"] {
            assert!(es_peligrosa(n), "{n} es vector conocido y debe estar");
        }
    }
}
