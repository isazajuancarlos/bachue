// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **Bachué — cadena de esquemas de contraseña + *upgrade* oportunista.**
//!
//! Absorbe lo que hacía `tumbaga` (Python): verificar una contraseña contra un hash
//! guardado **sin saber de antemano con qué algoritmo se hizo**, y —al iniciar sesión,
//! que es el único momento en que se tiene la clave en claro— **migrarlo al esquema de
//! hoy sin que el usuario restablezca nada**.
//!
//! # Las tres reglas que la hacen segura
//!
//! 1. **La ESCRITURA es SIEMPRE Argon2id** (vía [`guaca::claves`], una sola
//!    implementación en el universo). Los esquemas de legado son **verify-only**: se leen
//!    para migrar, nunca se escriben. Por eso `cifrar` no está en el trait.
//! 2. **El hash lleva su esquema DENTRO** (`$argon2id$…`, `$2b$…`), así que la cadena lo
//!    reconoce por su forma; no hay que recordar en la base de datos qué algoritmo era.
//! 3. **El upgrade nunca abarata** un Argon2: esa decisión NO se reimplementa aquí
//!    —la tiene, probada, [`bachue_clave::renovar_si_hace_falta`]— (directiva 1). La cadena
//!    solo la orquesta: un hash de LEGADO siempre migra a Argon2id; un Argon2 se renueva
//!    solo si hoy cuesta más.
//!
//! # Por qué un hash desconocido FALLA RUIDOSO (directiva 20)
//!
//! Si ningún esquema reconoce el hash, [`Cadena::verificar`] devuelve
//! `Err(EsquemaDesconocido)`, **no** «contraseña inválida». Un formato que no se sabe leer
//! es una avería de configuración (un esquema retirado sin migrar, un dato corrupto), no un
//! intento fallido: tratarlo como contraseña mala lo escondería y dejaría a un usuario
//! legítimo fuera sin traza.
//!
//! **LÍMITE HONESTO (integración):** esto solo cubre PREFIJOS desconocidos. Un hash con
//! prefijo conocido (`$argon2…`) pero cuerpo CORRUPTO o TRUNCADO —el caso clásico: una
//! columna dimensionada para bcrypt (`VARCHAR(60)`) que corta el PHC de Argon2id (~97
//! chars) al migrar— se lee como «contraseña incorrecta», no como avería, porque
//! distinguir «truncado» de «no casa» exigiría reimplementar la verificación fuera de
//! guaca (una sola implementación, D1). Mitigación en el LLAMANTE, no aquí: dimensiona la
//! columna para el PHC completo de Argon2id, y trata una oleada de «contraseña
//! incorrecta» JUSTO tras una migración como sospecha de truncamiento, no como usuarios
//! que de golpe olvidaron su clave.

#![forbid(unsafe_code)]

/// Un esquema de hash de contraseña: sabe RECONOCER su formato y VERIFICAR contra él.
/// No expone `cifrar` a propósito — solo el esquema de escritura (Argon2id) produce
/// hashes nuevos; los de legado son de solo lectura.
pub trait EsquemaDeContrasena: Send + Sync {
    /// Nombre corto, para trazas.
    fn nombre(&self) -> &'static str;
    /// ¿Este hash es de este esquema? (por su prefijo, que viaja dentro del hash).
    fn reconoce(&self, hash: &str) -> bool;
    /// ¿La clave casa con el hash? Nunca entra en pánico: un hash ilegible es `false`.
    fn verifica(&self, clave: &str, hash: &str) -> bool;
    /// `true` = de LEGADO: se verifica pero NO se escribe con él, así que un acierto
    /// contra este esquema siempre dispara migración a Argon2id.
    fn solo_lectura(&self) -> bool;
}

/// Argon2id vía guaca — el esquema de ESCRITURA y el moderno de lectura.
struct Argon2id;

impl EsquemaDeContrasena for Argon2id {
    fn nombre(&self) -> &'static str {
        "argon2id"
    }
    fn reconoce(&self, hash: &str) -> bool {
        hash.starts_with("$argon2")
    }
    fn verifica(&self, clave: &str, hash: &str) -> bool {
        guaca::claves::verificar(clave, hash)
    }
    fn solo_lectura(&self) -> bool {
        false
    }
}

/// Lector de LEGADO **bcrypt** (feature `legado`), verify-only. Migra a Argon2id al entrar.
#[cfg(feature = "legado")]
struct Bcrypt;

#[cfg(feature = "legado")]
impl EsquemaDeContrasena for Bcrypt {
    fn nombre(&self) -> &'static str {
        "bcrypt"
    }
    fn reconoce(&self, hash: &str) -> bool {
        hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$")
    }
    fn verifica(&self, clave: &str, hash: &str) -> bool {
        // `bcrypt::verify` falla ante un hash mal formado; eso es `false`, no pánico.
        bcrypt::verify(clave, hash).unwrap_or(false)
    }
    fn solo_lectura(&self) -> bool {
        true
    }
}

/// El resultado de verificar: si la clave casó, y —si hay que reescribir el hash— el
/// nuevo (Argon2id de hoy).
///
/// # Contrato de persistencia (las DOS condiciones, no una)
///
/// El llamante persiste `hash_nuevo`:
/// 1. **SOLO si `valida`** (una clave incorrecta nunca produce un `hash_nuevo` que valga
///    la pena, y este tipo lo garantiza: `hash_nuevo` es `Some` solo cuando `valida`);
/// 2. **y SOLO si el hash guardado sigue siendo el que se verificó** — con un
///    *compare-and-swap*: `UPDATE … SET hash = ? WHERE id = ? AND hash = <el que se
///    pasó a `verificar`>`; **cero filas afectadas ⇒ la contraseña cambió entretanto
///    (otra pestaña, un restablecimiento tras una fuga): NO escribir.**
///
/// La 2.ª condición no es teórica: sin ella, una migración rezagada (la ventana que este
/// crate abre —bcrypt/Argon2 tardan cientos de ms—) reescribe `Argon2(clave_vieja)` encima
/// de `Hash(clave_nueva)` y **revierte en silencio la rotación**. Es el lost-update que
/// `informes` ya aprendió a golpes (`cuentas.rs`, con su test de mutación); vive aquí en la
/// doc porque este crate es el ÚNICO canal de la regla hacia los consumidores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resultado {
    /// ¿La contraseña es correcta?
    pub valida: bool,
    /// Hash al que MIGRAR (persistir con el CAS de arriba), si el guardado era de legado
    /// o estaba caduco. `None` = el guardado ya está al día, o la clave no casó.
    pub hash_nuevo: Option<String>,
}

/// El hash guardado no lo reconoce ningún esquema de la cadena (directiva 20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EsquemaDesconocido;

impl std::fmt::Display for EsquemaDesconocido {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ningún esquema de la cadena reconoce este hash")
    }
}

impl std::error::Error for EsquemaDesconocido {}

/// La cadena de esquemas: reconoce el hash guardado, lo verifica y, al acertar, decide
/// la migración. La ESCRITURA siempre es Argon2id.
pub struct Cadena {
    /// Orden de reconocimiento; `[0]` es Argon2id (el moderno/escritura).
    esquemas: Vec<Box<dyn EsquemaDeContrasena>>,
}

impl Default for Cadena {
    fn default() -> Self {
        Self::nueva()
    }
}

impl Cadena {
    /// La cadena estándar: Argon2id + (con `legado`) bcrypt.
    pub fn nueva() -> Self {
        // `mut` solo se usa con la feature `legado`; sin ella el vec no se muta.
        #[allow(unused_mut)]
        let mut esquemas: Vec<Box<dyn EsquemaDeContrasena>> = vec![Box::new(Argon2id)];
        #[cfg(feature = "legado")]
        esquemas.push(Box::new(Bcrypt));
        Self { esquemas }
    }

    /// Añade un lector de legado a la cadena (extensibilidad: scrypt, pbkdf2, o un
    /// formato propio de un sistema que se está migrando).
    #[must_use]
    pub fn con_lector(mut self, lector: Box<dyn EsquemaDeContrasena>) -> Self {
        // Un lector añadido es SIEMPRE de legado (verify-only): la escritura es Argon2id
        // y punto. Un lector con `solo_lectura()=false` no migraría —caería en la
        // renovación de Argon2 sobre un hash que no es Argon2 → `None`, en silencio—.
        debug_assert!(
            lector.solo_lectura(),
            "con_lector es para esquemas de LEGADO verify-only (solo_lectura()=true)"
        );
        self.esquemas.push(lector);
        self
    }

    /// Cifra una contraseña NUEVA. Siempre Argon2id (vía guaca). `None` solo si el propio
    /// Argon2 falla; el llamante lo trata como fallo, no lo ignora.
    pub fn cifrar(&self, clave: &str) -> Option<String> {
        bachue_clave::hashear(clave)
    }

    /// Verifica `clave` contra `hash` guardado. Reconoce el esquema por la forma del hash;
    /// si ninguno lo reconoce, `Err(EsquemaDesconocido)` (avería, no contraseña mala).
    ///
    /// Al ACERTAR decide la migración: un hash de LEGADO migra siempre a Argon2id; un
    /// Argon2 se renueva solo si hoy cuesta más (regla de [`bachue_clave`], nunca abarata).
    pub fn verificar(&self, clave: &str, hash: &str) -> Result<Resultado, EsquemaDesconocido> {
        let esquema = self
            .esquemas
            .iter()
            .find(|e| e.reconoce(hash))
            .ok_or(EsquemaDesconocido)?;

        let valida = esquema.verifica(clave, hash);
        let hash_nuevo = if !valida {
            None
        } else if esquema.solo_lectura() {
            // Legado que acertó → migrar a Argon2id. Si el hasheo fallara (entropía),
            // `None`: el login entra igual y la migración se reintenta en el próximo.
            self.cifrar(clave)
        } else {
            // Argon2 que acertó → renovar solo si hace falta (nunca abaratar).
            bachue_clave::renovar_si_hace_falta(hash, clave)
        };
        Ok(Resultado { valida, hash_nuevo })
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const BUENA: &str = "contraseña-de-prueba-larga-2026";

    /// Un esquema de LEGADO de juguete, para ejercitar la migración SIN depender de la
    /// feature `legado` (bcrypt): un hash `$fake$<secreto>` casa si `clave == secreto`.
    /// Verify-only, como todo legado.
    struct FalsoLegado;
    impl EsquemaDeContrasena for FalsoLegado {
        fn nombre(&self) -> &'static str {
            "falso-legado"
        }
        fn reconoce(&self, hash: &str) -> bool {
            hash.starts_with("$fake$")
        }
        fn verifica(&self, clave: &str, hash: &str) -> bool {
            hash.strip_prefix("$fake$") == Some(clave)
        }
        fn solo_lectura(&self) -> bool {
            true
        }
    }

    /// Argon2id: la buena entra y no se re-hashea (ya está al día); la mala no entra y no
    /// migra. Pareja discriminante (directiva 33): sin la comprobación de validez, la mala
    /// también «migraría».
    #[test]
    fn argon2id_la_buena_entra_sin_rehash_la_mala_no() {
        let cadena = Cadena::nueva();
        let h = cadena.cifrar(BUENA).expect("hashea");

        let r = cadena.verificar(BUENA, &h).expect("argon2 reconocido");
        assert!(r.valida, "la correcta entra");
        assert_eq!(r.hash_nuevo, None, "un hash recién hecho ya está al día: no re-hashea");

        let r = cadena.verificar("otra-cosa", &h).expect("argon2 reconocido");
        assert!(!r.valida, "la incorrecta no entra");
        assert_eq!(r.hash_nuevo, None, "una clave incorrecta NUNCA produce migración");
    }

    /// **La migración de LEGADO (el aporte de tumbaga), y su pareja.** Un hash de legado
    /// que acierta debe (a) validar y (b) devolver `hash_nuevo` en **Argon2id** que casa
    /// con la MISMA clave. La pareja: con clave mala, ni valida ni migra. Discrimina
    /// (directiva 33): si `solo_lectura()` fuera `false` no habría migración y (a) fallaría;
    /// si se migrara sin comprobar validez, la pareja mala fallaría.
    #[test]
    fn un_hash_de_legado_que_acierta_migra_a_argon2id() {
        let cadena = Cadena::nueva().con_lector(Box::new(FalsoLegado));
        let viejo = format!("$fake${BUENA}");

        let r = cadena.verificar(BUENA, &viejo).expect("legado reconocido");
        assert!(r.valida, "la clave correcta contra el hash de legado entra");
        let nuevo = r.hash_nuevo.expect("un acierto de legado DEBE migrar");
        assert!(nuevo.starts_with("$argon2"), "migra a Argon2id, no a otro legado: {nuevo}");
        // Y el hash migrado sirve: la misma clave entra por el camino moderno, sin migrar de nuevo.
        let r2 = cadena.verificar(BUENA, &nuevo).expect("argon2 reconocido");
        assert!(r2.valida && r2.hash_nuevo.is_none(), "el hash migrado ya está al día");

        // Pareja: clave mala contra el legado — ni entra ni migra.
        let r = cadena.verificar("mala", &viejo).expect("legado reconocido");
        assert!(!r.valida && r.hash_nuevo.is_none(), "legado + clave mala: ni valida ni migra");
    }

    /// Un Argon2 DÉBIL (menos trabajo que el de hoy) se renueva al acertar; y la pareja:
    /// eso delega en `bachue_clave` (nunca abaratar), no se reimplementa aquí.
    #[test]
    fn un_argon2_debil_se_renueva_al_entrar() {
        use argon2::password_hash::{PasswordHasher, SaltString};
        use argon2::{Algorithm, Argon2, Params, Version};

        let salt = SaltString::encode_b64(&[7u8; 16]).expect("salt");
        let debil = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(8, 1, 1, None).unwrap())
            .hash_password(BUENA.as_bytes(), &salt)
            .expect("hash débil")
            .to_string();

        let cadena = Cadena::nueva();
        let r = cadena.verificar(BUENA, &debil).expect("argon2 reconocido");
        assert!(r.valida, "la clave correcta entra aunque el hash sea débil");
        let nuevo = r.hash_nuevo.expect("un Argon2 débil DEBE renovarse");
        assert!(nuevo.starts_with("$argon2"));
        // El renovado ya está al día: no vuelve a renovar.
        let r2 = cadena.verificar(BUENA, &nuevo).expect("argon2 reconocido");
        // EL renovado DEBE verificar con la MISMA clave. Sin este assert, renovar con un
        // secreto equivocado (`renovar(hash, hash)`) pasaría verde —da `hash_nuevo=None`
        // porque `valida` es false— y CADA usuario con Argon2 débil entraría una vez y
        // quedaría fuera para siempre. Caso rojo medido por el concilio (mutante M2).
        assert!(r2.valida, "el hash renovado verifica con la MISMA clave");
        assert_eq!(r2.hash_nuevo, None, "el hash renovado ya está al día");

        // PAREJA (directiva 33): clave MALA contra el MISMO hash débil —el caso donde la
        // renovación SÍ dispararía— no valida NI migra. Sin esta pareja, quitar el guard
        // `!valida` de la rama Argon2 (toma de cuenta: se reescribe el hash al intento del
        // atacante) pasaría verde. Caso rojo medido por el concilio.
        let r = cadena.verificar("clave-incorrecta", &debil).expect("argon2 reconocido");
        assert!(!r.valida, "clave mala contra un hash débil no entra");
        assert_eq!(r.hash_nuevo, None, "clave mala NUNCA produce migración, ni con hash débil");
    }

    /// Un Argon2 MÁS FUERTE que la política de hoy (más trabajo `m×t`) NUNCA se abarata al
    /// entrar. Es la PAREJA de la delegación en `bachue_clave::renovar_si_hace_falta`
    /// (directiva 33): sin ella, reimplementar la renovación como "params ≠ hoy" —el bug
    /// de informes/tumbaga que abarataba 53×— pasaría verde. Caso rojo medido (mutante M1).
    #[test]
    fn un_argon2_mas_fuerte_no_se_abarata_al_entrar() {
        use argon2::password_hash::{PasswordHasher, SaltString};
        use argon2::{Algorithm, Argon2, Params, Version};

        // 64 MiB × 1 = 65536 de trabajo, por encima de la política de hoy, pero con t=1
        // (< el t de hoy): el caso emblemático "más trabajo total pero t menor" que NO se
        // debe rebajar.
        let salt = SaltString::encode_b64(&[9u8; 16]).expect("salt");
        let fuerte = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(65536, 1, 1, None).unwrap())
            .hash_password(BUENA.as_bytes(), &salt)
            .expect("hash fuerte")
            .to_string();

        let cadena = Cadena::nueva();
        let r = cadena.verificar(BUENA, &fuerte).expect("argon2 reconocido");
        assert!(r.valida, "la clave correcta entra");
        assert_eq!(
            r.hash_nuevo, None,
            "un hash MÁS fuerte que hoy NUNCA se abarata (nunca se renueva a la baja)"
        );
    }


    /// Un hash que no reconoce NINGÚN esquema falla RUIDOSO (directiva 20), no como
    /// «contraseña inválida». Pareja: un Argon2 real sí se reconoce.
    #[test]
    fn un_hash_desconocido_falla_ruidoso() {
        let cadena = Cadena::nueva();
        assert_eq!(
            cadena.verificar(BUENA, "no-es-un-hash-conocido"),
            Err(EsquemaDesconocido),
            "un formato desconocido es una avería, no un intento fallido"
        );
        let h = cadena.cifrar(BUENA).expect("hashea");
        assert!(cadena.verificar(BUENA, &h).is_ok(), "un Argon2 real sí se reconoce");
    }

    /// bcrypt REAL de punta a punta (directiva 28), solo con la feature `legado`: un hash
    /// bcrypt verifica y migra a Argon2id; la pareja mala no.
    #[cfg(feature = "legado")]
    #[test]
    fn bcrypt_real_verifica_y_migra() {
        let h = bcrypt::hash(BUENA, 4).expect("bcrypt hash (coste bajo para la prueba)");
        assert!(h.starts_with("$2"), "es un hash bcrypt: {h}");
        let cadena = Cadena::nueva();

        let r = cadena.verificar(BUENA, &h).expect("bcrypt reconocido");
        assert!(r.valida, "bcrypt correcto entra");
        let nuevo = r.hash_nuevo.expect("bcrypt es legado: migra");
        assert!(nuevo.starts_with("$argon2"), "migra a Argon2id");

        let r = cadena.verificar("mala", &h).expect("bcrypt reconocido");
        assert!(!r.valida && r.hash_nuevo.is_none(), "bcrypt + clave mala: ni valida ni migra");
    }
}
