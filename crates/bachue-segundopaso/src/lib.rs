// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **Bachué F3.a — el segundo paso del login (segundo factor).**
//!
//! Tras la contraseña correcta (F1), quien entra presenta un código: un TOTP de seis
//! dígitos o uno de los códigos de recuperación de un solo uso. Este módulo decide CUÁL
//! de los dos es, comprueba el que toca, y devuelve un veredicto UNIFICADO que le dice al
//! servicio dos cosas: si abre, y si el intento cuenta para el freno.
//!
//! No reimplementa ninguna de las dos comprobaciones: el TOTP con su anti-replay lo hace
//! [`guaca::dosfactores`], y el hash Argon2 de los códigos de recuperación,
//! [`guaca::claves`]. Aquí vive el FLUJO que hoy medico e informes reescriben, y —lo que
//! importa— la decisión de qué cuenta como fallo, que es donde se pierde la seguridad si
//! se colapsa.
//!
//! # La lección que este módulo encarna (directiva 20 y 33)
//!
//! **No todo "no abrió" es un fallo del usuario.** guaca::dosfactores distingue CUATRO
//! estados a propósito, y este módulo los conserva porque colapsarlos a un `bool`
//! (abrió / no abrió) borra la diferencia que decide si a alguien se le cobra un fallo:
//!
//! - un TOTP **incorrecto** es un fallo → CUENTA para el freno;
//! - un TOTP **reutilizado** (un código bueno reenviado) es señal de repetición →
//!   cuenta, pero se nombra aparte para que un ataque de replay no se esconda entre
//!   dedazos;
//! - un secreto **ilegible** (base32 corrupta, columna truncada, descifrado que devolvió
//!   basura) NO dice nada del código que se tecleó → **no** cuenta: cobrar un fallo por
//!   una avería del servidor bloquearía a un usuario legítimo por algo que él no hizo.
//!
//! Si [`Resolucion::cuenta_como_fallo`] se escribiera como `!abre()`, el tercer caso se
//! cobraría igual que el primero. La pareja de pruebas de este módulo lo caza.
//!
//! # Lo que NO orquesta, y por qué
//!
//! El **freno** en sí (¿está esta cuenta bloqueada ahora mismo?) lo evalúa el servicio
//! con [`guaca::freno`] ANTES de llamar aquí, con la misma tabla de intentos que el
//! primer factor — este módulo solo dice si el intento SUMA a esa tabla. Y el token
//! `PendienteSegundoFactor` que prueba que el primer factor pasó lo verifica
//! `bachue_sesion`; la fachada `bachue` muestra el flujo completo compuesto. Aquí se
//! comprueba el factor y nada más: un módulo sin estado, que recibe las filas y decide.
//!
//! # El contrato con el servicio — la seguridad que queda de TU lado
//!
//! Sin estado significa que tres invariantes viven en el llamante, no aquí. Se escriben
//! como REQUISITO y no como nota (la revisión de F3.a los señaló como el punto más
//! cargado del módulo, y son justo la clase de contrato que divergió en las copias de
//! medico/informes que este universo de librerías existe para cerrar):
//!
//! 1. **El anti-replay de los códigos de recuperación es TUYO.** El TOTP lleva su
//!    segunda línea dentro del primitivo —un código reenviado cae en `Reutilizado`
//!    aunque te equivoques—; la recuperación NO tiene equivalente. La propiedad de un
//!    solo uso descansa entera en dos acciones tuyas, y fallar cualquiera abre un replay
//!    que nada aquí ni en guaca señala:
//!    - pasa en `hashes_recuperacion` **solo los códigos vivos** (uno ya gastado casa y
//!      abre de nuevo);
//!    - ante [`Resolucion::SuperadoRecuperacion`], retira el código de ese `indice`
//!      **contra la misma lista que pasaste, sin reordenar ni reconsultar** (retirar por
//!      otro orden invalida el código equivocado y deja vivo el usado), y hazlo
//!      **atómico respecto de la comprobación** —es el mismo fallo que guaca cerró para
//!      el contador TOTP: quemarlo en una sentencia aparte abrió tres sesiones con un
//!      código en informes—.
//! 2. **Empareja el enrolamiento con el usuario autenticado.** [`segundo_paso`] recibe un
//!    [`Enrolamiento`] suelto; nada ata ese secreto y esos hashes al `usuario_id` del
//!    token `PendienteSegundoFactor`. Carga el enrolamiento del **mismo** usuario que
//!    porta el pendiente: el segundo factor es tan bueno como ese emparejamiento.
//! 3. **Persiste el contador en el éxito TOTP.** [`Resolucion::SuperadoTotp`] trae el
//!    `contador` a guardar; sin guardarlo, el mismo código vuelve a valer.

#![forbid(unsafe_code)]

use guaca::dosfactores::Veredicto;

/// Lo que el servicio trae de su base para comprobar el segundo factor de una cuenta.
///
/// Referencias prestadas, no propias: este módulo no guarda nada. El `secreto_totp_b32`
/// llega **ya descifrado** (el servicio lo saca de reposo con [`guaca::reposo`]); los
/// `hashes_recuperacion` son los Argon2 de los códigos que aún no se han gastado.
pub struct Enrolamiento<'a> {
    /// El secreto TOTP en base32, tal como lo enrola [`guaca::dosfactores::generar_secreto`].
    pub secreto_totp_b32: &'a str,
    /// El contador de la última verificación TOTP buena de ESTA cuenta, o `None` si aún
    /// no hubo ninguna. Es lo único que sostiene el anti-replay del TOTP.
    pub ultimo_contador: Option<u64>,
    /// Los hashes Argon2 de los códigos de recuperación que SIGUEN vivos (los gastados no
    /// se pasan: un código de un solo uso se retira invalidándolo tras usarlo). El orden
    /// es el que el servicio decida; el índice devuelto en [`Resolucion::SuperadoRecuperacion`]
    /// apunta a ESTE arreglo.
    pub hashes_recuperacion: &'a [String],
}

/// El veredicto UNIFICADO del segundo paso. Cinco estados, no dos: ver la cabecera del
/// módulo. Un solo `bool` aquí sería la directiva 20 al revés —sustituir la ausencia de
/// un dato (¿por qué no abrió?) por un valor pobre—.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolucion {
    /// TOTP correcto. El servicio emite la sesión plena y **guarda este `contador`** como
    /// nuevo último contador (sin eso, el mismo código vuelve a valer y el anti-replay no
    /// existe).
    SuperadoTotp { contador: u64 },
    /// Un código de recuperación casó. El servicio emite la sesión plena y **retira el
    /// código de este `indice`** (un solo uso). `indice` apunta a `hashes_recuperacion`.
    SuperadoRecuperacion { indice: usize },
    /// El código no corresponde: TOTP de ninguna ventana admitida, o código con forma de
    /// recuperación que no casa con ninguno vivo. Es un fallo y CUENTA para el freno.
    Rechazado,
    /// El TOTP era bueno y ya se había gastado (contador que no avanza). No abre; cuenta
    /// aparte para que un replay no se esconda entre los `Rechazado`.
    Reutilizado,
    /// El secreto TOTP no se pudo interpretar. No dice nada del código: **no** abre y
    /// **no** cuenta para el freno. Es una avería del servidor, no un intento fallido.
    NoComprobable,
}

impl Resolucion {
    /// ¿Se supera el segundo paso? Solo los dos `Superado*`. Todo lo demás, no.
    pub fn abre(&self) -> bool {
        matches!(self, Resolucion::SuperadoTotp { .. } | Resolucion::SuperadoRecuperacion { .. })
    }

    /// ¿Suma este intento a la tabla de fallos del freno? **`Rechazado` y `Reutilizado`
    /// sí; `NoComprobable` NO** (avería del servidor), y los `Superado*` tampoco. Está
    /// escrito enumerando lo que SÍ cuenta —no como `!abre()`— precisamente para que
    /// `NoComprobable` no caiga del lado equivocado (directiva 23).
    pub fn cuenta_como_fallo(&self) -> bool {
        matches!(self, Resolucion::Rechazado | Resolucion::Reutilizado)
    }
}

/// **Comprueba el segundo factor: enruta a TOTP o a recuperación según la FORMA del
/// código, comprueba el que toca, y unifica el veredicto.**
///
/// El enrutado lo decide [`guaca::dosfactores::parece_codigo_de_recuperacion`] (ocho-guion-ocho),
/// no la longitud "cualquier cosa que no sean seis dígitos": un tecleado con forma de
/// recuperación se comprueba contra los códigos de recuperación; cualquier otra cosa, como
/// TOTP. Así un código de recuperación no se ensaya nunca por la vía TOTP ni al revés.
///
/// `ahora_unix` son segundos desde época (el servicio los pasa; no se leen aquí, para que
/// la comprobación sea determinista y probable). No hay camino que abra sin casar la pieza
/// correcta: ante la duda, [`Resolucion::Rechazado`].
pub fn segundo_paso(enrolamiento: &Enrolamiento, tecleado: &str, ahora_unix: u64) -> Resolucion {
    if guaca::dosfactores::parece_codigo_de_recuperacion(tecleado) {
        return por_recuperacion(enrolamiento.hashes_recuperacion, tecleado);
    }
    match guaca::dosfactores::verificar(
        enrolamiento.secreto_totp_b32,
        tecleado,
        ahora_unix,
        enrolamiento.ultimo_contador,
    ) {
        Veredicto::Correcto { contador } => Resolucion::SuperadoTotp { contador },
        Veredicto::Incorrecto => Resolucion::Rechazado,
        Veredicto::Reutilizado => Resolucion::Reutilizado,
        Veredicto::SecretoIlegible => Resolucion::NoComprobable,
    }
}

/// Comprueba un tecleado con forma de recuperación contra los hashes vivos. El PRIMERO
/// que casa gana; su índice se devuelve para que el servicio lo retire.
///
/// Se detiene en el primer acierto en vez de comparar contra todos: cada comparación es
/// un Argon2 (~decenas de ms), y este es el segundo paso —quien llega ya pasó la
/// contraseña y está bajo el freno—, así que el timing de "cuántos códigos quedan" no es
/// un oráculo que valga los cientos de ms por intento que costaría cerrarlo (directiva 18:
/// la restricción se prueba contra la operación normal, no solo contra el atacante).
fn por_recuperacion(hashes: &[String], tecleado: &str) -> Resolucion {
    let t = tecleado.trim();
    for (indice, hash) in hashes.iter().enumerate() {
        if guaca::claves::verificar(t, hash) {
            return Resolucion::SuperadoRecuperacion { indice };
        }
    }
    Resolucion::Rechazado
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use guaca::dosfactores::{generar_codigos_recuperacion, generar_secreto};

    /// Un secreto TOTP fijo y una función para producir el código de una ventana, para
    /// que las pruebas no dependan del azar ni del reloj.
    const SECRETO: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    /// El código TOTP válido en el instante `ahora_unix`, calculado con el MISMO secreto,
    /// leyendo de guaca (no fabricado a mano: un control fabricado por fuera coincide con
    /// la medición en un valor que la librería quizá nunca produce, directiva 33).
    fn totp_en(ahora_unix: u64) -> String {
        // guaca no expone "genera el código", solo "verifica"; se busca por reflexión el
        // de la ventana probando los diez mil posibles contra el propio verificador. Es un
        // arnés de prueba, no producción: caro pero honesto (usa el código MEDIDO).
        for n in 0..1_000_000u32 {
            let intento = format!("{n:06}");
            if matches!(
                guaca::dosfactores::verificar(SECRETO, &intento, ahora_unix, None),
                Veredicto::Correcto { .. }
            ) {
                return intento;
            }
        }
        unreachable!("alguno de los seis dígitos casa la ventana");
    }

    /// **EL EDGE (directiva 33): los cuatro caminos del TOTP se distinguen, y en
    /// particular el que NO cuenta para el freno.** Correcto abre y no cuenta; incorrecto
    /// no abre y cuenta; reutilizado no abre y cuenta; secreto ilegible no abre y NO
    /// cuenta. Sin el último caso, `cuenta_como_fallo` escrito como `!abre()` pasaría todo
    /// lo demás y solo este se pondría rojo — que es justo su razón de ser.
    #[test]
    fn los_cuatro_caminos_del_totp_se_distinguen() {
        let ahora = 1_770_000_030;
        let codigo = totp_en(ahora);

        // CORRECTO: abre, trae el contador, no cuenta como fallo.
        let e = Enrolamiento { secreto_totp_b32: SECRETO, ultimo_contador: None, hashes_recuperacion: &[] };
        let r = segundo_paso(&e, &codigo, ahora);
        assert!(matches!(r, Resolucion::SuperadoTotp { .. }), "el código de ahora abre: {r:?}");
        assert!(r.abre() && !r.cuenta_como_fallo());

        // REUTILIZADO: el mismo código con el contador ya avanzado a esa ventana. No abre,
        // pero cuenta (replay).
        let Resolucion::SuperadoTotp { contador } = r else { unreachable!() };
        let e2 = Enrolamiento { secreto_totp_b32: SECRETO, ultimo_contador: Some(contador), hashes_recuperacion: &[] };
        let r2 = segundo_paso(&e2, &codigo, ahora);
        assert_eq!(r2, Resolucion::Reutilizado, "un código ya gastado no vuelve a abrir");
        assert!(!r2.abre() && r2.cuenta_como_fallo());

        // INCORRECTO: seis dígitos que no son el de la ventana. No abre, cuenta.
        let malo = if codigo == "000000" { "999999" } else { "000000" };
        let r3 = segundo_paso(&e, malo, ahora);
        assert_eq!(r3, Resolucion::Rechazado);
        assert!(!r3.abre() && r3.cuenta_como_fallo());

        // NO COMPROBABLE: secreto ilegible. No abre y —el edge— NO cuenta para el freno.
        let roto = Enrolamiento { secreto_totp_b32: "!!!no-es-base32!!!", ultimo_contador: None, hashes_recuperacion: &[] };
        let r4 = segundo_paso(&roto, &codigo, ahora);
        assert_eq!(r4, Resolucion::NoComprobable);
        assert!(!r4.abre() && !r4.cuenta_como_fallo(), "una avería del servidor NO se le cobra al usuario");
    }

    /// Un código de recuperación válido abre por SU vía y devuelve su índice; uno
    /// inventado con la misma forma no abre. Su pareja: el mismo código de recuperación NO
    /// se ensaya como TOTP (forma distinta → ruta distinta), y un TOTP no se ensaya como
    /// recuperación.
    #[test]
    fn un_codigo_de_recuperacion_abre_por_su_via_y_da_su_indice() {
        let codigos = generar_codigos_recuperacion(3);
        let hashes: Vec<String> =
            codigos.iter().map(|c| guaca::claves::hashear(c).expect("hashea")).collect();

        // El segundo código de la lista abre, y su índice es 1.
        let e = Enrolamiento { secreto_totp_b32: SECRETO, ultimo_contador: None, hashes_recuperacion: &hashes };
        let r = segundo_paso(&e, &codigos[1], 1_770_000_030);
        assert_eq!(r, Resolucion::SuperadoRecuperacion { indice: 1 });
        assert!(r.abre() && !r.cuenta_como_fallo());

        // Uno con la MISMA forma (8-8) pero que no casa: rechazado, no abre.
        let falso = "AAAAAAAA-BBBBBBBB";
        assert!(guaca::dosfactores::parece_codigo_de_recuperacion(falso), "el arnés usa forma válida");
        assert_eq!(segundo_paso(&e, falso, 1_770_000_030), Resolucion::Rechazado);
    }

    /// **La pareja de enrutado (directiva 33): la forma decide la vía, no el contenido.**
    /// Un código de recuperación presentado cuando la cuenta lo tiene NO se cuela por la
    /// ruta TOTP (no son seis dígitos), y un TOTP de seis dígitos no toca la lista de
    /// recuperación aunque esté poblada. Sin esto, un cambio que enrutara por longitud
    /// abriría puertas cruzadas.
    #[test]
    fn la_forma_del_codigo_decide_la_via() {
        let codigos = generar_codigos_recuperacion(2);
        let hashes: Vec<String> =
            codigos.iter().map(|c| guaca::claves::hashear(c).expect("hashea")).collect();
        let e = Enrolamiento { secreto_totp_b32: SECRETO, ultimo_contador: None, hashes_recuperacion: &hashes };

        // Un TOTP correcto abre por TOTP aun con recuperación poblada.
        let ahora = 1_770_000_030;
        let codigo = totp_en(ahora);
        assert!(matches!(segundo_paso(&e, &codigo, ahora), Resolucion::SuperadoTotp { .. }));

        // Un código de recuperación (forma 8-8) NO se ensaya como TOTP: va a su lista.
        assert!(!guaca::dosfactores::parece_codigo_de_recuperacion(&codigo), "un TOTP no tiene forma de recuperación");
        assert!(guaca::dosfactores::parece_codigo_de_recuperacion(&codigos[0]));
        assert_eq!(segundo_paso(&e, &codigos[0], ahora), Resolucion::SuperadoRecuperacion { indice: 0 });
    }

    /// Sin códigos de recuperación vivos, uno con forma de recuperación se rechaza (no
    /// hay contra qué casar) — no cae por error a la ruta TOTP ni entra en pánico.
    #[test]
    fn sin_codigos_vivos_una_recuperacion_se_rechaza() {
        let e = Enrolamiento { secreto_totp_b32: SECRETO, ultimo_contador: None, hashes_recuperacion: &[] };
        assert_eq!(segundo_paso(&e, "AAAAAAAA-BBBBBBBB", 1_770_000_030), Resolucion::Rechazado);
    }

    /// El secreto que genera guaca es apto para el flujo (no un valor de laboratorio):
    /// enrolar-comprobar de punta a punta con un secreto REAL recién generado.
    #[test]
    fn un_secreto_recien_generado_de_guaca_funciona_de_punta_a_punta() {
        let secreto = generar_secreto();
        let ahora = 1_770_000_090;
        // Busca el código de la ventana con ese secreto real.
        let codigo = (0..1_000_000u32)
            .map(|n| format!("{n:06}"))
            .find(|c| matches!(guaca::dosfactores::verificar(&secreto, c, ahora, None), Veredicto::Correcto { .. }))
            .expect("alguno casa");
        let e = Enrolamiento { secreto_totp_b32: &secreto, ultimo_contador: None, hashes_recuperacion: &[] };
        assert!(segundo_paso(&e, &codigo, ahora).abre());
    }
}
