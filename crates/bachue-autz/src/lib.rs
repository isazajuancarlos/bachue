// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **Bachué — el motor ÚNICO de autorización.**
//!
//! Es el corazón del proyecto (F0 del plan, `conocimiento/proyectos/identidad/`).
//! No es "otra librería de auth": cada decisión de este archivo está anclada a un
//! MODO DE FALLO REAL que documentamos rompiendo o refutando IdP maduros (el corpus
//! `conocimiento/objetivos/`). Se generaliza el patrón ya probado en producción de
//! `informes::autz` (el alcance ES el `WHERE`, no un filtro opcional) y
//! `medico::auth` (capacidad + extractor que no compila sin el actor).
//!
//! # Las invariantes, y de qué objetivo salió cada una
//!
//! - **UNA sola puerta** ([`autorizar`]). Todo camino —HTTP, WebSocket, batch, push—
//!   la usa; está PROHIBIDO por diseño un segundo cálculo de "quién puede". *Discourse:
//!   el gate HTTP (`post_create_allowed`) y la audiencia del push (`secure_group_ids`)
//!   divergieron, y un usuario `readonly` recibía por MessageBus lo que la API le negaba.*
//! - **Se autoriza contra el DUEÑO DEL RECURSO**, nunca contra el contexto del
//!   llamante. *Zitadel: pasar la org del llamante en vez de la del recurso al chequeo
//!   de permiso rompió el aislamiento de tenant (IDOR cross-tenant); un permiso de org
//!   colapsaba a "global" y el id de la víctima nunca se comparaba.*
//! - **Fail-closed, y sin `Actor` no se puede ni invocar.** El tipo obliga a pasar el
//!   principal; no hay camino que llegue a la decisión sin actor en contexto. *Authentik:
//!   el import de blueprints instanciaba los validadores SIN `request`, y los
//!   `if not request: return` se saltaban la comprobación. midPoint: un controlador REST
//!   alcanzaba `runPrivileged` sin authz previa.*
//! - **El permiso es ACCIÓN + ÁMBITO, no un rol crudo.** *Grafana: el gate correcto es
//!   `authorize(EvalPermission(action, scope))`; un rol suelto sobre un recurso sensible
//!   es la puerta que se olvida.*
//! - **"No alcanza nada" es un VALOR, no la ausencia de uno.** No hay `Option` que
//!   alguien desenvuelva con `unwrap_or(todo)`: para un recurso es un `Negado` explícito,
//!   y para un listado es [`AlcanceEfectivo::Ninguno`]. *informes::autz: un alcance
//!   `Ninguna` explícito, no un hueco.*
//!
//! # Dos formas de preguntar, una sola fuente de verdad
//!
//! Las concesiones del actor responden a DOS preguntas, y las dos viven aquí para que no
//! diverjan (la lección Discourse: una sola puerta):
//! - por UN recurso cuyo dueño se conoce → [`autorizar`] (sí/no), y su variante con la
//!   segunda dimensión de habilitación-por-tenant → [`autorizar_habilitado`];
//! - por el alcance TOTAL de un LISTADO → [`alcance_de`] devuelve un [`AlcanceEfectivo`]
//!   que el consumidor materializa en el `WHERE` (el patrón informes: el alcance ES la
//!   consulta, no un filtro que se aplica fila por fila después de leer de más).
//! - Las concesiones del actor se leen **frescas de la fuente de verdad**, nunca de la
//!   sesión. *Un rol dentro de la cookie sobrevive a que un administrador lo revoque;
//!   entonces revocarlo no revoca nada.* (Se enforza en la capa de sesión; aquí el
//!   `Actor` se construye por petición, no se serializa.)
//!
//! # El principio rector, y qué entra al núcleo (estudio de los frameworks maduros, 2026-08-30)
//!
//! La superpotencia de este motor es **"el alcance ES el WHERE"**: la decisión de un
//! listado se materializa en una cláusula de consulta sobre CONJUNTOS de ámbitos, no en un
//! filtro fila por fila. Ese es el filtro para TODO concepto nuevo, y sale de estudiar
//! Zanzibar/SpiceDB, Cedar, OpenFGA, Casbin y Oso: **¿se expresa como unión / intersección
//! / resta de conjuntos de ámbitos que terminan en un WHERE?** Si sí, entra; si obliga a
//! evaluar en memoria o con predicados arbitrarios, va al borde o se descarta.
//!
//! **Ya soportado, sin código extra — porque el ámbito `A` es genérico y lo materializa el
//! consumidor:**
//! - **igualdad** (`WHERE duenio = ?`), el caso base;
//! - **relación N:M / ReBAC** (`WHERE EXISTS (…)`): el `Tercero↔stakeholder` de informes es
//!   esto — "puede ver X si participa en una relación con X", no "es dueño de X". El motor
//!   da el ámbito; el consumidor lo une a su tabla. Un salto que resuelve a un CONJUNTO, sí;
//!   grafo recursivo distribuido (Zanzibar completo), no —rompería la materialización—;
//! - **jerarquía de tenants** (`WHERE path LIKE 'inst_X/%'`, closure table): un ámbito que
//!   contiene a otros (org→sedes) se materializa como prefijo de ruta. El motor no necesita
//!   conocer el árbol.
//!
//! **Incorporado al núcleo:** el **deny-override acotado** ([`Prohibicion`]): la retracción
//! de un permiso válido (suspensión, bloqueo, confidencial) que el fail-closed no cubría.
//! Scope-shaped (un `Alcance`, no un predicado) para que los listados sigan siendo
//! "permitido − denegado" ([`AlcanceEfectivo::TodoExcepto`]). Y el **404-no-oráculo**
//! ([`autorizar_visible`] → [`Veredicto`]): negar OCULTANDO (404) vs MOSTRANDO (403), para no
//! filtrar la existencia de un recurso ajeno — la lección de `medico::aislamiento`, elevada
//! al motor como informes elevó el alcance-como-consulta.
//!
//! **Extensión con el hueco diseñado, no construida (falta un caso real):** condiciones
//! sobre un ATRIBUTO DEL RECURSO que se pliegan al WHERE (`estado = 'publicado'`, `fecha <
//! embargo`) — modeladas como condiciones tipadas y enumeradas, jamás un lenguaje abierto.
//!
//! **Fuera del núcleo a propósito, con motivo:** un DSL de políticas (`forbid … unless` de
//! Cedar, Rego, Polar) —construiría un lenguaje con su superficie de validación; el
//! allow-monótono + deny-acotado es *auditable y materializable*, y eso es la feature—;
//! el ABAC de ENTORNO (hora, IP) —no se materializa en un WHERE: va en el borde, como
//! middleware—; y los zookies/tokens de consistencia de Zanzibar —resuelven un caché global
//! desincronizado que una SQLite-por-instancia con consistencia fuerte no tiene—.

#![forbid(unsafe_code)]

/// A qué recursos alcanza una concesión del actor.
///
/// `Todo` es la autoridad global (administración/supervisión). `De(ambito)` es un
/// tenant concreto. No hay un tercer estado implícito: un actor sin ninguna concesión
/// no alcanza nada (fail-closed), y eso es un hecho del conjunto vacío, no un valor
/// especial que haya que recordar poner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Alcance<A> {
    /// Cualquier dueño. Solo para autoridades globales.
    Todo,
    /// Solo los recursos cuyo dueño es exactamente este ámbito.
    De(A),
}

/// El DUEÑO de un recurso: contra esto se autoriza (nunca contra el llamante).
///
/// `Publico` es EXPLÍCITO: un recurso sin dueño (p. ej. un aviso de portada). No es
/// la ausencia de dueño colada por un `Option`; es una decisión que el llamante
/// declara al construir el recurso, para que "público" no sea nunca un descuido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Duenio<A> {
    /// Pertenece a este ámbito/tenant/usuario.
    De(A),
    /// No tiene dueño: lo alcanza cualquiera que posea la acción en algún sitio.
    Publico,
}

/// Una concesión: el actor PUEDE `accion` sobre los recursos de `alcance`.
///
/// El permiso es la pareja (acción, ámbito), no un rol (lección Grafana). Un rol del
/// dominio se traduce a un conjunto de `Concesion` al construir el [`Actor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Concesion<A, Ac> {
    pub accion: Ac,
    pub alcance: Alcance<A>,
}

/// Una PROHIBICIÓN: el actor NO puede `accion` sobre los recursos de `alcance`, **aunque
/// una concesión se lo diera**. Gana sobre cualquier concesión (deny-override).
///
/// # Qué cubre que el fail-closed NO
///
/// El fail-closed cubre la AUSENCIA de permiso (sin concesión → negado). La prohibición
/// cubre la **retracción** de un permiso por lo demás válido, que es otra cosa: un usuario
/// **suspendido** o bajo **bloqueo legal** que conserva sus concesiones pero debe quedar
/// cortado ya, sin desmontarlas una por una; un recurso **confidencial** que nadie ve
/// aunque su tenant case. Es la lección de Cedar/Casbin (deny gana), acotada al modelo de
/// Bachué.
///
/// # Por qué lleva un `Alcance`, no un predicado (scope-shaped a propósito)
///
/// Una prohibición es un `Alcance`, igual que una concesión —no una condición arbitraria—.
/// Así los listados siguen siendo calculables como CONJUNTOS: `alcance_de` resta el
/// denegado del permitido ([`AlcanceEfectivo::TodoExcepto`] cuando el permitido es global).
/// Un predicado abierto (hora, IP, `cuando x > y`) convertiría el motor en un lenguaje de
/// políticas —con su superficie de validación y su riesgo—; eso queda FUERA del núcleo (ver
/// la cabecera del módulo, "el principio rector").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prohibicion<A, Ac> {
    pub accion: Ac,
    pub alcance: Alcance<A>,
}

/// Quién pide. Se construye POR PETICIÓN desde la fuente de verdad (nunca desde la
/// cookie), con las concesiones ya resueltas. Sin un `Actor` no se puede llamar a
/// [`autorizar`]: esa es la garantía de tipo de que ningún camino decide sin principal.
#[derive(Debug, Clone)]
pub struct Actor<A, Ac> {
    /// Identidad del principal (para la bitácora; la decisión NO depende de él salvo
    /// vía las concesiones).
    pub id: i64,
    concesiones: Vec<Concesion<A, Ac>>,
    prohibiciones: Vec<Prohibicion<A, Ac>>,
}

impl<A, Ac> Actor<A, Ac> {
    /// Un actor con sus concesiones ya resueltas y SIN prohibiciones. El constructor es el
    /// ÚNICO camino: no hay `Actor` "a medio construir" al que le falte resolver permisos.
    pub fn nuevo(id: i64, concesiones: Vec<Concesion<A, Ac>>) -> Self {
        Self { id, concesiones, prohibiciones: Vec::new() }
    }

    /// Un actor SIN ninguna concesión: no alcanza nada. Existe para que "sin permisos"
    /// sea un valor construible y probado, no un caso que se olvide.
    pub fn sin_permisos(id: i64) -> Self {
        Self { id, concesiones: Vec::new(), prohibiciones: Vec::new() }
    }

    /// Añade PROHIBICIONES (deny-override) a un actor. Encadenable sobre [`Actor::nuevo`].
    /// Se toman aparte de las concesiones a propósito: una prohibición no es "una concesión
    /// negativa" que alguien pueda mezclar en la misma lista y perder de vista; es una
    /// dimensión distinta que GANA, y el tipo la mantiene visible.
    #[must_use]
    pub fn con_prohibiciones(mut self, prohibiciones: Vec<Prohibicion<A, Ac>>) -> Self {
        self.prohibiciones = prohibiciones;
        self
    }

    /// Las concesiones (solo lectura): la decisión se toma en [`autorizar`], no
    /// dejando que un llamante inspeccione y decida por su cuenta (una sola puerta).
    pub fn concesiones(&self) -> &[Concesion<A, Ac>] {
        &self.concesiones
    }
}

/// El veredicto. `Negado` lleva el motivo para la bitácora, nunca para relajarse:
/// no existe `From<Negado>` a nada permisivo, ni un `unwrap_or(Permitido)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Permitido,
    Negado(Motivo),
}

/// Por qué se negó. Es diagnóstico; el `Display` es para el log, no para el cliente
/// (a quien se le responde de forma uniforme, sin decir si el recurso existe).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Motivo {
    /// El actor no tiene ninguna concesión de esa acción sobre ese dueño.
    SinConcesion,
    /// El actor SÍ tiene la concesión, pero el TENANT dueño del recurso no tiene
    /// habilitado el módulo que la acción requiere (la segunda dimensión, ortogonal al
    /// permiso: `medico` la trata distinto —el equivalente a un 503/403 con el módulo que
    /// abriría, no un 404—, por eso es un motivo aparte y no se confunde con `SinConcesion`).
    ModuloNoHabilitado,
    /// Una PROHIBICIÓN explícita cubre este recurso: el actor tenía la concesión, pero un
    /// deny la retrae (suspensión, bloqueo, confidencial). Se nombra aparte de `SinConcesion`
    /// porque se corrige en otro sitio —levantar la prohibición, no dar el permiso— y porque
    /// distingue "nunca pudo" de "podía y se le quitó".
    Prohibido,
}

impl Decision {
    /// ¿Permitido? Método explícito para el sitio de llamada; no hay conversión
    /// implícita a `bool` que se cuele en un `if` mal escrito.
    pub fn permitido(&self) -> bool {
        matches!(self, Decision::Permitido)
    }
}

impl<A> Alcance<A>
where
    A: PartialEq,
{
    /// ¿Este alcance cubre a ESTE dueño de recurso? Aquí vive la lección Zitadel:
    /// `De(a)` cubre solo `Duenio::De(a)` con `a` idéntico —jamás colapsa a global—;
    /// un `Publico` lo cubre cualquier alcance (basta poseer la acción).
    fn cubre(&self, duenio: &Duenio<A>) -> bool {
        match (self, duenio) {
            (Alcance::Todo, _) => true,
            (Alcance::De(_), Duenio::Publico) => true,
            (Alcance::De(a), Duenio::De(d)) => a == d,
        }
    }

    /// ¿Este alcance, usado como PROHIBICIÓN, alcanza a este dueño? Es como [`cubre`] SALVO
    /// en lo público: una prohibición `De(a)` **NO** apaga `Publico`. La asimetría es
    /// deliberada y es lo contrario de una concesión: conceder en A da lo público (lo ve
    /// cualquiera con la acción en algún sitio), pero PROHIBIR en A no debe apagar los
    /// recursos sin dueño —ocultar un confidencial de A no debería tumbar los avisos de
    /// portada—. Solo una prohibición GLOBAL (`Todo`) apaga también lo público.
    fn prohibe(&self, duenio: &Duenio<A>) -> bool {
        match (self, duenio) {
            (Alcance::Todo, _) => true,
            (Alcance::De(_), Duenio::Publico) => false,
            (Alcance::De(a), Duenio::De(d)) => a == d,
        }
    }
}

/// **LA ÚNICA PUERTA.** Devuelve `Permitido` sii el actor tiene ALGUNA concesión de
/// `accion` cuyo alcance cubra al dueño del recurso. Todo lo demás es `Negado`
/// (fail-closed). No hay parámetro que la relaje ni camino que la evite.
///
/// Se autoriza contra `duenio` —el dueño del RECURSO—, que el llamante resuelve del
/// id del recurso, nunca de su propio contexto (Zitadel). Como `actor` es obligatorio
/// y por referencia, no existe forma de invocarla "sin actor" (Authentik/midPoint).
///
/// **Una PROHIBICIÓN gana sobre cualquier concesión** (deny-override): se miran las
/// prohibiciones PRIMERO, y si alguna cubre al dueño, `Negado(Prohibido)` sin mirar los
/// permisos. Es más estricto que solo-allow: el deny solo puede NEGAR donde el allow
/// permitiría, nunca conceder — así la lección Zitadel (un permiso de A no alcanza B) queda
/// intacta bajo la nueva dimensión.
pub fn autorizar<A, Ac>(actor: &Actor<A, Ac>, accion: &Ac, duenio: &Duenio<A>) -> Decision
where
    A: PartialEq,
    Ac: PartialEq,
{
    // Deny-override: una prohibición que alcanza al dueño gana, antes de mirar las
    // concesiones. Usa `prohibe`, no `cubre`: una prohibición `De(A)` NO apaga lo `Publico`
    // (prohibir en un ámbito no tumba los recursos sin dueño); solo un deny global lo hace.
    let prohibido = actor
        .prohibiciones
        .iter()
        .any(|p| p.accion == *accion && p.alcance.prohibe(duenio));
    if prohibido {
        return Decision::Negado(Motivo::Prohibido);
    }
    let concedido = actor
        .concesiones
        .iter()
        .any(|c| c.accion == *accion && c.alcance.cubre(duenio));
    if concedido {
        Decision::Permitido
    } else {
        Decision::Negado(Motivo::SinConcesion)
    }
}

// ── EL 404-NO-ORÁCULO (la lección de medico::aislamiento) ───────────────────────
//
// `autorizar` dice sí/no. Pero al NEGAR hay dos situaciones que un producto tiene que
// responder distinto para no filtrar información: negar MOSTRANDO ("prohibido", 403) revela
// que el recurso EXISTE; negar OCULTANDO ("no existe", 404) no. medico lo aprendió por un
// defecto real: `defuncion::certificar` negaba mostrando, y la diferencia entre respuestas
// se leía por bisección como un ORÁCULO que reconstruía la hora de ingreso de un paciente
// de otro prestador. La regla de medico: si el actor no tiene NINGÚN alcance sobre el dueño
// (otro tenant), el recurso le es INVISIBLE (404); si lo alcanza pero le falta ESTA acción,
// existe-y-no-le-corresponde (403). Se eleva aquí para que ningún consumidor la reinvente.

/// El veredicto que distingue OCULTAR de MOSTRAR al negar — para no dar un oráculo de
/// existencia. El consumidor lo mapea: `Permitido`→sigue; `Prohibido`→403 (existe, no te
/// corresponde); `Invisible`→404 (no se revela que exista).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Veredicto {
    Permitido,
    /// El actor VE el dueño (tiene ALGÚN permiso sobre él) pero le falta esta acción, o un
    /// deny la retrae. Existe y no le corresponde → 403. Lleva el motivo para el log.
    Prohibido(Motivo),
    /// El actor no tiene NINGÚN permiso sobre el dueño: el recurso le es invisible → 404,
    /// sin revelar que existe.
    Invisible,
}

impl Veredicto {
    /// ¿Permitido? Método explícito, sin conversión implícita a `bool`.
    pub fn permitido(&self) -> bool {
        matches!(self, Veredicto::Permitido)
    }
}

/// ¿El actor tiene ALGÚN alcance sobre el dueño —de cualquier acción—? Es lo que decide si
/// el recurso le es visible: si ninguna concesión lo cubre, no debe saber siquiera que
/// existe. `Publico` lo alcanza cualquiera que tenga la acción en algún sitio (misma regla
/// que `cubre`), así que un recurso sin dueño nunca es invisible por aislamiento.
fn alcanza_al_duenio<A, Ac>(actor: &Actor<A, Ac>, duenio: &Duenio<A>) -> bool
where
    A: PartialEq,
{
    actor.concesiones.iter().any(|c| c.alcance.cubre(duenio))
}

/// **Autoriza distinguiendo OCULTAR de MOSTRAR** (el 404-no-oráculo). `Permitido` si tiene
/// la acción; `Invisible` (→404) si no tiene NINGÚN permiso sobre el dueño —otro tenant—;
/// `Prohibido` (→403) si ve el dueño pero le falta la acción o un deny la retrae. Es
/// [`autorizar`] envuelto con la decisión de visibilidad, en un solo sitio.
pub fn autorizar_visible<A, Ac>(actor: &Actor<A, Ac>, accion: &Ac, duenio: &Duenio<A>) -> Veredicto
where
    A: PartialEq,
    Ac: PartialEq,
{
    match autorizar(actor, accion, duenio) {
        Decision::Permitido => Veredicto::Permitido,
        // Negado: ¿lo ve? Si alcanza al dueño por alguna concesión, es 403 (existe); si no,
        // es 404 (invisible, no se revela existencia). Un deny (Prohibido) se muestra como
        // 403 por defecto —el actor tenía alcance—; ocultar un confidencial como 404 es
        // política del consumidor sobre el `Motivo`, no del motor.
        Decision::Negado(motivo) => {
            if alcanza_al_duenio(actor, duenio) {
                Veredicto::Prohibido(motivo)
            } else {
                Veredicto::Invisible
            }
        }
    }
}

// ── EJE 1 — EL ALCANCE COMO CONSULTA (el patrón de informes::autz) ──────────────
//
// `autorizar` decide por UN recurso cuyo dueño ya se conoce. Pero un LISTADO no tiene un
// dueño único: la pregunta es "¿qué recursos puede ver este actor?", y la respuesta tiene
// que ser el WHERE de la consulta, no un booleano por fila (que llegaría después de leer
// filas ajenas). informes lo resuelve haciendo que el alcance sea EL origen del WHERE.
// Aquí se generaliza: se colapsan las concesiones del actor para una acción en un
// [`AlcanceEfectivo`], que el consumidor materializa en su consulta.

/// El alcance TOTAL de un actor para una acción, como VALOR para construir la consulta de
/// un listado. Tres casos y ninguno implícito: colapsar a un booleano perdería la
/// diferencia entre "todo", "estos" y "nada", que es justo lo que decide el `WHERE`.
///
/// No tiene `Default` A PROPÓSITO (como la `Frase` de guaca): el consumidor debe decidir
/// los tres casos al construir el SQL —`match` exhaustivo, sin brazo `_`—, que es lo que
/// impide que un listado nuevo se olvide de filtrar y liste de más.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlcanceEfectivo<A> {
    /// Ve cualquier recurso: sin filtro (una autoridad global). El consumidor NO añade
    /// `WHERE` de propiedad.
    Todo,
    /// Ve solo los recursos cuyo dueño está en este conjunto (no vacío). El consumidor
    /// materializa `WHERE duenio IN (…)` —con un elemento, un `=`—. Para un ámbito que es
    /// una relación N:M (el `DeStakeholder` de informes), el consumidor traduce cada `A` a
    /// su `EXISTS`: el motor da los ámbitos, el consumidor sabe cómo se unen a la tabla.
    Conjunto(Vec<A>),
    /// Ve TODO menos los ámbitos de este conjunto (no vacío): una autoridad global a la que
    /// una PROHIBICIÓN scope-shaped le retrae unos ámbitos concretos (un recurso confidencial,
    /// un tenant bajo bloqueo). El consumidor materializa `WHERE duenio NOT IN (…)`. Nace solo
    /// cuando hay deny (ver [`Prohibicion`]); sin prohibiciones, `alcance_de` nunca lo produce.
    TodoExcepto(Vec<A>),
    /// No ve NADA (fail-closed como valor, no como hueco). El consumidor materializa una
    /// consulta que estructuralmente no puede devolver filas (`WHERE 0`), no un listado sin
    /// filtro. Es el `Alcance::Ninguna` de informes: explícito, no un `Option` que alguien
    /// desenvuelva con `unwrap_or(todo)`.
    Ninguno,
}

impl<A> AlcanceEfectivo<A> {
    /// **Materializa este alcance en un filtro de tipo `T`, sin repetir el colapso de casos
    /// ni poder confundir "todo" (sin filtro) con "nada" (imposible).** Es el patrón que
    /// informes repetía A MANO en cinco sitios —cada consulta hacía su propio `match` sobre
    /// el alcance, y basta uno mal escrito (un `Todo` tratado como `Ninguno`, o al revés)
    /// para convertir un listado acotado en una fuga—. Elevado aquí, el consumidor da las
    /// CUATRO traducciones una vez y el motor llama la que toca; no hay `match` que olvidar
    /// un brazo ni orden de comprobación que confundir.
    ///
    /// Agnóstico de I/O (el contrato de Bachué): `T` es lo que el consumidor construya —un
    /// fragmento de `WHERE` con sus bindings, un predicado en memoria, lo que sea—. Las
    /// cuatro ramas, con su materialización SQL típica al lado:
    /// - `sin_filtro()` para `Todo` — no se añade filtro de propiedad;
    /// - `incluir(&[A])` para `Conjunto` — `WHERE duenio IN (…)` o el `OR` de los ámbitos
    ///   (cada `A` traducido como el consumidor sepa: igualdad, `EXISTS` N:M, `LIKE` de
    ///   prefijo jerárquico);
    /// - `excluir(&[A])` para `TodoExcepto` — `WHERE duenio NOT IN (…)` (nace solo con deny);
    /// - `imposible()` para `Ninguno` — una consulta que no puede devolver filas (`WHERE 0`),
    ///   NUNCA sin filtro.
    ///
    /// Los `&[A]` de `incluir`/`excluir` son siempre NO vacíos (lo garantiza `alcance_de`),
    /// así que el consumidor no tiene que defenderse de un `IN ()` degenerado.
    pub fn materializar<T>(
        &self,
        sin_filtro: impl FnOnce() -> T,
        incluir: impl FnOnce(&[A]) -> T,
        excluir: impl FnOnce(&[A]) -> T,
        imposible: impl FnOnce() -> T,
    ) -> T {
        match self {
            AlcanceEfectivo::Todo => sin_filtro(),
            AlcanceEfectivo::Conjunto(ambitos) => incluir(ambitos),
            AlcanceEfectivo::TodoExcepto(ambitos) => excluir(ambitos),
            AlcanceEfectivo::Ninguno => imposible(),
        }
    }
}

/// **Colapsa las concesiones del actor para `accion` en su alcance TOTAL de listado.**
/// Si posee la acción con `Alcance::Todo` → [`AlcanceEfectivo::Todo`] (una sola concesión
/// global manda). Si posee una o más `De(a)` → [`AlcanceEfectivo::Conjunto`] con esos
/// ámbitos. Si no posee la acción en ningún sitio → [`AlcanceEfectivo::Ninguno`].
///
/// Es el hermano de [`autorizar`] para los LISTADOS: la misma fuente de verdad (las
/// concesiones), la misma acción, pero el resultado es el alcance a materializar en el
/// `WHERE` en vez de un sí/no sobre un recurso ya cargado.
///
/// **Es el alcance de PROPIEDAD, y solo eso.** Modela `Duenio::De(_)`, no `Duenio::Publico`:
/// un [`AlcanceEfectivo::Conjunto`] materializado como `WHERE duenio IN (…)` **excluye** los
/// recursos públicos que el actor sí puede ver por [`autorizar`]. Si un listado debe incluir
/// lo público, el consumidor lo une aparte (`… OR duenio IS NULL`) **pero gated por
/// [`autorizar`] cuando hay prohibiciones**: un deny GLOBAL (`Prohibicion` con `Alcance::Todo`)
/// apaga también lo público, así que unir lo ownerless a ciegas sería fail-open. La regla
/// segura para el consumidor: incluir lo público solo si `autorizar(actor, accion, Publico)`
/// es `Permitido`. Sobre `De(d)` las dos puertas coinciden siempre; sobre `Publico`, se
/// consulta [`autorizar`].
pub fn alcance_de<A, Ac>(actor: &Actor<A, Ac>, accion: &Ac) -> AlcanceEfectivo<A>
where
    A: PartialEq + Clone,
    Ac: PartialEq,
{
    // El alcance efectivo es lo PERMITIDO menos lo DENEGADO, calculado como conjuntos —así
    // se sostiene la garantía "el alcance ES el WHERE" también con deny (el principio rector
    // de la cabecera). Los dos lados se colapsan igual; luego se restan.
    let permitido = colapsar(actor.concesiones.iter().filter(|c| c.accion == *accion).map(|c| &c.alcance));
    let denegado = colapsar(actor.prohibiciones.iter().filter(|p| p.accion == *accion).map(|p| &p.alcance));

    match (permitido, denegado) {
        // Nada prohibido: el permitido tal cual.
        (p, Colapso::Ninguno) => p.a_efectivo(),
        // Todo prohibido: no queda nada, gane lo que gane el permitido (deny-override).
        (_, Colapso::Todo) => AlcanceEfectivo::Ninguno,
        // Global menos unos ámbitos concretos: "todo excepto ésos".
        (Colapso::Todo, Colapso::Algunos(d)) => AlcanceEfectivo::TodoExcepto(d),
        // Sin permiso: nada que restar.
        (Colapso::Ninguno, _) => AlcanceEfectivo::Ninguno,
        // Conjunto menos conjunto: los permitidos que no están denegados.
        (Colapso::Algunos(p), Colapso::Algunos(d)) => {
            let restante: Vec<A> = p.into_iter().filter(|a| !d.contains(a)).collect();
            if restante.is_empty() {
                AlcanceEfectivo::Ninguno
            } else {
                AlcanceEfectivo::Conjunto(restante)
            }
        }
    }
}

/// El colapso de una lista de alcances (de concesiones o de prohibiciones) para una acción.
/// Interno: es el paso común a los dos lados de `alcance_de`, antes de restar.
enum Colapso<A> {
    /// Alguna era global.
    Todo,
    /// Un conjunto no vacío de ámbitos concretos, sin duplicados.
    Algunos(Vec<A>),
    /// Ninguna.
    Ninguno,
}

impl<A> Colapso<A> {
    fn a_efectivo(self) -> AlcanceEfectivo<A> {
        match self {
            Colapso::Todo => AlcanceEfectivo::Todo,
            Colapso::Algunos(v) => AlcanceEfectivo::Conjunto(v),
            Colapso::Ninguno => AlcanceEfectivo::Ninguno,
        }
    }
}

/// Colapsa los alcances que casan la acción: si alguno es global → [`Colapso::Todo`]; si hay
/// ámbitos concretos → [`Colapso::Algunos`] (sin duplicados); si ninguno → [`Colapso::Ninguno`].
fn colapsar<'a, A>(alcances: impl Iterator<Item = &'a Alcance<A>>) -> Colapso<A>
where
    A: 'a + PartialEq + Clone,
{
    let mut ambitos: Vec<A> = Vec::new();
    for alcance in alcances {
        match alcance {
            Alcance::Todo => return Colapso::Todo,
            Alcance::De(a) => {
                if !ambitos.contains(a) {
                    ambitos.push(a.clone());
                }
            }
        }
    }
    if ambitos.is_empty() {
        Colapso::Ninguno
    } else {
        Colapso::Algunos(ambitos)
    }
}

// ── EJE 2 — LA HABILITACIÓN POR TENANT (la licencia-por-módulo de medico) ───────
//
// Una SEGUNDA dimensión, ortogonal al permiso del actor: aunque el actor tenga la acción
// sobre el tenant, el tenant tiene que tener CONTRATADO el módulo que la acción requiere.
// El mismo (accion, duenio) está permitido o no según lo que el tenant compró. La fuente
// (qué módulos tiene cada tenant) es del producto —el motor la recibe ya leída—; lo que se
// generaliza aquí es la COMBINACIÓN AND de las dos dimensiones, con su motivo propio.

/// **Autoriza combinando las DOS dimensiones: el permiso del actor Y la habilitación del
/// módulo en el tenant dueño.** `Permitido` sii el `modulo` está en `habilitados_del_tenant`
/// **y** el actor tiene la concesión (por [`autorizar`]).
///
/// Se comprueba la habilitación PRIMERO: si el tenant no contrató el módulo, sobra mirar el
/// permiso —y el motivo [`Motivo::ModuloNoHabilitado`] es el que el producto convierte en su
/// respuesta propia (medico: el 503/403 que nombra el módulo que abriría), distinto del
/// `SinConcesion`—. La lista `habilitados_del_tenant` la lee el consumidor de su catálogo;
/// qué hacer si esa lectura FALLA es decisión suya (directiva 20: falla ruidoso, no asume
/// "todo habilitado"), no de este motor.
///
/// **Nota para el consumidor sobre el orden.** Como la habilitación se mira antes que el
/// permiso, un actor SIN concesión alguna sobre el tenant recibe igualmente
/// `ModuloNoHabilitado` cuando el módulo no está contratado. Al cliente se le responde
/// uniforme (el `Motivo` es para el log), así que dentro del motor no filtra nada; pero si un
/// producto DECIDE surface la distinción (como medico), esa respuesta revela "el tenant no
/// contrató el módulo" con independencia del permiso. Si la existencia de un módulo concreto
/// fuese sensible, el consumidor invierte el orden (permiso primero) o unifica la respuesta.
pub fn autorizar_habilitado<A, Ac, M>(
    actor: &Actor<A, Ac>,
    accion: &Ac,
    duenio: &Duenio<A>,
    modulo: &M,
    habilitados_del_tenant: &[M],
) -> Decision
where
    A: PartialEq,
    Ac: PartialEq,
    M: PartialEq,
{
    if !habilitados_del_tenant.contains(modulo) {
        return Decision::Negado(Motivo::ModuloNoHabilitado);
    }
    autorizar(actor, accion, duenio)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // Tipos de dominio de prueba: dos tenants y dos acciones. Concretan el motor
    // genérico para que los casos rojos fallen por la vía REAL (directiva 33).
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Org {
        A,
        B,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Op {
        Leer,
        Escribir,
    }

    fn con(accion: Op, alcance: Alcance<Org>) -> Concesion<Org, Op> {
        Concesion { accion, alcance }
    }

    /// **CONTROL POSITIVO (lo primero, directiva 30):** un actor sin permisos no
    /// alcanza NADA. Si esto no fuera cierto, todo lo de abajo mediría un motor que
    /// dice "sí" por defecto —el peor fallo de un motor de authz—.
    #[test]
    fn sin_concesiones_no_alcanza_nada() {
        let a: Actor<Org, Op> = Actor::sin_permisos(1);
        assert_eq!(
            autorizar(&a, &Op::Leer, &Duenio::De(Org::A)),
            Decision::Negado(Motivo::SinConcesion)
        );
        assert_eq!(
            autorizar(&a, &Op::Leer, &Duenio::Publico),
            Decision::Negado(Motivo::SinConcesion)
        );
    }

    /// **LECCIÓN ZITADEL — se autoriza contra el DUEÑO DEL RECURSO, no el del
    /// llamante.** Un actor con `Leer` sobre la org A NO puede leer un recurso de la
    /// org B. Y su PAREJA: SÍ puede leer uno de la org A. Sin la pareja, un motor que
    /// niega todo pasaría el caso rojo; sin el caso rojo, un motor que colapsa a global
    /// (el bug real de Zitadel) pasaría el verde.
    #[test]
    fn el_permiso_de_un_tenant_no_alcanza_otro() {
        let a = Actor::nuevo(1, vec![con(Op::Leer, Alcance::De(Org::A))]);
        // ROJO por la vía real: recurso de OTRO tenant.
        assert!(!autorizar(&a, &Op::Leer, &Duenio::De(Org::B)).permitido());
        // VERDE: su propio tenant.
        assert!(autorizar(&a, &Op::Leer, &Duenio::De(Org::A)).permitido());
    }

    /// **LECCIÓN GRAFANA — el permiso es ACCIÓN + ámbito, no un rol.** Tener `Leer`
    /// sobre A no da `Escribir` sobre A. Pareja: `Leer` sí lee.
    #[test]
    fn una_accion_no_concede_otra() {
        let a = Actor::nuevo(1, vec![con(Op::Leer, Alcance::De(Org::A))]);
        assert!(!autorizar(&a, &Op::Escribir, &Duenio::De(Org::A)).permitido());
        assert!(autorizar(&a, &Op::Leer, &Duenio::De(Org::A)).permitido());
    }

    /// **`Alcance::Todo` es la autoridad global** (admin): cubre cualquier dueño. Su
    /// PAREJA discriminante: `De(A)` NO cubre `De(B)` —para que "Todo" no sea lo mismo
    /// que "De(cualquiera)" por un cubre() mal escrito—.
    #[test]
    fn todo_cubre_cualquier_duenio_pero_de_a_no_cubre_b() {
        let admin = Actor::nuevo(1, vec![con(Op::Escribir, Alcance::Todo)]);
        assert!(autorizar(&admin, &Op::Escribir, &Duenio::De(Org::A)).permitido());
        assert!(autorizar(&admin, &Op::Escribir, &Duenio::De(Org::B)).permitido());

        let acotado = Actor::nuevo(2, vec![con(Op::Escribir, Alcance::De(Org::A))]);
        assert!(acotado.concesiones()[0].alcance.cubre(&Duenio::De(Org::A)));
        assert!(!acotado.concesiones()[0].alcance.cubre(&Duenio::De(Org::B)));
    }

    /// **Un recurso `Publico` lo alcanza quien tenga la acción en ALGÚN ámbito**, y su
    /// PAREJA: quien no tiene esa acción, no —para que "público" no signifique "abierto
    /// a cualquiera sin ninguna concesión" (eso sería `sin_concesiones` de arriba)—.
    #[test]
    fn lo_publico_lo_alcanza_quien_tiene_la_accion_no_cualquiera() {
        let lector = Actor::nuevo(1, vec![con(Op::Leer, Alcance::De(Org::A))]);
        assert!(autorizar(&lector, &Op::Leer, &Duenio::Publico).permitido());
        // No tiene `Escribir` en ningún sitio: ni siquiera sobre lo público.
        assert!(!autorizar(&lector, &Op::Escribir, &Duenio::Publico).permitido());
    }

    // ── EL 404-NO-ORÁCULO (la lección de medico::aislamiento) ──

    /// **EL EDGE (directiva 33): negar OCULTANDO vs negar MOSTRANDO.** Un actor con `Leer`
    /// sobre A: sobre A abre; sobre B —otro tenant que no alcanza— el recurso es `Invisible`
    /// (→404, no revela existencia); sobre A pero pidiendo `Escribir` —ve A, le falta la
    /// acción— es `Prohibido` (→403). La pareja `Invisible`↔`Prohibido` es el punto: sin ella,
    /// un producto respondería 403 para el recurso ajeno y filtraría que existe (el oráculo de
    /// `defuncion::certificar` en medico).
    #[test]
    fn distingue_invisible_de_prohibido() {
        let actor = Actor::nuevo(1, vec![con(Op::Leer, Alcance::De(Org::A))]);
        // Su tenant, su acción: permitido.
        assert_eq!(autorizar_visible(&actor, &Op::Leer, &Duenio::De(Org::A)), Veredicto::Permitido);
        // OTRO tenant (no lo alcanza): INVISIBLE → 404, no se revela que exista.
        assert_eq!(autorizar_visible(&actor, &Op::Leer, &Duenio::De(Org::B)), Veredicto::Invisible);
        // Su tenant pero acción que no tiene: ve A, le falta Escribir → PROHIBIDO (403).
        assert_eq!(
            autorizar_visible(&actor, &Op::Escribir, &Duenio::De(Org::A)),
            Veredicto::Prohibido(Motivo::SinConcesion)
        );
    }

    /// Un deny (recurso confidencial en un tenant que el actor SÍ alcanza) es `Prohibido`
    /// (existe, el actor tiene alcance), no `Invisible`: ocultarlo como 404 es política del
    /// consumidor sobre el motivo. Su pareja: sin ninguna concesión sobre el dueño, `Invisible`.
    #[test]
    fn un_deny_sobre_un_tenant_alcanzado_es_prohibido_no_invisible() {
        let actor = Actor::nuevo(1, vec![con(Op::Leer, Alcance::Todo)])
            .con_prohibiciones(vec![prohib(Op::Leer, Alcance::De(Org::A))]);
        assert_eq!(
            autorizar_visible(&actor, &Op::Leer, &Duenio::De(Org::A)),
            Veredicto::Prohibido(Motivo::Prohibido)
        );
        // Un actor sin ningún alcance sobre B: invisible.
        let ajeno = Actor::nuevo(2, vec![con(Op::Leer, Alcance::De(Org::A))]);
        assert_eq!(autorizar_visible(&ajeno, &Op::Leer, &Duenio::De(Org::B)), Veredicto::Invisible);
    }

    // ── EJE 1 — ALCANCE COMO CONSULTA (reproduce informes::autz) ──

    /// **El alcance efectivo colapsa a los TRES casos que decide el `WHERE` de un listado**,
    /// reproduciendo informes: un `Admin` (concesión global) ve todo; un `Operador`
    /// (concesión de su ámbito) ve su conjunto; un `Tercero` sin vínculo (sin concesión) no
    /// ve nada. Las tres son distintas: sin los tres casos, un colapso a booleano —o un
    /// `Ninguno` que se confunde con `Conjunto([])`— pasaría de largo.
    #[test]
    fn el_alcance_efectivo_reproduce_los_tres_casos_de_informes() {
        // Admin: concesión global → ve TODO (sin filtro).
        let admin = Actor::nuevo(1, vec![con(Op::Leer, Alcance::Todo)]);
        assert_eq!(alcance_de(&admin, &Op::Leer), AlcanceEfectivo::Todo);

        // Operador: concesión de SU ámbito → conjunto con ese ámbito.
        let operador = Actor::nuevo(2, vec![con(Op::Leer, Alcance::De(Org::A))]);
        assert_eq!(alcance_de(&operador, &Op::Leer), AlcanceEfectivo::Conjunto(vec![Org::A]));

        // Tercero sin vínculo: ninguna concesión de esa acción → NO ve nada (no un conjunto
        // vacío que un `IN ()` interpretaría mal, sino el caso explícito).
        let tercero: Actor<Org, Op> = Actor::sin_permisos(3);
        assert_eq!(alcance_de(&tercero, &Op::Leer), AlcanceEfectivo::Ninguno);

        // Y la pareja del Operador: para OTRA acción que no posee, tampoco ve nada —el
        // alcance es por (actor, ACCIÓN), no del actor en bloque—.
        assert_eq!(alcance_de(&operador, &Op::Escribir), AlcanceEfectivo::Ninguno);
    }

    /// Varias concesiones de la misma acción se UNEN en el conjunto (sin duplicar), y una
    /// global entre ellas DOMINA (ve todo). Sin esto, un motor que se quedara con la primera
    /// concesión daría un alcance más estrecho de lo real.
    #[test]
    fn el_alcance_une_varios_ambitos_y_lo_global_domina() {
        let multi = Actor::nuevo(
            1,
            vec![con(Op::Leer, Alcance::De(Org::A)), con(Op::Leer, Alcance::De(Org::B)), con(Op::Leer, Alcance::De(Org::A))],
        );
        assert_eq!(alcance_de(&multi, &Op::Leer), AlcanceEfectivo::Conjunto(vec![Org::A, Org::B]));

        // Con una concesión global en la mezcla, gana `Todo` (no un conjunto de dos).
        let con_global = Actor::nuevo(
            1,
            vec![con(Op::Leer, Alcance::De(Org::A)), con(Op::Leer, Alcance::Todo)],
        );
        assert_eq!(alcance_de(&con_global, &Op::Leer), AlcanceEfectivo::Todo);
    }

    /// **LA COSTURA CONTRA LA DIVERGENCIA (lección Discourse): las dos puertas coinciden
    /// sobre `De(d)`.** El invariante `d ∈ alcance_de(actor,acc) ⟺
    /// autorizar(actor,acc,De(d))=Permitido` se afirma como PROPIEDAD, no por casos: se barre
    /// un dominio pequeño de actores × acciones × dueños, y si un cambio futuro moviera una de
    /// las dos funciones sin la otra (el modo de fallo Discourse: el gate y la audiencia que
    /// se separan), este test se pone rojo. También fija que `Conjunto` es OWNED-ONLY: no
    /// mete `Publico`.
    #[test]
    fn las_dos_puertas_coinciden_sobre_un_duenio_concreto() {
        // Un abanico de actores que cubre los tres colapsos y la mezcla.
        let actores = vec![
            Actor::sin_permisos(0),
            Actor::nuevo(1, vec![con(Op::Leer, Alcance::Todo)]),
            Actor::nuevo(2, vec![con(Op::Leer, Alcance::De(Org::A))]),
            Actor::nuevo(3, vec![con(Op::Leer, Alcance::De(Org::A)), con(Op::Leer, Alcance::De(Org::B))]),
            Actor::nuevo(4, vec![con(Op::Escribir, Alcance::De(Org::A))]), // Leer: ninguno
            Actor::nuevo(5, vec![con(Op::Leer, Alcance::De(Org::A)), con(Op::Escribir, Alcance::Todo)]),
        ];
        for actor in &actores {
            for accion in [Op::Leer, Op::Escribir] {
                let efectivo = alcance_de(actor, &accion);
                for duenio in [Org::A, Org::B] {
                    let por_recurso = autorizar(actor, &accion, &Duenio::De(duenio.clone())).permitido();
                    let por_alcance = match &efectivo {
                        AlcanceEfectivo::Todo => true,
                        AlcanceEfectivo::Conjunto(v) => v.contains(&duenio),
                        AlcanceEfectivo::TodoExcepto(v) => !v.contains(&duenio),
                        AlcanceEfectivo::Ninguno => false,
                    };
                    assert_eq!(
                        por_recurso, por_alcance,
                        "divergen para actor {} accion {:?} duenio {:?}: recurso={} alcance={:?}",
                        actor.id, accion, duenio, por_recurso, efectivo
                    );
                }
            }
        }
    }

    // ── EJE 2 — HABILITACIÓN POR TENANT (reproduce la licencia de medico) ──

    /// Un módulo de prueba (la "licencia" de medico: qué contrató el tenant).
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Modulo {
        Clinico,
        Rips,
    }

    /// **Las DOS dimensiones son AND, y sus dos negativas NO se confunden** (reproduce
    /// medico). Con el actor que SÍ tiene `Escribir` sobre la org A: si A tiene el módulo
    /// `Clinico` habilitado, Permitido; si A NO lo tiene, `ModuloNoHabilitado` (no
    /// `SinConcesion`: el permiso estaba, faltó la licencia — medico lo convierte en un
    /// 503/403 que nombra el módulo); y un actor SIN la capacidad, aunque el módulo esté
    /// habilitado, `SinConcesion`. Los dos motivos distintos son el punto: un solo `Negado`
    /// los borraría, y se corrigen en sitios distintos (contratar el módulo vs. dar el permiso).
    #[test]
    fn habilitacion_y_permiso_son_and_con_motivos_distintos() {
        let escritor = Actor::nuevo(1, vec![con(Op::Escribir, Alcance::De(Org::A))]);

        // Permiso OK + módulo habilitado → permitido.
        assert!(
            autorizar_habilitado(&escritor, &Op::Escribir, &Duenio::De(Org::A), &Modulo::Clinico, &[Modulo::Clinico])
                .permitido()
        );

        // Permiso OK pero el tenant NO contrató el módulo → ModuloNoHabilitado (no SinConcesion).
        assert_eq!(
            autorizar_habilitado(&escritor, &Op::Escribir, &Duenio::De(Org::A), &Modulo::Clinico, &[Modulo::Rips]),
            Decision::Negado(Motivo::ModuloNoHabilitado)
        );

        // Módulo habilitado pero el actor NO tiene la capacidad → SinConcesion (no ModuloNoHabilitado).
        let lector = Actor::nuevo(2, vec![con(Op::Leer, Alcance::De(Org::A))]);
        assert_eq!(
            autorizar_habilitado(&lector, &Op::Escribir, &Duenio::De(Org::A), &Modulo::Clinico, &[Modulo::Clinico]),
            Decision::Negado(Motivo::SinConcesion)
        );

        // Y el cruce de tenant sigue vigente bajo la segunda dimensión: permiso sobre A no
        // escribe en B aunque B tenga el módulo (la lección Zitadel no se pierde al añadir la licencia).
        assert_eq!(
            autorizar_habilitado(&escritor, &Op::Escribir, &Duenio::De(Org::B), &Modulo::Clinico, &[Modulo::Clinico]),
            Decision::Negado(Motivo::SinConcesion)
        );
    }

    // ── EJE 3 — DENY-OVERRIDE (la lección Cedar/Casbin, scope-shaped) ──

    fn prohib(accion: Op, alcance: Alcance<Org>) -> Prohibicion<Org, Op> {
        Prohibicion { accion, alcance }
    }

    /// **EL EDGE DEL DENY (directiva 33): una prohibición GANA sobre la concesión que la
    /// haría pasar.** Un actor con `Leer` sobre A, prohibido de `Leer` en A → Negado por
    /// `Prohibido` (no Permitido, no `SinConcesion`: tenía el permiso y se le retrae). Su
    /// PAREJA: sin la prohibición, el mismo actor SÍ entra —sin ella, un motor que negara
    /// todo pasaría el rojo; sin el rojo, uno que ignora las prohibiciones pasaría el verde—.
    #[test]
    fn una_prohibicion_gana_sobre_la_concesion() {
        let base = || Actor::nuevo(1, vec![con(Op::Leer, Alcance::De(Org::A))]);
        // Sin prohibición: entra (control positivo).
        assert!(autorizar(&base(), &Op::Leer, &Duenio::De(Org::A)).permitido());
        // Con la prohibición del mismo (acción, ámbito): NEGADO por Prohibido.
        let vetado = base().con_prohibiciones(vec![prohib(Op::Leer, Alcance::De(Org::A))]);
        assert_eq!(
            autorizar(&vetado, &Op::Leer, &Duenio::De(Org::A)),
            Decision::Negado(Motivo::Prohibido)
        );
    }

    /// El deny es SCOPE-SHAPED: una prohibición `De(A)` no toca `De(B)`. Un admin (`Todo`)
    /// prohibido solo en A: no entra a A (Prohibido), sí entra a B. Sin esto, un deny que
    /// cubriera de más apagaría permisos legítimos —el sesgo a cerrar (directiva 21)—.
    #[test]
    fn el_deny_solo_alcanza_su_ambito() {
        let admin = Actor::nuevo(1, vec![con(Op::Leer, Alcance::Todo)])
            .con_prohibiciones(vec![prohib(Op::Leer, Alcance::De(Org::A))]);
        assert_eq!(autorizar(&admin, &Op::Leer, &Duenio::De(Org::A)), Decision::Negado(Motivo::Prohibido));
        assert!(autorizar(&admin, &Op::Leer, &Duenio::De(Org::B)).permitido());
        // Y otra acción no prohibida sigue libre (el deny es por (acción, ámbito)).
        let admin2 = Actor::nuevo(2, vec![con(Op::Escribir, Alcance::Todo)])
            .con_prohibiciones(vec![prohib(Op::Leer, Alcance::De(Org::A))]);
        assert!(autorizar(&admin2, &Op::Escribir, &Duenio::De(Org::A)).permitido());
    }

    /// **El deny en los LISTADOS: `alcance_de` resta el denegado del permitido**, en los
    /// cinco casos que decide el `WHERE`. Es "permitido − denegado" calculado como conjuntos
    /// (el principio rector), y produce `TodoExcepto` cuando el permitido es global.
    #[test]
    fn el_alcance_efectivo_resta_lo_denegado() {
        let leer = Op::Leer;
        // Global menos {A} → TodoExcepto([A]).
        let g = Actor::nuevo(1, vec![con(leer, Alcance::Todo)])
            .con_prohibiciones(vec![prohib(leer, Alcance::De(Org::A))]);
        assert_eq!(alcance_de(&g, &leer), AlcanceEfectivo::TodoExcepto(vec![Org::A]));

        // Conjunto {A,B} menos {A} → Conjunto([B]).
        let c = Actor::nuevo(2, vec![con(leer, Alcance::De(Org::A)), con(leer, Alcance::De(Org::B))])
            .con_prohibiciones(vec![prohib(leer, Alcance::De(Org::A))]);
        assert_eq!(alcance_de(&c, &leer), AlcanceEfectivo::Conjunto(vec![Org::B]));

        // Conjunto {A} menos {A} → Ninguno (no un conjunto vacío que un `IN ()` malinterprete).
        let vacio = Actor::nuevo(3, vec![con(leer, Alcance::De(Org::A))])
            .con_prohibiciones(vec![prohib(leer, Alcance::De(Org::A))]);
        assert_eq!(alcance_de(&vacio, &leer), AlcanceEfectivo::Ninguno);

        // Cualquier permitido menos Todo → Ninguno (deny-override total).
        let todo_prohibido = Actor::nuevo(4, vec![con(leer, Alcance::Todo)])
            .con_prohibiciones(vec![prohib(leer, Alcance::Todo)]);
        assert_eq!(alcance_de(&todo_prohibido, &leer), AlcanceEfectivo::Ninguno);

        // Sin prohibición (control): el permitido tal cual.
        let libre = Actor::nuevo(5, vec![con(leer, Alcance::Todo)]);
        assert_eq!(alcance_de(&libre, &leer), AlcanceEfectivo::Todo);
    }

    /// **Un deny en un ÁMBITO no apaga lo `Publico`; un deny GLOBAL sí** (la corrección de la
    /// revisión). Un lector global que oculta un confidencial de A —`Prohibicion{Leer,De(A)}`—
    /// **sigue viendo** los avisos de portada (`Publico`); solo `Prohibicion{Leer,Todo}` los
    /// apaga. Sin esta distinción, ocultar un recurso de un tenant tumbaría lo ownerless
    /// (fail-closed no intencional).
    #[test]
    fn un_deny_de_ambito_no_apaga_lo_publico_pero_uno_global_si() {
        let global = || Actor::nuevo(1, vec![con(Op::Leer, Alcance::Todo)]);
        // deny De(A): niega A, NO niega Publico.
        let oculta_a = global().con_prohibiciones(vec![prohib(Op::Leer, Alcance::De(Org::A))]);
        assert_eq!(autorizar(&oculta_a, &Op::Leer, &Duenio::De(Org::A)), Decision::Negado(Motivo::Prohibido));
        assert!(autorizar(&oculta_a, &Op::Leer, &Duenio::Publico).permitido(), "prohibir en A no apaga lo público");
        // deny Todo: apaga también Publico.
        let veta_todo = global().con_prohibiciones(vec![prohib(Op::Leer, Alcance::Todo)]);
        assert_eq!(autorizar(&veta_todo, &Op::Leer, &Duenio::Publico), Decision::Negado(Motivo::Prohibido));
    }

    /// **La costura anti-divergencia se mantiene CON deny**: la propiedad `d ∈
    /// alcance_de(actor,acc) ⟺ autorizar(actor,acc,De(d))=Permitido` sigue barriéndose,
    /// ahora con actores que llevan prohibiciones. Si el deny y `alcance_de` restaran
    /// distinto, este test se pone rojo (el modo Discourse, extendido al deny).
    #[test]
    fn las_dos_puertas_coinciden_tambien_con_deny() {
        let actores = vec![
            // Global menos A.
            Actor::nuevo(1, vec![con(Op::Leer, Alcance::Todo)]).con_prohibiciones(vec![prohib(Op::Leer, Alcance::De(Org::A))]),
            // {A,B} menos A.
            Actor::nuevo(2, vec![con(Op::Leer, Alcance::De(Org::A)), con(Op::Leer, Alcance::De(Org::B))])
                .con_prohibiciones(vec![prohib(Op::Leer, Alcance::De(Org::A))]),
            // {A} menos A → nada.
            Actor::nuevo(3, vec![con(Op::Leer, Alcance::De(Org::A))]).con_prohibiciones(vec![prohib(Op::Leer, Alcance::De(Org::A))]),
            // Global menos Todo → nada.
            Actor::nuevo(4, vec![con(Op::Leer, Alcance::Todo)]).con_prohibiciones(vec![prohib(Op::Leer, Alcance::Todo)]),
        ];
        for actor in &actores {
            let efectivo = alcance_de(actor, &Op::Leer);
            for duenio in [Org::A, Org::B] {
                let por_recurso = autorizar(actor, &Op::Leer, &Duenio::De(duenio.clone())).permitido();
                let por_alcance = match &efectivo {
                    AlcanceEfectivo::Todo => true,
                    AlcanceEfectivo::Conjunto(v) => v.contains(&duenio),
                    AlcanceEfectivo::TodoExcepto(v) => !v.contains(&duenio),
                    AlcanceEfectivo::Ninguno => false,
                };
                assert_eq!(
                    por_recurso, por_alcance,
                    "divergen con deny: actor {} duenio {:?}: recurso={} alcance={:?}",
                    actor.id, duenio, por_recurso, efectivo
                );
            }
        }
    }

    // ── FUSIÓN — la materialización del alcance, elevada al motor ──

    /// **`materializar` llama la rama correcta de cada caso, y en particular NO confunde
    /// "todo" con "nada"** (directiva 33). El edge es la pareja `Todo`↔`Ninguno`: si el motor
    /// las intercambiara, `Ninguno` caería en `sin_filtro` —la fuga exacta que el método
    /// existe para imposibilitar—. Cada rama devuelve un marcador distinto para atraparlo.
    #[test]
    fn materializar_llama_la_rama_correcta_y_no_confunde_todo_con_nada() {
        let marca = |a: &AlcanceEfectivo<Org>| {
            a.materializar(
                || "SIN_FILTRO".to_string(),
                |xs: &[Org]| format!("INCLUIR:{xs:?}"),
                |xs: &[Org]| format!("EXCLUIR:{xs:?}"),
                || "IMPOSIBLE".to_string(),
            )
        };
        assert_eq!(marca(&AlcanceEfectivo::Todo), "SIN_FILTRO");
        assert_eq!(marca(&AlcanceEfectivo::Ninguno), "IMPOSIBLE");
        assert_eq!(marca(&AlcanceEfectivo::Conjunto(vec![Org::A])), "INCLUIR:[A]");
        assert_eq!(marca(&AlcanceEfectivo::TodoExcepto(vec![Org::B])), "EXCLUIR:[B]");
        // El edge explícito: Ninguno NUNCA es sin_filtro, Todo NUNCA es imposible.
        assert_ne!(marca(&AlcanceEfectivo::Ninguno), "SIN_FILTRO", "Ninguno como sin-filtro sería la fuga");
        assert_ne!(marca(&AlcanceEfectivo::Todo), "IMPOSIBLE");
    }

    /// **La fusión de verdad: `materializar` reproduce el `WHERE` de los 5 sitios de informes
    /// con UNA llamada**, en vez del `match` repetido, y de paso le regala a informes el
    /// multi-ámbito que hoy no puede expresar. `Todo` sin filtro, `DeUsuario`/`DeStakeholder`
    /// como sus predicados (igualdad y `EXISTS` N:M), `Ninguno` como `0`.
    #[test]
    fn materializar_reproduce_el_where_de_informes() {
        #[derive(Debug, Clone, PartialEq, Eq)]
        enum Ambito {
            Usuario(i64),
            Stakeholder(i64),
        }
        let pred = |a: &Ambito| match a {
            Ambito::Usuario(id) => format!("usuario_id = {id}"),
            Ambito::Stakeholder(id) => {
                format!("EXISTS (SELECT 1 FROM participacion p WHERE p.stakeholder_id = {id})")
            }
        };
        let unir = |xs: &[Ambito]| xs.iter().map(pred).collect::<Vec<_>>().join(" OR ");
        let where_de = |a: &AlcanceEfectivo<Ambito>| {
            a.materializar(
                String::new,
                |xs: &[Ambito]| format!("WHERE {}", unir(xs)),
                |xs: &[Ambito]| format!("WHERE NOT ({})", unir(xs)),
                || "WHERE 0".to_string(),
            )
        };
        assert_eq!(where_de(&AlcanceEfectivo::Todo), "");
        assert_eq!(where_de(&AlcanceEfectivo::Conjunto(vec![Ambito::Usuario(7)])), "WHERE usuario_id = 7");
        assert_eq!(
            where_de(&AlcanceEfectivo::Conjunto(vec![Ambito::Stakeholder(3)])),
            "WHERE EXISTS (SELECT 1 FROM participacion p WHERE p.stakeholder_id = 3)"
        );
        assert_eq!(where_de(&AlcanceEfectivo::Ninguno), "WHERE 0");
        // El multi-ámbito que la fusión le regala a informes (hoy su Alcance no lo expresa).
        assert_eq!(
            where_de(&AlcanceEfectivo::Conjunto(vec![Ambito::Usuario(7), Ambito::Stakeholder(3)])),
            "WHERE usuario_id = 7 OR EXISTS (SELECT 1 FROM participacion p WHERE p.stakeholder_id = 3)"
        );
    }
}
