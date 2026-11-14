// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **Bachué F3.b — autenticación por passkey (WebAuthn / FIDO2, la *assertion*).**
//!
//! El paso de login sin contraseña: el navegador firma un reto con la clave privada que
//! vive en el autenticador (Touch ID, una llave, el teléfono) y el servidor comprueba la
//! firma contra la clave PÚBLICA que guardó al registrar. Este módulo hace TODO el
//! andamiaje de esa comprobación —lo que la especificación WebAuthn §7.2 llama verificar
//! una assertion— menos un paso: la verificación criptográfica de la firma.
//!
//! # Por qué la firma va detrás de un trait, y no es una excusa
//!
//! La mayoría de las passkeys firman con **ES256 (ECDSA sobre P-256)**; algunas con
//! **EdDSA (Ed25519)** o **RS256**. Medido el 2026-08-30: quipu firma HÍBRIDO
//! (Ed25519 **+** ML-DSA-87, combinador AND) y no expone ninguno de esos tres sueltos —
//! ni siquiera Ed25519 puro—. Verificar una passkey exige, pues, una pieza de cripto que
//! hoy no existe en el universo, y elegirla es una decisión (ampliar quipu con P-256,
//! exponer Ed25519 puro, o traer una dependencia). Mientras se decide, **el andamiaje no
//! espera**: todo lo que NO es la firma —el reto de un solo uso, el `clientDataJSON`, el
//! `authenticatorData`, el hash del RP, las banderas de presencia/verificación y el
//! CONTADOR anti-clonación— es correcto o incorrecto con independencia del esquema, y se
//! prueba entero aquí. La firma entra por [`VerificadorDeFirma`], y el día que se decida
//! el esquema es una `impl` de ese trait, sin tocar este flujo.
//!
//! # Las dos mitades del ciclo
//!
//! Este módulo raíz es la **assertion** (el login): recibe una [`Credencial`] ya registrada
//! y verifica una respuesta de `get()`. El **registro** (el alta, `create()`) vive en
//! [`registro`]: parsea el `attestationObject`/COSE de la clave nueva y produce la
//! [`Credencial`] —incluida la conversión COSE→SEC1 que el verificador de firma espera—.
//! El registro NO verifica la cadena de attestation (ver su cabecera): es la política
//! estándar para passkeys de consumidor.
//!
//! # El contrato con el servicio (sin estado, como todo Bachué)
//!
//! 1. **El reto es de un solo uso, y eso lo garantizas TÚ.** Genera un [`Desafio`],
//!    guárdalo ligado a esta ceremonia de login, y BÓRRALO en cuanto se use —aceptado o
//!    no—. Un reto que se acepta dos veces es un replay; este módulo comprueba que el
//!    reto COINCIDE, no que sea fresco (no tiene estado para saberlo).
//! 2. **Persiste `contador_nuevo`** de [`Assertion::Aceptada`]. Es la única defensa
//!    contra un autenticador CLONADO: si no lo guardas, el contador nunca avanza en tu
//!    base y la detección de clon (paso 6) queda ciega.
//! 3. **Carga la [`Credencial`] por el `id` que trae la respuesta**, y que sea del
//!    usuario que dice ser: como en el segundo factor, el andamiaje es tan bueno como el
//!    emparejamiento credencial↔usuario que hagas.

#![forbid(unsafe_code)]

mod cbor;
pub mod registro;

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

// ── El reto (challenge) ──────────────────────────────────────────────────────

/// Un reto para una ceremonia de login. 32 bytes de azar: el autenticador lo firma
/// (dentro del `clientDataJSON`) y así la firma no sirve para otra ceremonia.
pub struct Desafio(Vec<u8>);

impl Desafio {
    /// Un reto nuevo, 32 bytes de `OsRng`. 256 bits: irrepetible en la práctica, que es
    /// lo que impide reutilizar una respuesta capturada.
    pub fn nuevo() -> Self {
        let mut b = vec![0u8; 32];
        OsRng.fill_bytes(&mut b);
        Self(b)
    }

    /// Reconstruye un reto desde los bytes que el servicio guardó (para comparar contra
    /// lo que vuelve del navegador). No genera azar: es el reto que YA se emitió.
    pub fn desde_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Los bytes crudos, para guardarlos ligados a la ceremonia.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    /// El reto tal como viajará dentro del `clientDataJSON`: base64url SIN relleno, que es
    /// como WebAuthn codifica los `BufferSource`. Comparar contra esto evita decodificar
    /// lo que manda el cliente.
    pub fn como_b64url(&self) -> String {
        b64url_sin_relleno(&self.0)
    }
}

/// base64url (RFC 4648 §5) sin relleno. Propio, porque es trivial y ahorra una
/// dependencia: WebAuthn codifica así los buffers del `clientDataJSON`.
pub(crate) fn b64url_sin_relleno(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for trozo in bytes.chunks(3) {
        let b0 = trozo[0];
        s.push(T[(b0 >> 2) as usize] as char);
        match trozo.len() {
            1 => s.push(T[((b0 & 0b11) << 4) as usize] as char),
            2 => {
                let b1 = trozo[1];
                s.push(T[(((b0 & 0b11) << 4) | (b1 >> 4)) as usize] as char);
                s.push(T[((b1 & 0b1111) << 2) as usize] as char);
            }
            _ => {
                let (b1, b2) = (trozo[1], trozo[2]);
                s.push(T[(((b0 & 0b11) << 4) | (b1 >> 4)) as usize] as char);
                s.push(T[(((b1 & 0b1111) << 2) | (b2 >> 6)) as usize] as char);
                s.push(T[(b2 & 0b111111) as usize] as char);
            }
        }
    }
    s
}

// ── La clave pública y su algoritmo ──────────────────────────────────────────

/// Los bytes de la clave pública tal como se guardaron al registrar (formato COSE_Key).
/// Opaca para este módulo: quien la interpreta es el [`VerificadorDeFirma`], que es quien
/// sabe de qué curva es. Aquí solo viaja de la base al verificador.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClavePublicaCose(pub Vec<u8>);

/// El algoritmo de firma de una credencial, por su identificador COSE (RFC 9053). Se fija
/// al registrar y no cambia. El [`VerificadorDeFirma`] lo recibe para elegir la curva; un
/// algoritmo que el verificador no soporte es una firma que no casa, no un pánico.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algoritmo {
    /// ECDSA sobre P-256 con SHA-256. COSE alg −7. El de la mayoría de las passkeys.
    Es256,
    /// EdDSA sobre Ed25519. COSE alg −8.
    EdDSA,
    /// RSASSA-PKCS1-v1_5 con SHA-256. COSE alg −257.
    Rs256,
}

/// **La verificación criptográfica de la firma — el único paso que este módulo NO hace.**
/// Es la costura por la que entra la decisión de cripto (ver la cabecera). Una `impl` de
/// este trait sabe interpretar la [`ClavePublicaCose`] según el [`Algoritmo`] y decir si
/// `firma` es una firma válida de `mensaje` bajo esa clave.
///
/// El `mensaje` que se le entrega es exactamente el que manda WebAuthn §7.2 paso 17:
/// `authenticatorData ‖ SHA-256(clientDataJSON)`. Lo arma este módulo; el verificador solo
/// comprueba. Devolver `false` ante un algoritmo no soportado o una clave ilegible es
/// correcto: es una firma que no verifica, y el flujo la trata como tal (fail-closed).
pub trait VerificadorDeFirma {
    /// `true` solo si `firma` es una firma válida de `mensaje` bajo `clave` con `alg`.
    fn verificar(&self, alg: Algoritmo, clave: &ClavePublicaCose, mensaje: &[u8], firma: &[u8]) -> bool;
}

// ── La credencial registrada ─────────────────────────────────────────────────

/// Una passkey ya registrada de un usuario, tal como la guarda el servicio.
#[derive(Clone, Debug)]
pub struct Credencial {
    /// El identificador de la credencial (el `id` que devuelve el navegador). Por él se
    /// carga esta fila.
    pub id: Vec<u8>,
    /// La clave pública con la que se verifica la firma.
    pub clave: ClavePublicaCose,
    /// El algoritmo fijado al registrar.
    pub alg: Algoritmo,
    /// El último contador de firma visto. La defensa anti-clonación (paso 6) exige que el
    /// de cada assertion AVANCE respecto de éste.
    pub contador: u32,
}

// ── Política de la ceremonia ─────────────────────────────────────────────────

/// Qué exige esta ceremonia de login. La presencia de usuario (un toque) es SIEMPRE
/// obligatoria en WebAuthn y no se configura; lo que se elige es si además se exige
/// VERIFICACIÓN de usuario (PIN/biometría), que es lo que sube una passkey de "algo que
/// tienes" a "dos factores en un gesto".
#[derive(Clone, Copy, Debug)]
pub struct Politica {
    /// Exigir el bit UV (usuario verificado con PIN o biometría), no solo presente.
    pub exigir_verificacion_usuario: bool,
}

impl Default for Politica {
    fn default() -> Self {
        // Por defecto se exige verificación: una passkey que verifica al usuario es un
        // login de dos factores en un solo gesto, que es su razón de ser aquí.
        Self { exigir_verificacion_usuario: true }
    }
}

// ── Datos parseados ──────────────────────────────────────────────────────────

/// Lo que interesa del `clientDataJSON` (el JSON que el navegador firma indirectamente).
pub(crate) struct DatosCliente {
    pub(crate) tipo: String,
    /// El reto, en base64url sin relleno tal como lo pone el navegador.
    pub(crate) desafio_b64: String,
    pub(crate) origen: String,
}

/// Parsea el `clientDataJSON` sin arrastrar un parser de JSON completo: solo extrae tres
/// campos de cadena de un objeto plano. Es JSON UTF-8 producido por el navegador; se leen
/// `type`, `challenge` y `origin`. `None` si no es UTF-8 o falta alguno.
///
/// # Por qué una búsqueda de subcadenas es segura AQUÍ, y de qué depende
///
/// La spec advierte contra parsear el `clientDataJSON` por subcadenas o regex. Lo que hace
/// legítimo el atajo es una invariante *load-bearing*: **el MISMO buffer que se parsea aquí
/// es el que se hashea para el mensaje firmado** (`Sha256::digest(client_data_json)` en
/// [`verificar_assertion`]), y esa firma se verifica. Un atacante sin la clave no puede
/// alterar un byte sin invalidar la firma; y uno que SÍ firma (el dueño de la credencial
/// autenticándose como sí mismo) no gana nada confundiendo el parser, porque igual tiene
/// que producir el `challenge` correcto y `origin == esperado`. La seguridad la aporta la
/// FIRMA, no la finura del parser. **Si algún día se parsea sobre bytes distintos de los
/// firmados, o ANTES de tener el binding de firma (p. ej. para un log temprano), esta
/// clase de confusión pasa de inerte a explotable**: entonces hace falta un tokenizador
/// que solo acepte claves en posición de clave. Hoy no.
pub(crate) fn parsear_datos_cliente(json: &[u8]) -> Option<DatosCliente> {
    let texto = core::str::from_utf8(json).ok()?;
    Some(DatosCliente {
        tipo: campo_de_cadena(texto, "type")?,
        desafio_b64: campo_de_cadena(texto, "challenge")?,
        origen: campo_de_cadena(texto, "origin")?,
    })
}

/// Extrae el valor de cadena de `"clave":"valor"` de un JSON plano. Busca `"clave"`, salta
/// hasta las comillas de apertura del valor y lee hasta las de cierre, respetando el
/// escape `\"`. No interpreta objetos anidados —el `clientDataJSON` de WebAuthn es plano
/// en estos tres campos— y devuelve `None` si algo no cuadra (directiva 20: ante lo que no
/// sabe leer, no inventa).
fn campo_de_cadena(json: &str, clave: &str) -> Option<String> {
    let patron = format!("\"{clave}\"");
    let inicio = json.find(&patron)? + patron.len();
    let resto = &json[inicio..];
    let dos_puntos = resto.find(':')?;
    let tras = &resto[dos_puntos + 1..];
    let abre = tras.find('"')?;
    let cuerpo = &tras[abre + 1..];
    let mut valor = String::new();
    let mut escapando = false;
    for c in cuerpo.chars() {
        if escapando {
            // Sólo se necesita desescapar la comilla y la barra; el resto es literal para
            // los tres campos que se leen (no hay unicode escapado en type/origin, y el
            // challenge es base64url que no lleva caracteres a escapar).
            valor.push(c);
            escapando = false;
        } else if c == '\\' {
            escapando = true;
        } else if c == '"' {
            return Some(valor);
        } else {
            valor.push(c);
        }
    }
    None // comilla de cierre no encontrada
}

/// Los campos del `authenticatorData` que decide una assertion. Los 37 bytes fijos del
/// principio: `rpIdHash[32] ‖ flags[1] ‖ signCount[4]`. Lo que venga después (datos de
/// credencial con attestación, extensiones) no se necesita para el login y se ignora.
pub struct DatosAutenticador {
    rp_id_hash: [u8; 32],
    /// User Present: hubo un gesto (bit 0). WebAuthn lo exige siempre.
    presente: bool,
    /// User Verified: PIN o biometría (bit 2).
    verificado: bool,
    contador: u32,
}

/// Parsea los 37 bytes fijos del `authenticatorData`. `None` si hay menos de 37 (no puede
/// ser un authenticatorData válido).
fn parsear_datos_autenticador(bytes: &[u8]) -> Option<DatosAutenticador> {
    if bytes.len() < 37 {
        return None;
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&bytes[0..32]);
    let flags = bytes[32];
    let contador = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
    Some(DatosAutenticador {
        rp_id_hash,
        presente: flags & 0b0000_0001 != 0, // bit 0 = UP
        verificado: flags & 0b0000_0100 != 0, // bit 2 = UV
        contador,
    })
}

// ── El resultado ─────────────────────────────────────────────────────────────

/// El veredicto de verificar una assertion. `Aceptada` trae el contador a persistir; las
/// razones de `Rechazada` son para el LOG del servicio, no para el cliente —que recibe un
/// "no" genérico—: distinguir "firma inválida" de "contador retrocede" ayuda a operar (un
/// contador que retrocede es un posible clon, no un error de usuario).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assertion {
    /// Todo cuadró. Persiste `contador_nuevo` como el nuevo [`Credencial::contador`].
    Aceptada { contador_nuevo: u32 },
    /// No se acepta, por este motivo.
    Rechazada(Motivo),
}

impl Assertion {
    /// ¿Abre? Solo `Aceptada`.
    pub fn abre(&self) -> bool {
        matches!(self, Assertion::Aceptada { .. })
    }
}

/// Por qué se rechazó una assertion. Cada variante es un paso distinto de la verificación
/// WebAuthn §7.2, en el orden en que se comprueban.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Motivo {
    /// El `clientDataJSON` o el `authenticatorData` no se pudieron leer.
    DatosIlegibles,
    /// `clientData.type` no es `"webauthn.get"` (una assertion; `.create` es registro).
    TipoIncorrecto,
    /// El reto firmado no es el que se emitió para esta ceremonia.
    DesafioNoCoincide,
    /// El `origin` firmado no es el del servicio: la respuesta se produjo en otro sitio.
    OrigenNoCoincide,
    /// El hash del RP no casa: la credencial es de otro dominio (Relying Party).
    RpIdNoCoincide,
    /// No hubo gesto de presencia (bit UP en cero). WebAuthn nunca lo admite.
    UsuarioNoPresente,
    /// La política exigía verificación (PIN/biometría) y el bit UV está en cero.
    UsuarioNoVerificado,
    /// El contador no avanzó: **posible autenticador clonado**. Ver [`verificar_assertion`].
    ContadorRetrocede,
    /// La firma no verifica bajo la clave pública de la credencial.
    FirmaInvalida,
}

/// **Verifica una assertion de WebAuthn: el login por passkey completo, en el orden de la
/// especificación §7.2.** Fail-closed: cualquier paso que no cuadre devuelve
/// [`Assertion::Rechazada`] con su motivo, y solo si TODOS pasan hay `Aceptada`.
///
/// El contador anti-clonación (§7.2 paso 22) es la defensa que no tiene el resto: cada
/// autenticador lleva un contador de firmas que solo sube. Si llega una assertion con un
/// contador que **no avanza** respecto del guardado, o la clave se copió a otro dispositivo
/// o la respuesta es un replay: en los dos casos se rechaza. La única excepción es que
/// ambos sean cero, que es el autenticador que declara no llevar contador (legítimo, y
/// entonces esta defensa simplemente no aplica).
///
/// La firma se comprueba en el paso §7.2 21, sobre `authenticatorData ‖ SHA-256(clientDataJSON)`.
/// Aquí el contador va antes que la firma; el orden no abre ningún hueco (un contador
/// firmado por un atacante sin la clave cae igual en la verificación de firma), y a cambio
/// deja los motivos de rechazo ordenados de lo barato a lo caro.
#[allow(clippy::too_many_arguments)] // son los insumos de la ceremonia WebAuthn; agruparlos en un struct no reduce el acoplamiento, solo lo esconde.
pub fn verificar_assertion(
    cred: &Credencial,
    desafio_esperado: &Desafio,
    origen_esperado: &str,
    rp_id: &str,
    client_data_json: &[u8],
    authenticator_data: &[u8],
    firma: &[u8],
    politica: &Politica,
    verificador: &dyn VerificadorDeFirma,
) -> Assertion {
    use Motivo::*;
    macro_rules! no {
        ($m:expr) => {
            return Assertion::Rechazada($m)
        };
    }

    // Paso 1 — leer clientData.
    let Some(cliente) = parsear_datos_cliente(client_data_json) else { no!(DatosIlegibles) };
    // Paso 2 — es una assertion.
    if cliente.tipo != "webauthn.get" {
        no!(TipoIncorrecto)
    }
    // Paso 3 — el reto es el de esta ceremonia.
    if !iguales_en_tiempo_constante(cliente.desafio_b64.as_bytes(), desafio_esperado.como_b64url().as_bytes()) {
        no!(DesafioNoCoincide)
    }
    // Paso 4 — el origen es el nuestro.
    if cliente.origen != origen_esperado {
        no!(OrigenNoCoincide)
    }
    // Paso 5 — leer authenticatorData y comprobar RP y banderas.
    let Some(auth) = parsear_datos_autenticador(authenticator_data) else { no!(DatosIlegibles) };
    if auth.rp_id_hash != Sha256::digest(rp_id.as_bytes()).as_slice() {
        no!(RpIdNoCoincide)
    }
    if !auth.presente {
        no!(UsuarioNoPresente)
    }
    if politica.exigir_verificacion_usuario && !auth.verificado {
        no!(UsuarioNoVerificado)
    }
    // Contador anti-clonación (§7.2 paso 22). Solo se exige avance si alguno no es 0.
    if (auth.contador != 0 || cred.contador != 0) && auth.contador <= cred.contador {
        no!(ContadorRetrocede)
    }
    // La firma (§7.2 paso 21), sobre authenticatorData ‖ SHA-256(clientDataJSON).
    let mut mensaje = Vec::with_capacity(authenticator_data.len() + 32);
    mensaje.extend_from_slice(authenticator_data);
    mensaje.extend_from_slice(Sha256::digest(client_data_json).as_slice());
    if !verificador.verificar(cred.alg, &cred.clave, &mensaje, firma) {
        no!(FirmaInvalida)
    }
    Assertion::Aceptada { contador_nuevo: auth.contador }
}

/// Comparación que no filtra por cuántos bytes acertó. El reto no es secreto, pero
/// compararlo con `==` sobre bytes termina en la primera diferencia, y no cuesta nada
/// evitarlo (misma pieza que usa guaca en el TOTP).
pub(crate) fn iguales_en_tiempo_constante(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// **El verificador de firma de PRUEBA.** No es cripto de verdad —la de verdad es la
    /// decisión pendiente—: es un oráculo DETERMINISTA que acepta `firma` sólo si es
    /// `SHA-256(clave ‖ mensaje)`. Su único trabajo es probar que el andamiaje (a) arma el
    /// `mensaje` EXACTO de la spec y (b) respeta el veredicto. Si el flujo armara mal el
    /// mensaje —olvidara el hash del clientData, o concatenara al revés—, la firma buena
    /// dejaría de casar y los verdes se pondrían rojos. Discrimina por construcción.
    struct VerificadorDePrueba;
    impl VerificadorDeFirma for VerificadorDePrueba {
        fn verificar(&self, _alg: Algoritmo, clave: &ClavePublicaCose, mensaje: &[u8], firma: &[u8]) -> bool {
            let mut h = Sha256::new();
            h.update(&clave.0);
            h.update(mensaje);
            iguales_en_tiempo_constante(firma, h.finalize().as_slice())
        }
    }

    /// Produce la firma que `VerificadorDePrueba` aceptará para estos datos, armando el
    /// mensaje IGUAL que la spec. Es el "autenticador honesto" del arnés.
    fn firmar_de_prueba(clave: &ClavePublicaCose, authenticator_data: &[u8], client_data_json: &[u8]) -> Vec<u8> {
        let mut mensaje = Vec::new();
        mensaje.extend_from_slice(authenticator_data);
        mensaje.extend_from_slice(Sha256::digest(client_data_json).as_slice());
        let mut h = Sha256::new();
        h.update(&clave.0);
        h.update(&mensaje);
        h.finalize().to_vec()
    }

    const RP_ID: &str = "cuenta.xiliux.com";
    const ORIGEN: &str = "https://cuenta.xiliux.com";

    fn client_data(tipo: &str, desafio_b64: &str, origen: &str) -> Vec<u8> {
        format!("{{\"type\":\"{tipo}\",\"challenge\":\"{desafio_b64}\",\"origin\":\"{origen}\",\"crossOrigin\":false}}")
            .into_bytes()
    }

    /// Construye un authenticatorData de 37 bytes con el rpIdHash de RP_ID, las banderas
    /// dadas y el contador dado.
    fn auth_data(up: bool, uv: bool, contador: u32) -> Vec<u8> {
        let mut b = Vec::with_capacity(37);
        b.extend_from_slice(Sha256::digest(RP_ID.as_bytes()).as_slice());
        let mut flags = 0u8;
        if up {
            flags |= 0b0000_0001;
        }
        if uv {
            flags |= 0b0000_0100;
        }
        b.push(flags);
        b.extend_from_slice(&contador.to_be_bytes());
        b
    }

    fn credencial(contador: u32) -> Credencial {
        Credencial {
            id: b"cred-de-prueba".to_vec(),
            clave: ClavePublicaCose(b"clave-publica-de-prueba".to_vec()),
            alg: Algoritmo::Es256,
            contador,
        }
    }

    /// Una ceremonia HONESTA completa termina en `Aceptada` con el contador nuevo — y es
    /// el positivo de control de todos los casos rojos: si esto no abriera, un rojo no
    /// probaría nada.
    #[test]
    fn una_assertion_honesta_abre_y_avanza_el_contador() {
        let cred = credencial(5);
        let desafio = Desafio::nuevo();
        let ad = auth_data(true, true, 6);
        let cd = client_data("webauthn.get", &desafio.como_b64url(), ORIGEN);
        let firma = firmar_de_prueba(&cred.clave, &ad, &cd);

        let r = verificar_assertion(
            &cred, &desafio, ORIGEN, RP_ID, &cd, &ad, &firma, &Politica::default(), &VerificadorDePrueba,
        );
        assert_eq!(r, Assertion::Aceptada { contador_nuevo: 6 });
        assert!(r.abre());
    }

    /// **EL EDGE ANTI-CLONACIÓN (directiva 33).** Un autenticador clonado firma con el
    /// MISMO contador (o uno menor) que ya se vio. Con el contador guardado en 6: una
    /// assertion perfecta en todo lo demás pero con contador 6 (igual) o 5 (menor) se
    /// RECHAZA por `ContadorRetrocede`; con 7 (avanza) se acepta. Sin esta comprobación,
    /// una passkey copiada a dos dispositivos pasaría inadvertida.
    #[test]
    fn un_contador_que_no_avanza_es_un_clon() {
        let cred = credencial(6);
        let desafio = Desafio::nuevo();
        let cd = client_data("webauthn.get", &desafio.como_b64url(), ORIGEN);
        let correr = |contador: u32| {
            let ad = auth_data(true, true, contador);
            let firma = firmar_de_prueba(&cred.clave, &ad, &cd);
            verificar_assertion(&cred, &desafio, ORIGEN, RP_ID, &cd, &ad, &firma, &Politica::default(), &VerificadorDePrueba)
        };
        assert_eq!(correr(6), Assertion::Rechazada(Motivo::ContadorRetrocede), "mismo contador = clon");
        assert_eq!(correr(5), Assertion::Rechazada(Motivo::ContadorRetrocede), "contador menor = clon");
        assert!(correr(7).abre(), "contador que avanza = legítimo");
    }

    /// Un autenticador que declara NO llevar contador (0 → 0) es legítimo: la defensa no
    /// aplica en vez de bloquearlo. Su pareja: 0 guardado y 0 nuevo abre, pero una vez que
    /// el contador arrancó (guardado > 0) un 0 nuevo retrocede.
    #[test]
    fn contador_cero_a_cero_se_admite_pero_no_un_retroceso_a_cero() {
        let desafio = Desafio::nuevo();
        let cd = client_data("webauthn.get", &desafio.como_b64url(), ORIGEN);
        let abrir = |guardado: u32, nuevo: u32| {
            let cred = credencial(guardado);
            let ad = auth_data(true, true, nuevo);
            let firma = firmar_de_prueba(&cred.clave, &ad, &cd);
            verificar_assertion(&cred, &desafio, ORIGEN, RP_ID, &cd, &ad, &firma, &Politica::default(), &VerificadorDePrueba).abre()
        };
        assert!(abrir(0, 0), "un autenticador sin contador (0→0) es legítimo");
        assert!(!abrir(3, 0), "pero tras arrancar, un 0 es un retroceso");
    }

    /// **La firma se comprueba de verdad, y sobre el mensaje EXACTO de la spec.** Una
    /// firma que no casa se rechaza (control negativo). Y —lo que ata el mensaje— una
    /// firma buena para OTRO clientData (otro origen) tampoco abre: el hash del clientData
    /// entra en el mensaje, así que cambiar un byte del clientData invalida la firma.
    #[test]
    fn la_firma_cubre_el_mensaje_entero() {
        let cred = credencial(1);
        let desafio = Desafio::nuevo();
        let ad = auth_data(true, true, 2);
        let cd = client_data("webauthn.get", &desafio.como_b64url(), ORIGEN);

        // Firma basura: rechazada.
        let r = verificar_assertion(&cred, &desafio, ORIGEN, RP_ID, &cd, &ad, b"no-es-firma", &Politica::default(), &VerificadorDePrueba);
        assert_eq!(r, Assertion::Rechazada(Motivo::FirmaInvalida));

        // Firma VÁLIDA para un clientData con otro origen: como ese origen no es el
        // esperado, primero cae por OrigenNoCoincide; y si forzáramos el origen, la firma
        // no cubriría este clientData. Se comprueba la segunda mitad directamente: firmar
        // un clientData y verificar contra otro.
        let cd_otro = client_data("webauthn.get", &desafio.como_b64url(), "https://malo.example");
        let firma_de_otro = firmar_de_prueba(&cred.clave, &ad, &cd_otro);
        let r2 = verificar_assertion(&cred, &desafio, ORIGEN, RP_ID, &cd, &ad, &firma_de_otro, &Politica::default(), &VerificadorDePrueba);
        assert_eq!(r2, Assertion::Rechazada(Motivo::FirmaInvalida), "una firma de otro clientData no vale");
    }

    /// Cada validación estructural rechaza por SU motivo, y su pareja verde (la honesta de
    /// arriba) abre. Un banco de solo-rojos sobre datos que igual fallan no discriminaría
    /// (directiva 33): por eso cada caso cambia UNA cosa respecto de la ceremonia honesta.
    #[test]
    fn cada_validacion_estructural_tiene_su_motivo() {
        let cred = credencial(0);
        let desafio = Desafio::nuevo();
        let bueno_ad = auth_data(true, true, 1);
        let firmar = |ad: &[u8], cd: &[u8]| firmar_de_prueba(&cred.clave, ad, cd);

        // tipo incorrecto (webauthn.create en vez de .get)
        let cd = client_data("webauthn.create", &desafio.como_b64url(), ORIGEN);
        let f = firmar(&bueno_ad, &cd);
        assert_eq!(
            verificar_assertion(&cred, &desafio, ORIGEN, RP_ID, &cd, &bueno_ad, &f, &Politica::default(), &VerificadorDePrueba),
            Assertion::Rechazada(Motivo::TipoIncorrecto)
        );

        // reto que no coincide
        let cd = client_data("webauthn.get", &Desafio::nuevo().como_b64url(), ORIGEN);
        let f = firmar(&bueno_ad, &cd);
        assert_eq!(
            verificar_assertion(&cred, &desafio, ORIGEN, RP_ID, &cd, &bueno_ad, &f, &Politica::default(), &VerificadorDePrueba),
            Assertion::Rechazada(Motivo::DesafioNoCoincide)
        );

        // origen que no coincide
        let cd = client_data("webauthn.get", &desafio.como_b64url(), "https://phishing.example");
        let f = firmar(&bueno_ad, &cd);
        assert_eq!(
            verificar_assertion(&cred, &desafio, ORIGEN, RP_ID, &cd, &bueno_ad, &f, &Politica::default(), &VerificadorDePrueba),
            Assertion::Rechazada(Motivo::OrigenNoCoincide)
        );

        // rpId que no coincide (authData con el hash de otro RP)
        let cd = client_data("webauthn.get", &desafio.como_b64url(), ORIGEN);
        let mut ad_otro_rp = bueno_ad; // último uso de bueno_ad: se mueve, no se clona
        ad_otro_rp[0..32].copy_from_slice(Sha256::digest(b"otra.example".as_slice()).as_slice());
        let f = firmar_de_prueba(&cred.clave, &ad_otro_rp, &cd);
        assert_eq!(
            verificar_assertion(&cred, &desafio, ORIGEN, RP_ID, &cd, &ad_otro_rp, &f, &Politica::default(), &VerificadorDePrueba),
            Assertion::Rechazada(Motivo::RpIdNoCoincide)
        );

        // sin presencia de usuario (UP=0)
        let ad_sin_up = auth_data(false, true, 1);
        let f = firmar_de_prueba(&cred.clave, &ad_sin_up, &cd);
        assert_eq!(
            verificar_assertion(&cred, &desafio, ORIGEN, RP_ID, &cd, &ad_sin_up, &f, &Politica::default(), &VerificadorDePrueba),
            Assertion::Rechazada(Motivo::UsuarioNoPresente)
        );

        // presente pero no verificado, con política que lo exige
        let ad_sin_uv = auth_data(true, false, 1);
        let f = firmar_de_prueba(&cred.clave, &ad_sin_uv, &cd);
        assert_eq!(
            verificar_assertion(&cred, &desafio, ORIGEN, RP_ID, &cd, &ad_sin_uv, &f, &Politica::default(), &VerificadorDePrueba),
            Assertion::Rechazada(Motivo::UsuarioNoVerificado)
        );
        // …y con política que NO lo exige, ese mismo caso abre (la pareja).
        let flexible = Politica { exigir_verificacion_usuario: false };
        assert!(
            verificar_assertion(&cred, &desafio, ORIGEN, RP_ID, &cd, &ad_sin_uv, &f, &flexible, &VerificadorDePrueba).abre(),
            "sin exigir UV, presente basta"
        );

        // authData truncado (menos de 37 bytes) → ilegible
        let corto = vec![0u8; 20];
        let f = firmar_de_prueba(&cred.clave, &corto, &cd);
        assert_eq!(
            verificar_assertion(&cred, &desafio, ORIGEN, RP_ID, &cd, &corto, &f, &Politica::default(), &VerificadorDePrueba),
            Assertion::Rechazada(Motivo::DatosIlegibles)
        );
    }

    /// base64url sin relleno, contra vectores del RFC 4648 (y el caso del `-_` que lo
    /// distingue de base64 estándar). Sin esto, un encode con alfabeto estándar (`+/`)
    /// haría que el reto no casara nunca contra el del navegador.
    #[test]
    fn b64url_coincide_con_el_rfc() {
        assert_eq!(b64url_sin_relleno(b""), "");
        assert_eq!(b64url_sin_relleno(b"f"), "Zg");
        assert_eq!(b64url_sin_relleno(b"fo"), "Zm8");
        assert_eq!(b64url_sin_relleno(b"foo"), "Zm9v");
        assert_eq!(b64url_sin_relleno(b"foobar"), "Zm9vYmFy");
        // Bytes altos: base64 estándar daría "+/8=", base64url da "-_8" (sin relleno).
        assert_eq!(b64url_sin_relleno(&[0xfb, 0xff]), "-_8");
    }

    /// El parser de clientData lee los tres campos aunque el orden cambie y haya campos de
    /// más, y desescapa `\"`. Su pareja: un JSON sin uno de los campos da `None`.
    #[test]
    fn el_parser_de_clientdata_lee_los_campos_y_falla_si_falta() {
        let json = br#"{"origin":"https://a.b","extra":1,"type":"webauthn.get","challenge":"abc"}"#;
        let d = parsear_datos_cliente(json).expect("los tres campos están");
        assert_eq!(d.tipo, "webauthn.get");
        assert_eq!(d.desafio_b64, "abc");
        assert_eq!(d.origen, "https://a.b");
        // falta challenge
        assert!(parsear_datos_cliente(br#"{"type":"webauthn.get","origin":"x"}"#).is_none());
    }
}
