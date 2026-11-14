// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **La IP del cliente, de verdad.** Alimenta el `origen` de `guaca::freno`.
//!
//! `X-Forwarded-For` es una lista `cliente, proxy1, proxy2, …` donde cada proxy AÑADE
//! a la derecha la dirección de quien le habló. Sólo las entradas de la derecha las
//! escribió tu infraestructura; las de la izquierda las pudo poner el cliente. De ahí
//! los dos errores simétricos y su consecuencia sobre el freno:
//!
//! - Confiar en la IP del **socket** detrás de un proxy → todas las peticiones
//!   comparten la IP del proxy → el freno por `(correo, origen)` ya no distingue
//!   quién ataca, y frena a todos juntos o a nadie.
//! - Confiar en el extremo **izquierdo** de `X-Forwarded-For` → el atacante lo
//!   falsea y estrena un origen en cada intento → nunca llega al umbral → evade el
//!   freno por completo.
//!
//! La regla correcta es contar: con `t` proxies de confianza, la IP real del cliente
//! es la que queda justo a la izquierda de esas `t` entradas creíbles, en el índice
//! `len - t`. Cuanto más a la izquierda, más controlable por el cliente, y se ignora.

use std::net::IpAddr;
use std::str::FromStr;

/// Cuántos proxies inversos PROPIOS y de confianza hay entre el cliente y el servidor
/// de la app. Es el único parámetro de seguridad del módulo: fija cuántas entradas de
/// la derecha de `X-Forwarded-For` las puso tu infraestructura y por tanto se creen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Confianza {
    saltos: usize,
}

impl Confianza {
    /// `saltos` = número de proxies inversos de confianza delante de la app. **Cero**
    /// significa "sin proxy": la única fuente creíble es la IP del socket, y TODA
    /// cabecera `X-Forwarded-For` se ignora (la pone entera el cliente).
    ///
    /// **`saltos` debe ser EXACTO, y sobreestimarlo es peor que quedarse corto.**
    /// Quedarse corto pierde precisión (se devuelve la IP de un proxy y varios clientes
    /// comparten cubo de freno). Pasarse habilita FORJA: si hay 1 proxy real y se fija
    /// `con_saltos(2)`, un atacante que manda `X-Forwarded-For: A, B` hace que la app
    /// vea `A, B, <ip_real>` y `ip_de_reenvio` devuelva `B` —de su elección— con lo que
    /// estrena cubo de freno en cada intento e incrimina IPs ajenas. El número tiene que
    /// salir de la TOPOLOGÍA de despliegue (cuántos proxies añaden de verdad a la
    /// cadena), no ponerse a ojo.
    #[must_use]
    pub const fn con_saltos(saltos: usize) -> Self {
        Self { saltos }
    }

    #[must_use]
    pub const fn saltos(self) -> usize {
        self.saltos
    }
}

/// La IP del cliente, o la constancia RUIDOSA de que no se pudo determinar.
///
/// Nunca se inventa un valor por defecto (directiva 20): un `Desconocida` que la app
/// decida convertir en algo es decisión suya, a la vista, no un relleno mío que
/// parezca una IP real.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpCliente {
    Conocida(IpAddr),
    Desconocida,
}

impl IpCliente {
    #[must_use]
    pub fn conocida(self) -> Option<IpAddr> {
        match self {
            Self::Conocida(ip) => Some(ip),
            Self::Desconocida => None,
        }
    }

    /// El `origen` para `guaca::freno`, como cadena. Cuando la IP no se conoce se
    /// devuelve un centinela EXPLÍCITO —no una IP falsa— que además NO es una
    /// dirección válida: así todos los clientes de IP desconocida caen en el mismo
    /// cubo del freno (fail-closed) en vez de quedar cada uno libre. Como el freno
    /// también entra por `correo`, dos cuentas distintas no colisionan por esto: sólo
    /// comparten cubo los intentos de UNA cuenta desde orígenes que no supimos leer.
    #[must_use]
    pub fn como_origen(self) -> String {
        match self {
            Self::Conocida(ip) => ip.to_string(),
            Self::Desconocida => "origen-desconocido".to_string(),
        }
    }
}

/// Extrae la IP del cliente de `X-Forwarded-For` sabiendo cuántos proxies de confianza
/// lo han ido rellenando. Ver la cabecera del módulo para el porqué del índice.
///
/// Devuelve `Desconocida` (ruidoso, directiva 20) cuando:
/// - no hay proxies de confianza (`saltos == 0`): entonces `X-Forwarded-For` es 100 %
///   del cliente y esta vía no aplica —usa la IP del socket—;
/// - no llega la cabecera;
/// - la cadena es más corta que los `t` saltos esperados (truncada o mal configurada);
/// - la entrada del cliente no es una IP parseable.
#[must_use]
pub fn ip_de_reenvio(xff: Option<&str>, confianza: Confianza) -> IpCliente {
    let t = confianza.saltos;
    if t == 0 {
        return IpCliente::Desconocida;
    }
    let Some(xff) = xff else {
        return IpCliente::Desconocida;
    };
    let lista: Vec<&str> = xff
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    // La cadena legítima mide EXACTAMENTE `t` (cliente + los proxies que añaden). Si
    // mide menos, algo falta y no se adivina. Si mide más, las sobrantes están a la
    // IZQUIERDA y el índice `len - t` las salta solo.
    if lista.len() < t {
        return IpCliente::Desconocida;
    }
    let idx = lista.len() - t;
    parsear_ip(lista[idx])
}

/// Cuando el proxy de confianza SOBRESCRIBE una cabecera con la IP del cliente
/// (p. ej. `X-Real-IP` en nginx configurado para pisarla), esa cabecera es creíble
/// tal cual: el proxy la reescribe en cada petición y el cliente no la puede fijar.
///
/// Sólo es correcto si el operador GARANTIZA la sobrescritura. Si el proxy AÑADE en
/// vez de pisar (el comportamiento de `X-Forwarded-For`), usa [`ip_de_reenvio`] con
/// el número de saltos. A diferencia de aquélla, esta función no tiene defensa
/// estructural: confía en la cabecera entera, así que elegirla cuando el proxy NO
/// sobrescribe da spoofing TOTAL del origen del freno (el cliente fija el valor).
#[must_use]
pub fn ip_confiable_directa(cabecera: Option<&str>) -> IpCliente {
    match cabecera {
        Some(v) => parsear_ip(v.trim()),
        None => IpCliente::Desconocida,
    }
}

/// Parsea una entrada como IP, tolerando las dos formas con puerto que aparecen en la
/// práctica: IPv6 entre corchetes (`[::1]:443`) e IPv4 con puerto (`1.2.3.4:5678`).
/// Una IPv6 desnuda (`2001:db8::1`) se parsea directa; nunca se confunde su `:` con
/// un puerto porque tiene más de uno.
fn parsear_ip(s: &str) -> IpCliente {
    let s = s.trim();
    // IPv6 entre corchetes, con puerto opcional.
    if let Some(resto) = s.strip_prefix('[') {
        return match resto.find(']') {
            Some(fin) => match IpAddr::from_str(&resto[..fin]) {
                Ok(ip) => IpCliente::Conocida(ip),
                Err(_) => IpCliente::Desconocida,
            },
            None => IpCliente::Desconocida,
        };
    }
    // IP desnuda (IPv4 o IPv6 sin corchetes).
    if let Ok(ip) = IpAddr::from_str(s) {
        return IpCliente::Conocida(ip);
    }
    // IPv4 con puerto: un ÚNICO ':' separa host y puerto. Con más de uno es IPv6 y ya
    // habría parseado arriba; con exactamente uno, se prueba la parte host.
    if s.matches(':').count() == 1 {
        if let Some((host, _puerto)) = s.rsplit_once(':') {
            if let Ok(ip) = IpAddr::from_str(host) {
                return IpCliente::Conocida(ip);
            }
        }
    }
    IpCliente::Desconocida
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    /// VERDE y ROJO juntos (directiva 33): con 1 proxy de confianza y una cadena que el
    /// atacante ha PREFIJADO con una IP falsa, la función devuelve la que añadió el
    /// proxy (a la derecha), no la falsa (a la izquierda). El mutante ingenuo —tomar el
    /// extremo izquierdo— devolvería `9.9.9.9` y fallaría esta prueba.
    #[test]
    fn ignora_el_prefijo_falseado_por_el_cliente() {
        // XFF que ve la app: [falsa_del_atacante, real_que_puso_el_proxy].
        let r = ip_de_reenvio(Some("9.9.9.9, 203.0.113.7"), Confianza::con_saltos(1));
        assert_eq!(r, IpCliente::Conocida(ip("203.0.113.7")), "gana la de la derecha");
        assert_ne!(r.conocida(), Some(ip("9.9.9.9")), "la falsa NO se cree jamás");
    }

    #[test]
    fn un_solo_salto_cadena_minima() {
        // Con 1 proxy y cliente directo, la cadena legítima tiene 1 entrada: el cliente.
        let r = ip_de_reenvio(Some("198.51.100.23"), Confianza::con_saltos(1));
        assert_eq!(r, IpCliente::Conocida(ip("198.51.100.23")));
    }

    #[test]
    fn dos_saltos_toma_la_correcta() {
        // cliente -> LB -> nginx -> app. XFF que ve la app: [cliente, ip_del_LB].
        let r = ip_de_reenvio(Some("203.0.113.9, 10.0.0.2"), Confianza::con_saltos(2));
        assert_eq!(r, IpCliente::Conocida(ip("203.0.113.9")));
    }

    #[test]
    fn sin_proxy_ignora_la_cabecera() {
        // saltos=0: X-Forwarded-For es 100 % del cliente y no se usa.
        assert_eq!(
            ip_de_reenvio(Some("1.2.3.4"), Confianza::con_saltos(0)),
            IpCliente::Desconocida
        );
    }

    #[test]
    fn cadena_mas_corta_de_lo_esperado_es_ruidosa() {
        // Se esperan 2 saltos pero sólo hay 1 entrada: truncada/mal configurada.
        assert_eq!(
            ip_de_reenvio(Some("1.2.3.4"), Confianza::con_saltos(2)),
            IpCliente::Desconocida
        );
        assert_eq!(ip_de_reenvio(None, Confianza::con_saltos(1)), IpCliente::Desconocida);
    }

    #[test]
    fn formas_con_puerto_y_ipv6() {
        assert_eq!(parsear_ip("1.2.3.4:5678"), IpCliente::Conocida(ip("1.2.3.4")));
        assert_eq!(parsear_ip("[2001:db8::1]:443"), IpCliente::Conocida(ip("2001:db8::1")));
        assert_eq!(parsear_ip("2001:db8::1"), IpCliente::Conocida(ip("2001:db8::1")));
        assert_eq!(parsear_ip("no-una-ip"), IpCliente::Desconocida);
        assert_eq!(parsear_ip(""), IpCliente::Desconocida);
    }

    #[test]
    fn x_real_ip_directa_se_cree() {
        assert_eq!(
            ip_confiable_directa(Some("203.0.113.7")),
            IpCliente::Conocida(ip("203.0.113.7"))
        );
        assert_eq!(ip_confiable_directa(None), IpCliente::Desconocida);
    }

    #[test]
    fn origen_desconocido_es_centinela_no_ip() {
        assert_eq!(IpCliente::Desconocida.como_origen(), "origen-desconocido");
        assert!(IpAddr::from_str(&IpCliente::Desconocida.como_origen()).is_err());
    }

    /// La propiedad de seguridad, a lo bruto (directiva 8): con 3 proxies de confianza,
    /// se antepone a la cadena una cantidad ARBITRARIA de basura controlada por el
    /// cliente; la IP extraída SIEMPRE es la del cliente real, sea cual sea el prefijo.
    #[test]
    fn el_prefijo_del_atacante_nunca_cambia_el_resultado() {
        let real = "203.0.113.55";
        // Los 3 saltos de confianza que la infraestructura añade a la derecha.
        let cola = format!("{real}, 10.0.0.1, 10.0.0.2");
        for n in 0..200u32 {
            // n entradas falsas prefijadas por el atacante.
            let prefijo: Vec<String> = (0..n).map(|i| format!("172.16.{}.{}", i / 256, i % 256)).collect();
            let xff = if prefijo.is_empty() {
                cola.clone()
            } else {
                format!("{}, {cola}", prefijo.join(", "))
            };
            let r = ip_de_reenvio(Some(&xff), Confianza::con_saltos(3));
            assert_eq!(
                r,
                IpCliente::Conocida(ip(real)),
                "con {n} entradas falsas prefijadas, la IP real debe sobrevivir"
            );
        }
    }
}
