// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! **Bachué — defensas transversales (F5).** Las piezas de BORDE que un producto de
//! identidad necesita alrededor del flujo de login y que no son un primitivo de guaca
//! ni el motor de autz: tres funciones puras, sin estado y sin dependencias.
//!
//! Cada módulo nace de un modo de fallo MEDIDO en el corpus de objetivos, no de una
//! lista de buenas prácticas:
//!
//! - [`red`] — **la IP del cliente, de verdad.** El `freno` (guaca) frena por
//!   `(correo, origen)`; si detrás de un proxy la app le pasa la IP del socket, todos
//!   los clientes comparten origen y el freno colapsa, y si confía ciegamente en
//!   `X-Forwarded-For`, el atacante lo falsea para tener un origen nuevo en cada
//!   intento y lo evade. Este módulo saca la IP creíble según cuántos proxies propios
//!   hay, para que el `origen` del freno signifique lo que debe.
//! - [`redireccion`] — **a dónde se puede reenviar tras el login.** Fail-closed: sólo
//!   una ruta relativa de nuestro sitio o una URL absoluta de una lista registrada,
//!   comparada por igualdad EXACTA. La lección deriv (un `/qa/` sin anclar casa en
//!   cualquier posición) es un match por substring visto desde la regex.
//! - [`entorno`] — **qué variables pueden llegar a un proceso hijo.** Ciertos nombres
//!   de env cambian cómo ejecuta código el hijo (enlazador, intérpretes): fijar uno
//!   con valor controlado es ejecución de código, no configuración. La lección
//!   Doppler: se ELIMINAN, no se advierten, y la lista se mantiene completa con su
//!   prueba —o mejor, se enumera lo permitido y se descarta el resto—.

#![forbid(unsafe_code)]

pub mod entorno;
pub mod red;
pub mod redireccion;
