// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
//
// boi — comportamiento de cliente declarativo, sobre htmx, sin dependencias.
//
// El complemento de `maud` + htmx: maud teje el HTML en el servidor, htmx hace
// los intercambios parciales, y boi cubre lo que queda —la interacción que
// ocurre solo en el navegador—. Se marca el HTML con `data-*` y boi actúa; el
// HTML sigue siendo la única fuente de verdad.
//
// Cero dependencias, cero build: un módulo de JavaScript que el navegador
// entiende tal cual (`<script type="module" src="boi.js">`). Un tercero no puede
// comprometer lo que no existe — ese es el punto.
//
// Este archivo es el NÚCLEO: el registro de comportamientos, el escáner y el
// enganche al ciclo de htmx. NO trae comportamientos concretos (máscaras,
// validaciones): esos se añaden desde lo que cada proyecto pide de verdad, cada
// uno en su archivo, importando `registrar` de aquí.

// El catálogo de comportamientos registrados. Cada uno: un nombre único, un
// selector CSS y una función `init(elemento)` que se llama UNA vez por elemento
// que encaje. Se exporta para que las pruebas puedan vaciarlo entre casos.
export const comportamientos = [];

// El documento al que boi se enganchó, si ya lo hizo. Solo lo usa `registrar`
// para saber si llega tarde a la fiesta; no es estado de la librería.
let documentoEnganchado = null;
const documentosEnganchados = new WeakSet();

// El atributo con que se marca un elemento ya inicializado para un
// comportamiento. Es lo que hace el escáner idempotente: re-escanear un subárbol
// no vuelve a inicializar lo ya hecho. `boi-<nombre>-listo`.
export function marca(nombre) {
  return "boi-" + nombre + "-listo";
}

// Registra un comportamiento. Lo llama cada archivo de comportamiento al
// cargarse. Un nombre repetido es un error de programación —dos comportamientos
// peleando por el mismo—, no algo que se ignora en silencio (directiva 20).
export function registrar(nombre, selector, init) {
  // Se valida ANTES de empujar. Un comportamiento mal formado que entrara en la
  // lista envenenaría el catálogo para siempre: cada escaneo posterior volvería
  // a tropezar con él, y como el escaneo es lo que corre en cada swap de htmx,
  // la pantalla dejaría de enganchar comportamientos el resto de la sesión.
  //
  // Los CINCO son errores de programación y se DICEN (directiva 20), no se
  // ignoran en silencio. Eran tres cuando se escribió este comentario, cuatro
  // desde la tercera revisión —el nombre como atributo— y cinco desde el
  // 2026-08-13, con `init`. El número se corrige aquí porque un comentario que
  // dice «los tres» delante de una lista de cinco enseña a no contarla.
  if (comportamientos.some((c) => c.nombre === nombre)) {
    throw new Error("boi: el comportamiento «" + nombre + "» ya está registrado");
  }
  // La caja se compara en minúsculas porque HTML minúsculiza los nombres de
  // atributo: `Mix` y `mix` producirían la MISMA marca `boi-mix-listo`, y el
  // segundo comportamiento se saltaría sin decir una palabra. En SVG no, así que
  // el mismo par funcionaría en un sitio y no en otro — de los defectos que
  // cuestan una tarde.
  const enMinusculas = String(nombre).toLowerCase();
  if (comportamientos.some((c) => String(c.nombre).toLowerCase() === enMinusculas)) {
    throw new Error(
      "boi: «" + nombre + "» choca con un comportamiento ya registrado si se ignora la caja",
    );
  }
  // Un selector inválido no falla al registrarse: falla DENTRO del escaneo, que
  // es donde no hay a quién culpar. Se comprueba aquí, con el mismo motor de
  // selectores que va a usar el escáner.
  if (documentoEnganchado && typeof documentoEnganchado.querySelector === "function") {
    try {
      documentoEnganchado.querySelector(selector);
    } catch {
      throw new Error(
        "boi: el selector «" + selector + "» de «" + nombre + "» no es válido",
      );
    }
  }
  // Y el NOMBRE tiene que servir como nombre de atributo, que es la otra puerta
  // del mismo envenenamiento: `registrar("mi comportamiento", …)` pasaba la
  // comprobación del selector y luego `setAttribute("boi-mi comportamiento-listo")`
  // lanzaba en CADA escaneo, o sea en cada swap de htmx. Lo encontró la tercera
  // revisión, después de que la anterior cerrara la puerta del selector.
  if (documentoEnganchado && typeof documentoEnganchado.createElement === "function") {
    try {
      documentoEnganchado.createElement("i").setAttribute(marca(nombre), "");
    } catch {
      throw new Error(
        "boi: «" + nombre + "» no sirve como nombre de comportamiento: «" +
          marca(nombre) + "» no es un atributo válido",
      );
    }
  }

  // Y la quinta: `init` tiene que ser invocable. Sin esto,
  // `registrar("x", "#id", null)` entra al catálogo, el escáner MARCA el
  // elemento como inicializado y solo entonces `c.init(el)` lanza. Queda
  // aislado y avisado —el escáner no se cae—, pero el elemento cuenta como
  // hecho sin estarlo y **nunca se reintenta**: la pantalla se queda muerta con
  // la marca puesta, que es exactamente el envenenamiento que las otras cuatro
  // puertas existen para impedir.
  if (typeof init !== "function") {
    throw new Error(
      "boi: el `init` de «" + nombre + "» no es una función (llegó " + typeof init + ")",
    );
  }

  const comportamiento = { nombre, selector, init };
  comportamientos.push(comportamiento);

  // Un comportamiento que se registra CUANDO EL DOCUMENTO YA ESTÁ ANALIZADO se
  // aplica en el acto, porque el escaneo inicial ya pasó y `DOMContentLoaded` no
  // vuelve. Pasa siempre que boi entra por importación dinámica, y sin esto la
  // pantalla se queda muerta con `data-boi=listo` puesto —medido en Chromium el
  // 2026-08-12—.
  //
  // Se aplica SOLO el recién registrado, no el catálogo entero: escanearlo todo
  // en cada registro es cuadrático en el número de comportamientos, y para lo
  // ya escaneado el resultado es idéntico porque está marcado.
  //
  // CAMBIA una cosa, y se dice: antes, cada registro tardío funcionaba de paso
  // como re-escaneo completo del `body`, así que recogía elementos insertados
  // sin `htmx:load` —`innerHTML` a mano, un script ajeno—. Ya no. Quien inserte
  // sin htmx tiene `boi.escanear(nodo)`, que es la puerta explícita.
  if (documentoEnganchado && documentoEnganchado.readyState && documentoEnganchado.readyState !== "loading") {
    aplicar(documentoEnganchado.body, comportamiento);
  }
}

// Aplica todos los comportamientos a los elementos NUEVOS de `raiz` (incluida
// `raiz` misma). Salta los ya marcados. `raiz` se inyecta como parámetro —no se
// toma de un global— para que sea probable con un doble de prueba.
//
// Un `init` que lanza NO tumba el escaneo del resto: se aísla y se avisa por
// consola. Un comportamiento roto en una pantalla no debe dejar muerta la página
// entera (mejora progresiva, principio 4).
export function escanear(raiz) {
  if (!raiz || typeof raiz.querySelectorAll !== "function") return;
  for (const c of comportamientos) {
    // El aislamiento envuelve al comportamiento ENTERO, no solo a su `init`.
    // Antes cubría únicamente la llamada, y un selector que el navegador
    // rechaza —o un `setAttribute` con un nombre imposible— salía por encima del
    // bucle: todo comportamiento registrado DESPUÉS del malo no llegaba a
    // correr nunca, y en un swap de htmx eso deja media pantalla muerta.
    aplicar(raiz, c);
  }
}

// Aplica UN comportamiento a los elementos nuevos de `raiz`. Aislado: lo que
// falle aquí no puede impedir que los demás comportamientos se apliquen.
function aplicar(raiz, c) {
  if (!raiz || typeof raiz.querySelectorAll !== "function") return;
  try {
    const encajan = [];
    // La propia raíz puede encajar el selector, no solo sus descendientes.
    if (typeof raiz.matches === "function" && raiz.matches(c.selector)) {
      encajan.push(raiz);
    }
    raiz.querySelectorAll(c.selector).forEach((el) => encajan.push(el));
    for (const el of encajan) {
      if (el.hasAttribute(marca(c.nombre))) continue; // ya inicializado
      el.setAttribute(marca(c.nombre), "");
      try {
        c.init(el);
      } catch (err) {
        // No relanzar: aislar el fallo a este elemento (principio 4).
        avisar("el comportamiento «" + c.nombre + "» falló en", el, err);
      }
    }
  } catch (err) {
    // Una vez por CAUSA, no una por escaneo: en un panel con sondeo el escaneo
    // corre cada pocos segundos, y una alarma que sale mil veces es una que
    // nadie mira (directiva 23). Pero repetir no es lo mismo que callar: si el
    // comportamiento empieza a fallar por otra razón, esa sí se dice — un
    // «avisa una vez por nombre» dejaba mudo para siempre cualquier fallo
    // posterior, y en medico o chuspa eso es justo lo que uno quiere ver.
    //
    // La marca vive en el comportamiento, no en un `Set` de módulo: así se va
    // con él y no hay estado que sobreviva a vaciar el catálogo.
    const causa = String(err && err.message ? err.message : err);
    if (c.ultimoAviso !== causa) {
      c.ultimoAviso = causa;
      avisar("el comportamiento «" + c.nombre + "» no se pudo aplicar", raiz, err);
    }
  }
}

function avisar(mensaje, ...resto) {
  if (typeof console !== "undefined") console.error("boi: " + mensaje, ...resto);
}

// El enganche al mundo. Se llama una vez, con el `document` del navegador.
//
// Dos disparadores, y los dos importan:
//   - `DOMContentLoaded`: la carga inicial de la página.
//   - `htmx:load`: CADA fragmento que htmx trae por un intercambio parcial. Sin
//     esto, un fragmento nuevo llegaría SIN sus comportamientos —el fallo que más
//     se olvida (principio 3)—. htmx emite `htmx:load` sobre el nodo recién
//     insertado, y `event.detail.elt` es ese nodo: se escanea SOLO él.
export function enganchar(doc) {
  if (!doc || typeof doc.addEventListener !== "function") return;
  // Idempotente por documento: dos llamadas duplicaban los oyentes de
  // `htmx:load` y, desde que el respaldo se registra siempre, dejaban además un
  // `DOMContentLoaded` muerto por llamada. Escanear de más es gratis; oyentes de
  // más, no.
  if (documentosEnganchados.has(doc)) return;
  documentosEnganchados.add(doc);
  documentoEnganchado = doc;
  // El escaneo inicial, por los DOS caminos, y ninguno sustituye al otro.
  //
  // `DOMContentLoaded` ya no vuelve a dispararse si boi llega con el documento
  // analizado —una importación dinámica, un módulo dentro de un fragmento, un
  // `<script type="module" async>`—. Sin el escaneo inmediato la página se
  // quedaba SIN escanear y el rastro de más abajo se ponía igual: el DOM decía
  // «listo» sobre una pantalla en la que no se inicializó nada, que es peor que
  // no decir nada (directiva 20). Medido en Chromium el 2026-08-12.
  //
  // Y el oyente se registra SIEMPRE, no en un `else`: un documento ya analizado
  // pero todavía sin `body` —que existe— hacía que el escaneo inmediato saliera
  // por la guarda y que nadie dejara un respaldo. El mismo agujero, en un
  // rincón más estrecho. Escanear dos veces es gratis: es idempotente.
  doc.addEventListener("DOMContentLoaded", () => escanear(doc.body));
  if (doc.readyState && doc.readyState !== "loading") {
    escanear(doc.body);
  }
  doc.addEventListener("htmx:load", (e) => {
    const nodo = e && e.detail && e.detail.elt ? e.detail.elt : doc.body;
    escanear(nodo);
  });
  // DEJA RASTRO EN EL DOM. No es adorno: es lo único que un E2E puede mirar para
  // distinguir «boi cargó y se enganchó» de «el <script type=module> está en el
  // HTML y el navegador no lo ejecutó» —un módulo que la CSP bloquea, que llega
  // con el MIME equivocado o que revienta al importar falla EN SILENCIO, y el
  // servidor devuelve exactamente el mismo 200 con el mismo cuerpo.
  //
  // Una página sin ningún `data-*` de comportamiento no produce ninguna otra
  // marca, así que sin esto el caso más común —la pantalla de entrada— no se
  // puede comprobar en absoluto. Va en el núcleo y no en cada proyecto porque el
  // problema es de la librería, no de quien la usa (directiva 9).
  if (doc.documentElement && typeof doc.documentElement.setAttribute === "function") {
    doc.documentElement.setAttribute("data-boi", "listo");
  }
}

// En un navegador de verdad: publicar el núcleo en `globalThis.boi` (para que un
// `<script>` no-módulo pueda registrarse) y auto-enganchar. En deno/node no hay
// `document`, así que nada de esto corre y la prueba maneja su propio doble.
if (typeof document !== "undefined") {
  globalThis.boi = { registrar, escanear, comportamientos, marca };
  enganchar(document);
}
