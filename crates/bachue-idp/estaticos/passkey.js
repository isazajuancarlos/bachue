// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//
// Passkeys / WebAuthn (F3) — el PEGAMENTO del navegador: traduce entre el JSON de las
// ceremonias (base64url) y la API `navigator.credentials`, que habla `ArrayBuffer`. Vanilla y
// sin dependencias (directiva 26); se sirve como archivo y se carga como módulo ES, así la CSP
// `script-src 'self'` no necesita excepción. El servidor hace TODA la verificación; esto solo
// mueve bytes y llama al autenticador.
//
// Se auto-cablea por atributos `data-passkey` para no acoplarse a una pantalla concreta:
//   <button data-passkey="login" data-next="/">Entrar con una passkey</button>
//   <button data-passkey="registrar">Añadir una passkey</button>  (+ opcional <input id="passkey-apodo">)
//   <button data-passkey="borrar" data-id="7">Quitar</button>
// y escribe el estado en #passkey-aviso si existe (sin diálogos del navegador).

const esDisponible = () =>
  typeof window.PublicKeyCredential !== "undefined" &&
  typeof navigator.credentials?.create === "function";

// ── base64url ↔ ArrayBuffer ──────────────────────────────────────────────────
function b64urlABytes(s) {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const base = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(base);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function bytesAB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function aviso(texto, esError) {
  const el = document.getElementById("passkey-aviso");
  if (!el) return;
  el.textContent = texto;
  el.className = esError ? "aviso error" : "aviso ok";
}

// Enrolar y quitar una passkey exigen la contraseña actual (step-up). Si el campo
// está vacío, NO se dispara la ceremonia ni la petición: se avisa y se enfoca el
// campo. Antes el botón "Quitar" vivía separado del campo, así que se pulsaba con
// el campo vacío y el servidor respondía 401 ("No se pudo quitar"), que no decía
// qué faltaba. Devuelve la contraseña, o `null` si falta (el llamante aborta).
function contrasenaActual() {
  const el = document.getElementById("passkey-contrasena");
  const v = el?.value || "";
  if (!v) {
    aviso("Escribe tu contraseña actual para continuar.", true);
    el?.focus();
    return null;
  }
  return v;
}

// La app puede ir montada tras un PREFIJO (p. ej. /auth en el VPS, que nginx inyecta
// reescribiendo el HTML). nginx reescribe el HTML pero NO el cuerpo de este .js, así que las
// rutas absolutas desde la raíz (`/passkey/...`) se redirigían (302) fuera de la app. Este
// módulo se sirve como `<prefijo>/passkey.js`, de modo que el prefijo se deduce de su propia
// URL de módulo y se antepone a cada fetch; en la raíz (dev) queda vacío.
const BASE = new URL(".", import.meta.url).pathname.replace(/\/+$/, "");

async function pedirJson(url, cuerpo) {
  const r = await fetch(BASE + url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(cuerpo ?? {}),
  });
  let datos = null;
  try {
    datos = await r.json();
  } catch {
    datos = null;
  }
  return { ok: r.ok, datos };
}

// ── registro (create) ────────────────────────────────────────────────────────
async function registrar(apodo) {
  if (!esDisponible()) return aviso("Este navegador no admite passkeys.", true);
  // Exigir la contraseña ANTES de arrancar la ceremonia: si falta, no se llama a
  // `create()` y no queda una passkey huérfana en el autenticador.
  const contrasena = contrasenaActual();
  if (contrasena === null) return;
  // La contraseña (step-up) se verifica en el SERVIDOR aquí, en `/inicio`, antes de
  // arrancar la ceremonia: si es incorrecta o hay freno, no se llama a `create()` y no
  // queda una passkey huérfana en el autenticador.
  const ini = await pedirJson("/passkey/registrar/inicio", { contrasena });
  if (!ini.ok) {
    const seg = ini.datos?.espera;
    return aviso(
      seg ? `Demasiados intentos. Espera ${seg} s e inténtalo de nuevo.`
          : "Contraseña incorrecta o sesión caducada.",
      true,
    );
  }
  if (!ini.datos) return aviso("No se pudo iniciar el registro.", true);
  aviso("Sigue las indicaciones de tu dispositivo…", false);
  const o = ini.datos;
  const publicKey = {
    challenge: b64urlABytes(o.challenge),
    rp: o.rp,
    user: {
      id: b64urlABytes(o.user.id),
      name: o.user.name,
      displayName: o.user.displayName,
    },
    pubKeyCredParams: o.pubKeyCredParams,
    authenticatorSelection: o.authenticatorSelection,
    excludeCredentials: (o.excludeCredentials || []).map((c) => ({
      type: c.type,
      id: b64urlABytes(c.id),
    })),
    timeout: o.timeout,
    attestation: o.attestation,
  };
  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey });
  } catch (e) {
    return aviso("Registro cancelado o fallido.", true);
  }
  const fin = await pedirJson("/passkey/registrar/fin", {
    challenge: o.challenge,
    id: cred.id,
    clientDataJSON: bytesAB64url(cred.response.clientDataJSON),
    attestationObject: bytesAB64url(cred.response.attestationObject),
    apodo: apodo || "",
    // El step-up ya se verificó en `/inicio`; el reto consumido aquí es su prueba.
  });
  if (fin.ok && fin.datos?.ok) {
    aviso("Passkey añadida.", false);
    window.location.reload();
  } else {
    aviso("No se pudo guardar la passkey.", true);
  }
}

// ── login (get) ──────────────────────────────────────────────────────────────
async function entrar(next) {
  if (!esDisponible()) return aviso("Este navegador no admite passkeys.", true);
  aviso("Elige tu passkey…", false);
  const ini = await pedirJson("/passkey/login/inicio");
  if (!ini.ok || !ini.datos) return aviso("No se pudo iniciar el acceso.", true);
  const o = ini.datos;
  const publicKey = {
    challenge: b64urlABytes(o.challenge),
    rpId: o.rpId,
    allowCredentials: (o.allowCredentials || []).map((c) => ({
      type: c.type,
      id: b64urlABytes(c.id),
    })),
    userVerification: o.userVerification,
    timeout: o.timeout,
  };
  let cred;
  try {
    cred = await navigator.credentials.get({ publicKey });
  } catch (e) {
    return aviso("Acceso cancelado o fallido.", true);
  }
  const fin = await pedirJson("/passkey/login/fin", {
    challenge: o.challenge,
    id: cred.id,
    clientDataJSON: bytesAB64url(cred.response.clientDataJSON),
    authenticatorData: bytesAB64url(cred.response.authenticatorData),
    signature: bytesAB64url(cred.response.signature),
    next: next || "",
  });
  if (fin.ok && fin.datos?.ok) {
    window.location.assign(fin.datos.next || "/");
  } else {
    aviso("No se pudo iniciar sesión con la passkey.", true);
  }
}

async function borrar(id, boton) {
  // Mismo guardia que al enrolar: sin contraseña no se manda la petición (antes
  // el 401 "No se pudo quitar" no decía que faltaba la contraseña).
  const contrasena = contrasenaActual();
  if (contrasena === null) return;
  const fin = await pedirJson("/seguridad/passkey/borrar", {
    id: Number(id),
    // Step-up: quitar un factor también exige la contraseña actual.
    contrasena,
  });
  if (fin.ok && fin.datos?.ok) {
    window.location.reload();
  } else {
    aviso("No se pudo quitar la passkey.", true);
  }
}

function cablear() {
  for (const b of document.querySelectorAll('[data-passkey]')) {
    const modo = b.getAttribute("data-passkey");
    b.addEventListener("click", (ev) => {
      ev.preventDefault();
      if (modo === "login") entrar(b.getAttribute("data-next") || "/");
      else if (modo === "registrar")
        registrar(document.getElementById("passkey-apodo")?.value || "");
      else if (modo === "borrar") borrar(b.getAttribute("data-id"), b);
    });
  }
  // Si el navegador no admite passkeys, oculta los controles que no funcionarían.
  if (!esDisponible()) {
    for (const b of document.querySelectorAll('[data-passkey]')) b.hidden = true;
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", cablear);
} else {
  cablear();
}
