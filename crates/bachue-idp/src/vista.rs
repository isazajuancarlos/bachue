// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! Las pantallas: layout maud + estáticos VENDORIZADOS (htmx 2.0.4 y boi, la
//! micro-librería propia — misma versión que el resto, directiva 26; jamás por CDN, que
//! un IdP tiene que servir sin depender de que alguien le sirva un archivo).
//!
//! Los formularios son PLANOS y funcionan SIN JavaScript: el login no puede depender de
//! que el navegador ejecute htmx. htmx/boi son realce, no la vía crítica (por eso el E2E
//! por HTTP prueba el producto de verdad; ver `tests/e2e.rs`).

use axum::http::header;
use axum::response::{IntoResponse, Response};
use maud::{html, Markup, DOCTYPE};

const HTMX_JS: &str = include_str!("../estaticos/htmx.min.js");
const BOI_JS: &str = include_str!("../estaticos/boi.js");
const BOI_CSS: &str = include_str!("../estaticos/boi.css");
const ESTILO_CSS: &str = include_str!("../estaticos/estilo.css");
const PASSKEY_JS: &str = include_str!("../estaticos/passkey.js");

pub async fn htmx_js() -> Response {
    ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], HTMX_JS).into_response()
}
/// El pegamento WebAuthn del navegador (F3): traduce entre el JSON de las ceremonias y
/// `navigator.credentials`. Vendorizado y servido como archivo, igual que htmx/boi.
pub async fn passkey_js() -> Response {
    ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], PASSKEY_JS).into_response()
}
pub async fn boi_js() -> Response {
    ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], BOI_JS).into_response()
}
pub async fn boi_css() -> Response {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], BOI_CSS).into_response()
}
pub async fn estilo_css() -> Response {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], ESTILO_CSS).into_response()
}

/// Envoltura común: `<html>` con css + htmx + boi vendorizados, y el `cuerpo` dentro de
/// un `<main>`.
fn envoltura(titulo: &str, cuerpo: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="es" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (titulo) " — Bachué" }
                link rel="stylesheet" href="/boi.css";
                link rel="stylesheet" href="/estilo.css";
                script src="/htmx.min.js" defer {}
                // boi.js es un MÓDULO ES (usa `export`); como script clásico
                // `<script src defer>` el `export` de nivel superior es un
                // SyntaxError y el archivo NO ejecuta (no auto-engancha, no
                // publica globalThis.boi). Se carga como módulo, igual que medico.
                script type="module" src="/boi.js" {}
                // El pegamento WebAuthn (F3): se auto-cablea a los botones
                // `data-passkey` de la página; en una sin ellos no hace nada. La
                // CSP `script-src 'self'` lo cubre (se sirve como archivo propio).
                script type="module" src="/passkey.js" {}
            }
            body { main { (cuerpo) } }
        }
    }
}

fn aviso_error(aviso: Option<&str>) -> Markup {
    html! {
        @if let Some(a) = aviso {
            p.aviso.error { (a) }
        }
    }
}

/// Pantalla de login. `next` es el destino post-login YA validado (ruta relativa segura).
/// `registro_abierto` decide si se ofrece el enlace de "crear cuenta": con el registro
/// cerrado (pago primero) no hay alta libre, así que no se invita a una pantalla muerta.
pub fn entrar(aviso: Option<&str>, next: &str, registro_abierto: bool, passkey_activo: bool) -> Markup {
    envoltura(
        "Entrar",
        html! {
            h1 { "Entrar" small { "Bachué — identidad" } }
            form method="post" action="/entrar" {
                input type="hidden" name="next" value=(next);
                label for="usuario" { "Usuario" }
                input type="text" id="usuario" name="usuario" autocomplete="username" required autofocus;
                label for="contrasena" { "Contraseña" }
                input type="password" id="contrasena" name="contrasena" autocomplete="current-password" required;
                (aviso_error(aviso))
                button type="submit" { "Entrar" }
            }
            // Login passwordless por passkey (F3). El botón lo activa passkey.js vía
            // `data-passkey="login"`; si el navegador no admite passkeys, el script lo
            // oculta. El estado (éxito/fallo) se escribe en #passkey-aviso, sin diálogos.
            @if passkey_activo {
                p.o-separador { "o" }
                button.secundario type="button" data-passkey="login" data-next=(next) {
                    "Entrar con una passkey"
                }
                p #passkey-aviso {}
            }
            @if registro_abierto {
                p.pie { "¿Sin cuenta? " a href="/registrarse" { "Crear una" } }
            }
        },
    )
}

/// Pantalla de "fijar tu contraseña": el usuario reclama la cuenta que su pago provisionó.
/// El `token` (firmado, un solo uso) viaja en un campo oculto; aquí solo se elige la clave.
pub fn establecer(token: &str, aviso: Option<&str>) -> Markup {
    envoltura(
        "Fijar contraseña",
        html! {
            h1 { "Fija tu contraseña" small { "Bachué — identidad" } }
            p.aviso.ok { "Tu suscripción está activa. Elige la contraseña con la que entrarás." }
            form method="post" action="/establecer" {
                input type="hidden" name="token" value=(token);
                label for="contrasena" { "Contraseña" }
                input type="password" id="contrasena" name="contrasena" autocomplete="new-password" required autofocus;
                (aviso_error(aviso))
                button type="submit" { "Guardar y entrar" }
            }
        },
    )
}

/// El enlace de reclamo no vale (vencido, ya usado o manipulado). No se dice CUÁL: un
/// enlace vencido y uno inventado se ven igual (no se filtra si un token existió).
pub fn establecer_no_vale() -> Markup {
    envoltura(
        "Enlace no válido",
        html! {
            h1 { "Enlace no válido" small { "Bachué — identidad" } }
            p.aviso.error { "Este enlace para fijar la contraseña no es válido o ya venció." }
            p.pie { "Si ya fijaste tu contraseña, " a href="/entrar" { "entra aquí" } "." }
        },
    )
}

/// El registro público está cerrado (modelo "pago primero"): el alta es por suscripción.
pub fn registro_cerrado() -> Markup {
    envoltura(
        "Registro cerrado",
        html! {
            h1 { "Registro cerrado" small { "Bachué — identidad" } }
            p.aviso.error { "El registro directo no está disponible. El acceso se habilita al contratar el servicio." }
            p.pie { "¿Ya tienes cuenta? " a href="/entrar" { "Entrar" } }
        },
    )
}

/// Pantalla del segundo factor (TOTP). `next` viaja en un campo oculto para no perder el
/// destino post-login entre el GET y el POST.
pub fn segundo_factor(aviso: Option<&str>, next: &str) -> Markup {
    envoltura(
        "Segundo factor",
        html! {
            h1 { "Segundo factor" small { "Escribe el código de tu app" } }
            form method="post" action="/segundo-factor" {
                input type="hidden" name="next" value=(next);
                label for="codigo" { "Código de 6 cifras" }
                input type="text" id="codigo" name="codigo" inputmode="numeric" autocomplete="one-time-code" required autofocus;
                (aviso_error(aviso))
                button type="submit" { "Verificar" }
            }
        },
    )
}

pub fn registro(aviso: Option<&str>, usuario: &str) -> Markup {
    envoltura(
        "Crear cuenta",
        html! {
            h1 { "Crear cuenta" small { "Bachué — identidad" } }
            form method="post" action="/registrarse" {
                label for="usuario" { "Usuario" }
                input type="text" id="usuario" name="usuario" value=(usuario) autocomplete="username" required autofocus;
                label for="contrasena" { "Contraseña" }
                input type="password" id="contrasena" name="contrasena" autocomplete="new-password" required;
                (aviso_error(aviso))
                button type="submit" { "Crear cuenta" }
            }
            p.pie { "¿Ya tienes cuenta? " a href="/entrar" { "Entrar" } }
        },
    )
}

/// El panel tras autenticarse. `passkeys` son las credenciales del usuario (vacío si no tiene
/// o si la capa está apagada); `passkey_activo` decide si se ofrece gestionarlas.
pub fn panel(
    usuario: &str,
    tiene_2fa: bool,
    passkeys: &[crate::db::ResumenPasskey],
    passkey_activo: bool,
) -> Markup {
    envoltura(
        "Tu cuenta",
        html! {
            h1 { "Hola, " (usuario) small { "Estás autenticado" } }
            p.aviso.ok {
                "Segundo factor: "
                @if tiene_2fa { "activo" } @else { "sin activar" }
            }
            @if !tiene_2fa {
                // Sólo abre la pantalla de activación; la contraseña se pide AL CONFIRMAR
                // (que es donde el 2FA se persiste).
                form method="post" action="/seguridad/2fa" {
                    button type="submit" { "Activar segundo factor" }
                }
            }
            // Gestión de passkeys (F3): listar, añadir y quitar. Las acciones las ejecuta
            // passkey.js por `fetch` (ceremonias WebAuthn), de ahí los `data-passkey`.
            @if passkey_activo {
                section.passkeys {
                    h2 { "Passkeys" small { "Entra sin contraseña, resistente a phishing" } }
                    @if passkeys.is_empty() {
                        p.tenue { "No tienes passkeys. Añade una para entrar sin contraseña." }
                    } @else {
                        ul.passkeys {
                            @for pk in passkeys {
                                li {
                                    span { (pk.apodo.as_deref().unwrap_or("passkey")) }
                                    " "
                                    small.tenue { "(" (pk.creado.get(0..10).unwrap_or(&pk.creado)) ")" }
                                    " "
                                    button.tenue type="button" data-passkey="borrar" data-id=(pk.id) {
                                        "Quitar"
                                    }
                                }
                            }
                        }
                    }
                    label for="passkey-contrasena" { "Confirma tu contraseña para añadir o quitar una passkey" }
                    input type="password" id="passkey-contrasena" name="passkey-contrasena" autocomplete="current-password" placeholder="Tu contraseña actual";
                    label for="passkey-apodo" { "Nombre para la nueva passkey (opcional)" }
                    input type="text" id="passkey-apodo" name="passkey-apodo" maxlength="64" placeholder="p. ej. iPhone de Ana";
                    button.secundario type="button" data-passkey="registrar" { "Añadir una passkey" }
                    p #passkey-aviso {}
                }
            }
            form method="post" action="/salir" {
                button.tenue type="submit" { "Salir" }
            }
        },
    )
}

/// Pantalla de activación del segundo factor: muestra el secreto a enrolar y pide un
/// código para confirmar que la app quedó bien configurada.
pub fn activar_2fa(secreto: &str, aviso: Option<&str>) -> Markup {
    envoltura(
        "Activar 2FA",
        html! {
            h1 { "Activar segundo factor" small { "Añade este secreto a tu app TOTP" } }
            code.secreto { (secreto) }
            form method="post" action="/seguridad/2fa/confirmar" {
                input type="hidden" name="secreto" value=(secreto);
                label for="codigo" { "Código de 6 cifras para confirmar" }
                input type="text" id="codigo" name="codigo" inputmode="numeric" autocomplete="one-time-code" required autofocus;
                // STEP-UP: confirmar el cambio de 2FA exige la contraseña actual.
                label for="contrasena" { "Tu contraseña (confirma el cambio)" }
                input type="password" id="contrasena" name="contrasena" autocomplete="current-password" required;
                (aviso_error(aviso))
                button type="submit" { "Confirmar y activar" }
            }
        },
    )
}

/// Los códigos de recuperación, mostrados UNA sola vez tras activar el 2FA. Es la red de
/// seguridad: si se pierde el autenticador, uno de estos deja entrar (un solo uso). No se
/// vuelven a mostrar —sólo se guarda su Argon2—, así que la pantalla avisa de guardarlos ya.
pub fn codigos_recuperacion(codigos: &[String]) -> Markup {
    envoltura(
        "Códigos de recuperación",
        html! {
            h1 { "Guarda tus códigos de recuperación" small { "Se muestran UNA sola vez" } }
            p { "Si pierdes tu app de autenticación, cada uno de estos códigos te deja entrar una vez. Guárdalos en un lugar seguro; no volverás a verlos." }
            ul.codigos {
                @for codigo in codigos {
                    li { code.secreto { (codigo) } }
                }
            }
            a href="/" { "Ya los guardé, continuar" }
        },
    )
}
