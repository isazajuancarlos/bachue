# Verificación E2E de passkeys en navegador real

Los `tests/passkey_e2e.rs` cubren TODA la criptografía del servidor (registro, login
discoverable, replay, origen phishing, credencial ajena, contador anti-clon, capa
apagada) con un autenticador ES256 **de software**, 7/7. Lo que NO cubren es el código
JS del cliente (`estaticos/passkey.js`): el armado de las opciones WebAuthn, la
conversión base64url↔ArrayBuffer, la extracción de la respuesta de `create()`/`get()`,
y el swap htmx en el DOM. Eso solo se prueba **dibujando la pantalla** en un navegador
real (directiva 28). Esta es la receta de esa pasada manual, que se corre UNA vez al
tocar la ceremonia o el JS cliente.

> **Estado:** verificada el 2026-10-06 en Windows 11 + Brave, con Windows Hello como
> autenticador de plataforma. Ciclo completo VERDE: registro → persistencia → login
> passwordless → borrado.

> **OJO — el prefijo (`/auth` en prod):** en localhost la app va en la RAÍZ, pero en el VPS
> nginx la monta bajo `/auth` reescribiendo el HTML. Ese prefijo NO se ejercita en localhost,
> así que este E2E de raíz NO prueba que `passkey.js` funcione tras el prefijo. `passkey.js`
> deduce su base de `import.meta.url` y la antepone a cada `fetch`. Para probarlo de verdad,
> sirve bajo un prefijo (nginx local con el mismo `sub_filter`, o `BACHUE_IDP_PASSKEY_ORIGEN`
> correcto) y confirma en la pestaña Red que los `POST` van a `<prefijo>/passkey/...` y dan 200,
> no 302. (Bug cazado en prod el 2026-10-06: fetches absolutos desde la raíz → 302.)

## 1. Arrancar el IdP local con passkeys activadas

Binario ya compilado (`cargo build -p bachue-idp`). Desde PowerShell, en un directorio
de scratch (crea `bachue-e2e.db` en el cwd; no versionar):

```powershell
$env:BACHUE_IDP_SECRETO        = "dev-secreto-passkey-e2e-0123456789ABCDEF"  # ≥32 bytes
$env:BACHUE_IDP_INSEGURO       = "1"                      # permite http (solo dev)
$env:BACHUE_IDP_REGISTRO_ABIERTO = "1"                    # /registrarse abierto
$env:BACHUE_IDP_RP_ID          = "localhost"              # enciende la capa passkeys
$env:BACHUE_IDP_PASSKEY_ORIGEN = "http://localhost:8090"  # origen esperado (http en dev)
$env:BACHUE_IDP_PUERTO         = "8090"
$env:BACHUE_IDP_DB             = "sqlite://bachue-e2e.db"
& Z:\bachue\target\debug\bachue-idp.exe
```

`http://localhost` es contexto seguro para WebAuthn, así que `INSEGURO=1` basta; no hace
falta TLS. El RP ID debe ser `localhost` y el origen `http://localhost:8090` (con puerto).

## 2. El autenticador

Hay dos vías. La que FUNCIONÓ en Brave fue **Windows Hello** (autenticador de plataforma
real). El autenticador virtual de DevTools (`WebAuthn.addVirtualAuthenticator`) **no
interceptó** en Brave en esta máquina: al disparar `create()` salió igualmente el diálogo
nativo de Windows. Si se quiere la vía virtual, hay que confirmar que el entorno virtual
está realmente activo y capturando antes de la ceremonia; si sale el diálogo del SO, no lo
está.

Con Windows Hello, la passkey de prueba queda guardada en el almacén de Windows
(Configuración → Cuentas → Claves de acceso, bajo `localhost`) y se borra ahí al terminar.

## 3. DOS trampas de FOCO (esto es lo que cuesta descubrir)

`navigator.credentials.create()/get()` lanza `NotAllowedError: "the operation is not
allowed at this time because the page does not have focus"` si no se cumplen **las dos**:

1. **La ventana del navegador debe ser la ventana ACTIVA del sistema operativo.** Un clic
   sintético de automatización NO la activa. Si conduces desde una terminal, el foco del SO
   vuelve a la terminal en cuanto interactúas con ella — por eso **el clic que dispara la
   ceremonia lo tiene que dar un humano en la ventana del navegador**, o hay que minimizar
   la terminal para ceder el foreground (`ShowWindow(term, SW_MINIMIZE)` fuerza el cambio;
   `SetForegroundWindow` solo NO basta, Windows bloquea el robo de foreground).

2. **DevTools NO puede estar ACOPLADO (docked) a la ventana.** Docked, WebAuthn ve "sin
   foco" aunque `document.hasFocus()` devuelva `true` y la ventana esté al frente. Hay que
   desacoplarlo a ventana separada (menú ⋮ → Dock side → Undock into separate window) o no
   abrirlo. Este es el fallo más engañoso: todo "parece" enfocado y aun así falla.

## 4. El guion

Cuenta de prueba (si no existe, créala en `/registrarse`):
`usuario = e2epasskey`, `contraseña = Zorro-Nieve-Caoba-Rio-42` (≥12, no predecible).

1. **Registro:** autenticado, en `/` → sección Passkeys → (opcional nombre) → **Añadir una
   passkey** → confirmar Windows Hello (PIN/huella). Debe aparecer la passkey en la lista
   con su fecha, sin "Registro cancelado o fallido".
2. **Comprobar persistencia (servidor, no solo DOM):** en la consola (el `/inicio` exige
   ahora la contraseña actual como step-up — ponla en `contrasena`),
   `fetch('/passkey/registrar/inicio',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({contrasena:'Zorro-Nieve-Caoba-Rio-42'})}).then(r=>r.json()).then(o=>o.excludeCredentials)`
   debe listar la credencial recién creada (prueba que está en la BD, no solo pintada).
3. **Login passwordless:** **Salir** → `/entrar` → **Entrar con una passkey** → confirmar
   Windows Hello. Debe entrar **sin teclear usuario ni contraseña** y volver a
   "ESTÁS AUTENTICADO".
4. **Borrado:** en el panel, botón **Quitar** de una passkey. Desaparece de la lista y del
   `excludeCredentials` del servidor.

Ojo: el botón **Quitar** borra la credencial en la **BD de bachue**; borrar la passkey en
el almacén de **Windows** (Configuración) es otro sitio. El login necesita que exista en
los dos; si borras solo la de Windows, el panel de bachue la sigue mostrando pero el login
no la encontrará.

## 5. Limpieza

- Borrar la passkey de prueba del almacén de Windows (Configuración → Cuentas → Claves de
  acceso → `localhost`).
- Borrar `bachue-e2e.db` del scratch.
- Parar el binario.
