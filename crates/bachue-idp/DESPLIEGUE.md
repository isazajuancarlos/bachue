<!-- SPDX-License-Identifier: LicenseRef-Xiliux-Propietario -->
# Despliegue de bachue-idp

**El VPS NO tiene Docker.** bachue-idp corre como **servicio systemd**
(`bachue-idp.service`), un solo binario Linux en `/home/debian/bachue-idp/bachue-idp`
(directiva 26: un ejecutable + SQLite). No hay imagen, no hay contenedor. Por eso
este repo **no** lleva `Dockerfile` (se retiró el 2026-10-06; describía un deploy
que no existe).

## 1. Construir el binario Linux (desde el dev Windows)

El viejo box Linux que compilaba ya no existe; se cruza desde Windows con
**`cargo-zigbuild`** (sin Docker, sin WSL). `zig` hace de enlazador C: las únicas
deps C del árbol son `ring` (TLS de reqwest) y `libsqlite3-sys`, que cruzan limpio.

```powershell
# requisitos (una vez): scoop install zig ; rustup target add x86_64-unknown-linux-gnu ;
#                        cargo install cargo-zigbuild
cd Z:\bachue
cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.31 -p bachue-idp
# binario: Z:\bachue\target\x86_64-unknown-linux-gnu\release\bachue-idp
```

- **glibc 2.31** (Debian 11) fijado a propósito: corre en el Debian 13 del VPS
  (glibc más nueva) sin la sorpresa de "built against too-new glibc".
- Las deps `quipu`/`guaca` resuelven por ruta relativa (`../quipu`, `../../../guaca`):
  deben estar como hermanas de `Z:\bachue` y **LIMPIAS** (`git status` sin cambios),
  porque el binario enlaza lo que esté *checked out*, no un `rev` fijo. Anota los SHA
  que compilaste (D31): el SHA de bachue NO determina la cripto del binario.

## 2. Desplegar (lo corre Juan; TOCAR el VPS se anuncia antes)

`desplegar.ps1` hace la secuencia entera y verificada de `conocimiento/despliegue/VPS.md`:
respaldo con marca de tiempo del binario actual → `scp` del nuevo → `sha256` que debe
COINCIDIR a los dos lados → `systemctl restart` → `is-active` + `journalctl` + `curl`
al dominio. **Nunca pisa el `.env` del servidor** (ahí están las credenciales de prod).

```powershell
# tras construir, y tras correr la revisión de seguridad sobre el SHA que se despliega (D25):
powershell -File Z:\bachue\desplegar.ps1
```

La verdad de lo desplegado es el `curl` a `https://tunjo.xiliux.com/entrar`, no el
`is-active` (un servicio con `Restart=always` puede verse activo y servir 502).
Vuelta atrás: `desplegar.ps1 -Revertir` restaura el último `.bak-<marca>` y reinicia.
