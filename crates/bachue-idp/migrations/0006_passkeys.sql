-- SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
-- Passkeys / WebAuthn (F3): las credenciales registradas y los retos de un solo uso de las
-- dos ceremonias (registro `create()` y login `get()`). El andamiaje y la cripto viven en
-- `bachue-passkey`/`bachue-passkey-es256`; aquí solo se PERSISTE lo que el servicio tiene
-- que guardar entre el inicio y el fin de cada ceremonia.

-- Una passkey registrada de un usuario. Se carga por `cred_id` (el id que devuelve el
-- navegador), que es ÚNICO en todo el sistema: por él se identifica al usuario en el login
-- discoverable (sin que el usuario teclee su nombre), de ahí el UNIQUE y su índice implícito.
CREATE TABLE credenciales_passkey (
    id          INTEGER PRIMARY KEY,
    usuario_id  INTEGER NOT NULL REFERENCES usuarios(id),
    cred_id     BLOB    NOT NULL UNIQUE,         -- Credencial::id (bytes del navegador)
    clave_sec1  BLOB    NOT NULL,                -- clave pública en SEC1 (0x04‖x‖y), la deja el registro
    algoritmo   INTEGER NOT NULL,               -- alg COSE: -7 = ES256 (hoy el único soportado)
    contador    INTEGER NOT NULL,               -- signCount anti-clonación; AVANZA en cada login (CAS)
    apodo       TEXT,                            -- etiqueta opcional que pone el usuario (p.ej. "iPhone")
    creado      TEXT    NOT NULL                 -- RFC 3339
);
-- Cubre "las passkeys de este usuario" (listar en el panel, y poblar allowCredentials si
-- algún día se hace login no-discoverable).
CREATE INDEX idx_credenciales_passkey_usuario ON credenciales_passkey (usuario_id);

-- El reto (challenge) de una ceremonia en vuelo. De un solo uso: se CONSUME con
-- compare-and-swap (`usado` 0→1 con guarda de caducidad) al terminar la ceremonia —mismo
-- anti-replay que `oidc_codigo` y el contador TOTP—. `proposito` separa los dos ritos para
-- que un reto de registro no sirva para iniciar sesión ni al revés.
--
-- `usuario_id` es NULL en el login DISCOVERABLE (passwordless): el reto NO se liga a un
-- usuario porque es la credencial devuelta la que identifica a su dueño; en el registro va
-- el usuario de la sesión que enrola. Un reto nunca es secreto (viaja al navegador), pero su
-- VALOR es único (UNIQUE) para que el CAS sobre él sea exacto.
CREATE TABLE desafios_passkey (
    id          INTEGER PRIMARY KEY,
    reto        BLOB    NOT NULL UNIQUE,         -- Desafio::bytes() (32 B de OsRng)
    proposito   TEXT    NOT NULL,               -- 'registro' | 'login'
    usuario_id  INTEGER REFERENCES usuarios(id),-- la ceremonia de registro lo fija; el login no
    expira      INTEGER NOT NULL,               -- epoch UTC de caducidad (ventana corta)
    usado       INTEGER NOT NULL DEFAULT 0       -- CAS 0→1 al consumir (un solo uso)
);
