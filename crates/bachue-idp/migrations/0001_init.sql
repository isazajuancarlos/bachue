-- SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
-- Bachué IdP — esquema inicial. Una base por instancia (directiva 26).

CREATE TABLE usuarios (
    id               INTEGER PRIMARY KEY,
    usuario          TEXT    NOT NULL UNIQUE,
    hash             TEXT    NOT NULL,           -- Argon2 (guaca::claves), nunca la contraseña
    version          INTEGER NOT NULL DEFAULT 0, -- se sube para revocar TODAS las sesiones
    totp_secret      TEXT,                       -- NULL = sin segundo factor
    totp_contador    INTEGER,                    -- último contador TOTP gastado (anti-replay)
    creado           TEXT    NOT NULL            -- RFC 3339
);

-- Bitácora de intentos de login, para el freno por (usuario, origen). El origen es la
-- IP del cliente extraída con defensas::red (no la del socket detrás de un proxy).
CREATE TABLE intentos (
    id       INTEGER PRIMARY KEY,
    usuario  TEXT    NOT NULL,   -- el TECLEADO (exista o no la cuenta)
    origen   TEXT    NOT NULL,   -- IP del cliente
    momento  TEXT    NOT NULL,   -- RFC 3339
    exito    INTEGER NOT NULL    -- 0 = fallo, 1 = acierto
);

CREATE INDEX idx_intentos_freno ON intentos (usuario, origen, momento);
