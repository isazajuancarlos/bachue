-- SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
-- Bachué IdP — provisión "pago primero": una cuenta se PROVISIONA (no se crea con
-- contraseña) tras un pago verificado; el usuario real la RECLAMA fijando su clave.
--
-- Aquí NO se guarda ninguna contraseña ni el token en claro: el token de reclamo es
-- un token FIRMADO (bachue::sesion, dominio Recuperacion) que lleva el `id` de esta
-- fila; su validez y caducidad las sostiene la firma, no la base. Esta tabla solo
-- registra QUÉ usuario está pendiente de reclamo y si YA se reclamó (un solo uso).

CREATE TABLE provisiones (
    id          INTEGER PRIMARY KEY,          -- lo lleva el token de reclamo (firmado)
    usuario     TEXT    NOT NULL UNIQUE,      -- el usuario_id del pago (correo); una provisión por usuario
    referencia  TEXT    NOT NULL,             -- id de suscripción Paddle (auditoría)
    version     INTEGER NOT NULL DEFAULT 0,   -- reservado para revocar tokens en vuelo (hoy 0)
    usado       INTEGER NOT NULL DEFAULT 0,   -- 1 = ya reclamada; el reclamo es de UN solo uso (CAS)
    creado      TEXT    NOT NULL              -- RFC 3339
);
