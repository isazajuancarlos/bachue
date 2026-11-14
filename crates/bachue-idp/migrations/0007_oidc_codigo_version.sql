-- SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
-- La `version` del usuario en el MOMENTO de /authorize, guardada junto al authorization_code.
-- `/token` exige que coincida con la version ACTUAL al canjear: si el usuario hizo `salir`
-- (que sube `version`) entre /authorize y /token, el código pendiente queda invalidado
-- (invalid_grant) en vez de producir un access_token que sobreviva al logout (concilio
-- 2026-10-18, hallazgo fable: el `ver` se fijaba al canjear, no al autorizar).
-- Nullable: no hay códigos en vuelo (viven 60 s); un código pre-migración sin `ver` lo trata
-- `/token` como fail-closed (invalid_grant).
ALTER TABLE oidc_codigo ADD COLUMN ver INTEGER;
