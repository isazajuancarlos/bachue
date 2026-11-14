-- SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
-- OIDC (veta mindalá #1, rebanada 3): el authorization_code de un solo uso.
-- Vida corta (lo fija el emisor, ~60 s) y consumo COMPARE-AND-SWAP en /token: un código
-- solo se canjea una vez (replay = rechazo). Guarda el code_challenge (PKCE S256) que se
-- verifica contra el code_verifier en /token, el sujeto autenticado y el nonce del RP.
CREATE TABLE oidc_codigo (
    codigo         TEXT    PRIMARY KEY,      -- aleatorio 256 bits, base64url
    cliente        TEXT    NOT NULL,         -- client_id al que se emitió
    redirect_uri   TEXT    NOT NULL,         -- la URI EXACTA validada en /authorize
    code_challenge TEXT    NOT NULL,         -- PKCE S256 (base64url(SHA-256(verifier)))
    sub            TEXT    NOT NULL,         -- sujeto autenticado (usuario)
    nonce          TEXT,                     -- nonce del RP (opcional), va al id_token
    expira         INTEGER NOT NULL,         -- epoch UTC de caducidad
    usado          INTEGER NOT NULL DEFAULT 0
);
