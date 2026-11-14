-- Códigos de recuperación del 2FA: la red que hace SEGURO exigir el segundo factor.
-- Sin ellos, perder el autenticador es una cuenta muerta (el lockout que guaca::freno
-- rechaza por diseño). Cada código se guarda como Argon2 (guaca::claves), nunca en claro;
-- se muestran una sola vez al enrolar. `usado` es de un solo uso (CAS 0→1, como el
-- contador anti-replay del TOTP).
CREATE TABLE codigos_recuperacion (
    id         INTEGER PRIMARY KEY,
    usuario_id INTEGER NOT NULL REFERENCES usuarios(id),
    hash       TEXT    NOT NULL,
    usado      INTEGER NOT NULL DEFAULT 0
);
-- Cubre la consulta de códigos VIVOS de un usuario (usuario_id + usado).
CREATE INDEX idx_codigos_recuperacion_vivos ON codigos_recuperacion (usuario_id, usado);
