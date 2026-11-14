-- Obligatoriedad del 2FA (modo `gracia`): la fecha límite, por usuario, para enrolar el
-- segundo factor antes de que se le fuerce. NULL = sin ventana asignada aún (se fija en el
-- primer login bajo `gracia` de un usuario sin 2FA). RFC 3339, como el resto de marcas.
-- Es per-usuario y no global (D32): cada quien recibe su ventana completa desde su primer
-- login tras activarse la política, no una fecha común que deje fuera a los que entran tarde.
ALTER TABLE usuarios ADD COLUMN enrolar_2fa_antes_de TEXT;
