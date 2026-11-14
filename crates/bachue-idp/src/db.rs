// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
// Copyright (c) 2026 Juan Carlos Isaza
//! La base: SQLite por instancia (WAL + claves foráneas, directiva 26). Queries en
//! tiempo de ejecución (`query_as`), sin exigir una BD en tiempo de compilación.

use crate::error::{Error, Resultado};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{FromRow, SqlitePool};
use std::str::FromStr;

#[derive(FromRow, Clone, Debug)]
pub struct Usuario {
    pub id: i64,
    pub usuario: String,
    pub hash: String,
    pub version: i64,
    pub totp_secret: Option<String>,
    pub totp_contador: Option<i64>,
    /// Fecha límite (RFC 3339) para enrolar el 2FA en modo `gracia`; `None` = sin asignar.
    pub enrolar_2fa_antes_de: Option<String>,
}

impl Usuario {
    pub fn tiene_2fa(&self) -> bool {
        self.totp_secret.is_some()
    }
}

pub async fn abrir(url: &str) -> Resultado<SqlitePool> {
    let opciones = SqliteConnectOptions::from_str(url)
        .map_err(|e| Error::Interno(format!("url de base de datos inválida: {e}")))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opciones)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

pub async fn usuario_por_nombre(pool: &SqlitePool, usuario: &str) -> Resultado<Option<Usuario>> {
    Ok(sqlx::query_as::<_, Usuario>(
        "SELECT id, usuario, hash, version, totp_secret, totp_contador, enrolar_2fa_antes_de \
         FROM usuarios WHERE usuario = ?",
    )
    .bind(usuario)
    .fetch_optional(pool)
    .await?)
}

pub async fn usuario_por_id(pool: &SqlitePool, id: i64) -> Resultado<Option<Usuario>> {
    Ok(sqlx::query_as::<_, Usuario>(
        "SELECT id, usuario, hash, version, totp_secret, totp_contador, enrolar_2fa_antes_de \
         FROM usuarios WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?)
}

/// Crea el usuario. Devuelve `None` si el nombre YA existe (la restricción UNIQUE): así
/// el registro no sobrescribe una cuenta ajena (lección del concilio sobre re-registro).
pub async fn crear_usuario(
    pool: &SqlitePool,
    usuario: &str,
    hash: &str,
    creado: &str,
) -> Resultado<Option<i64>> {
    match sqlx::query("INSERT INTO usuarios (usuario, hash, creado) VALUES (?, ?, ?)")
        .bind(usuario)
        .bind(hash)
        .bind(creado)
        .execute(pool)
        .await
    {
        Ok(r) => Ok(Some(r.last_insert_rowid())),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub async fn registrar_intento(
    pool: &SqlitePool,
    usuario: &str,
    origen: &str,
    momento: &str,
    exito: bool,
) -> Resultado<()> {
    sqlx::query("INSERT INTO intentos (usuario, origen, momento, exito) VALUES (?, ?, ?, ?)")
        .bind(usuario)
        .bind(origen)
        .bind(momento)
        .bind(i64::from(exito))
        .execute(pool)
        .await?;
    Ok(())
}

/// Como `registrar_intento`, pero devuelve el `id` de la fila insertada para poder
/// RETIRARLA después. Lo usa el cierre de la carrera check-then-act: se anota un fallo
/// PROVISIONAL antes de la verificación (cara) y, si resultó no contar —un acierto de
/// contraseña sobre una cuenta con 2FA, que no debe reiniciar el cubo PERO tampoco dejar
/// un fallo espurio contra el titular—, se borra ese `id` con `borrar_intento`.
pub async fn registrar_intento_prov(
    pool: &SqlitePool,
    usuario: &str,
    origen: &str,
    momento: &str,
) -> Resultado<i64> {
    let (id,): (i64,) =
        sqlx::query_as("INSERT INTO intentos (usuario, origen, momento, exito) VALUES (?, ?, ?, 0) RETURNING id")
            .bind(usuario)
            .bind(origen)
            .bind(momento)
            .fetch_one(pool)
            .await?;
    Ok(id)
}

/// Retira un intento por su `id` (el que devolvió `registrar_intento_prov`). Idempotente:
/// si ya no existe, no pasa nada.
pub async fn borrar_intento(pool: &SqlitePool, id: i64) -> Resultado<()> {
    sqlx::query("DELETE FROM intentos WHERE id = ?").bind(id).execute(pool).await?;
    Ok(())
}

/// Los intentos de un `(usuario, origen)` desde `corte` (RFC 3339), en orden cronológico
/// — justo lo que `freno::evaluar` necesita para decidir si frenar.
pub async fn intentos_desde(
    pool: &SqlitePool,
    usuario: &str,
    origen: &str,
    corte: &str,
) -> Resultado<Vec<(String, bool)>> {
    let filas: Vec<(String, i64)> = sqlx::query_as(
        "SELECT momento, exito FROM intentos \
         WHERE usuario = ? AND origen = ? AND momento >= ? ORDER BY momento",
    )
    .bind(usuario)
    .bind(origen)
    .bind(corte)
    .fetch_all(pool)
    .await?;
    Ok(filas.into_iter().map(|(m, e)| (m, e != 0)).collect())
}

/// Activa el 2FA de un usuario en UNA transacción: fija el secreto TOTP (cifrado) con su
/// contador anti-replay, y reemplaza sus códigos de recuperación por estos hashes (borra los
/// viejos). Atómico a propósito (concilio): un fallo parcial no puede dejar el 2FA activo SIN
/// su red de recuperación, ni códigos sin secreto. Re-enrolar invalida los códigos viejos
/// (D22: la limpieza se acota al usuario que se regenera). El `contador` es el del código con
/// que se confirmó, para que ese mismo código no se pueda repetir.
///
/// LÍMITE conocido (<8, concilio): la escritura no lleva guarda de `version`, así que un reset
/// del operador que caiga en la ventana entre leer al usuario y este `activar_2fa` (el hasheo
/// de 10 códigos Argon2) quedaría deshecho por el confirmar en vuelo. Es una carrera estrecha
/// (exige contraseña + timing) y auto-sanada (el operador ve al titular aún bloqueado y repite).
/// Cierre futuro coherente con el diseño: `WHERE id=? AND version=?` devolviendo `bool`.
pub async fn activar_2fa(
    pool: &SqlitePool,
    id: i64,
    totp_cifrado: &str,
    contador: i64,
    hashes: &[String],
) -> Resultado<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE usuarios SET totp_secret = ?, totp_contador = ? WHERE id = ?")
        .bind(totp_cifrado)
        .bind(contador)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM codigos_recuperacion WHERE usuario_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    for hash in hashes {
        sqlx::query("INSERT INTO codigos_recuperacion (usuario_id, hash, usado) VALUES (?, ?, 0)")
            .bind(id)
            .bind(hash)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Los HASHES de los códigos VIVOS (no usados) de un usuario, en orden estable.
/// `Resolucion::SuperadoRecuperacion { indice }` apunta a la posición en este mismo orden,
/// así que el hash de esa posición es el que se retira.
pub async fn codigos_recuperacion_vivos(
    pool: &SqlitePool,
    usuario_id: i64,
) -> Resultado<Vec<String>> {
    let filas: Vec<(String,)> = sqlx::query_as(
        "SELECT hash FROM codigos_recuperacion WHERE usuario_id = ? AND usado = 0 ORDER BY id",
    )
    .bind(usuario_id)
    .fetch_all(pool)
    .await?;
    Ok(filas.into_iter().map(|(h,)| h).collect())
}

/// Marca un código como usado (un solo uso), identificándolo por su `usuario_id` y su `hash`
/// —no por el `id` (rowid), que SQLite recicla al borrar y re-enrolar (concilio): un rowid
/// reutilizado marcaría el código equivocado—. El `usuario_id` ata la retirada al dueño en la
/// BD, no sólo en la lógica HTTP (defensa en profundidad). Devuelve `true` si lo marcó (CAS
/// `usado` 0→1), `false` si otra petición concurrente ya lo gastó — mismo anti-replay que el
/// contador TOTP.
pub async fn marcar_codigo_recuperacion_usado(
    pool: &SqlitePool,
    usuario_id: i64,
    hash: &str,
) -> Resultado<bool> {
    let r = sqlx::query(
        "UPDATE codigos_recuperacion SET usado = 1 WHERE usuario_id = ? AND hash = ? AND usado = 0",
    )
    .bind(usuario_id)
    .bind(hash)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// Fija la fecha límite de enrolamiento (modo `gracia`) SOLO si aún no tiene una — así cada
/// usuario recibe su ventana completa desde su primer login bajo la política, y una llamada
/// posterior no la recorta ni la reinicia (`WHERE enrolar_2fa_antes_de IS NULL`).
pub async fn fijar_limite_enrolar_2fa(pool: &SqlitePool, id: i64, limite: &str) -> Resultado<()> {
    sqlx::query(
        "UPDATE usuarios SET enrolar_2fa_antes_de = ? WHERE id = ? AND enrolar_2fa_antes_de IS NULL",
    )
    .bind(limite)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Reseteo de 2FA por OPERADOR (rompe-cristales): borra el secreto TOTP, su contador, la
/// ventana de gracia y TODOS los códigos de recuperación del usuario, en una transacción, y
/// **sube `version` para invalidar sus sesiones vivas** (`usuario_de_sesion` compara `version`):
/// un reset por compromiso no deja abierta la sesión que quizá abrió el atacante. Es la salida
/// cuando alguien pierde el autenticador Y los códigos; sin ella, el 2FA obligatorio fabricaría
/// cuentas muertas. Devuelve `true` si el usuario existía.
pub async fn limpiar_2fa(pool: &SqlitePool, id: i64) -> Resultado<bool> {
    let mut tx = pool.begin().await?;
    let r = sqlx::query(
        "UPDATE usuarios SET totp_secret = NULL, totp_contador = NULL, enrolar_2fa_antes_de = NULL, version = version + 1 WHERE id = ?",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM codigos_recuperacion WHERE usuario_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    // Remediación por compromiso: una passkey enrolada con una sesión robada NO debe
    // sobrevivir al reset, o el atacante conserva un acceso passwordless permanente que la
    // rotación de `version` no toca (las passkeys no son sesiones). Se borran en la MISMA
    // transacción que el reset de 2FA (concilio F3, 2026-10-06).
    sqlx::query("DELETE FROM credenciales_passkey WHERE usuario_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(r.rows_affected() == 1)
}

/// Sube `version` del usuario, lo que INVALIDA todas sus sesiones vivas
/// (`usuario_de_sesion` compara `version`). Es lo que hace que «Salir» cierre la
/// sesión DE VERDAD —no solo borre la cookie del navegador—: un token copiado
/// antes de salir deja de validar. Revoca TODOS los dispositivos del usuario, que
/// para un IdP es el cierre de sesión correcto. Devuelve `true` si el usuario
/// existía. (Misma rotación que usa el reset por operador, `limpiar_2fa`.)
pub async fn revocar_sesiones(pool: &SqlitePool, id: i64) -> Resultado<bool> {
    let r = sqlx::query("UPDATE usuarios SET version = version + 1 WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected() == 1)
}

// ───────────────────────── provisión "pago primero" ─────────────────────────

/// Resultado de intentar aprovisionar (crear un reclamo para) un usuario.
pub enum Aprovisionamiento {
    /// Reclamo pendiente: `id` y `version` van FIRMADOS en el token de reclamo.
    Pendiente { id: i64, version: i64 },
    /// El usuario YA tiene cuenta con contraseña: nada que provisionar.
    YaTieneCuenta,
    /// Ya hay una provisión RECLAMADA para ese usuario: no se re-emite token (409).
    YaReclamada,
}

/// Resultado de reclamar una provisión (fijar la contraseña).
pub enum Reclamo {
    /// Cuenta creada con la contraseña dada; los datos para abrir la sesión.
    Creada { id: i64, usuario: String, version: i64 },
    /// La cuenta YA existía (carrera): el token se gastó, pero no se creó nada nuevo.
    YaExistia,
    /// El token no vale: no hay tal provisión, o ya fue reclamada (el CAS perdió).
    NoVale,
}

/// Crea (o re-emite, si el webhook reintenta) el reclamo de un usuario. Idempotente:
/// - usuario con cuenta → `YaTieneCuenta` (no se toca, no se provisiona);
/// - provisión previa ya RECLAMADA → `YaReclamada`;
/// - provisión previa sin reclamar → se actualiza la referencia y se re-emite con el
///   MISMO `(id, version)` (el reclamo sigue siendo de un solo uso: lo garantiza `usado`);
/// - sin provisión → se crea (upsert por si dos webhooks corren a la vez).
pub async fn aprovisionar(
    pool: &SqlitePool,
    usuario: &str,
    referencia: &str,
    creado: &str,
) -> Resultado<Aprovisionamiento> {
    if usuario_por_nombre(pool, usuario).await?.is_some() {
        return Ok(Aprovisionamiento::YaTieneCuenta);
    }
    let previa: Option<(i64, i64, i64)> =
        sqlx::query_as("SELECT id, version, usado FROM provisiones WHERE usuario = ?")
            .bind(usuario)
            .fetch_optional(pool)
            .await?;
    match previa {
        Some((_, _, usado)) if usado != 0 => Ok(Aprovisionamiento::YaReclamada),
        Some((id, version, _)) => {
            sqlx::query("UPDATE provisiones SET referencia = ? WHERE id = ?")
                .bind(referencia)
                .bind(id)
                .execute(pool)
                .await?;
            Ok(Aprovisionamiento::Pendiente { id, version })
        }
        None => {
            // Upsert: si otra petición insertó la misma `usuario` entre el SELECT y aquí,
            // el ON CONFLICT la respeta en vez de reventar por la restricción UNIQUE.
            sqlx::query(
                "INSERT INTO provisiones (usuario, referencia, version, usado, creado) \
                 VALUES (?, ?, 0, 0, ?) \
                 ON CONFLICT(usuario) DO UPDATE SET referencia = excluded.referencia",
            )
            .bind(usuario)
            .bind(referencia)
            .bind(creado)
            .execute(pool)
            .await?;
            let (id, version, usado): (i64, i64, i64) =
                sqlx::query_as("SELECT id, version, usado FROM provisiones WHERE usuario = ?")
                    .bind(usuario)
                    .fetch_one(pool)
                    .await?;
            if usado != 0 {
                Ok(Aprovisionamiento::YaReclamada)
            } else {
                Ok(Aprovisionamiento::Pendiente { id, version })
            }
        }
    }
}

/// Reclama la provisión `id` (la del token): marca `usado` con COMPARE-AND-SWAP (un solo
/// uso — dos canjes del mismo token, solo uno gana) y crea la cuenta con `hash`. El orden
/// —gastar el token ANTES de crear la cuenta— es deliberado: si dos canjes corren a la vez,
/// solo el que gana el CAS crea la cuenta; el otro ve `NoVale`.
pub async fn reclamar_provision(
    pool: &SqlitePool,
    id: i64,
    hash: &str,
    creado: &str,
) -> Resultado<Reclamo> {
    let fila: Option<(String,)> = sqlx::query_as("SELECT usuario FROM provisiones WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    let Some((usuario,)) = fila else {
        return Ok(Reclamo::NoVale);
    };
    let cas = sqlx::query("UPDATE provisiones SET usado = 1 WHERE id = ? AND usado = 0")
        .bind(id)
        .execute(pool)
        .await?;
    if cas.rows_affected() == 0 {
        return Ok(Reclamo::NoVale); // ya reclamada: replay del token
    }
    match crear_usuario(pool, &usuario, hash, creado).await? {
        Some(nuevo_id) => Ok(Reclamo::Creada { id: nuevo_id, usuario, version: 0 }),
        None => Ok(Reclamo::YaExistia), // carrera: la cuenta ya se creó por otra vía
    }
}

/// Avanza el contador TOTP gastado (anti-replay del segundo factor) con COMPARE-AND-SWAP:
/// sólo escribe si el contador nuevo es MAYOR que el guardado (o no había ninguno).
/// Devuelve `true` si avanzó. Cierra el TOCTOU entre verificar el código y persistir: dos
/// peticiones concurrentes con el mismo código sólo dejan que UNA gane (hallazgo del concilio).
pub async fn actualizar_contador_totp(pool: &SqlitePool, id: i64, contador: i64) -> Resultado<bool> {
    let r = sqlx::query(
        "UPDATE usuarios SET totp_contador = ? \
         WHERE id = ? AND (totp_contador IS NULL OR totp_contador < ?)",
    )
    .bind(contador)
    .bind(id)
    .bind(contador)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// Los datos de un `authorization_code` OIDC que se necesitan al canjearlo en `/token`.
#[derive(FromRow, Clone, Debug)]
pub struct CodigoOidc {
    pub cliente: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub sub: String,
    pub nonce: Option<String>,
    /// La `version` del usuario cuando se emitió el código (en `/authorize`). `/token` la
    /// compara con la actual para invalidar el código si el usuario salió en medio.
    pub ver: Option<i64>,
}

/// Guarda un `authorization_code` OIDC recién emitido en `/authorize`.
#[allow(clippy::too_many_arguments)]
pub async fn crear_codigo_oidc(
    pool: &SqlitePool,
    codigo: &str,
    cliente: &str,
    redirect_uri: &str,
    code_challenge: &str,
    sub: &str,
    nonce: Option<&str>,
    expira: i64,
    ver: i64,
) -> Resultado<()> {
    sqlx::query(
        "INSERT INTO oidc_codigo (codigo, cliente, redirect_uri, code_challenge, sub, nonce, expira, ver) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(codigo)
    .bind(cliente)
    .bind(redirect_uri)
    .bind(code_challenge)
    .bind(sub)
    .bind(nonce)
    .bind(expira)
    .bind(ver)
    .execute(pool)
    .await?;
    Ok(())
}

/// Canjea el código de UN SOLO USO en `/token`: lo marca `usado` y devuelve sus datos, todo
/// en un UPDATE atómico con guarda `usado = 0 AND expira > ahora`. `None` = no existe, ya se
/// usó, o caducó — los tres indistinguibles a propósito (no se filtra al cliente cuál). El
/// COMPARE-AND-SWAP cierra el replay: dos canjes del mismo código, solo uno gana.
pub async fn canjear_codigo_oidc(
    pool: &SqlitePool,
    codigo: &str,
    ahora: i64,
) -> Resultado<Option<CodigoOidc>> {
    Ok(sqlx::query_as::<_, CodigoOidc>(
        "UPDATE oidc_codigo SET usado = 1 WHERE codigo = ? AND usado = 0 AND expira > ? \
         RETURNING cliente, redirect_uri, code_challenge, sub, nonce, ver",
    )
    .bind(codigo)
    .bind(ahora)
    .fetch_optional(pool)
    .await?)
}

// ───────────────────────── passkeys / WebAuthn (F3) ─────────────────────────

/// Una credencial passkey cargada por su `cred_id`, con lo que el login necesita: a quién
/// pertenece, su clave pública (SEC1), el algoritmo y el contador para la defensa anti-clon.
#[derive(FromRow, Clone, Debug)]
pub struct CredencialPasskey {
    pub id: i64,
    pub usuario_id: i64,
    pub cred_id: Vec<u8>,
    pub clave_sec1: Vec<u8>,
    pub algoritmo: i64,
    pub contador: i64,
}

/// Guarda un reto de ceremonia ligado a su propósito (`'registro'`|`'login'`). `usuario_id`
/// es `Some` en el registro (el de la sesión que enrola) y `None` en el login discoverable.
pub async fn crear_desafio_passkey(
    pool: &SqlitePool,
    reto: &[u8],
    proposito: &str,
    usuario_id: Option<i64>,
    expira: i64,
) -> Resultado<()> {
    sqlx::query(
        "INSERT INTO desafios_passkey (reto, proposito, usuario_id, expira, usado) VALUES (?, ?, ?, ?, 0)",
    )
    .bind(reto)
    .bind(proposito)
    .bind(usuario_id)
    .bind(expira)
    .execute(pool)
    .await?;
    Ok(())
}

/// Lo que devuelve consumir un reto: a quién estaba ligado (el registro lo fija; el login
/// discoverable no). El reto en sí no se devuelve (lo tiene el llamante).
pub struct DesafioConsumido {
    pub usuario_id: Option<i64>,
}

/// Consume el reto de UN SOLO USO para `proposito`: lo marca `usado` con COMPARE-AND-SWAP y
/// con guarda de caducidad, y devuelve a quién estaba ligado. `None` = no existe, ya se usó,
/// caducó, o es de otro propósito — indistinguibles a propósito (no se filtra cuál). Este CAS
/// es la defensa de replay PRIMARIA de la ceremonia: una respuesta repetida trae el mismo
/// reto, ya `usado`, y cae aquí antes de verificar nada (igual que `canjear_codigo_oidc`).
pub async fn consumir_desafio_passkey(
    pool: &SqlitePool,
    reto: &[u8],
    proposito: &str,
    ahora: i64,
) -> Resultado<Option<DesafioConsumido>> {
    let fila: Option<(Option<i64>,)> = sqlx::query_as(
        "UPDATE desafios_passkey SET usado = 1 \
         WHERE reto = ? AND proposito = ? AND usado = 0 AND expira > ? \
         RETURNING usuario_id",
    )
    .bind(reto)
    .bind(proposito)
    .bind(ahora)
    .fetch_optional(pool)
    .await?;
    Ok(fila.map(|(usuario_id,)| DesafioConsumido { usuario_id }))
}

/// Registra una passkey para un usuario. Devuelve `None` si el `cred_id` YA existe (UNIQUE):
/// una credencial no se re-registra sobre otra, sea del mismo usuario o de otro (defensa en
/// profundidad, misma lección que `crear_usuario`).
#[allow(clippy::too_many_arguments)]
pub async fn crear_credencial_passkey(
    pool: &SqlitePool,
    usuario_id: i64,
    cred_id: &[u8],
    clave_sec1: &[u8],
    algoritmo: i64,
    contador: i64,
    apodo: Option<&str>,
    creado: &str,
) -> Resultado<Option<i64>> {
    match sqlx::query(
        "INSERT INTO credenciales_passkey (usuario_id, cred_id, clave_sec1, algoritmo, contador, apodo, creado) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(usuario_id)
    .bind(cred_id)
    .bind(clave_sec1)
    .bind(algoritmo)
    .bind(contador)
    .bind(apodo)
    .bind(creado)
    .execute(pool)
    .await
    {
        Ok(r) => Ok(Some(r.last_insert_rowid())),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Carga la credencial por su `cred_id` (único en todo el sistema). Es el paso que, en el
/// login discoverable, convierte "esta credencial firmó" en "este usuario es su dueño".
pub async fn credencial_passkey_por_cred_id(
    pool: &SqlitePool,
    cred_id: &[u8],
) -> Resultado<Option<CredencialPasskey>> {
    Ok(sqlx::query_as::<_, CredencialPasskey>(
        "SELECT id, usuario_id, cred_id, clave_sec1, algoritmo, contador \
         FROM credenciales_passkey WHERE cred_id = ?",
    )
    .bind(cred_id)
    .fetch_optional(pool)
    .await?)
}

/// Avanza el contador anti-clonación de una credencial con COMPARE-AND-SWAP: solo escribe si
/// el `contador_nuevo` es MAYOR que el guardado. Devuelve `true` si avanzó (o si no hay nada
/// que avanzar porque el autenticador no lleva contador, `contador_nuevo == 0`: ese caso lo
/// cubre la unicidad del RETO, no el contador — ver `verificar_assertion`). `false` = otra
/// petición concurrente ya lo avanzó (TOCTOU), que se trata como replay. Espeja
/// `actualizar_contador_totp`.
pub async fn actualizar_contador_passkey(
    pool: &SqlitePool,
    id: i64,
    contador_nuevo: i64,
) -> Resultado<bool> {
    // Autenticador sin contador (siempre 0): no hay avance que exigir; el replay lo cierra el
    // reto de un solo uso. No se escribe (0 no es mayor que 0) y se da por bueno.
    if contador_nuevo == 0 {
        return Ok(true);
    }
    let r = sqlx::query(
        "UPDATE credenciales_passkey SET contador = ? WHERE id = ? AND contador < ?",
    )
    .bind(contador_nuevo)
    .bind(id)
    .bind(contador_nuevo)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// Resumen de una passkey para el panel del usuario: sin material criptográfico, solo lo que
/// se muestra (y el `id` para poder borrarla).
#[derive(FromRow, Clone, Debug)]
pub struct ResumenPasskey {
    pub id: i64,
    pub apodo: Option<String>,
    pub creado: String,
}

/// Los `cred_id` de las passkeys de un usuario, para `excludeCredentials` en el registro: el
/// autenticador no vuelve a crear una credencial para una que ya tiene (evita duplicados en
/// el mismo dispositivo).
pub async fn cred_ids_de_usuario(pool: &SqlitePool, usuario_id: i64) -> Resultado<Vec<Vec<u8>>> {
    let filas: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT cred_id FROM credenciales_passkey WHERE usuario_id = ?")
            .bind(usuario_id)
            .fetch_all(pool)
            .await?;
    Ok(filas.into_iter().map(|(c,)| c).collect())
}

/// Las passkeys de un usuario, para listarlas en el panel (más reciente primero).
pub async fn passkeys_de_usuario(pool: &SqlitePool, usuario_id: i64) -> Resultado<Vec<ResumenPasskey>> {
    Ok(sqlx::query_as::<_, ResumenPasskey>(
        "SELECT id, apodo, creado FROM credenciales_passkey WHERE usuario_id = ? ORDER BY id DESC",
    )
    .bind(usuario_id)
    .fetch_all(pool)
    .await?)
}

/// Borra una passkey del usuario (por `id` y `usuario_id`: nadie borra la de otro). Devuelve
/// `true` si existía y era suya.
pub async fn borrar_passkey(pool: &SqlitePool, id: i64, usuario_id: i64) -> Resultado<bool> {
    let r = sqlx::query("DELETE FROM credenciales_passkey WHERE id = ? AND usuario_id = ?")
        .bind(id)
        .bind(usuario_id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected() == 1)
}
