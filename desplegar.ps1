# SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
# Despliegue de bachue-idp al VPS (systemd, sin Docker). LO CORRE JUAN.
# Secuencia verificada de conocimiento/despliegue/VPS.md: respaldo con marca ->
# scp -> sha256 que COINCIDE a los dos lados -> systemctl restart -> is-active +
# journalctl -> curl al dominio. NUNCA pisa el .env del servidor.
#   Desplegar:  powershell -File Z:\bachue\desplegar.ps1
#   Revertir:   powershell -File Z:\bachue\desplegar.ps1 -Revertir
param([switch]$Revertir)
$ErrorActionPreference = 'Stop'

$Servidor = 'debian@192.99.42.108'
$Dest     = '/home/debian/bachue-idp'
$Svc      = 'bachue-idp'
$Url      = 'https://tunjo.xiliux.com/entrar'
$BinLocal = 'Z:\bachue\target\x86_64-unknown-linux-gnu\release\bachue-idp'
$SshOpts  = @('-o','ControlMaster=no','-o','ControlPath=none','-o','ConnectTimeout=20')

function Remoto([string]$cmd) { & ssh @SshOpts $Servidor $cmd }

if ($Revertir) {
    Write-Host '== REVERTIR al ultimo respaldo ==' -ForegroundColor Yellow
    $ultimo = (Remoto "ls -1t $Dest/bachue-idp.bak-* 2>/dev/null | head -1").Trim()
    if (-not $ultimo) { throw 'No hay respaldo .bak-* en el servidor.' }
    Write-Host "Restaurando $ultimo"
    # Mismo patrón que el deploy: no se trunca el binario en ejecución (ETXTBSY); se copia a un
    # temporal y se activa con rename atómico.
    Remoto "cp -a '$ultimo' $Dest/bachue-idp.nuevo && mv -f $Dest/bachue-idp.nuevo $Dest/bachue-idp && sudo -n systemctl restart $Svc && sleep 5 && systemctl is-active $Svc"
    $codigo = Remoto "curl -s -o /dev/null -w '%{http_code}' $Url"
    Write-Host "curl $Url -> $codigo"
    return
}

# 0. Binario local presente + su huella.
if (-not (Test-Path $BinLocal)) { throw "No existe $BinLocal. Construye primero (ver DESPLIEGUE.md)." }
$shaLocal = (Get-FileHash $BinLocal -Algorithm SHA256).Hash.ToLower()
Write-Host "Binario local: $BinLocal"
Write-Host "sha256 local:  $shaLocal"
# Avisa si guaca/quipu tienen el arbol sucio (el binario enlaza lo que este checked out, D31).
foreach ($r in 'quipu','guaca') {
    $sucio = (& git -C "Z:\$r" status --porcelain) -join ''
    $sha   = (& git -C "Z:\$r" rev-parse --short HEAD)
    Write-Host ("  {0}: {1}{2}" -f $r, $sha, $(if ($sucio) { ' (ARBOL SUCIO!)' } else { '' })) -ForegroundColor $(if ($sucio) { 'Yellow' } else { 'Gray' })
}

# 1. RESPALDO del binario remoto, con marca de tiempo.
$marca = Get-Date -Format 'yyyyMMdd-HHmmss'
Write-Host "== Respaldo remoto bachue-idp.bak-$marca =="
Remoto "test -f $Dest/bachue-idp && cp -a $Dest/bachue-idp $Dest/bachue-idp.bak-$marca && echo respaldado"

# 2. SUBIR a un nombre TEMPORAL. NO se escribe sobre el binario en ejecución: truncarlo da
#    ETXTBSY ("Text file busy"). Se sube aparte y se activa con un rename atómico (paso 4).
Write-Host '== scp del binario nuevo (a .nuevo) =='
& scp @SshOpts $BinLocal "${Servidor}:$Dest/bachue-idp.nuevo"
if ($LASTEXITCODE -ne 0) { throw 'scp falló.' }

# 3. VERIFICAR que lo subido coincide (sha256) y marcarlo ejecutable (scp desde Windows no trae +x).
$shaRemoto = (Remoto "sha256sum $Dest/bachue-idp.nuevo | cut -d' ' -f1").Trim()
Write-Host "sha256 remoto: $shaRemoto"
if ($shaRemoto -ne $shaLocal) {
    Remoto "rm -f $Dest/bachue-idp.nuevo"
    throw "sha256 NO coincide (local $shaLocal != remoto $shaRemoto). Nada se activó; .nuevo borrado."
}
Write-Host 'sha256 coincide.' -ForegroundColor Green
Remoto "chmod 755 $Dest/bachue-idp.nuevo"

# 4. ACTIVAR con rename atómico (no choca con el inodo en ejecución) y reiniciar.
Write-Host '== mv atómico + systemctl restart + journal =='
Remoto "mv -f $Dest/bachue-idp.nuevo $Dest/bachue-idp && sudo -n systemctl restart $Svc && sleep 6 && systemctl is-active $Svc && journalctl -u $Svc -n 12 --no-pager"

# 5. LA VERDAD: curl al dominio (no el is-active).
$codigo = Remoto "curl -s -o /dev/null -w '%{http_code}' $Url"
Write-Host "curl $Url -> $codigo"
if ($codigo -match '^(2|3)\d\d$') {
    Write-Host "OK: desplegado y vivo ($codigo). Respaldo previo en $Dest/bachue-idp.bak-$marca" -ForegroundColor Green
} else {
    throw "El dominio responde $codigo (no 2xx/3xx). Revisa el journal y revierte con -Revertir."
}
