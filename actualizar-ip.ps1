param([string]$Ip = "", [string]$CamIp = "", [switch]$ResetKeycloak)
Set-Location $PSScriptRoot
$utf8 = New-Object System.Text.UTF8Encoding $false

docker info *> $null
if ($LASTEXITCODE -ne 0) { Write-Host "Docker no esta activo. Abre Docker Desktop, espera a 'Engine running' y repite."; exit 1 }

# 1. IP actual (adaptador con puerta de enlace, sin redes virtuales)
if (-not $Ip) {
  $cfg = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq "Up" -and $_.InterfaceAlias -notmatch "Tailscale|vEthernet|WSL|VirtualBox|Docker|VMware" } | Select-Object -First 1
  if (-not $cfg) { Write-Host "No encontre una red activa. Usa: .\actualizar-ip.ps1 -Ip x.x.x.x"; exit 1 }
  $Ip = @($cfg.IPv4Address)[0].IPAddress
}
Write-Host "IP del servidor: $Ip"

# 2. Reemplazar cualquier IP privada que acompane a los puertos del laboratorio
$priv = '(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})'
$pat = '(?<![\d.])' + $priv + '(?=:(?:(?:8000|8081|5000|8971|8555)(?!\d)|"))'
$files = @(".env","compose.yaml","keycloak\identity-access-realm.json","frigate\config\config.yml","frigate\config.yml")
$files += Get-ChildItem -Recurse app -File -Include *.py,*.html,*.js,*.j2 | ForEach-Object { $_.FullName }
foreach ($f in $files) {
  if (-not (Test-Path $f)) { continue }
  $p = (Resolve-Path $f).Path
  $c = [System.IO.File]::ReadAllText($p, [System.Text.Encoding]::UTF8)
  $n = [regex]::Replace($c, $pat, $Ip)
  if ($n -ne $c) { [System.IO.File]::WriteAllText($p, $n, $utf8); Write-Host "Actualizado: $f" }
}

# 3. Variables del .env
function Set-EnvVar($name, $value) {
  $l = @([System.IO.File]::ReadAllLines("$PWD\.env"))
  if ($l -match "^$name=") { $l = $l | ForEach-Object { if ($_ -match "^$name=") { "$name=$value" } else { $_ } } } else { $l += "$name=$value" }
  [System.IO.File]::WriteAllLines("$PWD\.env", $l, $utf8)
}
Set-EnvVar "APP_BASE_URL" "http://${Ip}:8000"
if ($CamIp) { Set-EnvVar "FRIGATE_CAM_ENTRADA_IP" $CamIp }

# 4. wsgi.py: aceptar cualquier red privada (ya no depende de una IP fija)
$w = "$PWD\app\wsgi.py"
$t = [System.IO.File]::ReadAllText($w, [System.Text.Encoding]::UTF8)
$t2 = [regex]::Replace($t, 'base\.startswith\(\([^)]*\)\)', 'base.startswith(("http://localhost", "http://192.168.", "http://10.", "http://172.", "https://"))')
if ($t2 -ne $t) { [System.IO.File]::WriteAllText($w, $t2, $utf8); Write-Host "wsgi.py: validacion de red privada aplicada" }

# 5. Realm: redirecciones por rango privado (evita borrar Keycloak en futuros cambios de red)
$rp = "$PWD\keycloak\identity-access-realm.json"
$realm = [System.IO.File]::ReadAllText($rp, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
$wild = @("http://localhost:8000/*","http://192.168.*","http://10.*") + (16..31 | ForEach-Object { "http://172.$_.*" })
$changed = $false
foreach ($c in $realm.clients) {
  if ($c.redirectUris -and (($c.redirectUris -join " ") -match "8000")) {
    $new = @(@($c.redirectUris) + $wild | Select-Object -Unique)
    if ($new.Count -ne @($c.redirectUris).Count) {
      $c | Add-Member -NotePropertyName redirectUris -NotePropertyValue $new -Force
      $c | Add-Member -NotePropertyName webOrigins -NotePropertyValue @("+") -Force
      $changed = $true
    }
  }
}
if ($changed) { [System.IO.File]::WriteAllText($rp, (ConvertTo-Json -InputObject $realm -Depth 100), $utf8); Write-Host "Realm: redirecciones por rango privado agregadas" }

# 6. Reiniciar servicios
docker compose down
if ($ResetKeycloak) { docker volume rm identity-access-lab-mvp_keycloak_data identity-access-lab-mvp_app_data }
docker compose up -d --build --force-recreate

# 7. Esperar y verificar
Write-Host "Esperando a la app (puede tardar 1-2 minutos)..."
$ok = $false
for ($i = 0; $i -lt 40; $i++) {
  try { if ((Invoke-WebRequest "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 5).StatusCode -eq 200) { $ok = $true; break } } catch {}
  Start-Sleep -Seconds 5
}
docker compose ps
if (-not $ok) { Write-Host "La app no respondio. Revisa: docker compose logs --tail 60 app"; exit 1 }
$loc = curl.exe -s -D - -o NUL http://localhost:8000/login | Select-String -Pattern "(?i)^location:"
if ($loc -and $loc.ToString().Contains($Ip)) { Write-Host "Login OK: redirige a Keycloak en $Ip" } else { Write-Host "AVISO: el login no redirige a $Ip -> $loc" }
Write-Host ("Acceso desde la red al puerto 8000: " + (Test-NetConnection $Ip -Port 8000 -WarningAction SilentlyContinue).TcpTestSucceeded)
if (-not (Get-NetFirewallRule -DisplayName "IAM Lab*" -ErrorAction SilentlyContinue)) { Write-Host "AVISO: faltan reglas de firewall (ejecuta el bloque de firewall como administrador)" }
Write-Host ""
Write-Host "Dashboard: http://${Ip}:8000"
Write-Host "Frigate:   http://${Ip}:5000"
Write-Host "Keycloak:  http://${Ip}:8081"
