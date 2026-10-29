Set-Location $PSScriptRoot
docker info *> $null
if ($LASTEXITCODE -ne 0) { Write-Host "Abre Docker Desktop y espera a 'Engine running'."; exit 1 }

$cfg = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq "Up" -and $_.InterfaceAlias -notmatch "Tailscale|vEthernet|WSL|VirtualBox|Docker|VMware" } | Select-Object -First 1
if (-not $cfg) { Write-Host "No hay red activa. Conectate al Wi-Fi y repite."; exit 1 }
$ip = @($cfg.IPv4Address)[0].IPAddress
$m = Select-String -Path .env -Pattern '^APP_BASE_URL=http://([^:/]+)' | Select-Object -First 1
$saved = if ($m) { $m.Matches[0].Groups[1].Value } else { "" }

# Respaldo de tarjetas NFC y usuarios (solo lectura del volumen)
New-Item -ItemType Directory -Force backups | Out-Null
docker volume inspect identity-access-lab-mvp_app_data *> $null
if ($LASTEXITCODE -eq 0) {
  docker run --rm -v identity-access-lab-mvp_app_data:/d -v "${PWD}\backups:/b" alpine sh -c "tar czf /b/app_data.tgz -C /d ." *> $null
  if ($LASTEXITCODE -eq 0) { Write-Host "Respaldo guardado en backups\app_data.tgz" }
}

if ($ip -ne $saved) {
  Write-Host "La IP cambio ($saved -> $ip). Ajustando sin borrar datos..."
  & "$PSScriptRoot\actualizar-ip.ps1" -Ip $ip
} else {
  docker compose up -d
}

Write-Host "Esperando a la app..."
$ok = $false
for ($i = 0; $i -lt 40; $i++) {
  try { if ((Invoke-WebRequest "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 5).StatusCode -eq 200) { $ok = $true; break } } catch {}
  Start-Sleep -Seconds 5
}
docker compose ps
if (-not $ok) { Write-Host "La app no respondio: docker compose logs --tail 60 app"; exit 1 }

if (Select-String -Path .env -Pattern '^NFC_ENABLED=true' -Quiet) {
  $tok = (Select-String -Path .env -Pattern '^NFC_BRIDGE_TOKEN=(.+)$').Matches[0].Groups[1].Value.Trim()
  Start-Process powershell -ArgumentList "-NoExit","-ExecutionPolicy","Bypass","-File","$PSScriptRoot\tools\nfc-bridge.ps1","-Token","$tok"
  Write-Host "Puente NFC abierto en otra ventana (no la cierres)."
}
Write-Host ""
Write-Host "Dashboard: http://${ip}:8000"
Write-Host "Frigate:   http://${ip}:5000"
