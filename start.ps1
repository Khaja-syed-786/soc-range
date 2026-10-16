# Start the SOC Simulator in the background and open the browser.
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$cfg = try { Get-Content (Join-Path $root 'config.json') -Raw -ErrorAction Stop | ConvertFrom-Json } catch { $null }
# Same order as src/config.js: SOCSIM_DATA_DIR, then config.json dataDir, then %LOCALAPPDATA%\SocSim
$dataDir = if ($env:SOCSIM_DATA_DIR) { $env:SOCSIM_DATA_DIR }
           elseif ($cfg -and $cfg.dataDir) { $cfg.dataDir }
           else { Join-Path $env:LOCALAPPDATA 'SocSim' }
if (-not [IO.Path]::IsPathRooted($dataDir)) { $dataDir = Join-Path $root $dataDir }
$port = if ($cfg -and $cfg.port) { $cfg.port } else { 5000 }
$pidFile = Join-Path $dataDir 'server.pid'
$url = "http://127.0.0.1:$port"
New-Item -ItemType Directory -Force $dataDir | Out-Null

if (Test-Path $pidFile) {
    $old = Get-Process -Id (Get-Content $pidFile) -ErrorAction SilentlyContinue
    if ($old -and $old.ProcessName -eq 'node') {
        Write-Host "SOC Simulator already running (PID $($old.Id)) at $url"
        Start-Process $url
        exit 0
    }
}

if (-not (Test-Path (Join-Path $root 'node_modules'))) {
    Write-Host 'Installing dependencies...'
    Push-Location $root; npm install --no-audit --no-fund; Pop-Location
}

$log = Join-Path $dataDir 'server.log'
$p = Start-Process node -ArgumentList 'server.js' -WorkingDirectory $root -WindowStyle Hidden `
    -RedirectStandardOutput $log -RedirectStandardError (Join-Path $dataDir 'server.err.log') -PassThru
$p.Id | Set-Content $pidFile

for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 500
    try { Invoke-RestMethod "$url/api/generator" -TimeoutSec 2 | Out-Null; $ok = $true; break } catch {}
}
if ($ok) {
    Write-Host "SOC Simulator started (PID $($p.Id)) at $url"
    Write-Host "Logs: $log"
    Start-Process $url
} else {
    Write-Host "Server did not respond. Check $log and $(Join-Path $dataDir 'server.err.log')"
    exit 1
}
