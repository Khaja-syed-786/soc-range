# Stop the SOC Simulator gracefully (state is saved on shutdown).
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

try {
    Invoke-RestMethod "$url/api/shutdown" -Method Post -Headers @{ 'X-SocSim' = '1' } -TimeoutSec 3 | Out-Null
    Write-Host 'Shutdown requested, saving state...'
} catch { Write-Host 'Server not responding to shutdown request.' }

if (Test-Path $pidFile) {
    $id = Get-Content $pidFile
    for ($i = 0; $i -lt 10; $i++) {
        $p = Get-Process -Id $id -ErrorAction SilentlyContinue
        if (-not $p) { break }
        Start-Sleep -Milliseconds 300
    }
    $p = Get-Process -Id $id -ErrorAction SilentlyContinue
    if ($p -and $p.ProcessName -eq 'node') { Stop-Process -Id $id -Force; Write-Host "Force-stopped PID $id" }
    Remove-Item $pidFile -Force
}
Write-Host 'SOC Simulator stopped.'
