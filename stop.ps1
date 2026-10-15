# Stop the SOC Simulator gracefully (state is saved on shutdown).
$dataDir = if ($env:SOCSIM_DATA_DIR) { $env:SOCSIM_DATA_DIR } else { Join-Path $env:LOCALAPPDATA 'SocSim' }
$pidFile = Join-Path $dataDir 'server.pid'
$url = 'http://127.0.0.1:5000'

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
