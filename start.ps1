# CyberGuard Threat Intelligence Platform - Windows Launch Orchestrator
$ErrorActionPreference = "Stop"

$rootDir = $PSScriptRoot
$backendDir = Join-Path $rootDir "backend"
$frontendDir = Join-Path $rootDir "frontend"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   CyberGuard Threat Intelligence SOC - Launch Orchestrator" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Check Backend Environment
$venvPython = Join-Path $backendDir "venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "[ERROR] Backend virtual environment not found at $venvPython." -ForegroundColor Red
    Write-Host "Please create the venv and install dependencies first." -ForegroundColor Yellow
    exit 1
}

# 2. Check Node / npm for Frontend
$localNode = "$env:LOCALAPPDATA\Programs\nodejs"
if (Test-Path $localNode) {
    $env:PATH = "$localNode;$env:PATH"
}

if (-not (Get-Command "npm" -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] 'npm' was not found in PATH." -ForegroundColor Red
    exit 1
}

# 3. Check Frontend node_modules
if (-not (Test-Path (Join-Path $frontendDir "node_modules"))) {
    Write-Host "[INFO] node_modules not found. Installing frontend dependencies..." -ForegroundColor Yellow
    Push-Location $frontendDir
    npm install
    Pop-Location
}

# 4. Launch Backend API Service
Write-Host "`n[+] Starting FastAPI ML Engine on http://127.0.0.1:8000..." -ForegroundColor Green
$backendProcess = Start-Process -FilePath $venvPython -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000" -WorkingDirectory $backendDir -PassThru -WindowStyle Hidden

# 5. Launch Next.js SOC Dashboard
Write-Host "[+] Starting Next.js SOC Dashboard on http://localhost:3000..." -ForegroundColor Green
$frontendProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "npm run dev" -WorkingDirectory $frontendDir -PassThru -WindowStyle Hidden

Start-Sleep -Seconds 3

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "           CYBERGUARD SERVICES ACTIVE & RUNNING             " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  * SOC Web Console:       http://localhost:3000" -ForegroundColor White
Write-Host "  * FastAPI Swagger Docs:  http://127.0.0.1:8000/docs" -ForegroundColor White
Write-Host "  * System Health Probe:   http://127.0.0.1:8000/health" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Press [Ctrl+C] to gracefully stop all services.`n" -ForegroundColor Yellow

try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
}
finally {
    Write-Host "`nStopping CyberGuard background services..." -ForegroundColor Yellow
    if ($backendProcess -and -not $backendProcess.HasExited) {
        Stop-Process -Id $backendProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($frontendProcess -and -not $frontendProcess.HasExited) {
        taskkill.exe /PID $frontendProcess.Id /T /F | Out-Null
    }
    Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    Write-Host "[OK] All CyberGuard services shut down cleanly." -ForegroundColor Green
}
