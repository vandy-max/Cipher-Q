$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Backend = Join-Path $Root 'backend'
$Frontend = Join-Path $Root 'frontend'
$EnvFile = Join-Path $Backend '.env'
$DevSecrets = Join-Path $Backend '.dev_secrets.json'

Write-Host '=== CipherQ v18 launcher ===' -ForegroundColor Cyan
Write-Host 'This starts MongoDB check + FastAPI + Vite. It does not erase or migrate database data.'

if (-not (Test-Path $EnvFile)) {
    Copy-Item (Join-Path $Backend '.env.example') $EnvFile
    $raw = Get-Content $EnvFile -Raw
    $raw = [regex]::Replace($raw, '(?m)^MONGODB_DATABASE=.*$', 'MONGODB_DATABASE=cipherq_dev_clean')
    Set-Content -Path $EnvFile -Value $raw -Encoding utf8
    Write-Host 'Created backend\.env targeting cipherq_dev_clean. Review it before continuing.' -ForegroundColor Yellow
}

$envText = Get-Content $EnvFile -Raw
$hasKeyEnv = ($envText -match '(?m)^\s*CIPHERQ_KEYRING\s*=') -or
             ($envText -match '(?m)^\s*CIPHERQ_KEYRING_FILE\s*=') -or
             ($envText -match '(?m)^\s*JWT_SECRET\s*=') -or
             ($envText -match '(?m)^\s*JWT_SECRET_FILE\s*=')
if (-not (Test-Path $DevSecrets) -and -not $hasKeyEnv) {
    Write-Host ''
    Write-Host 'STOP: backend\.dev_secrets.json was not found and backend\.env has no configured keyring/secrets.' -ForegroundColor Red
    Write-Host 'CipherQ encrypts whole MongoDB documents. Do NOT start against an existing encrypted database with newly generated keys.' -ForegroundColor Red
    Write-Host 'Copy the verified original backend\.dev_secrets.json from the project that can decrypt the configured database, OR configure JWT_SECRET_FILE and CIPHERQ_KEYRING_FILE in backend\.env to point to the exact existing secret files for that database. Never use sample keys or generate replacement keys for an existing encrypted database.' -ForegroundColor Yellow
    exit 2
}

if (-not (Test-Path (Join-Path $Backend '.venv\Scripts\python.exe'))) {
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        & py -3.11 -m venv (Join-Path $Backend '.venv')
        if ($LASTEXITCODE -ne 0) { throw 'Could not create Python 3.11 virtual environment. Install Python 3.11 and retry.' }
    } else {
        $py = Get-Command python -ErrorAction SilentlyContinue
        if (-not $py) { throw 'Python was not found. Install Python 3.11 and retry.' }
        & python -m venv (Join-Path $Backend '.venv')
        if ($LASTEXITCODE -ne 0) { throw 'Could not create Python virtual environment.' }
        Write-Host 'Warning: Python 3.11 is the configured runtime for this launcher.' -ForegroundColor Yellow
    }
}
$Py = Join-Path $Backend '.venv\Scripts\python.exe'
$pyVersion = (& $Py --version 2>&1 | Out-String).Trim()
if ($pyVersion -notmatch '^Python 3\.11\.') {
    throw "Existing backend virtual environment uses '$pyVersion'. Close CipherQ, then remove backend\.venv and rerun this launcher to recreate it with Python 3.11. This does not affect MongoDB data or encryption keys."
}
& $Py -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw 'pip upgrade failed.' }
& $Py -m pip install -r (Join-Path $Backend 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Backend dependency installation failed.' }

# Start the standard Windows MongoDB service if it exists but is stopped.
$mongoService = Get-Service -Name 'MongoDB' -ErrorAction SilentlyContinue
if ($mongoService -and $mongoService.Status -ne 'Running') {
    try {
        Start-Service -Name 'MongoDB'
        Start-Sleep -Seconds 3
        Write-Host 'Started Windows MongoDB service.' -ForegroundColor Green
    } catch {
        Write-Host 'Could not start the MongoDB Windows service automatically; checking connectivity anyway.' -ForegroundColor Yellow
    }
}

& $Py (Join-Path $Backend 'scripts\preflight_mongodb.py') $EnvFile
if ($LASTEXITCODE -ne 0) {
    Write-Host 'MongoDB is not reachable. Start your configured MongoDB server/service and rerun START_CIPHERQ.bat. No database data was changed.' -ForegroundColor Red
    exit 3
}

if (-not (Test-Path (Join-Path $Frontend 'node_modules'))) {
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { throw 'Node.js/npm was not found. Install Node.js 20+ and retry.' }
    Push-Location $Frontend
    try { & npm ci; if ($LASTEXITCODE -ne 0) { throw 'npm ci failed.' } }
    finally { Pop-Location }
}

$backendCmd = "Set-Location '$Backend'; & '.venv\Scripts\python.exe' -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --env-file .env"
$frontendCmd = "Set-Location '$Frontend'; npm run dev -- --host 127.0.0.1"
Start-Process powershell -ArgumentList @('-NoExit','-ExecutionPolicy','Bypass','-Command',$backendCmd)
Start-Sleep -Seconds 3
Start-Process powershell -ArgumentList @('-NoExit','-ExecutionPolicy','Bypass','-Command',$frontendCmd)

Write-Host ''
Write-Host 'Started backend and frontend in separate terminal windows.' -ForegroundColor Green
Write-Host 'Frontend: http://127.0.0.1:5173'
Write-Host 'Backend:  http://127.0.0.1:8000/api/health'
Write-Host 'If login fails, inspect the backend terminal first; do not regenerate encryption keys for an existing database.'
