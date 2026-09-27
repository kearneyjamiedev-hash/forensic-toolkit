param(
    [switch]$InstallTools
)

$ErrorActionPreference = "Stop"

$Python = ".\.venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    throw "Virtual environment Python was not found at $Python"
}

if ($InstallTools) {
    & $Python -m pip install -r requirements-security.txt

    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

Write-Host ""
Write-Host "=== Bandit: medium+ severity, medium+ confidence ==="
Write-Host ""

& $Python -m bandit `
    -r app forensics `
    -x tests `
    -ll `
    -ii

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Bandit reported a gated finding."
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "=== pip-audit: current virtual environment ==="
Write-Host ""

& $Python -m pip_audit `
    --local `
    --strict

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "pip-audit reported a vulnerability or collection failure."
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Security scans passed."
