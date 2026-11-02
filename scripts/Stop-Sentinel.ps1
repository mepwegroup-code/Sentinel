Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $projectRoot
try {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw "Docker not installed." }
    & docker compose -f compose.yaml stop
    if ($LASTEXITCODE -ne 0) { throw "Unable to stop Sentinel container." }
    Write-Host "Sentinel stopped. Reports and configuration have been kept." -ForegroundColor Green
} finally { Pop-Location }
