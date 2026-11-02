param([switch] $Rebuild, [switch] $NoBrowser)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $projectRoot

try {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "Docker CLI not found. Install and launch Docker Desktop first."
    }
    & docker info --format "{{.ServerVersion}}" *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Engine is not running. Open Docker Desktop and retry."
    }
    & docker compose version *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose v2 is unavailable. Update Docker Desktop."
    }

    if (-not (Test-Path -LiteralPath ".env")) {
        & (Join-Path $PSScriptRoot "Initialize-Sentinel.ps1")
    }
    $raw = Get-Content -LiteralPath ".env" -Raw
    foreach ($key in @("SENTINEL_ADMIN_PASSWORD", "SENTINEL_SESSION_SECRET", "SENTINEL_AGENT_TOKEN")) {
        if (-not ($raw -match "(?m)^$key=([A-Za-z0-9_-]{12,})\s*$")) {
            throw "Missing or invalid $key in .env. Edit .env before starting."
        }
    }

    & docker image inspect "sentinel-os:local" *> $null
    $imageExists = ($LASTEXITCODE -eq 0)
    if ($Rebuild -or -not $imageExists) {
        Write-Host "Building and starting Sentinel..." -ForegroundColor Cyan
        & docker compose -f compose.yaml up -d --build
    } else {
        Write-Host "Starting Sentinel..." -ForegroundColor Cyan
        & docker compose -f compose.yaml up -d
    }
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose start failed." }

    $url = "http://127.0.0.1:3000"
    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $health = Invoke-RestMethod -Uri "$url/api/health" -TimeoutSec 2
            if ($health.status -eq "ok") { $ready = $true; break }
        } catch { Start-Sleep -Seconds 1 }
    }
    if (-not $ready) {
        & docker compose -f compose.yaml ps
        throw "Sentinel did not pass the local health check. Run: docker compose logs sentinel"
    }
    Write-Host "Sentinel is running: $url" -ForegroundColor Green
    Write-Host "Login: admin (password in .env)"
    if (-not $NoBrowser) { Start-Process $url }
} finally {
    Pop-Location
}
