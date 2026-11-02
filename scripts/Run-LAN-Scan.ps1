param([string] $InterfaceName = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $projectRoot

try {
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
        throw "Node.js 22+ is required on Windows for LAN scans. Install Node.js (LTS) first."
    }
    $envPath = Join-Path $projectRoot ".env"
    if (-not (Test-Path -LiteralPath $envPath)) { throw "Missing .env. Run START_SENTINEL.cmd first." }
    $line = Get-Content $envPath | Where-Object { $_ -match '^SENTINEL_AGENT_TOKEN=' } | Select-Object -First 1
    if (-not $line) { throw "SENTINEL_AGENT_TOKEN not found in .env." }
    $env:SENTINEL_AGENT_TOKEN = ($line -split '=', 2)[1].Trim()
    if ($env:SENTINEL_AGENT_TOKEN.Length -lt 32) { throw "Agent token is too short." }
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/health" -TimeoutSec 3
        if ($health.status -ne 'ok') { throw "Unhealthy" }
    } catch { throw "Start Sentinel in Docker Desktop before running the LAN Agent." }

    Write-Host "Available physical/private network interfaces:" -ForegroundColor Cyan
    & node ".\agent\sentinel-agent.mjs" --list-interfaces
    if ($LASTEXITCODE -ne 0) { throw "Unable to list LAN interfaces." }
    if (-not $InterfaceName) {
        $InterfaceName = (Read-Host "Enter the network interface name exactly (blank for auto)").Trim()
    }
    Write-Host "Only scan networks you own or are explicitly authorized to assess." -ForegroundColor Yellow
    $confirmation = (Read-Host "Type YES to confirm network authorization").Trim()
    if ($confirmation -cne "YES") {
        Write-Host "LAN scan cancelled."
        return
    }
    $arguments = @(".\agent\sentinel-agent.mjs", "--server", "http://127.0.0.1:3000", "--token", "local-windows")
    if ($InterfaceName) { $arguments += @("--interface", $InterfaceName) }
    & node @arguments
    if ($LASTEXITCODE -ne 0) { throw "LAN Agent terminated with an error." }
} finally {
    Remove-Item Env:SENTINEL_AGENT_TOKEN -ErrorAction SilentlyContinue
    Pop-Location
}
