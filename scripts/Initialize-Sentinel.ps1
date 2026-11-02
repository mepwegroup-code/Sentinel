# Run once: create local secrets. Never commit .env.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$envPath = Join-Path $projectRoot ".env"

if (Test-Path -LiteralPath $envPath) {
    Write-Host "Existing .env preserved. No secrets were overwritten."
    return
}

function New-SecureHex([int] $byteCount) {
    $bytes = New-Object byte[] $byteCount
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return [System.BitConverter]::ToString($bytes).Replace("-", "").ToLowerInvariant()
}

$password = New-SecureHex 18
$sessionKey = New-SecureHex 48
$agentKey = New-SecureHex 48
$configuration = @"
# Generated locally. Never upload or commit.
NODE_ENV=production
PORT=3000
SENTINEL_DATA_DIR=/app/data
SENTINEL_ADMIN_PASSWORD=$password
SENTINEL_SESSION_SECRET=$sessionKey
SENTINEL_AGENT_TOKEN=$agentKey
GEMINI_API_KEY=
"@
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($envPath, $configuration + [Environment]::NewLine, $utf8NoBom)

Write-Host ""
Write-Host "Sentinel OS .env created. Store this password somewhere safe." -ForegroundColor Green
Write-Host "Login: admin"
Write-Host "Password: $password" -ForegroundColor Yellow
Write-Host "Config: $envPath"
Write-Host "Edit GEMINI_API_KEY in .env only if you use the AI features."
