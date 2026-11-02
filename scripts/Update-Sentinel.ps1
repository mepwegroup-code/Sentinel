Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $projectRoot
try {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw "Git not found. Install Git for Windows to update from the repository."
    }
    & git pull --ff-only
    if ($LASTEXITCODE -ne 0) {
        throw "Git pull failed. Keep your local edits safe; resolve the conflict manually."
    }
    & (Join-Path $PSScriptRoot "Start-Sentinel.ps1") -Rebuild
} finally { Pop-Location }
