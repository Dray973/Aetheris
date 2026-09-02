<#
    Build the Aetheris native scan library (dist\aetheris_scan.dll).

        powershell -ExecutionPolicy Bypass -File native\build.ps1

    Requires the Rust toolchain (rustup / cargo). The library is optional — the
    app falls back to a pure-Python implementation when it isn't present — so a
    missing toolchain is not fatal to a build.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$crate = Join-Path $PSScriptRoot 'entropy_rs'

Write-Host "==> cargo build --release ($crate)" -ForegroundColor Cyan
Push-Location $crate
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)." }
} finally {
    Pop-Location
}

$src = Join-Path $crate 'target\release\aetheris_scan.dll'
if (-not (Test-Path $src)) { throw "build produced no aetheris_scan.dll" }
$dst = Join-Path $repo 'dist\aetheris_scan.dll'
New-Item -ItemType Directory -Force (Split-Path $dst) | Out-Null
Copy-Item $src $dst -Force
$kb = [math]::Round((Get-Item $dst).Length / 1KB, 1)
Write-Host "  + Built $dst ($kb KB)" -ForegroundColor Green
