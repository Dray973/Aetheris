<#
    Build the Aetheris native engines into dist\.

        powershell -ExecutionPolicy Bypass -File native\build.ps1

      * aetheris_core.dll  (Rust, native\aetheris_core)  — analysis core:
        entropy, byte search, PE parsing/carving, region classification,
        SHA-256. Requires the Rust toolchain (rustup / cargo).

      * aetheris_win.dll   (C++, native\aetheris_win)    — Win32 engine:
        processes, memory maps and reads, the system-wide handle table.
        Requires the MSVC C++ toolset (Visual Studio Build Tools).

    Both libraries are optional — the app falls back to pure-Python
    implementations when they are absent — so a missing toolchain is reported
    and skipped rather than failing the build. Pass -Strict to fail instead.
#>
[CmdletBinding()]
param([switch] $Strict)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$dist = Join-Path $repo 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null

$built = @()
$skipped = @()

# --- Rust core -------------------------------------------------------------
$crate = Join-Path $PSScriptRoot 'aetheris_core'
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $skipped += 'aetheris_core.dll (cargo not found — install the Rust toolchain)'
} else {
    Write-Host "==> cargo build --release ($crate)" -ForegroundColor Cyan
    Push-Location $crate
    try {
        cargo build --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)." }
    } finally { Pop-Location }
    $src = Join-Path $crate 'target\release\aetheris_core.dll'
    if (-not (Test-Path $src)) { throw "build produced no aetheris_core.dll" }
    Copy-Item $src (Join-Path $dist 'aetheris_core.dll') -Force
    $built += 'aetheris_core.dll'
}

# --- C++ Win32 engine ------------------------------------------------------
$winBuild = Join-Path $PSScriptRoot 'aetheris_win\build.ps1'
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    $skipped += 'aetheris_win.dll (vswhere not found — install VS Build Tools with C++)'
} else {
    & powershell -ExecutionPolicy Bypass -File $winBuild
    if ($LASTEXITCODE -ne 0) { throw "aetheris_win build failed (exit $LASTEXITCODE)." }
    $built += 'aetheris_win.dll'
}

Write-Host ''
foreach ($b in $built) {
    $p = Join-Path $dist $b
    $kb = [math]::Round((Get-Item $p).Length / 1KB, 1)
    Write-Host "  + $b ($kb KB)" -ForegroundColor Green
}
foreach ($s in $skipped) { Write-Host "  - skipped $s" -ForegroundColor Yellow }
if ($Strict -and $skipped.Count) { throw "missing toolchains: $($skipped -join '; ')" }
