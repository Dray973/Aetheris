<#
    Build the Aetheris native Win32 engine (dist\aetheris_win.dll).

        powershell -ExecutionPolicy Bypass -File native\aetheris_win\build.ps1

    Requires the MSVC C++ toolset (Visual Studio Build Tools, "Desktop
    development with C++"). Located automatically via vswhere. The library is
    optional — the app falls back to the pure-Python implementations when it
    isn't present — so a missing toolchain is not fatal to a build.
#>
[CmdletBinding()]
param([string] $Config = 'Release')

$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "vswhere not found; install Visual Studio Build Tools (C++)." }

$ip = & $vswhere -all -products * -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $ip) { throw "MSVC C++ toolset not found; add 'Desktop development with C++' in the VS installer." }
$vcvars = Join-Path $ip 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found under $ip" }

$src = Join-Path $PSScriptRoot 'aetheris_win.cpp'
$outDir = Join-Path $repo 'dist'
$out = Join-Path $outDir 'aetheris_win.dll'
$obj = Join-Path $env:TEMP 'aetheris-win-build'
New-Item -ItemType Directory -Force $outDir | Out-Null
New-Item -ItemType Directory -Force $obj | Out-Null

$opt = if ($Config -eq 'Debug') { '/Od /Zi' } else { '/O2' }

Write-Host "==> Compiling $src ($Config)" -ForegroundColor Cyan
cmd /c "`"$vcvars`" && cl /nologo /LD $opt /EHsc /std:c++17 /W4 /Fo:`"$obj\\`" `"$src`" /Fe:`"$out`" /link /OPT:REF"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $out)) { throw "cl.exe build failed (exit $LASTEXITCODE)." }

# Tidy the import-lib / export files cl drops next to the DLL.
foreach ($ext in '.lib', '.exp') {
    $f = [System.IO.Path]::ChangeExtension($out, $ext)
    if (Test-Path $f) { Remove-Item $f -Force }
}
$kb = [math]::Round((Get-Item $out).Length / 1KB, 1)
Write-Host "  + Built $out ($kb KB)" -ForegroundColor Green
