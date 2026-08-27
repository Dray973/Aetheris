<#
    Aetheris Quantum Core - standalone installer (double-click path).

    Copies the application into a per-user install directory, bootstraps a
    Python virtual environment with all dependencies (downloading them as
    needed), and creates Start-menu + Desktop shortcuts that launch the suite
    (which then requests UAC elevation itself). Registers an entry in
    Add/Remove Programs.

    Per-user install (no admin required for the app itself); installing Python
    may prompt for elevation via winget / the python.org installer.
#>
[CmdletBinding()]
param(
    [string] $InstallDir = (Join-Path $env:LOCALAPPDATA 'Aetheris Quantum Core'),
    [switch] $NoShortcuts
)

$ErrorActionPreference = 'Stop'
$AppName = 'Aetheris Quantum Core'
$SourceDir = Split-Path $PSScriptRoot -Parent   # repo root (installer/ is under it)

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "  + $m" -ForegroundColor Green }

Write-Host ""
Write-Host "  Aetheris Quantum Core - Installer" -ForegroundColor White
Write-Host "  ---------------------------------" -ForegroundColor DarkGray
Write-Host ""

# --- 0. Sanity check: the app files must sit next to installer\ -----------
if (-not (Test-Path (Join-Path $SourceDir 'aetheris'))) {
    Write-Host "  ERROR: application files not found." -ForegroundColor Red
    Write-Host "  This installer expects the whole project folder, with the"
    Write-Host "  'aetheris' folder next to this 'installer' folder:"
    Write-Host ""
    Write-Host "    Aetheris\aetheris\..." -ForegroundColor Gray
    Write-Host "    Aetheris\run.py"        -ForegroundColor Gray
    Write-Host "    Aetheris\installer\install.ps1  (this file)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  You appear to have copied only the 'installer' folder." -ForegroundColor Yellow
    Write-Host "  To install on a machine WITHOUT Python / internet, use the" -ForegroundColor Yellow
    Write-Host "  standalone AetherisQuantumCore.exe instead (see installer\README.md)." -ForegroundColor Yellow
    throw "Missing application files (no 'aetheris' folder beside 'installer')."
}

# --- 1. Copy application files --------------------------------------------
Write-Step "Installing to $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$items = @('aetheris', 'run.py', 'requirements.txt', 'README.md', 'pyproject.toml')
foreach ($item in $items) {
    $src = Join-Path $SourceDir $item
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $InstallDir -Recurse -Force
    }
}
Write-Ok "Application files copied"

# --- 2. Bootstrap the Python environment (downloads dependencies) ---------
& (Join-Path $PSScriptRoot 'bootstrap.ps1') -InstallDir $InstallDir

# --- 3. Create launcher + shortcuts ---------------------------------------
$venvPyw = Join-Path $InstallDir '.venv\Scripts\pythonw.exe'
$runPy   = Join-Path $InstallDir 'run.py'
$iconPath = Join-Path $InstallDir 'aetheris\ui\assets\aetheris.ico'

if (-not $NoShortcuts) {
    Write-Step "Creating shortcuts"
    $shell = New-Object -ComObject WScript.Shell

    function New-Shortcut($linkPath) {
        $sc = $shell.CreateShortcut($linkPath)
        $sc.TargetPath = $venvPyw
        $sc.Arguments = "`"$runPy`""
        $sc.WorkingDirectory = $InstallDir
        $sc.Description = 'Advanced Systems Instrumentation Suite'
        if (Test-Path $iconPath) { $sc.IconLocation = $iconPath }
        $sc.WindowStyle = 1
        $sc.Save()
        # Flip the .lnk "run as administrator" flag (byte 21, bit 0x20) so the
        # suite starts elevated (it also self-elevates via UAC as a fallback).
        $bytes = [System.IO.File]::ReadAllBytes($linkPath)
        $bytes[21] = $bytes[21] -bor 0x20
        [System.IO.File]::WriteAllBytes($linkPath, $bytes)
    }

    $startMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
    New-Shortcut (Join-Path $startMenu "$AppName.lnk")
    New-Shortcut (Join-Path ([Environment]::GetFolderPath('Desktop')) "$AppName.lnk")
    Write-Ok "Start-menu and Desktop shortcuts created"
}

# --- 4. Register uninstaller ----------------------------------------------
Write-Step "Registering uninstaller"
Copy-Item (Join-Path $PSScriptRoot 'uninstall.ps1') -Destination $InstallDir -Force
$uninstKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\AetherisQuantumCore'
New-Item -Path $uninstKey -Force | Out-Null
$uninstCmd = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$InstallDir\uninstall.ps1`""
Set-ItemProperty -Path $uninstKey -Name 'DisplayName'     -Value $AppName
Set-ItemProperty -Path $uninstKey -Name 'DisplayVersion'  -Value '0.1.0'
Set-ItemProperty -Path $uninstKey -Name 'Publisher'       -Value 'Aetheris'
Set-ItemProperty -Path $uninstKey -Name 'InstallLocation' -Value $InstallDir
if (Test-Path $iconPath) { Set-ItemProperty -Path $uninstKey -Name 'DisplayIcon' -Value $iconPath }
Set-ItemProperty -Path $uninstKey -Name 'UninstallString' -Value $uninstCmd
Set-ItemProperty -Path $uninstKey -Name 'NoModify'        -Value 1 -Type DWord
Set-ItemProperty -Path $uninstKey -Name 'NoRepair'        -Value 1 -Type DWord
Write-Ok "Registered in Add/Remove Programs"

Write-Host ""
Write-Host "  Installation complete." -ForegroundColor Green
Write-Host "  Launch from the Start menu or Desktop shortcut ('$AppName')." -ForegroundColor Gray
Write-Host ""
