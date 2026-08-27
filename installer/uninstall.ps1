<#
    Aetheris Quantum Core - uninstaller.
    Removes shortcuts, the Add/Remove Programs entry, and the install directory.
#>
[CmdletBinding()]
param(
    [string] $InstallDir = (Join-Path $env:LOCALAPPDATA 'Aetheris Quantum Core')
)

$AppName = 'Aetheris Quantum Core'
Write-Host "Uninstalling $AppName..." -ForegroundColor Cyan

# Shortcuts
$startMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\$AppName.lnk"
$desktop   = Join-Path ([Environment]::GetFolderPath('Desktop')) "$AppName.lnk"
foreach ($lnk in @($startMenu, $desktop)) {
    if (Test-Path $lnk) { Remove-Item $lnk -Force; Write-Host "  removed $lnk" }
}

# Add/Remove Programs entry
$uninstKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\AetherisQuantumCore'
if (Test-Path $uninstKey) { Remove-Item $uninstKey -Recurse -Force }

# Install directory (contains the venv). Guard against deleting from within it.
if ((Get-Location).Path -like "$InstallDir*") { Set-Location $env:TEMP }
if (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  removed $InstallDir"
}

Write-Host "Done." -ForegroundColor Green
