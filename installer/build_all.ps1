<#
    Refresh ALL distributables after any code change:
      1. run the test suite (abort if red)
      2. rebuild the frozen exe  -> dist\AetherisQuantumCore.exe
      3. if Inno Setup is installed, recompile both setup.exe installers

    Run this after every change so the exe + installers match the code.

        powershell -ExecutionPolicy Bypass -File installer\build_all.ps1
        # skip tests / sign the exe:
        powershell -ExecutionPolicy Bypass -File installer\build_all.ps1 -SkipTests
#>
[CmdletBinding()]
param(
    [switch] $SkipTests,
    [string] $PfxPath = $env:SIGN_PFX,
    [string] $PfxPassword = $env:SIGN_PASSWORD,
    # Base URL where you host the exe; version.json's download URL becomes
    # "<BaseUrl>/AetherisQuantumCore.exe". Leave blank to fill in later.
    [string] $BaseUrl = '',
    [string] $Notes = ''
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Set-Location $repo

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }

function Get-Python {
    foreach ($c in 'python', 'py') {
        if (Get-Command $c -ErrorAction SilentlyContinue) { return $c }
    }
    throw "Python not found on PATH."
}

# 1. Tests
if (-not $SkipTests) {
    Step "Running test suite"
    $py = Get-Python
    $env:QT_QPA_PLATFORM = 'offscreen'
    & $py -m pytest -q
    $rc = $LASTEXITCODE
    Remove-Item Env:\QT_QPA_PLATFORM -ErrorAction SilentlyContinue
    if ($rc -ne 0) { throw "Tests failed (exit $rc) - aborting build." }
}

# 2. Frozen exe
Step "Building frozen exe"
$signArgs = @()
if ($PfxPath) { $signArgs = @('-PfxPath', $PfxPath, '-PfxPassword', $PfxPassword) }
& (Join-Path $PSScriptRoot 'build_exe.ps1') @signArgs

# 2b. Generate version.json manifest for the auto-updater
Step "Writing dist\version.json (auto-update manifest)"
$py = Get-Python
$ver = (& $py -c "import aetheris; print(aetheris.__version__)").Trim()
$exe = Join-Path $repo 'dist\AetherisQuantumCore.exe'
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
$dlUrl = if ($BaseUrl) { ($BaseUrl.TrimEnd('/') + '/AetherisQuantumCore.exe') }
         else { 'REPLACE_WITH_YOUR_DOWNLOAD_URL/AetherisQuantumCore.exe' }
$manifest = [ordered]@{ version = $ver; url = $dlUrl; notes = $Notes; sha256 = $hash }
$manifest | ConvertTo-Json | Set-Content (Join-Path $repo 'dist\version.json') -Encoding ascii
Write-Host ("  v{0}  sha256 {1}...  url {2}" -f $ver, $hash.Substring(0,12), $dlUrl) -ForegroundColor Gray

# 3. Installers (only if Inno Setup is available)
$iscc = Get-ChildItem 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe' -ErrorAction SilentlyContinue |
        Select-Object -First 1
if ($iscc) {
    Step "Compiling self-contained installer (aetheris_exe.iss)"
    & $iscc.FullName (Join-Path $PSScriptRoot 'aetheris_exe.iss')
    Step "Compiling online installer (aetheris.iss)"
    & $iscc.FullName (Join-Path $PSScriptRoot 'aetheris.iss')
} else {
    Write-Host "  ! Inno Setup not found - skipped setup.exe compile." -ForegroundColor Yellow
    Write-Host "    Install it from https://jrsoftware.org/isdl.php to build the installers." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  All distributables refreshed:" -ForegroundColor Green
Write-Host "    dist\AetherisQuantumCore.exe" -ForegroundColor Gray
Write-Host "    dist\version.json            (auto-update manifest)" -ForegroundColor Gray
if ($iscc) {
    Write-Host "    installer\Output\AetherisQuantumCoreSetup.exe  (self-contained)" -ForegroundColor Gray
    Write-Host "    installer\Output\AetherisSetup.exe             (online)" -ForegroundColor Gray
}
