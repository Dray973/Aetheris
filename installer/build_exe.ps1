<#
    Build a single-file AetherisQuantumCore.exe with PyInstaller.

    Creates an isolated build environment with the full dependency set +
    PyInstaller, then compiles the onefile executable from aetheris.spec.
    Optionally Authenticode-signs the result (see docs/SIGNING.md).

        powershell -ExecutionPolicy Bypass -File installer\build_exe.ps1
        # signed:
        powershell -ExecutionPolicy Bypass -File installer\build_exe.ps1 `
            -PfxPath cert.pfx -PfxPassword $env:SIGN_PASSWORD

    Output: dist\AetherisQuantumCore.exe
#>
[CmdletBinding()]
param(
    [string] $BuildVenv = (Join-Path $env:TEMP 'aetheris-build-venv'),
    [string] $PfxPath = $env:SIGN_PFX,          # path to a code-signing .pfx
    [string] $PfxPassword = $env:SIGN_PASSWORD, # its password
    [string] $Thumbprint,                        # or a cert in the machine store
    [string] $TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Set-Location $repo

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }

function Find-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $kits = 'C:\Program Files (x86)\Windows Kits\10\bin'
    if (Test-Path $kits) {
        $found = Get-ChildItem $kits -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
                 Where-Object { $_.FullName -match '\\x64\\' } |
                 Sort-Object FullName -Descending | Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    return $null
}

function Invoke-Sign([string] $file) {
    if (-not $PfxPath -and -not $Thumbprint) {
        Write-Host "  (unsigned - provide -PfxPath/-Thumbprint to Authenticode-sign)" -ForegroundColor DarkGray
        return
    }
    $signtool = Find-SignTool
    if (-not $signtool) {
        Write-Host "  ! signtool.exe not found (install the Windows SDK); skipping signing" -ForegroundColor Yellow
        return
    }
    Write-Step "Signing $file"
    $args = @('sign', '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256')
    if ($Thumbprint) { $args += @('/sha1', $Thumbprint) }
    else { $args += @('/f', $PfxPath); if ($PfxPassword) { $args += @('/p', $PfxPassword) } }
    $args += $file
    & $signtool @args
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for $file" }
    Write-Host "  + signed $file" -ForegroundColor Green
}

# 1. Build environment
if (-not (Test-Path (Join-Path $BuildVenv 'Scripts\python.exe'))) {
    Write-Step "Creating build venv at $BuildVenv"
    python -m venv $BuildVenv
}
$py = Join-Path $BuildVenv 'Scripts\python.exe'

Write-Step "Installing dependencies + PyInstaller"
& $py -m pip install --upgrade pip --disable-pip-version-check | Out-Null
& $py -m pip install ".[recommended,forensics]" pyinstaller

# 1b. Build the native API-monitor agent DLL (best-effort; needs MSVC C++).
#     Bundled by aetheris.spec if present; the app degrades gracefully without it.
try {
    Write-Step "Building API-monitor agent DLL"
    & (Join-Path $repo 'agent\build.ps1')
} catch {
    Write-Host "  ! agent DLL build skipped ($($_.Exception.Message))" -ForegroundColor Yellow
}

# 2. Compile
# Build intermediates go to TEMP (never inside a synced OneDrive folder, which
# locks files and breaks PyInstaller's --clean). Only the final exe lands in dist\.
Write-Step "Running PyInstaller (onefile)"
$work = Join-Path $env:TEMP 'aetheris-pyi-build'
$dist = Join-Path $repo 'dist'
& $py -m PyInstaller --noconfirm --clean --workpath $work --distpath $dist aetheris.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed (exit $LASTEXITCODE)." }

$out = Join-Path $dist 'AetherisQuantumCore.exe'
if (-not (Test-Path $out)) {
    throw "Build failed: $out not found."
}
$mb = [math]::Round((Get-Item $out).Length / 1MB, 1)
Write-Host ""
Write-Host "  Built $out ($mb MB)" -ForegroundColor Green

# 3. Optional Authenticode signing
Invoke-Sign $out
