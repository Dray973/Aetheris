<#
    Aetheris Quantum Core - environment bootstrapper.

    Ensures a suitable Python is present, creates a dedicated virtual
    environment inside the install directory, and pip-installs the dependency
    tiers. Core deps must succeed; recommended/optional are best-effort so a
    missing native wheel (e.g. on a brand-new Python) never aborts the install.

    Called by install.ps1 (standalone) and by the Inno Setup package.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $InstallDir
)

$ErrorActionPreference = 'Stop'

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Host "  ! $msg" -ForegroundColor Yellow }
function Write-Ok($msg)   { Write-Host "  + $msg" -ForegroundColor Green }

# --- 1. Locate or install Python 3.10+ ------------------------------------
function Get-PythonExe {
    # Prefer the py launcher, then python on PATH; require >= 3.10.
    foreach ($cand in @(
        @{ Exe = 'py';     Args = @('-3') },
        @{ Exe = 'python'; Args = @() }
    )) {
        $exe = Get-Command $cand.Exe -ErrorAction SilentlyContinue
        if (-not $exe) { continue }
        try {
            $ver = & $exe.Source @($cand.Args + @('-c',
                'import sys;print("%d.%d"%sys.version_info[:2])')) 2>$null
            if ($LASTEXITCODE -eq 0 -and $ver) {
                $parts = $ver.Trim().Split('.')
                if ([int]$parts[0] -ge 3 -and [int]$parts[1] -ge 10) {
                    # Return an invokable command line.
                    return @($exe.Source) + $cand.Args
                }
            }
        } catch { }
    }
    return $null
}

Write-Step "Checking for Python 3.10+"
$python = Get-PythonExe
if (-not $python) {
    Write-Warn "No suitable Python found. Attempting installation..."
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        Write-Step "Installing Python via winget (Python.Python.3.12)"
        winget install -e --id Python.Python.3.12 --silent `
            --accept-package-agreements --accept-source-agreements
    } else {
        Write-Step "winget unavailable - downloading the official installer"
        $url = 'https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe'
        $tmp = Join-Path $env:TEMP 'python-aetheris-setup.exe'
        Invoke-WebRequest -Uri $url -OutFile $tmp
        # Per-user, add to PATH, no UI.
        Start-Process -FilePath $tmp -Wait -ArgumentList `
            '/quiet InstallAllUsers=0 PrependPath=1 Include_test=0'
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }
    # Re-probe (new PATH may need this process to re-read env).
    $env:Path = [System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
                [System.Environment]::GetEnvironmentVariable('Path','User')
    $python = Get-PythonExe
    if (-not $python) {
        throw "Python installation did not complete. Please install Python 3.12 " +
              "from python.org and re-run the installer."
    }
}
Write-Ok ("Using Python: " + ($python -join ' '))

# --- 2. Create the virtual environment ------------------------------------
$venv = Join-Path $InstallDir '.venv'
$venvPy = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path $venvPy)) {
    Write-Step "Creating virtual environment at $venv"
    & $python[0] @($python[1..($python.Count-1)] + @('-m','venv',$venv))
    if (-not (Test-Path $venvPy)) { throw "venv creation failed." }
}
Write-Ok "Virtual environment ready"

# --- 3. Install dependency tiers ------------------------------------------
Write-Step "Upgrading pip"
& $venvPy -m pip install --upgrade pip --disable-pip-version-check | Out-Null

function Install-Tier([string]$name, [string[]]$packages, [bool]$required) {
    Write-Step "Installing $name dependencies"
    foreach ($pkg in $packages) {
        & $venvPy -m pip install --disable-pip-version-check $pkg
        if ($LASTEXITCODE -ne 0) {
            if ($required) { throw "Required package '$pkg' failed to install." }
            Write-Warn "Optional package '$pkg' could not be installed (skipped)."
        } else {
            Write-Ok $pkg
        }
    }
}

Install-Tier 'core'        @('PyQt6>=6.6','psutil>=5.9') $true
Install-Tier 'recommended' @('numpy>=1.24','pyqtgraph>=0.13','pywin32>=306','comtypes>=1.2','PyOpenGL>=3.1') $false
Install-Tier 'forensics'   @('capstone>=5.0','keystone-engine>=0.9','memprocfs>=5.0') $false

Write-Ok "Dependency installation complete"
