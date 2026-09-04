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
function Test-PyVersion($exe, $prefix) {
    # Run the candidate; return $true only if it is a working Python >= 3.10.
    # The probe prints major*100+minor (e.g. 312) and uses NO quotes or format
    # strings: Windows PowerShell 5.1 mangles embedded double-quotes when calling
    # a native exe, which silently broke the old 'import sys;print("%d.%d"%...)'.
    try {
        $out = & $exe @($prefix + @('-c',
            'import sys;print(sys.version_info[0]*100+sys.version_info[1])')) 2>$null
        if ($LASTEXITCODE -eq 0 -and $out -and ([int]($out.Trim()) -ge 310)) {
            return $true
        }
    } catch { }
    return $false
}

function Get-PythonExe {
    # 1) py launcher (usually C:\Windows\py.exe -- on PATH even when python isn't).
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py -and (Test-PyVersion $py.Source @('-3'))) { return @($py.Source, '-3') }
    # 2) python on PATH.
    $pyth = Get-Command python -ErrorAction SilentlyContinue
    if ($pyth -and (Test-PyVersion $pyth.Source @())) { return @($pyth.Source) }
    # 3) Known install locations -- finds a just-installed (winget/python.org) or
    #    manually-installed Python that is not yet on THIS session's PATH.
    $globs = @()
    if ($env:LOCALAPPDATA)        { $globs += (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python3*\python.exe') }
    if ($env:ProgramFiles)        { $globs += (Join-Path $env:ProgramFiles 'Python3*\python.exe') }
    if (${env:ProgramFiles(x86)}) { $globs += (Join-Path ${env:ProgramFiles(x86)} 'Python3*\python.exe') }
    $globs += 'C:\Python3*\python.exe'
    foreach ($g in $globs) {
        $hits = Get-ChildItem -Path $g -ErrorAction SilentlyContinue |
                Sort-Object FullName -Descending      # prefer newest (Python312 > 310)
        foreach ($h in $hits) {
            if (Test-PyVersion $h.FullName @()) { return @($h.FullName) }
        }
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
    # Refresh this session's PATH from the registry, then re-probe. Get-PythonExe
    # also scans install locations, so a Python that never got added to PATH
    # (common with winget's per-user install) is still found.
    $env:Path = [System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
                [System.Environment]::GetEnvironmentVariable('Path','User')
    $python = Get-PythonExe
    if (-not $python) {
        throw "Could not locate Python 3.10+ even after installation. Install " +
              "Python 3.12 from python.org (tick 'Add python.exe to PATH') and " +
              "re-run -- or just use the standalone AetherisQuantumCore.exe, " +
              "which bundles Python and needs no install."
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

Install-Tier 'core'        @('PySide6>=6.6','psutil>=5.9') $true
Install-Tier 'recommended' @('numpy>=1.24','pyqtgraph>=0.13','pywin32>=306','comtypes>=1.2','PyOpenGL>=3.1') $false
Install-Tier 'forensics'   @('capstone>=5.0','keystone-engine>=0.9','memprocfs>=5.0') $false

Write-Ok "Dependency installation complete"
