<#
    build.ps1  -  one command to produce the employee installer.
    Run on a Windows build machine (with Python 3.9+):

        powershell -ExecutionPolicy Bypass -File build\build.ps1

    Steps:
      1. Install build deps (PyInstaller) + app deps into the current Python.
      2. Freeze gui.py + cli.py into dist\USBVirusScanner.exe and dist\usbscan.exe.
      3. If Inno Setup (iscc) is available, compile Output\USBVirusScannerSetup.exe.

    Result: Output\USBVirusScannerSetup.exe  -  the single file to deploy.

    Pass -Offline to first download+bundle ClamAV so the installer needs NO
    internet on the employee PC (runs build\fetch-vendor.ps1 for you).
#>

param(
    [switch]$Offline = $false,
    [string]$Version = ""      # e.g. -Version 1.1.0 ; default = keep current
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

Write-Host "== Building USB Virus Scanner installer ==" -ForegroundColor Cyan

# Version handling: -Version stamps both the app (scanner\__init__.py) and the
# installer so `usbscan version` and Add/Remove Programs stay in sync. If not
# given, reuse whatever __version__ the source already has.
$initFile = "scanner\__init__.py"
if ($Version) {
    (Get-Content $initFile) `
        -replace '__version__\s*=\s*".*"', "__version__ = ""$Version""" |
        Set-Content $initFile
    Write-Host "  Version stamped: $Version" -ForegroundColor Green
} else {
    $m = Select-String -Path $initFile -Pattern '__version__\s*=\s*"([^"]+)"'
    $Version = if ($m) { $m.Matches[0].Groups[1].Value } else { "1.0.0" }
    Write-Host "  Version: $Version (unchanged)" -ForegroundColor Green
}

# 0. Offline bundle: fetch ClamAV + virus DB into vendor\ if asked / missing.
$clamStaged = Test-Path "vendor\ClamAV\clamscan.exe"
if ($Offline -and -not $clamStaged) {
    Write-Host "[0/3] Fetching ClamAV engine + signatures for offline bundle..." -ForegroundColor Yellow
    & powershell -ExecutionPolicy Bypass -File "build\fetch-vendor.ps1"
    $clamStaged = Test-Path "vendor\ClamAV\clamscan.exe"
}
if ($clamStaged) {
    Write-Host "  ClamAV is bundled -> installer will be FULLY OFFLINE." -ForegroundColor Green
} else {
    Write-Host "  No bundled ClamAV -> installer will fetch it online (winget)." -ForegroundColor DarkYellow
    Write-Host "  For a zero-download installer, re-run:  build\build.ps1 -Offline" -ForegroundColor DarkYellow
}

# 1. dependencies
Write-Host "[1/3] Installing Python dependencies..." -ForegroundColor Yellow
& python -m pip install --upgrade pip
& python -m pip install -r requirements.txt pyinstaller

# 2. freeze both exes
#    Explicit workpath so PyInstaller's default (.\build) doesn't clobber our
#    build\ scripts folder; dist lands at the project root where installer.iss
#    expects it (..\dist).
Write-Host "[2/3] Freezing executables with PyInstaller..." -ForegroundColor Yellow
& python -m PyInstaller build\usb_virus_scanner.spec --noconfirm --clean `
    --workpath build\_work --distpath dist
if (-not (Test-Path "dist\USBVirusScanner.exe")) { throw "GUI exe not produced." }
if (-not (Test-Path "dist\usbscan.exe"))         { throw "CLI exe not produced." }
Write-Host "  -> dist\USBVirusScanner.exe" -ForegroundColor Green
Write-Host "  -> dist\usbscan.exe" -ForegroundColor Green

# 3. compile the installer if Inno Setup is present
Write-Host "[3/3] Building single-file installer (Inno Setup)..." -ForegroundColor Yellow
$iscc = Get-Command iscc -ErrorAction SilentlyContinue
if (-not $iscc) {
    foreach ($p in @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles}\Inno Setup 6\ISCC.exe")) {
        if (Test-Path $p) { $iscc = $p; break }
    }
}
if ($iscc) {
    & $iscc "/DAppVersion=$Version" "build\installer.iss"
    Write-Host "`nDONE. Installer (v$Version): Output\USBVirusScannerSetup.exe" -ForegroundColor Green
    Write-Host "Hand that ONE file to employees  -  double-click, Next, done." -ForegroundColor Green
} else {
    Write-Warning "Inno Setup (iscc) not found. Install it from https://jrsoftware.org/isdl.php"
    Write-Warning "Then re-run, or compile manually:  iscc build\installer.iss"
    Write-Host "Standalone exes are ready in dist\ meanwhile." -ForegroundColor Green
}
