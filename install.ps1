<#
    USB Virus Scanner — Windows installer / bootstrap.
    Run in an elevated PowerShell:  powershell -ExecutionPolicy Bypass -File install.ps1

    - Installs ClamAV (via winget if available) and Python deps.
    - Updates virus signatures (freshclam).
    - Optionally registers the auto-scan watcher as a startup scheduled task.
#>

param(
    [switch]$RegisterWatcher = $false
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "== USB Virus Scanner setup ==" -ForegroundColor Cyan

# --- 1. Python check -------------------------------------------------------
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
    Write-Warning "Python not found. Install Python 3.9+ from python.org or the Store, then re-run."
    exit 1
}

# --- 2. ClamAV -------------------------------------------------------------
$clam = "C:\Program Files\ClamAV\clamscan.exe"
if (-not (Test-Path $clam)) {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        Write-Host "Installing ClamAV via winget..." -ForegroundColor Yellow
        winget install --id ClamAV.ClamAV -e --accept-package-agreements --accept-source-agreements
    } else {
        Write-Warning "ClamAV not found and winget unavailable. Download from https://www.clamav.net/downloads and install to C:\Program Files\ClamAV."
    }
}

# ClamAV needs a config to run freshclam; create minimal ones if missing.
$clamDir = "C:\Program Files\ClamAV"
if (Test-Path $clamDir) {
    foreach ($cfg in @("freshclam.conf", "clamd.conf")) {
        $sample = Join-Path $clamDir "conf_examples\$cfg.sample"
        $target = Join-Path $clamDir $cfg
        if ((Test-Path $sample) -and (-not (Test-Path $target))) {
            (Get-Content $sample) -replace '^Example', '#Example' | Set-Content $target
            Write-Host "Created $target"
        }
    }
    Write-Host "Updating virus signatures (freshclam)..." -ForegroundColor Yellow
    & (Join-Path $clamDir "freshclam.exe")
}

# --- 3. Python dependencies ------------------------------------------------
Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
& python -m pip install --upgrade pip
& python -m pip install -r (Join-Path $Root "requirements.txt")

# --- 4. Data directories ---------------------------------------------------
foreach ($d in @(
    "C:\ProgramData\USBVirusScanner\Quarantine",
    "C:\ProgramData\USBVirusScanner\Logs",
    "C:\ProgramData\USBVirusScanner\Reports")) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

# --- 5. Optional: register auto-scan watcher at startup --------------------
if ($RegisterWatcher) {
    $action  = New-ScheduledTaskAction -Execute "python" `
                 -Argument "`"$Root\cli.py`" watch" -WorkingDirectory $Root
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    Register-ScheduledTask -TaskName "USBVirusScannerWatcher" -Action $action `
        -Trigger $trigger -Principal $principal -Force
    Write-Host "Registered startup task 'USBVirusScannerWatcher'." -ForegroundColor Green
}

# --- 6. Desktop shortcut to the GUI (no console window) --------------------
try {
    $desktop = [Environment]::GetFolderPath("Desktop")
    $lnk = Join-Path $desktop "USB Virus Scanner.lnk"
    $ws = New-Object -ComObject WScript.Shell
    $sc = $ws.CreateShortcut($lnk)
    $sc.TargetPath = "pythonw"
    $sc.Arguments  = "`"$Root\gui.py`""
    $sc.WorkingDirectory = $Root
    $sc.IconLocation = "shell32.dll,77"
    $sc.Save()
    Write-Host "Created desktop shortcut: $lnk" -ForegroundColor Green
} catch {
    Write-Warning "Could not create desktop shortcut: $_"
}

Write-Host "`nDone." -ForegroundColor Green
Write-Host "  GUI :  double-click 'USB Virus Scanner' on the Desktop  (or: pythonw `"$Root\gui.py`")"
Write-Host "  CLI :  python `"$Root\cli.py`" drives"
