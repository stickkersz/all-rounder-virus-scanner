; Inno Setup script - builds a single USBVirusScannerSetup.exe installer.
; Compile:  iscc build\installer.iss   (or open in Inno Setup Compiler)
; Prereq :  run build.ps1 first so dist\USBVirusScanner.exe and dist\usbscan.exe exist.
;
; FULLY-OFFLINE build: run build\fetch-vendor.ps1 once to populate vendor\ClamAV\
; (engine + virus database). This script detects that at COMPILE time and, when
; present, bundles ClamAV and omits every online step - the resulting setup.exe
; needs no internet at all. If vendor\ is empty, an optional online task fetches
; ClamAV via winget instead.
;
; Produces:  Output\USBVirusScannerSetup.exe  - one file to hand to employees.

; Display name only — AppId, install dir, exe names and scheduled-task names
; deliberately keep the USBVirusScanner identity so existing installs upgrade
; in place and keep their quarantine/logs/config.
#define AppName    "All-Round Virus Scanner"
; Version can be overridden at build time:  iscc /DAppVersion=1.1.0 ...
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#define AppExe     "USBVirusScanner.exe"
#define Publisher  "Company IT Security"

; Compile-time detection: is a ClamAV engine staged in vendor\ClamAV ?
#define ClamBundled FileExists(SourcePath + "..\vendor\ClamAV\clamscan.exe")

[Setup]
; Stable AppId -> Windows recognizes new builds as UPGRADES of the same product
; (replaces files in place, keeps one Add/Remove Programs entry). Never change it.
AppId={{6AEB4019-0F4C-4792-B68C-9A3BF2D5F2F1}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
VersionInfoVersion={#AppVersion}
AppPublisher={#Publisher}
DefaultDirName={autopf}\USBVirusScanner
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\Output
OutputBaseFilename=USBVirusScannerSetup
Compression=lzma2/max
SolidCompression=yes
; Installing to Program Files + scheduled task needs admin.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
UninstallDisplayIcon={app}\{#AppExe}
SetupIconFile=app.ico

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "autowatch";   Description: "Auto-scan every USB drive on insert (recommended)"; GroupDescription: "Protection:"
Name: "realtime";    Description: "Real-time protection: scan files the moment they land (recommended)"; GroupDescription: "Protection:"
Name: "feedsync";    Description: "Daily threat-intel feed sync (URLhaus; needs internet)"; GroupDescription: "Protection:"
#if !ClamBundled
; Only offered when the engine was NOT bundled (online build).
Name: "installclam"; Description: "Download + install ClamAV engine + signatures (needs internet)"; GroupDescription: "Engine:"
#endif

[Files]
; Frozen executables (no Python needed on the employee PC).
Source: "..\dist\USBVirusScanner.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\usbscan.exe";         DestDir: "{app}"; Flags: ignoreversion
; Editable config + detection rules, placed next to the exe.
Source: "..\config.yaml";              DestDir: "{app}"; Flags: onlyifdoesntexist
Source: "..\signatures\*";             DestDir: "{app}\signatures"; Flags: recursesubdirs createallsubdirs
Source: "..\README.md";                DestDir: "{app}"; Flags: isreadme
#if ClamBundled
; Bundled ClamAV engine + virus database -> fully offline install.
Source: "..\vendor\ClamAV\*"; DestDir: "{commonpf}\ClamAV"; Flags: recursesubdirs createallsubdirs
#endif

[Dirs]
Name: "{commonappdata}\USBVirusScanner\Quarantine"
Name: "{commonappdata}\USBVirusScanner\Logs"
Name: "{commonappdata}\USBVirusScanner\Reports"
Name: "{commonappdata}\USBVirusScanner\Feeds"

[Icons]
Name: "{group}\{#AppName}";            Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall {#AppName}";  Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}";      Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
#if !ClamBundled
; ONLINE fallback (omitted entirely from an offline build).
Filename: "winget"; Parameters: "install --id ClamAV.ClamAV -e --silent --accept-package-agreements --accept-source-agreements"; \
  Flags: runhidden waituntilterminated; Tasks: installclam; StatusMsg: "Downloading ClamAV engine..."
Filename: "{cmd}"; Parameters: "/c ""\""{commonpf}\ClamAV\freshclam.exe\"" || exit 0"""; \
  Flags: runhidden waituntilterminated; Tasks: installclam; StatusMsg: "Updating virus signatures..."
#endif
; Register the auto-scan watcher as a SYSTEM scheduled task at logon.
Filename: "schtasks"; Parameters: "/Create /F /SC ONLOGON /RL HIGHEST /RU SYSTEM /TN ""USBVirusScannerWatcher"" /TR ""\""{app}\usbscan.exe\"" watch"""; \
  Flags: runhidden waituntilterminated; Tasks: autowatch; StatusMsg: "Enabling auto-scan on USB insert..."
; Real-time file monitoring as a SYSTEM scheduled task at logon.
Filename: "schtasks"; Parameters: "/Create /F /SC ONLOGON /RL HIGHEST /RU SYSTEM /TN ""USBVirusScannerMonitor"" /TR ""\""{app}\usbscan.exe\"" monitor"""; \
  Flags: runhidden waituntilterminated; Tasks: realtime; StatusMsg: "Enabling real-time protection..."
; Refresh virus signatures daily so detection tracks new variants.
Filename: "schtasks"; Parameters: "/Create /F /SC DAILY /ST 12:00 /RL HIGHEST /RU SYSTEM /TN ""USBVirusScannerUpdate"" /TR ""\""{app}\usbscan.exe\"" update"""; \
  Flags: runhidden waituntilterminated; StatusMsg: "Scheduling daily signature updates..."
; Refresh threat-intel feeds daily (30 min after signatures, spreads the load).
Filename: "schtasks"; Parameters: "/Create /F /SC DAILY /ST 12:30 /RL HIGHEST /RU SYSTEM /TN ""USBVirusScannerFeeds"" /TR ""\""{app}\usbscan.exe\"" feeds"""; \
  Flags: runhidden waituntilterminated; Tasks: feedsync; StatusMsg: "Scheduling daily feed sync..."
; Offer to launch the GUI at the end.
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName} now"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Remove the scheduled tasks on uninstall.
Filename: "schtasks"; Parameters: "/Delete /F /TN ""USBVirusScannerWatcher"""; Flags: runhidden; RunOnceId: "DelWatchTask"
Filename: "schtasks"; Parameters: "/Delete /F /TN ""USBVirusScannerUpdate"""; Flags: runhidden; RunOnceId: "DelUpdateTask"
Filename: "schtasks"; Parameters: "/Delete /F /TN ""USBVirusScannerMonitor"""; Flags: runhidden; RunOnceId: "DelMonitorTask"
Filename: "schtasks"; Parameters: "/Delete /F /TN ""USBVirusScannerFeeds"""; Flags: runhidden; RunOnceId: "DelFeedsTask"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\USBVirusScanner\Logs"
Type: filesandordirs; Name: "{commonappdata}\USBVirusScanner\Reports"
Type: filesandordirs; Name: "{commonappdata}\USBVirusScanner\Feeds"
; NOTE: Quarantine is intentionally kept on uninstall so quarantined malware
; isn't released back onto disk. Remove it manually if desired.
