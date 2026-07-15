; Inno Setup script — builds a single USBVirusScannerSetup.exe installer.
; Compile:  iscc build\installer.iss   (or open in Inno Setup Compiler)
; Prereq :  run build.ps1 first so dist\USBVirusScanner.exe and dist\usbscan.exe exist.
;
; Produces:  Output\USBVirusScannerSetup.exe  — one file to hand to employees.

#define AppName    "USB Virus Scanner"
#define AppVersion "1.0.0"
#define AppExe     "USBVirusScanner.exe"
#define Publisher  "Company IT Security"

[Setup]
AppName={#AppName}
AppVersion={#AppVersion}
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

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "autowatch";   Description: "Auto-scan every USB drive on insert (recommended)"; GroupDescription: "Protection:"
Name: "installclam"; Description: "Install/refresh ClamAV engine + signatures (needs internet)"; GroupDescription: "Engine:"

[Files]
; Frozen executables (no Python needed on the employee PC).
Source: "..\dist\USBVirusScanner.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\usbscan.exe";         DestDir: "{app}"; Flags: ignoreversion
; Editable config + detection rules, placed next to the exe.
Source: "..\config.yaml";              DestDir: "{app}"; Flags: onlyifdoesntexist
Source: "..\signatures\*";             DestDir: "{app}\signatures"; Flags: recursesubdirs createallsubdirs
Source: "..\README.md";                DestDir: "{app}"; Flags: isreadme
; Optional: ship a ClamAV build in vendor\ClamAV to make the installer fully
; offline/standalone. If absent, the "installclam" task uses winget instead.
Source: "..\vendor\ClamAV\*"; DestDir: "{commonpf}\ClamAV"; Flags: recursesubdirs createallsubdirs skipifsourcedoesntexist

[Dirs]
Name: "{commonappdata}\USBVirusScanner\Quarantine"
Name: "{commonappdata}\USBVirusScanner\Logs"
Name: "{commonappdata}\USBVirusScanner\Reports"

[Icons]
Name: "{group}\{#AppName}";            Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall {#AppName}";  Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}";      Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
; 1. Optional ClamAV install via winget (only if user ticked the task).
Filename: "winget"; Parameters: "install --id ClamAV.ClamAV -e --silent --accept-package-agreements --accept-source-agreements"; \
  Flags: runhidden waituntilterminated; Tasks: installclam; StatusMsg: "Installing ClamAV engine..."
; 2. Update signatures (best-effort; ignore failure if offline).
Filename: "{cmd}"; Parameters: "/c ""\""{commonpf}\ClamAV\freshclam.exe\"" || exit 0"""; \
  Flags: runhidden waituntilterminated; Tasks: installclam; StatusMsg: "Updating virus signatures..."
; 3. Register the auto-scan watcher as a SYSTEM scheduled task at logon.
Filename: "schtasks"; Parameters: "/Create /F /SC ONLOGON /RL HIGHEST /RU SYSTEM /TN ""USBVirusScannerWatcher"" /TR ""\""{app}\usbscan.exe\"" watch"""; \
  Flags: runhidden waituntilterminated; Tasks: autowatch; StatusMsg: "Enabling auto-scan on USB insert..."
; 4. Offer to launch the GUI at the end.
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName} now"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Remove the scheduled task on uninstall.
Filename: "schtasks"; Parameters: "/Delete /F /TN ""USBVirusScannerWatcher"""; Flags: runhidden; RunOnceId: "DelWatchTask"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\USBVirusScanner\Logs"
Type: filesandordirs; Name: "{commonappdata}\USBVirusScanner\Reports"
; NOTE: Quarantine is intentionally kept on uninstall so quarantined malware
; isn't released back onto disk. Remove it manually if desired.
