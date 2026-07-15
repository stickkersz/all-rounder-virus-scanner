# USB Virus Scanner

Company-wide malware scanner for **USB drives and hard disks on Windows**.
Auto-scans any removable drive the moment it is plugged in, quarantines
infected files off the drive, and writes audit logs + reports for IT.

> 📖 **New here? Read the [step-by-step Installation & User Guide (GUIDE.md)](GUIDE.md)** —
> plain-language install steps and a tutorial for scanning, quarantine, and more.
> This README is the technical reference.

## Detection layers

| Layer | What it catches | Engine |
|-------|-----------------|--------|
| **ClamAV signatures** | Millions of known viruses/malware, inside archives too | `clamscan` / `clamdscan` |
| **Company hash blocklist** | Known-bad files from your own IR / threat intel | SHA-256 match |
| **YARA rules** | Behavior patterns, zero-days ClamAV misses | `yara-python` |
| **USB heuristics** | `autorun.inf` autostart, double extensions (`invoice.pdf.exe`), risky script droppers | built-in |

On a confirmed infection the file is moved to an encrypted-neutralized
quarantine (XOR-obfuscated so it can't be double-clicked into execution),
logged, and included in a per-scan report. Everything is reversible via
`quarantine --restore`.

## How it works

Two front-ends (`gui.py`, `cli.py`) drive one shared **`ScanEngine`**. A scan
runs as a pipeline:

```
   insert USB / pick target
            │
   ┌────────▼─────────┐
   │ 1. Walk the tree │  os.scandir, once. Collect path+size+mtime.
   │    (single pass) │  Apply max-file-size cap.
   └────────┬─────────┘
   ┌────────▼─────────┐
   │ 2. Cache filter  │  Drop files unchanged since last CLEAN scan
   │                  │  (path+size+mtime match) → candidate list.
   └────────┬─────────┘
   ┌────────▼─────────┐
   │ 3. ClamAV        │  Candidates handed to clamscan/clamdscan via
   │    signatures    │  --file-list (+ --multiscan). Parses "FOUND".
   └────────┬─────────┘
   ┌────────▼─────────┐
   │ 4. Heuristic     │  Thread pool. Per file: autorun.inf, double
   │    layer         │  extension, SHA-256 hash blocklist, YARA rules.
   │                  │  Deep read gated to risky/small files (fast mode).
   └────────┬─────────┘
   ┌────────▼─────────┐
   │ 5. Quarantine    │  INFECTED files moved off the drive, XOR-
   │                  │  neutralized, indexed for restore.
   └────────┬─────────┘
   ┌────────▼─────────┐
   │ 6. Log + report  │  Rotating log, JSONL for SIEM, text report.
   │    + cache clean │  Clean files recorded so next scan skips them.
   └──────────────────┘
```

**Detection is layered on purpose:** ClamAV catches the millions of known
signatures; the hash blocklist catches files your own incident-response team
flagged; YARA catches behavior patterns and zero-days ClamAV has no signature
for yet; the heuristics catch USB-specific propagation tricks (autostart,
masquerading) that aren't "malware bytes" at all. A file can be flagged by any
layer independently.

**Removable-drive detection** uses the Win32 API (`GetLogicalDrives` /
`GetDriveType`) via `ctypes` — no service, no admin, works Windows 7→11. The
`watch` command polls for drive arrival and auto-scans on insert.

### Project layout

```
usb-virus-scanner/
├── cli.py               # CLI entry point (scan/watch/drives/quarantine/update)
├── gui.py               # Tkinter desktop GUI
├── config.yaml          # all tunables (paths, speed, detection knobs)
├── scanner/
│   ├── engine.py        # ScanEngine + ClamAV wrapper (the pipeline above)
│   ├── heuristics.py    # autorun/double-ext + hash blocklist + YARA
│   ├── quarantine.py    # move / neutralize / restore + index
│   ├── cache.py         # skip unchanged-clean files
│   ├── watcher.py       # USB insert detection (Win32 ctypes)
│   ├── reporter.py      # logging + JSONL + text reports
│   ├── paths.py         # source vs frozen-exe base dir
│   ├── config.py        # config load + defaults
│   └── models.py        # Detection / ScanResult types
├── signatures/
│   ├── hash_blocklist.txt   # your SHA-256 blocklist
│   └── yara/usb_threats.yar # starter YARA rules
├── tests/make_eicar.py  # writes the harmless EICAR AV test file
└── build/               # PyInstaller spec + Inno Setup + icon → setup.exe
```

## Run from source (dev / quick try)

Works on Windows, macOS, and Linux (drive detection falls back to mount points
off Windows, so you can develop anywhere).

```bash
git clone https://github.com/stickkersz/usb-virus-scanner.git
cd usb-virus-scanner
python -m pip install -r requirements.txt

python cli.py drives          # list removable drives
python cli.py scan <path>     # scan a folder/drive
python gui.py                 # launch the GUI
```

ClamAV is optional for a quick try — without it, the heuristic + hash + YARA
layers still run (you'll see a "ClamAV not found" notice). Install ClamAV for
full signature coverage.

## Install (Windows)

Elevated PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
# add -RegisterWatcher to auto-start the insert-watcher at logon:
powershell -ExecutionPolicy Bypass -File install.ps1 -RegisterWatcher
```

Installs ClamAV (via winget), Python deps, updates signatures, creates
`C:\ProgramData\USBVirusScanner\{Quarantine,Logs,Reports}`.

## GUI (end users)

```powershell
python gui.py
```

Simple window: pick a drive (or **Browse…** a folder), click **Scan**, watch
progress, see a color-coded threat list and a CLEAN/THREATS banner. Infected
files are quarantined automatically; **Quarantine…** opens a list where a file
can be restored. Tick **Report only** to detect without moving anything.

Built on Tkinter — ships with Python, so nothing extra to install for the
front-end. Scanning runs on a background thread; the window stays responsive.
Make a desktop shortcut to `pythonw gui.py` (note `pythonw` = no console
window) for non-technical staff.

## CLI (IT / fleet)

```powershell
python cli.py drives                 # list attached removable drives
python cli.py scan E:\               # scan a drive now (quarantines threats)
python cli.py scan E:\ --no-quarantine   # report only, touch nothing
python cli.py watch                  # auto-scan every USB as it is inserted
python cli.py update                 # refresh ClamAV signatures (freshclam)
python cli.py quarantine             # list quarantined files
python cli.py quarantine --restore <ID> --to D:\recovered.bin
```

Exit code `0` = clean, `1` = threats found — usable in scripts / GPO.

## Build the employee installer (one .exe)

On a Windows build machine with Python 3.9+ **and** [Inno Setup 6](https://jrsoftware.org/isdl.php):

```powershell
powershell -ExecutionPolicy Bypass -File build\build.ps1
```

Produces **`Output\USBVirusScannerSetup.exe`** — a single file to hand to
employees. It:

- freezes `gui.py` + `cli.py` with PyInstaller into `USBVirusScanner.exe`
  (GUI) and `usbscan.exe` (CLI) — **no Python needed on the employee PC**;
- wraps them with Inno Setup into one setup executable.

What the employee gets when they run `USBVirusScannerSetup.exe`:

- installs to `C:\Program Files\USBVirusScanner`, Start-Menu + optional Desktop shortcut;
- checkbox **"Auto-scan every USB on insert"** → registers a SYSTEM scheduled task;
- checkbox **"Install/refresh ClamAV"** → pulls ClamAV via winget + updates signatures;
- creates the `ProgramData\USBVirusScanner\{Quarantine,Logs,Reports}` folders.

Double-click → Next → Finish. Silent/GPO install: `USBVirusScannerSetup.exe /VERYSILENT /NORESTART`.

### Fully-offline installer (zero downloads on the employee PC)

By default the installer fetches the ClamAV engine + virus database from the
internet (winget + freshclam) during setup. To bundle **everything** into the
one setup file so employees need **no internet at all**:

```powershell
# on the build machine, WITH internet, ONE time:
powershell -ExecutionPolicy Bypass -File build\fetch-vendor.ps1   # downloads ClamAV + signatures into vendor\
powershell -ExecutionPolicy Bypass -File build\build.ps1          # bundles them

# or do both in one go:
powershell -ExecutionPolicy Bypass -File build\build.ps1 -Offline
```

The build auto-detects `vendor\ClamAV\` at compile time: when present, ClamAV
and the full signature DB are packed inside `USBVirusScannerSetup.exe` and every
online step is removed. The employee just double-clicks — engine, database,
scanner, GUI, shortcuts, auto-scan task, all installed from that one file,
offline. Re-run `fetch-vendor.ps1` when you want to refresh the bundled
signatures. (`vendor\` is git-ignored — ~450 MB of Windows binaries, not
committed.)

The app icon (`build\app.ico`, a security shield + USB mark) is embedded into
both exes and used by the shortcuts. Regenerate/edit it with
`python build\make_icon.py` (needs Pillow).

Build artifacts (`dist\`, `Output\`) are git-ignored.

## Fleet deployment

- **Recommended:** push `USBVirusScannerSetup.exe` via SCCM/Intune/GPO and
  install silently: `USBVirusScannerSetup.exe /VERYSILENT /NORESTART`.
  (Source install alternative: push the folder and run `install.ps1 -RegisterWatcher`.)
- The watcher runs as a startup scheduled task under SYSTEM; every inserted
  USB is scanned automatically, no user action.
- Point `logging.jsonl` at a shared path or ship `events.jsonl` to your SIEM
  for company-wide visibility.
- Maintain `signatures/hash_blocklist.txt` centrally and sync it out; add
  hashes as incidents happen.

## Test it works

```powershell
python tests\make_eicar.py C:\temp\eicartest    # writes harmless EICAR test file
python cli.py scan C:\temp\eicartest            # must report a detection
```

EICAR is the industry-standard harmless AV test string — every scanner flags
it, it does nothing.

## Speed on slow laptops

Optimized so old/slow company machines scan fast:

- **Single tree walk** — the drive is enumerated once; ClamAV gets a file-list
  instead of re-walking the tree itself (was double disk IO).
- **Scan cache** (`use_cache`) — files unchanged since the last clean scan are
  skipped entirely (path + size + mtime). Re-scanning the same USB / company
  hard disk is near-instant. Cache lives in `…\Logs\scan_cache.json`.
- **Fast mode** (`deep_scan_all: false`) — SHA-256 + YARA only run on risky-type
  files or files under `deep_scan_max_mb` (default 50). Big movies/backups are
  not read byte-by-byte. Set `deep_scan_all: true` for max thoroughness.
- **Parallel** — `workers: auto` scales threads to CPU cores (capped so a
  single-disk laptop doesn't thrash); `multiscan: true` uses clamd's parallel
  engine.
- **Skip archives** for extra speed on weak hardware: set `scan_archives: false`.

Tuning cheatsheet for a very slow laptop: `deep_scan_max_mb: 20`,
`scan_archives: false`, keep `use_cache: true`. For an air-gapped high-security
box: `deep_scan_all: true`, `scan_archives: true`.

## Config

All paths and behavior live in `config.yaml` (ClamAV path, quarantine dir,
suspicious extensions, workers, poll interval, etc.). Defaults are built in,
so the tool runs even if the file is missing.

## Windows compatibility

Drive detection uses the Win32 API (`GetLogicalDrives` / `GetDriveType`) via
`ctypes` — works on Windows 7 → 11 / Server with no extra service. ClamAV and
Python 3.9+ are the only prerequisites. On Linux/macOS it falls back to
mount-point polling so you can develop and test off Windows.

## Notes / limits

- Quarantine "neutralize" is XOR obfuscation to stop accidental execution — it
  is not cryptographic protection of the sample.
- Keep ClamAV signatures fresh (`update` / scheduled `freshclam`) — detection
  is only as good as the DB.
- Run the watcher elevated so it can read/quarantine files owned by other users.
