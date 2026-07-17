# All-Round Virus Scanner

Company-wide malware scanner for **Windows**: USB drives, fixed disks, and
(opt-in) mapped network drives. Auto-scans any removable drive the moment it is
plugged in, quarantines infected files off the drive, and writes audit logs +
reports for IT.

> **Note:** the installer, exe names and install paths still use the original
> `USBVirusScanner` naming, so existing deployments keep their quarantine, logs
> and config. Only the app's display name changed.

> 📖 Prefer plain-language, step-by-step instructions with screenshots-in-words?
> Read the **[Installation & User Guide (GUIDE.md)](GUIDE.md)**. This README is
> the quick reference + technical detail.

---

# Installation

Pick the one that fits you.

## 1. Employees — install from the one setup file (easiest)

Your IT team gives you **`USBVirusScannerSetup.exe`**. Nothing else needed.

1. **Double-click** `USBVirusScannerSetup.exe`.
2. If Windows shows "Windows protected your PC", click **More info → Run anyway**.
3. Click **Yes** at the admin prompt.
4. Tick the options you want (defaults are fine):
   - ☑ Create a desktop shortcut
   - ☑ Auto-scan every USB drive on insert (recommended)
5. Click **Install → Finish**.

Done. The scanner, the virus engine, and the virus database all install from
that single file. A **USB Virus Scanner** icon appears on your desktop.

## 2. IT — build the one setup file

Do this once on a Windows machine, then hand the result to everyone.

**Step 1 — install the two prerequisites:**
[Python 3.9+](https://www.python.org/downloads/) (tick "Add to PATH" during
install) and [Inno Setup 6](https://jrsoftware.org/isdl.php).

**Step 2 — verify the prerequisites (in PowerShell):**

```powershell
python --version        # expect Python 3.9 or newer
iscc /?                 # Inno Setup; if "not recognized", install it and reopen PowerShell
```

**Step 3 — get the code:**

```powershell
git clone https://github.com/stickkersz/usb-virus-scanner.git
cd usb-virus-scanner
# already cloned? just update:  git pull
```

**Step 4 — build the installer:**

```powershell
# Fully offline installer (employees need no internet) — recommended.
# The first run downloads ClamAV + the virus DB (~450 MB, one time).
powershell -ExecutionPolicy Bypass -File build\build.ps1 -Offline

# ...or a smaller installer that downloads ClamAV during each install:
powershell -ExecutionPolicy Bypass -File build\build.ps1
```

The build prints `[0/3] … [3/3]` and ends with
`DONE. Installer: Output\USBVirusScannerSetup.exe`.

**Result:** **`Output\USBVirusScannerSetup.exe`** — the single file to deploy.

**Step 5 — smoke-test the build (harmless EICAR test file):**

```powershell
python tests\make_eicar.py C:\temp\eicartest
"C:\Program Files\USBVirusScanner\usbscan.exe" scan C:\temp\eicartest
```

Expect `Verdict : THREATS FOUND` (exit code 1). That confirms the bundled
ClamAV engine + database detect real signatures. Then plug in a USB stick to
confirm auto-scan-on-insert fires.

**Step 6 — deploy silently across the fleet** (SCCM / Intune / GPO):

```powershell
USBVirusScannerSetup.exe /VERYSILENT /NORESTART
```

<sub>Build troubleshooting: `iscc not recognized` → install Inno Setup 6 and
reopen PowerShell. `fetch-vendor.ps1` download fails → pass a current version,
e.g. `build\fetch-vendor.ps1 -Version 1.4.2`, or drop a ClamAV portable build
into `vendor\ClamAV\` manually. PyInstaller "module not found" → add it to
`hidden` in `build\usb_virus_scanner.spec`.</sub>

## 3. Install from source (dev / quick try)

Runs on Windows, macOS, and Linux. Needs **Python 3.9+**.

```bash
git clone https://github.com/stickkersz/usb-virus-scanner.git
cd usb-virus-scanner
python -m pip install -r requirements.txt

python cli.py drives          # list removable drives
python cli.py scan <path>     # scan a folder/drive
python gui.py                 # launch the GUI
```

ClamAV is optional here — without it, the heuristic + hash + YARA layers still
run (you'll see a "ClamAV not found" notice). Install ClamAV for full signature
coverage. (Windows one-shot installer for the source layout:
`powershell -ExecutionPolicy Bypass -File install.ps1 -RegisterWatcher`.)

---

# Usage

## GUI (end users)

```powershell
python gui.py          # or double-click the desktop shortcut
```

Pick a drive (or **Browse…** a folder) → click **Scan** → watch the live
progress bar with **"scanning file X of Y"** and the current file name, then
read the colored banner (green CLEAN / red THREATS). Infected files are
quarantined automatically; **Quarantine…** lists them and can restore. Tick
**Report only** to detect without moving anything.

The UI is thread-off (scanning never blocks the window) and progress events are
coalesced — one redraw per tick — so even a drive with 100k files stays smooth.

## CLI (IT / fleet)

```powershell
usbscan drives                 # list attached removable drives (bare roots)
usbscan drives --all           # ...include fixed + mapped network drives
usbscan drives --all --kinds   # ...labelled with each drive's kind
usbscan scan E:\               # scan a drive now (quarantines threats)
usbscan scan E:\ --no-quarantine   # report only, touch nothing
usbscan watch                  # auto-scan every USB as it is inserted
usbscan monitor                # real-time: scan files the moment they land
usbscan update                 # refresh ClamAV signatures (freshclam)
usbscan quarantine             # list quarantined files
usbscan quarantine --restore <ID> --to D:\recovered.bin
usbscan quarantine --delete <ID>       # permanently delete one (irreversible)
usbscan quarantine --purge             # permanently delete ALL (asks to confirm)
usbscan quarantine --purge --yes       # ...skip the confirmation
```

Exit codes — usable in scripts / GPO: `0` = clean, `1` = threats found,
`2` = bad arguments, `3` = completed with errors (**partial coverage** — e.g.
an unreadable drive; do not treat as a clean scan). (From source, use
`python cli.py …` instead of `usbscan …`.)

## Scan profiles

Instead of naming a path, scan a preset target set. All roots are merged into
**one** verdict and one report.

```powershell
usbscan scan --profile quick    # common malware drop + persistence locations
usbscan scan --profile full     # every fixed + removable drive
usbscan scan --profile custom D:\ E:\shared    # exactly these paths
usbscan scan --profile quick E:\   # quick locations PLUS the E:\ drive
```

Paths given alongside `--profile quick/full` are scanned **in addition** to
the profile's targets, and a path already covered by the profile is scanned
**once**, not twice. Quick resolves Desktop/Downloads through the registry, so
OneDrive **Known Folder Move** redirection is followed.

`drives` prints bare roots so scripts can feed them straight back into `scan`;
add `--kinds` for human-readable labels.

| Profile | Covers |
|---|---|
| `quick` | Downloads, Desktop, Temp, `%AppData%`, and the Startup folders |
| `full`  | Every fixed + removable drive. Network drives only if `scan_network_drives: true` |
| `custom` | The paths you pass |

`quick` deliberately skips the whole of `%LocalAppData%` — browser caches there
run to tens of GB and would make Quick slower than Full. It still covers
`%LocalAppData%\Temp`, the actual drop target. `full` still covers everything.

## Exclusions

Full-disk scanning makes exclusions matter: walking every VM image and
`node_modules` tree costs hours and finds nothing. Set them in `config.yaml`
under `scanner.exclusions` — **nothing is excluded by default.**

```yaml
scanner:
  exclusions:
    - "D:\\VMs"           # absolute path -> that folder and everything under it
    - "\\Windows\\WinSxS" # driveless     -> same, on EVERY drive letter
    - "node_modules"      # bare name     -> any folder with that name, any depth
    - "*.iso"             # wildcard      -> matches full path or bare filename
```

Only `*` and `?` are wildcards (`[` is a literal — legal in Windows names like
`D:\VMs [old]`).

> ⚠️ An exclusion is a **hole in coverage** — an excluded path is scanned by no
> layer at all. Never exclude user-writable drop targets (Downloads, Temp,
> `%AppData%`); that is exactly where malware lands.

Excluded directories are *pruned*, so a skipped tree costs one comparison
instead of a full walk. Who wins when an exclusion covers a scan root:

- **A path you named explicitly** (CLI path, `--profile custom`, GUI pick)
  wins over the exclusion — otherwise `usbscan scan D:\VMs` would report a
  false "0 files, CLEAN". Exclusions deeper inside that tree still apply.
- **Machine-chosen roots** (drive-insert auto-scan, `--profile quick/full`
  resolution) honor exclusions fully, so you CAN exclude a known-huge drive
  from auto-scanning. The skip is recorded in the report's errors (exit
  code 3), never silent.

## Real-time monitoring

`usbscan monitor` watches directories for new/changed files and scans them
the moment they finish writing — through the **same** engine as manual scans
(one detection path, one quarantine, one log).

- **What it watches:** `realtime.paths` in `config.yaml`; empty = the Quick
  profile locations (Downloads, Desktop, Temp, AppData, Startup) — where new
  files actually land. Watching whole drives works but costs more.
  Running as a **service account** (the installer's SYSTEM logon task), the
  default expands to *every* user profile on the machine — a per-user default
  would resolve to the service account's own profile and watch nobody's
  Downloads.
- **Turn it on:** `realtime.enabled: true` starts it with the GUI; the
  installer's "Real-time protection" checkbox registers it as a logon task.
- **Needs clamd.** Without the resident ClamAV daemon each batch cold-starts
  clamscan and reloads the whole signature database (tens of seconds, ~1 GB).
  The monitor warns when clamd is missing — install/enable it for real-time.
- **Debounce:** a file is scanned once it has gone `settle_seconds` (default 2)
  without a new write, so a growing download is scanned once at the end, not
  hundreds of times mid-write. Renames (`x.part` → `x.exe`) scan the final name.
- **No feedback loop:** the quarantine, log and report directories are never
  watched — quarantining a hit writes files, which would otherwise re-trigger
  the monitor forever.
- **Exclusions apply fully** (these are machine-selected files, not paths you
  named). `--no-quarantine`, `realtime.quarantine: false`, or the GUI's
  **Report only** checkbox = report without moving anything.
- Requires the `watchdog` package (bundled in the installer build; from
  source: `pip install watchdog`). Everything else works without it.

## Web protection (download-origin checks)

Windows stamps every downloaded file with a **Mark of the Web** (the
`Zone.Identifier` stream) recording the URL it came from. During any scan,
risky-extension files have that origin checked against synced threat-intel
feeds — catching brand-new malware whose payload has no signature yet but
whose distribution URL is already known-bad.

```powershell
usbscan feeds        # sync feeds (URLhaus by abuse.ch — free, no API key)
```

- The installer registers a daily sync task (12:30). After a sync everything
  works **offline** — no lookup leaves the machine. Long-running processes
  (`monitor`, an open GUI) pick up refreshed feeds automatically; no restart.
- An origin match flags **SUSPICIOUS, never INFECTED**: the URL being
  malicious is strong evidence, but the file content is unproven, so origin
  alone never auto-quarantines.
- Matching is **exact-URL**, not host-level — host matching would flag every
  download from any compromised CDN (too many false positives).
- Feeds with `type: sha256` merge into the same hash-blocklist layer as your
  company blocklist — one detection path.
- **Optional Google Safe Browsing**: set `web.safe_browsing_api_key` (register
  your own key at console.cloud.google.com). Privacy tradeoff: when enabled,
  download-origin URLs are sent to Google. Off by default; a network failure
  fails open (it can add detections, never suppress them).

## Prove it works (safe test)

```powershell
python tests\make_eicar.py C:\temp\eicartest    # writes harmless EICAR test file
usbscan scan C:\temp\eicartest                  # must report a detection
```

EICAR is the industry-standard harmless AV test string — every scanner flags
it, it does nothing.

---

# How it works

Five detection layers, each catching what the others miss:

| Layer | What it catches | Engine |
|-------|-----------------|--------|
| **ClamAV signatures** | Millions of known viruses/malware, inside archives too | `clamscan` / `clamdscan` |
| **ClamAV PUA + heuristics** | Adware / potentially-unwanted programs, packed/broken PEs | `--detect-pua`, `--heuristic-alerts` |
| **Company hash blocklist** | Known-bad files from your own IR / threat intel | SHA-256 match |
| **YARA rules** | Ransomware, spyware/keyloggers, worms, trojan downloaders, macro droppers, packers — by *technique*, so novel variants match | `yara-python` |
| **USB + behavior heuristics** | `autorun.inf`, double extensions, ransom notes, encrypted-file extensions, packed/high-entropy executables | built-in |

## Threat coverage

Detection is designed around the real threat landscape — ~1.56B known samples
plus ~450k new variants/day. Known samples are caught by signatures; novel ones
by technique/behavior:

| Threat category | How it's detected here |
|-----------------|------------------------|
| **Trojans** | ClamAV signatures; YARA `Trojan_Downloader_Generic` (download+exec APIs); packed-executable entropy check |
| **Ransomware** | YARA `Ransomware_Note_Text` / `Ransomware_Crypto_API_Combo` (crypto + shadow-copy deletion); heuristic ransom-note + `.locked/.crypt/...` extension flags |
| **Spyware / keyloggers / infostealers** | YARA `Spyware_Keylogger_Indicators`, `Infostealer_Browser_Credentials`; ClamAV signatures |
| **Viruses** | ClamAV signatures (file-infector DB); hash blocklist |
| **Worms** | YARA `Worm_Network_Selfspread`; `autorun.inf` heuristic (removable-media spread) |
| **Adware / PUP** | ClamAV `--detect-pua`; YARA `Adware_PUP_Bundler` |

**Zero-days (the 450k/day):** the YARA rules match on *techniques* (crypto+VSS
deletion, download+exec, keylogging APIs, packer markers) and the entropy check
flags obfuscated binaries — so brand-new variants with no signature still get
caught. **Keep ClamAV fresh** (`usbscan update`, or the scheduled `freshclam`
the installer sets up) so signature coverage tracks the daily flood.

Two front-ends (`gui.py`, `cli.py`) drive one shared **`ScanEngine`**. A scan is
a pipeline:

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

A confirmed infection is moved to a neutralized quarantine (XOR-obfuscated so it
can't be double-clicked into execution), logged, and put in a per-scan report.
Everything is reversible via `quarantine --restore`.

**Drive detection** uses the Win32 API (`GetLogicalDrives` / `GetDriveType`) via
`ctypes` — no service, no admin, works Windows 7→11. The same call classifies
removable, fixed, network and optical drives, so one enumerator feeds the drive
list, the scan profiles and the insert watcher. The `watch` command polls for
drive arrival and auto-scans on insert. Optical drives are never scanned (read-
only, and spinning one up costs seconds for no benefit).

## Project layout

```
usb-virus-scanner/
├── cli.py               # CLI entry point (scan/watch/drives/quarantine/update)
├── gui.py               # Tkinter desktop GUI
├── config.yaml          # all tunables (paths, speed, detection knobs)
├── scanner/
│   ├── engine.py        # ScanEngine + ClamAV wrapper (the pipeline above)
│   ├── heuristics.py    # autorun/double-ext + hash blocklist + YARA
│   ├── drives.py        # enumerate removable/fixed/network/optical drives
│   ├── profiles.py      # Quick / Full / Custom scan target sets
│   ├── exclusions.py    # config-driven skip patterns (pruned during the walk)
│   ├── quarantine.py    # move / neutralize / restore + index
│   ├── cache.py         # skip unchanged-clean files
│   ├── realtime.py      # real-time monitor (watchdog + debounced queue)
│   ├── web.py           # feeds sync + Mark-of-the-Web origin checks
│   ├── watcher.py       # USB insert polling (enumeration lives in drives.py)
│   ├── reporter.py      # logging + JSONL + text reports
│   ├── paths.py         # source vs frozen-exe base dir
│   ├── config.py        # config load + defaults
│   └── models.py        # Detection / ScanResult types
├── signatures/
│   ├── hash_blocklist.txt   # your SHA-256 blocklist
│   └── yara/usb_threats.yar # starter YARA rules
├── tests/               # pytest suite + EICAR generator
└── build/               # PyInstaller spec + Inno Setup + icon → setup.exe
```

---

# Deployment & operations

## Fully-offline installer (zero downloads on the employee PC)

By default the installer fetches the ClamAV engine + virus database from the
internet (winget + freshclam) during setup. To bundle **everything** into the
one setup file so employees need **no internet at all**:

```powershell
# on the build machine, WITH internet, ONE time:
powershell -ExecutionPolicy Bypass -File build\fetch-vendor.ps1   # ClamAV + signatures -> vendor\
powershell -ExecutionPolicy Bypass -File build\build.ps1          # bundles them

# or both at once:
powershell -ExecutionPolicy Bypass -File build\build.ps1 -Offline
```

The build auto-detects `vendor\ClamAV\` at compile time: when present, ClamAV
and the full signature DB are packed inside `USBVirusScannerSetup.exe` and every
online step is removed. Re-run `fetch-vendor.ps1` to refresh the bundled
signatures. (`vendor\` is git-ignored — ~450 MB of Windows binaries, not
committed.)

The app icon (`build\app.ico`) is embedded into both exes and the shortcuts;
regenerate it with `python build\make_icon.py` (needs Pillow). Build artifacts
(`dist\`, `Output\`) are git-ignored.

## Fleet deployment

- **Recommended:** push `USBVirusScannerSetup.exe` via SCCM/Intune/GPO, install
  with `/VERYSILENT /NORESTART`. (Source alternative: push the folder + run
  `install.ps1 -RegisterWatcher`.)
- The watcher runs as a startup scheduled task under SYSTEM; every inserted USB
  is scanned automatically, no user action.
- Ship `events.jsonl` to your SIEM for company-wide visibility.
- Maintain `signatures/hash_blocklist.txt` centrally and sync it out; add hashes
  as incidents happen.
- Keep signatures fresh: schedule `usbscan update` (or `freshclam`).

## Updating an already-installed deployment

There are **two completely separate kinds of update**. Know which one you need:

| You want... | Use | Gets new features? | Gets newer virus definitions? |
|-------------|-----|:---:|:---:|
| Latest **virus definitions** | `usbscan update` | ❌ | ✅ |
| New **program features / fixes** (e.g. the delete button, GUI changes) | rebuild + reinstall `setup.exe` | ✅ | ✅ |

> **Key point:** `usbscan update` only refreshes the virus database — it does
> **not** add program features. New features live inside the `.exe`, so they
> only arrive by installing a newly-built `setup.exe`.

### A) Update virus definitions (fast, no rebuild)

Already automatic — the installer registers a daily task
(`USBVirusScannerUpdate`, noon) that refreshes the ClamAV database. To force one
now:

```powershell
"C:\Program Files\USBVirusScanner\usbscan.exe" update
```

### B) Update the program to a new version (new features / fixes)

New features and bug fixes live **inside the `.exe`**, so they arrive only by
building a fresh `setup.exe` and installing it over the top. The installer
upgrades **in place** — it has a fixed `AppId`, so Windows replaces the old files
and keeps a single Add/Remove Programs entry. You do **not** uninstall first.

**Step 0 — Check the version you have now** (on any installed PC):

```powershell
"C:\Program Files\USBVirusScanner\usbscan.exe" version
```

**Step 1 — Build a new installer** (on the BUILD machine, with internet once):

```powershell
cd usb-virus-scanner
git pull                                   # get the new code
powershell -ExecutionPolicy Bypass -File build\build.ps1 -Offline -Version 1.1.0
```

Bump `-Version` every release (`1.1.0`, `1.2.0`, …) so the number shows correctly
in `usbscan version` and Add/Remove Programs. Omit it to keep the current number.
The new `USBVirusScannerSetup.exe` lands in `dist\`.

**Step 2 — Install the update on each PC.** Pick one:

```powershell
# Single PC, interactive: just double-click USBVirusScannerSetup.exe, OR:
USBVirusScannerSetup.exe

# Single PC, unattended (no prompts, no reboot):
USBVirusScannerSetup.exe /VERYSILENT /NORESTART

# Whole fleet: push that same silent command via GPO / Intune / SCCM.
```

> **Close the app first (recommended).** If the GUI or a `monitor`/`watch` run is
> open, Windows may hold `USBVirusScanner.exe` locked. The silent install still
> completes, but the running old copy keeps its old code until it is closed and
> reopened. On a locked-file error, close the app (and stop the scheduled tasks)
> and re-run the installer.

**Step 3 — Verify the update took:**

```powershell
"C:\Program Files\USBVirusScanner\usbscan.exe" version      # shows the new number
"C:\Program Files\USBVirusScanner\usbscan.exe" scan --profile quick   # smoke test
```

The real-time monitor and feed tasks are re-created by the installer, so
protection resumes automatically at the next logon (or start it now from the GUI
checkbox / `usbscan monitor`).

**Kept safe across an upgrade:** the user's `config.yaml`, the Quarantine folder,
and the scheduled tasks (re-created). Uninstalling also keeps Quarantine, so
contained malware is never released back onto disk.

**Rollback:** updates are just installers, so to go back, build (or keep) the
previous `setup.exe` and run it the same way — same in-place upgrade, one
Add/Remove Programs entry. Keep the last known-good `setup.exe` before rolling
out a new one.

---

# Configuration & tuning

All behavior lives in `config.yaml` (ClamAV paths, quarantine dir, suspicious
extensions, workers, poll interval, speed knobs). Defaults are built in, so the
tool runs even if the file is missing.

## Accuracy — avoiding false positives on legit Windows files

Legit software can resemble malware to behavior heuristics: **signed installers
are packed/high-entropy**, and system tools import keylogger-like APIs. Three
trust signals quiet those false alarms — and **none of them ever hides a real
ClamAV, hash-blocklist, or YARA detection**; they only suppress the FP-prone
heuristics:

- **Authenticode signatures** (`trust_signed: true`) — a validly-signed PE from
  a trusted publisher (Microsoft, etc.) skips the packed/entropy heuristic. This
  uses Windows' own code-signing trust, so it works across builds with no list
  to maintain. The check is lazy (only runs when entropy is already high).
- **Trusted paths** (`trusted_paths`) — files under `C:\Windows`,
  `C:\Program Files`, `C:\Program Files (x86)` skip the entropy heuristic.
- **SHA-256 allowlist** (`signatures/allowlist_sha256.txt`) — exact known-good
  hashes are fully trusted (heuristic + YARA skipped for them). Populate from
  [NSRL](https://www.nist.gov/itl/ssd/software-quality-group/nsrl), your golden
  image (`Get-FileHash -Algorithm SHA256`), or add a hash whenever the scanner
  false-positives on a file you trust.

Precedence is safe: an explicit **hash-blocklist / ClamAV hit always wins** over
any allowlist or signature (so signed malware or a trusted-path implant is still
caught by the authoritative layers).

## Speed on slow laptops

- **Single tree walk** — the drive is enumerated once; ClamAV gets a file-list
  instead of re-walking the tree (was double disk IO).
- **Scan cache** (`use_cache`) — files unchanged since the last clean scan are
  skipped entirely. Re-scanning the same USB / hard disk is near-instant. Cache
  lives in `…\Logs\scan_cache.json`.
- **Fast mode** (`deep_scan_all: false`) — SHA-256 + YARA only run on risky-type
  files or files under `deep_scan_max_mb` (default 50). Big media isn't read
  byte-by-byte. Set `deep_scan_all: true` for max thoroughness.
- **Parallel** — `workers: auto` scales to CPU cores (capped so a single-disk
  laptop doesn't thrash); `multiscan: true` uses clamd's parallel engine.
- **Single-read deep scan** — a file's hash, YARA match, and entropy check all
  run off one read of the bytes (small files buffered once; huge files stream),
  instead of reading the file 2-3 times.
- **No redundant `stat`** — the cache reuses size/mtime from the initial walk.
- **Resident-daemon signature scan** — prefers `clamdscan` (ClamAV DB stays in
  RAM, ~10-100x faster on repeat scans) and auto-falls back to one-shot
  `clamscan` if the `clamd` service isn't running.
- **Skip archives** for extra speed on weak hardware: `scan_archives: false`.

Cheatsheet — very slow laptop: `deep_scan_max_mb: 20`, `scan_archives: false`,
`use_cache: true`. Air-gapped high-security box: `deep_scan_all: true`,
`scan_archives: true`.

---

# Development

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q          # 45 tests: cache, quarantine, heuristics, engine, CLI, units
```

The suite covers detection correctness, quarantine round-trip (byte-exact
restore), cache invalidation, deep-scan gating, CLI exit codes, and config
merging. No ClamAV needed — the heuristic/hash/YARA layers are exercised
directly.

## Windows compatibility

Drive detection uses the Win32 API via `ctypes` — Windows 7 → 11 / Server, no
extra service. ClamAV and Python 3.9+ are the only prerequisites. On
Linux/macOS it falls back to mount-point polling so you can develop off Windows.

## Notes / limits

- Quarantine "neutralize" is XOR obfuscation to stop accidental execution — not
  cryptographic protection of the sample.
- Detection is only as good as the ClamAV DB — keep it fresh.
- Run the watcher elevated so it can read/quarantine files owned by other users.
