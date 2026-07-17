# All-Round Virus Scanner — Installation & User Guide

> *Formerly "USB Virus Scanner". It now protects the whole computer — USB
> drives, hard disks, downloads, and files in real time. The setup file and
> install folders keep the old `USBVirusScanner` names on purpose, so upgrades
> keep your settings and quarantine.*

A friendly, step-by-step guide. No prior experience needed. Two parts:

1. **[Installation & Setup](#part-1--installation--setup)** — get it onto a PC.
2. **[Tutorial: using the program](#part-2--tutorial-using-the-program)** — scan, read results, handle threats.

> **Who should read what?**
> - **Employee / normal user** → [Install with the setup file](#a-employees--the-easy-way-one-file) + the whole [Tutorial](#part-2--tutorial-using-the-program).
> - **IT / whoever builds the installer** → [Build the setup file](#c-it--build-the-one-click-setup-file).

---

## Part 1 — Installation & Setup

### A. Employees — the easy way (one file)

You only need the single file **`USBVirusScannerSetup.exe`** (your IT team gives you this).

1. **Double-click** `USBVirusScannerSetup.exe`.
2. If Windows shows a blue "Windows protected your PC" box, click **More info → Run anyway** (this is normal for new in-house apps).
3. Click **Yes** when asked for admin permission.
4. On the options screen, tick the boxes you want (defaults are fine):
   - ☑ **Create a desktop shortcut**
   - ☑ **Auto-scan every USB drive on insert** (recommended)
   - ☑ **Real-time protection** — scans files the moment they land (recommended)
   - ☑ **Daily threat-intel feed sync** — needs internet; skip on offline PCs
5. Click **Install**, wait a few seconds, then **Finish**.
6. Done. You'll see an **All-Round Virus Scanner** icon on your desktop.

That's it — the scanner, the virus engine, and the virus database are all installed from that one file. **[Jump to the Tutorial →](#part-2--tutorial-using-the-program)**

---

### B. Test / try it from source (developers)

Works on Windows, macOS, and Linux. Needs **Python 3.9+**.

1. Install Python from [python.org](https://www.python.org/downloads/) (on Windows, tick **"Add Python to PATH"** during install).
2. Open a terminal (Windows: **PowerShell**) and run:
   ```powershell
   git clone https://github.com/stickkersz/usb-virus-scanner.git
   cd usb-virus-scanner
   python -m pip install -r requirements.txt
   ```
3. Try it:
   ```powershell
   python cli.py drives     # lists your removable drives
   python gui.py            # opens the window
   ```

> Without ClamAV installed you still get the heuristic + hash + YARA layers (you'll see a "ClamAV not found" notice). For full virus coverage, install ClamAV (the Windows installer below does this for you).

---

### C. IT — build the one-click setup file

Do this **once** on a Windows machine to produce the `USBVirusScannerSetup.exe` you hand to employees.

**You need:**
- **Python 3.9+** — [python.org](https://www.python.org/downloads/) (tick "Add to PATH").
- **Inno Setup 6** — [jrsoftware.org/isdl.php](https://jrsoftware.org/isdl.php) (just click through the installer).

**Steps:**

1. Get the code:
   ```powershell
   git clone https://github.com/stickkersz/usb-virus-scanner.git
   cd usb-virus-scanner
   ```
2. Build the installer:

   **Option 1 — fully offline** (employees need no internet; recommended):
   ```powershell
   powershell -ExecutionPolicy Bypass -File build\build.ps1 -Offline
   ```
   This downloads the ClamAV engine + virus database once, then bundles
   everything inside the setup file (~450 MB download, one time).

   **Option 2 — smaller installer** (downloads ClamAV during each install):
   ```powershell
   powershell -ExecutionPolicy Bypass -File build\build.ps1
   ```
3. When it finishes, your installer is here:
   ```
   Output\USBVirusScannerSetup.exe
   ```
4. Hand that one file to employees, or push it company-wide.

**Deploy silently to many PCs** (SCCM / Intune / Group Policy):
```powershell
USBVirusScannerSetup.exe /VERYSILENT /NORESTART
```

> **Refresh the bundled virus signatures later:** re-run
> `build\fetch-vendor.ps1` then `build\build.ps1` to make a fresh installer.

---

## Part 2 — Tutorial: using the program

### 1. Scan a USB stick (the window / GUI)

1. Open **All-Round Virus Scanner** (desktop icon, or Start menu).
2. Plug in the USB stick you want to check.
3. In the **Target** box, pick your USB drive from the dropdown
   (e.g. `E:\`). Click **Refresh** if it isn't listed yet.
   *Want to scan a folder instead? Click **Browse…** and choose it.*
4. Click **▶ Scan**.
5. Watch the progress bar. When it's done you'll see a colored banner:
   - 🟢 **Green "CLEAN"** — nothing bad found. You're safe.
   - 🔴 **Red "THREATS FOUND"** — infected files were found and **automatically moved to quarantine** (removed from the USB so they can't run).
6. The table lists what was found:
   - **red rows** = infected (already quarantined)
   - **orange rows** = suspicious (worth a look)

> **Just want to check without changing anything?** Tick **"Report only"** before scanning — it finds threats but never moves or deletes files.

### 1b. Scan the whole computer (Quick / Full)

Two buttons next to **▶ Scan**:

- **Quick Scan** — checks the places malware actually lands: Downloads,
  Desktop, temporary folders, and the auto-start locations. Takes minutes.
  **Do this if you just want a fast check-up.**
- **Full Scan** — every drive in the computer, every file. Can take **hours**
  on a big disk, so the program asks you to confirm first.

From the command line: `usbscan scan --profile quick` or
`usbscan scan --profile full`.

> **IT tip:** big folders you never want scanned (VM images, build caches) go
> in `config.yaml` under `scanner.exclusions`. Never exclude Downloads, Temp
> or AppData — that's exactly where malware lands.

### 2. What happens to infected files (quarantine)

Infected files are **moved off the drive** into a safe quarantine folder and
"neutralized" so they can't accidentally run. Nothing is permanently deleted —
you can put a file back if it was a false alarm.

**To view, restore, or delete quarantined files:**

1. In the window, click **Quarantine…**.
2. You'll see a list of everything quarantined (name, threat, original location).
3. To bring one back: select it → **Restore selected…** → confirm.
   ⚠️ Only restore a file if you're **sure** it's safe — it was flagged as malware.
4. To wipe malware for good: select it → **Delete selected**, or **🗑 Delete ALL**
   to nuke everything in quarantine. You'll be asked to confirm — **deletion is
   permanent and cannot be undone.**

From the command line:

```powershell
usbscan quarantine --delete <ID>     # delete one, forever
usbscan quarantine --purge           # delete everything (asks to confirm)
usbscan quarantine --purge --yes     # ...no prompt (for scripts)
```

### 3. Automatic scanning when you plug in a USB

If you (or IT) enabled **"Auto-scan on insert"** during install, you don't have
to do anything: **every USB drive is scanned the moment it's plugged in**, in
the background. If something bad is found, it's quarantined and logged
automatically.

### 3b. Real-time protection (files scanned as they arrive)

Tick **"Real-time protection"** in the window, and every new or changed file
in your Downloads, Desktop and temp folders is scanned **the moment it
finishes arriving** — before you open it. Threats are quarantined instantly
and appear in the results table.

- IT can turn this on for everyone at install time (the "Real-time
  protection" checkbox) — it then runs in the background on every logon, no
  window needed.
- It also checks **where a downloaded file came from**: if the download URL is
  on a known malware list (updated by the daily feed sync), the file is
  flagged even before the virus database knows the file itself.

### 4. Using the command line (IT / power users)

Open **PowerShell** in the install folder (`C:\Program Files\USBVirusScanner`)
or use the installed `usbscan` command:

```powershell
usbscan drives                 # list plugged-in removable drives
usbscan scan E:\               # scan drive E: now (quarantines threats)
usbscan scan E:\ --no-quarantine   # report only, change nothing
usbscan watch                  # keep running; auto-scan every USB on insert
usbscan monitor                # keep running; real-time scan of new files
usbscan scan --profile quick   # fast scan of common malware locations
usbscan scan --profile full    # every drive (long!)
usbscan feeds                  # refresh the malicious-URL list (URLhaus)
usbscan quarantine             # list quarantined files
usbscan quarantine --restore <ID> --to D:\recovered.bin   # restore one
usbscan update                 # refresh the virus signatures
```

The exit code is **0 = clean**, **1 = threats found**, **2 = bad arguments**,
**3 = finished with errors** (something couldn't be read — don't treat as
clean). Handy for scripts.

*(From source, replace `usbscan` with `python cli.py`.)*

### 5. Keep the virus database fresh

Virus detection is only as good as its signatures. Update them regularly:

```powershell
usbscan update
```

IT can schedule this (e.g. a daily task) so every PC stays current.

### 5b. Three kinds of "update" — don't mix them up

This trips people up, so here it is plainly:

| If you want... | Do this | Rebuild needed? |
|----------------|---------|:---:|
| **Newer virus definitions** (catch the latest malware) | `usbscan update` | No |
| **Newer malicious-URL lists** (for the download-origin check) | `usbscan feeds` | No |
| **New program features** (e.g. the new Delete button, a bug fix) | build a new `setup.exe` and reinstall it | **Yes** |

**Plain-English rule:**

- `usbscan update` = **new virus definitions only.** It does **not** add
  buttons or features. (And it already runs automatically every day.)
- **New features live inside the program file (`.exe`).** The only way to get
  them onto a computer is to install a freshly-built `setup.exe`.

**So: to get a new feature like the Delete button, you must rebuild + reinstall.**
`usbscan update` will not bring it.

**How to update the program (for whoever builds it):**

```powershell
# 1) On the build computer - get the new code and build a new installer:
cd usb-virus-scanner
git pull
powershell -ExecutionPolicy Bypass -File build\build.ps1 -Offline -Version 1.1.0

# 2) On each PC - run the new installer (upgrades in place, keeps your data):
USBVirusScannerSetup.exe /VERYSILENT /NORESTART
```

Your `config.yaml`, the Quarantine folder, and the scheduled tasks all survive
the upgrade.

### 6. Where the results are saved

Everything is logged under `C:\ProgramData\USBVirusScanner\`:

| Folder | What's in it |
|--------|--------------|
| `Reports\` | A readable text report for each scan |
| `Logs\` | Running log + `events.jsonl` (for security teams / SIEM) |
| `Quarantine\` | The quarantined (neutralized) files + a restore index |

### 7. Prove it actually catches viruses (safe test)

Use **EICAR** — the industry-standard *harmless* test file that every antivirus
flags but which does nothing:

```powershell
python tests\make_eicar.py C:\temp\eicartest
usbscan scan C:\temp\eicartest
```

You should see it reported as a threat. That confirms scanning works.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| "ClamAV not found" notice | The virus engine isn't installed. Use the setup file (option A), or run `usbscan update` after installing ClamAV. Heuristic/hash/YARA still work meanwhile. |
| Windows blocks the setup file | Click **More info → Run anyway**. It's an in-house app without a paid signing certificate. |
| USB drive not listed | Click **Refresh**, or make sure the drive is mounted. Try `usbscan drives`. |
| Auto-scan not happening | It only runs if "Auto-scan on insert" was ticked at install. IT can re-run the installer or the scheduled task `USBVirusScannerWatcher`. |
| Scan is slow on an old laptop | It speeds up a lot on the *second* scan (unchanged files are skipped). See "Speed on slow laptops" in the [README](README.md). |
| A file I trust got quarantined | Open **Quarantine…**, select it, **Restore**. Consider adding an exception with IT. |

Still stuck? Open an issue: https://github.com/stickkersz/usb-virus-scanner/issues
