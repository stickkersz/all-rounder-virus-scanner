# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec — builds two standalone onefile executables:
#   USBVirusScanner.exe   GUI, windowed (no console) — for employees
#   usbscan.exe           CLI, console — for IT / the watcher scheduled task
#
# Build:  pyinstaller build\usb_virus_scanner.spec --noconfirm
# Output: dist\USBVirusScanner.exe  and  dist\usbscan.exe
#
# config.yaml and signatures\ are intentionally NOT bundled inside the exe —
# the installer copies them next to the exe so IT can edit rules/blocklist and
# so the onefile temp-extract dir isn't used for mutable data.

import os

block_cipher = None
# SPECPATH is injected by PyInstaller = the folder holding THIS .spec (build\).
# Anchor everything on the project root so the build works no matter what the
# current directory is when pyinstaller is invoked.
PROJECT = os.path.dirname(SPECPATH)
ROOT = PROJECT
ICON = os.path.join(PROJECT, "build", "app.ico")

# Only the deps the code actually imports. Drive detection uses ctypes, not
# WMI/pywin32, so those are intentionally absent — nothing imports them.
hidden = [
    "yara",
    "yaml",
    "rich",
    # watchdog picks its platform observer dynamically — PyInstaller's static
    # analysis misses the Windows backend, so name it explicitly.
    "watchdog",
    "watchdog.observers",
    "watchdog.observers.read_directory_changes",
    "watchdog.observers.winapi",
    "watchdog.observers.polling",
]

gui_a = Analysis(
    [os.path.join(PROJECT, "gui.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[],
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)
gui_pyz = PYZ(gui_a.pure, gui_a.zipped_data, cipher=block_cipher)
gui_exe = EXE(
    gui_pyz,
    gui_a.scripts,
    gui_a.binaries,
    gui_a.zipfiles,
    gui_a.datas,
    [],
    name="USBVirusScanner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,          # windowed — no console popup for employees
    icon=ICON if os.path.exists(ICON) else None,
)

cli_a = Analysis(
    [os.path.join(PROJECT, "cli.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[],
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)
cli_pyz = PYZ(cli_a.pure, cli_a.zipped_data, cipher=block_cipher)
cli_exe = EXE(
    cli_pyz,
    cli_a.scripts,
    cli_a.binaries,
    cli_a.zipfiles,
    cli_a.datas,
    [],
    name="usbscan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,           # console for CLI + watcher task
    icon=ICON if os.path.exists(ICON) else None,
)
