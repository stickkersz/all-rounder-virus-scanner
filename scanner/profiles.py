"""Scan profiles: Quick, Full, Custom.

A profile resolves to a list of target roots; the engine scans each one. Roots
are de-duplicated and de-nested (if C:\\ is a target, C:\\Users\\x\\Downloads is
dropped) so no file is scanned twice.
"""

from __future__ import annotations

import os
import sys
import tempfile
from typing import Iterable, List, Optional

from .drives import scannable_roots
from .paths import is_under, norm_for_match

QUICK = "quick"
FULL = "full"
CUSTOM = "custom"
PROFILES = (QUICK, FULL, CUSTOM)

# Downloads has no environment variable; its authoritative location is this
# known-folder GUID in the registry (documented KNOWNFOLDERID).
_DOWNLOADS_GUID = "{374DE290-123F-4565-9164-39C4925E467B}"


def _win_shell_folder(value_name: str, fallback: str) -> str:
    """Resolve a user shell folder from the registry (Windows).

    Corporate fleets commonly redirect Desktop/Downloads via OneDrive Known
    Folder Move — the real Desktop is ~\\OneDrive\\Desktop and ~\\Desktop does
    not exist. Hardcoding the home-relative path would make the Quick profile
    silently skip the user's actual Desktop on exactly those machines.
    """
    try:
        import winreg  # Windows-only; ImportError elsewhere
        key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
            raw, _typ = winreg.QueryValueEx(k, value_name)
        resolved = os.path.expandvars(raw)
        return resolved if resolved else fallback
    except (ImportError, OSError):
        return fallback


def _windows_quick_locations() -> List[str]:
    """Where malware actually lands and persists on Windows.

    Deliberately NOT all of %LOCALAPPDATA%: browser/app caches there run to tens
    of GB and would make a "Quick" scan slower than a Full one. We take
    AppData\\Local\\Temp (the real drop target) and Roaming (the common
    persistence spot) instead. A Full scan still covers everything.
    """
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
    local = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
    public = os.environ.get("PUBLIC", r"C:\Users\Public")
    programdata = os.environ.get("ProgramData", r"C:\ProgramData")
    return [
        _win_shell_folder(_DOWNLOADS_GUID, os.path.join(home, "Downloads")),
        _win_shell_folder("Desktop", os.path.join(home, "Desktop")),
        os.path.join(public, "Downloads"),
        os.path.join(local, "Temp"),
        tempfile.gettempdir(),
        appdata,
        # Startup folders — per-user and all-users autorun persistence.
        os.path.join(appdata, "Microsoft", "Windows", "Start Menu",
                     "Programs", "Startup"),
        os.path.join(programdata, "Microsoft", "Windows", "Start Menu",
                     "Programs", "StartUp"),
    ]


def _posix_quick_locations() -> List[str]:
    """POSIX equivalents so Quick is testable/usable off Windows."""
    home = os.path.expanduser("~")
    out = [
        os.path.join(home, "Downloads"),
        os.path.join(home, "Desktop"),
        tempfile.gettempdir(),
    ]
    if sys.platform == "darwin":
        # LaunchAgents = the mac persistence equivalent of a Startup folder.
        out += [
            os.path.join(home, "Library", "LaunchAgents"),
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
        ]
    else:
        out += [os.path.join(home, ".config", "autostart"), "/etc/cron.d"]
    return out


def quick_locations() -> List[str]:
    raw = (_windows_quick_locations() if sys.platform == "win32"
           else _posix_quick_locations())
    return [p for p in raw if os.path.isdir(p)]


def running_as_service_account() -> bool:
    """True when this process is the SYSTEM account (a machine-wide service).

    Detected by where the account's profile points: SYSTEM's home is
    ...\\config\\systemprofile, never a real user's folder.
    """
    if sys.platform != "win32":
        return False
    return "config\\systemprofile" in os.path.expanduser("~").lower()


def all_users_quick_locations(users_root: Optional[str] = None) -> List[str]:
    """Quick locations for EVERY user profile on the machine.

    A machine-wide service can't use the per-user paths: %USERPROFILE% and the
    HKCU shell folders resolve to the *service account's* profile, so a monitor
    running as SYSTEM would watch systemprofile\\Temp while every employee's
    real Downloads went unwatched — protection that looks healthy and covers
    nobody.

    `users_root` is injectable so the profile-skipping logic is testable off
    Windows.
    """
    if users_root is None:
        users_root = os.path.join(os.environ.get("SystemDrive", "C:") + os.sep,
                                  "Users")
    if not os.path.isdir(users_root):
        return []
    # Template/service profiles hold no user downloads. "Public" is kept: it
    # has a real, shared Downloads folder.
    skip = {"default", "default user", "all users", "defaultaccount"}
    out: List[str] = []
    try:
        names = os.listdir(users_root)
    except OSError:
        return []
    for name in names:
        if name.lower() in skip:
            continue
        home = os.path.join(users_root, name)
        if not os.path.isdir(home):
            continue
        out += [
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "AppData", "Local", "Temp"),
            os.path.join(home, "AppData", "Roaming", "Microsoft", "Windows",
                         "Start Menu", "Programs", "Startup"),
        ]
    return [p for p in out if os.path.isdir(p)]


def monitor_default_roots() -> List[str]:
    """Default watch roots for the real-time monitor.

    Running as SYSTEM (the installer's logon task) -> every user's folders.
    Running as a person (GUI, `usbscan monitor` in a console) -> that person's.
    """
    if running_as_service_account():
        return dedupe_roots(all_users_quick_locations())
    return dedupe_roots(quick_locations())


def dedupe_roots(paths: Iterable[str]) -> List[str]:
    """Drop duplicates and any path already covered by a parent in the list.

    Order-preserving: the quick profile's curated order (likeliest infection
    sites first) and the user's own --profile custom order survive dedupe.
    """
    originals = list(paths)
    norms = [norm_for_match(p) for p in originals]
    kept: List[str] = []
    kept_norms: List[str] = []
    for n, original in zip(norms, originals):
        if any(is_under(n, k) for k in kept_norms):
            continue          # duplicate, or covered by an already-kept parent
        if any(n != m and is_under(n, m) for m in norms):
            continue          # covered by a parent appearing later in the list
        kept.append(original)
        kept_norms.append(n)
    return kept


def resolve_targets(profile: str, custom: Iterable[str] | None = None,
                    include_network: bool = False) -> List[str]:
    """Target roots for a profile.

    quick  -> common malware drop/persistence locations
    full   -> every fixed + removable drive (network only if opted in)
    custom -> exactly the paths given
    """
    profile = (profile or "").lower()
    if profile == QUICK:
        targets = quick_locations()
    elif profile == FULL:
        targets = scannable_roots(include_network=include_network)
    elif profile == CUSTOM:
        targets = [p for p in (custom or [])]
        if not targets:
            raise ValueError("custom profile requires at least one path")
    else:
        raise ValueError(f"unknown profile {profile!r}; expected one of "
                         f"{', '.join(PROFILES)}")
    return dedupe_roots(targets)
