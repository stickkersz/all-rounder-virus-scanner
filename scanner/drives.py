"""Drive enumeration for every disk class, not just removable media.

This generalizes the old USB-only detection: the same Win32 call that told us
"is this a USB stick" also reports fixed, network and optical drives, so one
enumerator serves the drive list, the scan profiles and the insert watcher.

Windows uses GetDriveTypeW via ctypes (no pywin32/WMI dependency, keeping the
frozen exe small). POSIX is a best-effort fallback so the tool stays testable
off Windows.
"""

from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import dataclass
from typing import List

# Win32 DRIVE_* constants (winbase.h).
DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6

# Our own kind labels (stable across platforms; used in config + CLI).
REMOVABLE = "removable"
FIXED = "fixed"
NETWORK = "network"
CDROM = "cdrom"

_WIN_KINDS = {
    DRIVE_REMOVABLE: REMOVABLE,
    DRIVE_FIXED: FIXED,
    DRIVE_REMOTE: NETWORK,
    DRIVE_CDROM: CDROM,
}

# Mount bases that hold user-mounted volumes on macOS/Linux. A volume under one
# of these is treated as removable; the root filesystem is treated as fixed.
_POSIX_REMOVABLE_BASES = ("/Volumes", "/media", "/mnt", "/run/media")


@dataclass(frozen=True)
class Drive:
    root: str
    kind: str

    def __str__(self) -> str:
        return f"{self.root}  [{self.kind}]"


def _windows_drives() -> List[Drive]:
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    bitmask = kernel32.GetLogicalDrives()
    out: List[Drive] = []
    for i in range(26):
        if not (bitmask >> i) & 1:
            continue
        root = f"{chr(ord('A') + i)}:\\"
        kind = _WIN_KINDS.get(kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)))
        if kind:
            out.append(Drive(root, kind))
    return out


def _same_volume_as_root(path: str) -> bool:
    """True if `path` lives on the same device as '/'.

    macOS exposes the boot volume as /Volumes/<name> as well as '/'. Without
    this check a Full scan would walk the whole system disk twice.
    """
    try:
        return os.stat(path).st_dev == os.stat("/").st_dev
    except OSError:
        return False


def _posix_drives() -> List[Drive]:
    out: List[Drive] = [Drive("/", FIXED)]
    user = os.environ.get("USER", "")
    user_bases = [f"/media/{user}", f"/run/media/{user}"] if user else []
    bases = list(_POSIX_REMOVABLE_BASES) + user_bases
    # Pre-seed with every base so listing /media doesn't ALSO emit
    # /media/<user> itself as a phantom "drive" (it's a container, and its
    # children are enumerated via their own base entry).
    seen = {"/"} | set(bases)
    # The boot-volume alias (/Volumes/<name> == '/') is a macOS artifact. On
    # Linux the same st_dev test would also drop bind mounts and loopback dirs
    # under /media//mnt that earlier releases scanned — a silent coverage
    # regression — so the filter is darwin-only.
    dedupe_boot = sys.platform == "darwin"
    for base in bases:
        if not os.path.isdir(base):
            continue
        try:
            names = os.listdir(base)
        except OSError:
            continue
        for name in names:
            p = os.path.join(base, name)
            if p in seen or not os.path.isdir(p):
                continue
            seen.add(p)
            if dedupe_boot and _same_volume_as_root(p):
                continue          # the boot volume, already listed as "/"
            out.append(Drive(p, REMOVABLE))
    return out


def list_drives(kinds: tuple = (REMOVABLE,)) -> List[Drive]:
    """Every attached drive whose kind is in `kinds`.

    Optical drives are enumerable but excluded by default everywhere — they are
    read-only and spinning one up on every scan is slow for no benefit.
    """
    all_drives = _windows_drives() if sys.platform == "win32" else _posix_drives()
    return [d for d in all_drives if d.kind in kinds]


def list_removable(include_fixed: bool = False) -> List[str]:
    """Roots of removable (and optionally fixed) drives.

    Kept as the drive-insert watcher's entry point and for the existing USB-only
    flow, so generalizing the enumerator didn't change that behavior.
    """
    kinds = (REMOVABLE, FIXED) if include_fixed else (REMOVABLE,)
    return [d.root for d in list_drives(kinds)]


def scannable_roots(include_network: bool = False) -> List[str]:
    """Roots a Full scan should cover: every fixed and removable drive.

    Network drives are opt-in (`include_network`) — walking a mapped share can
    be extremely slow and may scan another machine's files, so it is never the
    default.
    """
    kinds = [FIXED, REMOVABLE]
    if include_network:
        kinds.append(NETWORK)
    return [d.root for d in list_drives(tuple(kinds))]
