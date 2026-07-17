"""Low-end hardware adaptation: size the scanner to the machine it runs on.

A company fleet includes 2 GB / 2-core laptops and slow eMMC/HDD disks. The
scan pipeline reads whole files into memory (per worker) and fans out across a
thread pool; unchecked, that OOMs or freezes a weak machine while a big Full
scan runs. This module derives safe worker counts and buffer caps from the
actual RAM, and can drop the process to below-normal priority so the PC stays
usable during a scan.

Everything here is best-effort and zero-dependency (ctypes on Windows, os.sysconf
on POSIX). If detection fails it returns None and callers keep their old
defaults — the governor only ever makes the scan *gentler*, never breaks it.
"""

from __future__ import annotations

import ctypes
import os
import sys
from typing import Optional, Tuple

# A machine with less than this much RAM is treated as "low memory": smaller
# per-file buffers and fewer workers. 4 GB is the practical floor for a usable
# Windows box; below it, browser + OS already eat most of RAM.
LOW_MEMORY_BYTES = 4 * 1024 * 1024 * 1024

# Never let the sum of per-worker file buffers exceed this share of *available*
# RAM. Keeps a Full scan from paging the machine to death.
_BUFFER_MEM_FRACTION = 0.25

# Hard floor/ceiling on worker threads. 1 is valid on a single-core / very low
# RAM box; the old code forced a minimum of 2, which on a 2 GB machine could
# double the peak buffer for no throughput gain (disk-bound anyway).
_MIN_WORKERS = 1
_MAX_WORKERS = 8


def system_memory() -> Tuple[Optional[int], Optional[int]]:
    """(total_bytes, available_bytes), best-effort. Either may be None.

    Windows: GlobalMemoryStatusEx (no pywin32 dependency).
    Linux:   os.sysconf page counts.
    macOS/other: total only, or (None, None) — the caller then keeps defaults.
    """
    try:
        if sys.platform == "win32":
            class _MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            m = _MEMORYSTATUSEX()
            m.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):  # type: ignore[attr-defined]
                return int(m.ullTotalPhys), int(m.ullAvailPhys)
            return None, None
        # POSIX
        page = os.sysconf("SC_PAGE_SIZE")
        total = os.sysconf("SC_PHYS_PAGES") * page
        try:
            avail = os.sysconf("SC_AVPHYS_PAGES") * page
        except (ValueError, OSError):
            avail = None            # macOS lacks SC_AVPHYS_PAGES
        return int(total), (int(avail) if avail is not None else None)
    except Exception:
        return None, None


def resolve_workers(configured, in_memory_cap: int,
                    cpu: Optional[int] = None,
                    avail_mem: Optional[int] = None) -> int:
    """Worker-thread count for the heuristic pool.

    An explicit positive int in config always wins (the admin knows the box).
    'auto' scales to cores but is then clamped so the worst-case buffer
    (workers * in_memory_cap) fits inside a fraction of *available* RAM — the
    RAM clamp is what makes a Full scan safe on a 2 GB laptop with 4 logical
    cores.
    """
    if isinstance(configured, int) and configured > 0:
        return configured
    cpu = cpu or os.cpu_count() or 2
    n = max(_MIN_WORKERS, min(_MAX_WORKERS, cpu))
    if avail_mem and in_memory_cap > 0:
        by_ram = int(avail_mem * _BUFFER_MEM_FRACTION // in_memory_cap)
        n = max(_MIN_WORKERS, min(n, by_ram))
    return n


def resolve_memory_cap(default_cap: int,
                       total_mem: Optional[int] = None) -> int:
    """Per-file in-memory read cap. Shrinks on low-RAM machines.

    Files above the cap are STREAMED through the hash/YARA/entropy checks
    instead of buffered, so shrinking it never drops a file from the scan —
    it only trades a little speed for a lot less peak memory. That makes it a
    100%% safe knob to lower automatically.
    """
    if total_mem is not None and total_mem < LOW_MEMORY_BYTES:
        return min(default_cap, 16 * 1024 * 1024)
    return default_cap


def set_background_priority() -> bool:
    """Drop the current process to below-normal priority so a scan doesn't
    make a weak machine unusable. Returns True if applied.

    Windows: SetPriorityClass(BELOW_NORMAL_PRIORITY_CLASS). One notch down —
    foreground apps stay ahead, but the scan yields CPU instead of pinning it.
    POSIX: os.setpriority to an ABSOLUTE nice of 10 — idempotent, so calling
    this once per engine (CLI, GUI, monitor) can't drift the process toward
    max niceness the way a cumulative os.nice(+10) would. Best-effort; a
    failure is swallowed (never abort a scan because we couldn't be polite).
    """
    try:
        if sys.platform == "win32":
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
            h = ctypes.windll.kernel32.GetCurrentProcess()  # type: ignore[attr-defined]
            return bool(ctypes.windll.kernel32.SetPriorityClass(  # type: ignore[attr-defined]
                h, BELOW_NORMAL_PRIORITY_CLASS))
        os.setpriority(os.PRIO_PROCESS, 0, 10)      # absolute, not cumulative
        return True
    except Exception:
        return False
