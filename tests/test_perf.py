"""Low-end resource governor: RAM-aware workers, buffer cap, priority."""

from scanner import perf


CAP = 64 * 1024 * 1024        # 64 MB, the default per-file in-memory cap
GB = 1024 * 1024 * 1024


def test_explicit_worker_count_always_wins():
    # An admin-set positive integer is honored regardless of RAM.
    assert perf.resolve_workers(6, CAP, cpu=2, avail_mem=1 * GB) == 6
    assert perf.resolve_workers(1, CAP, cpu=16, avail_mem=64 * GB) == 1


def test_auto_scales_to_cores_when_ram_is_ample():
    # 32 GB free -> RAM never binds; clamps to min(8, cpu).
    assert perf.resolve_workers("auto", CAP, cpu=4, avail_mem=32 * GB) == 4
    assert perf.resolve_workers("auto", CAP, cpu=16, avail_mem=32 * GB) == 8


def test_low_ram_clamps_workers_below_core_count():
    # 2 GB free, 64 MB buffers -> 25% of 2 GB = 512 MB / 64 MB = 8, but a
    # tighter budget must bite. 512 MB free with 8 cores:
    n = perf.resolve_workers("auto", CAP, cpu=8, avail_mem=512 * 1024 * 1024)
    # 25% of 512 MB = 128 MB -> 2 buffers of 64 MB.
    assert n == 2


def test_worker_floor_is_one_not_two():
    # A tiny machine must be allowed a single worker (old code forced >= 2,
    # doubling peak memory for no throughput on a disk-bound scan).
    n = perf.resolve_workers("auto", CAP, cpu=1, avail_mem=256 * 1024 * 1024)
    assert n == 1


def test_missing_memory_info_keeps_cpu_scaling():
    # Detection failed (avail_mem=None) -> fall back to pure CPU scaling.
    assert perf.resolve_workers("auto", CAP, cpu=4, avail_mem=None) == 4


def test_memory_cap_shrinks_on_low_ram():
    assert perf.resolve_memory_cap(CAP, total_mem=2 * GB) == 16 * 1024 * 1024
    assert perf.resolve_memory_cap(CAP, total_mem=8 * GB) == CAP
    assert perf.resolve_memory_cap(CAP, total_mem=None) == CAP     # unknown -> keep


def test_system_memory_is_best_effort():
    total, avail = perf.system_memory()
    # Either concrete positive numbers, or None when detection isn't available.
    assert total is None or total > 0
    assert avail is None or avail > 0


def test_set_background_priority_never_raises():
    # Best-effort: returns a bool, must not blow up a scan on any platform.
    assert isinstance(perf.set_background_priority(), bool)
