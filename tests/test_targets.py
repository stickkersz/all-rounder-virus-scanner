"""Drive enumeration, scan profiles, and exclusion matching.

Drive enumeration is mocked throughout — tests must never depend on real USB
hardware or on which disks the CI box happens to have (spec §7).
"""

import os

import pytest

from scanner import drives, profiles
from scanner.drives import FIXED, NETWORK, REMOVABLE, Drive
from scanner.exclusions import ExclusionMatcher
from scanner.profiles import CUSTOM, FULL, QUICK, dedupe_roots, resolve_targets


# ---- exclusions ---------------------------------------------------------
def test_no_patterns_excludes_nothing():
    m = ExclusionMatcher([])
    assert not m.active
    assert not m.excludes("/anything/at/all.exe")


def test_none_patterns_excludes_nothing():
    assert not ExclusionMatcher(None).excludes("/x")


def test_absolute_prefix_excludes_subtree(tmp_path):
    vms = tmp_path / "VMs"
    m = ExclusionMatcher([str(vms)])
    assert m.excludes(str(vms))                      # the dir itself
    assert m.excludes(str(vms / "big.vmdk"))         # a child
    assert m.excludes(str(vms / "deep" / "x.bin"))   # any depth
    assert not m.excludes(str(tmp_path / "VMsNotReally" / "x"))  # not a prefix match


def test_bare_name_excludes_at_any_depth(tmp_path):
    m = ExclusionMatcher(["node_modules"])
    assert m.excludes(str(tmp_path / "node_modules"))
    assert m.excludes(str(tmp_path / "app" / "deep" / "node_modules"))
    assert not m.excludes(str(tmp_path / "src" / "main.py"))


def test_glob_matches_basename(tmp_path):
    m = ExclusionMatcher(["*.iso"])
    assert m.excludes(str(tmp_path / "ubuntu.iso"))
    assert not m.excludes(str(tmp_path / "ubuntu.exe"))


def test_glob_spans_directories(tmp_path):
    m = ExclusionMatcher(["*/Chrome/*/Cache"])
    assert m.excludes(str(tmp_path / "x" / "Chrome" / "Default" / "Cache"))


def test_exclusion_ignores_blank_patterns():
    assert not ExclusionMatcher(["", "   "]).active


# ---- drives -------------------------------------------------------------
def test_list_drives_filters_by_kind(monkeypatch):
    fake = [Drive("C:\\", FIXED), Drive("E:\\", REMOVABLE), Drive("Z:\\", NETWORK)]
    monkeypatch.setattr(drives, "_windows_drives", lambda: fake)
    monkeypatch.setattr(drives, "_posix_drives", lambda: fake)
    assert [d.root for d in drives.list_drives((REMOVABLE,))] == ["E:\\"]
    assert len(drives.list_drives((FIXED, REMOVABLE))) == 2


def test_list_removable_include_fixed(monkeypatch):
    fake = [Drive("C:\\", FIXED), Drive("E:\\", REMOVABLE)]
    monkeypatch.setattr(drives, "_windows_drives", lambda: fake)
    monkeypatch.setattr(drives, "_posix_drives", lambda: fake)
    assert drives.list_removable() == ["E:\\"]
    assert sorted(drives.list_removable(include_fixed=True)) == ["C:\\", "E:\\"]


def test_scannable_roots_excludes_network_unless_opted_in(monkeypatch):
    fake = [Drive("C:\\", FIXED), Drive("E:\\", REMOVABLE), Drive("Z:\\", NETWORK)]
    monkeypatch.setattr(drives, "_windows_drives", lambda: fake)
    monkeypatch.setattr(drives, "_posix_drives", lambda: fake)
    assert "Z:\\" not in drives.scannable_roots()
    assert "Z:\\" in drives.scannable_roots(include_network=True)


def test_cdrom_never_in_scannable_roots(monkeypatch):
    fake = [Drive("C:\\", FIXED), Drive("D:\\", drives.CDROM)]
    monkeypatch.setattr(drives, "_windows_drives", lambda: fake)
    monkeypatch.setattr(drives, "_posix_drives", lambda: fake)
    assert drives.scannable_roots(include_network=True) == ["C:\\"]


def test_drive_str_shows_kind():
    assert "removable" in str(Drive("E:\\", REMOVABLE))


# ---- profiles -----------------------------------------------------------
def test_dedupe_drops_nested_paths(tmp_path):
    parent = str(tmp_path)
    child = str(tmp_path / "sub" / "deep")
    assert dedupe_roots([child, parent]) == [parent]


def test_dedupe_drops_duplicates(tmp_path):
    p = str(tmp_path)
    assert dedupe_roots([p, p]) == [p]


def test_dedupe_keeps_siblings(tmp_path):
    a, b = str(tmp_path / "a"), str(tmp_path / "b")
    assert len(dedupe_roots([a, b])) == 2


def test_dedupe_does_not_treat_prefix_string_as_parent(tmp_path):
    """'/x/VMs' must not swallow '/x/VMsOther' — string prefix != path parent."""
    a, b = str(tmp_path / "VMs"), str(tmp_path / "VMsOther")
    assert len(dedupe_roots([a, b])) == 2


def test_custom_profile_uses_given_paths(tmp_path):
    p = str(tmp_path)
    assert resolve_targets(CUSTOM, custom=[p]) == [p]


def test_custom_profile_without_paths_raises():
    with pytest.raises(ValueError, match="custom profile requires"):
        resolve_targets(CUSTOM, custom=[])


def test_unknown_profile_raises():
    with pytest.raises(ValueError, match="unknown profile"):
        resolve_targets("turbo")


def test_full_profile_uses_every_disk(monkeypatch):
    monkeypatch.setattr(profiles, "scannable_roots",
                        lambda include_network=False: ["C:\\", "E:\\"])
    assert resolve_targets(FULL) == ["C:\\", "E:\\"]


def test_full_profile_passes_network_flag(monkeypatch):
    seen = {}

    def fake(include_network=False):
        seen["network"] = include_network
        return ["C:\\"]

    monkeypatch.setattr(profiles, "scannable_roots", fake)
    resolve_targets(FULL, include_network=True)
    assert seen["network"] is True


def test_quick_profile_returns_only_existing_dirs(monkeypatch, tmp_path):
    real = tmp_path / "Downloads"
    real.mkdir()
    monkeypatch.setattr(profiles, "_posix_quick_locations",
                        lambda: [str(real), str(tmp_path / "ghost")])
    monkeypatch.setattr(profiles, "_windows_quick_locations",
                        lambda: [str(real), str(tmp_path / "ghost")])
    assert resolve_targets(QUICK) == [str(real)]


def test_quick_locations_all_exist():
    """Whatever this box has, quick never returns a path that isn't there."""
    assert all(os.path.isdir(p) for p in profiles.quick_locations())


# ---- for_explicit_root (explicit scan root beats its own exclusion) ------
def test_explicit_root_drops_covering_prefix_rule(tmp_path):
    vms = str(tmp_path / "VMs")
    m = ExclusionMatcher([vms]).for_explicit_root(vms)
    assert not m.active
    assert not m.excludes(str(tmp_path / "VMs" / "disk.vmdk"))


def test_explicit_root_keeps_unrelated_rules(tmp_path):
    """Scanning an excluded root must still honor exclusions deeper inside it."""
    vms = str(tmp_path / "VMs")
    m = ExclusionMatcher([vms, "node_modules"]).for_explicit_root(vms)
    assert m.active
    assert m.excludes(str(tmp_path / "VMs" / "app" / "node_modules"))
    assert not m.excludes(str(tmp_path / "VMs" / "disk.vmdk"))


def test_explicit_root_leaves_original_untouched(tmp_path):
    vms = str(tmp_path / "VMs")
    original = ExclusionMatcher([vms])
    original.for_explicit_root(vms)
    assert original.excludes(vms)      # copy, not mutation


def test_explicit_root_on_unrelated_path_keeps_everything(tmp_path):
    m = ExclusionMatcher(["node_modules"]).for_explicit_root(str(tmp_path / "usb"))
    assert m.excludes(str(tmp_path / "usb" / "node_modules"))


def test_explicit_root_keeps_name_rule_matching_root(tmp_path):
    """Scanning ...\node_modules explicitly must NOT drop the name rule:
    nested node_modules trees inside it still prune (review finding)."""
    root = str(tmp_path / "proj" / "node_modules")
    m = ExclusionMatcher(["node_modules"]).for_explicit_root(root)
    assert m.active
    assert m.excludes(str(tmp_path / "proj" / "node_modules" / "pkg" / "node_modules"))


def test_posix_boot_volume_not_listed_twice(monkeypatch, tmp_path):
    """macOS shows the boot disk as both '/' and /Volumes/<name>; a Full scan
    must not walk the system disk twice."""
    monkeypatch.setattr(drives, "_POSIX_REMOVABLE_BASES", (str(tmp_path),))
    monkeypatch.setattr(drives.sys, "platform", "darwin")
    (tmp_path / "Macintosh HD").mkdir()
    (tmp_path / "USB STICK").mkdir()
    monkeypatch.setattr(drives, "_same_volume_as_root",
                        lambda p: p.endswith("Macintosh HD"))
    roots = [d.root for d in drives._posix_drives()]
    assert "/" in roots
    assert not any("Macintosh HD" in r for r in roots)
    assert any("USB STICK" in r for r in roots)


def test_linux_bind_mount_on_root_device_still_listed(monkeypatch, tmp_path):
    """The boot-volume st_dev filter is macOS-only: on Linux a bind mount on
    the root device must keep appearing (v1 behavior, review finding)."""
    monkeypatch.setattr(drives, "_POSIX_REMOVABLE_BASES", (str(tmp_path),))
    monkeypatch.setattr(drives.sys, "platform", "linux")
    (tmp_path / "bindmount").mkdir()
    monkeypatch.setattr(drives, "_same_volume_as_root", lambda p: True)
    roots = [d.root for d in drives._posix_drives()]
    assert any("bindmount" in r for r in roots)


def test_media_user_dir_not_a_phantom_drive(monkeypatch, tmp_path):
    """A base that appears as another base's child (/media vs /media/<user>)
    is a container, not a drive: only its children are drives."""
    media = tmp_path / "media"
    (media / "bob" / "STICK").mkdir(parents=True)
    monkeypatch.setattr(drives, "_POSIX_REMOVABLE_BASES",
                        (str(media), str(media / "bob")))
    monkeypatch.setattr(drives.sys, "platform", "linux")
    roots = [d.root for d in drives._posix_drives()]
    assert not any(r.endswith("/bob") for r in roots)
    assert any(r.endswith("/STICK") for r in roots)


# ---- pattern classification fixes (review findings) ----------------------
def test_driveless_absolute_pattern_matches_any_drive():
    r"""'\Windows\WinSxS' (no drive letter) must match c:/windows/winsxs —
    before the fix it silently no-opped on Windows while working on macOS."""
    m = ExclusionMatcher([r"\Windows\WinSxS"])
    assert m.excludes(r"C:\Windows\WinSxS\x86_pkg\file.dll") or \
        not os.path.normcase("A") == "a"  # only asserts on case-folding (win-like) platforms


def test_driveless_pattern_matching_is_platform_independent(monkeypatch):
    """Simulate the Windows shape directly: normalized path 'c:/windows/winsxs/f'
    against normalized driveless pattern '/windows/winsxs'."""
    from scanner.exclusions import _matches, _PREFIX
    assert _matches(_PREFIX, "/windows/winsxs", "c:/windows/winsxs/f.dll", "f.dll")
    assert not _matches(_PREFIX, "/windows/winsxs", "c:/users/x/winsxs", "winsxs")


def test_bracket_is_literal_not_glob(tmp_path):
    """'[' is legal in Windows filenames; 'D:\\VMs [old]' must stay a prefix
    rule (fnmatch would treat [old] as a character class and never match)."""
    vms = str(tmp_path / "VMs [old]")
    m = ExclusionMatcher([vms])
    assert m.excludes(os.path.join(vms, "disk.vmdk"))


def test_dedupe_preserves_input_order(tmp_path):
    """Quick profile curates likeliest-infection-site-first ordering; dedupe
    must not scramble it (old shortest-first sort did)."""
    downloads = str(tmp_path / "user" / "long" / "Downloads")
    appdata = str(tmp_path / "A")
    assert dedupe_roots([downloads, appdata]) == [downloads, appdata]


def test_win_shell_folder_falls_back_off_windows(tmp_path):
    from scanner.profiles import _win_shell_folder
    fallback = str(tmp_path / "Desktop")
    assert _win_shell_folder("Desktop", fallback) == fallback
