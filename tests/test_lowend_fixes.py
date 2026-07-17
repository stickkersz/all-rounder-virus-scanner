"""Regression tests for the low-end hardening pass:
- trusted-path prefix must respect a path boundary (no over-trust)
- XOR neutralize/restore stays byte-exact after the translate() speedup
"""

import os

from scanner.heuristics import HeuristicEngine
from scanner.quarantine import _NEUTRALIZE_KEY, _xor_file


def _heur(tmp_path, trusted):
    return HeuristicEngine({"enabled": True, "trust_signed": False,
                            "trusted_paths": trusted}, base_dir=str(tmp_path))


def test_trusted_path_requires_boundary(tmp_path):
    trusted = tmp_path / "safe"
    trusted.mkdir()
    h = _heur(tmp_path, [str(trusted)])

    inside = trusted / "sub" / "packed.exe"
    inside.parent.mkdir(parents=True)
    inside.write_bytes(b"MZ")
    assert h._is_soft_trusted(str(inside)) is True

    # A sibling dir that merely shares the prefix string must NOT be trusted:
    # "<...>/safe-evil" starts with "<...>/safe" but is a different directory.
    evil = tmp_path / "safe-evil" / "payload.exe"
    evil.parent.mkdir(parents=True)
    evil.write_bytes(b"MZ")
    assert h._is_soft_trusted(str(evil)) is False


def test_trusted_path_exact_dir_is_trusted(tmp_path):
    trusted = tmp_path / "safe"
    trusted.mkdir()
    h = _heur(tmp_path, [str(trusted)])
    assert h._is_soft_trusted(str(trusted)) is True


def test_xor_roundtrip_is_byte_exact(tmp_path):
    src = tmp_path / "payload.bin"
    # Span > 1 MB read block and include every byte value so the translate
    # table is exercised across the whole range.
    original = bytes(range(256)) * 5000
    src.write_bytes(original)

    neutralized = tmp_path / "q.quarantine"
    _xor_file(str(src), str(neutralized))
    blob = neutralized.read_bytes()
    assert blob == bytes(b ^ _NEUTRALIZE_KEY for b in original)
    assert blob != original                         # actually obfuscated

    # XOR is symmetric: the same op restores the exact original bytes.
    restored = tmp_path / "restored.bin"
    _xor_file(str(neutralized), str(restored))
    assert restored.read_bytes() == original
