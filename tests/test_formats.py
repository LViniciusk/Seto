"""Tests for signature-driven container identification."""

from __future__ import annotations

import pytest

from seto.formats import PROBE_SIZE, UNKNOWN, identify, identify_file

from conftest import build_elf32


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"\x7fELF" + b"\x00" * 60, "ELF"),
        (b"~PSP" + b"\x00" * 60, "PSP"),
        (b"~SCE" + b"\x00" * 60, "SCE"),
        (b"\x00PBP" + b"\x00" * 60, "PBP"),
        (b"\x00PSF" + b"\x00" * 60, "PSF"),
        (b"\x00" * 0x8001 + b"CD001" + b"\x00" * 10, "ISO9660"),
    ],
    ids=["elf", "psp", "sce", "pbp", "psf", "iso9660"],
)
def test_identify_known_signatures(payload: bytes, expected: str) -> None:
    assert identify(payload).fmt == expected


def test_identify_unknown_payload() -> None:
    assert identify(b"not a container at all") is UNKNOWN


def test_identify_iso_ignores_short_prefix() -> None:
    assert identify(b"\x00" * PROBE_SIZE).fmt == "unknown"


def test_identify_file_reads_only_the_probe(tmp_path) -> None:
    path = tmp_path / "module.prx"
    path.write_bytes(build_elf32(sections=[{"name": ".text", "type": 1, "data": b"\x00" * 16}]))
    assert identify_file(path).fmt == "ELF"


def test_identify_file_missing_signature(tmp_path) -> None:
    path = tmp_path / "random.bin"
    path.write_bytes(b"\xde\xad\xbe\xef" * 4)
    assert identify_file(path).fmt == "unknown"
