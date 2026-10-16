"""Tests for the deterministic inventory manifest and report."""

from __future__ import annotations

import json

import pytest

from seto import inventory
from seto.hashing import fingerprint_file
from seto.toolchain import Settings

from conftest import (
    PSF_TYPE_STR,
    PSF_TYPE_VAL,
    SHF_ALLOC,
    SHF_EXECINSTR,
    build_elf32,
    build_sfo,
    jr,
    word,
)


def _module_bytes() -> bytes:
    code = word(0x00000000) + word(jr(31))
    return build_elf32(
        sections=[
            {
                "name": ".text",
                "type": 1,
                "flags": SHF_ALLOC | SHF_EXECINSTR,
                "addr": 0,
                "size": len(code),
                "data": code,
            },
            {
                "name": ".comment",
                "type": 1,
                "flags": 0,
                "data": b"MW MIPS C Compiler (2.4.1.01)\x00",
            },
        ]
    )


@pytest.fixture
def extracted(tmp_path):
    root = tmp_path / "root"
    (root / "gmodule").mkdir(parents=True)
    (root / "PARAM.SFO").write_bytes(
        build_sfo(
            [
                ("DISC_ID", PSF_TYPE_STR, b"ULUS10136\x00"),
                ("BOOTABLE", PSF_TYPE_VAL, 1),
            ]
        )
    )
    (root / "gmodule" / "libtest.prx").write_bytes(_module_bytes())
    (root / "readme.txt").write_bytes(b"notes\n")
    return root


# ------------------------------------------------------------------- iteration


def test_iter_files_is_sorted_and_recursive(extracted) -> None:
    files = inventory.iter_files(extracted)
    names = [path.name for path in files]
    assert names == sorted(names, key=str.lower)
    assert {"PARAM.SFO", "libtest.prx", "readme.txt"} == set(names)


def test_iter_files_rejects_a_missing_root(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        inventory.iter_files(tmp_path / "nope")


# -------------------------------------------------------------------- recording


def test_record_file_counts_and_identifies(extracted) -> None:
    record = inventory.record_file(extracted, extracted / "gmodule" / "libtest.prx")
    raw = (extracted / "gmodule" / "libtest.prx").read_bytes()
    assert record.relpath == "gmodule/libtest.prx"
    assert record.size == len(raw)
    assert record.sha256 == fingerprint_file(extracted / "gmodule" / "libtest.prx").sha256
    assert record.fmt == "ELF"
    assert record.detail.startswith("ELF32")


def test_record_file_marks_non_elf_detail(extracted) -> None:
    record = inventory.record_file(extracted, extracted / "readme.txt")
    assert record.fmt == "unknown"
    assert record.detail == "no known signature"


# --------------------------------------------------------------------- module


def test_analyze_module_discovers_functions(extracted) -> None:
    module = inventory.analyze_module(extracted, extracted / "gmodule" / "libtest.prx")
    assert module.fmt == "ELF"
    assert module.machine == 8
    assert module.comment == "MW MIPS C Compiler (2.4.1.01)"
    assert len(module.functions) == 1
    function = module.functions[0]
    assert function["name"] == "func_00000000"
    assert function["section"] == ".text"
    assert function["size"] == 8


def test_read_parameter_sfo(tmp_path, extracted) -> None:
    document = inventory.read_parameter_sfo(extracted)
    assert document is not None
    entries = {entry["key"]: entry["value"] for entry in document["entries"]}
    assert entries["DISC_ID"] == "ULUS10136"
    assert entries["BOOTABLE"] == "1"
    assert inventory.read_parameter_sfo(tmp_path) is None


# -------------------------------------------------------------------- baseline


def test_baseline_from_settings_normalises_fields() -> None:
    settings = Settings(
        data={
            "baseline": {
                "iso": "TF1.iso",
                "disc_id": "ULUS10136",
                "disc_version": "1.03",
                "size": 123,
                "sha256": "abc",
            }
        }
    )
    baseline = inventory.baseline_from_settings(settings)
    assert baseline["disc_id"] == "ULUS10136"
    assert baseline["disc_version"] == "1.03"
    assert baseline["expected_size"] == 123
    assert baseline["expected_sha256"] == "ABC"


# ------------------------------------------------------------------- manifest


def test_build_manifest_without_an_iso(extracted, tmp_path) -> None:
    manifest = inventory.build_manifest(
        iso_path=tmp_path / "missing.iso",
        extracted_root=extracted,
        verify_iso=False,
    )
    assert manifest["schema"] == inventory.INVENTORY_SCHEMA
    baseline = manifest["baseline"]
    assert baseline["present"] is False
    assert baseline["verified"] is None
    assert manifest["summary"] == {"file_count": 3, "module_count": 1, "function_count": 1}
    assert manifest["module_errors"] == []
    assert manifest["parameter_sfo"]["version"] == 0x00000101


def test_build_manifest_verifies_a_matching_iso(extracted, tmp_path) -> None:
    iso = tmp_path / "TF1.iso"
    iso.write_bytes(b"synthetic baseline payload")
    fingerprint = fingerprint_file(iso)
    settings = Settings(
        data={
            "baseline": {
                "iso": str(iso),
                "size": fingerprint.size,
                "sha256": fingerprint.sha256,
                "disc_id": "ULUS10136",
            }
        }
    )
    manifest = inventory.build_manifest(
        iso_path=iso, extracted_root=extracted, settings=settings, verify_iso=True
    )
    assert manifest["baseline"]["verified"] is True
    assert manifest["baseline"]["actual_sha256"] == fingerprint.sha256.upper()
    assert manifest["baseline"]["issues"] == []


def test_build_manifest_reports_a_mismatching_iso(extracted, tmp_path) -> None:
    iso = tmp_path / "TF1.iso"
    iso.write_bytes(b"synthetic baseline payload")
    settings = Settings(
        data={"baseline": {"iso": str(iso), "size": 1, "sha256": "00" * 32}}
    )
    manifest = inventory.build_manifest(
        iso_path=iso, extracted_root=extracted, settings=settings, verify_iso=True
    )
    assert manifest["baseline"]["verified"] is False
    assert len(manifest["baseline"]["issues"]) == 2


def test_build_manifest_is_deterministic(extracted, tmp_path) -> None:
    kwargs = {"iso_path": tmp_path / "missing.iso", "extracted_root": extracted, "verify_iso": False}
    first = inventory.write_json(tmp_path / "a.json", inventory.build_manifest(**kwargs))
    second = inventory.write_json(tmp_path / "b.json", inventory.build_manifest(**kwargs))
    assert first.read_bytes() == second.read_bytes()


def test_write_json_ends_with_a_newline_and_sorts_keys(tmp_path) -> None:
    target = inventory.write_json(tmp_path / "nested" / "out.json", {"b": 1, "a": 2})
    text = target.read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert list(json.loads(text)) == ["a", "b"]


# --------------------------------------------------------------------- report


def test_render_markdown_covers_the_manifest(extracted, tmp_path) -> None:
    manifest = inventory.build_manifest(
        iso_path=tmp_path / "missing.iso", extracted_root=extracted, verify_iso=False
    )
    report = inventory.render_markdown(manifest)
    assert report.startswith("# Seto inventory report")
    assert "## PARAM.SFO" in report
    assert "`DISC_ID`" in report
    assert "gmodule/libtest.prx" in report
    assert "Compiler: `MW MIPS C Compiler (2.4.1.01)`" in report
    assert "- Functions discovered: 1" in report


def test_load_manifest_round_trips(tmp_path, extracted) -> None:
    path = inventory.write_json(
        tmp_path / "manifest.json",
        inventory.build_manifest(
            iso_path=tmp_path / "missing.iso", extracted_root=extracted, verify_iso=False
        ),
    )
    assert inventory.load_manifest(path)["summary"]["module_count"] == 1
