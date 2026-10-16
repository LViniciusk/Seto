"""Tests for the command line interface and its exit-code contract."""

from __future__ import annotations

import json

import pytest

from seto import cli
from seto.hashing import fingerprint_file

from conftest import SHF_ALLOC, SHF_EXECINSTR, build_elf32, jal, jr, word

FUNCTION_CODE = word(jal(0x0)) + word(jr(31))
OTHER_CODE = word(0x00000000) + word(jr(31))


def _module_bytes(code: bytes = FUNCTION_CODE) -> bytes:
    return build_elf32(
        sections=[
            {
                "name": ".text",
                "type": 1,
                "flags": SHF_ALLOC | SHF_EXECINSTR,
                "addr": 0,
                "size": len(code),
                "data": code,
            }
        ]
    )


@pytest.fixture
def prx(tmp_path):
    path = tmp_path / "libtest.prx"
    path.write_bytes(_module_bytes())
    return path


# ------------------------------------------------------------------- parser/main


def test_build_parser_accepts_every_command() -> None:
    parser = cli.build_parser()
    for argv in (
        ["detect", "a"],
        ["functions", "--prx", "a"],
        ["split", "--prx", "a"],
        ["check-layout", "--layout", "a", "--prx", "b"],
        ["disasm", "--prx", "a"],
        ["match", "--prx", "a", "--function", "0", "--candidate", "b"],
        ["toolchain"],
        ["verify"],
        ["inventory"],
    ):
        assert parser.parse_args(argv) is not None


def test_version_flag_exits_cleanly(capsys) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])
    assert exit_info.value.code == 0
    assert "seto" in capsys.readouterr().out


def test_missing_config_file_is_an_error(tmp_path, capsys) -> None:
    assert cli.main(["--config", str(tmp_path / "absent.toml"), "toolchain"]) == cli.EXIT_ERROR
    assert "error:" in capsys.readouterr().err


# ----------------------------------------------------------------------- detect


def test_detect_recognises_elf(prx, capsys) -> None:
    assert cli.main(["detect", str(prx)]) == cli.EXIT_OK
    assert "ELF" in capsys.readouterr().out


def test_detect_flags_unknown_content(tmp_path, capsys) -> None:
    raw = tmp_path / "blob.bin"
    raw.write_bytes(b"not a known container")
    assert cli.main(["detect", str(raw)]) == cli.EXIT_MISMATCH
    assert "unknown" in capsys.readouterr().out


def test_detect_reports_a_missing_file(tmp_path, capsys) -> None:
    assert cli.main(["detect", str(tmp_path / "nope.bin")]) == cli.EXIT_ERROR
    assert "MISSING" in capsys.readouterr().err


# -------------------------------------------------------------------- functions


def test_functions_lists_discovered_functions(prx, capsys) -> None:
    assert cli.main(["functions", "--prx", str(prx)]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "func_00000000" in out
    assert "total: 1 functions" in out


def test_functions_json(prx, capsys) -> None:
    assert cli.main(["functions", "--prx", str(prx), "--json"]) == cli.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["section"] == ".text"
    assert len(payload["functions"]) == 1
    assert payload["functions"][0]["calls"] == [0]


def test_functions_missing_section_is_an_error(prx, capsys) -> None:
    assert cli.main(["functions", "--prx", str(prx), "--section", ".rodata"]) == cli.EXIT_ERROR
    assert "error:" in capsys.readouterr().err


# ------------------------------------------------------------ split/check-layout


def test_split_and_check_layout_round_trip(prx, tmp_path, capsys) -> None:
    out = tmp_path / "split"
    assert cli.main(["split", "--prx", str(prx), "--out", str(out)]) == cli.EXIT_OK
    assert (out / "layout.json").is_file()
    assert (out / "libtest.yaml").is_file()
    assert cli.main(["check-layout", "--layout", str(out / "layout.json"), "--prx", str(prx)]) == cli.EXIT_OK
    assert "layout OK" in capsys.readouterr().out


# ------------------------------------------------------------------------ match


def test_match_self_comparison_is_matched(prx, capsys) -> None:
    assert (
        cli.main(["match", "--prx", str(prx), "--function", "0x0", "--candidate", str(prx)])
        == cli.EXIT_OK
    )
    assert "MATCHED" in capsys.readouterr().out


def test_match_against_a_different_candidate_is_a_mismatch(prx, tmp_path, capsys) -> None:
    candidate = tmp_path / "other.prx"
    candidate.write_bytes(_module_bytes(OTHER_CODE))
    assert (
        cli.main(["match", "--prx", str(prx), "--function", "0x0", "--candidate", str(candidate)])
        == cli.EXIT_MISMATCH
    )
    assert "NONMATCHING" in capsys.readouterr().out


def test_match_against_a_raw_blob_records_a_limitation(prx, tmp_path, capsys) -> None:
    blob = tmp_path / "raw.bin"
    blob.write_bytes(FUNCTION_CODE)
    assert (
        cli.main(
            ["match", "--prx", str(prx), "--function", "0x0", "--candidate", str(blob), "--json"]
        )
        == cli.EXIT_OK
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "MATCHED"
    assert any("not ELF" in note for note in payload["limitations"])


def test_match_unknown_function_is_an_error(prx, capsys) -> None:
    assert (
        cli.main(["match", "--prx", str(prx), "--function", "0x999", "--candidate", str(prx)])
        == cli.EXIT_ERROR
    )
    assert "no function starts" in capsys.readouterr().err


# ----------------------------------------------------------------------- disasm


def test_disasm_unknown_function_is_an_error(prx, capsys) -> None:
    assert cli.main(["disasm", "--prx", str(prx), "--function", "0x999"]) == cli.EXIT_ERROR
    assert "no function starts" in capsys.readouterr().err


def test_disasm_is_ok_or_blocked_on_capstone(prx, capsys) -> None:
    code = cli.main(["disasm", "--prx", str(prx), "--function", "0x0"])
    captured = capsys.readouterr()
    assert code in (cli.EXIT_OK, cli.EXIT_BLOCKED)
    if code == cli.EXIT_BLOCKED:
        assert "BLOCKED" in captured.err
    else:
        assert "func" in captured.out or ":" in captured.out


# -------------------------------------------------------------------- toolchain


def test_toolchain_reports_availability(capsys) -> None:
    assert cli.main(["toolchain"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "external tools" in out
    assert "missing:" in out


def test_toolchain_json(capsys) -> None:
    assert cli.main(["toolchain", "--json"]) == cli.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    names = {tool["name"] for tool in payload["tools"]}
    assert "mwccpsp" in names
    assert "ghidra" in names


# --------------------------------------------------------------------- inventory


def test_inventory_writes_a_manifest(prx, tmp_path, capsys) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "module.prx").write_bytes(prx.read_bytes())
    out = tmp_path / "inv"
    code = cli.main(
        [
            "inventory",
            "--iso",
            str(tmp_path / "missing.iso"),
            "--extracted",
            str(root),
            "--out",
            str(out),
            "--no-verify",
            "--quiet",
        ]
    )
    assert code == cli.EXIT_OK
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["summary"]["module_count"] == 1


# ------------------------------------------------------------------------ verify


def test_verify_accepts_a_matching_baseline(tmp_path, capsys) -> None:
    iso = tmp_path / "TF1.iso"
    iso.write_bytes(b"baseline payload")
    fingerprint = fingerprint_file(iso)
    config = tmp_path / "seto.toml"
    config.write_text(
        "[baseline]\n"
        f'iso = "{iso.as_posix()}"\n'
        f"size = {fingerprint.size}\n"
        f'sha256 = "{fingerprint.sha256}"\n',
        encoding="utf-8",
    )
    assert cli.main(["--config", str(config), "verify"]) == cli.EXIT_OK
    assert "status: OK" in capsys.readouterr().out


def test_verify_rejects_a_mismatching_baseline(tmp_path, capsys) -> None:
    iso = tmp_path / "TF1.iso"
    iso.write_bytes(b"baseline payload")
    config = tmp_path / "seto.toml"
    config.write_text(
        "[baseline]\n" f'iso = "{iso.as_posix()}"\nsize = 1\nsha256 = "00"\n',
        encoding="utf-8",
    )
    assert cli.main(["--config", str(config), "verify"]) == cli.EXIT_MISMATCH
    assert "FAIL" in capsys.readouterr().err


def test_verify_without_an_iso_is_an_error(tmp_path, capsys) -> None:
    config = tmp_path / "seto.toml"
    config.write_text('[baseline]\niso = "nope.iso"\n', encoding="utf-8")
    assert cli.main(["--config", str(config), "verify"]) == cli.EXIT_ERROR
    assert "ISO not found" in capsys.readouterr().err
