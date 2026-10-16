"""Tests for the command line interface and its exit-code contract."""

from __future__ import annotations

import json

import pytest

from seto import cli
from seto.hashing import fingerprint_file

from conftest import (
    SHF_ALLOC,
    SHF_EXECINSTR,
    build_elf32,
    build_symbols,
    jal,
    jr,
    word,
)

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


def _prx_bytes(code: bytes = FUNCTION_CODE) -> bytes:
    """A linked PSP PRX (``e_type = 0xFFA0``), used as the "original"."""
    return build_elf32(
        e_type=0xFFA0,
        sections=[
            {
                "name": ".text",
                "type": 1,
                "flags": SHF_ALLOC | SHF_EXECINSTR,
                "addr": 0,
                "size": len(code),
                "data": code,
            }
        ],
    )


def _object_bytes(
    code: bytes,
    *,
    text_addr: int = 0,
    symbol_name: str | None = None,
    symbol_offset: int = 0,
    pad_before_text: int = 0,
) -> bytes:
    """Build an ``ET_REL`` object with an optional symbol and a non-zero base."""
    sections: list[dict] = []
    if pad_before_text:
        sections.append(
            {
                "name": ".rodata",
                "type": 1,
                "flags": SHF_ALLOC,
                "addr": text_addr,
                "size": pad_before_text,
                "data": b"\x00" * pad_before_text,
            }
        )
    sections.append(
        {
            "name": ".text",
            "type": 1,
            "flags": SHF_ALLOC | SHF_EXECINSTR,
            "addr": text_addr,
            "size": len(code),
            "data": code,
        }
    )
    if symbol_name is not None:
        text_index = next(i for i, s in enumerate(sections, start=1) if s["name"] == ".text")
        symtab_index = len(sections) + 1
        strtab_index = symtab_index + 1
        symtab, strtab = build_symbols(
            [
                {"name": "", "value": 0, "size": 0, "info": 0, "other": 0, "shndx": 0},
                {
                    "name": symbol_name,
                    "value": text_addr + symbol_offset,
                    "size": len(code) - symbol_offset,
                    "info": 0x12,
                    "other": 0,
                    "shndx": text_index,
                },
            ]
        )
        sections.append(
            {"name": ".symtab", "type": 2, "flags": 0, "addr": 0, "size": len(symtab),
             "data": symtab, "link": strtab_index, "info": 1, "align": 4, "entsize": 0x10}
        )
        sections.append(
            {"name": ".strtab", "type": 3, "flags": 0, "addr": 0, "size": len(strtab),
             "data": strtab, "align": 1}
        )
    return build_elf32(sections=sections)


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


def test_check_layout_rejects_malformed_json(prx, tmp_path, capsys) -> None:
    layout = tmp_path / "layout.json"
    layout.write_text("{ not json", encoding="utf-8")
    assert cli.main(["check-layout", "--layout", str(layout), "--prx", str(prx)]) == cli.EXIT_ERROR
    assert "error:" in capsys.readouterr().err


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


def test_match_against_a_raw_blob_is_inconclusive(prx, tmp_path, capsys) -> None:
    # A raw blob may be byte-identical, but without ELF metadata it is never a
    # *proof*: the exit code must be 5 (inconclusive), not 0 (matched).
    blob = tmp_path / "raw.bin"
    blob.write_bytes(FUNCTION_CODE)
    assert (
        cli.main(
            ["match", "--prx", str(prx), "--function", "0x0", "--candidate", str(blob), "--json"]
        )
        == cli.EXIT_INCONCLUSIVE
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "INCONCLUSIVE"
    assert payload["percent"] == 100.0
    assert any("not ELF" in note for note in payload["limitations"])
    assert "raw bytes at absolute file offset 0x0" in payload["candidate"]["location"]


def test_match_rejects_a_malformed_elf_instead_of_treating_it_as_a_blob(prx, tmp_path, capsys) -> None:
    candidate = tmp_path / "broken.o"
    candidate.write_bytes(b"\x7fELF" + b"\x00" * 8)  # ELF magic, truncated header
    assert (
        cli.main(["match", "--prx", str(prx), "--function", "0x0", "--candidate", str(candidate)])
        == cli.EXIT_ERROR
    )
    assert "error:" in capsys.readouterr().err


def test_match_selects_a_function_at_a_nonzero_offset(prx, tmp_path, capsys) -> None:
    candidate = tmp_path / "other.prx"
    candidate.write_bytes(_module_bytes(FUNCTION_CODE + OTHER_CODE))
    # The fixture gives two discovered functions; selecting the first by offset
    # must compare against the *original* function (index 0 == FUNCTION_CODE).
    assert (
        cli.main(
            [
                "match",
                "--prx",
                str(prx),
                "--function",
                "0x0",
                "--candidate",
                str(candidate),
                "--candidate-section-offset",
                "0",
            ]
        )
        == cli.EXIT_OK
    )
    assert "MATCHED" in capsys.readouterr().out


def test_match_with_multiple_candidate_functions_is_inconclusive(prx, tmp_path, capsys) -> None:
    candidate = tmp_path / "other.prx"
    candidate.write_bytes(_module_bytes(FUNCTION_CODE + OTHER_CODE))
    assert (
        cli.main(["match", "--prx", str(prx), "--function", "0x0", "--candidate", str(candidate)])
        == cli.EXIT_INCONCLUSIVE
    )
    assert "INCONCLUSIVE" in capsys.readouterr().err


def test_match_absolute_file_offset_must_lie_inside_the_section(prx, tmp_path, capsys) -> None:
    candidate = tmp_path / "other.prx"
    candidate.write_bytes(_module_bytes())
    # The synthetic module's .text does not start at file offset 0.
    assert (
        cli.main(
            ["match", "--prx", str(prx), "--function", "0x0", "--candidate", str(candidate),
             "--candidate-offset", "0x2"]
        )
        == cli.EXIT_ERROR
    )
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize("bad", ["-4", "0x2"])
def test_match_rejects_unaligned_candidate_section_offsets(prx, tmp_path, capsys, bad) -> None:
    candidate = tmp_path / "other.prx"
    candidate.write_bytes(_module_bytes())
    assert (
        cli.main(
            ["match", "--prx", str(prx), "--function", "0x0", "--candidate", str(candidate),
             "--candidate-section-offset", bad]
        )
        == cli.EXIT_ERROR
    )
    assert "error:" in capsys.readouterr().err


def test_match_candidate_smaller_than_the_function_is_an_error(prx, tmp_path, capsys) -> None:
    candidate = tmp_path / "small.prx"
    candidate.write_bytes(_module_bytes(word(jr(31))))
    assert (
        cli.main(
            ["match", "--prx", str(prx), "--function", "0x0", "--candidate", str(candidate),
             "--candidate-section-offset", "0"]
        )
        == cli.EXIT_ERROR
    )
    assert "error:" in capsys.readouterr().err


def test_match_locates_an_et_rel_symbol_at_a_different_base_and_offset(
    prx, tmp_path, capsys
) -> None:
    # .text lives at a non-zero file offset, the section base is non-zero and the
    # target function is the second one in the object: only the symbol pins it down.
    candidate = tmp_path / "func.o"
    candidate.write_bytes(
        _object_bytes(
            OTHER_CODE + FUNCTION_CODE,
            text_addr=0x8000,
            symbol_name="func_00000000",
            symbol_offset=8,
            pad_before_text=16,
        )
    )
    assert (
        cli.main(
            ["match", "--prx", str(prx), "--function", "0x0", "--candidate", str(candidate),
             "--candidate-symbol", "func_00000000", "--json"]
        )
        == cli.EXIT_OK
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "MATCHED"
    assert payload["evidence"] == "compiled-object"
    assert "symbol 'func_00000000'" in payload["candidate"]["location"]
    assert payload["candidate"]["section_offset"] == 8


def test_match_et_rel_without_a_symbol_and_multiple_functions_is_inconclusive(
    prx, tmp_path, capsys
) -> None:
    candidate = tmp_path / "func.o"
    candidate.write_bytes(_object_bytes(OTHER_CODE + FUNCTION_CODE))
    assert (
        cli.main(["match", "--prx", str(prx), "--function", "0x0", "--candidate", str(candidate)])
        == cli.EXIT_INCONCLUSIVE
    )
    assert "INCONCLUSIVE" in capsys.readouterr().err


def test_match_against_the_original_is_binary_range_evidence(tmp_path, capsys) -> None:
    original = tmp_path / "module.prx"
    original.write_bytes(_prx_bytes())
    assert (
        cli.main(
            ["match", "--prx", str(original), "--function", "0x0",
             "--candidate", str(original), "--json"]
        )
        == cli.EXIT_OK
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "MATCHED"
    assert payload["evidence"] == "binary-range"


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
