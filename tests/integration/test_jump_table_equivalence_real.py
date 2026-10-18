"""Integration tests for the SETO-DECOMP-015 code + jump-table comparison.

Two independent layers:

* a GNU MIPSel integration test that proves the linker semantics the experiment
  relies on (``R_MIPS_32`` against a positioned ``.text``, ``HI16``/``LO16``
  destination reconstruction, ``R_MIPS_26`` via ``--defsym``), using a synthetic
  assembly object only;
* an opt-in WSL2 test that runs the real Metrowerks compile/link against the
  local PRX.  It never runs on native Windows and never merges anything.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from seto import elf, mips
from scripts.probe_common import ensure_build_dir, validated_build_root, write_build_text
from scripts.probe_jump_table_equivalence import (
    compare_table_entries,
    paired_effective_address,
)

pytestmark = pytest.mark.integration
REPO_ROOT = Path(__file__).resolve().parents[2]
REAL_OPT_IN = "SETO_JUMP_TABLE_EQUIVALENCE_REAL"
CALL_SYMBOL = "external_call"
CALL_TARGET = 0x2364
TEXT_ADDRESS = 0x39C
TABLE_LAYOUTS = {"A": 0x4770, "B": 0x4774}

# `table_func` lays the HI16/LO16 pair on words 0/1 and the call on word 2; the
# six case bodies follow, 0x18 bytes into `.text`.
CASE_OFFSETS = tuple(0x18 + 8 * index for index in range(6))


def _require_gnu_tools() -> None:
    required = (
        "mipsel-linux-gnu-as",
        "mipsel-linux-gnu-ld",
        "mipsel-linux-gnu-readelf",
        "mipsel-linux-gnu-objdump",
    )
    missing = [tool for tool in required if shutil.which(tool) is None]
    if missing:
        pytest.skip(f"GNU MIPSel integration tools are not installed: {', '.join(missing)}")


def _assemble_case_object(work_dir: Path, build_root: Path) -> Path:
    source = work_dir / "case-table.s"
    write_build_text(
        source,
        textwrap.dedent(
            f"""\
            .set noreorder
            .text
            .globl table_func
            table_func:
                lui $v1, %hi(rodata_table)
                addiu $v1, $v1, %lo(rodata_table)
                jal {CALL_SYMBOL}
                nop
                jr $ra
                nop
            case0:
                jr $ra
                nop
            case1:
                jr $ra
                nop
            case2:
                jr $ra
                nop
            case3:
                jr $ra
                nop
            case4:
                jr $ra
                nop
            case5:
                jr $ra
                nop
            .section .rodata,"a"
            .align 2
            .globl rodata_table
            rodata_table:
                .word case0
                .word case1
                .word case2
                .word case3
                .word case4
                .word case5
            """
        ),
        build_root,
    )
    object_path = work_dir / "case-table.o"
    assembled = subprocess.run(
        ["mipsel-linux-gnu-as", "-32", "-march=mips2", "-o", str(object_path), str(source)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert assembled.returncode == 0, assembled.stderr
    return object_path


def _link_case_object(object_path: Path, work_dir: Path, case: str, build_root: Path) -> Path:
    table_address = TABLE_LAYOUTS[case]
    script = work_dir / f"link-{case}.ld"
    write_build_text(
        script,
        textwrap.dedent(
            f"""\
            OUTPUT_FORMAT("elf32-tradlittlemips")
            OUTPUT_ARCH(mips)
            ENTRY(table_func)
            SECTIONS
            {{
              .gnu.attributes 0 : {{ *(.gnu.attributes) }}
              .text 0x{TEXT_ADDRESS:x} : SUBALIGN(4) {{ *(.text) }}
              .rodata 0x{table_address:x} : SUBALIGN(4) {{ *(.rodata) }}
              .MIPS.abiflags : {{ *(.MIPS.abiflags) }}
              .reginfo : {{ *(.reginfo) }}
              .pdr : {{ *(.pdr) }}
            }}
            ASSERT(ADDR(.text) == 0x{TEXT_ADDRESS:x}, "text address")
            ASSERT(ADDR(.rodata) == 0x{table_address:x}, "table address")
            ASSERT(SIZEOF(.rodata) == 0x18, "table size")
            """
        ),
        build_root,
    )
    output = work_dir / f"linked-{case}.elf"
    linked = subprocess.run(
        [
            "mipsel-linux-gnu-ld",
            "-m",
            "elf32ltsmip",
            "-T",
            str(script),
            f"--defsym={CALL_SYMBOL}=0x{CALL_TARGET:x}",
            "-o",
            str(output),
            str(object_path),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert linked.returncode == 0, linked.stderr
    return output


def test_gnu_mipsel_linker_resolves_the_rodata_table_and_hi16_lo16() -> None:
    _require_gnu_tools()
    seto_root = validated_build_root(REPO_ROOT, subdir="seto015")
    work_dir = REPO_ROOT / "build/seto015/gnu-integration"
    ensure_build_dir(work_dir, seto_root)
    object_path = _assemble_case_object(work_dir, seto_root)

    relocatable = elf.parse(object_path)
    assert relocatable.header.e_type == elf.ET_REL
    table_relocations = relocatable.relocations_for(".rodata")
    assert len(table_relocations) == 6
    assert {relocation.type_name for relocation in table_relocations} == {"R_MIPS_32"}
    text_relocations = {relocation.type_name for relocation in relocatable.relocations_for(".text")}
    assert {"R_MIPS_HI16", "R_MIPS_LO16", "R_MIPS_26"} <= text_relocations

    linked_a = elf.parse(_link_case_object(object_path, work_dir, "A", seto_root))
    assert linked_a.header.e_type == elf.ET_EXEC
    assert not linked_a.relocations
    assert not [symbol.name for symbol in linked_a.symbols if symbol.shndx == elf.SHN_UNDEF and symbol.name]

    text = linked_a.require_section(".text")
    words = mips.decode_words(linked_a.section_data(text), "linked case A")
    assert paired_effective_address(words[0], words[1]) == TABLE_LAYOUTS["A"]
    assert mips.jump_target(words[2], TEXT_ADDRESS + 8) == CALL_TARGET
    table = linked_a.require_section(".rodata")
    entries = mips.decode_words(linked_a.section_data(table), "linked table A")
    assert len(entries) == 6
    assert entries == tuple(TEXT_ADDRESS + offset for offset in CASE_OFFSETS)

    linked_b = elf.parse(_link_case_object(object_path, work_dir, "B", seto_root))
    b_table = mips.decode_words(linked_b.section_data(linked_b.require_section(".rodata")), "linked table B")
    assert b_table == entries, "the table entries are .text-relative and must not move with .rodata"
    b_words = mips.decode_words(linked_b.section_data(linked_b.require_section(".text")), "linked case B")
    assert [index for index, (left, right) in enumerate(zip(words, b_words, strict=True)) if left != right] == [1]
    assert paired_effective_address(b_words[0], b_words[1]) == TABLE_LAYOUTS["B"]
    assert compare_table_entries(entries, b_table) == []

    for tool_args in (
        ["mipsel-linux-gnu-readelf", "-hWr", str(work_dir / "linked-A.elf")],
        ["mipsel-linux-gnu-objdump", "-dr", str(work_dir / "linked-A.elf")],
    ):
        inspected = subprocess.run(tool_args, capture_output=True, text=True, timeout=60, check=False)
        assert inspected.returncode == 0, inspected.stderr


def _run_real_report(out_path: Path) -> bytes:
    command = [
        sys.executable,
        "scripts/probe_jump_table_equivalence.py",
        "--config",
        "config/wsl/seto.toml",
        "--prx",
        "private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx",
        "--source",
        "decomp/src/func_0000039C.c",
        "--build-dir",
        "build/seto015/integration-real",
        "--out",
        out_path.relative_to(REPO_ROOT).as_posix(),
    ]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = "src"
    result = subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=1200,
    )
    assert result.returncode == 0, (
        f"real jump-table experiment failed ({result.returncode})\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert out_path.is_file(), "real run returned success without writing its report"
    return out_path.read_bytes()


def test_real_metrowerks_prx_jump_table_comparison_is_controlled_and_deterministic() -> None:
    if os.name == "nt" or "microsoft" not in platform.release().lower():
        pytest.skip("requires Ubuntu under WSL2; never runs the private PRX on native Windows")
    if os.environ.get(REAL_OPT_IN) != "1":
        pytest.skip(f"set {REAL_OPT_IN}=1 to opt into the WSL2 Metrowerks/PRX integration")

    required = ("mipsel-linux-gnu-ld", "mipsel-linux-gnu-readelf", "mipsel-linux-gnu-objdump", "file")
    missing = [tool for tool in required if shutil.which(tool) is None]
    assert not missing, f"{REAL_OPT_IN}=1 but required real-link tools are missing: {missing}"
    assert (REPO_ROOT / "private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx").is_file(), (
        f"{REAL_OPT_IN}=1 but the authorized local PRX is missing"
    )

    seto_root = validated_build_root(REPO_ROOT, subdir="seto015")
    integration_dir = REPO_ROOT / "build/seto015/integration-real"
    ensure_build_dir(integration_dir, seto_root)
    first_path = integration_dir / "report-1.json"
    second_path = integration_dir / "report-2.json"
    first = _run_real_report(first_path)
    second = _run_real_report(second_path)
    assert first == second, "canonical jump-table JSON differs across identical fresh runs"
    report = json.loads(first)

    assert report["experiment_status"] == "PASS"
    assert report["baseline"]["status"] == "INCONCLUSIVE"
    assert report["baseline"]["matching_words"] == 28
    assert report["baseline"]["total_words"] == 30
    assert report["original_match_status"] == "INCONCLUSIVE"
    assert report["promoted_to_matched"] is False
    assert report["independent_identity_proven"] is False
    assert report["code"]["equal_words"] == 30
    assert report["code"]["total_words"] == 30
    assert report["code"]["differences"] == []
    assert report["jump_table"]["original_address"] == "0x4770"
    assert report["jump_table"]["candidate_address"] == "0x4770"
    assert report["jump_table"]["entry_count"] == 6
    assert report["jump_table"]["equal_entries"] == 6
    assert report["jump_table"]["differences"] == []
    assert report["jump_table"]["layout_assignment"] == "CONTROLLED"
    assert report["equivalence_claim"] == "ASSUMPTION_DEPENDENT"

    prx_path = REPO_ROOT / report["provenance"]["prx_path"]
    source_path = REPO_ROOT / report["provenance"]["source_path"]
    object_path = REPO_ROOT / report["provenance"]["fresh_object_path"]
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest(prx_path) == report["provenance"]["prx_sha256"]
    assert digest(source_path) == report["provenance"]["source_sha256"]
    assert digest(object_path) == report["provenance"]["fresh_object_sha256"]
    for script in report["provenance"]["linker_script_sha256"].values():
        assert len(script) == 64
    assert report["provenance"]["flags"] == ["-O4,p", "-sdatathreshold", "0"]

    variants = report["linker"]["variants"]
    for label, variant in variants.items():
        linked_path = REPO_ROOT / variant["linked_elf_path"]
        assert digest(linked_path) == variant["linked_elf_sha256"]
        linked = elf.parse(linked_path)
        assert linked.header.e_type == elf.ET_EXEC
        assert linked.header.e_machine == elf.EM_MIPS
        assert linked.relocations == ()
        assert not [symbol.name for symbol in linked.symbols if symbol.shndx == elf.SHN_UNDEF and symbol.name]
        assert linked.require_section(".text").addr == 0x39C
        assert linked.require_section(".rodata").addr in (0x4770, 0x4774)
        assert linked.require_section(".mwcats").size == 8
        assert [
            section.name for section in linked.sections if section.flags & mips.SHF_EXECINSTR
        ] == [".text"]
        words = mips.decode_words(linked.section_data(linked.require_section(".text")), f"linked case {label}")
        assert [f"0x{word:08x}" for word in words] == variant["linked_words"]
        entries = mips.decode_words(linked.section_data(linked.require_section(".rodata")), f"table {label}")
        assert [f"0x{value:08x}" for value in entries] == variant["linked_entries"]
        assert variant["table_differences"] == []
        assert variant["entry_destinations"] == [
            {
                "entry_index": index,
                "address": f"0x{value:x}",
                "expected_case_address": f"0x{0x3D4 + 8 * index:x}",
                "inside_function": True,
                "matches_expected_case": True,
            }
            for index, value in enumerate(entries)
        ]

    assert variants["A"]["equal_words"] == 30
    assert variants["A"]["equal_entries"] == 6
    assert variants["A"]["hi16_lo16_effective_address"] == "0x4770"
    assert variants["A"]["hi16_lo16_reconstructs_table"] is True
    assert variants["A"]["call_target"] == "0x2364"
    assert variants["A"]["call_is_controlled_target"] is True
    assert variants["A"]["linked_entries"] == ["0x000003d4", "0x000003dc", "0x000003e4", "0x000003ec", "0x000003f4", "0x000003fc"]
    assert variants["B"]["linked_entries"] == variants["A"]["linked_entries"]
    layout_differences = report["linker"]["layout_control_b_vs_a"]
    assert [row["word_index"] for row in layout_differences] == [9]
    assert layout_differences[0]["address"] == "0x3c0"
    assert report["linker"]["generated_stubs"] is False

    controls = report["controls"]
    assert controls["C"]["relocation_inventory_preserved"] is True
    assert [row["entry_index"] for row in controls["C"]["table_differences"]] == [0, 1]
    assert controls["C"]["equal_words"] == 30
    assert controls["D"]["relocation_inventory_preserved"] is True
    assert [row["entry_index"] for row in controls["D"]["table_differences"]] == [3]
    assert controls["D"]["equal_words"] == 30
    assert controls["E"]["relocation_inventory_preserved"] is True
    assert [row["word_index"] for row in controls["E"]["differences"]] == [0]
    assert controls["E"]["equal_entries"] == 6
    for control in controls.values():
        assert control["detected"] is True
        assert control["promoted_to_matched"] is False

    assert report["original_prx"]["jump_table"]["target"]["section"] == ".data"
    assert report["original_prx"]["jump_table"]["target"]["offset"] == "0x8"
    assert report["original_prx"]["jump_table"]["entries"] == [
        "0x000003d4",
        "0x000003dc",
        "0x000003e4",
        "0x000003ec",
        "0x000003f4",
        "0x000003fc",
    ]
    assert report["original_prx"]["jump_table"]["module_relative_address"] == "0x4770"
    call = report["original_prx"]["call"]
    assert call["call_site"] == "0x3a4"
    assert call["candidate_symbol"] == "func_00002364"
    assert call["assignment_kind"] == "CONTROLLED_FROM_ORIGINAL_PRX_IMPORT_STUB"
    assert call["original_stub_address"] == "0x2364"
    assert call["candidate_symbol_identity_independently_proven"] is False
    assert call["original_import"]["library"] == "libehsys"
    assert call["original_import"]["nid"] == "0x31454993"
    assert report["original_prx"]["psp_table_relocations"]["runtime_comparison"] == "NOT_DEMONSTRATED"
    assert report["original_prx"]["psp_text_relocations"]["runtime_comparison"] == "NOT_DEMONSTRATED"
    psp_table_rows = report["original_prx"]["psp_table_relocations"]["relocations"]
    assert [row["type"] for row in psp_table_rows] == ["R_MIPS_32"] * 6
    assert [row["module_relative_applied_word"] for row in psp_table_rows] == report["original_prx"]["jump_table"]["entries"]
    assert all(row["actual_runtime_load_base_known"] is False for row in psp_table_rows)

    assert "C:\\" not in first.decode("utf-8")
    assert "/mnt/c/" not in first.decode("utf-8")
    assert "/home/" not in first.decode("utf-8")
