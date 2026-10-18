"""Integration tests for the SETO-DECOMP-016 multi-reference link & data comparison.

Two independent layers:

* a GNU MIPSel integration test (without ``private/``) that proves the linker
  semantics the experiment relies on for ``func_00000414`` (7-entry ``R_MIPS_32``
  ``.rodata`` jump table with repeated case offset ``0x6c``, 5 ``HI16``/``LO16``
  pairs including the shared ``D_000047D0`` pair at ``21->24`` and ``33->36``,
  5 ``R_MIPS_26`` calls via ``--defsym``, and negative controls B, C, D, and E);
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
import scripts.probe_multi_reference_equivalence as probe

pytestmark = pytest.mark.integration
REPO_ROOT = Path(__file__).resolve().parents[2]
REAL_OPT_IN = "SETO_MULTI_REFERENCE_EQUIVALENCE_REAL"


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


def _assemble_multi_ref_object(work_dir: Path, build_root: Path) -> Path:
    """Assemble a synthetic 41-word func_00000414 object with 7-entry .rodata and .mwcats."""
    source = work_dir / "multi-ref.s"
    write_build_text(
        source,
        textwrap.dedent(
            """\
            .set noreorder
            .set noat
            .text
            .globl func_00000414
            .type func_00000414, @function
            func_00000414:
                addiu $sp, $sp, -0x10          # 0 (0x414)
                sw $ra, 4($sp)                 # 1 (0x418)
                sw $s0, 0($sp)                 # 2 (0x41c)
                jal func_00002354              # 3 (0x420)
                move $s0, $a0                  # 4 (0x424)
                sltiu $a0, $v0, 7              # 5 (0x428)
                beqz $a0, .Ldefault            # 6 (0x42c)
                nop                            # 7 (0x430)
                lui $v1, %hi("@15")            # 8 (0x434)
                sll $v0, $v0, 2                # 9 (0x438)
                addiu $v1, $v1, %lo("@15")     # 10 (0x43c)
                addu $v0, $v0, $v1             # 11 (0x440)
                lw $v0, 0($v0)                 # 12 (0x444)
                jr $v0                         # 13 (0x448)
                nop                            # 14 (0x44c)
            .Lcase0:                           # offset 0x3c (0x450)
                lui $a1, %hi(D_000047A4)       # 15 (0x450)
                move $a0, $s0                  # 16 (0x454)
                jal func_000008A4              # 17 (0x458)
                addiu $a1, $a1, %lo(D_000047A4)# 18 (0x45c)
                b .Lexit                       # 19 (0x460)
                lw $ra, 0xc($sp)               # 20 (0x464)
            .Lcase1:                           # offset 0x54 (0x468)
                lui $a1, %hi(D_000047D0)       # 21 (0x468)
                move $a0, $s0                  # 22 (0x46c)
                jal func_000008A4              # 23 (0x470)
                addiu $a1, $a1, %lo(D_000047D0)# 24 (0x474)
                b .Lexit                       # 25 (0x478)
                nop                            # 26 (0x47c)
            .Lcase2_6:                         # offset 0x6c (0x480)
                lui $a1, %hi(D_00004800)       # 27 (0x480)
                move $a0, $s0                  # 28 (0x484)
                jal func_000008A4              # 29 (0x488)
                addiu $a1, $a1, %lo(D_00004800)# 30 (0x48c)
                b .Lexit                       # 31 (0x490)
                nop                            # 32 (0x494)
            .Ldefault:                         # offset 0x84 (0x498)
                lui $a1, %hi(D_000047D0)       # 33 (0x498)
                move $a0, $s0                  # 34 (0x49c)
                jal func_000008A4              # 35 (0x4a0)
                addiu $a1, $a1, %lo(D_000047D0)# 36 (0x4a4)
            .Lexit:
                lw $ra, 0xc($sp)               # 37 (0x4a8)
                lw $s0, 8($sp)                 # 38 (0x4ac)
                jr $ra                         # 39 (0x4b0)
                addiu $sp, $sp, 0x10           # 40 (0x4b4)
            .size func_00000414, . - func_00000414

            .section .rodata,"a",@progbits
            .align 2
            .globl "@15"
            .type "@15", @object
            .size "@15", 28
            "@15":
                .word func_00000414 + 0x3c
                .word func_00000414 + 0x54
                .word func_00000414 + 0x6c
                .word func_00000414 + 0x6c
                .word func_00000414 + 0x6c
                .word func_00000414 + 0x6c
                .word func_00000414 + 0x6c

            .section .mwcats,"",@progbits
            .align 2
                .word func_00000414
                .word 0xa4
            """
        ),
        build_root,
    )
    object_path = work_dir / "multi-ref.o"
    assembled = subprocess.run(
        ["mipsel-linux-gnu-as", "-32", "-march=mips2", "-o", str(object_path), str(source)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert assembled.returncode == 0, assembled.stderr
    return object_path


def _link_gnu_object(
    object_path: Path,
    work_dir: Path,
    label: str,
    table_address: int,
    controlled_symbols: dict[str, int],
    build_root: Path,
) -> tuple[elf.ElfFile, tuple[int, ...], tuple[int, ...]]:
    script = work_dir / f"link-{label}.ld"
    write_build_text(
        script,
        textwrap.dedent(
            f"""\
            OUTPUT_FORMAT("elf32-tradlittlemips")
            OUTPUT_ARCH(mips)
            ENTRY(func_00000414)
            SECTIONS
            {{
              .mwcats 0 : SUBALIGN(4) {{ KEEP(*(.mwcats)) }}
              .gnu.attributes 0 : {{ *(.gnu.attributes) }}
              .text 0x{probe.FUNCTION_ADDRESS:x} : SUBALIGN(4) {{ *(.text) }}
              .rodata 0x{table_address:x} : SUBALIGN(4) {{ *(.rodata) }}
              .MIPS.abiflags : {{ *(.MIPS.abiflags) }}
              .reginfo : {{ *(.reginfo) }}
              .pdr : {{ *(.pdr) }}
            }}
            ASSERT(ADDR(.text) == 0x{probe.FUNCTION_ADDRESS:x}, "text address")
            ASSERT(ADDR(.rodata) == 0x{table_address:x}, "table address")
            ASSERT(SIZEOF(.rodata) == 0x{probe.TABLE_SIZE:x}, "table size")
            ASSERT(func_00000414 == 0x{probe.FUNCTION_ADDRESS:x}, "function symbol")
            ASSERT(SIZEOF(.mwcats) == 0x8, "mwcats size")
            """
        ),
        build_root,
    )
    output = work_dir / f"linked-{label}.elf"
    defsyms = [
        f"--defsym={sym}=0x{addr:x}" for sym, addr in sorted(controlled_symbols.items())
    ]
    linked_proc = subprocess.run(
        [
            "mipsel-linux-gnu-ld",
            "-m",
            "elf32ltsmip",
            "-T",
            str(script),
            *defsyms,
            "-o",
            str(output),
            str(object_path),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert linked_proc.returncode == 0, linked_proc.stderr
    linked = elf.parse(output)
    assert linked.header.e_type == elf.ET_EXEC
    probe.validate_link_has_no_unresolved(linked)
    probe.validate_table_section(linked, table_address=table_address, label=label)
    probe.validate_linked_controlled_symbols(linked, controlled_symbols)
    text_words = mips.decode_words(
        linked.section_data(linked.require_section(".text"))[: probe.FUNCTION_SIZE],
        f"linked {label} .text",
    )
    table_entries = probe.linked_table_entries(linked, table_address=table_address)
    return linked, text_words, table_entries


def test_gnu_mipsel_linker_resolves_multi_reference_code_and_rodata_table() -> None:
    _require_gnu_tools()
    seto_root = validated_build_root(REPO_ROOT, subdir="seto016")
    work_dir = REPO_ROOT / "build/seto016/gnu-integration"
    ensure_build_dir(work_dir, seto_root)
    object_path = _assemble_multi_ref_object(work_dir, seto_root)

    relocatable = elf.parse(object_path)
    assert relocatable.header.e_type == elf.ET_REL
    candidate_words = probe._function_words(relocatable, 0, label="synthetic gnu candidate")
    candidate_sites, _pairing = probe.validate_candidate_text_inventory(
        relocatable, candidate_words
    )
    table_section, table_relocations, table_words = probe.candidate_table_entries(relocatable)
    addends = probe.validate_candidate_table_invariants(table_relocations, table_words)
    assert addends == probe.EXPECTED_OFFSETS

    _linked_a, baseline_words, baseline_entries = _link_gnu_object(
        object_path,
        work_dir,
        "case-a",
        probe.TABLE_ADDRESS,
        probe.CONTROLLED_SYMBOLS,
        seto_root,
    )
    assert baseline_entries == probe.EXPECTED_TARGETS
    probe.validate_structural_destinations(baseline_entries)
    assigned_a = {probe.TABLE_SYMBOL: probe.TABLE_ADDRESS, **probe.CONTROLLED_SYMBOLS}
    pair_rows = probe.reconstruct_hi16_lo16_pairs(
        baseline_words, baseline_words, assigned_targets=assigned_a
    )
    probe.validate_hi16_lo16_pairs(pair_rows)
    call_rows = probe.reconstruct_call_sites(
        baseline_words, baseline_words, assigned_targets=probe.CONTROLLED_SYMBOLS
    )
    probe.validate_call_sites(call_rows)

    _linked_b, moved_words, moved_entries = _link_gnu_object(
        object_path,
        work_dir,
        "case-b",
        probe.TABLE_ALTERNATE_ADDRESS,
        probe.CONTROLLED_SYMBOLS,
        seto_root,
    )
    b_diffs = probe.validate_control_b(
        baseline_words,
        moved_words,
        baseline_entries,
        moved_entries,
        assigned_address=probe.TABLE_ALTERNATE_ADDRESS,
    )
    assert [row["word_index"] for row in b_diffs] == [10]

    # Control C: mutating shared D_000047D0 changes only words 24 and 36
    c_symbols = {
        **probe.CONTROLLED_SYMBOLS,
        probe.SHARED_DATA_SYMBOL: probe.SHARED_DATA_ALTERNATE_ADDRESS,
    }
    _linked_c, c_words, c_entries = _link_gnu_object(
        object_path,
        work_dir,
        "control-c",
        probe.TABLE_ADDRESS,
        c_symbols,
        seto_root,
    )
    c_diffs = probe.validate_control_c(
        baseline_words,
        c_words,
        baseline_entries,
        c_entries,
        assigned_address=probe.SHARED_DATA_ALTERNATE_ADDRESS,
    )
    assert [row["word_index"] for row in c_diffs] == [24, 36]

    # Control D: swapping table addends 0 and 1 changes only entries 0 and 1
    tampered_d_bytes = bytearray(object_path.read_bytes())
    tampered_d_bytes[table_section.offset : table_section.offset + 4] = (
        table_words[1] & 0xFFFFFFFF
    ).to_bytes(4, "little")
    tampered_d_bytes[table_section.offset + 4 : table_section.offset + 8] = (
        table_words[0] & 0xFFFFFFFF
    ).to_bytes(4, "little")
    tampered_d = work_dir / "tampered-d.o"
    probe.write_build_bytes(tampered_d, bytes(tampered_d_bytes), seto_root)
    _linked_d, d_words, d_entries = _link_gnu_object(
        tampered_d,
        work_dir,
        "control-d",
        probe.TABLE_ADDRESS,
        probe.CONTROLLED_SYMBOLS,
        seto_root,
    )
    d_diffs = probe.validate_control_d(
        baseline_entries,
        d_entries,
        baseline_words,
        d_words,
    )
    assert [row["entry_index"] for row in d_diffs] == [0, 1]

    # Control E: flipping non-relocated word 0 changes only code word 0
    text_section = relocatable.require_section(".text")
    tampered_e_bytes = bytearray(object_path.read_bytes())
    tampered_e_bytes[text_section.offset : text_section.offset + 4] = (
        (candidate_words[0] ^ 1) & 0xFFFFFFFF
    ).to_bytes(4, "little")
    tampered_e = work_dir / "tampered-e.o"
    probe.write_build_bytes(tampered_e, bytes(tampered_e_bytes), seto_root)
    _linked_e, e_words, e_entries = _link_gnu_object(
        tampered_e,
        work_dir,
        "control-e",
        probe.TABLE_ADDRESS,
        probe.CONTROLLED_SYMBOLS,
        seto_root,
    )
    e_diffs = probe.validate_control_e(
        baseline_words,
        e_words,
        baseline_entries,
        e_entries,
        word_index=0,
        relocation_sites=candidate_sites.sites,
    )
    assert [row["word_index"] for row in e_diffs] == [0]

    for tool_args in (
        ["mipsel-linux-gnu-readelf", "-hWr", "-s", str(work_dir / "linked-case-a.elf")],
        ["mipsel-linux-gnu-objdump", "-dr", str(work_dir / "linked-case-a.elf")],
    ):
        inspected = subprocess.run(
            tool_args, capture_output=True, text=True, timeout=60, check=False
        )
        assert inspected.returncode == 0, inspected.stderr


def _run_real_report(out_path: Path) -> bytes:
    command = [
        sys.executable,
        "scripts/probe_multi_reference_equivalence.py",
        "--config",
        "config/wsl/seto.toml",
        "--prx",
        "private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx",
        "--source",
        "decomp/src/func_00000414.c",
        "--build-dir",
        "build/seto016/integration-real",
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
        f"real multi-reference experiment failed ({result.returncode})\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert out_path.is_file(), "real run returned success without writing its report"
    return out_path.read_bytes()


def test_real_metrowerks_prx_multi_reference_comparison_is_controlled_and_deterministic() -> None:
    if os.name == "nt" or "microsoft" not in platform.release().lower():
        pytest.skip("requires Ubuntu under WSL2; never runs the private PRX on native Windows")
    if os.environ.get(REAL_OPT_IN) != "1":
        pytest.skip(f"set {REAL_OPT_IN}=1 to opt into the WSL2 Metrowerks/PRX integration")

    required = (
        "mipsel-linux-gnu-ld",
        "mipsel-linux-gnu-readelf",
        "mipsel-linux-gnu-objdump",
        "file",
    )
    missing = [tool for tool in required if shutil.which(tool) is None]
    assert not missing, f"{REAL_OPT_IN}=1 but required real-link tools are missing: {missing}"
    assert (REPO_ROOT / "private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx").is_file(), (
        f"{REAL_OPT_IN}=1 but the authorized local PRX is missing"
    )

    seto_root = validated_build_root(REPO_ROOT, subdir="seto016")
    integration_dir = REPO_ROOT / "build/seto016/integration-real"
    ensure_build_dir(integration_dir, seto_root)
    first_path = integration_dir / "report-1.json"
    second_path = integration_dir / "report-2.json"
    first = _run_real_report(first_path)
    second = _run_real_report(second_path)
    assert first == second, "canonical multi-reference JSON differs across identical fresh runs"
    report = json.loads(first)

    assert report["experiment_status"] == "PASS"
    assert report["baseline"]["status"] == "INCONCLUSIVE"
    assert report["baseline"]["matching_words"] == 31
    assert report["baseline"]["total_words"] == 41
    assert report["original_match_status"] == "INCONCLUSIVE"
    assert report["promoted_to_matched"] is False
    assert report["independent_identity_proven"] is False
    assert report["code"]["equal_words"] == 41
    assert report["code"]["total_words"] == 41
    assert report["code"]["differences"] == []
    assert report["jump_table"]["original_address"] == "0x4788"
    assert report["jump_table"]["candidate_address"] == "0x4788"
    assert report["jump_table"]["entry_count"] == 7
    assert report["jump_table"]["equal_entries"] == 7
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
        assert not [
            symbol.name for symbol in linked.symbols if symbol.shndx == elf.SHN_UNDEF and symbol.name
        ]
        assert linked.require_section(".text").addr == 0x414
        assert linked.require_section(".rodata").addr in (0x4788, 0x4784)
        assert linked.require_section(".mwcats").size == 8
        assert [
            section.name for section in linked.sections if section.flags & mips.SHF_EXECINSTR
        ] == [".text"]
        words = mips.decode_words(
            linked.section_data(linked.require_section(".text")), f"linked case {label}"
        )
        assert [f"0x{word:08x}" for word in words] == variant["linked_words"]
        entries = mips.decode_words(
            linked.section_data(linked.require_section(".rodata")), f"table {label}"
        )
        assert [f"0x{value:08x}" for value in entries] == variant["linked_entries"]
        assert variant["table_differences"] == []

    assert variants["A"]["equal_words"] == 41
    assert variants["A"]["equal_entries"] == 7
    assert variants["A"]["hi16_lo16_pairs"][0]["linked_effective_address"] == "0x4788"
    assert variants["A"]["hi16_lo16_pairs"][0]["reconstructs_assigned_target"] is True
    assert variants["A"]["linked_entries"] == [
        "0x00000450",
        "0x00000468",
        "0x00000480",
        "0x00000480",
        "0x00000480",
        "0x00000480",
        "0x00000480",
    ]
    assert variants["B"]["linked_entries"] == variants["A"]["linked_entries"]
    assert variants["B"]["hi16_lo16_pairs"][0]["reconstructs_assigned_target"] is True
    assert variants["B"]["hi16_lo16_pairs"][0]["linked_effective_address"] == "0x4784"
    layout_differences = report["linker"]["layout_control_b_vs_a"]
    assert [row["word_index"] for row in layout_differences] == [10]
    assert layout_differences[0]["address"] == "0x43c"
    assert report["linker"]["generated_stubs"] is False

    # 5 HI16/LO16 pairs including shared D_000047D0
    pairs = report["hi16_lo16_pairs"]
    assert len(pairs) == 5
    assert [row["linked_effective_address"] for row in pairs] == [
        "0x4788",
        "0x47a4",
        "0x47d0",
        "0x4800",
        "0x47d0",
    ]
    shared_pairs = [row for row in pairs if row["shared_symbol"]]
    assert [(row["hi_index"], row["lo_index"], row["linked_effective_address"]) for row in shared_pairs] == [
        (21, 24, "0x47d0"),
        (33, 36, "0x47d0"),
    ]
    assert all(row["reconstructs_assigned_target"] is True for row in pairs)
    assert all(row["matches_original_effective_address"] is True for row in pairs)
    assert all(row["independent_identity_proven"] is False for row in pairs)

    # 5 R_MIPS_26 calls
    calls = report["calls"]
    assert len(calls) == 5
    assert [row["linked_target"] for row in calls] == [
        "0x2354",
        "0x8a4",
        "0x8a4",
        "0x8a4",
        "0x8a4",
    ]
    assert all(row["reconstructs_assigned_target"] is True for row in calls)
    assert all(row["matches_original_target"] is True for row in calls)
    assert all(row["independent_identity_proven"] is False for row in calls)

    # 3 original PRX .data strings (metadata & hashes only, no raw string contents)
    strings = report["original_prx"]["strings"]
    assert len(strings) == 3
    assert [row["candidate_symbol"] for row in strings] == [
        "D_000047A4",
        "D_000047D0",
        "D_00004800",
    ]
    assert [row["original_section_offset"] for row in strings] == ["0x3c", "0x68", "0x98"]
    assert strings[1]["shared_reference"] is True
    assert [pair["hi_index"] for pair in strings[1]["referenced_by_pairs"]] == [21, 33]
    for row in strings:
        assert row["original_section"] == ".data"
        assert row["nul_terminated"] is True
        assert row["within_section_bounds"] is True
        assert row["non_overlapping"] is True
        assert len(row["sha256_with_nul"]) == 64
        assert len(row["sha256_without_nul"]) == 64
        assert row["candidate_string_bytes_proven"] is False
        assert row["cross_artifact_identity"] == "UNPROVEN"

    # Controls A, B, C, D, E
    controls = report["controls"]
    assert controls["A"]["status"] == "PASS"
    assert controls["A"]["equal_words"] == 41
    assert controls["A"]["equal_entries"] == 7
    assert [row["word_index"] for row in controls["B"]["differences_vs_a"]] == [10]
    assert controls["B"]["equal_entries_vs_a"] == 7
    assert controls["B"]["effective_table_address"] == "0x4784"
    assert [row["word_index"] for row in controls["C"]["differences"]] == [24, 36]
    assert controls["C"]["equal_words"] == 39
    assert controls["C"]["equal_entries"] == 7
    assert controls["D"]["relocation_inventory_preserved"] is True
    assert [row["entry_index"] for row in controls["D"]["table_differences"]] == [0, 1]
    assert controls["D"]["equal_words"] == 41
    assert controls["E"]["relocation_inventory_preserved"] is True
    assert [row["word_index"] for row in controls["E"]["differences"]] == [0]
    assert controls["E"]["equal_entries"] == 7
    for label in ("B", "C", "D", "E"):
        assert controls[label]["detected"] is True
        assert controls[label]["promoted_to_matched"] is False
    assert controls["A"]["promoted_to_matched"] is False

    text_report = first.decode("utf-8")
    assert "http" not in text_report.lower()
    assert "C:\\" not in text_report
    assert "/mnt/c/" not in text_report
    assert "/home/" not in text_report
