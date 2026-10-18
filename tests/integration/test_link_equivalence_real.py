"""Opt-in WSL2 integration for the real 0x4B8 compile/link comparison."""

from __future__ import annotations

import json
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from seto import elf, mips
from scripts.probe_link_equivalence import compare_word_sequences, paired_effective_address

pytestmark = pytest.mark.integration
REPO_ROOT = Path(__file__).resolve().parents[2]
REAL_OPT_IN = "SETO_LINK_EQUIVALENCE_REAL"


def test_gnu_mipsel_linker_applies_hi16_lo16_with_carry() -> None:
    required = (
        "mipsel-linux-gnu-as",
        "mipsel-linux-gnu-ld",
        "mipsel-linux-gnu-readelf",
        "mipsel-linux-gnu-objdump",
        "mipsel-linux-gnu-nm",
    )
    missing = [tool for tool in required if shutil.which(tool) is None]
    if missing:
        pytest.skip(f"GNU MIPSel integration tools are not installed: {', '.join(missing)}")

    smoke_dir = REPO_ROOT / "build/seto014/r2/integration-smoke"
    smoke_dir.mkdir(parents=True, exist_ok=True)
    source = smoke_dir / "hi-lo.s"
    object_path = smoke_dir / "hi-lo.o"
    source.write_text(
        ".set noreorder\n.text\n.globl _start\n_start:\n"
        "    lui $a0, %hi(test_symbol)\n"
        "    addiu $a0, $a0, %lo(test_symbol)\n"
        "    jr $ra\n    nop\n.data\n.globl test_symbol\n"
        "test_symbol:\n    .word 0x12345678\n",
        encoding="utf-8",
    )
    assembled = subprocess.run(
        ["mipsel-linux-gnu-as", "-32", "-march=mips2", "-o", str(object_path), str(source)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert assembled.returncode == 0, assembled.stderr
    relocatable = elf.parse(object_path)
    assert relocatable.header.e_type == elf.ET_REL
    assert [(rel.type_name, rel.symbol) for rel in relocatable.relocations_for(".text")] == [
        ("R_MIPS_HI16", "test_symbol"),
        ("R_MIPS_LO16", "test_symbol"),
    ]

    for target, expected_hi, expected_lo, expected_signed_lo in (
        (0x4830, 0x0000, 0x4830, 18480),
        (0x4834, 0x0000, 0x4834, 18484),
        (0x8004, 0x0001, 0x8004, -32764),
    ):
        script = smoke_dir / f"link-{target:x}.ld"
        output = smoke_dir / f"linked-{target:x}.elf"
        script.write_text(
            textwrap.dedent(
                f'''\
                OUTPUT_FORMAT("elf32-tradlittlemips")
                OUTPUT_ARCH(mips)
                ENTRY(_start)
                SECTIONS
                {{
                  .gnu.attributes 0 : {{ *(.gnu.attributes) }}
                  .text 0x4b8 : SUBALIGN(4) {{ *(.text) }}
                  .data 0x{target:x} : SUBALIGN(4) {{ *(.data) }}
                  .MIPS.abiflags : {{ *(.MIPS.abiflags) }}
                  .reginfo : {{ *(.reginfo) }}
                  .pdr : {{ *(.pdr) }}
                }}
                ASSERT(ADDR(.text) == 0x4b8, "text address")
                ASSERT(test_symbol == 0x{target:x}, "symbol address")
                '''
            ),
            encoding="utf-8",
        )
        linked = subprocess.run(
            [
                "mipsel-linux-gnu-ld",
                "-m",
                "elf32ltsmip",
                "-T",
                str(script),
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
        module = elf.parse(output)
        assert module.header.e_type == elf.ET_EXEC
        assert module.header.ei_class == elf.ELFCLASS32
        assert module.header.ei_data == elf.ELFDATA2LSB
        assert module.header.e_machine == elf.EM_MIPS
        assert not module.relocations
        assert not [symbol for symbol in module.symbols if symbol.shndx == elf.SHN_UNDEF and symbol.name]
        text = module.require_section(".text")
        words = mips.decode_words(module.section_data(text), str(output))
        start = next(symbol for symbol in module.symbols if symbol.name == "_start")
        assert start.value == 0x4B8
        lui, addiu = words[:2]
        assert mips.immediate(lui) == expected_hi
        assert mips.immediate(addiu) == expected_lo
        assert mips.signed_immediate(addiu) == expected_signed_lo
        assert paired_effective_address(lui, addiu) == target
        assert next(symbol for symbol in module.symbols if symbol.name == "test_symbol").value == target
        for tool_args in (
            ["mipsel-linux-gnu-readelf", "-hWr", str(output)],
            ["mipsel-linux-gnu-objdump", "-dr", str(output)],
            ["mipsel-linux-gnu-nm", "-u", str(output)],
        ):
            inspected = subprocess.run(tool_args, capture_output=True, text=True, timeout=60, check=False)
            assert inspected.returncode == 0, inspected.stderr
            if tool_args[0].endswith("-nm"):
                assert not inspected.stdout.strip()


def _run_real_report(out_path: Path) -> bytes:
    command = [
        sys.executable,
        "scripts/probe_link_equivalence.py",
        "--config",
        "config/wsl/seto.toml",
        "--prx",
        "private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx",
        "--source",
        "decomp/src/func_000004B8.c",
        "--build-dir",
        "build/seto014/r2/integration-real",
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
        timeout=900,
    )
    assert result.returncode == 0, (
        f"real link-equivalence experiment failed ({result.returncode})\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert out_path.is_file(), "real run returned success without writing its report"
    return out_path.read_bytes()


def test_real_metrowerks_prx_link_comparison_is_controlled_and_deterministic() -> None:
    if os.name == "nt" or "microsoft" not in platform.release().lower():
        pytest.skip("requires Ubuntu under WSL2; never runs the private PRX on native Windows")
    if os.environ.get(REAL_OPT_IN) != "1":
        pytest.skip(f"set {REAL_OPT_IN}=1 to opt into the WSL2 Metrowerks/PRX integration")

    required = (
        "mipsel-linux-gnu-ld",
        "mipsel-linux-gnu-readelf",
        "mipsel-linux-gnu-objdump",
        "mipsel-linux-gnu-nm",
        "file",
    )
    missing = [tool for tool in required if shutil.which(tool) is None]
    assert not missing, f"{REAL_OPT_IN}=1 but required real-link tools are missing: {missing}"
    assert (REPO_ROOT / "private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx").is_file(), (
        f"{REAL_OPT_IN}=1 but the authorized local PRX is missing"
    )

    build_root = REPO_ROOT / "build/seto014/r2"
    first_path = build_root / "integration-report-1.json"
    second_path = build_root / "integration-report-2.json"
    first = _run_real_report(first_path)
    second = _run_real_report(second_path)
    assert first == second, "canonical link-equivalence JSON differs across identical fresh runs"
    report = json.loads(first)

    assert report["experiment_status"] == "PASS"
    assert report["baseline"]["status"] == "INCONCLUSIVE"
    assert report["baseline"]["matching_words"] == 18
    assert report["baseline"]["total_words"] == 20
    assert report["promoted_to_matched"] is False
    assert report["identity_evidence"]["independently_verified"] is False
    original_path = REPO_ROOT / report["provenance"]["prx_path"]
    source_path = REPO_ROOT / report["provenance"]["source_path"]
    object_path = REPO_ROOT / report["provenance"]["fresh_object_path"]
    linker_script = REPO_ROOT / report["provenance"]["linker_script_path"]
    match_record_path = REPO_ROOT / report["compile_and_match"]["provenance_record"]
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest(original_path) == report["provenance"]["prx_sha256"]
    assert digest(source_path) == report["provenance"]["source_sha256"]
    assert digest(object_path) == report["provenance"]["fresh_object_sha256"]
    assert digest(linker_script) == report["provenance"]["linker_script_sha256"]
    match_record = json.loads(match_record_path.read_text(encoding="utf-8"))
    assert match_record["status"] == "INCONCLUSIVE"
    assert match_record["provenance"]["source_sha256"] == report["provenance"]["source_sha256"]
    assert match_record["provenance"]["object_sha256"] == report["provenance"]["fresh_object_sha256"]
    assert match_record["provenance"]["flags"] == ["-O4,p", "-sdatathreshold", "0"]
    assert report["candidate_object"]["text_section_size"] == 0x50
    assert report["candidate_object"]["function_section_offset"] == 0
    assert report["candidate_object"]["function_symbol_value"] == "0x0"

    original = elf.parse(original_path)
    original_text = original.require_section(".text")
    original_offset = 0x4B8 - original_text.addr
    original_words = mips.decode_words(
        original.section_data(original_text)[original_offset : original_offset + 0x50],
        "original PRX 0x4B8",
    )
    assert len(original_words) == 20
    assert [f"0x{word:08x}" for word in original_words] == report["original_prx"]["function_file_words"]

    for label, variant in report["linker"]["variants"].items():
        linked_path = REPO_ROOT / variant["linked_elf_path"]
        assert digest(linked_path) == variant["linked_elf_sha256"]
        linked = elf.parse(linked_path)
        assert linked.header.e_type == elf.ET_EXEC
        assert linked.header.e_machine == elf.EM_MIPS
        assert linked.header.ei_class == elf.ELFCLASS32
        assert linked.header.ei_data == elf.ELFDATA2LSB
        linked_text = linked.require_section(".text")
        assert linked_text.addr == 0x4B8
        assert linked_text.size == 0x50
        linked_words = mips.decode_words(linked.section_data(linked_text), f"linked case {label}")
        assert [f"0x{word:08x}" for word in linked_words] == variant["linked_words"]
        differences = compare_word_sequences(original_words, linked_words)
        assert differences == variant["differences"]
        assert variant["equal_words"] == 20 - len(differences)
        assert linked.relocations == ()
        assert not [sym for sym in linked.symbols if sym.shndx == elf.SHN_UNDEF and sym.name]
        assert linked.require_section(".mwcats").size == 8
        assert variant["mwcats"]["resolved_function_pointer"] == "0x4b8"
        assert variant["hi16_lo16_semantic_group"]["word_indices"] == [3, 6]
        assert paired_effective_address(linked_words[3], linked_words[6]) == int(
            variant["effective_data_address"], 16
        )
        assert variant["linked_call_targets"] == {
            "func_00000894": "0x894",
            "func_00000854": "0x854",
            "func_00002D0C": "0x2d0c",
            "func_000008A4": "0x8a4",
        }

    assert report["equivalence_claim"] in {
        "ASSUMPTION_DEPENDENT",
        "DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS",
    }

    variants = report["linker"]["variants"]
    assert variants["A"]["effective_data_address"] == "0x4830"
    assert variants["B"]["effective_data_address"] == "0x4834"
    assert variants["C"]["effective_data_address"] == "0x8004"
    assert variants["A"]["hi16_lo16_semantic_group"]["matches_original_target"] is True
    assert variants["B"]["hi16_lo16_semantic_group"]["matches_original_target"] is False
    assert variants["C"]["hi16_lo16_semantic_group"]["matches_original_target"] is False
    assert variants["C"]["hi16_immediate"] == "0x0001"
    assert variants["C"]["lo16_immediate"] == "0x8004"
    assert variants["C"]["lo16_signed"] == -32764
    assert [item["address"] for item in report["linker"]["case_b_vs_a_differences"]] == ["0x4d0"]
    assert [item["address"] for item in report["linker"]["case_c_vs_a_differences"]] == ["0x4c4", "0x4d0"]
    assert report["linker"]["generated_stubs"] is False
    assert report["linker"]["tampered_nonrelocated_negative"]["detected"] is True
    assert report["linker"]["tampered_nonrelocated_negative"]["differences"][0]["address"] == "0x4b8"
    tampered = report["linker"]["tampered_nonrelocated_negative"]
    tampered_path = REPO_ROOT / tampered["linked_elf_path"]
    tampered_object = REPO_ROOT / tampered["mutated_object_path"]
    assert digest(tampered_path) == tampered["linked_elf_sha256"]
    assert digest(tampered_object) == tampered["mutated_object_sha256"]
    tampered_module = elf.parse(tampered_path)
    tampered_text = tampered_module.require_section(".text")
    tampered_words = mips.decode_words(tampered_module.section_data(tampered_text), "tampered link")
    assert compare_word_sequences(original_words, tampered_words) == tampered["differences"]
    assert tampered["mutated_object_sha256"] != report["provenance"]["fresh_object_sha256"]
    assert report["provenance"]["fresh_object_sha256"] == digest(object_path)

    data_evidence = report["original_prx"]["data_target"]
    assert data_evidence["target"]["section"] == ".data"
    assert data_evidence["target"]["offset"] == "0xc8"
    assert data_evidence["target"]["file_offset"] == "0x4890"
    assert data_evidence["utf8"] == "/PSP/SAVEDATA/"
    data_section = original.require_section(".data")
    original_data = original.section_data(data_section)
    assert original_data[0xC8 : 0xC8 + 14] == bytes.fromhex(data_evidence["bytes_hex"])
    assert report["original_prx"]["psp_runtime_relocation_analysis"]["runtime_comparison"] == "NOT_DEMONSTRATED"
    assert "C:\\" not in first.decode("utf-8")
    assert "/mnt/c/" not in first.decode("utf-8")
    assert "/home/" not in first.decode("utf-8")
