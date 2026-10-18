"""Integration tests for the SETO-DECOMP-017 integrated module reconstruction & equivalence.

Two layers of integration verification:
1. A GNU MIPSel integration test (without private PRX or Metrowerks compiler):
   assembles 15 synthetic MIPS candidate objects with exact sizes, a representative
   subset of local and import calls, 2 co-linked jump tables in .rodata, and .mwcats metadata.
   Links them via mipsel-linux-gnu-ld under the 0x0-0x7F4 layout with the 0x84 fragment,
   validating the integrated linking pipeline and relocation resolution.
2. An opt-in WSL2 test (SETO_INTEGRATED_MODULE_REAL=1):
   compiles fresh all 15 candidate functions with Metrowerks, links them into a single
   ELF, compares the full 509 words and 13 jump table entries against the authorized local
   libhtml_view.prx, runs Controls A-E, and proves byte-for-byte determinism across two runs.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
for _p in (REPO_ROOT, REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import pytest

import scripts.probe_integrated_module_equivalence as probe
from scripts.probe_common import ensure_build_dir, validated_build_root, write_build_text
from seto import elf, mips

pytestmark = pytest.mark.integration
REAL_OPT_IN = "SETO_INTEGRATED_MODULE_REAL"


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


def _assemble_synthetic_candidate(
    work_dir: Path,
    c_name: str,
    addr: int,
    total_w: int,
    build_root: Path,
    *,
    has_rodata_entries: tuple[int, ...] | None = None,
    rodata_sym: str | None = None,
    local_calls: Sequence[str] = (),
    import_calls: Sequence[str] = (),
) -> Path:
    """Assemble a synthetic object conforming to the function's size, calls, and rodata."""
    func_name = mips.function_name(addr)
    s_path = work_dir / f"{func_name}.s"
    obj_path = work_dir / f"{func_name}.o"

    lines = [
        ".set noreorder",
        ".set noat",
        ".text",
        f".globl {func_name}",
        f".type {func_name}, @function",
        f"{func_name}:",
    ]

    # Generate instructions to match total_w
    instr_count = 0
    # Add local calls
    for callee in local_calls:
        lines.append(f"    jal {callee}")
        lines.append("    nop")
        instr_count += 2
    # Add import calls
    for imp in import_calls:
        lines.append(f"    jal {imp}")
        lines.append("    nop")
        instr_count += 2

    # Pad with nops or return
    if instr_count < total_w - 2:
        for _ in range(total_w - 2 - instr_count):
            lines.append("    nop")
    lines.append("    jr $ra")
    lines.append("    nop")
    lines.append(f".size {func_name}, . - {func_name}")

    if has_rodata_entries and rodata_sym:
        lines.append('.section .rodata,"a",@progbits')
        lines.append(".align 2")
        lines.append(f'.type "{rodata_sym}", @object')
        lines.append(f'.size "{rodata_sym}", {len(has_rodata_entries) * 4}')
        lines.append(f'"{rodata_sym}":')
        for off in has_rodata_entries:
            lines.append(f"    .word {func_name} + 0x{off:x}")

    # .mwcats metadata: (size << 16) | category tag, then the relocated function pointer
    lines.append('.section .mwcats,"",@progbits')
    lines.append(".align 2")
    lines.append(f"    .word 0x{((total_w * 4) << 16) | probe.MWCATS_FUNCTION_TAG:x}")
    lines.append(f"    .word {func_name}")

    write_build_text(s_path, "\n".join(lines) + "\n", build_root)
    proc = subprocess.run(
        ["mipsel-linux-gnu-as", "-32", "-march=mips2", "-no-pad-sections", "-o", str(obj_path), str(s_path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, f"as failed for {func_name}: {proc.stderr}"
    return obj_path


def test_gnu_mipsel_synthetic_whole_module_link() -> None:
    """Verify integrated link of all 15 objects and the 0x84 fragment via GNU ld without private/."""
    _require_gnu_tools()
    build_root = validated_build_root(REPO_ROOT, subdir="seto017")
    work_dir = build_root / "gnu-synthetic-module"
    ensure_build_dir(work_dir, build_root)

    cases = probe.ordered_inventory()
    objects: list[Path] = []

    for addr, c_name, _status, _mw, total_w in cases:
        func_name = mips.function_name(addr)
        has_rodata = None
        rodata_sym = None
        local_c = []
        import_c = []

        if func_name == "func_0000008C":
            local_c = ["func_00000134"]
            import_c = ["func_00002F6C"]
        elif func_name == "func_0000039C":
            has_rodata = probe.TABLE_39C_EXPECTED_OFFSETS
            rodata_sym = "@13"
            import_c = ["func_00002364"]
        elif func_name == "func_00000414":
            has_rodata = probe.TABLE_414_EXPECTED_OFFSETS
            rodata_sym = "@15"
            import_c = ["func_00002354"]
        elif func_name == "func_00000000":
            # References fragment symbol func_00000084
            local_c = ["func_00000034", "func_00000084"]
            import_c = ["func_00001F04"]

        obj_path = _assemble_synthetic_candidate(
            work_dir,
            c_name,
            addr,
            total_w,
            build_root,
            has_rodata_entries=has_rodata,
            rodata_sym=rodata_sym,
            local_calls=local_c,
            import_calls=import_c,
        )
        objects.append(obj_path)

    # Generate linker script
    script_text = probe.generate_linker_script(cases, rodata_address=probe.RODATA_START)
    script_path = work_dir / "synthetic_module.ld"
    write_build_text(script_path, script_text, build_root)

    out_elf = work_dir / "synthetic_linked.elf"
    # Provide all 46 controlled symbols
    controlled = dict(probe.CONTROLLED_IMPORTS)
    controlled.update(probe.CONTROLLED_DATA_SYMBOLS)

    cmd = [
        "mipsel-linux-gnu-ld",
        "-EL",
        "-m",
        "elf32ltsmip",
        "-T",
        str(script_path),
        "-o",
        str(out_elf),
        *[f"--defsym={sym}=0x{addr:x}" for sym, addr in sorted(controlled.items())],
        *[str(obj) for obj in objects],
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    assert res.returncode == 0, f"ld failed: {res.stderr}"
    assert out_elf.is_file()

    # Parse and validate linked structure
    linked_mod = elf.parse(out_elf)
    assert linked_mod.header.e_type == elf.ET_EXEC
    assert linked_mod.header.e_machine == elf.EM_MIPS

    sec_text, sec_rodata = probe.validate_linked_structure(
        linked_mod, label="gnu-synthetic", expected_cases=cases
    )
    assert sec_text.addr == 0x0
    assert sec_text.size == 0x7F4
    assert sec_rodata.addr == 0x4770
    assert sec_rodata.size == 0x34

    # Validate fragment words at 0x84
    text_words = mips.decode_words(linked_mod.section_data(sec_text), "synthetic text")
    assert len(text_words) == probe.TEXT_WORDS
    assert text_words[0x84 // 4] == probe.FRAGMENT_WORDS[0]
    assert text_words[(0x84 // 4) + 1] == probe.FRAGMENT_WORDS[1]

    # Validate 13 table entries
    table_words = mips.decode_words(linked_mod.section_data(sec_rodata), "synthetic rodata")
    assert len(table_words) == probe.TOTAL_TABLE_ENTRIES
    # First 6 entries for 0x39C
    assert tuple(table_words[:6]) == probe.TABLE_39C_EXPECTED_TARGETS
    # Next 7 entries for 0x414
    assert tuple(table_words[6:]) == probe.TABLE_414_EXPECTED_TARGETS


def _run_real_report(out_path: Path) -> bytes:
    cmd = [
        sys.executable,
        "scripts/probe_integrated_module_equivalence.py",
        "--config",
        "config/wsl/seto.toml",
        "--prx",
        "private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx",
        "--build-dir",
        "build/seto017/integration-real",
        "--out",
        out_path.relative_to(REPO_ROOT).as_posix(),
    ]
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    assert proc.returncode in (0, probe.DIVERGENCE_EXIT_CODE), (
        f"real probe exited {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    assert out_path.is_file(), "probe finished without writing output report"
    return out_path.read_bytes()


def test_real_metrowerks_prx_integrated_module_equivalence_is_controlled_and_deterministic() -> None:
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
    missing = [t for t in required if shutil.which(t) is None]
    assert not missing, f"{REAL_OPT_IN}=1 but required tools missing: {missing}"
    prx_file = REPO_ROOT / "private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx"
    assert prx_file.is_file(), f"{REAL_OPT_IN}=1 but private PRX not found"

    build_root = validated_build_root(REPO_ROOT, subdir="seto017")
    integ_dir = REPO_ROOT / "build/seto017/integration-real"
    ensure_build_dir(integ_dir, build_root)

    first_path = integ_dir / "report-1.json"
    second_path = integ_dir / "report-2.json"
    first = _run_real_report(first_path)
    second = _run_real_report(second_path)
    assert first == second, "canonical integrated JSON differs across identical fresh runs"

    report = json.loads(first)
    assert report["module"] == "libhtml_view.prx"
    assert report["experiment_status"] in ("PASS", "DIVERGENCE")
    assert report["equivalence_claim"] in (
        "ASSUMPTION_DEPENDENT",
        "DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS",
    )
    assert report["independent_identity_proven"] is False
    assert report["promoted_to_matched"] is False
    assert report["runtime_comparison"] == "NOT_DEMONSTRATED"

    # Summary
    summary = report["summary"]
    assert summary["total_text_words"] == 509
    assert summary["c_reconstructed_words"] == 507
    assert summary["unreconstructed_fragment_words"] == 2
    assert summary["total_table_entries"] == 13
    assert summary["functions_total"] == 15
    assert summary["functions_matched"] == 7
    assert summary["functions_inconclusive"] == 8
    assert summary["functions_nonmatching"] == 0
    assert summary["total_calls"] == 72
    assert summary["local_calls"] == 22
    assert summary["import_calls"] == 50

    # Fragment 0x84
    frag = report["fragment_0x84"]
    assert frag["address"] == "0x84"
    assert frag["classification"] == "ORIGINAL_UNRECONSTRUCTED_FRAGMENT"
    assert frag["verified_c_decompilation"] is False
    assert frag["layout_symbol"] == "func_00000084"
    assert frag["matches_original_prx"] is True

    # Controls
    controls = report["controls"]
    if report["experiment_status"] == "PASS":
        for label in ("A", "B", "C", "D", "E"):
            assert controls[label]["status"] == "PASS"
            assert controls[label]["detected"] is True
            assert controls[label]["promoted_to_matched"] is False
    else:
        assert controls["A"]["status"] == "DIVERGENCE"
        for label in ("B", "C", "D", "E"):
            assert controls[label]["status"] == "NOT_RUN"
            assert controls[label]["detected"] is False

    # Path safety & sanitization
    text_content = first.decode("utf-8")
    assert "C:\\" not in text_content
    assert "/mnt/c/" not in text_content
    assert "/home/" not in text_content
