"""Read-only PRX validation and opt-in Metrowerks matches for module 018."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from seto import elf, mips
from seto.hashing import sha256_file

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = REPO_ROOT / "private" / "original" / "PSP_GAME" / "USRDIR" / "gmodule" / "libtutoriallist.prx"
EXPECTED_SHA256 = "2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49"
OPT_IN = "SETO_LIBTUTORIALLIST_REAL"
pytestmark = pytest.mark.integration

if not MODULE.is_file():
    if os.environ.get(OPT_IN) == "1":
        pytest.fail("BLOCKED: the real PRX is absent while the 018 real-match opt-in is active")
    pytest.skip("original libtutoriallist.prx is absent; the test reads private/ only", allow_module_level=True)

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import triage_libtutoriallist as triage  # noqa: E402


def test_real_prx_structural_baseline_is_complete_and_reproducible() -> None:
    module_sha256 = sha256_file(MODULE)
    triage.verify_module_sha256(module_sha256)
    module = elf.parse(MODULE)
    baseline = triage.build_baseline(module, module_sha256)

    assert module.is_prx and module.is_mips
    assert baseline["module"]["sha256"] == EXPECTED_SHA256
    assert baseline["elf"]["text"]["addr"] == 0
    assert baseline["elf"]["text"]["size"] == 9648
    assert baseline["elf"]["section_count"] == 25
    assert baseline["elf"]["program_header_count"] == 1
    assert baseline["elf"]["symbol_count"] == 0
    assert len(baseline["functions"]) == 25
    assert baseline["relocations"]["count"] == 474
    assert baseline["relocations"]["psp_inventory"]["complete"] is True
    assert baseline["imports"]["call_kind_counts"] == {"import": 205, "local": 32}
    assert baseline["imports"]["unknown_call_count"] == 0
    assert baseline["imports"]["table_count"] == 1
    assert baseline["imports"]["stub_count"] == 1245
    assert baseline["imports"]["tables"][0]["library"] == "libehsys"
    assert baseline["layout"]["validation_issues"] == []

    by_start = {int(str(function["start"]), 16): function for function in baseline["functions"]}
    expected_selected_imports = {
        0x6E8: {
            ("0x71c", "libehsys", "0x10F3BB61", "0x2610"),
            ("0x724", "libehsys", "0xB2B9FEFA", "0x37e0"),
            ("0x734", "libehsys", "0x85F89FE8", "0x3768"),
            ("0x748", "libehsys", "0x7187E0F0", "0x3758"),
            ("0x750", "libehsys", "0x89812D8A", "0x3770"),
            ("0x75c", "libehsys", "0xF462EE6E", "0x3aa8"),
            ("0x76c", "libehsys", "0x09794DF0", "0x3bc8"),
            ("0x788", "libehsys", "0x5CBB9E43", "0x3c70"),
        },
        0x1A3C: {("0x1ac0", "libehsys", "0xB89D38DC", "0x42a0")},
        0x1E94: set(),
    }
    for address, expected in expected_selected_imports.items():
        actual = {
            (
                call["address"],
                call["import"]["library"],
                call["import"]["nid"],
                call["import"]["stub_address"],
            )
            for call in by_start[address]["calls"]
            if call.get("import")
        }
        assert actual == expected, f"import identities changed for {mips.function_name(address)}"
    assert triage.canonical_json(baseline) == triage.canonical_json(
        triage.build_baseline(elf.parse(MODULE), module_sha256)
    )


@pytest.mark.skipif(os.environ.get(OPT_IN) != "1", reason=f"set {OPT_IN}=1 for real WSL2 matching")
def test_selected_real_matches_run_fresh_twice_and_preserve_reports() -> None:
    if sys.platform != "linux":
        pytest.fail("BLOCKED: the real Metrowerks integration must run under WSL2/Linux")

    build_root = REPO_ROOT / "build" / "seto018"
    config = REPO_ROOT / "config" / "wsl" / "seto.toml"
    baseline_path = build_root / "baseline.json"
    triage_path = build_root / "triage.json"
    ghidra_path = build_root / triage.GHIDRA_EVIDENCE_NAME
    for path in (config, baseline_path, triage_path, ghidra_path):
        if not path.is_file() or path.is_symlink():
            pytest.fail(f"BLOCKED: required local integration input is absent or unsafe: {path.name}")

    module_sha256 = sha256_file(MODULE)
    triage.verify_module_sha256(module_sha256)
    module = elf.parse(MODULE)
    baseline = triage.build_baseline(module, module_sha256)
    stored_baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    if triage.canonical_json(stored_baseline) != triage.canonical_json(baseline):
        pytest.fail("BLOCKED: generated baseline does not match the current PRX")

    ghidra_report = triage._load_ghidra_report(ghidra_path, triage.validated_build_root(REPO_ROOT, subdir="seto018"))
    regenerated_triage = triage.build_triage(baseline, ghidra_report)
    stored_triage = json.loads(triage_path.read_text(encoding="utf-8"))
    if triage.canonical_json(stored_triage) != triage.canonical_json(regenerated_triage):
        pytest.fail("BLOCKED: generated triage does not match the current baseline/Ghidra evidence")
    if stored_triage["selected_count"] < 3:
        pytest.fail("BLOCKED: fewer than three functions were selected from the evidence")

    results: list[dict[str, object]] = []
    for selected in stored_triage["selected_functions"]:
        address = int(str(selected["start"]), 16)
        source = REPO_ROOT / "decomp" / "src" / "libtutoriallist" / f"{selected['name']}.c"
        first = triage.run_real_match(
            address,
            source,
            attempt=1,
            expected_total_words=int(selected["instruction_count"]),
            config_value=config,
        )
        second = triage.run_real_match(
            address,
            source,
            attempt=2,
            expected_total_words=int(selected["instruction_count"]),
            config_value=config,
        )
        comparison_keys = ["status", "exit_code", "source_sha256", "object_sha256"]
        if first["status"] == "ERROR":
            comparison_keys.extend(("phase", "report_written", "error"))
        else:
            comparison_keys.extend(
                (
                    "matching_words",
                    "total_words",
                    "difference_count",
                    "differences",
                    "relocation_issues",
                    "limitations",
                    "resolved_calls",
                    "resolved_data",
                )
            )
        for key in comparison_keys:
            assert first[key] == second[key], f"fresh {selected['name']} runs differ in {key}"
        if first["status"] == "ERROR":
            pytest.fail(f"unexpected matcher error for {selected['name']}: {first['error']}")
        else:
            assert first["status"] in ("MATCHED", "NONMATCHING", "INCONCLUSIVE")
        results.append(first)

    by_address = {int(str(result["address"]), 16): result for result in results}
    matched = by_address[0x6E8]
    assert matched["status"] == "MATCHED" and matched["exit_code"] == 0
    assert matched["matching_words"] == matched["total_words"] == 47
    assert matched["difference_count"] == 0
    assert matched["differences"] == []
    assert matched["relocation_issues"] == []
    assert matched["limitations"] == []
    assert matched["verified_decompilation"] is True

    buffer_clear = by_address[0x1A3C]
    assert buffer_clear["status"] == "MATCHED" and buffer_clear["exit_code"] == 0
    assert buffer_clear["matching_words"] == buffer_clear["total_words"] == 52
    assert buffer_clear["difference_count"] == 0
    assert buffer_clear["differences"] == []
    assert buffer_clear["relocation_issues"] == []
    assert buffer_clear["limitations"] == []
    assert buffer_clear["verified_decompilation"] is True

    # SETO-DECOMP-020 recorded this search as NONMATCHING 7/31 with 24
    # differences; SETO-DECOMP-021 recovered the do/while plus wrapper form and
    # the tracked source now matches, so the baseline expectation moves with
    # the proven result while the historical record stays in
    # docs/decomp-progress.md.
    search = by_address[0x1E94]
    assert search["status"] == "MATCHED" and search["exit_code"] == 0
    assert search["matching_words"] == search["total_words"] == 31
    assert search["difference_count"] == 0
    assert search["differences"] == []
    assert search["relocation_issues"] == []
    assert search["limitations"] == []
    assert search["verified_decompilation"] is True

    summary = {
        "schema_version": 1,
        "module": {"name": "libtutoriallist.prx", "sha256": module_sha256},
        "attempts_per_function": 2,
        "functions": results,
    }
    triage.ensure_build_dir(build_root, triage.validated_build_root(REPO_ROOT, subdir="seto018"))
    triage.write_build_text(build_root / "match-results.json", triage.canonical_json(summary), triage.validated_build_root(REPO_ROOT, subdir="seto018"))

    assert sha256_file(MODULE) == EXPECTED_SHA256
