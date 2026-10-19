"""Opt-in real Metrowerks regression for the new 019 reconstructions."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

from seto import elf
from seto.hashing import sha256_file

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = (
    REPO_ROOT
    / "private"
    / "original"
    / "PSP_GAME"
    / "USRDIR"
    / "gmodule"
    / "libtutoriallist.prx"
)
EXPECTED_SHA256 = "2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49"
OPT_IN = "SETO_LIBTUTORIALLIST_019_REAL"

pytestmark = pytest.mark.integration

if not MODULE.is_file():
    if os.environ.get(OPT_IN) == "1":
        pytest.fail("BLOCKED: the original PRX is absent while the 019 real-match opt-in is active")
    pytest.skip("original libtutoriallist.prx is absent; the test reads private/ only", allow_module_level=True)

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import triage_libtutoriallist as triage  # noqa: E402


@pytest.mark.skipif(os.environ.get(OPT_IN) != "1", reason=f"set {OPT_IN}=1 for real WSL2 matching")
def test_new_libtutoriallist_candidates_match_freshly_and_report_exact_results() -> None:
    if sys.platform != "linux":
        pytest.fail("BLOCKED: the real Metrowerks integration must run under WSL2/Linux")

    config = REPO_ROOT / "config" / "wsl" / "seto.toml"
    baseline_path = REPO_ROOT / "build" / "seto018" / "baseline.json"
    triage_path = REPO_ROOT / "build" / "seto018" / "triage.json"
    ghidra_path = REPO_ROOT / "build" / "seto018" / triage.GHIDRA_EVIDENCE_NAME
    for path in (config, baseline_path, triage_path, ghidra_path):
        if not path.is_file() or path.is_symlink():
            pytest.fail(f"BLOCKED: required 018 input is absent or unsafe: {path.name}")

    module_sha = sha256_file(MODULE)
    assert module_sha == EXPECTED_SHA256
    baseline = triage.build_baseline(elf.parse(MODULE), module_sha)
    stored_baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert triage.canonical_json(stored_baseline) == triage.canonical_json(baseline)
    build_root_018 = triage.validated_build_root(REPO_ROOT, subdir="seto018")
    ghidra = triage._load_ghidra_report(ghidra_path, build_root_018)
    rebuilt_triage = triage.build_triage(baseline, ghidra)
    stored_triage = json.loads(triage_path.read_text(encoding="utf-8"))
    assert triage.canonical_json(stored_triage) == triage.canonical_json(rebuilt_triage)

    selected = {0x7A4: 83, 0xFF0: 153}
    by_start = {
        int(str(row["start"]), 16): row
        for row in rebuilt_triage["functions"]
        if isinstance(row, dict)
    }
    for address, words in selected.items():
        row = by_start[address]
        assert row["instruction_count"] == words
        assert row["ghidra"]["boundary_status"] == "EXACT"
        assert row["data_references"] == []
        assert row["call_counts"].get("unknown", 0) == 0

    results: list[dict[str, object]] = []
    timings: list[dict[str, object]] = []
    for address, expected_words in selected.items():
        name = triage.mips.function_name(address)
        source = REPO_ROOT / "decomp" / "src" / "libtutoriallist" / f"{name}.c"
        attempts: list[dict[str, object]] = []
        for attempt in (1, 2):
            started = time.perf_counter()
            result = triage.run_real_match(
                address,
                source,
                attempt=attempt,
                expected_total_words=expected_words,
                config_value=config,
                build_subdir="seto019",
            )
            timings.append(
                {
                    "function": name,
                    "attempt": attempt,
                    "compile_and_match_seconds": round(time.perf_counter() - started, 3),
                }
            )
            attempts.append(result)
        first, second = attempts
        assert first == second, f"fresh {name} source/object/match evidence changed"
        results.append(first)

    by_address = {int(str(result["address"]), 16): result for result in results}
    matched = by_address[0x7A4]
    assert matched["status"] == "MATCHED" and matched["exit_code"] == 0
    assert matched["matching_words"] == matched["total_words"] == 83
    assert matched["difference_count"] == 0 and matched["differences"] == []
    assert matched["relocation_issues"] == [] and matched["limitations"] == []
    assert matched["verified_decompilation"] is True

    rectangle = by_address[0xFF0]
    assert rectangle["status"] == "MATCHED" and rectangle["exit_code"] == 0
    assert rectangle["matching_words"] == rectangle["total_words"] == 153
    assert rectangle["difference_count"] == 0 and rectangle["differences"] == []
    assert rectangle["relocation_issues"] == [] and rectangle["limitations"] == []
    assert rectangle["verified_decompilation"] is True

    build_root_019 = triage.validated_build_root(REPO_ROOT, subdir="seto019")
    triage.ensure_build_dir(build_root_019, build_root_019)
    summary = {
        "schema_version": 1,
        "module": {"name": "libtutoriallist.prx", "sha256": module_sha},
        "functions": results,
        "attempts_per_function": 2,
    }
    triage.write_build_text(
        build_root_019 / "match-results.json",
        triage.canonical_json(summary),
        build_root_019,
    )
    triage.write_build_text(
        build_root_019 / "timings.json",
        json.dumps(
            {"measurement": "wall time for fresh compile plus strict match", "attempts": timings},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        build_root_019,
    )
