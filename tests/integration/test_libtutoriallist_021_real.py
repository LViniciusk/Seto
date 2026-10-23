"""Opt-in, real Metrowerks regressions for SETO-DECOMP-021 candidates."""

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
OPT_IN = "SETO_LIBTUTORIALLIST_021_REAL"
CASES = {
    0x1254: (163, "MATCHED", 163),
    0x1E94: (31, "MATCHED", 31),
    0x14E0: (161, "MATCHED", 161),
    0x1764: (182, "NONMATCHING", 42),
}

pytestmark = pytest.mark.integration

if not MODULE.is_file():
    if os.environ.get(OPT_IN) == "1":
        pytest.fail("BLOCKED: the original PRX is absent while the 021 opt-in is active")
    pytest.skip("original libtutoriallist.prx is absent; the test reads private/ only", allow_module_level=True)

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import triage_libtutoriallist as triage  # noqa: E402


def _stable_result(result: dict[str, object]) -> dict[str, object]:
    keys = (
        "function",
        "address",
        "status",
        "exit_code",
        "module_sha256",
        "source_sha256",
        "object_sha256",
        "matching_words",
        "total_words",
        "difference_count",
        "differences",
        "relocation_issues",
        "limitations",
        "resolved_calls",
        "resolved_data",
        "verified_decompilation",
    )
    return {key: result.get(key) for key in keys}


@pytest.mark.skipif(os.environ.get(OPT_IN) != "1", reason=f"set {OPT_IN}=1 for real WSL2 matching")
def test_021_reconstructions_match_freshly_and_preserve_the_search_baseline() -> None:
    if sys.platform != "linux":
        pytest.fail("BLOCKED: the real Metrowerks integration must run under WSL2/Linux")

    config = REPO_ROOT / "config" / "wsl" / "seto.toml"
    try:
        baseline_path, triage_path, ghidra_path = triage.ensure_018_reports(REPO_ROOT)
    except triage.ProbeError as exc:
        pytest.fail(f"BLOCKED: {exc}")
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

    by_start = {
        int(str(row["start"]), 16): row
        for row in rebuilt_triage["functions"]
        if isinstance(row, dict)
    }
    for address, (words, _status, _matched) in CASES.items():
        row = by_start[address]
        assert row["instruction_count"] == words
        assert row["ghidra"]["boundary_status"] == "EXACT"
        assert row["data_references"] == []
        assert row["call_counts"].get("unknown", 0) == 0

    results: list[dict[str, object]] = []
    timings: list[dict[str, object]] = []
    for address, (words, expected_status, expected_matches) in CASES.items():
        name = triage.mips.function_name(address)
        source = REPO_ROOT / "decomp" / "src" / "libtutoriallist" / f"{name}.c"
        attempts: list[dict[str, object]] = []
        for attempt in (1, 2):
            started = time.perf_counter()
            result = triage.run_real_match(
                address,
                source,
                attempt=attempt,
                expected_total_words=words,
                config_value=config,
                build_subdir="seto021",
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
        assert _stable_result(first) == _stable_result(second), f"fresh {name} evidence changed"
        assert first["status"] == expected_status
        assert first["matching_words"] == expected_matches
        assert first["total_words"] == words
        results.append(first)

    by_address = {int(str(row["address"]), 16): row for row in results}
    for address in (0x1254, 0x1E94, 0x14E0):
        result = by_address[address]
        assert result["status"] == "MATCHED" and result["exit_code"] == 0
        assert result["difference_count"] == 0 and result["differences"] == []
        assert result["relocation_issues"] == [] and result["limitations"] == []
        assert result["verified_decompilation"] is True

    render = by_address[0x1764]
    assert render["status"] == "NONMATCHING" and render["exit_code"] == 3
    assert render["difference_count"] == 140
    assert len(render["differences"]) == 64
    assert len(render["relocation_issues"]) == 32
    assert render["limitations"] == []
    assert render["verified_decompilation"] is False

    build_root_021 = triage.validated_build_root(REPO_ROOT, subdir="seto021")
    triage.ensure_build_dir(build_root_021, build_root_021)
    summary = {
        "schema_version": 1,
        "module": {"name": "libtutoriallist.prx", "sha256": module_sha},
        "attempts_per_function": 2,
        "functions": results,
    }
    triage.write_build_text(
        build_root_021 / "match-results.json",
        triage.canonical_json(summary),
        build_root_021,
    )
    triage.write_build_text(
        build_root_021 / "timings.json",
        json.dumps(
            {"measurement": "wall time for fresh compile plus strict match", "attempts": timings},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        build_root_021,
    )
