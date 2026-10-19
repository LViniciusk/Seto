"""Opt-in, real Metrowerks regressions for SETO-DECOMP-020 candidates."""

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
OPT_IN = "SETO_LIBTUTORIALLIST_020_REAL"
CASES = {
    0x1A3C: (52, "MATCHED", 52),
    0xFF0: (153, "MATCHED", 153),
    # SETO-DECOMP-021 recovered the original do/while plus wrapper-guard form;
    # the 020 historical 7/31 result stays recorded in docs/decomp-progress.md.
    0x1E94: (31, "MATCHED", 31),
}

pytestmark = pytest.mark.integration

if not MODULE.is_file():
    if os.environ.get(OPT_IN) == "1":
        pytest.fail("BLOCKED: the original PRX is absent while the 020 opt-in is active")
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
def test_020_reconstructions_match_freshly_and_preserve_the_search_baseline() -> None:
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
                build_subdir="seto020",
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
    for address in (0x1A3C, 0xFF0):
        result = by_address[address]
        assert result["status"] == "MATCHED" and result["exit_code"] == 0
        assert result["difference_count"] == 0 and result["differences"] == []
        assert result["relocation_issues"] == [] and result["limitations"] == []
        assert result["verified_decompilation"] is True

    # SETO-DECOMP-020 recorded 7/31 with 24 differences here; SETO-DECOMP-021
    # recovered the original do/while plus wrapper-guard form, and the fresh
    # evidence below is the proven result. The historical numbers stay in
    # docs/decomp-progress.md.
    search = by_address[0x1E94]
    assert search["status"] == "MATCHED" and search["exit_code"] == 0
    assert search["matching_words"] == search["total_words"] == 31
    assert search["difference_count"] == 0 and search["differences"] == []
    assert search["relocation_issues"] == [] and search["limitations"] == []
    assert search["verified_decompilation"] is True

    build_root_020 = triage.validated_build_root(REPO_ROOT, subdir="seto020")
    triage.ensure_build_dir(build_root_020, build_root_020)
    summary = {
        "schema_version": 1,
        "module": {"name": "libtutoriallist.prx", "sha256": module_sha},
        "attempts_per_function": 2,
        "functions": results,
    }
    triage.write_build_text(
        build_root_020 / "match-results.json",
        triage.canonical_json(summary),
        build_root_020,
    )
    triage.write_build_text(
        build_root_020 / "timings.json",
        json.dumps(
            {"measurement": "wall time for fresh compile plus strict match", "attempts": timings},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        build_root_020,
    )
