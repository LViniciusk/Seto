"""Opt-in, real Metrowerks regressions for SETO-DECOMP-022 candidates."""

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
OPT_IN = "SETO_LIBTUTORIALLIST_022_REAL"

# address: (instruction words, status, matching words)
CASES = {
    0xE24: (115, "INCONCLUSIVE", 113),
    0x1D08: (59, "INCONCLUSIVE", 53),
    0x1764: (182, "NONMATCHING", 42),
}

# address: (data-reference count, locations, targets)
DATA_REFS = {
    0xE24: (1, ("INFERRED",), (None,)),
    0x1D08: (
        3,
        ("PROVEN", "PROVEN", "PROVEN"),
        ((".data", "0x34"), (".data", "0x34"), (".data", "0x80")),
    ),
    0x1764: (0, (), ()),
}

pytestmark = pytest.mark.integration

if not MODULE.is_file():
    if os.environ.get(OPT_IN) == "1":
        pytest.fail("BLOCKED: the original PRX is absent while the 022 opt-in is active")
    pytest.skip(
        "original libtutoriallist.prx is absent; the test reads private/ only",
        allow_module_level=True,
    )

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


def _target_tuple(target: object) -> tuple[str, str] | None:
    if not isinstance(target, dict):
        return None
    section = target.get("section")
    offset = target.get("offset")
    if not isinstance(section, str) or not isinstance(offset, str):
        return None
    return (section, offset)


@pytest.mark.skipif(
    os.environ.get(OPT_IN) != "1", reason=f"set {OPT_IN}=1 for real WSL2 matching"
)
def test_022_reconstructions_and_identity_limits() -> None:
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
        assert row["call_counts"].get("unknown", 0) == 0

        expected_count, expected_locations, expected_targets = DATA_REFS[address]
        references = row["data_references"]
        assert len(references) == expected_count
        assert tuple(reference["location"] for reference in references) == expected_locations
        assert tuple(
            _target_tuple(reference.get("target")) for reference in references
        ) == expected_targets

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
                build_subdir="seto022",
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

    for address, limitation_words, resolved_calls in (
        (0xE24, (42,), 21),
        (0x1D08, (2, 15, 25), 5),
    ):
        result = by_address[address]
        assert result["status"] == "INCONCLUSIVE" and result["exit_code"] == 5
        assert result["difference_count"] == 0 and result["differences"] == []
        assert result["relocation_issues"] == []
        assert result["resolved_data"] == []
        assert result["verified_decompilation"] is False
        assert len(result["resolved_calls"]) == resolved_calls
        assert len(result["limitations"]) == len(limitation_words)
        for word, limitation in zip(limitation_words, result["limitations"]):
            assert limitation.startswith(f"word {word}: HI16/LO16 data identity cannot be proven")

    render = by_address[0x1764]
    assert render["status"] == "NONMATCHING" and render["exit_code"] == 3
    assert render["difference_count"] == 140
    assert len(render["differences"]) == 64
    assert len(render["relocation_issues"]) == 32
    assert render["limitations"] == []
    assert render["verified_decompilation"] is False

    build_root_022 = triage.validated_build_root(REPO_ROOT, subdir="seto022")
    triage.ensure_build_dir(build_root_022, build_root_022)
    summary = {
        "schema_version": 1,
        "module": {"name": "libtutoriallist.prx", "sha256": module_sha},
        "attempts_per_function": 2,
        "functions": results,
    }
    triage.write_build_text(
        build_root_022 / "match-results.json",
        triage.canonical_json(summary),
        build_root_022,
    )
    triage.write_build_text(
        build_root_022 / "timings.json",
        json.dumps(
            {"measurement": "wall time for fresh compile plus strict match", "attempts": timings},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        build_root_022,
    )
