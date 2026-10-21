"""Opt-in WSL2/Metrowerks comparison evidence for SETO-DECOMP-024."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

from seto import elf, mips
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
OPT_IN = "SETO_LIBTUTORIALLIST_024_REAL"
WORDS = {0x1DF4: 36, 0x1B70: 42}

pytestmark = pytest.mark.integration

if not MODULE.is_file():
    if os.environ.get(OPT_IN) == "1":
        pytest.fail("BLOCKED: original libtutoriallist.prx is absent with the 024 opt-in active")
    pytest.skip("original libtutoriallist.prx is absent; this test reads private/ only", allow_module_level=True)

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import triage_libtutoriallist as triage  # noqa: E402


STABLE_KEYS = (
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


@pytest.mark.skipif(
    os.environ.get(OPT_IN) != "1", reason=f"set {OPT_IN}=1 for real WSL2 matching"
)
@pytest.mark.parametrize("address", (0x1DF4, 0x1B70))
def test_024_target_blocks_are_compared_and_identity_stays_strict(address: int) -> None:
    if sys.platform != "linux":
        pytest.fail("BLOCKED: the real Metrowerks integration must run under WSL2/Linux")

    config = REPO_ROOT / "config" / "wsl" / "seto.toml"
    if not config.is_file() or config.is_symlink():
        pytest.fail("BLOCKED: the WSL Metrowerks configuration is absent or unsafe")
    module_sha = sha256_file(MODULE)
    assert module_sha == EXPECTED_SHA256
    module = elf.parse(MODULE)
    baseline = triage.build_baseline(module, module_sha)
    row = next(item for item in baseline["functions"] if int(item["start"], 16) == address)
    assert row["instruction_count"] == WORDS[address]

    build_root = triage.validated_build_root(REPO_ROOT, subdir="seto024")
    name = triage.mips.function_name(address)
    source = REPO_ROOT / "decomp" / "src" / "libtutoriallist" / f"{name}.c"
    attempts = []
    timings = []
    for attempt in (1, 2):
        started = time.perf_counter()
        result = triage.run_real_match(
            address,
            source,
            attempt=attempt,
            expected_total_words=WORDS[address],
            config_value=config,
            build_subdir="seto024",
        )
        timings.append({
            "function": name,
            "attempt": attempt,
            "compile_and_match_seconds": round(time.perf_counter() - started, 3),
        })
        attempts.append(result)

    first, second = attempts
    assert {key: first.get(key) for key in STABLE_KEYS} == {
        key: second.get(key) for key in STABLE_KEYS
    }, f"fresh {name} results or hashes changed"
    assert first["status"] in ("MATCHED", "INCONCLUSIVE", "NONMATCHING")
    assert first["total_words"] == WORDS[address]
    assert first["verified_decompilation"] is (first["status"] == "MATCHED")
    assert first["status"] == "NONMATCHING"
    expected = {
        # The measured R2 baseline is deliberately retained until a source
        # variant yields a full comparison; these are not equivalence claims.
        0x1DF4: (19, 11, 3, 2),
        0x1B70: (5, 30, 8, 2),
    }[address]
    matching_words, differences, relocation_issue_count, limitation_count = expected
    assert first["matching_words"] == matching_words
    assert first["difference_count"] == differences
    assert len(first["differences"]) == differences
    assert len(first["relocation_issues"]) == relocation_issue_count
    assert len(first["limitations"]) == limitation_count
    assert first["resolved_data"] == []
    assert first["verified_decompilation"] is False

    triage.ensure_build_dir(build_root, build_root)
    results_path = build_root / f"{name}-024-results.json"
    triage.write_build_text(
        results_path,
        triage.canonical_json({
            "schema_version": 1,
            "module": {"name": "libtutoriallist.prx", "sha256": module_sha},
            "function": name,
            "attempts": attempts,
            "timings": timings,
        }),
        build_root,
    )
