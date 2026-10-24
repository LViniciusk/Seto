"""Opt-in real EBOOT/MWCC regression checks for SETO-DECOMP-036."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from seto import elf
from seto.hashing import sha256_file
from eboot_035_progress import BASELINE_DIFFERENCE_INDICES, assert_match_progress

REPO_ROOT = Path(__file__).resolve().parents[2]
EBOOT = REPO_ROOT / "private" / "decrypted" / "ULUS10136_EBOOT.elf"
EXPECTED_EBOOT_SHA256 = "d4d0efc3d6c49a7ba8142adbd316ed006a3035a572169e9ef04c6cd0daba7a91"
OPT_IN = "SETO_EBOOT_036_REAL"

pytestmark = pytest.mark.integration

if not EBOOT.is_file():
    if os.environ.get(OPT_IN) == "1":
        pytest.fail(f"BLOCKED: {EBOOT} is absent while {OPT_IN}=1")
    pytest.skip("local PPSSPP EBOOT dump is absent; this test reads private/", allow_module_level=True)


@pytest.mark.skipif(os.environ.get(OPT_IN) != "1", reason=f"set {OPT_IN}=1 for MWCC 036 integration")
def test_036_matching_recovery_and_baseline_preservation() -> None:
    if sys.platform != "linux":
        pytest.fail("BLOCKED: configured Metrowerks/wibo integration must run under WSL2/Linux")
    assert sha256_file(EBOOT.resolve(strict=True)) == EXPECTED_EBOOT_SHA256

    build_root = REPO_ROOT / "build" / "seto036" / "integration"
    build_root.mkdir(parents=True, exist_ok=True)
    match_script = REPO_ROOT / "scripts" / "match_function.py"
    config = REPO_ROOT / "config" / "wsl" / "seto.toml"

    # Preserve the already-certified 15/15 production function using the full 035 integration.
    env = os.environ.copy()
    env["SETO_EBOOT_035_REAL"] = "1"
    regression = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/integration/test_eboot_035_real.py", "-q"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=600, check=False,
    )
    assert regression.returncode == 0, regression.stdout + regression.stderr

    source = REPO_ROOT / "decomp" / "src" / "eboot" / "func_0003643C.c"
    attempts = []
    for number in (1, 2):
        out_dir = build_root / f"attempt-{number}"
        out_dir.mkdir(parents=True, exist_ok=True)
        run = subprocess.run(
            [sys.executable, str(match_script), "--config", str(config), "--prx", str(EBOOT),
             "--function", "0x3643C", "--size", "168", "--source", str(source),
             "--out", str(out_dir), "--json"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=360, check=False,
        )
        assert run.returncode == 0, run.stdout + run.stderr
        payload = json.loads(run.stdout)
        comparison = payload["match"]
        assert payload["status"] == comparison["status"] == "MATCHED"
        assert payload["verified_decompilation"] is True
        assert comparison["total_words"] == comparison["matching_words"] == 42
        assert comparison["difference_count"] == 0 and comparison["differences"] == []
        assert comparison["limitations"] == [] and comparison["relocation_issues"] == []
        assert comparison["resolved_calls"]
        assert_match_progress(
            payload,
            total_words=42,
            baseline_matching_words=26,
            baseline_difference_indices=BASELINE_DIFFERENCE_INDICES[0x3643C],
        )
        object_path = out_dir / f"{source.stem}.o"
        parsed = elf.parse(object_path)
        symbol = next(item for item in parsed.symbols if item.name == source.stem)
        assert symbol.size == 168
        attempts.append(payload)

    for key in ("source_sha256", "object_sha256"):
        assert attempts[0]["provenance"][key] == attempts[1]["provenance"][key]
