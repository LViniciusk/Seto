"""Real compilation of the R3 initializer, loader and recovered comparator."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from seto import elf, mips
from seto.hashing import sha256_file

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = REPO_ROOT / "private/original/PSP_GAME/USRDIR/gmodule/libtutoriallist.prx"
OPT_IN = "SETO_LIBTUTORIALLIST_CALLBACKS_REAL"
EXPECTED_SHA256 = "2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49"
CASES = {
    # words, counted words, data pairs, resolved direct calls, pairing warnings
    0x1B0C: (25, 15, 5, 2, 0),
    0x1C58: (44, 28, 8, 3, 0),
    0x1E84: (4, 4, 0, 0, 0),
}

pytestmark = pytest.mark.integration

if not MODULE.is_file():
    if os.environ.get(OPT_IN) == "1":
        pytest.fail("BLOCKED: original libtutoriallist.prx is absent with the callbacks opt-in active")
    pytest.skip("original libtutoriallist.prx is absent; this test reads private/ only", allow_module_level=True)

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import triage_libtutoriallist as triage  # noqa: E402


@pytest.mark.skipif(os.environ.get(OPT_IN) != "1", reason=f"set {OPT_IN}=1 for real WSL2 matching")
def test_initializer_loader_and_comparator_compile_and_compare_freshly() -> None:
    if sys.platform != "linux":
        pytest.fail("BLOCKED: real Metrowerks compilation requires WSL2/Linux")
    config = REPO_ROOT / "config/wsl/seto.toml"
    if not config.is_file() or config.is_symlink():
        pytest.fail("BLOCKED: official WSL toolchain configuration is absent or unsafe")
    module_sha = sha256_file(MODULE)
    assert module_sha == EXPECTED_SHA256
    module = elf.parse(MODULE)
    baseline = triage.build_baseline(module, module_sha)
    rows = {int(row["start"], 16): row for row in baseline["functions"]}

    # 0x1E84 was not found by old direct-call/Ghidra triage. Here the actual
    # relocated address passed in a3 establishes its role as a comparator.
    initializer = rows[0x1B0C]
    callback = next(ref for ref in initializer["data_references"]
                    if ref["combined_addend"] == "0x00001e84")
    assert callback["target"] == {"section": ".text", "offset": "0x1e84"}
    assert callback["pairing"] == "PROVEN"
    assert initializer["calls"][1]["import"]["nid"] == "0x1B00FB95"
    assert rows[0x1E84]["data_references"] == []

    # Fifth AND sixth integer arguments: callback in t0, cached handle in t1.
    text = module.require_section(".text")
    original_words = mips.decode_words(module.section_data(text), "original .text")
    assert original_words[(0x1CE8 - text.addr) // 4] == 0x00404821  # move t1,v0
    assert original_words[(0x1CF0 - text.addr) // 4] == 0x25081DF4  # addiu t0,t0,callback
    assert rows[0x1C58]["calls"][-1]["import"]["nid"] == "0x8288EEBC"

    build_root = triage.validated_build_root(REPO_ROOT, subdir="seto024")
    results = []
    for address, (words, matching, pairs, calls, warnings) in CASES.items():
        name = mips.function_name(address)
        assert rows[address]["end"] == hex(address + words * 4)
        assert rows[address]["instruction_count"] == words
        source = REPO_ROOT / "decomp/src/libtutoriallist" / f"{name}.c"
        attempts = []
        for attempt in (1, 2):
            result = triage.run_real_match(
                address, source, attempt=attempt, expected_total_words=words,
                config_value=config, build_subdir="seto024",
            )
            assert result["status"] in ("MATCHED", "INCONCLUSIVE"), result
            candidate = elf.parse(build_root / "matches" / f"f{address:x}" / f"attempt-{attempt}" / f"{name}.o")
            symbol = next(symbol for symbol in candidate.symbols if symbol.name == name)
            assert symbol.size == words * 4, "compare the entire candidate, not a truncated prefix"
            attempts.append(result)
        assert attempts[0] == attempts[1], f"fresh {name} evidence or hashes changed"
        result = attempts[0]
        assert result["status"] == ("INCONCLUSIVE" if pairs else "MATCHED")
        assert result["exit_code"] == (5 if pairs else 0)
        assert result["matching_words"] == matching
        assert result["total_words"] == words
        assert result["difference_count"] == 0 and result["differences"] == []
        assert result["relocation_issues"] == [] and result["resolved_data"] == []
        assert len(result["resolved_calls"]) == calls
        assert len(result["limitations"]) == pairs + warnings
        assert sum("data identity cannot be proven" in item for item in result["limitations"]) == pairs
        assert result["verified_decompilation"] is (pairs == 0)
        results.append(result)

    triage.ensure_build_dir(build_root / "deep-push", build_root)
    triage.write_build_text(
        build_root / "deep-push/callback-results.json",
        triage.canonical_json({"module_sha256": module_sha, "attempts_per_function": 2, "functions": results}),
        build_root,
    )
