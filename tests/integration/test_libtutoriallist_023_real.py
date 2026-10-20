"""Opt-in WSL2/Metrowerks evidence for SETO-DECOMP-023."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

from seto import datarefs, elf, mips
from seto.datarefs import DataTarget, SymbolLink
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
OPT_IN = "SETO_LIBTUTORIALLIST_023_REAL"

# address: original instruction count
CASES = {0x1B70: 42, 0x1DF4: 36}

pytestmark = pytest.mark.integration

if not MODULE.is_file():
    if os.environ.get(OPT_IN) == "1":
        pytest.fail("BLOCKED: original libtutoriallist.prx is absent with the 023 opt-in active")
    pytest.skip("original libtutoriallist.prx is absent; this test reads private/ only", allow_module_level=True)

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import triage_libtutoriallist as triage  # noqa: E402


def _stable_result(result: dict[str, object]) -> dict[str, object]:
    keys = (
        "function",
        "address",
        "status",
        "phase",
        "exit_code",
        "module_sha256",
        "source_sha256",
        "object_sha256",
        "error",
    )
    return {key: result.get(key) for key in keys}


def _function_row(report: dict[str, object], address: int) -> dict[str, object]:
    return next(
        row for row in report["functions"]
        if isinstance(row, dict) and int(str(row["start"]), 16) == address
    )


def _instruction_word(module: elf.ElfFile, address: int) -> int:
    text = module.require_section(".text")
    raw = module.section_data(text)
    offset = address - text.addr
    return int.from_bytes(raw[offset : offset + 4], "little")


@pytest.mark.skipif(
    os.environ.get(OPT_IN) != "1", reason=f"set {OPT_IN}=1 for real WSL2 matching"
)
def test_023_shared_state_identity_and_fresh_candidate_diagnostics() -> None:
    if sys.platform != "linux":
        pytest.fail("BLOCKED: the real Metrowerks integration must run under WSL2/Linux")

    config = REPO_ROOT / "config" / "wsl" / "seto.toml"
    build_root = triage.validated_build_root(REPO_ROOT, subdir="seto023")
    evidence_dir = build_root / "baseline" / "018"
    baseline_path = evidence_dir / "baseline.json"
    triage_path = evidence_dir / "triage.json"
    ghidra_path = evidence_dir / triage.GHIDRA_EVIDENCE_NAME
    for path in (config, baseline_path, triage_path, ghidra_path):
        if not path.is_file() or path.is_symlink():
            pytest.fail(f"BLOCKED: required 023 input is absent or unsafe: {path.name}")

    module_sha = sha256_file(MODULE)
    assert module_sha == EXPECTED_SHA256
    module = elf.parse(MODULE)
    baseline = triage.build_baseline(module, module_sha)
    stored_baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert triage.canonical_json(stored_baseline) == triage.canonical_json(baseline)
    ghidra = triage._load_ghidra_report(ghidra_path, build_root)
    rebuilt_triage = triage.build_triage(baseline, ghidra)
    stored_triage = json.loads(triage_path.read_text(encoding="utf-8"))
    assert triage.canonical_json(stored_triage) == triage.canonical_json(rebuilt_triage)

    by_start = {int(str(row["start"]), 16): row for row in rebuilt_triage["functions"]}
    for address, instruction_count in CASES.items():
        row = by_start[address]
        assert row["instruction_count"] == instruction_count
        assert row["ghidra"]["boundary_status"] == "EXACT"
        assert row["call_counts"].get("unknown", 0) == 0
        assert len(row["data_references"]) == 4
        for reference in row["data_references"]:
            assert reference["combined_addend"] == "0x00006250"
            assert reference["location"] == datarefs.INFERRED
            assert reference["target"] is None
            assert reference["load_segment"] == 0
            assert reference["load_offset"] == "0x6250"
            assert reference["initialized"] is False

    b70 = by_start[0x1B70]
    assert [(call["address"], call["kind"], call["target"]) for call in b70["calls"]] == [
        ("0x1ba4", "local", "0x1c58")
    ]
    assert [reference["pairing"] for reference in b70["data_references"]] == [
        datarefs.PROVEN,
        datarefs.PROVEN,
        datarefs.INFERRED,
        datarefs.PROVEN,
    ]

    df4 = by_start[0x1DF4]
    assert len(df4["calls"]) == 1
    call = df4["calls"][0]
    assert call["address"] == "0x1e18"
    assert call["kind"] == "import"
    assert call["import"] == {
        "library": "libehsys",
        "nid": "0x4B0DABFA",
        "stub_address": "0x3780",
        "stub_index": 570,
        "table_offset": "0x0",
    }
    assert all(reference["pairing"] == datarefs.PROVEN for reference in df4["data_references"])

    # Check the byte-width accesses from the actual original instruction words.
    byte_accesses = {
        0x1B7C: 0x24,  # lbu
        0x1BB8: 0x24,
        0x1BE4: 0x28,  # sb (in the jump delay slot)
        0x1BFC: 0x28,
        0x1E24: 0x24,
        0x1E4C: 0x28,
        0x1E54: 0x24,
        0x1E70: 0x28,
    }
    assert {address: mips.opcode(_instruction_word(module, address)) for address in byte_accesses} == byte_accesses

    # The address is in the zero-fill tail of one PT_LOAD and in no allocated section.
    for address in (0x6250, 0x6204):
        load = datarefs.load_location(module, address)
        assert load is not None
        assert (load.segment, load.offset, load.initialized) == (0, address, False)
        assert not any(section.is_allocated and section.contains_address(address) for section in module.sections)
    bss = module.section(".bss")
    assert bss is not None and bss.size == 0
    data = module.require_section(".data")
    assert (data.addr, data.size, data.end) == (0x60EC, 0xA4, 0x6190)

    # The existing location-only grouping confirms module-local sharing, not a cross-artifact link.
    reference_report = {
        "functions": [
            {"function": row["name"], "references": row["data_references"]}
            for row in baseline["functions"]
        ]
    }
    usage = datarefs.build_global_usage(reference_report)
    locations = usage["locations"]
    state_group = next(
        location for location in locations
        if location.get("kind") == "segment" and location.get("segment") == 0
        and location.get("offset") == "0x6250"
    )
    assert state_group["functions"] == [
        "func_00001B0C", "func_00001B70", "func_00001C58", "func_00001DF4"
    ]
    table_group = next(
        location for location in locations
        if location.get("kind") == "section" and location.get("section") == ".data"
        and location.get("offset") == "0x34"
    )
    assert table_group["functions"] == ["func_00001B0C", "func_00001D08"]
    extents_group = next(
        location for location in locations
        if location.get("kind") == "segment" and location.get("segment") == 0
        and location.get("offset") == "0x6204"
    )
    assert extents_group["functions"] == [
        "func_000002F4", "func_00000E24", "func_000021F8"
    ]
    name_group = next(
        location for location in locations
        if location.get("kind") == "section" and location.get("section") == ".data"
        and location.get("offset") == "0x80"
    )
    assert name_group["functions"] == ["func_00001D08"]

    # A caller-supplied symbol mapping without independent evidence is not identity.
    state_hi = next(
        relocation for relocation in module.relocations_for(".text")
        if relocation.section_offset == 0x1B78
    )
    original_resolver = datarefs.module_resolver(module, "libtutoriallist.prx")
    assert original_resolver(state_hi, 0x6250) is None
    results: list[dict[str, object]] = []
    timings: list[dict[str, object]] = []
    for address, expected_size, candidate_size in (
        (0x1B70, 168, 156),
        (0x1DF4, 144, 140),
    ):
        name = triage.mips.function_name(address)
        source = REPO_ROOT / "decomp" / "src" / "libtutoriallist" / f"{name}.c"
        attempts = []
        for attempt in (1, 2):
            started = time.perf_counter()
            result = triage.run_real_match(
                address,
                source,
                attempt=attempt,
                expected_total_words=CASES[address],
                config_value=config,
                build_subdir="seto023",
            )
            timings.append({
                "function": name,
                "attempt": attempt,
                "compile_and_match_seconds": round(time.perf_counter() - started, 3),
            })
            attempts.append(result)
        first, second = attempts
        assert _stable_result(first) == _stable_result(second), f"fresh {name} diagnostic changed"
        # These are genuine matcher ERRORs, not comparison statuses: the compiler
        # emits the lean C reconstruction shorter than the original interval.
        assert first["status"] == "ERROR"
        assert first["phase"] == "compare"
        assert first["exit_code"] == 1
        assert first["error"] == (
            f"error: candidate section '.text': needs {expected_size} bytes at section offset 0x0 "
            f"but the section is {candidate_size} bytes"
        )
        assert "matching_words" not in first
        assert "verified_decompilation" not in first
        results.append(first)

    candidate = elf.parse(
        build_root / "matches" / "f1b70" / "attempt-1" / "func_00001B70.o"
    )
    candidate_state_relocation = next(
        relocation for relocation in candidate.relocations_for(".text")
        if relocation.symbol == "func_00006250_state"
    )
    candidate_resolver = datarefs.module_resolver(candidate, "candidate-object")
    assert candidate_resolver(candidate_state_relocation, candidate_state_relocation.addend) is None
    unverified_link = SymbolLink(
        entries={"func_00006250_state": DataTarget(".data", 0x34)},
        evidence=("test-only unverified hypothesis",),
        verified=False,
    )
    assert unverified_link.resolver(module, "libtutoriallist.prx")(
        candidate_state_relocation, candidate_state_relocation.addend
    ) is None

    triage.ensure_build_dir(build_root, build_root)
    triage.write_build_text(
        build_root / "match-results.json",
        triage.canonical_json({
            "schema_version": 1,
            "module": {"name": "libtutoriallist.prx", "sha256": module_sha},
            "attempts_per_function": 2,
            "functions": results,
        }),
        build_root,
    )
    triage.write_build_text(
        build_root / "timings.json",
        json.dumps({"measurement": "fresh Metrowerks compile plus match", "attempts": timings}, indent=2, sort_keys=True) + "\n",
        build_root,
    )
