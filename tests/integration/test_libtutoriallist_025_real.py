"""Opt-in WSL2/Metrowerks evidence for SETO-DECOMP-025.

The six CLI cases use ``scripts/match_function.py`` and the public comparator,
including an explicit ``--size`` for the split 0x1C18/0x1C20 functions. Four
large functions use the production ``seto.matching.compare`` API over complete
candidate symbols and explicit original intervals, preserving size mismatches
where present. 0x2F4, 0x1F10 and 0x21F8 now have exact sizes; 0x8F0 remains
larger. Compilation uses the same official compiler/flag path; ERROR/BLOCKED
is never accepted as a comparison.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
from functools import partial
from pathlib import Path

import pytest

from seto import datarefs, elf, imports, matching
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
OPT_IN = "SETO_LIBTUTORIALLIST_025_REAL"

# address: (original words, explicit --size in bytes or None, expected result)
CLI_CASES = {
    0x8: (83, None, {
        "status": "INCONCLUSIVE", "matching": 63, "differences": 0,
        "relocations": 0, "limitations": 16, "symbol_size": 332,
    }),
    0x154: (75, None, {
        "status": "INCONCLUSIVE", "matching": 65, "differences": 0,
        "relocations": 0, "limitations": 9, "symbol_size": 300,
    }),
    0x280: (18, None, {
        "status": "INCONCLUSIVE", "matching": 12, "differences": 0,
        "relocations": 0, "limitations": 3, "symbol_size": 72,
    }),
    0x2C8: (11, None, {
        "status": "INCONCLUSIVE", "matching": 7, "differences": 0,
        "relocations": 0, "limitations": 2, "symbol_size": 44,
    }),
    0x1C18: (2, 8, {
        "status": "MATCHED", "matching": 2, "differences": 0,
        "relocations": 0, "limitations": 0, "symbol_size": 8,
    }),
    0x1C20: (14, 56, {
        "status": "INCONCLUSIVE", "matching": 8, "differences": 0,
        "relocations": 0, "limitations": 3, "symbol_size": 56,
    }),
}

# address: (original words, expected result) for complete-symbol comparisons.
WHOLE_CASES = {
    0x2F4: (253, {
        "status": "NONMATCHING", "matching": 134, "total": 253,
        "differences": 99, "relocations": 20, "limitations": 4,
        "symbol_size": 1012, "first_word": 81,
        "first_reason": "relocated word differs outside the relocation field",
    }),
    0x8F0: (333, {
        "status": "NONMATCHING", "matching": 52, "total": 342,
        "differences": 284, "relocations": 68, "limitations": 1,
        "symbol_size": 1368, "first_word": 15,
    }),
    0x1F10: (186, {
        "status": "NONMATCHING", "matching": 137, "total": 186,
        "differences": 11, "relocations": 0, "limitations": 23,
        "symbol_size": 744, "first_word": 100,
    }),
    0x21F8: (238, {
        "status": "INCONCLUSIVE", "matching": 190, "total": 238,
        "differences": 0, "relocations": 0, "limitations": 26,
        "symbol_size": 952, "first_word": None,
    }),
}

pytestmark = pytest.mark.integration

if not MODULE.is_file():
    if os.environ.get(OPT_IN) == "1":
        pytest.fail("BLOCKED: original libtutoriallist.prx is absent with the 025 opt-in active")
    pytest.skip(
        "original libtutoriallist.prx is absent; this test reads private/ only",
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
        "equivalence",
        "verified_decompilation",
    )
    return {key: result.get(key) for key in keys}


def _match_script():
    path = REPO_ROOT / "scripts" / "match_function.py"
    spec = importlib.util.spec_from_file_location("seto_match_function_025", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _fresh_compile(script, source: Path, object_path: Path, config: Path) -> None:
    settings = script.load_settings(config)
    status = script.find_tool(script._MWCCPSP, settings.tool_path("mwccpsp"))
    if not status.found:
        pytest.fail(f"BLOCKED: mwccpsp unavailable: {status.reason}")
    loaders = script.resolve_loaders([], settings)
    if loaders is None:
        pytest.fail("BLOCKED: no usable Win32 loader (wibo or wine) is available")
    flags = script.resolve_flags([], settings)
    includes = script.resolve_includes([], settings)
    object_path.parent.mkdir(parents=True, exist_ok=True)
    object_path.unlink(missing_ok=True)
    argv = script.mwcc_argv(
        status.path,
        source,
        object_path,
        flags=flags,
        includes=includes,
        loader=loaders,
    )
    result = script.run(argv, timeout=300)
    if not result.ok or not object_path.is_file():
        pytest.fail(f"BLOCKED: fresh compilation failed for {source.name}: {result.combined()}")


def _whole_symbol_match(
    script,
    source: Path,
    address: int,
    words: int,
    attempt: int,
    config: Path,
    build_root: Path,
) -> dict[str, object]:
    name = triage.mips.function_name(address)
    directory = build_root / "whole" / f"f{address:x}" / f"attempt-{attempt}"
    triage.ensure_build_dir(directory, build_root)
    object_path = directory / f"{name}.o"
    _fresh_compile(script, source, object_path, config)

    original = elf.parse(MODULE)
    candidate = elf.parse(object_path)
    text = original.require_section(".text")
    ctext = candidate.require_section(".text")
    symbol = next((item for item in candidate.symbols if item.name == name), None)
    if symbol is None or symbol.size == 0:
        pytest.fail(f"BLOCKED: {object_path.name} has no nonempty {name} symbol")
    raw_original = original.section_data(text)[
        address - text.addr : address - text.addr + words * 4
    ]
    raw_candidate = candidate.section_data(ctext)[symbol.value : symbol.value + symbol.size]
    comparison = matching.compare(
        raw_original,
        raw_candidate,
        name=name,
        address=address,
        original_relocations=original.relocations_for(".text"),
        candidate_relocations=candidate.relocations_for(".text"),
        original_section_offset=address - text.addr,
        candidate_section_offset=symbol.value,
        evidence=matching.EVIDENCE_COMPILED_OBJECT,
        call_resolver=partial(
            imports.resolve_call_target,
            module_imports=imports.build_import_table(original),
            candidate_symbols=imports.symbol_addresses(candidate) or None,
        ),
        original_data_resolver=datarefs.module_resolver(original, "original"),
        candidate_data_resolver=datarefs.module_resolver(candidate, "candidate"),
    ).summary()
    payload = {
        "function": name,
        "address": f"0x{address:x}",
        "original_words": words,
        "candidate_size": symbol.size,
        "source_sha256": sha256_file(source),
        "object_sha256": sha256_file(object_path),
        "status": comparison["status"],
        "matching_words": comparison["matching_words"],
        "total_words": comparison["total_words"],
        "difference_count": comparison["difference_count"],
        "differences": comparison["differences"],
        "relocation_issues": comparison["relocation_issues"],
        "limitations": comparison["limitations"],
        "resolved_calls": comparison["resolved_calls"],
        "resolved_data": comparison["resolved_data"],
    }
    triage.write_build_text(
        directory / "whole.json",
        triage.canonical_json(payload),
        build_root,
    )
    return payload


@pytest.mark.skipif(
    os.environ.get(OPT_IN) != "1", reason=f"set {OPT_IN}=1 for real WSL2 matching"
)
def test_025_new_reconstructions_and_complete_symbols() -> None:
    if sys.platform != "linux":
        pytest.fail("BLOCKED: the real Metrowerks integration must run under WSL2/Linux")

    config = REPO_ROOT / "config" / "wsl" / "seto.toml"
    if not config.is_file() or config.is_symlink():
        pytest.fail("BLOCKED: config/wsl/seto.toml is absent or unsafe")
    build_root = triage.validated_build_root(REPO_ROOT, subdir="seto025")
    module_sha = sha256_file(MODULE)
    assert module_sha == EXPECTED_SHA256
    module = elf.parse(MODULE)
    text = module.require_section(".text")
    assert (text.addr, text.size) == (0, 0x25B0)

    # The old linear inventory still groups 0x1C18 and 0x1C20 into one 16-word
    # window.  The new thunk is the authentic 2-word first interval.
    grouped = next(
        item for item in triage.mips.find_functions(module.section_data(text), 0, "025")
        if item.start == 0x1C18
    )
    assert grouped.size == 16 * 4
    assert module.section_data(text)[0x1C18:0x1C1C] == bytes.fromhex("08070008")
    assert module.section_data(text)[0x1C20:0x1C24] == bytes.fromhex("f0ffbd27")

    script = _match_script()
    cli_results: list[dict[str, object]] = []
    whole_results: list[dict[str, object]] = []
    timings: list[dict[str, object]] = []

    for address, (words, function_size, expected) in CLI_CASES.items():
        name = triage.mips.function_name(address)
        source = REPO_ROOT / "decomp" / "src" / "libtutoriallist" / f"{name}.c"
        attempts = []
        for attempt in (1, 2):
            started = time.perf_counter()
            result = triage.run_real_match(
                address,
                source,
                attempt=attempt,
                expected_total_words=words,
                function_size=function_size,
                config_value=config,
                build_subdir="seto025",
            )
            timings.append({
                "function": name,
                "attempt": attempt,
                "kind": "cli",
                "seconds": round(time.perf_counter() - started, 3),
            })
            attempts.append(result)
            candidate = elf.parse(
                build_root / "matches" / f"f{address:x}" / f"attempt-{attempt}" / f"{name}.o"
            )
            symbol = next(item for item in candidate.symbols if item.name == name)
            assert symbol.size == expected["symbol_size"]
        first, second = attempts
        assert _stable_result(first) == _stable_result(second), f"fresh {name} comparison changed"
        assert first["status"] == expected["status"]
        assert first["matching_words"] == expected["matching"]
        assert first["total_words"] == words
        assert first["difference_count"] == expected["differences"]
        assert len(first["relocation_issues"]) == expected["relocations"]
        assert len(first["limitations"]) == expected["limitations"]
        if expected["status"] == "MATCHED":
            assert first["exit_code"] == 0
            assert first["equivalence"] == matching.EQUIVALENCE_RESOLVED_RELOCATIONS
            assert first["resolved_calls"] == [
                "word 0 (0x1c18): this module @ 0x1c20 <=> this module @ 0x1c20"
            ]
            assert first["resolved_data"] == []
            assert first["verified_decompilation"] is True
        else:
            assert first["equivalence"] == ""
            assert first["verified_decompilation"] is False
        if address == 0x2C8:
            assert first["differences"] == []
            assert first["relocation_issues"] == []
            assert first["limitations"] == [
                "word 0: HI16/LO16 data identity cannot be proven "
                "(original: unresolved; candidate: unresolved)",
                "word 5: HI16/LO16 data identity cannot be proven "
                "(original: unresolved; candidate: unresolved)",
            ]
        cli_results.append(first)

    for address, (words, expected) in WHOLE_CASES.items():
        name = triage.mips.function_name(address)
        source = REPO_ROOT / "decomp" / "src" / "libtutoriallist" / f"{name}.c"
        attempts = []
        for attempt in (1, 2):
            started = time.perf_counter()
            result = _whole_symbol_match(
                script, source, address, words, attempt, config, build_root
            )
            timings.append({
                "function": name,
                "attempt": attempt,
                "kind": "whole-symbol",
                "seconds": round(time.perf_counter() - started, 3),
            })
            attempts.append(result)
        first, second = attempts
        assert first["object_sha256"] == second["object_sha256"], f"fresh {name} object changed"
        for key in (
            "status", "matching_words", "total_words", "difference_count",
            "differences", "relocation_issues", "limitations",
        ):
            assert first[key] == second[key]
        assert first["status"] == expected["status"]
        assert first["matching_words"] == expected["matching"]
        assert first["total_words"] == expected["total"]
        assert first["difference_count"] == expected["differences"]
        assert len(first["relocation_issues"]) == expected["relocations"]
        assert len(first["limitations"]) == expected["limitations"]
        assert first["candidate_size"] == expected["symbol_size"]
        if expected["first_word"] is not None:
            assert first["differences"][0]["word_index"] == expected["first_word"]
        if first["difference_count"]:
            assert first["differences"][0]["reason"] == expected.get("first_reason", "word differs")
        whole_results.append(first)

    results = {
        "schema_version": 1,
        "task": "SETO-DECOMP-025",
        "module": {"name": "libtutoriallist.prx", "sha256": module_sha},
        "attempts_per_function": 2,
        "cli_cases": cli_results,
        "whole_symbol_cases": whole_results,
    }
    triage.write_build_text(
        build_root / "integration-results.json",
        triage.canonical_json(results),
        build_root,
    )
    triage.write_build_text(
        build_root / "integration-timings.json",
        json.dumps(
            {"measurement": "fresh Metrowerks compile plus match", "attempts": timings},
            indent=2,
            sort_keys=True,
        ) + "\n",
        build_root,
    )
