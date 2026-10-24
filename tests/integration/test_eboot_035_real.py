"""Opt-in export, Ghidra-boundary, and production compile/match checks for 035."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from seto import elf, exports, imports, mips
from seto.hashing import sha256_file

REPO_ROOT = Path(__file__).resolve().parents[2]
PRIVATE = REPO_ROOT / "private"
EBOOT = PRIVATE / "decrypted" / "ULUS10136_EBOOT.elf"
ORIGINAL = PRIVATE / "original" / "PSP_GAME" / "USRDIR" / "gmodule"
LIBTUTORIALLIST = ORIGINAL / "libtutoriallist.prx"
LIBHTML_VIEW = ORIGINAL / "libhtml_view.prx"
EXPECTED_EBOOT_SHA256 = "d4d0efc3d6c49a7ba8142adbd316ed006a3035a572169e9ef04c6cd0daba7a91"
EXPECTED_LIBTUTORIALLIST_SHA256 = "2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49"
EXPECTED_LIBHTML_VIEW_SHA256 = "319901ff13bc9a44be29596bcb64e4c0c7333dad9fb36bdafceb8c2aed611f26"
OPT_IN = "SETO_EBOOT_035_REAL"
LIBRARY = "libehsys"

# address, byte size, export NID, baseline status, baseline matching words, diffs.
FUNCTIONS = (
    (0x33D10, 60, 0x20E340D9, "MATCHED", 15, 0),
    (0x3643C, 168, 0x4175E3DB, "NONMATCHING", 26, 16),
    (0x9C98, 132, 0x1B00FB95, "NONMATCHING", 3, 30),
)
PRIORITY_EXPORTS = {
    0x31454993: 0x3D8F0,
    0x10F3BB61: 0x8040,
    0xB4471B5E: 0x38DB4,
    0x20E340D9: 0x33D10,
    0x8171F765: 0x3D8C8,
}
PRIORITY_IMPORT_CALLS = {
    0x31454993: {
        "libtutoriallist.prx": (0x108, 0xF04, 0x1DB0),
        "libhtml_view.prx": (0x3A4,),
    },
    0x10F3BB61: {
        "libtutoriallist.prx": (0x2C, 0x71C, 0x1B20),
        "libhtml_view.prx": (0x4DC, 0x52C),
    },
    0xB4471B5E: {"libtutoriallist.prx": (), "libhtml_view.prx": (0x1C,)},
    0x20E340D9: {"libtutoriallist.prx": (0x1C3C,), "libhtml_view.prx": ()},
    0x8171F765: {
        "libtutoriallist.prx": (0x2214, 0x2280),
        "libhtml_view.prx": (0x544,),
    },
}

pytestmark = pytest.mark.integration

if not EBOOT.is_file():
    if os.environ.get(OPT_IN) == "1":
        pytest.fail(f"BLOCKED: {EBOOT} is absent while {OPT_IN}=1")
    pytest.skip(
        "local PPSSPP EBOOT dump is absent; this test reads private/ only",
        allow_module_level=True,
    )

sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "tests"))
import probe_common  # noqa: E402
from eboot_035_progress import (  # noqa: E402
    BASELINE_DIFFERENCE_INDICES,
    assert_match_progress,
)


@pytest.mark.skipif(
    os.environ.get(OPT_IN) != "1",
    reason=f"set {OPT_IN}=1 for PPSSPP/MWCC 035 integration",
)
def test_035_verified_exports_and_three_real_compile_matches() -> None:
    if sys.platform != "linux":
        pytest.fail("BLOCKED: the configured Metrowerks/wibo integration must run under WSL2/Linux")

    eboot_path = EBOOT.resolve(strict=True)
    tutorial_path = LIBTUTORIALLIST.resolve(strict=True)
    html_path = LIBHTML_VIEW.resolve(strict=True)
    assert sha256_file(eboot_path) == EXPECTED_EBOOT_SHA256
    assert sha256_file(tutorial_path) == EXPECTED_LIBTUTORIALLIST_SHA256
    assert sha256_file(html_path) == EXPECTED_LIBHTML_VIEW_SHA256

    module = elf.parse(eboot_path)
    assert module.header.e_type == elf.ET_MIPS_PSP_PRX
    assert module.is_mips
    text = module.require_section(".text")
    assert text.flags & mips.SHF_EXECINSTR
    collection = exports.collect_exports(module, LIBRARY)
    assert len(collection.exports) == 1182
    assert len(collection.limitations) == 64
    assert len(collection.ambiguous_nids) == 15
    assert len(collection.aliases) == 15

    build_root = probe_common.validated_build_root(REPO_ROOT, subdir="seto035")
    triage_script = REPO_ROOT / "scripts" / "triage_eboot_035.py"
    triage_run = subprocess.run(
        [sys.executable, str(triage_script)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if triage_run.returncode != 0:
        pytest.fail(
            "BLOCKED/FAIL: deterministic export triage could not validate its saved "
            "Ghidra evidence\n"
            f"stdout:\n{triage_run.stdout}\nstderr:\n{triage_run.stderr}"
        )
    triage_path = build_root / "export-triage.json"
    triage = json.loads(triage_path.read_text(encoding="utf-8"))
    candidate_map = {int(item["address"], 16): item for item in triage["candidate_analysis"]}

    text_functions = mips.find_functions(module.section_data(text), text.addr, "EBOOT .text")
    function_map = {item.start: item for item in text_functions}
    parsed_imports = []
    for name, path in (("libtutoriallist.prx", tutorial_path), ("libhtml_view.prx", html_path)):
        imported_module = elf.parse(path)
        table = imports.build_import_table(imported_module)
        references = imports.call_references(imported_module, table)
        parsed_imports.append((name, table, references))

    priority_checks = {
        int(item["nid"], 16): item["exports"] for item in triage["priority_nid_checks"]
    }
    for nid, address in PRIORITY_EXPORTS.items():
        matching_exports = collection.exports_for_nid(nid)
        assert len(matching_exports) == 1
        assert matching_exports[0].address == address
        rows = priority_checks[nid]
        assert len(rows) == 1 and rows[0]["address"] == f"0x{address:x}"
        observed_call_sites = {}
        for module_name, table, references in parsed_imports:
            imported_sites = sorted(
                reference.address
                for reference in references
                if reference.imported is not None
                and reference.imported.identity == (LIBRARY, nid)
            )
            observed_call_sites[module_name] = tuple(imported_sites)
            assert any(item.identity == (LIBRARY, nid) for item in table.imports.values())
        assert observed_call_sites == PRIORITY_IMPORT_CALLS[nid]

    match_script = REPO_ROOT / "scripts" / "match_function.py"
    config = REPO_ROOT / "config" / "wsl" / "seto.toml"
    source_root = REPO_ROOT / "decomp" / "src" / "eboot"
    report_functions: list[dict[str, object]] = []

    for (
        address,
        size,
        nid,
        expected_status,
        expected_matching,
        expected_diffs,
    ) in FUNCTIONS:
        exported = collection.exports_for_nid(nid)
        assert len(exported) == 1
        assert exported[0].address == address
        assert exported[0].pointer_relocation.type == elf.R_MIPS_32
        assert exported[0].pointer_relocation.addend_valid
        assert exported[0].pointer_relocation.addend == address
        assert text.contains_address(address)

        interval = function_map.get(address)
        assert interval is not None and interval.end == address + size
        triage_candidate = candidate_map[address]
        assert triage_candidate["interval"] == [f"0x{address:x}", f"0x{address + size:x}"]
        ghidra = triage_candidate["boundary_evidence"]["ghidra"]
        assert ghidra["language"] == "Allegrex:LE:32:default"
        assert ghidra["boundary_status"] == "EXACT"
        assert ghidra["decomp_status"] == "OK"
        assert ghidra["instruction_count"] == size // 4

        source = source_root / f"func_{address:08X}.c"
        if not source.is_file() or source.is_symlink():
            pytest.fail(f"BLOCKED: C source is absent or unsafe: {source}")

        imported_by: list[dict[str, object]] = []
        for module_name, table, references in parsed_imports:
            matching_stubs = [
                item for item in table.imports.values() if item.identity == (LIBRARY, nid)
            ]
            if not matching_stubs:
                continue
            call_sites = [
                reference.address
                for reference in references
                if reference.imported is not None and reference.imported.identity == (LIBRARY, nid)
            ]
            imported_by.append(
                {
                    "module": module_name,
                    "stub_addresses": [f"0x{item.stub_address:x}" for item in matching_stubs],
                    "call_sites": [f"0x{site:x}" for site in sorted(call_sites)],
                }
            )
        assert imported_by, f"no cross-module import evidence for {LIBRARY}/0x{nid:08X}"
        assert triage_candidate["importers"]

        attempts: list[dict[str, object]] = []
        for attempt_number in (1, 2):
            out_dir = build_root / "real" / f"attempt-{attempt_number}" / f"{address:08x}"
            probe_common.ensure_build_dir(out_dir, build_root)
            result = subprocess.run(
                [
                    sys.executable,
                    str(match_script),
                    "--config",
                    str(config),
                    "--prx",
                    str(eboot_path),
                    "--function",
                    hex(address),
                    "--size",
                    str(size),
                    "--source",
                    str(source),
                    "--out",
                    str(out_dir),
                    "--json",
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=360,
                check=False,
            )
            if result.returncode not in (0, 3, 5):
                pytest.fail(
                    f"BLOCKED/FAIL: compile+match for 0x{address:x} attempt {attempt_number} "
                    f"exited {result.returncode}\n"
                    f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
                )
            payload = json.loads(result.stdout)
            assert result.returncode == payload["exit_code"]
            assert payload["evidence"] == "compiled-object"
            assert payload["provenance"]["flags"] == ["-O4,p", "-sdatathreshold", "0"]
            comparison = payload["match"]
            assert comparison["total_words"] == size // 4
            assert comparison["relocation_issues"] == []
            assert comparison["limitations"] == []
            if expected_status == "MATCHED":
                assert payload["status"] == "MATCHED"
                assert payload["verified_decompilation"] is True
                assert comparison["status"] == "MATCHED"
                assert comparison["matching_words"] == expected_matching
                assert comparison["difference_count"] == expected_diffs
                assert comparison["differences"] == []
                if address == 0x33D10:
                    assert any("0x92fc" in call for call in comparison["resolved_calls"])
            else:
                assert expected_status == "NONMATCHING"
                assert expected_diffs == len(BASELINE_DIFFERENCE_INDICES[address])
                assert_match_progress(
                    payload,
                    total_words=size // 4,
                    baseline_matching_words=expected_matching,
                    baseline_difference_indices=BASELINE_DIFFERENCE_INDICES[address],
                )

            object_path = out_dir / f"{source.stem}.o"
            candidate_object = elf.parse(object_path)
            symbol = next(item for item in candidate_object.symbols if item.name == source.stem)
            assert symbol.size == size
            assert payload["provenance"]["source_sha256"] == sha256_file(source)
            attempts.append(payload)

        assert (
            attempts[0]["provenance"]["source_sha256"]
            == attempts[1]["provenance"]["source_sha256"]
        )
        assert (
            attempts[0]["provenance"]["object_sha256"]
            == attempts[1]["provenance"]["object_sha256"]
        )
        report_functions.append(
            {
                "address": f"0x{address:x}",
                "size": size,
                "nid": f"0x{nid:08X}",
                "export_slot": exported[0].slot_index,
                "export_pointer_relocation": exported[0].pointer_relocation.summary(),
                "interval": [f"0x{address:x}", f"0x{address + size:x}"],
                "ghidra": ghidra,
                "importers": imported_by,
                "attempts": attempts,
            }
        )

    report = {
        "schema_version": 1,
        "task": "SETO-DECOMP-035",
        "eboot_sha256": EXPECTED_EBOOT_SHA256,
        "proven_exports": len(collection.exports),
        "limitations": len(collection.limitations),
        "functions": report_functions,
    }
    probe_common.write_build_text(
        build_root / "real-results.json",
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        build_root,
    )
