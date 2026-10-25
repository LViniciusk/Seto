"""Opt-in real EBOOT/MWCC checks for the new 037 reconstructions."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import probe_common
from scripts.triage_eboot_035 import parse_ghidra_evidence
from seto import elf, exports, imports, mips
from seto.hashing import sha256_file

REPO_ROOT = Path(__file__).resolve().parents[2]
PRIVATE = REPO_ROOT / "private"
EBOOT = PRIVATE / "decrypted" / "ULUS10136_EBOOT.elf"
TUTORIALLIST = PRIVATE / "original" / "PSP_GAME" / "USRDIR" / "gmodule" / "libtutoriallist.prx"
HTML_VIEW = PRIVATE / "original" / "PSP_GAME" / "USRDIR" / "gmodule" / "libhtml_view.prx"
EXPECTED_EBOOT_SHA256 = "d4d0efc3d6c49a7ba8142adbd316ed006a3035a572169e9ef04c6cd0daba7a91"
EXPECTED_TUTORIALLIST_SHA256 = "2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49"
EXPECTED_HTML_VIEW_SHA256 = "319901ff13bc9a44be29596bcb64e4c0c7333dad9fb36bdafceb8c2aed611f26"
OPT_IN = "SETO_EBOOT_037_REAL"
LIBRARY = "libehsys"

# Address, full byte size, NID, real call count in libtutoriallist.prx.
FUNCTIONS = (
    (0x36CCC, 80, 0xFDD168CA, 42),
    (0x37BC8, 72, 0xCABEA834, 10),
    (0x388B4, 72, 0x5CBB9E43, 2),
)

pytestmark = pytest.mark.integration

if not EBOOT.is_file():
    if os.environ.get(OPT_IN) == "1":
        pytest.fail(f"BLOCKED: {EBOOT} is absent while {OPT_IN}=1")
    pytest.skip("local PPSSPP EBOOT dump is absent; this test reads private/", allow_module_level=True)


@pytest.mark.skipif(os.environ.get(OPT_IN) != "1", reason=f"set {OPT_IN}=1 for MWCC 037 integration")
def test_037_exports_boundaries_and_two_independent_real_matches() -> None:
    if sys.platform != "linux":
        pytest.fail("BLOCKED: configured Metrowerks/wibo integration must run under WSL2/Linux")

    assert sha256_file(EBOOT.resolve(strict=True)) == EXPECTED_EBOOT_SHA256
    assert sha256_file(TUTORIALLIST.resolve(strict=True)) == EXPECTED_TUTORIALLIST_SHA256
    assert sha256_file(HTML_VIEW.resolve(strict=True)) == EXPECTED_HTML_VIEW_SHA256

    module = elf.parse(EBOOT)
    text = module.require_section(".text")
    assert text.flags & mips.SHF_EXECINSTR
    collection = exports.collect_exports(module, LIBRARY)
    function_candidates = {
        item.start: item
        for item in mips.find_functions(module.section_data(text), text.addr, "EBOOT .text")
    }

    imports_by_module = []
    for name, path in (("libtutoriallist.prx", TUTORIALLIST), ("libhtml_view.prx", HTML_VIEW)):
        imported = elf.parse(path)
        table = imports.build_import_table(imported)
        imports_by_module.append((name, imports.call_references(imported, table)))

    build_root = probe_common.validated_build_root(REPO_ROOT, subdir="seto037")
    try:
        probe_common.ensure_build_dir(build_root, build_root)
        evidence_dir = build_root / "ghidra-evidence"
        probe_common.ensure_build_dir(evidence_dir, build_root)
    except probe_common.ProbeError as exc:
        pytest.fail(f"BLOCKED: unsafe 037 evidence directory: {exc}")
    for address, size, nid, tutorial_call_count in FUNCTIONS:
        found = collection.exports_for_nid(nid)
        assert len(found) == 1 and found[0].address == address
        export = found[0]
        assert export.pointer_relocation.type == elf.R_MIPS_32
        assert export.pointer_relocation.addend_valid and export.pointer_relocation.addend == address
        assert text.contains_address(address) and text.contains_address(address + size - 4)
        candidate = function_candidates[address]
        assert candidate.end == address + size
        ghidra_log = evidence_dir / f"{address:x}.log"
        assert ghidra_log.is_file() and not ghidra_log.is_symlink()
        evidence = parse_ghidra_evidence(
            ghidra_log.read_text(encoding="utf-8", errors="replace"),
            address,
            address + size,
        )
        assert evidence["instruction_count"] == size // 4

        observed = {}
        for module_name, references in imports_by_module:
            sites = tuple(sorted(
                reference.address
                for reference in references
                if reference.imported is not None
                and reference.imported.identity == (LIBRARY, nid)
            ))
            observed[module_name] = sites
        assert len(observed["libtutoriallist.prx"]) == tutorial_call_count
        assert observed["libhtml_view.prx"] == ()

    try:
        probe_common.ensure_build_dir(build_root, build_root)
        integration_dir = build_root / "integration"
        probe_common.ensure_build_dir(integration_dir, build_root)
    except probe_common.ProbeError as exc:
        pytest.fail(f"BLOCKED: unsafe 037 integration output path: {exc}")

    match_script = REPO_ROOT / "scripts" / "match_function.py"
    config = REPO_ROOT / "config" / "wsl" / "seto.toml"
    for address, size, _nid, _call_count in FUNCTIONS:
        source = REPO_ROOT / "decomp" / "src" / "eboot" / f"func_{address:08X}.c"
        assert source.is_file() and not source.is_symlink()
        results = []
        for number in (1, 2):
            attempt_dir = integration_dir / f"0x{address:08X}" / f"attempt-{number}"
            parent = attempt_dir.parent
            try:
                probe_common.ensure_build_dir(parent, build_root)
                probe_common.ensure_build_dir(attempt_dir, build_root)
            except probe_common.ProbeError as exc:
                pytest.fail(f"BLOCKED: unsafe 037 attempt directory: {exc}")
            run = subprocess.run(
                [
                    sys.executable,
                    str(match_script),
                    "--config", str(config),
                    "--prx", str(EBOOT),
                    "--function", hex(address),
                    "--size", str(size),
                    "--source", str(source),
                    "--out", str(attempt_dir),
                    "--json",
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=360,
                check=False,
            )
            assert run.returncode == 0, run.stdout + run.stderr
            payload = json.loads(run.stdout)
            comparison = payload["match"]
            assert payload["status"] == comparison["status"] == "MATCHED"
            assert payload["verified_decompilation"] is True
            assert comparison["total_words"] == comparison["matching_words"] == size // 4
            assert comparison["difference_count"] == 0 and comparison["differences"] == []
            assert comparison["limitations"] == [] and comparison["relocation_issues"] == []
            assert comparison["resolved_calls"]
            obj = elf.parse(attempt_dir / f"{source.stem}.o")
            symbol = next(item for item in obj.symbols if item.name == source.stem)
            assert symbol.size == size
            results.append(payload)

        for key in ("source_sha256", "object_sha256"):
            assert results[0]["provenance"][key] == results[1]["provenance"][key]
