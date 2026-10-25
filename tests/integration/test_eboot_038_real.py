"""Opt-in real EBOOT/MWCC checks for SETO-DECOMP-038."""

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
OPT_IN = "SETO_EBOOT_038_REAL"
LIBRARY = "libehsys"

# Address, end-exclusive boundary, NID, libtutoriallist calls, libhtml_view calls.
# The five middle candidates form the 038 shortlist; 0x38DB4 and 0x44EB4 are
# the task's separately prioritized targets.
EXPORT_RANGES = (
    (0x38DB4, 0x38EB0, 0xB4471B5E, 0, 1),
    (0x44EB4, 0x44F00, 0xAB962AE7, 4, 0),
    (0x36D1C, 0x36D8C, 0x8EA6B1E7, 26, 0),
    (0x2C28C, 0x2C2FC, 0x7187E0F0, 1, 0),
    (0x37F38, 0x38040, 0xE6E4401F, 9, 0),
    (0x4217C, 0x4222C, 0x942B03D0, 5, 0),
    (0x8040, 0x813C, 0x10F3BB61, 3, 2),
)

# Address, exact byte size, NID. These are the only 038 production sources.
MATCHED_FUNCTIONS = (
    (0x38DB4, 252, 0xB4471B5E),
    (0x36D1C, 112, 0x8EA6B1E7),
)

pytestmark = pytest.mark.integration

if not EBOOT.is_file():
    if os.environ.get(OPT_IN) == "1":
        pytest.fail(f"BLOCKED: {EBOOT} is absent while {OPT_IN}=1")
    pytest.skip("local PPSSPP EBOOT dump is absent; this test reads private/", allow_module_level=True)


@pytest.mark.skipif(os.environ.get(OPT_IN) != "1", reason=f"set {OPT_IN}=1 for MWCC 038 integration")
def test_038_exports_boundaries_and_two_independent_real_matches() -> None:
    if sys.platform != "linux":
        pytest.fail("BLOCKED: configured Metrowerks/wibo integration must run under WSL2/Linux")

    assert sha256_file(EBOOT.resolve(strict=True)) == EXPECTED_EBOOT_SHA256
    assert sha256_file(TUTORIALLIST.resolve(strict=True)) == EXPECTED_TUTORIALLIST_SHA256
    assert sha256_file(HTML_VIEW.resolve(strict=True)) == EXPECTED_HTML_VIEW_SHA256

    module = elf.parse(EBOOT)
    text = module.require_section(".text")
    assert text.flags & mips.SHF_EXECINSTR
    collection = exports.collect_exports(module, LIBRARY)
    imports_by_module = []
    for name, path in (("libtutoriallist.prx", TUTORIALLIST), ("libhtml_view.prx", HTML_VIEW)):
        imported = elf.parse(path)
        imports_by_module.append((name, imports.call_references(imported, imports.build_import_table(imported))))

    function_candidates = {
        function.start: function
        for function in mips.find_functions(module.section_data(text), text.addr, "EBOOT .text")
    }

    try:
        build_root = probe_common.validated_build_root(REPO_ROOT, subdir="seto038")
        probe_common.ensure_build_dir(build_root, build_root)
        evidence_dir = build_root / "ghidra-evidence"
        probe_common.ensure_build_dir(evidence_dir, build_root)
    except probe_common.ProbeError as exc:
        pytest.fail(f"BLOCKED: unsafe 038 evidence directory: {exc}")

    for address, end, nid, tutorial_count, html_count in EXPORT_RANGES:
        found = collection.exports_for_nid(nid)
        assert len(found) == 1 and found[0].address == address
        export = found[0]
        assert export.pointer_relocation.type == elf.R_MIPS_32
        assert export.pointer_relocation.addend_valid and export.pointer_relocation.addend == address
        assert text.contains_address(address) and text.contains_address(end - 4)

        evidence_path = evidence_dir / f"{address:x}.log"
        assert evidence_path.is_file() and not evidence_path.is_symlink()
        evidence = parse_ghidra_evidence(
            evidence_path.read_text(encoding="utf-8", errors="replace"), address, end
        )
        assert evidence["instruction_count"] == (end - address) // 4

        observed = {}
        for module_name, references in imports_by_module:
            observed[module_name] = tuple(
                sorted(
                    reference.address
                    for reference in references
                    if reference.imported is not None
                    and reference.imported.identity == (LIBRARY, nid)
                )
            )
        assert len(observed["libtutoriallist.prx"]) == tutorial_count
        assert len(observed["libhtml_view.prx"]) == html_count

    # The automatic linear function finder truncates 0x8040, while Ghidra's
    # independently checked body is the exact 63-instruction export range.
    assert function_candidates[0x8040].end == 0x80F4

    match_script = REPO_ROOT / "scripts" / "match_function.py"
    config = REPO_ROOT / "config" / "wsl" / "seto.toml"
    try:
        integration_dir = build_root / "integration"
        probe_common.ensure_build_dir(integration_dir, build_root)
    except probe_common.ProbeError as exc:
        pytest.fail(f"BLOCKED: unsafe 038 integration directory: {exc}")

    for address, size, _nid in MATCHED_FUNCTIONS:
        source = REPO_ROOT / "decomp" / "src" / "eboot" / f"func_{address:08X}.c"
        assert source.is_file() and not source.is_symlink()
        results = []
        for number in (1, 2):
            function_dir = integration_dir / f"0x{address:08X}"
            attempt_dir = function_dir / f"attempt-{number}"
            try:
                probe_common.ensure_build_dir(function_dir, build_root)
                probe_common.ensure_build_dir(attempt_dir, build_root)
            except probe_common.ProbeError as exc:
                pytest.fail(f"BLOCKED: unsafe 038 attempt directory: {exc}")

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
            assert len(comparison["resolved_calls"]) == 1

            provenance = payload["provenance"]
            assert provenance["flags"] == ["-O4,p", "-sdatathreshold", "0"]
            assert provenance["data_map"] is None
            obj = elf.parse(attempt_dir / f"{source.stem}.o")
            symbol = next(item for item in obj.symbols if item.name == source.stem)
            assert symbol.size == size
            assert len(obj.section_data(obj.require_section(".text"))) == size
            relocations = obj.relocations_for(".text")
            assert len(relocations) == 1
            assert relocations[0].type == elf.R_MIPS_26
            assert relocations[0].symbol == "func_00031308"
            results.append(payload)

        for key in ("source_sha256", "object_sha256"):
            assert results[0]["provenance"][key] == results[1]["provenance"][key]
