"""Opt-in end-to-end verification of one locally recovered EBOOT function."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from seto import elf, exports, imports, mips
from seto.hashing import sha256_file

REPO_ROOT = Path(__file__).resolve().parents[2]
PRIVATE = REPO_ROOT / "private"
EBOOT = PRIVATE / "decrypted" / "ULUS10136_EBOOT.elf"
ORIGINAL = PRIVATE / "original" / "PSP_GAME"
LIBTUTORIALLIST = ORIGINAL / "USRDIR" / "gmodule" / "libtutoriallist.prx"
LIBHTML_VIEW = ORIGINAL / "USRDIR" / "gmodule" / "libhtml_view.prx"
EXPECTED_EBOOT_SHA256 = "d4d0efc3d6c49a7ba8142adbd316ed006a3035a572169e9ef04c6cd0daba7a91"
EXPECTED_LIBTUTORIALLIST_SHA256 = "2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49"
EXPECTED_LIBHTML_VIEW_SHA256 = "319901ff13bc9a44be29596bcb64e4c0c7333dad9fb36bdafceb8c2aed611f26"
FUNCTION = 0x3D8F0
FUNCTION_SIZE = 8
LIBRARY = "libehsys"
NID = 0x31454993
OPT_IN = "SETO_EBOOT_034_REAL"

pytestmark = pytest.mark.integration

if not EBOOT.is_file():
    if os.environ.get(OPT_IN) == "1":
        pytest.fail(f"BLOCKED: {EBOOT} is absent while {OPT_IN}=1")
    pytest.skip(
        "local PPSSPP EBOOT dump is absent; this test reads private/ only",
        allow_module_level=True,
    )

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import probe_common  # noqa: E402


def _imported_nid(path: Path) -> dict[str, object]:
    assert path.is_file(), f"BLOCKED: required sibling module is absent: {path}"
    module = elf.parse(path)
    table = imports.build_import_table(module)
    matches = [
        item for item in table.imports.values() if item.identity == (LIBRARY, NID)
    ]
    assert len(matches) == 1, (
        f"{path.name} does not import exactly one {LIBRARY}/0x{NID:08X} stub"
    )
    return {
        "module": path.name,
        "sha256": sha256_file(path),
        "library_table_count": len(table.tables),
        "library_stub_count": len(table.imports),
        "matching_stub": matches[0].summary(),
    }


@pytest.mark.skipif(
    os.environ.get(OPT_IN) != "1",
    reason=f"set {OPT_IN}=1 for PPSSPP/MWCC integration",
)
def test_034_eboot_export_and_exact_leaf_match() -> None:
    if sys.platform != "linux":
        pytest.fail("BLOCKED: the official Metrowerks/wibo integration must run under WSL2/Linux")

    module_path = EBOOT.resolve(strict=True)
    assert sha256_file(module_path) == EXPECTED_EBOOT_SHA256
    module = elf.parse(module_path)
    assert module.header.e_type == elf.ET_MIPS_PSP_PRX
    assert module.header.ei_class == elf.ELFCLASS32
    assert module.header.ei_data == elf.ELFDATA2LSB
    assert module.header.e_machine == elf.EM_MIPS
    assert module.header.e_entry == 0
    assert module.header.e_ehsize == elf.ELF_HEADER_SIZE
    assert module.header.e_phentsize == elf.PROGRAM_HEADER_SIZE
    assert module.header.e_shentsize == elf.SECTION_HEADER_SIZE
    assert module.header.e_shoff < module.reader.size
    text = module.require_section(".text")
    assert text.addr == 0 and text.flags & mips.SHF_EXECINSTR
    assert module.comment() == "MW MIPS C Compiler (2.4.1.01)"

    load_segments = [item for item in module.segments if item.type == elf.PT_LOAD]
    assert len(load_segments) == 1
    load_segment = load_segments[0]
    assert load_segment.flags & 1  # PF_X
    assert load_segment.filesz <= load_segment.memsz
    assert load_segment.vaddr <= module.header.e_entry < load_segment.vaddr + load_segment.memsz
    assert load_segment.offset == text.offset and load_segment.vaddr == text.addr
    assert text.offset + text.size <= load_segment.offset + load_segment.filesz
    for section in module.sections:
        if section.is_allocated:
            assert section.offset - load_segment.offset == section.addr - load_segment.vaddr

    relocation_counts = Counter(item.type_name for item in module.relocations)
    assert relocation_counts == {
        "R_MIPS_26": 6694,
        "R_MIPS_32": 2537,
        "R_MIPS_HI16": 4013,
        "R_MIPS_LO16": 4125,
    }
    assert all(item.application_valid and item.addend_valid for item in module.relocations)
    assert all(item.target_section is not None for item in module.relocations)

    function = next(
        (
            item
            for item in mips.find_functions(module.section_data(text), text.addr)
            if item.start == FUNCTION
        ),
        None,
    )
    assert function is not None and function.end == FUNCTION + FUNCTION_SIZE
    assert function.calls == ()
    assert not [
        item
        for item in module.relocations_for(".text")
        if item.section_offset is not None and FUNCTION <= item.section_offset < FUNCTION + FUNCTION_SIZE
    ]

    matching_exports = exports.collect_exports(module, LIBRARY).exports_for_nid(NID)
    assert len(matching_exports) == 1
    export = matching_exports[0]
    assert export.address == FUNCTION
    assert export.function_count == 1245
    assert export.pointer_relocation.type == elf.R_MIPS_32
    assert export.pointer_relocation.addend_valid
    assert export.pointer_relocation.addend == export.address
    assert module.require_section(".text").contains_address(export.address)
    export_summary = {
        "library": export.library,
        "nid": f"0x{export.nid:08X}",
        "function_address": f"0x{export.address:x}",
        "entry_index": export.entry_index,
        "slot_index": export.slot_index,
        "pointer_site": f"0x{export.pointer_site:x}",
        "function_count": export.function_count,
        "pointer_relocation": export.pointer_relocation.summary(),
    }

    imports_by_module = [
        _imported_nid(LIBTUTORIALLIST),
        _imported_nid(LIBHTML_VIEW),
    ]
    assert imports_by_module[0]["sha256"] == EXPECTED_LIBTUTORIALLIST_SHA256
    assert imports_by_module[1]["sha256"] == EXPECTED_LIBHTML_VIEW_SHA256

    config = REPO_ROOT / "config" / "wsl" / "seto.toml"
    match_script = REPO_ROOT / "scripts" / "match_function.py"
    source = REPO_ROOT / "decomp" / "src" / "eboot" / "func_0003D8F0.c"
    for label, path in (
        ("WSL config", config),
        ("match script", match_script),
        ("C source", source),
    ):
        if not path.is_file() or path.is_symlink():
            pytest.fail(f"BLOCKED: {label} is absent or unsafe: {path}")

    build_root = probe_common.validated_build_root(REPO_ROOT, subdir="seto034")
    attempts: list[dict[str, object]] = []
    for attempt in (1, 2):
        out_dir = build_root / "real" / f"attempt-{attempt}"
        probe_common.ensure_build_dir(out_dir, build_root)
        result = subprocess.run(
            [
                sys.executable,
                str(match_script),
                "--config",
                str(config),
                "--prx",
                str(module_path),
                "--function",
                hex(FUNCTION),
                "--size",
                str(FUNCTION_SIZE),
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
        if result.returncode != 0:
            pytest.fail(
                f"BLOCKED/FAIL: EBOOT compile+match attempt {attempt} exited {result.returncode}\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        payload = json.loads(result.stdout)
        assert payload["status"] == "MATCHED"
        assert payload["verified_decompilation"] is True
        assert payload["provenance"]["flags"] == ["-O4,p", "-sdatathreshold", "0"]
        comparison = payload["match"]
        assert comparison["matching_words"] == 2
        assert comparison["total_words"] == 2
        assert comparison["difference_count"] == 0
        assert comparison["relocation_issues"] == []
        assert comparison["limitations"] == []

        object_path = out_dir / f"{source.stem}.o"
        candidate = elf.parse(object_path)
        symbol = next(item for item in candidate.symbols if item.name == "func_0003D8F0")
        assert symbol.size == FUNCTION_SIZE
        attempts.append(payload)

    assert (
        attempts[0]["provenance"]["source_sha256"]
        == attempts[1]["provenance"]["source_sha256"]
        == sha256_file(source)
    )
    assert (
        attempts[0]["provenance"]["object_sha256"]
        == attempts[1]["provenance"]["object_sha256"]
    )
    report = {
        "schema_version": 1,
        "task": "SETO-DECOMP-034",
        "eboot_sha256": EXPECTED_EBOOT_SHA256,
        "function": {
            "address": hex(FUNCTION),
            "size": FUNCTION_SIZE,
            "export": export_summary,
        },
        "cross_artifact_imports": imports_by_module,
        "attempts": attempts,
    }
    probe_common.write_build_text(
        build_root / "real-results.json",
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        build_root,
    )
