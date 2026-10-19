"""Integration tests against the real game media.

These tests are skipped automatically when the extracted module or the ISO are
absent (they are never committed - see ``.gitignore``).  Run them with::

    py -3.12 -m pytest tests/integration -m integration

Nothing here writes to the original data: the inventory and split commands are
read-only with respect to ``private/``.
"""

from __future__ import annotations

import json
import os
import re
import sys
from functools import partial
from pathlib import Path

import pytest

from seto import cli, datarefs, elf, imports, inventory, matching, mips, psp_reloc, split
from seto.matching import MATCHED, compare
from seto.hashing import sha256_file
from seto.toolchain import TOOL_SPECS, find_tool, load_settings

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = REPO_ROOT / "private" / "original" / "PSP_GAME" / "USRDIR" / "gmodule" / "libhtml_view.prx"
GAME_ROOT = REPO_ROOT / "private" / "original" / "PSP_GAME"
ISO = REPO_ROOT / "TF1.iso"


def _toolchain_config() -> Path:
    wsl_profile = REPO_ROOT / "config" / "wsl" / "seto.toml"
    if os.name == "posix" and wsl_profile.is_file():
        return wsl_profile
    return REPO_ROOT / "config" / "seto.toml"

pytestmark = pytest.mark.integration

if not MODULE.is_file():
    pytest.skip(
        f"original module not present ({MODULE}); integration tests need private/",
        allow_module_level=True,
    )


@pytest.fixture(scope="module")
def parsed() -> elf.ElfFile:
    return elf.parse(MODULE)


def test_header_matches_the_documented_baseline(parsed: elf.ElfFile) -> None:
    assert parsed.is_prx
    assert parsed.is_mips
    assert parsed.header.e_machine == elf.EM_MIPS
    comment = parsed.comment()
    assert comment is not None and "MW MIPS C Compiler" in comment


def test_text_section_geometry(parsed: elf.ElfFile) -> None:
    text = parsed.require_section(".text")
    assert text.offset == 0x60
    assert text.size == 0x7F4
    assert text.addr == 0x0


def test_function_discovery_is_stable(parsed: elf.ElfFile) -> None:
    text = parsed.require_section(".text")
    functions = mips.find_functions(parsed.section_data(text), text.addr)
    assert len(functions) == 16
    by_address = {function.start: function for function in functions}
    target = by_address[0x244]
    assert target.size == 0x34
    assert target.calls == (0x2EDC, 0x2F0C, 0x2EF4, 0x2F54)


def test_relocations_are_typed_and_resolved(parsed: elf.ElfFile) -> None:
    relocations = parsed.relocations_for(".text")
    assert relocations
    types = {relocation.type_name for relocation in relocations}
    assert {"R_MIPS_26", "R_MIPS_HI16", "R_MIPS_LO16"} <= types
    assert all(relocation.section_offset is not None for relocation in relocations)


def test_split_layout_validates_against_the_real_module(parsed: elf.ElfFile) -> None:
    layout = split.build_layout(parsed, "libhtml_view")
    assert split.validate_layout(layout, parsed) == ()
    assert layout.image_delta == 0x60
    assert len(layout.segments) == 3
    assert len(layout.subsegments()) == 15


def test_func_00000244_self_comparison_is_matched(parsed: elf.ElfFile) -> None:
    text = parsed.require_section(".text")
    code = parsed.section_data(text)
    function = next(
        item for item in mips.find_functions(code, text.addr) if item.start == 0x244
    )
    offset = function.start - text.addr
    region = code[offset : offset + function.size]
    result = compare(
        region,
        region,
        name=function.name(),
        address=function.start,
        original_relocations=parsed.relocations_for(".text"),
        candidate_relocations=parsed.relocations_for(".text"),
        original_section_offset=offset,
        candidate_section_offset=offset,
    )
    assert result.status == MATCHED
    assert result.total_words == 13


def test_import_table_recovers_the_whole_module(parsed: elf.ElfFile) -> None:
    table = imports.build_import_table(parsed)
    assert table.limitations == ()
    assert [item.library for item in table.tables] == [
        "libehsys", "sceNet", "sceNetInet", "sceNetApctl",
        "sceNetResolver", "sceSsl", "sceHttp", "sceUtility",
    ]
    assert len(table.imports) == 1268
    assert table.code_range == (0x0, 0x7F4)
    # Every identity the table keeps must really be a trampoline of the module.
    stub_section = parsed.require_section(".sceStub.text")
    data = parsed.section_data(stub_section)
    for address in table.imports:
        offset = address - stub_section.addr
        assert data[offset : offset + 4] == b"\x08\x00\xe0\x03"


def test_the_four_calls_of_func_00000244_have_proven_identities(parsed: elf.ElfFile) -> None:
    table = imports.build_import_table(parsed)
    references = imports.call_references(
        parsed, table, section=".text", start=0x244, end=0x278
    )
    assert [
        (item.address, item.kind, item.imported.library, item.imported.nid)
        for item in references
    ] == [
        (0x24C, "import", "sceHttp", 0x76D1363B),
        (0x254, "import", "sceHttp", 0xF9D8EB63),
        (0x25C, "import", "sceHttp", 0xD1C8945E),
        (0x264, "import", "sceSsl", 0x191CDEFF),
    ]
    assert all(item.delay_slot is not None for item in references)


def test_every_call_of_the_module_is_classified(parsed: elf.ElfFile) -> None:
    table = imports.build_import_table(parsed)
    references = imports.call_references(parsed, table, section=".text")
    assert len(references) == 72
    assert {item.kind for item in references} == {"import", "local"}


def test_a_call_can_be_told_apart_from_another_import(parsed: elf.ElfFile) -> None:
    table = imports.build_import_table(parsed)
    resolver = partial(imports.resolve_call_target, module_imports=table)
    site = matching.RelocationSite
    # The first call of func_00000244 reaches sceHttp/0x76D1363B; a candidate
    # that reaches another stub of the same library must not be accepted.
    first = resolver(site(word_index=0, type=elf.R_MIPS_26, addend=0x2EDC, symbol=None))
    other = resolver(site(word_index=0, type=elf.R_MIPS_26, addend=0x2EF4, symbol=None))
    assert first.identity == ("sceHttp", 0x76D1363B)
    assert other.identity == ("sceHttp", 0xD1C8945E)
    assert first.identity != other.identity
    ssl = resolver(site(word_index=0, type=elf.R_MIPS_26, addend=0x2F54, symbol=None))
    assert ssl.identity == ("sceSsl", 0x191CDEFF)


def test_split_run_splat_verifies_the_real_listing(tmp_path, capsys) -> None:
    """splat really consumes the generated config, and its listing is checked.

    The exit code alone is not the evidence: splat's own output must name the
    two code listings and every word of them must have been verified against the
    original bytes (509 words in ``.text``, 2536 in ``.sceStub.text``).
    """
    config = _toolchain_config()
    settings = load_settings(config)
    splat = find_tool(
        next(spec for spec in TOOL_SPECS if spec.name == "splat"),
        settings.tool_path("splat"),
    )
    if not splat.found:
        pytest.skip(f"splat is not configured/installed for this profile: {splat.reason}")
    out = tmp_path / "split"
    code = cli.main(
        [
            "--config",
            str(config),
            "split", "--prx", str(MODULE), "--out", str(out),
            "--base-path", "..", "--target-path", str(MODULE), "--run-splat",
        ]
    )
    printed = capsys.readouterr().out
    assert code == 0
    assert (out / "libhtml_view.yaml").is_file()
    assert (tmp_path / "asm" / "libhtml_view" / "text.s").is_file()
    assert "listing: text.s 509 words (verified against the original bytes)" in printed
    assert (
        "listing: sceStub_text.s 2536 words (verified against the original bytes)"
        in printed
    )
    evidence_dir = os.environ.get("SETO013_EVIDENCE_DIR")
    if evidence_dir:
        text_listing = re.search(r"listing: text\.s (\d+) words \(verified against the original bytes\)", printed)
        stub_listing = re.search(
            r"listing: sceStub_text\.s (\d+) words \(verified against the original bytes\)",
            printed,
        )
        assert text_listing is not None and stub_listing is not None
        evidence_path = Path(evidence_dir)
        evidence_path.mkdir(parents=True, exist_ok=True)
        (evidence_path / "splat.json").write_text(
            json.dumps(
                {
                    "module_sha256": sha256_file(MODULE),
                    "test_source": "tests/integration/test_real_media.py",
                    "test_source_sha256": sha256_file(Path(__file__)),
                    "platform": sys.platform,
                    "tool_version": splat.version,
                    "test": "tests/integration/test_real_media.py::test_split_run_splat_verifies_the_real_listing",
                    "status": "PASS",
                    "listings": [
                        {"section": ".text", "words": int(text_listing.group(1)), "verified_against_original_bytes": True},
                        {"section": ".sceStub.text", "words": int(stub_listing.group(1)), "verified_against_original_bytes": True},
                    ],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )


def test_inventory_over_the_extracted_media() -> None:
    if not GAME_ROOT.is_dir():
        pytest.skip("extracted PSP_GAME tree not present")
    manifest = inventory.build_manifest(
        extracted_root=GAME_ROOT,
        settings=load_settings(REPO_ROOT / "config" / "seto.toml"),
        verify_iso=False,
    )
    assert manifest["parameter_sfo"]["entries"]
    assert manifest["summary"]["module_count"] == 2
    assert manifest["summary"]["function_count"] == 41
    assert manifest["module_errors"] == []


def test_the_reconstructions_data_references_are_recovered(parsed: elf.ElfFile) -> None:
    """The three C reconstructions' data references, straight from the PRX."""
    by_function = {}
    for start, end in ((0x244, 0x278), (0x4B8, 0x508), (0x6E4, 0x704)):
        by_function[f"0x{start:x}"] = datarefs.recover_references(parsed, ".text", start, end)

    # func_00000244 only calls imports: no data reference at all.
    assert by_function["0x244"] == ()

    # func_000004B8 builds the address of "/PSP/SAVEDATA/" at .data + 0xc8.  The
    # location is proven, but the stripped module exposes no symbol identity for
    # the HI16/LO16 pair, so the reference itself is only INFERRED.
    (string,) = by_function["0x4b8"]
    assert string.instruction == 0x4D0
    assert string.combined == 0x4830
    assert string.target == datarefs.DataTarget(".data", 0xC8)
    assert string.location == datarefs.PROVEN
    assert string.pairing == datarefs.PROVEN
    assert string.status == datarefs.PROVEN
    assert string.summary()["object_identity"] == datarefs.NOT_APPLICABLE
    assert string.unresolved is None
    assert [item.type for item in string.relocations] == ["R_MIPS_HI16", "R_MIPS_LO16"]
    assert {item.format for item in string.relocations} == {"PSP"}
    assert [item.application for item in string.relocations] == [".text+0x4c4", ".text+0x4d0"]
    assert [item.raw_info for item in string.relocations] == [0x00000005, 0x00000006]
    assert {item.segment_index for item in string.relocations} == {0}
    assert {item.relative_index for item in string.relocations} == {0}
    assert {item.source_section for item in string.relocations} == {".rel.text"}

    # func_000006E4 writes two globals and stores one of their addresses.  The
    # combined addends are module-relative addresses in the segment's zero-filled
    # tail, which no named ELF section covers, so their location is only INFERRED.
    references = {item.instruction: item for item in by_function["0x6e4"]}
    assert references[0x6EC].combined == 0x604860
    assert references[0x6F4].combined == 0x4860
    assert references[0x700].combined == 0x604B9C
    for reference in references.values():
        assert reference.status == datarefs.INFERRED
        assert reference.pairing == datarefs.PROVEN
        assert reference.target is None
        assert reference.load is not None and not reference.load.initialized

    # The 0x600000 is the high half of the *other* address, not a base.  The pair
    # that forms 0x604860 has HI16 addend 0x60, the pair that forms 0x4860 has
    # HI16 addend 0x00, so the difference is 0x60 << 16 - and it is the only
    # difference between them.  Three distinct module-relative addresses.
    assert references[0x6EC].combined - references[0x6F4].combined == 0x600000
    assert references[0x700].combined - 0x4B9C == 0x600000
    assert references[0x6EC].relocations[0].addend == 0x60
    assert references[0x6F4].relocations[0].addend == 0x00
    assert references[0x700].relocations[0].addend == 0x60


def test_func_00000084_is_referenced_as_an_argument_by_func_00000000(
    parsed: elf.ElfFile,
) -> None:
    """0x84 is not called, but its address is taken and passed as an argument.

    ``func_00000000`` builds three relocatable addresses and passes them to an
    imported ``libehsys`` entry point.  The second is ``.text+0x84``: the address
    just past ``func_00000034``.  So the module does reach 0x84 as a *value*, even
    though no call or branch targets it - the claim that nothing references it is
    wrong, and this test pins the reference instead of leaving it to prose.
    """
    references = datarefs.recover_references(parsed, ".text", 0x0, 0x34)
    assert [reference.instruction for reference in references] == [0x14, 0x18, 0x20]

    start_of_34, start_of_84, tail = references
    assert start_of_34.combined == 0x34
    assert start_of_84.combined == 0x84
    assert start_of_84.target == datarefs.DataTarget(".text", 0x84)
    assert start_of_84.location == datarefs.PROVEN
    assert start_of_84.pairing == datarefs.PROVEN
    assert start_of_84.status == datarefs.PROVEN
    assert start_of_84.unresolved is None

    # The third is the zero-filled tail, which no named section covers.
    assert tail.combined == 0x4850
    assert tail.target is None
    assert tail.location == datarefs.INFERRED
    assert tail.unresolved == "destination is only in a load segment, not a named section"

    # 0x84 as a destination is distinct from 0x34: both are code addresses in the
    # same section, and the plain section offsets keep them apart.
    assert start_of_84.target.offset - start_of_34.target.offset == 0x50


def test_module_relative_and_runtime_relocation_bases_are_distinct(parsed: elf.ElfFile) -> None:
    """Zero-load-base arithmetic reproduces the file; a runtime base is explicit."""
    (segment,) = parsed.segments
    assert segment.vaddr == 0
    assert psp_reloc.relative_base(parsed, parsed.relocations_for(".text")[0]) == 0
    runtime_base = 0x08800000
    assert (
        psp_reloc.relative_base(
            parsed, parsed.relocations_for(".text")[0], load_base=runtime_base
        )
        == runtime_base
    )

    text = parsed.section_data(parsed.require_section(".text"))

    def word_at(offset: int) -> int:
        return int.from_bytes(text[offset : offset + 4], "little")

    relocated_values = {}
    for start, end in ((0x6E4, 0x704), (0x4B8, 0x508)):
        for reference in datarefs.recover_references(parsed, ".text", start, end):
            if reference.kind != "hi16-lo16":
                continue
            hi, lo = reference.relocations
            assert hi.application_offset is not None and lo.application_offset is not None
            hi_word = word_at(hi.application_offset)
            lo_word = word_at(lo.application_offset)
            assert psp_reloc.apply_relocation(
                elf.R_MIPS_HI16, hi_word, 0, lo16_word=lo_word
            ) == hi_word
            loaded_hi = psp_reloc.apply_relocation(
                elf.R_MIPS_HI16, hi_word, runtime_base, lo16_word=lo_word
            )
            loaded_lo = psp_reloc.apply_relocation(elf.R_MIPS_LO16, lo_word, runtime_base)
            assert loaded_hi is not None and loaded_lo is not None
            low = loaded_lo & 0xFFFF
            signed_low = low - 0x10000 if low & 0x8000 else low
            relocated = (((loaded_hi & 0xFFFF) << 16) + signed_low) & 0xFFFFFFFF
            assert relocated == (reference.combined + runtime_base) & 0xFFFFFFFF
            relocated_values[reference.instruction] = relocated

    assert (relocated_values[0x6EC] - relocated_values[0x6F4]) & 0xFFFFFFFF == 0x600000
    assert (relocated_values[0x700] - (0x4B9C + runtime_base)) & 0xFFFFFFFF == 0x600000


def test_the_relocation_inventory_matches_the_documented_baseline(parsed: elf.ElfFile) -> None:
    """Every relocation section is the fixed-width PSP form, fully understood."""
    inventory = psp_reloc.psp_inventory(parsed)
    assert inventory["formats"] == ["PSP"]
    assert inventory["standard_entries"] == 0
    assert inventory["psp_entries"] == 181
    assert inventory["types"] == {
        "R_MIPS_26": 72,
        "R_MIPS_32": 49,
        "R_MIPS_HI16": 30,
        "R_MIPS_LO16": 30,
    }
    assert inventory["unknown_types"] == []
    assert inventory["compressed_sections"] == []
    assert inventory["segment_relocation_payloads"] == []
    assert inventory["segment_indices"] == {"0": 181}
    assert inventory["relative_indices"] == {"0": 181}
    assert inventory["relative_segments_with_nonzero_vaddr"] == []
    assert inventory["runtime_addressing"] == "load_base + p_vaddr; load_base is not inferred from the ELF"
    assert {section["name"] for section in inventory["sections"]} == {
        ".rel.text",
        ".rel.sceStub.text",
        ".rel.data",
        ".rel.lib.ent",
        ".rel.lib.stub",
        ".rel.rodata.sceModuleInfo",
        ".rel.rodata.sceResident",
        ".rel.rodata.sceVstub",
    }


def test_the_datarefs_report_carries_the_relocation_inventory(parsed: elf.ElfFile) -> None:
    report = datarefs.build_reference_report(parsed, ".text", [("func_000006E4", 0x6E4, 0x704)])
    assert report["relocation_inventory"]["psp_entries"] == 181
    (entry,) = report["functions"]
    assert entry["function"] == "func_000006E4"
    for reference in entry["references"]:
        for relocation in reference["relocations"]:
            assert relocation["format"] == "PSP"
            assert relocation["source_section"] == ".rel.text"
            assert relocation["segment_index"] == 0
            assert relocation["relative_index"] == 0
            assert relocation["raw_offset"] is not None


def test_the_savedata_string_is_in_the_data_section(parsed: elf.ElfFile) -> None:
    data = parsed.section_data(parsed.require_section(".data"))
    offset = 0x4830 - parsed.require_section(".data").addr
    assert data[offset : offset + 14] == b"/PSP/SAVEDATA/"
    details = datarefs.data_target_details(parsed, datarefs.DataTarget(".data", offset))
    assert details is not None
    assert details["elf_virtual_address"] == "0x4830"
    assert details["file_offset"] == "0x4890"


def test_the_global_references_are_not_section_backed(parsed: elf.ElfFile) -> None:
    # 0x604860/0x604b9c/0x4860 lie in the module's zero-filled tail but in no
    # named ELF section, which is exactly why they are only INFERRED.
    for address in (0x604860, 0x604B9C, 0x4860):
        assert not any(
            section.is_allocated and section.contains_address(address)
            for section in parsed.sections
        )
        location = datarefs.load_location(parsed, address)
        assert location is not None and not location.initialized


def test_datarefs_command_writes_the_report(parsed: elf.ElfFile, tmp_path, capsys) -> None:
    out = tmp_path / "datarefs.json"
    status = cli.main(
        [
            "datarefs", "--prx", str(MODULE),
            "--function", "0x244", "--function", "0x4b8", "--function", "0x6e4",
            "--out", str(out),
        ]
    )
    assert status == cli.EXIT_INCONCLUSIVE
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["sha256"]
    assert [entry["function"] for entry in payload["functions"]] == [
        "func_00000244", "func_000004B8", "func_000006E4",
    ]
    assert "func_000006E4" in capsys.readouterr().out


def test_iso_matches_the_documented_baseline() -> None:
    if not ISO.is_file():
        pytest.skip("TF1.iso not present")
    settings = load_settings(REPO_ROOT / "config" / "seto.toml")
    manifest = inventory.build_manifest(
        iso_path=ISO,
        extracted_root=GAME_ROOT if GAME_ROOT.is_dir() else REPO_ROOT / "private" / "missing",
        settings=settings,
        verify_iso=True,
    )
    baseline = manifest["baseline"]
    assert baseline["present"] is True
    assert baseline["verified"] is True, baseline["issues"]
    assert baseline["disc_id"] == "ULUS10136"
    assert baseline["disc_version"] == "1.03"
