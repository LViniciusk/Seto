"""Tests for layout derivation, validation and splat configuration emission."""

from __future__ import annotations

import dataclasses
import json
from typing import Sequence

import pytest

from seto import elf, split
from seto.binio import ParseError
from seto.elf import Section
from seto.split import Layout, LayoutSegment, Subsegment

from conftest import SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, build_elf32

TEXT_ADDR = 0x0
TEXT_OFFSET = 0x100
TEXT_SIZE = 0x20
RODATA_ADDR = 0x20
RODATA_OFFSET = 0x120
RODATA_SIZE = 0x10


def _module() -> elf.ElfFile:
    return elf.parse(
        build_elf32(
            e_type=elf.ET_MIPS_PSP_PRX,
            sections=[
                {
                    "name": ".text",
                    "type": elf.SHT_PROGBITS,
                    "flags": SHF_ALLOC | SHF_EXECINSTR,
                    "addr": TEXT_ADDR,
                    "offset": TEXT_OFFSET,
                    "size": TEXT_SIZE,
                    "data": b"\x00" * TEXT_SIZE,
                },
                {
                    "name": ".rodata",
                    "type": elf.SHT_PROGBITS,
                    "flags": SHF_ALLOC,
                    "addr": RODATA_ADDR,
                    "offset": RODATA_OFFSET,
                    "size": RODATA_SIZE,
                    "data": b"\x11" * RODATA_SIZE,
                },
            ],
        )
    )


# ------------------------------------------------------------------ build_layout


def test_build_layout_from_the_real_section_table() -> None:
    parsed = _module()
    layout = split.build_layout(parsed, "module")
    assert layout.file_size == parsed.reader.size
    assert layout.image_delta == TEXT_OFFSET - TEXT_ADDR
    assert [segment.name for segment in layout.segments] == ["header", "module", "elf_meta"]

    header = layout.segments[0]
    assert header.type == split.BIN_KIND
    assert header.start == 0

    code = layout.segments[1]
    assert code.start == TEXT_OFFSET
    assert code.vram == TEXT_ADDR
    assert code.type == split.CODE_TYPE
    assert [(s.name, s.kind, s.offset, s.size) for s in code.subsegments] == [
        ("text", split.ASM_KIND, TEXT_OFFSET, TEXT_SIZE),
        ("rodata", split.BIN_KIND, RODATA_OFFSET, RODATA_SIZE),
    ]

    tail = layout.segments[2]
    assert tail.start == RODATA_OFFSET + RODATA_SIZE
    assert tail.subsegments[0].end == layout.file_size


def test_build_layout_rejects_a_module_without_allocated_sections() -> None:
    parsed = elf.parse(build_elf32(sections=[{"name": ".debug", "flags": 0, "data": b"\x00" * 4}]))
    with pytest.raises(ParseError, match="no allocated section"):
        split.build_layout(parsed, "empty")


def test_segment_name_strips_leading_dots() -> None:
    assert split.segment_name(Section(1, ".text", 1, 0, 0, 0, 4, 0, 0, 4, 0)) == "text"
    assert split.segment_name(Section(2, ".sceStub.text", 1, 0, 0, 0, 4, 0, 0, 4, 0)) == "sceStub_text"
    assert split.segment_name(Section(3, "", 1, 0, 0, 0, 4, 0, 0, 4, 0)) == "section_3"


# --------------------------------------------------------------- validate_layout


def test_validate_layout_accepts_the_derived_layout() -> None:
    parsed = _module()
    layout = split.build_layout(parsed, "module")
    assert split.validate_layout(layout, parsed) == ()


def test_validate_layout_flags_a_file_size_mismatch() -> None:
    parsed = _module()
    layout = split.build_layout(parsed, "module")
    broken = dataclasses.replace(layout, file_size=layout.file_size + 4)
    issues = split.validate_layout(broken, parsed)
    assert any(issue.severity == split.ERROR and "file_size" in issue.message for issue in issues)


def test_validate_layout_flags_an_overlap() -> None:
    parsed = _module()
    segments = (
        LayoutSegment("a", split.BIN_KIND, 0, 0, (Subsegment(0, split.BIN_KIND, "a", 8),)),
        LayoutSegment("b", split.BIN_KIND, 4, 0, (Subsegment(4, split.BIN_KIND, "b", 8),)),
    )
    layout = Layout(basename="x", file_size=16, image_delta=0, segments=segments)
    issues = split.validate_layout(layout, parsed)
    assert any("overlaps" in issue.message for issue in issues)


def test_validate_layout_flags_a_kind_mismatch() -> None:
    parsed = _module()
    layout = split.build_layout(parsed, "module")
    code = layout.segments[1]
    wrong = dataclasses.replace(
        code,
        subsegments=(
            dataclasses.replace(code.subsegments[0], kind=split.BIN_KIND),
            code.subsegments[1],
        ),
    )
    broken = dataclasses.replace(layout, segments=(layout.segments[0], wrong, layout.segments[2]))
    issues = split.validate_layout(broken, parsed)
    assert any("kind" in issue.message for issue in issues)


def test_validate_layout_flags_a_span_leaving_the_file() -> None:
    parsed = _module()
    layout = split.build_layout(parsed, "module")
    segments = (
        LayoutSegment(
            "x",
            split.BIN_KIND,
            0,
            0,
            (Subsegment(0, split.BIN_KIND, "x", layout.file_size + 8),),
        ),
    )
    broken = Layout(basename="x", file_size=layout.file_size, image_delta=0, segments=segments)
    issues = split.validate_layout(broken, parsed)
    assert any("leaves the file" in issue.message for issue in issues)


def test_validate_layout_flags_a_gap_between_regions() -> None:
    parsed = _module()
    segments = (
        LayoutSegment("a", split.BIN_KIND, 0, 0, (Subsegment(0, split.BIN_KIND, "a", 8),)),
        LayoutSegment("b", split.BIN_KIND, 12, 0, (Subsegment(12, split.BIN_KIND, "b", 4),)),
    )
    layout = Layout(basename="x", file_size=16, image_delta=0, segments=segments)
    issues = split.validate_layout(layout, parsed)
    assert any(issue.severity == split.ERROR and "gap" in issue.message for issue in issues)


def test_validate_layout_reports_nobits_sections_explicitly() -> None:
    parsed = elf.parse(
        build_elf32(
            e_type=elf.ET_MIPS_PSP_PRX,
            sections=[
                {
                    "name": ".text",
                    "type": elf.SHT_PROGBITS,
                    "flags": SHF_ALLOC | SHF_EXECINSTR,
                    "addr": 0,
                    "size": 0x20,
                    "data": b"\x00" * 0x20,
                },
                {
                    "name": ".bss",
                    "type": elf.SHT_NOBITS,
                    "flags": SHF_ALLOC | SHF_WRITE,
                    "addr": 0x20,
                    "size": 0x10,
                },
            ],
        )
    )
    layout = split.build_layout(parsed, "module")
    # .bss owns no file bytes and must not appear as a file subsegment.
    assert all("bss" not in segment.name for segment in layout.segments)
    issues = split.validate_layout(layout, parsed)
    assert not any(issue.severity == split.ERROR for issue in issues)
    assert any("SHT_NOBITS" in issue.message for issue in issues)


# ------------------------------------------------------------------- load_layout


def test_load_layout_round_trips(tmp_path) -> None:
    layout = split.build_layout(_module(), "module")
    path = tmp_path / "layout.json"
    path.write_text(layout.to_json(), encoding="utf-8")
    assert split.load_layout(path) == layout


def test_load_layout_rejects_invalid_json(tmp_path) -> None:
    path = tmp_path / "layout.json"
    path.write_text("{ this is not json", encoding="utf-8")
    with pytest.raises(ParseError, match="invalid layout JSON"):
        split.load_layout(path)


@pytest.mark.parametrize(
    "payload",
    [
        "[]",
        "{}",
        '{"basename": "x", "file_size": 16, "image_delta": 0}',
        '{"basename": "x", "file_size": 0, "image_delta": 0, "segments": [{"name": "s", "type": "code", "start": 0, "vram": 0, "subsegments": [{"offset": 0, "kind": "bin", "name": "a", "size": 4}]}]}',
        '{"basename": "x", "file_size": 16, "image_delta": 0, "segments": []}',
        '{"basename": "x", "file_size": 16, "image_delta": 0, "segments": [{"name": "s", "type": "code", "start": 0, "vram": 0, "subsegments": [{"offset": 0, "kind": "bin", "name": "a", "size": -4}]}]}',
        '{"basename": "x", "file_size": 16, "image_delta": 0, "segments": [{"name": "s", "type": "code", "start": 0, "vram": 0, "subsegments": [{"offset": -4, "kind": "bin", "name": "a", "size": 4}]}]}',
    ],
)
def test_load_layout_rejects_malformed_structures(tmp_path, payload) -> None:
    path = tmp_path / "layout.json"
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(ParseError):
        split.load_layout(path)


def test_layout_issue_render() -> None:
    assert split.LayoutIssue(split.ERROR, "boom").render() == "ERROR: boom"
    assert split.LayoutIssue(split.WARNING, "careful").render() == "WARNING: careful"


# ------------------------------------------------------------- yaml and json I/O


def test_emit_splat_yaml_is_generated_from_the_layout() -> None:
    layout = split.build_layout(_module(), "module")
    text = split.emit_splat_yaml(
        layout,
        base_path="..",
        target_path="private/original/module.prx",
        asm_path="asm/module",
        ld_script_path="build/module.ld",
    )
    assert "name: module" in text
    assert "platform: psp" in text
    assert "compiler: MWCC" in text
    assert "target_path: private/original/module.prx" in text
    assert f"start: 0x{layout.segments[1].start:x}" in text
    assert "text" in text and "rodata" in text
    assert f"[0x{layout.file_size:x}]" in text


def test_cross_check_yaml_accepts_the_emitted_configuration() -> None:
    pytest.importorskip("yaml")
    layout = split.build_layout(_module(), "module")
    text = split.emit_splat_yaml(
        layout, base_path="..", target_path="m.prx", asm_path="a", ld_script_path="l.ld"
    )
    assert split.cross_check_yaml(text, layout) == ()


def test_cross_check_yaml_detects_a_bad_sentinel() -> None:
    pytest.importorskip("yaml")
    layout = split.build_layout(_module(), "module")
    text = split.emit_splat_yaml(
        layout, base_path="..", target_path="m.prx", asm_path="a", ld_script_path="l.ld"
    )
    broken = dataclasses.replace(layout, file_size=layout.file_size + 4)
    issues = split.cross_check_yaml(text, broken)
    assert any("sentinel" in issue.message for issue in issues)


def test_cross_check_yaml_rejects_an_empty_document() -> None:
    pytest.importorskip("yaml")
    layout = split.build_layout(_module(), "module")
    issues = split.cross_check_yaml("name: module\nsegments: []\n", layout)
    assert any("no segments" in issue.message for issue in issues)


def test_layout_json_round_trips() -> None:
    layout = split.build_layout(_module(), "module")
    restored = Layout.from_dict(json.loads(layout.to_json()))
    assert restored.summary() == layout.summary()
    assert restored == layout


def test_default_outputs() -> None:
    layout = split.build_layout(_module(), "module")
    layout_path, yaml_path = split.default_outputs(layout, "build/split")
    assert layout_path.name == "layout.json"
    assert yaml_path.name == "module.yaml"


# --------------------------------------------------------------- splat listing

LISTING_ADDRESS = 0x100
LISTING_OFFSET = 0x200
LISTING_WORDS = (0x27BDFFF0, 0x3C040000, 0x03E00008, 0x00000000)


def _original(*words: int) -> bytes:
    """A file whose four words live at ``LISTING_OFFSET``."""
    blob = bytearray(0x300)
    for index, value in enumerate(words):
        blob[LISTING_OFFSET + 4 * index : LISTING_OFFSET + 4 * index + 4] = value.to_bytes(
            4, "little"
        )
    return bytes(blob)


def _listing(
    words: Sequence[int],
    *,
    address: int = LISTING_ADDRESS,
    file_offset: int = LISTING_OFFSET,
) -> str:
    """A listing in the shape spimdisasm writes: offset, address, raw bytes."""
    lines = ["/* Generated by spimdisasm 1.42.4 */", ""]
    for index, value in enumerate(words):
        encoded = value.to_bytes(4, "little").hex().upper()
        lines.append(
            f"    /* {file_offset + 4 * index:x} {address + 4 * index:08X} {encoded} */  nop"
        )
    return "\n".join(lines) + "\n"


def _verify(text: str, original: bytes, **overrides) -> tuple:
    arguments = {
        "label": "text.s",
        "address": LISTING_ADDRESS,
        "file_offset": LISTING_OFFSET,
        "size": len(LISTING_WORDS) * 4,
    }
    arguments.update(overrides)
    return split.verify_listing(
        split.parse_listing(text, "text.s"), original, **arguments
    )


def test_parse_listing_reads_offset_address_and_word() -> None:
    entries = split.parse_listing(_listing(LISTING_WORDS), "text.s")
    assert [entry.file_offset for entry in entries] == [0x200, 0x204, 0x208, 0x20C]
    assert [entry.address for entry in entries] == [0x100, 0x104, 0x108, 0x10C]
    assert [entry.word for entry in entries] == list(LISTING_WORDS)
    assert entries[0].data == b"\xf0\xff\xbd\x27"


def test_parse_listing_rejects_a_line_it_cannot_read() -> None:
    with pytest.raises(ParseError, match="unrecognised listing line"):
        split.parse_listing("    /* 0 0 ZZZZZZZZ */  nop\n", "text.s")
    with pytest.raises(ParseError, match="unrecognised listing line"):
        split.parse_listing("addiu $sp, $sp, -0x10\n", "text.s")


def test_parse_listing_accepts_labels_and_directives() -> None:
    text = (
        ".set noreorder\n.section .text, \"ax\"\n\n"
        "nonmatching func_00000100, 0x10\n\nglabel func_00000100\n"
        + _listing(LISTING_WORDS)
        + "endlabel func_00000100\n"
    )
    assert len(split.parse_listing(text, "text.s")) == 4


def test_verify_listing_accepts_a_listing_that_matches_the_file() -> None:
    assert _verify(_listing(LISTING_WORDS), _original(*LISTING_WORDS)) == ()


def test_verify_listing_rejects_a_word_that_differs_from_the_file() -> None:
    words = list(LISTING_WORDS)
    words[2] = 0x00000000
    issues = _verify(_listing(words), _original(*LISTING_WORDS))
    assert len(issues) == 1
    assert "the file holds" in issues[0].message


def test_verify_listing_rejects_a_wrong_file_offset() -> None:
    issues = _verify(_listing(LISTING_WORDS, file_offset=LISTING_OFFSET + 4), _original(*LISTING_WORDS))
    assert any("off the layout" in issue.message for issue in issues)


def test_verify_listing_rejects_a_gap_and_a_short_listing() -> None:
    entries = split.parse_listing(_listing(LISTING_WORDS[:2]), "text.s")
    issues = split.verify_listing(
        entries,
        _original(*LISTING_WORDS),
        label="text.s",
        address=LISTING_ADDRESS,
        file_offset=LISTING_OFFSET,
        size=len(LISTING_WORDS) * 4,
    )
    assert any("covers 0x8 of 0x10 bytes" in issue.message for issue in issues)


def test_verify_listing_rejects_an_empty_listing() -> None:
    issues = split.verify_listing(
        (),
        _original(*LISTING_WORDS),
        label="text.s",
        address=LISTING_ADDRESS,
        file_offset=LISTING_OFFSET,
        size=len(LISTING_WORDS) * 4,
    )
    assert len(issues) == 1
    assert "decodes no word" in issues[0].message
