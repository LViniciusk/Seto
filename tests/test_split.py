"""Tests for layout derivation, validation and splat configuration emission."""

from __future__ import annotations

import dataclasses
import json

import pytest

from seto import elf, split
from seto.binio import ParseError
from seto.elf import Section
from seto.split import Layout, LayoutSegment, Subsegment

from conftest import SHF_ALLOC, SHF_EXECINSTR, build_elf32

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
