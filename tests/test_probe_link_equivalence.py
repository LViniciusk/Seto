"""Pure regression tests for the controlled R2 link comparison."""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from seto import elf, mips, synthetic
from seto.binio import ParseError

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "probe_link_equivalence.py"
SPEC = importlib.util.spec_from_file_location("seto_probe_link_equivalence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)


def _lui(register: int, immediate: int) -> int:
    return (0x0F << 26) | (register << 16) | (immediate & 0xFFFF)


def _addiu(target: int, source: int, immediate: int) -> int:
    return (0x09 << 26) | (source << 21) | (target << 16) | (immediate & 0xFFFF)


def test_compare_word_sequences_requires_exactly_twenty_words() -> None:
    words = (0,) * 20
    assert probe.compare_word_sequences(words, words) == []
    with pytest.raises(ParseError, match="expected 20 words"):
        probe.compare_word_sequences(words[:-1], words)
    with pytest.raises(ParseError, match="expected 20 words"):
        probe.compare_word_sequences(words, words + (0,))


def test_compare_word_sequences_reports_an_unrelocated_instruction() -> None:
    original = [0] * 20
    changed = list(original)
    original[0] = 0x27BDFFD0
    changed[0] = 0x27BDFFD1
    differences = probe.compare_word_sequences(original, changed)
    assert differences == [
        {
            "word_index": 0,
            "address": "0x4b8",
            "original": "0x27bdffd0",
            "linked": "0x27bdffd1",
        }
    ]


@pytest.mark.parametrize(
    "target,hi,lo,signed_lo",
    [
        (0x4830, 0, 0x4830, 0x4830),
        (0x4834, 0, 0x4834, 0x4834),
        (0x8004, 1, 0x8004, -32764),
    ],
)
def test_hi16_lo16_uses_signed_low_and_carry(target, hi, lo, signed_lo) -> None:
    lui = _lui(4, hi)
    addiu = _addiu(4, 4, lo)
    assert mips.signed_immediate(addiu) == signed_lo
    assert probe.paired_effective_address(lui, addiu) == target


def test_hi16_lo16_pair_rejects_wrong_register_flow_or_opcode() -> None:
    with pytest.raises(ParseError, match="LUI"):
        probe.paired_effective_address(0x24040000, _addiu(4, 4, 0x4830))
    with pytest.raises(ParseError, match="consuming"):
        probe.paired_effective_address(_lui(4, 0), _addiu(5, 5, 0x4830))


def test_controlled_address_variants_change_only_the_expected_pair_words() -> None:
    baseline = [0] * 20
    baseline[3] = _lui(5, 0)
    baseline[6] = _addiu(5, 5, 0x4830)
    plus_four = list(baseline)
    plus_four[6] = _addiu(5, 5, 0x4834)
    carry = list(baseline)
    carry[3] = _lui(5, 1)
    carry[6] = _addiu(5, 5, 0x8004)

    b_diffs, c_diffs = probe.validate_address_controls(baseline, plus_four, carry)
    assert [row["address"] for row in b_diffs] == ["0x4d0"]
    assert [row["address"] for row in c_diffs] == ["0x4c4", "0x4d0"]

    changed_outside_pair = list(plus_four)
    changed_outside_pair[0] ^= 1
    with pytest.raises(probe.ProbeError, match="case B"):
        probe.validate_address_controls(baseline, changed_outside_pair, carry)


def test_nonrelocated_negative_control_requires_a_nonrelocated_site() -> None:
    baseline = [0] * 20
    tampered = list(baseline)
    tampered[0] = 1
    assert probe.validate_nonrelocated_tamper(
        baseline, tampered, word_index=0, relocation_sites={}
    )[0]["address"] == "0x4b8"
    with pytest.raises(probe.ProbeError, match="is relocated"):
        probe.validate_nonrelocated_tamper(
            baseline, tampered, word_index=0, relocation_sites={0: object()}
        )


def test_linker_script_pins_layout_and_retains_metrowerks_metadata() -> None:
    script = probe._linker_script()
    assert '.text 0x4b8 : SUBALIGN(4) { *(.text) }' in script
    assert "ASSERT(SIZEOF(.text) == 0x50" in script
    assert ".mwcats 0 : SUBALIGN(4) { KEEP(*(.mwcats)) }" in script
    assert "ASSERT(SIZEOF(.mwcats) == 0x8" in script
    assert "stub" not in script.lower()


def test_linked_elf_header_validation_rejects_wrong_type_arch_and_endianness() -> None:
    module = elf.parse(synthetic.build_mips_object())
    probe._require_mips_elf(module, file_type=elf.ET_REL, label="synthetic ET_REL")
    with pytest.raises(probe.ProbeError, match="type"):
        probe._require_mips_elf(module, file_type=elf.ET_EXEC, label="wrong type")

    wrong_endian = elf.parse(synthetic.build_mips_object())
    wrong_endian.header = replace(wrong_endian.header, ei_data=2)
    with pytest.raises(probe.ProbeError, match="little-endian"):
        probe._require_mips_elf(wrong_endian, file_type=elf.ET_REL, label="wrong endian")

    wrong_machine = elf.parse(synthetic.build_mips_object())
    wrong_machine.header = replace(wrong_machine.header, e_machine=3)
    with pytest.raises(probe.ProbeError, match="not MIPS"):
        probe._require_mips_elf(wrong_machine, file_type=elf.ET_REL, label="wrong machine")

    wrong_class = elf.parse(synthetic.build_mips_object())
    wrong_class.header = replace(wrong_class.header, ei_class=2)
    with pytest.raises(probe.ProbeError, match="ELF32"):
        probe._require_mips_elf(wrong_class, file_type=elf.ET_REL, label="wrong class")


def test_bad_text_layout_and_unresolved_relocations_are_rejected() -> None:
    module = elf.parse(synthetic.build_mips_object())
    with pytest.raises(probe.ProbeError, match="linked .text layout"):
        probe.validate_linked_text_layout(module)
    with pytest.raises(probe.ProbeError, match="unconsumed relocations"):
        probe.validate_link_has_no_unresolved(module)


def test_undefined_symbol_is_rejected_even_if_relocations_are_empty() -> None:
    module = elf.parse(synthetic.build_mips_object())
    index = next(index for index, symbol in enumerate(module.symbols) if symbol.name)
    undefined = replace(module.symbols[index], shndx=elf.SHN_UNDEF)
    module.symbols = (*module.symbols[:index], undefined, *module.symbols[index + 1 :])
    module.relocations = ()
    with pytest.raises(probe.ProbeError, match="undefined symbols"):
        probe.validate_link_has_no_unresolved(module)


def test_object_or_source_from_another_build_is_rejected_by_hash() -> None:
    probe.validate_recorded_hash("object", "a" * 64, "a" * 64)
    with pytest.raises(probe.ProbeError, match="SHA-256"):
        probe.validate_recorded_hash("object", "a" * 64, "b" * 64)
    with pytest.raises(probe.ProbeError, match="SHA-256"):
        probe.validate_recorded_hash("PRX", "a" * 64, None)


def test_only_expected_fresh_match_baseline_is_accepted() -> None:
    record = {
        "status": "INCONCLUSIVE",
        "match": {
            "status": "INCONCLUSIVE",
            "matching_words": 18,
            "total_words": 20,
            "difference_count": 0,
            "relocation_issues": [],
        },
    }
    assert probe.validate_match_baseline(record, 5) == record["match"]
    with pytest.raises(probe.ProbeError, match="18/20 INCONCLUSIVE"):
        probe.validate_match_baseline(record, 0)
    wrong = {**record, "match": {**record["match"], "difference_count": 1}}
    with pytest.raises(probe.ProbeError, match="18/20 INCONCLUSIVE"):
        probe.validate_match_baseline(wrong, 5)


def test_saved_match_record_must_match_the_fresh_match_function_stdout() -> None:
    stdout = {
        "function": "func_000004B8",
        "status": "INCONCLUSIVE",
        "provenance": {"source_sha256": "a" * 64, "object_sha256": "b" * 64},
        "match": {"status": "INCONCLUSIVE", "matching_words": 18},
    }
    persisted = {key: value for key, value in stdout.items() if key != "match"}
    probe.validate_saved_match_record(stdout, persisted)
    stale = {**persisted, "provenance": {**persisted["provenance"], "object_sha256": "c" * 64}}
    with pytest.raises(probe.ProbeError, match="persisted match_function record"):
        probe.validate_saved_match_record(stdout, stale)


def test_report_classification_never_promotes_controlled_equality() -> None:
    assert probe.equivalence_claim(20) == "ASSUMPTION_DEPENDENT"
    assert probe.equivalence_claim(19) == "DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS"
    report = probe._base_report()
    assert report["experiment_status"] == "FAIL"
    assert report["baseline"]["status"] == "INCONCLUSIVE"
    assert report["identity_evidence"]["independently_verified"] is False
    assert report["promoted_to_matched"] is False


def test_canonical_json_is_stable_and_sorted() -> None:
    first = {"z": [1, 2], "a": {"b": True}}
    second = {"a": {"b": True}, "z": [1, 2]}
    assert probe.canonical_json(first) == probe.canonical_json(second)
    assert probe.canonical_json(first).endswith("\n")


def test_input_path_cannot_escape_the_seto014_build_tree() -> None:
    root = (REPO_ROOT / "build/seto014").resolve()
    with pytest.raises(probe.ProbeError, match="escapes allowed tree"):
        probe._repo_path(Path("../../private/original/module.prx"), allowed_root=root)


def test_validated_build_root_accepts_real_and_missing_directories_without_creating_them(
    tmp_path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(probe, "REPO_ROOT", repo)
    root = probe._validated_build_root()
    assert root == (repo / "build/seto014").resolve()
    assert not (repo / "build").exists()

    (repo / "build").mkdir()
    root = probe._validated_build_root()
    assert root == (repo / "build/seto014").resolve()
    assert (repo / "build").is_dir()
    assert not (repo / "build/seto014").exists()

    (repo / "build/seto014").mkdir()
    assert probe._validated_build_root() == (repo / "build/seto014").resolve()


@pytest.mark.parametrize("component", ["build", "seto014"])
def test_validated_build_root_rejects_regular_files(tmp_path, monkeypatch, component) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(probe, "REPO_ROOT", repo)
    path = repo / "build"
    if component == "seto014":
        path.mkdir()
        path = path / "seto014"
    path.write_text("not a directory", encoding="utf-8")
    with pytest.raises(probe.ProbeError, match="build path is not a directory"):
        probe._validated_build_root()


def _create_symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"platform does not permit local symlink creation: {exc}")


@pytest.mark.parametrize("component", ["build", "seto014"])
@pytest.mark.parametrize("broken", [False, True], ids=["external", "broken"])
def test_validated_build_root_rejects_symlinks_before_resolve(
    tmp_path, monkeypatch, component, broken
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    if not broken:
        outside.mkdir()
    monkeypatch.setattr(probe, "REPO_ROOT", repo)
    link = repo / "build"
    if component == "seto014":
        link.mkdir()
        link = link / "seto014"
    target = outside / "does-not-exist" if broken else outside
    _create_symlink_or_skip(link, target)
    with pytest.raises(probe.ProbeError, match="build directory must not be a symlink"):
        probe._validated_build_root()


@pytest.mark.parametrize("component", ["build", "seto014"])
def test_invalid_build_root_never_writes_report_to_symlink_target(
    tmp_path, monkeypatch, component, capsys
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")
    monkeypatch.setattr(probe, "REPO_ROOT", repo)
    monkeypatch.chdir(repo)
    link = repo / "build"
    if component == "seto014":
        link.mkdir()
        link = link / "seto014"
    _create_symlink_or_skip(link, outside)

    exit_code = probe.main([])
    captured = capsys.readouterr()
    assert exit_code != 0
    assert "build directory must not be a symlink" in captured.err
    assert "PASS" not in captured.out
    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert sorted(path.name for path in outside.iterdir()) == ["sentinel.txt"]
    assert not (outside / "link-equivalence.json").exists()
