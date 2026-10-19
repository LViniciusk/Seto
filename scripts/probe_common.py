#!/usr/bin/env python3
"""Shared, function-agnostic helpers for the controlled post-link experiments.

``probe_link_equivalence`` (SETO-DECOMP-014) and ``probe_jump_table_equivalence``
(SETO-DECOMP-015) reuse exactly the pieces that do not depend on the function
under study:

* controlled process execution (argv, timeout, no ``shell=True``);
* canonical JSON and hash validation;
* ELF header / undefined-symbol validation;
* literal word comparison;
* the build-path protections (root validation before ``resolve``, symlink
  rejection, output confinement inside the build tree).

Nothing here knows a function name, address or artifact.  The docstring of each
entry point states its contract; the two experiment scripts keep their own
function-specific validation and report shape.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Sequence

from seto import elf
from seto.binio import ParseError


class ProbeError(Exception):
    """An objective experiment error with a report classification."""

    def __init__(self, status: str, message: str) -> None:
        super().__init__(message)
        self.status = status


def canonical_json(value: object) -> str:
    """Serialize stable report data without timestamps or absolute paths."""
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def compare_word_sequences(
    original: Sequence[int],
    candidate: Sequence[int],
    *,
    address: int,
    expected_words: int,
) -> list[dict[str, object]]:
    """Compare all words literally; no relocation masks or normalization apply."""
    if len(original) != expected_words or len(candidate) != expected_words:
        raise ParseError(
            f"expected {expected_words} words on each side; "
            f"got original={len(original)}, candidate={len(candidate)}"
        )
    return [
        {
            "word_index": index,
            "address": f"0x{address + index * 4:x}",
            "original": f"0x{left:08x}",
            "linked": f"0x{right:08x}",
        }
        for index, (left, right) in enumerate(zip(original, candidate, strict=True))
        if left != right
    ]


def paired_effective_address(hi_word: int, lo_word: int) -> int:
    """Decode a linked LUI/ADDIU pair using signed LO16 semantics."""
    from seto import matching, mips

    if mips.opcode(hi_word) != 0x0F or mips.rs(hi_word) != 0:
        raise ParseError("HI16 site is not a LUI instruction")
    if mips.opcode(lo_word) != 0x09 or mips.rt(hi_word) != mips.rs(lo_word):
        raise ParseError("LO16 site is not an ADDIU consuming the LUI register")
    return matching.combine_hi16_lo16(
        mips.immediate(hi_word), mips.signed_immediate(lo_word)
    )


def validate_recorded_hash(label: str, actual: str, recorded: object) -> None:
    if not isinstance(recorded, str) or actual != recorded:
        raise ProbeError("FAIL", f"{label} SHA-256 does not match its compile provenance record")


def validate_saved_match_record(
    stdout_record: dict[str, object], saved_record: dict[str, object]
) -> None:
    """Require the persisted match_function provenance record to match this run."""
    expected = {key: value for key, value in stdout_record.items() if key != "match"}
    if saved_record != expected:
        raise ProbeError("FAIL", "persisted match_function record differs from this fresh invocation")


def validate_nonrelocated_tamper(
    original: Sequence[int],
    tampered: Sequence[int],
    *,
    word_index: int,
    relocation_sites: dict[int, object],
    address: int,
    expected_words: int,
) -> list[dict[str, object]]:
    """Require a tampered instruction to be non-relocated and the only difference."""
    if word_index in relocation_sites:
        raise ProbeError("FAIL", f"tamper word {word_index} is relocated")
    differences = compare_word_sequences(
        original, tampered, address=address, expected_words=expected_words
    )
    if [row["word_index"] for row in differences] != [word_index]:
        raise ProbeError("FAIL", "nonrelocated instruction tamper was not isolated and detected")
    return differences


def inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def validated_build_root(repo_root: Path, *, subdir: str) -> Path:
    """Reject redirected build roots before resolving any path components.

    Symlinks (including broken ones) and regular files are rejected for both
    ``build`` and ``build/<subdir>``.  A missing directory is accepted and never
    created here.
    """
    build = repo_root / "build"
    root = build / subdir
    for path in (build, root):
        if path.is_symlink():
            raise ProbeError("FAIL", f"build directory must not be a symlink: {path}")
        if path.exists() and not path.is_dir():
            raise ProbeError("FAIL", f"build path is not a directory: {path}")
    return root.resolve()


def ensure_build_dir(path: Path, build_root: Path) -> None:
    if path.is_symlink():
        raise ProbeError("FAIL", f"build directory may not be a symlink: {path.as_posix()}")
    path.mkdir(parents=True, exist_ok=True)
    if not inside(path, build_root) or not path.is_dir():
        raise ProbeError("FAIL", f"build directory escapes its allowed root: {path}")


def prepare_build_file(path: Path, build_root: Path) -> None:
    if path.is_symlink():
        raise ProbeError("FAIL", f"build output may not be a symlink: {path.as_posix()}")
    if not inside(path, build_root):
        raise ProbeError("FAIL", f"build output escapes its allowed root: {path}")
    if path.exists() and not path.is_file():
        raise ProbeError("FAIL", f"build output is not a regular file: {path.as_posix()}")


def write_build_text(path: Path, text: str, build_root: Path) -> None:
    prepare_build_file(path, build_root)
    # Preserve canonical LF bytes on Windows as well as POSIX.  Path.write_text's
    # default newline translation otherwise makes hashed JSON reports differ by
    # host even when their text is identical.
    path.write_text(text, encoding="utf-8", newline="\n")


def write_build_bytes(path: Path, data: bytes, build_root: Path) -> None:
    prepare_build_file(path, build_root)
    path.write_bytes(data)


def repo_path(value: Path, *, repo_root: Path, allowed_root: Path) -> Path:
    path = value if value.is_absolute() else repo_root / value
    path = path.resolve()
    if not inside(path, allowed_root):
        raise ProbeError("FAIL", f"path escapes allowed tree: {value}")
    return path


def relative(path: Path, repo_root: Path) -> str:
    return path.resolve().relative_to(repo_root.resolve()).as_posix()


def run(
    argv: list[str],
    *,
    cwd: Path,
    timeout: int = 300,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def require_mips_elf(module: elf.ElfFile, *, file_type: int, label: str) -> None:
    header = module.header
    if header.ei_class != elf.ELFCLASS32:
        raise ProbeError("UNSUPPORTED", f"{label} is not ELF32")
    if header.ei_data != elf.ELFDATA2LSB:
        raise ProbeError("UNSUPPORTED", f"{label} is not little-endian")
    if header.e_machine != elf.EM_MIPS:
        raise ProbeError("UNSUPPORTED", f"{label} is not MIPS")
    if header.e_type != file_type:
        raise ProbeError(
            "UNSUPPORTED",
            f"{label} has type {header.file_type_name}, expected {elf.FILE_TYPE_NAMES[file_type]}",
        )


def validate_link_has_no_unresolved(module: elf.ElfFile) -> None:
    if module.relocations:
        raise ProbeError(
            "FAIL",
            f"linked ELF contains unconsumed relocations: {[r.summary() for r in module.relocations]}",
        )
    undefined = [
        symbol.name for symbol in module.symbols if symbol.shndx == elf.SHN_UNDEF and symbol.name
    ]
    if undefined:
        raise ProbeError("FAIL", f"linked ELF has undefined symbols: {undefined}")
