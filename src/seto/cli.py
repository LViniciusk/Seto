"""Command line interface: ``seto <command>``.

Exit codes
----------
``0``  success
``1``  usage, I/O or parse error
``3``  a verification or matching check failed (the operation ran, the answer is "not equal")
``4``  blocked: a required external tool is unavailable
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from seto import __version__, elf, formats, inventory, mips, split
from seto.binio import ParseError, SetoError
from seto.hashing import verify_file
from seto.matching import MATCHED, MatchResult, compare
from seto.toolchain import Settings, detect_all, load_settings

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_MISMATCH = 3
EXIT_BLOCKED = 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seto",
        description="Matching decompilation infrastructure for Yu-Gi-Oh! GX Tag Force 1 (PSP).",
    )
    parser.add_argument("--version", action="version", version=f"seto {__version__}")
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="configuration file (default: config/seto.toml when present)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inventory_parser = subparsers.add_parser(
        "inventory", help="build the deterministic inventory and report"
    )
    inventory_parser.add_argument("--iso", type=Path, default=None)
    inventory_parser.add_argument("--extracted", type=Path, default=None)
    inventory_parser.add_argument("--out", type=Path, default=Path("build/inventory"))
    inventory_parser.add_argument(
        "--no-verify", action="store_true", help="skip ISO size/SHA-256 verification"
    )
    inventory_parser.add_argument("--quiet", action="store_true")

    verify_parser = subparsers.add_parser(
        "verify", help="verify the ISO against the documented baseline"
    )
    verify_parser.add_argument("--iso", type=Path, default=None)

    detect_parser = subparsers.add_parser(
        "detect", help="identify container formats by signature"
    )
    detect_parser.add_argument("paths", nargs="+", type=Path)

    functions_parser = subparsers.add_parser(
        "functions", help="list functions discovered in a module section"
    )
    functions_parser.add_argument("--prx", type=Path, required=True)
    functions_parser.add_argument("--section", default=".text")
    functions_parser.add_argument("--json", action="store_true")

    split_parser = subparsers.add_parser(
        "split", help="derive a validated layout and a splat configuration"
    )
    split_parser.add_argument("--prx", type=Path, required=True)
    split_parser.add_argument("--out", type=Path, default=Path("build/split"))
    split_parser.add_argument("--basename", default=None)
    split_parser.add_argument("--base-path", default="..")
    split_parser.add_argument("--target-path", default=None)
    split_parser.add_argument("--asm-path", default=None)
    split_parser.add_argument("--ld-script-path", default=None)

    check_parser = subparsers.add_parser(
        "check-layout", help="validate a layout.json against the real module"
    )
    check_parser.add_argument("--layout", type=Path, required=True)
    check_parser.add_argument("--prx", type=Path, required=True)

    disasm_parser = subparsers.add_parser(
        "disasm", help="disassemble a section (requires capstone)"
    )
    disasm_parser.add_argument("--prx", type=Path, required=True)
    disasm_parser.add_argument("--section", default=".text")
    disasm_parser.add_argument(
        "--function", type=lambda value: int(value, 0), default=None,
        help="restrict to the function starting at this address",
    )
    disasm_parser.add_argument("--count", type=int, default=None)

    match_parser = subparsers.add_parser(
        "match", help="compare a reconstructed function against the original"
    )
    match_parser.add_argument("--prx", type=Path, required=True)
    match_parser.add_argument("--section", default=".text")
    match_parser.add_argument(
        "--function", type=lambda value: int(value, 0), required=True,
        help="start address of the function to compare",
    )
    match_parser.add_argument("--size", type=lambda value: int(value, 0), default=None)
    match_parser.add_argument("--candidate", type=Path, required=True)
    match_parser.add_argument("--candidate-section", default=None)
    match_parser.add_argument(
        "--candidate-offset", type=lambda value: int(value, 0), default=None,
        help="byte offset of the region inside the candidate",
    )
    match_parser.add_argument("--json", action="store_true")

    toolchain_parser = subparsers.add_parser(
        "toolchain", help="report external tool availability"
    )
    toolchain_parser.add_argument("--json", action="store_true")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        settings = load_settings(arguments.config)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    handlers = {
        "inventory": _command_inventory,
        "verify": _command_verify,
        "detect": _command_detect,
        "functions": _command_functions,
        "split": _command_split,
        "check-layout": _command_check_layout,
        "disasm": _command_disasm,
        "match": _command_match,
        "toolchain": _command_toolchain,
    }
    try:
        return handlers[arguments.command](arguments, settings)
    except (SetoError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


def _command_inventory(arguments: argparse.Namespace, settings: Settings) -> int:
    manifest = inventory.build_manifest(
        iso_path=arguments.iso,
        extracted_root=arguments.extracted,
        settings=settings,
        verify_iso=not arguments.no_verify,
    )
    output_dir = Path(arguments.out)
    manifest_path = inventory.write_json(output_dir / "manifest.json", manifest)
    report_path = inventory.write_text(output_dir / "report.md", inventory.render_markdown(manifest))
    if not arguments.quiet:
        summary = manifest["summary"]
        print(f"manifest: {manifest_path}")
        print(f"report:   {report_path}")
        print(
            f"files: {summary['file_count']}  modules: {summary['module_count']}  "
            f"functions: {summary['function_count']}"
        )
        for error in manifest["module_errors"]:
            print(f"module error: {error['relpath']}: {error['error']}", file=sys.stderr)
    baseline = manifest["baseline"]
    if baseline.get("verified") is False:
        for issue in baseline.get("issues", []):
            print(f"baseline: {issue}", file=sys.stderr)
        return EXIT_MISMATCH
    if baseline.get("present") is False:
        print(f"baseline: ISO not found at {baseline['path']}", file=sys.stderr)
    return EXIT_OK


def _command_verify(arguments: argparse.Namespace, settings: Settings) -> int:
    baseline = inventory.baseline_from_settings(settings)
    iso = Path(arguments.iso) if arguments.iso is not None else Path(str(baseline["iso"]))
    if not iso.is_file():
        print(f"error: ISO not found: {iso}", file=sys.stderr)
        return EXIT_ERROR
    if not baseline["expected_size"] or not baseline["expected_sha256"]:
        print("error: no baseline size/sha256 configured", file=sys.stderr)
        return EXIT_ERROR
    result = verify_file(iso, int(baseline["expected_size"]), str(baseline["expected_sha256"]))
    print(f"{iso}")
    print(f"  size:   {result.size}")
    print(f"  sha256: {result.sha256.upper()}")
    if result.ok:
        print("  status: OK")
        return EXIT_OK
    for issue in result.issues:
        print(f"  status: FAIL ({issue})", file=sys.stderr)
    return EXIT_MISMATCH


def _command_detect(arguments: argparse.Namespace, settings: Settings) -> int:
    del settings
    exit_code = EXIT_OK
    for path in arguments.paths:
        if not path.is_file():
            print(f"{path}: MISSING", file=sys.stderr)
            exit_code = EXIT_ERROR
            continue
        signature = formats.identify_file(path)
        print(f"{path}: {signature.fmt} - {signature.description}")
        if signature.fmt == "unknown":
            exit_code = EXIT_MISMATCH
    return exit_code


def _command_functions(arguments: argparse.Namespace, settings: Settings) -> int:
    del settings
    parsed = elf.parse(arguments.prx)
    section = parsed.require_section(arguments.section)
    functions = mips.find_functions(
        parsed.section_data(section), section.addr, f"{arguments.prx.name}:{arguments.section}"
    )
    if arguments.json:
        print(
            json.dumps(
                {
                    "prx": str(arguments.prx),
                    "section": arguments.section,
                    "address": section.addr,
                    "size": section.size,
                    "functions": [item.summary() for item in functions],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return EXIT_OK
    print(f"{arguments.prx} :: {arguments.section} (0x{section.size:x} bytes at 0x{section.addr:x})")
    print(f"{'name':<16} {'start':>10} {'size':>6}  calls")
    for item in functions:
        calls = ", ".join(f"0x{target:x}" for target in item.calls) or "-"
        print(f"{item.name():<16} {item.start:>#10x} {item.size:>6}  {calls}")
    print(f"total: {len(functions)} functions")
    return EXIT_OK


def _command_split(arguments: argparse.Namespace, settings: Settings) -> int:
    del settings
    parsed = elf.parse(arguments.prx)
    basename = arguments.basename or arguments.prx.stem
    layout = split.build_layout(parsed, basename)
    issues = split.validate_layout(layout, parsed)

    output_dir = Path(arguments.out)
    layout_path = inventory.write_text(output_dir / "layout.json", layout.to_json())
    target_path = arguments.target_path or str(arguments.prx)
    yaml_text = split.emit_splat_yaml(
        layout,
        base_path=arguments.base_path,
        target_path=target_path,
        asm_path=arguments.asm_path or f"asm/{basename}",
        ld_script_path=arguments.ld_script_path or f"build/{basename}.ld",
    )
    issues += split.cross_check_yaml(yaml_text, layout)
    yaml_path = inventory.write_text(output_dir / f"{basename}.yaml", yaml_text)

    print(f"layout: {layout_path}")
    print(f"splat:  {yaml_path}")
    print(
        f"segments: {len(layout.segments)}  subsegments: {len(layout.subsegments())}  "
        f"image delta: 0x{layout.image_delta:x}"
    )
    errors = [issue for issue in issues if issue.severity == split.ERROR]
    for issue in issues:
        print(f"  {issue.render()}")
    if errors:
        print(f"{len(errors)} layout error(s)", file=sys.stderr)
        return EXIT_MISMATCH
    print("layout validated against the real module")
    return EXIT_OK


def _command_check_layout(arguments: argparse.Namespace, settings: Settings) -> int:
    del settings
    parsed = elf.parse(arguments.prx)
    layout = split.Layout.from_dict(inventory.load_manifest(arguments.layout))
    issues = split.validate_layout(layout, parsed)
    for issue in issues:
        print(f"  {issue.render()}")
    errors = [issue for issue in issues if issue.severity == split.ERROR]
    if errors:
        print(f"{len(errors)} layout error(s)", file=sys.stderr)
        return EXIT_MISMATCH
    print("layout OK")
    return EXIT_OK


def _command_disasm(arguments: argparse.Namespace, settings: Settings) -> int:
    del settings
    parsed = elf.parse(arguments.prx)
    section = parsed.require_section(arguments.section)
    data = parsed.section_data(section)
    base = section.addr
    if arguments.function is not None:
        functions = mips.find_functions(data, base, f"{arguments.prx.name}:{arguments.section}")
        match = next((item for item in functions if item.start == arguments.function), None)
        if match is None:
            print(
                f"error: no function starts at 0x{arguments.function:x}; "
                f"known starts: {', '.join(f'0x{item.start:x}' for item in functions)}",
                file=sys.stderr,
            )
            return EXIT_ERROR
        data = data[match.start - base : match.end - base]
        base = match.start
    try:
        lines = mips.disassemble(data, base, arguments.count)
    except RuntimeError as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return EXIT_BLOCKED

    annotation = _relocation_annotation(parsed, arguments.section, base, len(data))
    for index, line in enumerate(lines):
        marker = annotation.get(base + index * 4)
        print(f"{line}{'  ; ' + marker if marker else ''}")
    return EXIT_OK


def _relocation_annotation(
    parsed: elf.ElfFile, section_name: str, base: int, length: int
) -> dict[int, str]:
    section = parsed.require_section(section_name)
    region_offset = base - section.addr
    annotations: dict[int, str] = {}
    for relocation in parsed.relocations_for(section_name):
        if relocation.section_offset is None:
            continue
        delta = relocation.section_offset - region_offset
        if 0 <= delta < length and delta % 4 == 0:
            symbol = relocation.symbol or f"addend=0x{relocation.addend:x}"
            annotations[base + delta] = f"{relocation.type_name} {symbol}"
    return annotations


def _command_match(arguments: argparse.Namespace, settings: Settings) -> int:
    del settings
    original_elf = elf.parse(arguments.prx)
    section = original_elf.require_section(arguments.section)
    code = original_elf.section_data(section)
    functions = mips.find_functions(code, section.addr, f"{arguments.prx.name}:{arguments.section}")
    function = next((item for item in functions if item.start == arguments.function), None)
    if function is None and arguments.size is None:
        print(
            f"error: no function starts at 0x{arguments.function:x}; "
            f"known starts: {', '.join(f'0x{item.start:x}' for item in functions)}",
            file=sys.stderr,
        )
        return EXIT_ERROR

    if arguments.size is not None:
        start, size = arguments.function, arguments.size
        name = mips.function_name(start)
    else:
        assert function is not None
        start, size = function.start, function.size
        name = function.name()

    region_offset = start - section.addr
    if region_offset < 0 or region_offset + size > section.size:
        print("error: requested function range leaves the section", file=sys.stderr)
        return EXIT_ERROR
    original = code[region_offset : region_offset + size]

    candidate_section_name = arguments.candidate_section or arguments.section
    candidate, candidate_section_offset, candidate_relocations, limitations = _load_candidate(
        path=arguments.candidate,
        section_relative=region_offset,
        size=size,
        section_name=candidate_section_name,
        explicit_offset=arguments.candidate_offset,
    )

    result = compare(
        original,
        candidate,
        name=name,
        address=start,
        original_relocations=original_elf.relocations_for(arguments.section),
        candidate_relocations=candidate_relocations,
        original_section_offset=region_offset,
        candidate_section_offset=candidate_section_offset,
        limitations=limitations,
    )

    if arguments.json:
        print(json.dumps(result.summary(), indent=2, sort_keys=True))
    else:
        _print_match(result)
    return EXIT_OK if result.is_matched else EXIT_MISMATCH


def _load_candidate(
    *,
    path: Path,
    section_relative: int,
    size: int,
    section_name: str,
    explicit_offset: int | None,
) -> tuple[bytes, int, tuple[elf.Relocation, ...], tuple[str, ...]]:
    """Load the candidate region.

    Returns the bytes, the region's offset relative to its own section start
    (the same space as ``Relocation.section_offset``), the candidate's
    relocations for that section, and any limitations.  When the candidate is a
    linked module the region defaults to the same section-relative offset as
    the original; when it is a raw blob it defaults to offset 0.
    ``--candidate-offset`` always wins.
    """
    if not path.is_file():
        raise FileNotFoundError(f"candidate not found: {path}")
    try:
        candidate_elf = elf.parse(path)
    except ParseError as exc:
        data = path.read_bytes()
        offset = explicit_offset or 0
        if offset + size > len(data):
            raise ParseError(
                f"candidate {path} is too small: need {size} bytes at 0x{offset:x}, "
                f"file is {len(data)} bytes"
            ) from exc
        return (
            data[offset : offset + size],
            offset,
            (),
            (f"candidate is not ELF ({exc}); compared as raw bytes without relocations",),
        )

    section = candidate_elf.section(section_name)
    if section is None:
        raise ParseError(f"candidate {path} has no section {section_name!r}")
    file_offset = (
        explicit_offset
        if explicit_offset is not None
        else section.offset + section_relative
    )
    if file_offset < section.offset or file_offset + size > section.offset + section.size:
        raise ParseError(
            f"candidate section {section_name!r} does not contain {size} bytes at 0x{file_offset:x}"
        )
    return (
        candidate_elf.reader.bytes_at(file_offset, size),
        file_offset - section.offset,
        candidate_elf.relocations_for(section_name),
        (),
    )


def _print_match(result: MatchResult) -> None:
    print(f"function {result.name} @ 0x{result.address:x}")
    print(f"  status:  {result.status}")
    print(f"  match:   {result.percent:.2f}% ({result.matching_words}/{result.total_words} words)")
    print(f"  diffs:   {result.difference_count}")
    for difference in result.differences:
        print(
            f"    +0x{difference.word_index * 4:x} @0x{difference.address:x}: "
            f"{difference.original:08x} != {difference.candidate:08x} ({difference.reason})"
        )
    for issue in result.relocation_issues[:10]:
        print(f"    reloc: {issue}")
    for limitation in result.limitations:
        print(f"    note: {limitation}")
    if result.status == MATCHED:
        print("  result: MATCHED (no divergence proven in the validated range)")


def _command_toolchain(arguments: argparse.Namespace, settings: Settings) -> int:
    statuses = detect_all(settings)
    if arguments.json:
        print(json.dumps({"tools": [status.summary() for status in statuses]}, indent=2, sort_keys=True))
        return EXIT_OK
    print("external tools")
    for status in statuses:
        print(f"  {status.line()}")
    missing = [status.name for status in statuses if not status.found]
    print(f"missing: {', '.join(missing) if missing else 'none'}")
    return EXIT_OK


__all__ = ["EXIT_BLOCKED", "EXIT_ERROR", "EXIT_MISMATCH", "EXIT_OK", "build_parser", "main"]
