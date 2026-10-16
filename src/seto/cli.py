"""Command line interface: ``seto <command>``.

Exit codes
----------
``0``  success
``1``  usage, I/O or parse error
``3``  a verification or matching check failed (the operation ran, the answer is "not equal")
``4``  blocked: a required external tool is unavailable
``5``  inconclusive: the operation ran but the evidence is insufficient to decide
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Sequence

from seto import __version__, elf, formats, imports, inventory, mips, split
from seto.binio import ParseError, SetoError
from seto.hashing import sha256_file, verify_file
from seto.matching import (
    INCONCLUSIVE,
    MATCHED,
    NONMATCHING,
    CallResolver,
    MatchResult,
    compare,
)
from seto.smoke import smoke_report
from seto.toolchain import (
    BLOCKED,
    INCOMPATIBLE,
    MISSING,
    TOOL_SPECS,
    UNSUPPORTED,
    Settings,
    detect_all,
    find_tool,
    load_settings,
    run,
    splat_argv,
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_MISMATCH = 3
EXIT_BLOCKED = 4
EXIT_INCONCLUSIVE = 5

#: splat disassembles a whole module; a small one takes seconds, but the bound
#: exists so a wedged tool can never hang the pipeline.
SPLAT_TIMEOUT = 900.0


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
    split_parser.add_argument(
        "--base-path", default="../..",
        help="splat base_path, relative to the config file's own directory",
    )
    split_parser.add_argument("--target-path", default=None)
    split_parser.add_argument("--asm-path", default=None)
    split_parser.add_argument("--ld-script-path", default=None)
    split_parser.add_argument(
        "--run-splat", action="store_true",
        help="run splat on the emitted config and verify its listing against the module",
    )

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
        help="absolute file offset of the region inside the candidate",
    )
    match_parser.add_argument(
        "--candidate-section-offset", type=lambda value: int(value, 0), default=None,
        help="offset of the region relative to its section inside the candidate",
    )
    match_parser.add_argument(
        "--candidate-symbol", default=None,
        help="ELF symbol that starts the function inside the candidate (preferred)",
    )
    match_parser.add_argument(
        "--candidate-symbol-fallback", action="store_true",
        help="allow automatic detection when --candidate-symbol is not found (default: INCONCLUSIVE)",
    )
    match_parser.add_argument("--json", action="store_true")

    imports_parser = subparsers.add_parser(
        "imports", help="recover the imported-function identity of the module's calls"
    )
    imports_parser.add_argument("--prx", type=Path, required=True)
    imports_parser.add_argument("--section", default=".text")
    imports_parser.add_argument(
        "--function", type=lambda value: int(value, 0), default=None,
        help="restrict the call report to the function starting at this address",
    )
    imports_parser.add_argument("--json", action="store_true")
    imports_parser.add_argument(
        "--out", type=Path, default=None,
        help="also write the JSON report to this path",
    )

    toolchain_parser = subparsers.add_parser(
        "toolchain", help="report external tool availability"
    )
    toolchain_parser.add_argument("--json", action="store_true")
    toolchain_parser.add_argument(
        "--smoke",
        action="store_true",
        help="prove what each tool can actually do with a synthetic input",
    )
    toolchain_parser.add_argument(
        "--tool",
        action="append",
        default=None,
        metavar="NAME",
        choices=tuple(spec.name for spec in TOOL_SPECS) + ("ghidra",),
        help="restrict --smoke to this tool (repeatable)",
    )
    toolchain_parser.add_argument(
        "--smoke-workspace",
        type=Path,
        default=None,
        help="keep the synthetic inputs and artefacts here instead of a temporary directory",
    )
    toolchain_parser.add_argument(
        "--out", type=Path, default=None,
        help="also write the JSON report to this path",
    )

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
        "imports": _command_imports,
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
    parsed = elf.parse(arguments.prx)
    basename = arguments.basename or arguments.prx.stem
    layout = split.build_layout(parsed, basename)
    issues = list(split.validate_layout(layout, parsed))

    output_dir = Path(arguments.out)
    layout_path = inventory.write_text(output_dir / "layout.json", layout.to_json())
    target_path = arguments.target_path or str(arguments.prx)
    asm_path = arguments.asm_path or f"asm/{basename}"
    ld_script_path = arguments.ld_script_path or f"build/{basename}.ld"
    yaml_text = split.emit_splat_yaml(
        layout,
        base_path=arguments.base_path,
        target_path=target_path,
        asm_path=asm_path,
        ld_script_path=ld_script_path,
    )
    issues += split.cross_check_yaml(yaml_text, layout)
    yaml_path = inventory.write_text(output_dir / f"{basename}.yaml", yaml_text)

    print(f"layout: {layout_path}")
    print(f"splat:  {yaml_path}")
    print(
        f"segments: {len(layout.segments)}  subsegments: {len(layout.subsegments())}  "
        f"image delta: 0x{layout.image_delta:x}"
    )

    if arguments.run_splat:
        blocked = _run_splat(arguments, settings, layout, yaml_path, asm_path, issues)
        if blocked is not None:
            return blocked

    errors = [issue for issue in issues if issue.severity == split.ERROR]
    for issue in issues:
        print(f"  {issue.render()}")
    if errors:
        print(f"{len(errors)} layout error(s)", file=sys.stderr)
        return EXIT_MISMATCH
    print("layout validated against the real module")
    return EXIT_OK


def _run_splat(
    arguments: argparse.Namespace,
    settings: Settings,
    layout: split.Layout,
    yaml_path: Path,
    asm_path: str,
    issues: list[split.LayoutIssue],
) -> int | None:
    """Run splat on the emitted config and verify what it produced.

    Returns an exit code when the pipeline cannot continue (the tool is missing,
    or it failed), and ``None`` when the artefacts were produced and checked, in
    which case ``issues`` carries whatever the check found.
    """
    spec = next(item for item in TOOL_SPECS if item.name == "splat")
    status = find_tool(spec, settings.tool_path("splat"))
    if not status.found or status.path is None:
        print(f"BLOCKED: splat is unavailable: {status.reason}", file=sys.stderr)
        return EXIT_BLOCKED

    result = run(splat_argv(status.path, yaml_path), timeout=SPLAT_TIMEOUT)
    if not result.ok:
        reason = "timed out" if result.timed_out else f"exit code {result.returncode}"
        print(f"error: splat failed ({reason})", file=sys.stderr)
        for line in result.combined().splitlines()[-5:]:
            print(f"  {line}", file=sys.stderr)
        return EXIT_ERROR

    print(f"splat:  {status.path} ({status.version or 'unknown version'})")
    lines = [line.rstrip() for line in result.stdout.splitlines()]
    start = next((index for index, line in enumerate(lines) if line.startswith("Split ")), None)
    if start is not None:
        for line in lines[start:]:
            if not line.strip():
                break
            print(f"  {line.strip()}")

    # splat resolves ``base_path`` relative to the configuration file's own
    # directory, so the emitted artefacts are found from there.
    base = (yaml_path.parent / arguments.base_path).resolve()
    for listing in split.verify_splat_output(layout, arguments.prx.read_bytes(), base / asm_path):
        issues += listing.issues
        verdict = (
            "verified against the original bytes"
            if listing.verified
            else f"{len(listing.issues)} issue(s), see below"
        )
        print(f"listing: {listing.name} {listing.words} words ({verdict})")
    return None


def _command_check_layout(arguments: argparse.Namespace, settings: Settings) -> int:
    del settings
    parsed = elf.parse(arguments.prx)
    layout = split.load_layout(arguments.layout)
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
    try:
        region = _load_candidate(
            path=arguments.candidate,
            size=size,
            section_name=candidate_section_name,
            original_section_relative=region_offset,
            file_offset=arguments.candidate_offset,
            section_relative=arguments.candidate_section_offset,
            symbol=arguments.candidate_symbol,
            symbol_fallback=arguments.candidate_symbol_fallback,
        )
    except Inconclusive as exc:
        print(f"INCONCLUSIVE: {exc}", file=sys.stderr)
        return EXIT_INCONCLUSIVE

    # A call is the one reference the two sides may encode differently: the
    # module stores the trampoline it calls, a relocatable object stores the
    # symbol its author declared for it.  The module's own import table is the
    # authority that decides whether both name the same imported function.
    resolver = _call_resolver(original_elf, region.symbol_addresses)

    # ``seto match`` compares instructions and relocations; it cannot know where
    # the candidate came from, so its evidence is always "binary-range" and a
    # MATCHED result here is never by itself a verified decompilation.  Only
    # scripts/match_function.py, which performed the compilation, can claim that.
    result = compare(
        original,
        region.data,
        name=name,
        address=start,
        original_relocations=original_elf.relocations_for(arguments.section),
        candidate_relocations=region.relocations,
        original_section_offset=region_offset,
        candidate_section_offset=region.section_offset,
        limitations=region.limitations,
        call_resolver=resolver,
    )

    if arguments.json:
        payload = result.summary()
        payload["candidate"] = {
            "path": str(arguments.candidate),
            "location": region.description,
            "section_offset": region.section_offset,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_match(result, region)
    if result.status == MATCHED:
        return EXIT_OK
    if result.status == NONMATCHING:
        return EXIT_MISMATCH
    return EXIT_INCONCLUSIVE


def _relative_posix(path: Path) -> str:
    """Render a path the same way on every machine.

    Reports are written to be diffed, so a path is expressed relative to the
    working directory and with ``/`` separators; a path that is not below the
    working directory keeps its own (absolute) form rather than pretending to be
    relative.
    """
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _command_imports(arguments: argparse.Namespace, settings: Settings) -> int:
    del settings
    original_elf = elf.parse(arguments.prx)
    table = imports.build_import_table(original_elf)
    section = original_elf.require_section(arguments.section)

    start = end = None
    name = arguments.section
    if arguments.function is not None:
        code = original_elf.section_data(section)
        functions = mips.find_functions(code, section.addr, f"{arguments.prx.name}:{section.name}")
        function = next((item for item in functions if item.start == arguments.function), None)
        if function is None:
            print(
                f"error: no function starts at 0x{arguments.function:x} in {section.name}",
                file=sys.stderr,
            )
            return EXIT_ERROR
        start, end = function.start, function.end
        name = function.name()

    references = imports.call_references(
        original_elf, table, section=section.name, start=start, end=end
    )
    unresolved = [item for item in references if item.kind == "unknown"]

    payload = {
        "prx": _relative_posix(arguments.prx),
        "sha256": sha256_file(arguments.prx),
        "section": section.name,
        "function": None if start is None else f"0x{start:x}",
        "imports": table.summary(),
        "references": [item.summary() for item in references],
        "unresolved": len(unresolved),
    }
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if arguments.out is not None:
        inventory.write_text(arguments.out, text)

    if arguments.json:
        print(text, end="")
    else:
        _print_imports(arguments, table, name, references, unresolved)

    return EXIT_INCONCLUSIVE if unresolved else EXIT_OK


def _print_imports(
    arguments: argparse.Namespace,
    table: imports.ImportTable,
    name: str,
    references: tuple[imports.CallReference, ...],
    unresolved: list[imports.CallReference],
) -> None:
    print(f"{arguments.prx} :: {table.module}")
    if not table.tables:
        print(f"no {imports.LIB_STUB_SECTION} table: this module declares no imports")
        return
    print(f"{'library':<16} {'stubs':>6}  {'stub range':<20} {'nid range':<20}")
    for item in table.tables:
        stub_range = f"[0x{item.stub_table:x}, 0x{item.stub_end:x})"
        nid_range = f"[0x{item.nid_table:x}, 0x{item.nid_end:x})"
        print(f"{item.library:<16} {item.stub_count:>6}  {stub_range:<20} {nid_range:<20}")
    print(f"total: {len(table.tables)} libraries, {len(table.imports)} imported functions")
    if references:
        print(f"calls in {name}:")
        for item in references:
            print(f"  {item.line()}")
    if unresolved:
        print(f"UNRESOLVED: {len(unresolved)} call reference(s) could not be identified")


@dataclass(frozen=True)
class CandidateRegion:
    """A candidate region located inside a compiled or raw file."""

    data: bytes
    section_offset: int
    relocations: tuple[elf.Relocation, ...]
    limitations: tuple[str, ...]
    description: str
    #: Symbol name -> module address, for a *linked* candidate only (``ET_REL``
    #: values are section offsets, which name no module address).
    symbol_addresses: dict[str, int] = field(default_factory=dict)


class Inconclusive(Exception):
    """The candidate region cannot be pinned down unambiguously."""


class SymbolNotFound(Exception):
    """The requested symbol is not defined in the requested section."""


@dataclass(frozen=True)
class SymbolLocation:
    """Where a requested candidate symbol was found inside a section."""

    section_offset: int
    description: str


def _load_candidate(
    *,
    path: Path,
    size: int,
    section_name: str,
    original_section_relative: int,
    file_offset: int | None = None,
    section_relative: int | None = None,
    symbol: str | None = None,
    symbol_fallback: bool = False,
) -> CandidateRegion:
    """Locate the candidate region, distinguishing file and section offsets.

    Resolution order (highest priority first):

    1. ``--candidate-offset``: an absolute file offset.
    2. ``--candidate-section-offset``: an offset relative to its section.
    3. ``--candidate-symbol``: an ELF symbol whose ``value`` starts the function.
    4. For ``ET_REL`` objects, the only function discovered in the section.
    5. For linked modules, the same section-relative offset as the original.

    A raw (non-ELF) file is compared as bytes but is explicitly flagged as a
    limitation, so it can never yield a *verified* ``MATCHED``.  A file that
    begins with the ELF magic but fails to parse is rejected instead of being
    silently downgraded to a raw blob.
    """
    if not path.is_file():
        raise FileNotFoundError(f"candidate not found: {path}")
    magic = _read_magic(path)

    if magic != elf.ELF_MAGIC:
        if section_relative is not None or symbol is not None:
            raise ParseError("--candidate-section-offset/--candidate-symbol require an ELF candidate")
        offset = file_offset or 0
        data = path.read_bytes()
        _validate_file_range(offset, size, len(data), f"{path}")
        return CandidateRegion(
            data=data[offset : offset + size],
            section_offset=offset,
            relocations=(),
            limitations=(
                "candidate is not ELF; compared as raw bytes without relocations",
            ),
            description=f"raw bytes at absolute file offset 0x{offset:x}",
        )

    candidate_elf = elf.parse(path)  # a malformed ELF raises ParseError here
    section = candidate_elf.section(section_name)
    if section is None:
        raise ParseError(f"candidate {path} has no section {section_name!r}")
    if section.is_nobits or section.size == 0:
        raise ParseError(f"candidate section {section_name!r} has no file bytes")

    limitations: list[str] = []
    located, description = _locate_candidate_offset(
        candidate_elf,
        section,
        size=size,
        original_section_relative=original_section_relative,
        file_offset=file_offset,
        section_relative=section_relative,
        symbol=symbol,
        symbol_fallback=symbol_fallback,
        limitations=limitations,
    )
    return CandidateRegion(
        data=candidate_elf.reader.bytes_at(section.offset + located, size),
        section_offset=located,
        relocations=candidate_elf.relocations_for(section_name),
        limitations=tuple(limitations),
        description=description,
        symbol_addresses=imports.symbol_addresses(candidate_elf),
    )


def _call_resolver(
    original_elf: elf.ElfFile,
    candidate_symbols: dict[str, int],
) -> CallResolver | None:
    """A resolver for the module's call references, or ``None``.

    Returns ``None`` only when the module declares no imports at all - no
    ``.lib.stub`` section - in which case call relocations keep being compared
    literally, which is exactly what a module without trampolines needs.  When
    the section exists but its table could not be fully recovered, a resolver is
    still returned: it will fail to identify the calls it cannot prove, which
    makes the comparison inconclusive instead of silently different.
    """
    if original_elf.section(imports.LIB_STUB_SECTION) is None:
        return None
    table = imports.build_import_table(original_elf)
    return partial(
        imports.resolve_call_target,
        module_imports=table,
        candidate_symbols=candidate_symbols or None,
    )


def _read_magic(path: Path) -> bytes:
    with path.open("rb") as handle:
        return handle.read(4)


def _validate_file_range(offset: int, size: int, total: int, label: str) -> None:
    if offset < 0:
        raise ParseError(f"{label}: negative offset 0x{offset:x}")
    if offset % 4:
        raise ParseError(f"{label}: unaligned offset 0x{offset:x} (MIPS code is word-aligned)")
    if offset + size > total:
        raise ParseError(
            f"{label}: needs {size} bytes at 0x{offset:x} but the file is {total} bytes"
        )


def _validate_section_offset(offset: int, size: int, section_size: int, label: str) -> None:
    if offset < 0:
        raise ParseError(f"{label}: negative section offset 0x{offset:x}")
    if offset % 4:
        raise ParseError(f"{label}: unaligned section offset 0x{offset:x}")
    if offset + size > section_size:
        raise ParseError(
            f"{label}: needs {size} bytes at section offset 0x{offset:x} but the section "
            f"is {section_size} bytes"
        )


def _locate_candidate_offset(
    candidate_elf: elf.ElfFile,
    section: elf.Section,
    *,
    size: int,
    original_section_relative: int,
    file_offset: int | None,
    section_relative: int | None,
    symbol: str | None,
    symbol_fallback: bool = False,
    limitations: list[str],
) -> tuple[int, str]:
    label = f"candidate section {section.name!r}"

    if file_offset is not None:
        if file_offset < section.offset or file_offset + size > section.offset + section.size:
            raise ParseError(
                f"{label}: absolute file offset 0x{file_offset:x} does not contain {size} bytes"
            )
        return file_offset - section.offset, f"absolute file offset 0x{file_offset:x}"

    if section_relative is not None:
        _validate_section_offset(section_relative, size, section.size, label)
        return section_relative, f"section-relative offset 0x{section_relative:x}"

    if symbol:
        try:
            located = _resolve_symbol(candidate_elf, symbol, section)
        except SymbolNotFound as exc:
            # An explicit request that cannot be satisfied is never silently
            # replaced by a guess: falling back has to be asked for.
            if not symbol_fallback:
                raise Inconclusive(
                    f"{exc}; pass --candidate-symbol-fallback to allow automatic detection"
                ) from exc
            limitations.append(
                f"requested symbol {symbol!r} was not usable ({exc}); "
                "fell back to automatic detection"
            )
        else:
            _validate_section_offset(located.section_offset, size, section.size, label)
            return located.section_offset, located.description

    if candidate_elf.header.e_type == elf.ET_REL:
        data = candidate_elf.section_data(section)
        discovered = mips.find_functions(data, section.addr, f"{candidate_elf.reader.name}:{section.name}")
        if len(discovered) == 1:
            offset = discovered[0].start - section.addr
            _validate_section_offset(offset, size, section.size, label)
            return offset, f"the only function in {section.name!r} ({discovered[0].name()})"
        if not discovered:
            raise Inconclusive(
                f"{candidate_elf.reader.name}: no function was discovered in {section.name!r}; "
                "pass --candidate-section-offset or --candidate-symbol"
            )
        raise Inconclusive(
            f"{candidate_elf.reader.name}: {len(discovered)} functions were discovered in "
            f"{section.name!r}; pass --candidate-section-offset or --candidate-symbol to select one"
        )

    _validate_section_offset(original_section_relative, size, section.size, label)
    return (
        original_section_relative,
        f"assumed identical layout (section-relative 0x{original_section_relative:x})",
    )


def _resolve_symbol(candidate_elf: elf.ElfFile, name: str, section: elf.Section) -> SymbolLocation:
    """Locate ``name`` inside ``section`` from the ELF symbol table.

    Only a symbol whose ``shndx`` *is* the section index qualifies: a numeric
    value that merely fits inside the section proves nothing about its owner.
    ``ET_REL`` ``st_value`` is already section-relative; in a linked file the
    section's virtual address is subtracted instead.

    Raises :class:`SymbolNotFound` when the symbol is absent or belongs to
    another section, and :class:`Inconclusive` when it is ambiguous.
    """
    same_name = [symbol for symbol in candidate_elf.symbols if symbol.name == name]
    if not same_name:
        raise SymbolNotFound(f"symbol {name!r} is not present in the candidate")
    in_section = [
        symbol
        for symbol in same_name
        if symbol.is_defined and symbol.shndx == section.index
    ]
    if not in_section:
        where = ", ".join(sorted({str(symbol.shndx) for symbol in same_name}))
        raise SymbolNotFound(
            f"symbol {name!r} is not defined in section {section.name!r} (shndx {where})"
        )

    functions = [symbol for symbol in in_section if symbol.is_function] or in_section
    e_type = candidate_elf.header.e_type
    offsets = {
        symbol.value if e_type == elf.ET_REL else symbol.value - section.addr
        for symbol in functions
    }
    if len(offsets) > 1:
        listed = ", ".join(hex(offset) for offset in sorted(offsets))
        raise Inconclusive(f"symbol {name!r} is ambiguous in {section.name!r}: offsets {listed}")
    offset = offsets.pop()
    _validate_section_offset(offset, 0, section.size, f"symbol {name!r}")
    return SymbolLocation(
        section_offset=offset,
        description=f"symbol {name!r} at section offset 0x{offset:x}",
    )


def _print_match(result: MatchResult, region: CandidateRegion) -> None:
    print(f"function {result.name} @ 0x{result.address:x}")
    print(f"  status:  {result.status}")
    print(f"  match:   {result.percent:.2f}% ({result.matching_words}/{result.total_words} words)")
    print(f"  diffs:   {result.difference_count}")
    print(f"  evidence: {result.evidence}")
    print(f"  located: {region.description}")
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
        print(
            "  result: MATCHED (binary-range equivalence only; not a verified decompilation)"
        )
    elif result.status == INCONCLUSIVE:
        print("  result: INCONCLUSIVE (evidence is insufficient to prove equivalence)")
    else:
        print("  result: NONMATCHING (a divergence was proven)")


def _command_toolchain(arguments: argparse.Namespace, settings: Settings) -> int:
    """Report what is installed, and - with ``--smoke`` - what actually works."""
    if arguments.out is not None and not arguments.json:
        print("error: --out requires --json", file=sys.stderr)
        return EXIT_ERROR
    if (arguments.tool or arguments.smoke_workspace is not None) and not arguments.smoke:
        print("error: --tool and --smoke-workspace require --smoke", file=sys.stderr)
        return EXIT_ERROR
    if not arguments.smoke:
        statuses = detect_all(settings)
        if arguments.json:
            payload = {"tools": [status.summary() for status in statuses]}
            text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
            if arguments.out is not None:
                inventory.write_text(arguments.out, text)
            print(text, end="")
            return EXIT_OK
        print("external tools")
        for status in statuses:
            print(f"  {status.line()}")
        missing = [status.name for status in statuses if status.state == MISSING]
        print(f"missing: {', '.join(missing) if missing else 'none'}")
        print("run `seto toolchain --smoke` to prove what each tool can do")
        return EXIT_OK

    statuses = smoke_report(
        settings,
        tools=arguments.tool,
        workspace=arguments.smoke_workspace,
    )
    if arguments.json:
        payload = {"tools": [status.summary() for status in statuses]}
        text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        if arguments.out is not None:
            inventory.write_text(arguments.out, text)
        print(text, end="")
        return EXIT_OK

    print("external tools (smoke test)")
    for status in statuses:
        print(f"  {status.line()}")
        for capability in status.capabilities:
            print(capability.line())
    blocked = [
        status.name
        for status in statuses
        if status.state in (MISSING, INCOMPATIBLE, UNSUPPORTED, BLOCKED)
    ]
    failed_capabilities = [
        f"{status.name}/{capability.name}"
        for status in statuses
        for capability in status.capabilities
        if capability.state in (MISSING, INCOMPATIBLE, UNSUPPORTED)
    ]
    unproven = [
        f"{status.name}/{capability.name}"
        for status in statuses
        for capability in status.capabilities
        if capability.state == BLOCKED
    ]
    print("not usable for PSP analysis: " + (", ".join(blocked) if blocked else "none"))
    if failed_capabilities:
        print("failed capabilities: " + ", ".join(failed_capabilities))
    if unproven:
        print("not demonstrated here: " + ", ".join(unproven))
    return EXIT_OK


__all__ = [
    "EXIT_BLOCKED",
    "EXIT_ERROR",
    "EXIT_INCONCLUSIVE",
    "EXIT_MISMATCH",
    "EXIT_OK",
    "build_parser",
    "main",
]
