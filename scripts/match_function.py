#!/usr/bin/env python3
"""Compile one reconstructed function and compare it against the original.

This is the "automated compile + compare" step from the task, and it is also the
only place where a match may be called a *verified decompilation*: the plain
``seto match`` command only compares an arbitrary candidate and cannot know where
that candidate came from.

The script establishes the operational provenance itself:

1. it identifies the source, the compiler and the flags it will use;
2. it compiles, and requires a zero exit code;
3. it removes any previous object first, so the artefact it compares is the one
   this run just produced;
4. it hashes the source and the object (SHA-256);
5. it asks ``seto match`` to compare exactly that object;
6. it records the result, the compiler, the flags, the hashes and the function in
   a JSON record (``--report``, by default ``<out>/<source>.match.json``).

This is a verifiable record of a local execution, not an unforgeable attestation:
the record is only as trustworthy as the machine that produced it.

It never fakes a result.  It locates ``mwccpsp`` through ``config/seto.toml``, an
environment variable (``SETO_MWCCPSP``) or ``PATH``; when the compiler is missing
it prints a ``BLOCKED`` diagnosis and exits ``4``.  Otherwise it propagates the
exit code of ``seto match`` unchanged (``0`` matched, ``3`` nonmatching,
``5`` inconclusive).

The candidate function is located by its ``func_XXXXXXXX`` symbol inside the
object; when the compiler names it differently, pass ``--symbol`` (with the real
name) or ``--no-symbol`` to fall back to automatic detection.

Data references need more than the object: an ``ET_REL`` symbol names an original
object only once an independent artifact proves the link. ``--data-map`` may
record an advisory assertion, but a JSON evidence string is not validation and
cannot promote a data reference to ``MATCHED``. The object's own section/offset
and equal numeric addends prove nothing about the original module.

Example
-------
    python scripts/match_function.py \
        --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx \
        --function 0x244 \
        --source decomp/src/func_00000244.c

On Linux/WSL2, prepend the Win32 loader:

    python scripts/match_function.py ... --loader wibo
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from seto.cli import (  # noqa: E402
    EXIT_BLOCKED,
    EXIT_ERROR,
    EXIT_INCONCLUSIVE,
    EXIT_MISMATCH,
    EXIT_OK,
)
from seto.hashing import sha256_file  # noqa: E402
from seto.matching import (  # noqa: E402
    EQUIVALENCE_BINARY,
    EQUIVALENCE_RESOLVED_RELOCATIONS,
    EVIDENCE_COMPILED_OBJECT,
    INCONCLUSIVE,
    MATCHED,
    NONMATCHING,
)
from seto.mips import function_name  # noqa: E402
from seto.toolchain import (  # noqa: E402
    TOOL_SPECS,
    Settings,
    find_tool,
    load_settings,
    mwcc_argv,
    run,
    spec_for,
)

# The proprietary PSP compiler, as declared in seto.toolchain.TOOL_SPECS.
_MWCCPSP = next(spec for spec in TOOL_SPECS if spec.name == "mwccpsp")


@dataclass(frozen=True)
class MatchRecord:
    """What a compile+compare run did, so the result can be audited later."""

    function: str
    address: int
    section: str
    status: str
    evidence: str
    equivalence: str
    verified_decompilation: bool
    exit_code: int
    symbol: str | None
    source: str
    source_sha256: str
    object: str
    object_sha256: str
    compiler: str
    loader: tuple[str, ...]
    flags: tuple[str, ...]
    includes: tuple[str, ...]
    defines: tuple[str, ...]
    data_map: str | None = None
    candidate_section: str | None = None

    def summary(self) -> dict:
        return {
            "function": self.function,
            "address": f"0x{self.address:x}",
            "section": self.section,
            "symbol": self.symbol,
            "status": self.status,
            "evidence": self.evidence,
            "equivalence": self.equivalence,
            "verified_decompilation": self.verified_decompilation,
            "exit_code": self.exit_code,
            "provenance": {
                "source": self.source,
                "source_sha256": self.source_sha256,
                "object": self.object,
                "object_sha256": self.object_sha256,
                "compiler": self.compiler,
                "loader": list(self.loader),
                "flags": list(self.flags),
                "includes": list(self.includes),
                "defines": list(self.defines),
                "data_map": self.data_map,
                "candidate_section": self.candidate_section,
            },
        }


def equivalence_of(status: str, payload: Mapping) -> str:
    """Name what a ``MATCHED`` proves, from the comparator's own evidence.

    A compiled ``ET_REL`` object can never be byte-identical to a linked module:
    the field a call relocation covers holds a symbol reference instead of an
    address.  A ``MATCHED`` is therefore either plain binary equality of the
    compared range (nothing had to be resolved) or equivalence whose call
    references were canonically resolved.  *Full binary equality after linking* is
    never claimed by this script, because this script does not link.
    """
    if status != MATCHED:
        return ""
    if payload.get("resolved_calls") or payload.get("resolved_data"):
        return EQUIVALENCE_RESOLVED_RELOCATIONS
    return EQUIVALENCE_BINARY


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="match_function", description=__doc__.splitlines()[0])
    parser.add_argument("--prx", type=Path, required=True)
    parser.add_argument("--function", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--section", default=".text")
    parser.add_argument(
        "--candidate-section",
        default=None,
        help="candidate object section (defaults to the original section)",
    )
    parser.add_argument(
        "--size",
        type=lambda value: int(value, 0),
        default=None,
        help="explicit original interval size in bytes (for split/recovered ranges)",
    )
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--compiler", type=Path, default=None, help="override the compiler path")
    parser.add_argument("--loader", action="append", default=[], help="e.g. --loader wibo")
    parser.add_argument("--flag", action="append", default=[], help="compiler flag, repeatable")
    parser.add_argument("--include", action="append", default=[], help="include dir, repeatable")
    parser.add_argument("--define", action="append", default=[], help="macro definition, repeatable")
    parser.add_argument("--symbol", default=None, help="candidate symbol name (default: func_XXXXXXXX)")
    parser.add_argument("--no-symbol", action="store_true", help="let seto detect the candidate function")
    parser.add_argument(
        "--data-map",
        type=Path,
        default=None,
        help="JSON file linking candidate data symbols to original locations",
    )
    parser.add_argument("--out", type=Path, default=Path("build/match"))
    parser.add_argument(
        "--report", type=Path, default=None, help="where to write the JSON provenance record"
    )
    parser.add_argument("--json", action="store_true")
    return parser


def resolve_flags(flags: Sequence[str], settings: Settings) -> list[str]:
    """Return the compiler flags, falling back to ``[match] flags`` in the config."""
    if flags:
        return [str(flag) for flag in flags]
    configured = settings.get("match", "flags", default=None)
    if isinstance(configured, list):
        return [str(flag) for flag in configured]
    return []


def resolve_includes(includes: Sequence[str], settings: Settings) -> list[str]:
    if includes:
        return [str(item) for item in includes]
    configured = settings.get("match", "includes", default=None)
    if isinstance(configured, list):
        return [str(item) for item in configured]
    return ["decomp/include"]


def _resolve_loader_command(value: str) -> str | None:
    """Resolve an explicit loader path/name without invoking a shell."""
    candidate = Path(value)
    if candidate.is_file():
        return str(candidate)
    return shutil.which(value)


def _configured_loader(name: str, settings: Settings) -> str | None:
    """Resolve one known Win32 loader using config, env, then PATH."""
    spec = spec_for(name)
    if spec is None:
        return None
    candidates: list[str] = []
    configured = settings.tool_path(name)
    if configured:
        path = Path(configured)
        if path.is_dir():
            candidates.extend(str(path / candidate) for candidate in spec.names)
        else:
            candidates.append(configured)
    env_value = os.environ.get(spec.env_var)
    if env_value:
        candidates.append(env_value)
    candidates.extend(item for item in (shutil.which(candidate) for candidate in spec.names) if item)
    for candidate in candidates:
        resolved = _resolve_loader_command(candidate)
        if resolved is not None:
            return resolved
    return None


def resolve_loaders(
    requested: Sequence[str], settings: Settings, *, platform: str | None = None
) -> tuple[str, ...] | None:
    """Choose the configured/discovered Win32 loader on POSIX, or native Windows.

    An explicit ``--loader`` remains an override. ``None`` means a POSIX compiler
    was selected but no usable loader could be located.
    """
    if requested:
        resolved_items: list[str | None] = []
        for item in requested:
            spec = next(
                (
                    known
                    for known in (spec_for("wibo"), spec_for("wine"))
                    if known is not None and item in known.names
                ),
                None,
            )
            if spec is not None:
                # A named loader selects that tool and should honor its normal
                # config -> environment -> PATH resolution order. A caller-supplied
                # path remains an exact explicit override.
                resolved = _configured_loader(spec.name, settings)
                if resolved is None:
                    resolved = _resolve_loader_command(item)
            else:
                resolved = _resolve_loader_command(item)
            resolved_items.append(resolved)
        resolved = tuple(resolved_items)
        if any(item is None for item in resolved):
            return None
        return tuple(item for item in resolved if item is not None)
    current = platform or ("nt" if os.name == "nt" else "posix")
    if current == "nt":
        return ()
    for name in ("wibo", "wine"):
        resolved = _configured_loader(name, settings)
        if resolved is not None:
            return (resolved,)
    return None


def build_match_argv(
    *,
    python: str,
    prx: Path,
    section: str,
    function: int,
    candidate: Path,
    symbol: str | None,
    config: Path | None,
    data_map: Path | None = None,
    size: int | None = None,
    candidate_section: str | None = None,
) -> list[str]:
    """Build the ``python -m seto match ... --json`` command line.

    ``--config`` must precede the subcommand, so it is inserted immediately
    after ``seto`` rather than appended to the end.  ``--json`` is always
    requested: the script has to read the status to build its record.
    """
    argv = [python, "-m", "seto"]
    if config is not None:
        argv += ["--config", str(config)]
    argv += [
        "match",
        "--prx",
        str(prx),
        "--section",
        section,
        "--function",
        hex(function),
        "--candidate",
        str(candidate),
    ]
    if size is not None:
        argv += ["--size", str(size)]
    if candidate_section is not None:
        argv += ["--candidate-section", candidate_section]
    if symbol:
        argv += ["--candidate-symbol", symbol]
    if data_map is not None:
        argv += ["--data-map", str(data_map)]
    argv.append("--json")
    return argv


def _blocked(status) -> int:
    print("BLOCKED: mwccpsp is required to compile the candidate", file=sys.stderr)
    print(f"  reason: {status.reason}", file=sys.stderr)
    print(
        "  hint: set SETO_MWCCPSP, add [tools.mwccpsp] path=... to config/seto.toml, "
        "or put mwccpsp on PATH",
        file=sys.stderr,
    )
    return EXIT_BLOCKED


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)

    settings = load_settings(arguments.config)
    configured = str(arguments.compiler) if arguments.compiler else settings.tool_path("mwccpsp")
    status = find_tool(_MWCCPSP, configured)
    if not status.found:
        return _blocked(status)
    assert status.path is not None

    loaders = resolve_loaders(arguments.loader, settings)
    if loaders is None:
        print("BLOCKED: no usable Win32 loader (wibo or wine) is available", file=sys.stderr)
        print("  hint: configure [tools.wibo] or [tools.wine], or pass --loader", file=sys.stderr)
        return EXIT_BLOCKED

    if not arguments.source.is_file():
        print(f"error: source not found: {arguments.source}", file=sys.stderr)
        return EXIT_ERROR
    if not arguments.prx.is_file():
        print(f"error: module not found: {arguments.prx}", file=sys.stderr)
        return EXIT_ERROR
    if arguments.size is not None and (arguments.size <= 0 or arguments.size % 4):
        print("error: --size must be a positive multiple of 4 bytes", file=sys.stderr)
        return EXIT_ERROR

    symbol = None if arguments.no_symbol else (arguments.symbol or function_name(arguments.function))
    flags = resolve_flags(arguments.flag, settings)
    includes = resolve_includes(arguments.include, settings)

    out_dir = Path(arguments.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    object_path = out_dir / (arguments.source.stem + ".o")
    report_path = arguments.report or out_dir / (arguments.source.stem + ".match.json")

    # A stale object must never be mistaken for this run's output.
    object_path.unlink(missing_ok=True)

    argv_compile = mwcc_argv(
        status.path,
        arguments.source,
        object_path,
        flags=flags,
        includes=includes,
        defines=arguments.define,
        loader=loaders,
    )
    print("compiling:", file=sys.stderr)
    print("  " + " ".join(argv_compile), file=sys.stderr)
    compile_result = run(argv_compile, timeout=300)
    if compile_result.combined():
        print(compile_result.combined(), file=sys.stderr)
    if not compile_result.ok:
        print(f"error: compilation failed (exit {compile_result.returncode})", file=sys.stderr)
        return EXIT_ERROR
    if not object_path.is_file():
        print(f"error: compiler produced no object at {object_path}", file=sys.stderr)
        return EXIT_ERROR

    source_sha256 = sha256_file(arguments.source)
    object_sha256 = sha256_file(object_path)

    argv_match = build_match_argv(
        python=sys.executable,
        prx=arguments.prx,
        section=arguments.section,
        function=arguments.function,
        candidate=object_path,
        symbol=symbol,
        config=arguments.config,
        data_map=arguments.data_map,
        size=arguments.size,
        candidate_section=arguments.candidate_section,
    )

    print("comparing:", file=sys.stderr)
    print("  " + " ".join(argv_match), file=sys.stderr)
    match_result = run(argv_match, timeout=120)
    try:
        payload = json.loads(match_result.stdout)
        match_status = str(payload["status"])
    except (ValueError, KeyError, TypeError):
        # The comparator failed before producing a verdict: report it as-is.
        sys.stdout.write(match_result.stdout)
        sys.stderr.write(match_result.stderr)
        return match_result.returncode if match_result.returncode is not None else EXIT_ERROR

    exit_code = match_result.returncode if match_result.returncode is not None else EXIT_ERROR
    expected = {MATCHED: EXIT_OK, NONMATCHING: EXIT_MISMATCH, INCONCLUSIVE: EXIT_INCONCLUSIVE}
    if match_status not in expected:
        print(f"error: comparator reported an unknown status {match_status!r}", file=sys.stderr)
        return EXIT_ERROR
    if exit_code != expected[match_status]:
        print(
            f"error: comparator reported {match_status} with exit code {exit_code}",
            file=sys.stderr,
        )
        return EXIT_ERROR

    record = MatchRecord(
        function=function_name(arguments.function),
        address=arguments.function,
        section=arguments.section,
        status=match_status,
        evidence=EVIDENCE_COMPILED_OBJECT,
        equivalence=equivalence_of(match_status, payload),
        verified_decompilation=match_status == MATCHED,
        exit_code=exit_code,
        symbol=symbol,
        source=str(arguments.source),
        source_sha256=source_sha256,
        object=str(object_path),
        object_sha256=object_sha256,
        compiler=str(status.path),
        loader=loaders,
        flags=tuple(flags),
        includes=tuple(includes),
        defines=tuple(arguments.define),
        data_map=None if arguments.data_map is None else str(arguments.data_map),
        candidate_section=arguments.candidate_section,
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)

    # The object must not have changed while the comparator was reading it.
    if sha256_file(object_path) != object_sha256:
        print("error: the object changed during the comparison", file=sys.stderr)
        return EXIT_ERROR

    report_path.write_text(json.dumps(record.summary(), indent=2, sort_keys=True), encoding="utf-8")

    if arguments.json:
        summary = record.summary()
        summary["match"] = payload
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"function {record.function} @ 0x{record.address:x}")
        print(f"  status:   {record.status}")
        print(f"  evidence: {record.evidence}")
        print(f"  equivalence: {record.equivalence or '-'}")
        print(f"  verified decompilation: {'yes' if record.verified_decompilation else 'no'}")
        print(f"  source:   {record.source} ({record.source_sha256})")
        print(f"  object:   {record.object} ({record.object_sha256})")
        print(f"  compiler: {record.compiler}")
        print(f"  flags:    {' '.join(record.flags) or '-'}")
        print(f"  record:   {report_path}")

    return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
