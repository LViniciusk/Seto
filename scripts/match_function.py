#!/usr/bin/env python3
"""Compile one reconstructed function and compare it against the original.

This is the "automated compile + compare" step from the task.  It never fakes a
result:

* it locates ``mwccpsp`` through ``config/seto.toml``, an environment variable
  (``SETO_MWCCPSP``) or ``PATH``;
* when the compiler is missing it prints a ``BLOCKED`` diagnosis and exits ``4``;
* otherwise it compiles the source to an object file and hands that ``.o`` to
  ``seto match``, whose relocation-aware comparator decides ``MATCHED`` /
  ``NONMATCHING`` / ``INCONCLUSIVE`` and whose exit code is propagated unchanged.

The candidate function is located by its ``func_XXXXXXXX`` symbol inside the
object (``--candidate-symbol``); when the compiler names it differently, pass
``--symbol`` or an explicit ``--no-symbol`` to fall back to automatic detection.

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
import sys
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from seto.cli import EXIT_BLOCKED, EXIT_ERROR  # noqa: E402
from seto.mips import function_name  # noqa: E402
from seto.toolchain import (  # noqa: E402
    TOOL_SPECS,
    Settings,
    find_tool,
    load_settings,
    mwcc_argv,
    run,
)

# The proprietary PSP compiler, as declared in seto.toolchain.TOOL_SPECS.
_MWCCPSP = next(spec for spec in TOOL_SPECS if spec.name == "mwccpsp")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="match_function", description=__doc__.splitlines()[0])
    parser.add_argument("--prx", type=Path, required=True)
    parser.add_argument("--function", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--section", default=".text")
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--compiler", type=Path, default=None, help="override the compiler path")
    parser.add_argument("--loader", action="append", default=[], help="e.g. --loader wibo")
    parser.add_argument("--flag", action="append", default=[], help="compiler flag, repeatable")
    parser.add_argument("--include", action="append", default=[], help="include dir, repeatable")
    parser.add_argument("--define", action="append", default=[], help="macro definition, repeatable")
    parser.add_argument("--symbol", default=None, help="candidate symbol name (default: func_XXXXXXXX)")
    parser.add_argument("--no-symbol", action="store_true", help="let seto detect the candidate function")
    parser.add_argument("--out", type=Path, default=Path("build/match"))
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


def build_match_argv(
    *,
    python: str,
    prx: Path,
    section: str,
    function: int,
    candidate: Path,
    symbol: str | None,
    config: Path | None,
    json_output: bool = False,
) -> list[str]:
    """Build the ``python -m seto match ...`` command line.

    ``--config`` must precede the subcommand, so it is inserted immediately
    after ``seto`` rather than appended to the end.
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
    if symbol:
        argv += ["--candidate-symbol", symbol]
    if json_output:
        argv.append("--json")
    return argv


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)

    settings = load_settings(arguments.config)
    configured = str(arguments.compiler) if arguments.compiler else settings.tool_path("mwccpsp")
    status = find_tool(_MWCCPSP, configured)
    if not status.found:
        print("BLOCKED: mwccpsp is required to compile the candidate", file=sys.stderr)
        print(f"  reason: {status.reason}", file=sys.stderr)
        print(
            "  hint: set SETO_MWCCPSP, add [tools.mwccpsp] path=... to config/seto.toml, "
            "or put mwccpsp on PATH",
            file=sys.stderr,
        )
        return EXIT_BLOCKED
    assert status.path is not None

    if not arguments.source.is_file():
        print(f"error: source not found: {arguments.source}", file=sys.stderr)
        return EXIT_ERROR
    if not arguments.prx.is_file():
        print(f"error: module not found: {arguments.prx}", file=sys.stderr)
        return EXIT_ERROR

    symbol = None if arguments.no_symbol else (arguments.symbol or function_name(arguments.function))

    out_dir = Path(arguments.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    object_path = out_dir / (arguments.source.stem + ".o")

    argv_compile = mwcc_argv(
        status.path,
        arguments.source,
        object_path,
        flags=resolve_flags(arguments.flag, settings),
        includes=resolve_includes(arguments.include, settings),
        defines=arguments.define,
        loader=arguments.loader,
    )
    print("compiling:")
    print("  " + " ".join(argv_compile))
    compile_result = run(argv_compile, timeout=300)
    if compile_result.combined():
        print(compile_result.combined())
    if not compile_result.ok:
        print(f"error: compilation failed (exit {compile_result.returncode})", file=sys.stderr)
        return EXIT_ERROR
    if not object_path.is_file():
        print(f"error: compiler produced no object at {object_path}", file=sys.stderr)
        return EXIT_ERROR

    argv_match = build_match_argv(
        python=sys.executable,
        prx=arguments.prx,
        section=arguments.section,
        function=arguments.function,
        candidate=object_path,
        symbol=symbol,
        config=arguments.config,
        json_output=arguments.json,
    )

    print("comparing:")
    print("  " + " ".join(argv_match))
    match_result = run(argv_match, timeout=120)
    sys.stdout.write(match_result.stdout)
    sys.stderr.write(match_result.stderr)
    return match_result.returncode if match_result.returncode is not None else EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
