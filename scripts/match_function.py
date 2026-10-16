#!/usr/bin/env python3
"""Compile one reconstructed function and compare it against the original.

This is the "automated compile + compare" step from the task.  It never fakes a
result:

* it locates ``mwccpsp`` through ``config/seto.toml``, an environment variable
  (``SETO_MWCCPSP``) or ``PATH``;
* when the compiler is missing it prints a ``BLOCKED`` diagnosis and exits ``4``;
* otherwise it compiles the source to an object file and hands that ``.o`` to
  ``seto match``, whose relocation-aware comparator decides ``MATCHED`` /
  ``NONMATCHING`` and whose exit code is propagated unchanged.

Example
-------
    python scripts/match_function.py \
        --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx \
        --function 0x244 \
        --source decomp/src/func_00000244.c \
        --flag=-O4,p --flag=-sdatathreshold --flag=0

On Linux/WSL2, prepend the Win32 loader:

    python scripts/match_function.py ... --loader wibo
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from seto.cli import EXIT_BLOCKED, EXIT_ERROR  # noqa: E402
from seto.toolchain import (  # noqa: E402
    TOOL_SPECS,
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
    parser.add_argument("--out", type=Path, default=Path("build/match"))
    parser.add_argument("--json", action="store_true")
    return parser


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

    out_dir = Path(arguments.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    object_path = out_dir / (arguments.source.stem + ".o")

    argv_compile = mwcc_argv(
        status.path,
        arguments.source,
        object_path,
        flags=arguments.flag,
        includes=arguments.include or ["decomp/include"],
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

    argv_match = [
        sys.executable,
        "-m",
        "seto",
        "match",
        "--prx",
        str(arguments.prx),
        "--section",
        arguments.section,
        "--function",
        hex(arguments.function),
        "--candidate",
        str(object_path),
    ]
    if arguments.json:
        argv_match.append("--json")
    if arguments.config is not None:
        argv_match[2:2] = ["--config", str(arguments.config)]

    print("comparing:")
    print("  " + " ".join(argv_match))
    match_result = run(argv_match, timeout=120)
    sys.stdout.write(match_result.stdout)
    sys.stderr.write(match_result.stderr)
    return match_result.returncode if match_result.returncode is not None else EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
