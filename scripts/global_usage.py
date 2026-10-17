#!/usr/bin/env python3
"""Group a ``seto datarefs`` report by demonstrated module location.

This is the SETO-DECOMP-010 cross-function view: it reads the per-function
reference report the CLI already produced and applies the pure
:func:`seto.datarefs.build_global_usage` grouping. It parses no ELF bytes and
adds no CLI surface, so the same grouping is unit-tested without a PRX.

    PYTHONPATH=src python3 -m seto datarefs --prx <prx> --out build/datarefs.json
    python3 scripts/global_usage.py --report build/datarefs.json --out build/global-usage.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from seto import datarefs  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="global_usage", description=__doc__.splitlines()[0])
    parser.add_argument("--report", type=Path, required=True, help="a `seto datarefs` JSON report")
    parser.add_argument("--out", type=Path, required=True)
    return parser


def build_usage(report: dict[str, object]) -> dict[str, object]:
    """Carry the report's provenance next to the grouped locations."""
    usage = datarefs.build_global_usage(report)
    for key in ("prx", "sha256"):
        if key in report:
            usage[key] = report[key]
    return usage


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    report = json.loads(arguments.report.read_text(encoding="utf-8"))
    usage = build_usage(report)

    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    arguments.out.write_text(
        json.dumps(usage, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"{arguments.out}: {len(usage['locations'])} locations, "
        f"{len(usage['unresolved'])} unresolved references"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
