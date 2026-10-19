from __future__ import annotations

from pathlib import Path

from scripts.probe_common import ensure_build_dir, write_build_text


def test_write_build_text_preserves_canonical_lf_bytes(tmp_path: Path) -> None:
    build_root = tmp_path / "build"
    ensure_build_dir(build_root, build_root)
    report = build_root / "report.json"

    write_build_text(report, '{"first":1}\n{"second":2}\n', build_root)

    assert report.read_bytes() == b'{"first":1}\n{"second":2}\n'
