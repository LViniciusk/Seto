from __future__ import annotations

from pathlib import Path

import pytest

from scripts.probe_common import ProbeError, ensure_build_dir, validated_build_root


def test_036_build_root_rejects_redirected_symlink_before_matcher(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    (repo / "build").mkdir()
    try:
        (repo / "build" / "seto036").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"platform does not permit local symlink creation: {exc}")

    with pytest.raises(ProbeError, match="build directory must not be a symlink"):
        validated_build_root(repo, subdir="seto036")
    assert list(outside.iterdir()) == []


def test_036_attempt_directory_rejects_symlink_before_matcher(tmp_path: Path) -> None:
    root = tmp_path / "build" / "seto036"
    root.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "integration" / "attempt-1"
    link.parent.mkdir()
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"platform does not permit local symlink creation: {exc}")

    with pytest.raises(ProbeError, match="build directory may not be a symlink"):
        ensure_build_dir(link, root)
    assert list(outside.iterdir()) == []
