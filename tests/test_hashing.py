"""Tests for streaming hashing and baseline verification."""

from __future__ import annotations

from hashlib import sha256

import pytest

from seto.hashing import (
    FileFingerprint,
    fingerprint_file,
    sha256_file,
    verify_file,
    verify_fingerprint,
)


def test_sha256_matches_reference_implementation(tmp_path) -> None:
    path = tmp_path / "payload.bin"
    payload = bytes(range(256)) * 40
    path.write_bytes(payload)
    assert sha256_file(path) == sha256(payload).hexdigest()


def test_sha256_chunking_is_irrelevant(tmp_path) -> None:
    path = tmp_path / "payload.bin"
    payload = bytes(range(256)) * 10
    path.write_bytes(payload)
    assert sha256_file(path, chunk_size=1) == sha256_file(path, chunk_size=4096)


def test_fingerprint_reports_size_and_digest(tmp_path) -> None:
    path = tmp_path / "payload.bin"
    path.write_bytes(b"seto")
    fingerprint = fingerprint_file(path)
    assert fingerprint == FileFingerprint(size=4, sha256=sha256(b"seto").hexdigest())


def test_fingerprint_rejects_bad_chunk_size(tmp_path) -> None:
    path = tmp_path / "payload.bin"
    path.write_bytes(b"seto")
    with pytest.raises(ValueError):
        fingerprint_file(path, chunk_size=0)


def test_verify_fingerprint_accepts_matching_baseline() -> None:
    fingerprint = FileFingerprint(size=4, sha256=sha256(b"seto").hexdigest())
    result = verify_fingerprint(fingerprint, 4, sha256(b"seto").hexdigest().upper())
    assert result.ok
    assert result.issues == ()


def test_verify_fingerprint_reports_every_mismatch() -> None:
    fingerprint = FileFingerprint(size=5, sha256="00" * 32)
    result = verify_fingerprint(fingerprint, 4, "11" * 32)
    assert not result.ok
    assert len(result.issues) == 2
    assert "size mismatch" in result.issues[0]


def test_verify_file_detects_modified_content(tmp_path) -> None:
    path = tmp_path / "iso-ish.bin"
    path.write_bytes(b"original")
    good = verify_file(path, 8, sha256(b"original").hexdigest())
    assert good.ok
    path.write_bytes(b"modified")
    bad = verify_file(path, 8, sha256(b"original").hexdigest())
    assert not bad.ok
