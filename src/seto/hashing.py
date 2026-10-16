"""Streaming hashing and baseline verification of the original media."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

DEFAULT_CHUNK_SIZE = 1 << 20


@dataclass(frozen=True)
class FileFingerprint:
    """Size and SHA-256 of a file, computed without loading it into memory."""

    size: int
    sha256: str


def sha256_file(path: str | Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Return the lowercase hex SHA-256 of ``path``, streamed in chunks."""
    digest = sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def fingerprint_file(path: str | Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> FileFingerprint:
    """Return size and SHA-256 of ``path`` in a single streaming pass."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    digest = sha256()
    size = 0
    with open(path, "rb") as handle:
        while chunk := handle.read(chunk_size):
            size += len(chunk)
            digest.update(chunk)
    return FileFingerprint(size=size, sha256=digest.hexdigest())


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of comparing a file fingerprint against an expected baseline."""

    ok: bool
    size: int
    sha256: str
    issues: tuple[str, ...] = ()


def verify_fingerprint(
    actual: FileFingerprint,
    expected_size: int,
    expected_sha256: str,
) -> VerificationResult:
    """Compare ``actual`` against the expected baseline, collecting every issue."""
    expected_digest = expected_sha256.strip().lower()
    issues: list[str] = []
    if actual.size != expected_size:
        issues.append(f"size mismatch: expected {expected_size}, got {actual.size}")
    if actual.sha256 != expected_digest:
        issues.append(f"sha256 mismatch: expected {expected_digest}, got {actual.sha256}")
    return VerificationResult(
        ok=not issues,
        size=actual.size,
        sha256=actual.sha256,
        issues=tuple(issues),
    )


def verify_file(
    path: str | Path,
    expected_size: int,
    expected_sha256: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> VerificationResult:
    """Fingerprint ``path`` and compare it against the expected baseline."""
    return verify_fingerprint(
        fingerprint_file(path, chunk_size), expected_size, expected_sha256
    )
