"""Validate and safely extract release ZIPs used by the toolchain bootstrap.

This helper intentionally accepts ZIP archives only.  Before writing anything,
it checks the archive CRCs, rejects absolute/traversal paths, Windows drive or
backslash paths, symlinks and special files, and verifies every resolved target
stays beneath the destination.  Both bootstrap variants call this same code.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath


class UnsafeArchiveError(ValueError):
    """The archive contains an entry that must not be extracted."""


def verify_sha256(path: str | Path, expected: str) -> bool:
    """Return whether ``path`` has the expected lowercase/uppercase SHA-256."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().lower() == expected.strip().lower()


def safe_extract_zip(archive: str | Path, destination: str | Path) -> None:
    """Validate then extract a ZIP without allowing paths to escape destination."""
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(archive) as zipped:
        bad_member = zipped.testzip()
        if bad_member is not None:
            raise UnsafeArchiveError(f"CRC check failed for {bad_member!r}")

        validated: list[tuple[zipfile.ZipInfo, Path, bool]] = []
        for info in zipped.infolist():
            name = info.filename
            posix = PurePosixPath(name)
            windows = PureWindowsPath(name)
            if (
                not name
                or "\\" in name
                or posix.is_absolute()
                or windows.is_absolute()
                or windows.drive
                or any(part == ".." for part in posix.parts)
            ):
                raise UnsafeArchiveError(f"unsafe archive path: {name!r}")

            mode = info.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            is_dir = info.is_dir() or file_type == stat.S_IFDIR
            if file_type == stat.S_IFLNK or (file_type not in (0, stat.S_IFREG, stat.S_IFDIR)):
                raise UnsafeArchiveError(f"unsupported file type in archive: {name!r}")

            target = root.joinpath(*posix.parts)
            resolved = target.resolve()
            if resolved != root and root not in resolved.parents:
                raise UnsafeArchiveError(f"archive path escapes destination: {name!r}")
            validated.append((info, target, is_dir))

        # Validation happens for the whole archive before the first write.
        for info, target, is_dir in validated:
            if is_dir:
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            # Recheck after parent creation; an existing symlink must not redirect
            # a write outside the installation root.
            resolved = target.resolve()
            if resolved != root and root not in resolved.parents:
                raise UnsafeArchiveError(f"archive path escapes destination: {info.filename!r}")
            with zipped.open(info, "r") as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
            if os.name != "nt":
                # Preserve release launcher bits lost by Windows-created ZIPs,
                # while never restoring setuid/setgid or group/world write.
                permissions = stat.S_IMODE(info.external_attr >> 16) & 0o755
                if permissions:
                    target.chmod(permissions)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-sha256", nargs=2, metavar=("FILE", "EXPECTED"))
    parser.add_argument("archive", type=Path, nargs="?")
    parser.add_argument("destination", type=Path, nargs="?")
    args = parser.parse_args()
    if args.verify_sha256:
        return 0 if verify_sha256(*args.verify_sha256) else 1
    if args.archive is None or args.destination is None:
        parser.error("archive and destination are required unless --verify-sha256 is used")
    safe_extract_zip(args.archive, args.destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
