"""Path validation helpers.

Every path that Seto derives from data (inventory walks, layout generation,
tool configuration) is validated so that it cannot escape the directory it is
supposed to live in.  Seto is read-only with respect to the original media, so
these checks guard the *derived* outputs.
"""

from __future__ import annotations

from pathlib import Path

from seto.binio import SetoError


def ensure_within_root(root: str | Path, path: str | Path) -> Path:
    """Resolve ``path`` (relative to ``root``) and require it stays inside ``root``."""
    root_resolved = Path(root).resolve()
    candidate = Path(path)
    resolved = (candidate if candidate.is_absolute() else root_resolved / candidate).resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise SetoError(f"path {path!r} escapes root {root_resolved}")
    return resolved


def relative_posix(root: str | Path, path: str | Path) -> str:
    """Return ``path`` relative to ``root`` as a forward-slash string.

    ``path`` is resolved against the current directory and must live inside
    ``root``; anything else raises :class:`~seto.binio.SetoError`.
    """
    root_resolved = Path(root).resolve()
    resolved = Path(path).resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise SetoError(f"path {path!r} is not inside {root_resolved}")
    return resolved.relative_to(root_resolved).as_posix()
