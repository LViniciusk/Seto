"""Container identification by real magic signatures.

Detection is signature-driven and never guesses: a file that does not match a
known signature is reported as ``unknown``. Encrypted containers (``~PSP``,
``~SCE``) are *identified* but deliberately not parsed further: their payloads
are encrypted and out of scope for static parsing.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ELF_MAGIC = b"\x7fELF"
PSP_MAGIC = b"~PSP"
SCE_MAGIC = b"~SCE"
PBP_MAGIC = b"\x00PBP"
PSF_MAGIC = b"\x00PSF"
ISO9660_MAGIC = b"CD001"


@dataclass(frozen=True)
class Signature:
    """A recognised container signature at a fixed offset."""

    fmt: str
    magic: bytes
    offset: int
    description: str


SIGNATURES: tuple[Signature, ...] = (
    Signature("ELF", ELF_MAGIC, 0, "ELF object or module"),
    Signature("PSP", PSP_MAGIC, 0, "~PSP encrypted/compressed PSP executable"),
    Signature("SCE", SCE_MAGIC, 0, "~SCE signed SCE module container"),
    Signature("PBP", PBP_MAGIC, 0, "PSP PBP package"),
    Signature("PSF", PSF_MAGIC, 0, "PSP system metadata (PARAM.SFO)"),
    Signature(
        "ISO9660",
        ISO9660_MAGIC,
        0x8001,
        "ISO 9660 volume descriptor",
    ),
)

UNKNOWN = Signature("unknown", b"", 0, "no known signature")

PROBE_SIZE = max(sig.offset + len(sig.magic) for sig in SIGNATURES)


def identify(data: bytes) -> Signature:
    """Return the first :data:`SIGNATURES` entry matching ``data``."""
    for signature in SIGNATURES:
        end = signature.offset + len(signature.magic)
        if data[signature.offset : end] == signature.magic:
            return signature
    return UNKNOWN


def identify_file(path: str | Path) -> Signature:
    """Read only the prefix needed for detection and identify the container."""
    with open(path, "rb") as handle:
        head = handle.read(PROBE_SIZE)
    return identify(head)
