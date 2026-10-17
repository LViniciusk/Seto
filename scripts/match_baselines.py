"""Expected real compile-match results shared by tests and module auditing.

These values are assertions used to detect baseline changes. Audit output is
always derived from the current compiler/matcher reports, never populated from
this table.
"""

REAL_MATCH_CASES = (
    (0x244, "func_00000244.c", "MATCHED", 13, 13),
    (0x4B8, "func_000004B8.c", "INCONCLUSIVE", 18, 20),
    (0x6E4, "func_000006E4.c", "INCONCLUSIVE", 2, 8),
    (0x34, "func_00000034.c", "MATCHED", 20, 20),
    (0x134, "func_00000134.c", "MATCHED", 17, 17),
    (0x358, "func_00000358.c", "MATCHED", 17, 17),
    (0x8C, "func_0000008C.c", "MATCHED", 42, 42),
    (0x178, "func_00000178.c", "MATCHED", 51, 51),
    (0x278, "func_00000278.c", "MATCHED", 56, 56),
    (0x0, "func_00000000.c", "INCONCLUSIVE", 7, 13),
    (0x39C, "func_0000039C.c", "INCONCLUSIVE", 28, 30),
    (0x414, "func_00000414.c", "INCONCLUSIVE", 31, 41),
    (0x634, "func_00000634.c", "INCONCLUSIVE", 42, 44),
    (0x508, "func_00000508.c", "INCONCLUSIVE", 63, 75),
    (0x704, "func_00000704.c", "INCONCLUSIVE", 40, 60),
)


def match_tag(address: int) -> str:
    """Stable build-directory tag used by the existing SETO-DECOMP-012 reports."""
    return "f000" if address == 0 else f"f{address:x}"
