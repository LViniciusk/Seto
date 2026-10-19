/*
 * libtutoriallist.prx, .text [0x1E94, 0x1F10), 31 instructions.
 *
 * Ghidra 12.1.3 found an exact one-range function body. The listing has no
 * relocation-backed calls or static data references. The loop is a binary
 * search over 16-bit values with a byte stride; the argument names and semantic
 * role remain provisional.
 *
 * The reconstruction reproduces the original instruction for instruction:
 *  - stride_halfwords = stride_bytes / 2 is a signed truncating division
 *    (bgez + sra / addiu+1 + sra), emitted first at 0x1E94.
 *  - The guard is a positive wrapper (if (high >= 0) { ... }) with one shared
 *    "return -1" after it, which lays the fall-through body out at 0x1EB4 and
 *    the shared return at 0x1F04; an early "if (high < 0) return -1" instead
 *    inverts the branch and inserts an extra jump.
 *  - The midpoint is the direct (low + high) / 2 of the original (addu at
 *    0x1EB4 followed by a signed truncating division); the overflow-safe
 *    low + (high - low) / 2 form does not appear in the binary.
 *  - low is declared and initialized before high, which is what maps high to
 *    the caller's a2 (the decremented count) and low to a3 in the body.
 *  - The loop is bottom-tested (do/while) with the comparison slt a2,a3
 *    (high < low) at 0x1EF8 and the likely backedge at 0x1EFC.
 *
 * Status: MATCHED 31/31, zero differences and zero relocation issues.
 * Source SHA-256 fc0e0b93f7ac4f2ef9cd7f8b72191093ed7c2f35336244ce172c98864365b155;
 * object SHA-256 24df0bdbcc2926ef4c5e8bf0c18231dcf9047068447ed978e68916f834c8fcc4.
 */

int func_00001E94(
    unsigned short key,
    const unsigned short *values,
    int count,
    int stride_bytes
)
{
    int stride_halfwords;
    int low;
    int high;
    int middle;
    unsigned short value;

    stride_halfwords = stride_bytes / 2;
    low = 0;
    high = count - 1;

    if (high >= 0) {
        do {
            /* high >= low on entry; the original uses the plain sum. */
            middle = (low + high) / 2;
            value = values[middle * stride_halfwords];
            if (key == value)
                return middle;
            if (value < key)
                low = middle + 1;
            else
                high = middle - 1;
        } while (high >= low);
    }

    return -1;
}
