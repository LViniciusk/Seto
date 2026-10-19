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
 * Input-domain requirements for this C reconstruction (the binary-equivalent
 * instructions are preserved; the direct midpoint and the unguarded index
 * are kept because they are what the original executes):
 *
 *  - count must be nonnegative, and small enough that count - 1 and the
 *    midpoint sum low + high stay representable in int. Under the loop
 *    invariant 0 <= low <= high < count, low + high <= 2 * (count - 1);
 *    count <= 1073741824 (2^30) is therefore a sufficient bound for the sum.
 *  - The index product middle * stride_halfwords must fit in signed int for
 *    every accessed middle, which bounds |stride_bytes / 2| accordingly.
 *  - stride_halfwords = stride_bytes / 2 keeps the original signed
 *    truncating division: negative strides stay negative, and an odd stride
 *    drops its remainder.
 *  - values must point to valid, halfword-aligned storage that provides
 *    every accessed element, i.e. all indices middle * stride_halfwords for
 *    0 <= middle < count. The original loads with lhu (zero-extended 16-bit
 *    load) and every compared operand stays within [0, 0xFFFF], so the
 *    signed compare in the binary agrees with the unsigned 16-bit values.
 *  - count == 0 is safe: high == -1 fails the wrapper guard and the function
 *    returns -1 without touching values.
 *
 * The known local caller (func_00001D08) uses count = 4 and stride_bytes =
 * 0xC; that is usage evidence, not a universal contract for other callers.
 *
 * Status: MATCHED 31/31, zero differences and zero relocation issues.
 * Final source/object hashes and fresh-attempt evidence are recorded outside
 * the source, in docs/decomp-progress.md and build/seto021/REPORT.md.
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
