/*
 * libtutoriallist.prx, .text [0x14E0, 0x1764), 161 instructions.
 *
 * Draws the tutorial progress indicator. Arguments are the renderer handle,
 * a screen position (x, y), a mode selector, the total/progress counters, a
 * boolean flag, the current counter and, as the ninth O32 argument at 48(sp),
 * the context handle forwarded to func_00003850. The eight import call sites
 * reach the trampolines 0x3850, 0x3BC0 (x2), 0x3B78 (x2), 0x3AF0 (x2) and
 * 0x3AE8 (x2); there are no static data references, so the only relocations
 * are those eight jal sites (R_MIPS_26), resolved through the canonical stub
 * identities. The 020 experiment missed every call and reported 11 relocation
 * issues precisely because its body layout diverged before those sites.
 *
 * The reconstruction reproduces the original instruction for instruction:
 *  - half = total / 2 is the unsigned shift srl s0,s3,1 at 0x152C. The mode
 *    test is (mode & 0xFF) == 1, selecting indent 8 or 0; both draw calls use
 *    it (t1 = indent + 48 at 0x156C, t1 = indent at 0x16F4).
 *  - `if (progress == 0) return renderer;` is the bnel s2,zero at 0x15A4:
 *    MWCC branches to the body when the counter is non-zero, leaves the
 *    beq zero,zero epilogue jump on the fall-through path and hoists the divu
 *    into the taken-only delay slot. A `if (progress != 0) { ... }` wrapper
 *    inverts the branch (beql s2,zero,epilogue) and shortens the body by one
 *    word; that difference alone made the 021 c1 candidate 160 words long.
 *  - rem = current % total is unsigned (divu/mfhi at 0x15A8/0x15B4). The
 *    fraction ping-pongs: rem/half when rem < half, (total-rem)/half
 *    otherwise. MWCC duplicates the unsigned conversion pair (bltzl + srl/or
 *    + cvt.s.w + add.s) into both arms before the div.s at 0x1618/0x166C;
 *    each conversion re-tests the sign bit, so the source values are
 *    unsigned int rather than int.
 *  - the clamp is c.lt.s/c.ngt.s against 0.0f and 1.0f (0x1670-0x16A4), the
 *    scale is 255.0f, and the back conversion uses the c.le.s 2^31 / sub.s /
 *    trunc.w.s / or path (0x16B0-0x16E0), i.e. an unsigned int result.
 *  - the alpha byte is built as (intensity << 24) | 0xFFFFFF and passed to
 *    func_00003B78, followed by the 8x8 marker draw and the progress-bar draw
 *    (0, 46, indent, 0, 0).
 *
 * Defined-behavior preconditions for this C reconstruction (the original
 * instruction sequence is preserved; no defensive branch is added here,
 * because the binary has none):
 *
 *  - progress == 0 returns before the modulo and before any floating-point
 *    division, independently of total.
 *  - When progress != 0, total >= 2 is required so that total and
 *    half = total / 2 are nonzero denominators:
 *      * total == 0 reaches `current % total`, integer division by zero,
 *        which is undefined behavior in C; the original executes divu with
 *        a zero divisor, a case the instruction set does not define either.
 *      * total == 1 leaves half == 0 and always takes the else arm, whose
 *        `(float)(total - rem) / (float)half` is a floating-point division
 *        by zero rather than a normal quotient.
 *      * total >= 2 makes half >= 1, so both arms divide by a nonzero
 *        denominator for every value of current.
 *  - half = total / 2 itself is safe for total == 0 (unsigned division is
 *    defined and yields 0); the hazard begins at the modulo below.
 *
 * The only known caller (0x1764, call sites 0x19C4 and 0x1A04) obtains total
 * from context[1] of the func_000037E0 result and derives progress from
 * height comparisons; it does not check total >= 2, so this file documents
 * the precondition instead of claiming a runtime guarantee the binary does
 * not have.
 *
 * Status: MATCHED 161/161, zero differences and zero relocation issues.
 * Final source/object hashes and fresh-attempt evidence are recorded outside
 * the source, in docs/decomp-progress.md and build/seto021/REPORT.md.
 */

#include "libtutoriallist_stubs.h"

void *func_000014E0(
    void *renderer,
    int x,
    int y,
    int mode,
    unsigned int total,
    unsigned int progress,
    int flag,
    unsigned int current,
    int context
)
{
    unsigned int half = total / 2;
    int indent = (mode & 0xFF) == 1 ? 8 : 0;
    unsigned int rem;
    float fraction;
    unsigned int intensity;

    renderer = func_00003850(renderer, context);
    renderer = func_00003BC0(renderer, 0, 0);

    if (flag != 0) {
        renderer = func_00003B78(renderer, 0xFFFFFFFFu);
        renderer = func_00003AF0(renderer, 8, 8, 8, 8);
        renderer = func_00003AE8(renderer, x, y, 0, 46, indent + 48, 0, 0);
    }

    if (progress == 0)
        return renderer;

    rem = current % total;
    if (rem < half)
        fraction = (float)rem / (float)half;
    else
        fraction = (float)(total - rem) / (float)half;

    if (fraction < 0.0f)
        fraction = 0.0f;
    if (fraction > 1.0f)
        fraction = 1.0f;

    intensity = (unsigned int)(fraction * 255.0f);

    renderer = func_00003B78(renderer, 0xFFFFFFu | (intensity << 24));
    renderer = func_00003AF0(renderer, 8, 8, 8, 8);
    renderer = func_00003AE8(renderer, x, y, 0, 46, indent, 0, 0);

    return renderer;
}
