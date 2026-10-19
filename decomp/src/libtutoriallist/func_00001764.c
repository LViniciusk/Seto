/*
 * libtutoriallist.prx, .text [0x1764, 0x1A3C), 182 instructions.
 *
 * Ghidra confirmed one exact body range. After the usual renderer setup this
 * function computes a clamped progress interval from its last three values,
 * draws a vertical gauge, and forwards that interval to func_000014E0 in two
 * modes. The nine-argument call uses the eight Allegrex integer argument
 * registers plus one stack argument. Signatures and names remain
 * usage-derived hypotheses.
 *
 * The three "max/min" clamp words at 0x17F4, 0x1818 and 0x181C are only ever
 * emitted by the compiler's Allegrex max/min intrinsics; equivalent C in the
 * form of if/branch or ternary never produced them at any tested
 * optimization level, so the two intrinsics below are the minimal faithful
 * construct for those instructions.
 *
 * Status: NONMATCHING 42/182 (remaining words diverge through a global
 * register permutation of the original: renderer s7 vs s6, width s3 vs s7,
 * ready s6 vs s0, filled s0 vs s7 and height spilled at 76(sp) vs s8, plus
 * the original's "full" computation in the func_00001D08 call delay slot).
 * Source forms that reproduce the call-delay-slot schedule (single-step
 * initializer) always select the alternate parameter rotation, and the
 * two-step forms that keep the parameters in the original registers always
 * sink the computation below the ready branch. Evidence: the v1-v31, perm-*
 * and q* variants plus the saved-register mapping tables under
 * build/seto021/experiments/1764 and the SETO-DECOMP-021 report.
 */

#include "libtutoriallist_stubs.h"

extern int func_00001D08(int arg0);
extern void *func_000014E0(
    void *renderer, int x, int y, int mode, unsigned int total,
    unsigned int progress, int flag, unsigned int current, int context
);

void *func_00001764(
    void *renderer,
    int x,
    int y,
    int width,
    int height,
    int start_value,
    int end_value
)
{
    int full;
    int ready;
    int filled;
    int start;
    int *context;
    int total;
    int *current_context;

    ready = func_00001D08(0x1003);
    full = width;
    full -= 2;

    if (ready == 0)
        return renderer;

    if (start_value < end_value) {
        filled = start_value * full / end_value;
        filled = __builtin_allegrex_max(filled, 10);
        start = height * (full - filled) / (end_value - start_value);
        start = __builtin_allegrex_max(start, 0);
        start = __builtin_allegrex_min(start, full - filled);
    } else {
        filled = full;
        start = 0;
    }

    renderer = func_00003BC0(renderer, 0, 0);
    renderer = func_00003B78(renderer, 0xFFFFFFFFu);
    renderer = func_00003850(renderer, ready);
    renderer = func_00003AF0(renderer, 8, 5, 8, 5);
    renderer = func_00003AE8(renderer, x, y, 0, 0x37, 0, 0, 0);
    renderer = func_00003AE8(renderer, x, y + width - 5, 0, 0x37, 0xF, 0, 0);
    renderer = func_00003AF0(renderer, 8, 5, 8, width - 10);
    renderer = func_00003AE8(renderer, x, y + 5, 0, 0x37, 5, 0, 0);
    renderer = func_00003AF0(renderer, 4, 5, 4, 5);
    renderer = func_00003AE8(renderer, x + 2, y + start + 2, 0, 0x37, 0x28, 0, 0);
    renderer = func_00003AE8(
        renderer, x + 2, y + start + filled - 3, 0, 0x37, 0x37, 0, 0
    );
    renderer = func_00003AF0(renderer, 4, 5, 4, filled - 10);
    renderer = func_00003AE8(renderer, x + 2, y + start + 7, 0, 0x37, 0x2D, 0, 0);

    context = func_000037E0();
    total = context[1];
    current_context = func_000037E0();
    renderer = func_000014E0(
        renderer, x, y - 7, 0, total, height > 0, 1, *current_context, ready
    );

    context = func_000037E0();
    total = context[1];
    current_context = func_000037E0();
    renderer = func_000014E0(
        renderer, x, y + width + 2, 1, total,
        height < end_value - start_value, 1, *current_context, ready
    );

    return renderer;
}
