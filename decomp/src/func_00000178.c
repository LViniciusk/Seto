/*
 * libhtml_view.prx, .text 0x178-0x244 (0xCC bytes, 51 instructions).
 *
 * EVIDENCE: the verified listing is an ordered chain of five calls. The first
 * two take the constant 0x28000 (`lui 2; ori ...,0x8000`): sceSsl NID
 * 0x957ECBE2, then sceHttp NID 0xAB1ABE07. The first status is returned directly
 * when negative; the remaining failures converge on one cleanup at 0x1b4 that
 * calls the already-reconstructed local `func_00000244`. The next calls are
 * sceHttp 0xE4D21302 with four zero arguments, sceHttp 0x87797BDD with two zero
 * arguments, and sceHttp 0xF1657B22 with none; the last result is returned when
 * non-negative. Boundaries: 0x178 is a direct local `jal` target (from
 * `func_00000278`) and the exclusive end 0x244 is the next function's start.
 * There are no data relocations; the only frame is the 0x10-byte
 * `$ra`/`$s0` save. The constant 0x28000 and the zero arguments are the observed
 * register values; their semantic types remain provisional.
 *
 * REAL COMPILE + MATCH: Metrowerks 3.0.1 build 219 with `-O4,p -sdatathreshold 0`
 * reproduces 51/51 words, with zero differences, relocation issues or
 * limitations. The five imports resolve by `(library, NID)` and the cleanup call
 * resolves to module address 0x244. This is a verified decompilation for the
 * observed compiler/flags. Provenance hashes are in docs/decomp-progress.md.
 */

#include "sce_stubs.h"

extern void func_00000244(void);

int func_00000178(void)
{
    int status;

    status = func_00002F5C(0x28000);
    if (status < 0)
        return status;

    status = func_00002EEC(0x28000);
    if (status < 0) {
        func_00000244();
        return status;
    }

    status = func_00002EFC(0, 0, 0, 0);
    if (status < 0) {
        func_00000244();
        return status;
    }

    status = func_00002EE4(0, 0);
    if (status < 0) {
        func_00000244();
        return status;
    }

    status = func_00002F04();
    if (status < 0) {
        func_00000244();
        return status;
    }

    return status;
}
