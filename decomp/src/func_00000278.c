/*
 * libhtml_view.prx, .text 0x278-0x358 (0xE0 bytes, 56 instructions).
 *
 * EVIDENCE: the verified listing begins with a call to the reconstructed local
 * `func_0000008C` and returns its status directly when negative. It then calls
 * sceNet NID 0x39AF39A6 with the constants (0x20000, 0x2a, 0, 0x2a, 0) - the
 * fifth argument is passed in `$t0` - and again returns directly on failure.
 * The remaining four steps (sceNetInet 0x17943399, sceNetResolver 0xF3370E61,
 * sceNetApctl 0xE2F91F9B with (0x1800, 0x30), and the reconstructed local
 * `func_00000178`) converge on a single cleanup at 0x2d0/0x33c that calls the
 * reconstructed local `func_00000358` before returning the failing status.
 * Boundaries: 0x278 is a direct local `jal` target (from `func_00000704`) and
 * the exclusive end 0x358 is the next function's start. There are no data
 * relocations; the only frame is the 0x10-byte `$ra`/`$s0` save. The constants
 * are observed register values; their semantic types remain provisional.
 *
 * REAL COMPILE + MATCH: Metrowerks 3.0.1 build 219 with `-O4,p -sdatathreshold 0`
 * reproduces 56/56 words, with zero differences, relocation issues or
 * limitations. Every import resolves by `(library, NID)` and the four local calls
 * resolve to module addresses 0x8c, 0x178 and 0x358 (`func_00000358` four
 * times). This is a verified decompilation for the observed compiler/flags.
 * Provenance hashes are in docs/decomp-progress.md.
 */

#include "sce_stubs.h"

extern int func_0000008C(void);
extern int func_00000178(void);
extern void func_00000358(void);

int func_00000278(void)
{
    int status;

    status = func_0000008C();
    if (status < 0)
        return status;

    status = func_00002F4C(0x20000, 0x2A, 0, 0x2A, 0);
    if (status < 0)
        return status;

    status = func_00002F24();
    if (status < 0) {
        func_00000358();
        return status;
    }

    status = func_00002F3C();
    if (status < 0) {
        func_00000358();
        return status;
    }

    status = func_00002F1C(0x1800, 0x30);
    if (status < 0) {
        func_00000358();
        return status;
    }

    status = func_00000178();
    if (status < 0) {
        func_00000358();
        return status;
    }

    return status;
}
