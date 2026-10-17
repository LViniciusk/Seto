/*
 * libhtml_view.prx, .text 0x8C-0x134 (0xA8 bytes, 42 instructions).
 *
 * EVIDENCE: the verified listing is six calls to the same `.sceStub.text`
 * entry, `0x2f6c`, with constants 1, 3, 4, 5, 6 and 7 in `$a0` (2 is skipped).
 * The module's own import table identifies the entry as
 * `(sceUtility, NID 0x1579A159)`. After every call the result is copied to `$s0`
 * and tested with `bltz`: a negative status branches to one cleanup block at
 * 0x118, which calls the already-reconstructed local `func_00000134` and then
 * returns that status. When all six succeed the last result is returned. The
 * entry is a direct local `jal` target (from `func_00000278`) and the exclusive
 * end 0x134 is the next function's start, so the boundary is exact. There are no
 * data relocations; the only frame is a 0x10-byte save of `$ra`/`$s0`.
 *
 * REAL COMPILE + MATCH: Metrowerks 3.0.1 build 219 with `-O4,p -sdatathreshold 0`
 * reproduces 42/42 words, with zero differences, relocation issues or
 * limitations. The six calls resolve by `(sceUtility, NID 0x1579A159)` and the
 * cleanup call resolves to module address 0x134. This is a verified
 * decompilation for the observed compiler/flags; the stub name and the option
 * values remain provisional. Provenance hashes are in docs/decomp-progress.md.
 */

#include "sce_stubs.h"

extern void func_00000134(void);

int func_0000008C(void)
{
    int status;

    status = func_00002F6C(1);
    if (status < 0)
        goto cleanup;

    status = func_00002F6C(3);
    if (status < 0)
        goto cleanup;

    status = func_00002F6C(4);
    if (status < 0)
        goto cleanup;

    status = func_00002F6C(5);
    if (status < 0)
        goto cleanup;

    status = func_00002F6C(6);
    if (status < 0)
        goto cleanup;

    status = func_00002F6C(7);
    if (status < 0)
        goto cleanup;

    return status;

cleanup:
    func_00000134();
    return status;
}
