/*
 * libhtml_view.prx, .text 0x134-0x178 (0x44 bytes, 17 instructions).
 *
 * EVIDENCE: the verified listing is six ordered calls to the same `.sceStub.text`
 * entry, `0x2f74`, with constants 7, 6, 5, 4, 3 and 1 in `$a0`. The import table
 * identifies the entry as `(sceUtility, NID 0x64D50C56)`. There are no data
 * relocations or conditional branches. The entry boundary is a direct local
 * `jal` target and the Ghidra post-script reports an exact 17-instruction body.
 *
 * REAL COMPILE + MATCH: Metrowerks 3.0.1 build 219 with
 * `-O4,p -sdatathreshold 0` reproduces 17/17 words, with zero differences,
 * relocation issues or limitations. All six calls resolve as
 * sceUtility/NID 0x64D50C56. This is a verified decompilation for the observed
 * compiler/flags; the stub name and parameter's semantic type remain provisional.
 * Provenance hashes are recorded in docs/decomp-progress.md.
 */

#include "sce_stubs.h"

void func_00000134(void)
{
    func_00002F74(7);
    func_00002F74(6);
    func_00002F74(5);
    func_00002F74(4);
    func_00002F74(3);
    func_00002F74(1);
}
