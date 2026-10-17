/*
 * libhtml_view.prx, .text 0x34-0x84 (0x50 bytes, 20 instructions).
 *
 * EVIDENCE: this entry follows the previous `jr $ra` delay slot and Ghidra's
 * `SetoAnalyzeFunction` check confirms the exact 20-instruction body. The
 * verified listing and m2c agree: initialize through `func_00000964(0,
 * 0x4000)`, call local setup functions `func_000006E4` and `func_00000704`, then
 * repeat `func_00002ADC` while `func_00000704` returns zero. On nonzero status it
 * calls `func_0000295C(0xE, 0)`. All five calls are resolved (three imports,
 * two local functions); this function has no data relocations.
 *
 * The imported names remain address-derived. `func_00000704` is declared with
 * an integer result because the original reads `$v0`; its semantic type and the
 * helper prototypes remain provisional until supported by an independent
 * source-level artifact.
 *
 * REAL COMPILE + MATCH: Metrowerks 3.0.1 build 219 with
 * `-O4,p -sdatathreshold 0` reproduces 20/20 words, with zero differences,
 * relocation issues or limitations. The three imported calls resolve by
 * (library, NID), and both local calls resolve to module functions. This is a
 * verified decompilation for the observed compiler/flags; helper names and the
 * integer interpretation of `func_00000704` remain provisional. Provenance
 * hashes are recorded in docs/decomp-progress.md.
 */

#include "sce_stubs.h"

extern void func_000006E4(void);
extern int func_00000704(void);

void func_00000034(void)
{
    func_00000964(0, 0x4000);
    func_000006E4();

    for (;;) {
        if (func_00000704() != 0) {
            break;
        }
        func_00002ADC();
    }

    func_0000295C(0xE, 0);
}
