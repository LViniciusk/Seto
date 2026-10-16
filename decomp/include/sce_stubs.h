/*
 * Imported SCE library entry points reached through libhtml_view's
 * `.sceStub.text` trampolines.
 *
 * The reference module is stripped, so the real NIDs and names are not
 * recoverable from this binary alone.  Each declaration below is keyed by the
 * *stub address* the call site targets, which is an exact, verifiable fact taken
 * from the module's own relocation table (the `jal` targets).  The provisional
 * `func_<addr>` names deliberately encode that address so nothing is invented.
 *
 * When real names are recovered (from REA/Ghidra on a module that resolves its
 * imports, or from the SCE import tables of a non-stripped build) only these
 * identifiers need to change; the call sites are already correct.
 */
#ifndef SETO_DECOMP_SCE_STUBS_H
#define SETO_DECOMP_SCE_STUBS_H

/* libhtml_view.prx, .sceStub.text trampolines (each `jr $ra; nop`). */
extern void func_00002EDC(void); /* stub @ 0x2edc */
extern void func_00002F0C(void); /* stub @ 0x2f0c */
extern void func_00002EF4(void); /* stub @ 0x2ef4 */
extern void func_00002F54(void); /* stub @ 0x2f54 */

#endif /* SETO_DECOMP_SCE_STUBS_H */
