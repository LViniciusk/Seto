/*
 * Imported SCE library entry points reached through libhtml_view's
 * `.sceStub.text` trampolines.
 *
 * IDENTITY.  Each stub below is identified by the (library, NID) pair the module
 * itself declares: `.lib.stub` points at the library name in
 * `.rodata.sceResident` and at the NID array in `.rodata.sceNid`, and every
 * trampoline address is checked against the bytes at that address (a real
 * `jr $ra`).  The pair is the identity - two libraries may export the same NID,
 * and two identical NIDs in different libraries are NOT the same function.
 *
 * The full, reproducible report is decomp/imports/libhtml_view.json:
 *
 *   python -m seto imports --prx <libhtml_view.prx> --out decomp/imports/libhtml_view.json
 *
 * NAMES.  The module is stripped and its own import table stores no per-function
 * names, so the *names* of these entry points are not recoverable from this
 * binary alone: a name would have to come from the exporting library's table in
 * another module.  The identifiers below therefore stay provisional and are
 * keyed by the stub address the call site targets, which is an exact fact taken
 * from the relocation table.  The comments record the recovered identity.
 */
#ifndef SETO_DECOMP_SCE_STUBS_H
#define SETO_DECOMP_SCE_STUBS_H

/* libhtml_view.prx, .sceStub.text trampolines (each `jr $ra; nop`).
 * These four are the ones func_00000244 calls, in call order. */
extern void func_00002EDC(void); /* stub @ 0x2edc; sceHttp  NID 0x76D1363B */
extern void func_00002F0C(void); /* stub @ 0x2f0c; sceHttp  NID 0xF9D8EB63 */
extern void func_00002EF4(void); /* stub @ 0x2ef4; sceHttp  NID 0xD1C8945E */
extern void func_00002F54(void); /* stub @ 0x2f54; sceSsl   NID 0x191CDEFF */

/* Additional imports used by the SETO-DECOMP-008 candidates. Names remain
 * address-derived until the exporting library tables are recovered. */
extern void func_00000964(int value, unsigned int size); /* libehsys NID 0xEA748E31 */
extern void func_0000295C(int mode, int value);          /* libehsys NID 0x08813E19 */
extern void func_00002ADC(void);                         /* libehsys NID 0xF1BC43DB */
extern void func_00002F74(int option);                   /* sceUtility NID 0x64D50C56 */
extern void func_00002F14(void);                         /* sceNetApctl NID 0xB3EDD0EC */
extern void func_00002F34(void);                         /* sceNetResolver NID 0x6138194A */
extern void func_00002F2C(void);                         /* sceNetInet NID 0xA9ED66B9 */
extern void func_00002F44(void);                         /* sceNet NID 0x281928A9 */

#endif /* SETO_DECOMP_SCE_STUBS_H */
