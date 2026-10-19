/*
 * Address-derived imported entry points reached by libtutoriallist.prx.
 *
 * Each `(library, NID, stub)` identity comes from this PRX's validated
 * `.lib.stub` / `.sceStub.text` tables. Names and signatures remain provisional:
 * the parameter lists record the observed call-site usage, not SDK prototypes.
 */
#ifndef SETO_DECOMP_LIBTUTORIALLIST_STUBS_H
#define SETO_DECOMP_LIBTUTORIALLIST_STUBS_H

/* func_00001A3C: usage-derived display call; signature is provisional. */
extern void func_000042A0(int arg0, int arg1, int arg2, const short *arg3);
/* libehsys, NID 0xB89D38DC, stub 0x42A0 */

/* func_000006E8: usage-derived setup/render calls; signatures are provisional. */
extern void func_00002610(int *arg0, int arg1, int arg2);
/* libehsys, NID 0x10F3BB61, stub 0x2610 */
extern int *func_000037E0(void);
/* libehsys, NID 0xB2B9FEFA, stub 0x37E0 */
extern void *func_00003768(void *arg0);
/* libehsys, NID 0x85F89FE8, stub 0x3768 */
extern void *func_00003758(void *arg0, int arg1, int *arg2);
/* libehsys, NID 0x7187E0F0, stub 0x3758 */
extern void *func_00003770(void *arg0);
/* libehsys, NID 0x89812D8A, stub 0x3770 */
extern void *func_00003AA8(void *arg0, int arg1);
/* libehsys, NID 0xF462EE6E, stub 0x3AA8 */
extern void *func_00003BC8(void *arg0, int arg1, int arg2);
/* libehsys, NID 0x09794DF0, stub 0x3BC8 */
extern void *func_00003C70(
    void *arg0, int arg1, int arg2, int arg3, int arg4, int arg5
);
/* libehsys, NID 0x5CBB9E43, stub 0x3C70 */

#endif /* SETO_DECOMP_LIBTUTORIALLIST_STUBS_H */
