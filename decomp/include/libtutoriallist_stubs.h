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

/* func_000007A4 / func_00000FF0 / func_000014E0: usage-derived renderer calls. */
extern void *func_00003850(void *arg0, int arg1);
/* libehsys, NID 0x9EA6989A, stub 0x3850 */
extern void *func_00003AE8(
    void *arg0, unsigned int arg1, unsigned int arg2, unsigned int arg3,
    unsigned int arg4, unsigned int arg5, unsigned int arg6, unsigned int arg7
);
/* libehsys, NID 0xFDD168CA, stub 0x3AE8 */
extern void *func_00003AF0(
    void *arg0, unsigned int arg1, unsigned int arg2, unsigned int arg3,
    unsigned int arg4
);
/* libehsys, NID 0x8EA6B1E7, stub 0x3AF0 */
extern void *func_00003B78(void *arg0, unsigned int arg1);
/* libehsys, NID 0xCABEA834, stub 0x3B78 */
extern void *func_00003BC0(void *arg0, unsigned int arg1, unsigned int arg2);
/* libehsys, NID 0xE6E4401F, stub 0x3BC0 */
extern void *func_000041D8(int arg0, int arg1);
/* libehsys, NID 0xE58C0FDC, stub 0x41D8 */
extern void func_00004270(unsigned int arg0, unsigned int arg1);
/* libehsys, NID 0x942B03D0, stub 0x4270 */
extern void func_00004280(unsigned int arg0);
/* libehsys, NID 0x60B55A50, stub 0x4280 */
extern void func_00004350(void *arg0);
/* libehsys, NID 0xB8AD96EA, stub 0x4350 */
extern void *func_00004358(void);
/* libehsys, NID 0xA4AFF8E6, stub 0x4358 */

/* func_00000E24 / func_00001D08: usage-derived state and buffer calls. */
extern int func_00004120(void);
/* libehsys, NID 0x31454993, stub 0x4120 */
extern void func_00004340(unsigned int arg0);
/* libehsys, NID 0xAB962AE7, stub 0x4340 */
extern void func_000042A8(
    int arg0, int arg1, int arg2, int arg3, void *arg4, int arg5
);
/* libehsys, NID 0x3BB2BAC6, stub 0x42A8 */
extern void func_000025D0(void *arg0, int arg1, int arg2);
/* libehsys, NID 0x7661E728, stub 0x25D0 */
extern int func_00003790(int arg0, void *arg1, int arg2);
/* libehsys, NID 0xC6C15111, stub 0x3790 */

#endif /* SETO_DECOMP_LIBTUTORIALLIST_STUBS_H */
