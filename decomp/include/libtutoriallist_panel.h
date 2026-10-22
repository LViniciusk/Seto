/* Provisional views of the zero-fill storage beginning at module offset 0x6190.
 * Offsets/widths follow observed loads, stores and the 0xB8-byte initialization.
 * No data definition, link placement or cross-artifact identity is asserted.
 */
#ifndef SETO_LIBTUTORIALLIST_PANEL_H
#define SETO_LIBTUTORIALLIST_PANEL_H

typedef struct LibtutoriallistPanelFlags {
    unsigned char group : 4;
    unsigned char closing : 1;
    unsigned char unknown : 3;
} LibtutoriallistPanelFlags;

typedef struct LibtutoriallistPanel {
    unsigned short phase;
    unsigned short unknown02;
    LibtutoriallistPanelFlags flags;
    unsigned char unknown05;
    unsigned short current;
    unsigned short leading[2];
    unsigned short trailing[2];
    unsigned short count[2];
    unsigned short entries[2][24];
    unsigned short extents[26];
    unsigned char unknownA8[16];
} LibtutoriallistPanel;

extern LibtutoriallistPanel func_00006190_panel;

/* The repeated original list lookup returns sentinel key 24 out of range.
 * The category argument is byte-sized; callers still owe group/entry bounds.
 */
static inline int libtutoriallist_panel_key(unsigned char group, int index)
{
    if (index >= func_00006190_panel.count[group])
        return 24;
    return func_00006190_panel.entries[group][index];
}
extern int func_00006238_context;
extern int func_0000623C_file;
extern int func_00006240_data;
extern void func_00001B0C(void);
extern void func_00001C18(void);
extern int func_00000280(void);
extern void func_00001F10(void);
extern void func_000021F8(void);
extern int func_00001B70(void);

/* Usage-derived imports; return values marked void are unused at these sites. */
extern int func_00002738(const void *, int, int, int, int, int);
extern void func_00002740(int, int *, int);
extern int func_000039F0(int, int);
extern void func_00002720(int, int);
extern void func_00002748(int, int);
extern void func_00002750(int);
extern void func_000049A0(void);
extern void func_00004990(int);
extern void func_00004300(int);
extern void func_000042F0(int);
extern void func_000042E0(int);
extern void func_00004310(int);
extern void func_000048E8(int, unsigned int, int);
extern void func_000048F0(int, unsigned int, int);
extern int func_000048F8(void);
extern void func_00003D90(int);
extern void func_000049B0(int);
extern void func_000049C0(int);
extern void func_00004A00(int);
extern int func_00004298(void);
extern unsigned char func_000040F8(int);
extern int func_000042C8(int, void *);
extern unsigned short func_00004118(int);
extern int *func_00003A38(void);
extern void *func_00003C38(void *, int, int, int, int);
extern void *func_00003AB0(void *, int);
extern void *func_00003A68(int, int);
extern void func_00003A70(void *);
extern void *func_00003C90(void *, unsigned int);
extern void *func_00003CA0(void *, int);
extern void *func_00003C98(void *, int);
extern void *func_00003CA8(void *, int);
extern void func_00004908(void **);
extern void *func_000006E8(void *);
extern void *func_000007A4(void *);
extern void *func_000008F0(void *, int, int, int, int);
extern void *func_00000E24(void *, int, int, int);
extern void *func_00001254(void *, int, int, int, int);
extern void *func_00001764(void *, int, int, int, int, int, int);

#endif
