/*
 * SETO-DECOMP-011 (final audit hardening): provisional description of the
 * shared state block at 0x604864.
 *
 * SCOPE.  This is NOT the recovered original type.  No symbol table, debug
 * information or section header in the stripped module names the object; the
 * block lies past `p_filesz` of the single load segment, so `seto datarefs`
 * can only report its address as INFERRED.  What the two functions that use it
 * do prove is the *layout of the observed accesses*: which offsets the
 * compiler was told to touch and with which width.  This header records exactly
 * that, so the C stops describing a 0xA4-byte region as a single byte and stops
 * reaching into it through pointers-to-int casts.
 *
 * OBSERVED ACCESSES (see docs/decomp-progress.md, SETO-DECOMP-011).  All are
 * 4-byte accesses produced by `lw`/`sw`:
 *
 *   0x00  sw  0xA4                          (func_00000508)
 *   0x04  sw  func_0000039C()               (func_00000508)
 *   0x08  sw  0 or 1                        (func_00000508)
 *   0x0C  sw  0x11     0x10 sw  0x13        (func_00000508)
 *   0x14  sw  0x12     0x18 sw  0x10        (func_00000508)
 *   0x1C  lw                                (func_00000634)
 *   0x30  sw  incoming argument             (func_00000508)
 *   0x34  sw  0x00600000 (a literal: the `lui` carries no relocation)
 *   0x40  sw  0x604918  0x44 sw 3  0x48 sw 2  0x4C sw 0x2BA
 *   0x50  sw  0x604B18  0x54/0x58/0x5C sw 0
 *   0x60  sw  3        0x64 sw  0x200   0x68 sw  0x604918
 *   0x6C/0x70/0x74 sw 1                 0x78 sw 0
 *
 * `func_00000508` also clears exactly 0xA4 bytes (`func_00000854(base, 0,
 * 0xA4)`), which fixes the extent of the region without interpreting the fields.
 *
 * WHY THIS SHAPE.  The three `void *` fields are the three offsets where an
 * address is stored (`+0x30` the incoming argument, `+0x40` and `+0x68`
 * 0x604918, `+0x50` 0x604B18); they make those stores pointer-typed.  Everything
 * else stays `unsigned int`, including the `+0x34` literal and the word read by
 * `func_00000634`.  The trailing `reserved` covers 0x7C..0xA3, which the clear
 * touches but no field access does.
 *
 * The `SetoObservedBlock` name and every field name are descriptive placeholders
 * for positions, not recovered semantics.
 */
#ifndef SETO_DECOMP_SHARED_STATE_H
#define SETO_DECOMP_SHARED_STATE_H

typedef struct {
    unsigned int words_00_2c[12]; /* 0x00..0x2F */
    void *field_30;               /* 0x30 */
    unsigned int words_34_3c[3];  /* 0x34..0x3F */
    void *field_40;               /* 0x40 */
    unsigned int words_44_4c[3];  /* 0x44..0x4F */
    void *field_50;               /* 0x50 */
    unsigned int words_54_64[5];  /* 0x54..0x67 */
    void *field_68;               /* 0x68 */
    unsigned int words_6c_78[4];  /* 0x6C..0x7B */
    unsigned char reserved[0x28]; /* 0x7C..0xA3 */
} SetoObservedBlock;

/*
 * `offsetof`.  The Metrowerks 3.0.1 installation used for these reconstructions
 * has no reachable standard headers - `<stddef.h>` cannot be opened, because
 * the compiler reports "Environment variable 'MWCIncludes' not found" - so
 * `offsetof` is not defined.  The expansion below is the same expression and
 * this compiler folds it to a constant expression and rejects it when the value
 * is wrong (checked against a deliberately false bound, which fails with
 * "illegal constant expression").
 */
#define SETO_OFFSETOF(type, member) ((unsigned long)&((type *)0)->member)

/*
 * Layout checks, evaluated by the compiler that builds the target.  Metrowerks
 * 3.0.1 build 219 predates `_Static_assert`, so the array-size idiom is used: a
 * false condition makes the typedef a negative-size array, and the compile
 * stops instead of silently accepting a shifted field.
 */
typedef char seto_check_int_size[sizeof(unsigned int) == 4 ? 1 : -1];
typedef char seto_check_pointer_size[sizeof(void *) == 4 ? 1 : -1];
typedef char seto_check_block_size[sizeof(SetoObservedBlock) == 0xA4 ? 1 : -1];
typedef char seto_check_block_alignment[sizeof(SetoObservedBlock) % 4 == 0 ? 1 : -1];

/* Byte offset of `index` in one of the `unsigned int` groups above. */
#define SETO_WORD_OFFSET(group, index) \
    (SETO_OFFSETOF(SetoObservedBlock, group) + (index) * sizeof(unsigned int))

typedef char seto_check_word_00[SETO_WORD_OFFSET(words_00_2c, 0) == 0x00 ? 1 : -1];
typedef char seto_check_word_1c[SETO_WORD_OFFSET(words_00_2c, 7) == 0x1C ? 1 : -1];
typedef char seto_check_field_30[SETO_OFFSETOF(SetoObservedBlock, field_30) == 0x30 ? 1 : -1];
typedef char seto_check_word_34[SETO_WORD_OFFSET(words_34_3c, 0) == 0x34 ? 1 : -1];
typedef char seto_check_field_40[SETO_OFFSETOF(SetoObservedBlock, field_40) == 0x40 ? 1 : -1];
typedef char seto_check_field_50[SETO_OFFSETOF(SetoObservedBlock, field_50) == 0x50 ? 1 : -1];
typedef char seto_check_field_68[SETO_OFFSETOF(SetoObservedBlock, field_68) == 0x68 ? 1 : -1];
typedef char seto_check_word_78[SETO_WORD_OFFSET(words_6c_78, 3) == 0x78 ? 1 : -1];

/*
 * The block itself.  The declaration is provisional: it describes the region's
 * layout for these two translation units, and it does not claim that the PRX
 * object and this object are the same object (see "Limitations" in the docs).
 */
extern SetoObservedBlock D_00604864; /* 0x604864, past `p_filesz`; INFERRED */

#endif /* SETO_DECOMP_SHARED_STATE_H */
