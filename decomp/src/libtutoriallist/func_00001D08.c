/*
 * libtutoriallist.prx, .text [0x1D08, 0x1DF4), 59 instructions.
 *
 * Ghidra confirmed one exact body range. The function looks up a 16-bit key in
 * a four-entry table through func_00001E94 (count 4, stride 12 bytes), then
 * returns the entry's cached value at +4. On a cache miss it obtains a handle
 * from func_00001C58, copies a six-byte name fragment (three two-byte chunks)
 * from `.data+0x80`, formats one character selected by func_00004120 into a
 * 256-byte local buffer, converts it through func_00003790, and caches the
 * result in the entry.
 *
 * The two table references combine to module offset 0x00006120 (.data+0x34)
 * and the name fragment to 0x0000616C (.data+0x80). Both locations are proven
 * inside the original `.data` section, but no candidate symbol is linked to
 * them: a location in the original artifact is not an object identity in the
 * candidate object. The extern declarations below state the observed reference
 * shapes without asserting that the candidate names the same objects. The
 * comparator therefore keeps these references unresolved even though every
 * instruction word agrees.
 *
 * The 12-byte stride, the +4/+8 fields and the 256-byte buffer are recovered
 * from the instruction sequence; the field roles remain provisional. The
 * func_00001E94 contract is the one documented in its own source (count,
 * stride, halfword table), not a new universal contract.
 *
 * The declaration order below (buffers, loop pointers, then scalars) is
 * load-bearing: it is what selects entry=s0 and handle=s1 in the original.
 * Permutations that put the scalar group first produce the mirror assignment
 * (entry=s1, handle=s0) and seven word differences. The `if (index < 0)`
 * early return is also load-bearing; a positive wrapper selects a different
 * branch layout and saves one instruction.
 *
 * Key ABI: func_00001E94 masks its key with `andi a0,a0,0xffff` at 0x1EB0,
 * and the original call site at 0x1D24 passes a0 unchanged. The caller-side
 * key is therefore a 16-bit domain. Declaring func_00001E94(unsigned short)
 * while keeping this function's key as int makes Metrowerks insert a redundant
 * `andi a0,a0,0xffff` at 0x1D10; the body shifts and the result is NONMATCHING
 * 3/59. Declaring both keys unsigned short removes the call-site conversion and
 * reproduces the certified object byte for byte.
 *
 * Demonstrated by the binary for `name[func_00004120()]`: the name fragment is
 * six bytes copied from .data+0x80, the selected byte is read at buffer+index,
 * and the path contains no clamp or bounds check.
 *
 * Required input domain for `name[func_00004120()]` (hypothesis, not
 * demonstrated): func_00004120() must return a value in [0, 5]. The artifact
 * does not prove that range; other uses of func_00004120 in the module compare
 * it with zero, and an out-of-range value makes the original read adjacent
 * stack bytes (undefined behavior in C). This is the caller's obligation, not
 * a property of every call.
 *
 * Demonstrated by the binary for the table: func_00001E94 is called with
 * count 4 and stride 12, and the returned index addresses a four-entry table.
 * Required input domain (hypothesis, not demonstrated): the index must select
 * a valid entry; the table's ownership and full extent remain unproven, and
 * the original does not bounds-check the index.
 *
 * Status: INCONCLUSIVE 53/59, zero instruction differences. The three
 * limitations are the HI16/LO16 pairs at words 2, 15 and 25: the original
 * targets .data+0x34, .data+0x34 and .data+0x80, while the candidate symbols
 * are unresolved. The comparator excludes both words of each unresolved pair,
 * so 53/59 is its maximum without inventing a cross-artifact identity.
 */

#include "libtutoriallist_stubs.h"

extern int func_00001C58(void);

extern unsigned short func_00001D08_entries[];
extern const char func_00001D08_names[];

int func_00001D08(unsigned short key)
{
    char buffer[256];
    char name[6];
    const char *source;
    char *target;
    int remaining;
    int index;
    int *entry;
    int handle;
    int value;

    index = func_00001E94(key, func_00001D08_entries, 4, 12);

    if (index < 0)
        return 0;

    entry = (int *)((char *)func_00001D08_entries + index * 12);
    if (entry[1] != 0)
        return entry[1];

    handle = func_00001C58();

    source = func_00001D08_names;
    target = name;
    remaining = 3;
    do {
        target[0] = source[0];
        target[1] = source[1];
        source += 2;
        target += 2;
    } while (--remaining > 0);

    if (handle == 0)
        return 0;

    func_000025D0(buffer, entry[2], name[func_00004120()]);

    value = func_00003790(handle, buffer, 0);
    entry[1] = value;
    return value;
}
