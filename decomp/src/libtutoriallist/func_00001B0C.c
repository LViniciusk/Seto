/*
 * libtutoriallist.prx, .text [0x1B0C, 0x1B70), 25 instructions.
 *
 * Clears the shared byte through libehsys/0x10F3BB61 (destination, 0, 1), sets
 * its low bit and passes the four-entry, 12-byte-stride table to the imported
 * libehsys/0x1B00FB95 with func_00001E84 as the halfword-key comparator.
 * Both import return values are unused. The table is the same provisional
 * symbol used by func_00001D08; no initialized data or identity is invented.
 *
 * INCONCLUSIVE 15/25, zero instruction differences/relocation issues. Five
 * HI16/LO16 pairs (three shared-state, table, comparator) remain unresolved.
 * Complete candidate symbol: 100 bytes, matching the original interval size.
 */

#include "libtutoriallist_stubs.h"

extern unsigned short func_00001D08_entries[];

void func_00001B0C(void)
{
    func_00002610(&func_00006250_state, 0, 1);
    func_00006250_state.active = 1;
    func_00002638(func_00001D08_entries, 4, 12, func_00001E84);
}
