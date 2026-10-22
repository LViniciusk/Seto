/*
 * libtutoriallist.prx, .text [0x1E84, 0x1E94), four instructions.
 *
 * Halfword-key comparator passed as the fourth argument to import 0x2638 by
 * func_00001B0C. The relocated callback pointer establishes the entry missing
 * from the earlier direct-call/Ghidra triage. Reads unsigned halfwords from
 * the two valid, halfword-aligned input pointers and returns their difference
 * in [-65535, 65535], without signed overflow. No bounds/null guard is present
 * in the original. MATCHED 4/4, complete 16-byte symbol, no relocations.
 */

#include "libtutoriallist_stubs.h"

int func_00001E84(const unsigned short *arg0, const unsigned short *arg1)
{
    return *arg0 - *arg1;
}
