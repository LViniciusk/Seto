/* [0x280,0x2C8), cleanup, returns 1. The positive file-id guard and the
 * reload after the first import preserve the original call-side effects.
 *
 * RESULT: INCONCLUSIVE 12/18 words, zero instruction/relocation differences,
 * 72-byte candidate. Three HI16/LO16 pairs remain unproven.
 */
#include "libtutoriallist_stubs.h"
#include "libtutoriallist_panel.h"

int func_00000280(void)
{
    func_00001C18();
    if (func_0000623C_file > 0) {
        func_00002748(func_0000623C_file, func_00006240_data);
        func_00002750(func_0000623C_file);
    }
    return 1;
}
