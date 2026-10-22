/* [0x8,0x154), initialization export. Globals remain provisional zero-fill
 * references. Import signatures describe the observed register arguments only.
 *
 * RESULT: INCONCLUSIVE 63/83 words, zero instruction/relocation differences,
 * 332-byte candidate. Eight HI16/LO16 pairs (16 limitation entries) remain
 * unproven; all other words match the original.
 */
#include "libtutoriallist_stubs.h"
#include "libtutoriallist_panel.h"

extern const unsigned char func_000060F0_name[];

void func_00000008(int index, int context)
{
    func_00002610(&func_00006190_panel, 0, 0xB8);
    if (context == 0) {
        func_0000623C_file = func_00002738(func_000060F0_name, 2, 0, 0x200000, 1, 0);
        func_00002740(func_0000623C_file, &func_00006240_data, 0);
        func_00006238_context = func_000039F0(func_00006240_data, 0x200000);
    } else {
        func_00006238_context = context;
    }
    func_00002720(0, 0x4000);
    func_00001B0C();
    if (index >= 0)
        func_00006190_panel.current = index;
    else
        func_00006190_panel.current = 8;
    if (func_00006190_panel.current >= 8) {
        func_000049A0();
        func_00004990(0x14A);
    }
    func_00004300(1);
    func_000042F0(1);
    func_00004340(0);
    if (func_00004120() == 0) {
        func_000042E0(1);
        func_00004310(0);
    } else {
        func_000042E0(0);
        func_00004310(1);
    }
}
