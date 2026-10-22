/*
 * libtutoriallist.prx, .text [0x1C58, 0x1D08), 44 instructions.
 *
 * Returns the cached word at module offset 0x6248 when it is nonzero. Otherwise,
 * when bit 0 of the shared byte is set, clears that bit, obtains a token and a
 * handle through libehsys imports, caches the handle and registers the existing
 * func_00001DF4 callback. That slow path returns zero even when the new handle
 * is nonzero. The second import consumes the word at module offset 0x6238.
 *
 * The last call has six register arguments: (3, path, handle, token, callback,
 * handle) in a0-a3/t0/t1. The callback's relocated low address is computed in
 * the jal delay slot. The import return is unused. These are observed call-site
 * types, not a recovered SDK contract; no incompatible pointer cast is needed.
 *
 * path is a provisional reference to .data+0x64, not a recreated game asset.
 * The globals and callback address remain unresolved cross-artifact references.
 * INCONCLUSIVE 28/44: zero differences/relocation issues, eight data pairs and
 * the original branch-crossing pairing limitations remain. Symbol size: 176.
 */

#include "libtutoriallist_stubs.h"

extern int func_00006248_handle;
extern int func_00006238_context;
extern const char func_00006150_path[];

int func_00001C58(void)
{
    int token;
    int handle;

    if (func_00006248_handle != 0)
        return func_00006248_handle;

    if (func_00006250_state.active != 0) {
        func_00006250_state.active = 0;
        token = func_000036A0(3, func_00006150_path);
        handle = func_00003A00(func_00006238_context, token);
        func_00006248_handle = handle;
        func_00003668(3, func_00006150_path, handle, token, func_00001DF4, handle);
    }
    return 0;
}
