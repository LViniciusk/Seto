/*
 * libhtml_view.prx, .text 0x4B8-0x508 (0x50 bytes, 20 instructions).
 *
 * Evidence: splat's verified `text.s`, `seto disasm`, m2c 0.1.0 and Ghidra
 * 12.1.3 / Allegrex headless analysis. Ghidra confirms the function takes one
 * 32-bit pointer-like argument, uses a 0x20-byte stack buffer, passes the
 * argument and the string at image offset 0x4830 (`/PSP/SAVEDATA/`) to
 * func_00000894, initializes the buffer, passes it to func_00002D0C, then
 * passes both values to func_000008A4. The saved `$s0` preserves the original
 * argument across those calls.
 *
 * m2c's preliminary output omits the first argument to func_00000894. Ghidra's
 * disassembly shows `$a0` still contains the entry argument at 0x4CC and `$a1`
 * is set to the path in the delay slot, so this reconstruction follows the
 * instruction stream, not m2c's omitted argument. The helper prototypes and
 * the argument's semantic type remain provisional; the stripped PRX does not
 * supply their source declarations. No `mwccpsp` is available, so this C is
 * UNVERIFIED and must not be counted as a matching decompilation.
 *
 * Status: UNVERIFIED (compilation/matching BLOCKED: no licensed mwccpsp).
 */

typedef unsigned char u8;

extern const char D_00004830[];
extern void func_00000894(void *arg0, const char *path);
extern void func_00000854(void *buffer, int value, unsigned int size);
extern void func_00002D0C(void *buffer);
extern void func_000008A4(void *arg0, void *buffer);

void func_000004B8(void *arg0)
{
    u8 local_buffer[0x20];

    func_00000894(arg0, D_00004830);
    func_00000854(local_buffer, 0, 0x20);
    func_00002D0C(local_buffer);
    func_000008A4(arg0, local_buffer);
}
