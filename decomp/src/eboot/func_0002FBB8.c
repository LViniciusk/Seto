/* Internal EBOOT tail wrapper at .text[0x2FBB8,0x2FBC0): exact two-instruction
 * Ghidra boundary. Calls 0x2FAC0 with mode 1; no data relocations and not an
 * export.
 */
extern int func_0002FAC0(unsigned int first,
                         unsigned int second,
                         unsigned int mode);

int func_0002FBB8(unsigned int first, unsigned int second)
{
    return func_0002FAC0(first, second, 1);
}
