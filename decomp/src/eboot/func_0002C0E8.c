/* Internal EBOOT tail wrapper at .text[0x2C0E8,0x2C0F0): exact two-instruction
 * Ghidra boundary. Forwards the register arguments unchanged to 0x2BF10; no
 * data relocations and not an export.
 */
extern int func_0002BF10(unsigned int a0,
                         unsigned int a1,
                         unsigned int a2,
                         unsigned int a3);

int func_0002C0E8(unsigned int a0,
                  unsigned int a1,
                  unsigned int a2,
                  unsigned int a3)
{
    return func_0002BF10(a0, a1, a2, a3);
}
