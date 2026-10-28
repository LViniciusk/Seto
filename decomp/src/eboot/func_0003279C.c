/* Internal EBOOT tail wrapper at .text[0x3279C,0x327A4): exact two-instruction
 * Ghidra boundary. Forwards the register arguments unchanged to 0x3236C; no
 * data relocations and not an export.
 */
extern int func_0003236C(unsigned int a0,
                         unsigned int a1,
                         unsigned int a2,
                         unsigned int a3);

int func_0003279C(unsigned int a0,
                  unsigned int a1,
                  unsigned int a2,
                  unsigned int a3)
{
    return func_0003236C(a0, a1, a2, a3);
}
