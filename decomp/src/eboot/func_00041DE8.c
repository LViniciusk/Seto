/* Internal EBOOT tail wrapper at .text[0x41DE8,0x41DF0): exact two-instruction
 * Ghidra boundary. Forwards the register arguments unchanged to 0x15660; no
 * data relocations and not an export.
 */
extern int func_00015660(unsigned int a0,
                         unsigned int a1,
                         unsigned int a2,
                         unsigned int a3);

int func_00041DE8(unsigned int a0,
                  unsigned int a1,
                  unsigned int a2,
                  unsigned int a3)
{
    return func_00015660(a0, a1, a2, a3);
}
