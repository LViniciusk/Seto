/* Internal EBOOT tail wrapper at .text[0x55044,0x5504C): exact two-instruction
 * Ghidra boundary. Forwards the register arguments unchanged to 0x391C0; no
 * data relocations and not an export.
 */
extern int func_000391C0(unsigned int a0,
                         unsigned int a1,
                         unsigned int a2,
                         unsigned int a3);

int func_00055044(unsigned int a0,
                  unsigned int a1,
                  unsigned int a2,
                  unsigned int a3)
{
    return func_000391C0(a0, a1, a2, a3);
}
