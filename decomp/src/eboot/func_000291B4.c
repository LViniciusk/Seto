/* Internal EBOOT tail wrapper at .text[0x291B4,0x291BC): exact two-instruction
 * Ghidra boundary. Tail-jumps to 0x33AE0 with the register argument set
 * unchanged; no data relocations and not an export.
 */
extern int func_00033AE0(unsigned int a0,
                         unsigned int a1,
                         unsigned int a2,
                         unsigned int a3);

int func_000291B4(unsigned int a0,
                  unsigned int a1,
                  unsigned int a2,
                  unsigned int a3)
{
    return func_00033AE0(a0, a1, a2, a3);
}
