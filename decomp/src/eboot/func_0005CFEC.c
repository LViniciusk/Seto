/* Internal EBOOT helper at .text[0x5CFEC,0x5D00C): exact eight-instruction
 * Ghidra boundary, no data relocations. Calls 0x5CF7C and returns whether its
 * result is nonzero; not an export.
 */
extern int func_0005CF7C(void);

int func_0005CFEC(void)
{
    return func_0005CF7C() != 0;
}
