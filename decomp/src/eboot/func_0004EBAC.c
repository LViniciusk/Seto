/* Internal EBOOT helper at .text[0x4EBAC,0x4EBCC): exact eight-instruction
 * Ghidra boundary, no data relocations. Calls 0x4CD4C and returns zero; not an
 * export.
 */
extern void func_0004CD4C(void);

int func_0004EBAC(void)
{
    func_0004CD4C();
    return 0;
}
