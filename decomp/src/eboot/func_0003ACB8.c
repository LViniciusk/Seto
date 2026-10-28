/* Internal EBOOT helper at .text[0x3ACB8,0x3ACDC): exact nine-instruction
 * Ghidra boundary, no data relocations. Returns field 76 of the structure
 * returned by 0x3A90C, incremented by one; not an export.
 */
extern int *func_0003A90C(void);

int func_0003ACB8(void)
{
    return func_0003A90C()[19] + 1;
}
