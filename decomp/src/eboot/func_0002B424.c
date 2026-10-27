/* Internal EBOOT helper at .text[0x2B424,0x2B444): exact eight-instruction
 * Ghidra boundary, no data relocations. Calls 0x1B94C and returns whether its
 * result is nonzero; not an export.
 */
extern int func_0001B94C(void);

int func_0002B424(void)
{
    return func_0001B94C() != 0;
}
