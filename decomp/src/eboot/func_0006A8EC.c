/* Internal EBOOT helper at .text[0x6A8EC,0x6A90C): exact eight-instruction
 * Ghidra boundary, no data relocations. Reads byte zero of the table returned
 * by 0x6A674 for index zero; not an export.
 */
extern char *func_0006A674(int index);

int func_0006A8EC(void)
{
    return func_0006A674(0)[0];
}
