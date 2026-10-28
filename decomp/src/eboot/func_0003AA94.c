/* Internal EBOOT helper at .text[0x3AA94,0x3AAB4): exact eight-instruction
 * Ghidra boundary, no data relocations. Adds 28 to the pointer returned by
 * 0x3A90C; not an export.
 */
extern void *func_0003A90C(void);

char *func_0003AA94(void)
{
    return (char *)func_0003A90C() + 28;
}
