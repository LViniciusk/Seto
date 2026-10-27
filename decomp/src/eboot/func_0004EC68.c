/* Internal EBOOT helper at .text[0x4EC68,0x4EC84): exact seven-instruction
 * Ghidra boundary, no calls or data relocations. Clears a nonzero field and
 * returns zero; the likely branch/delay slot matches the original; not export.
 */
int func_0004EC68(unsigned int *data)
{
    if (data[2] != 0)
        data[2] = 0;
    return 0;
}
