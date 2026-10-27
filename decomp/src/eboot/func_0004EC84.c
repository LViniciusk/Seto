/* Internal EBOOT helper at .text[0x4EC84,0x4EC98): exact five-instruction
 * Ghidra boundary, no calls or data relocations. Clears three words and
 * returns zero; this is not an export.
 */
int func_0004EC84(unsigned int *data)
{
    data[3] = 0;
    data[4] = 0;
    data[5] = 0;
    return 0;
}
