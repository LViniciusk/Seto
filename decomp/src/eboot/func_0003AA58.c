/* Internal EBOOT leaf at .text[0x3AA58,0x3AA60): exact two-instruction
 * Ghidra boundary, no calls or data relocations. Returns the observed constant
 * 0xFCA4; this is not an export.
 */
unsigned int func_0003AA58(void)
{
    return 0xfca4;
}
