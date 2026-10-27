/* Internal EBOOT helper at .text[0x297EC,0x297F8): exact three-instruction
 * Ghidra boundary, no calls or data relocations. Clears data[0x54] and returns
 * the original first argument; this is not an export.
 */
unsigned int *func_000297EC(unsigned int *result, unsigned int *data)
{
    data[21] = 0;
    return result;
}
