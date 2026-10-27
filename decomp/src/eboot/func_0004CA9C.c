/* Internal EBOOT accessor at .text[0x4CA9C,0x4CAA4): exact two-instruction
 * Ghidra boundary, no calls or data relocations. Returns the word at offset 4;
 * this is not an export.
 */
unsigned int func_0004CA9C(const unsigned int *data)
{
    return data[1];
}
