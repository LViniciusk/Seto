/* Internal EBOOT leaf at .text[0x2FC88,0x2FCA8): exact eight-instruction Ghidra
 * boundary, no calls or data relocations. Compares the low 24 bits of a word
 * with 0x504845 ("PHE") and returns a boolean; not an export.
 */
int func_0002FC88(const unsigned int *value)
{
    return (*value & 0xFFFFFF) == 0x504845;
}
