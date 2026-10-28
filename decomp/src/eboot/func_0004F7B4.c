/* Internal EBOOT wrapper at .text[0x4F7B4,0x4F7C0): exact three-instruction
 * Ghidra boundary. The tail call resolves canonically to the real
 * ThreadManForUser import at stub 0x6B004/NID 0x812346E4; this is not an export.
 */
extern int func_0006B004(unsigned int value, unsigned int zero);

int func_0004F7B4(unsigned int *data)
{
    return func_0006B004(data[1], 0);
}
