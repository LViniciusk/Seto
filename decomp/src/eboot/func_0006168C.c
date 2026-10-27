/* Internal EBOOT wrapper at .text[0x6168C,0x61698): exact three-instruction
 * Ghidra boundary. Tail-calls the helper at 0x5C4B4 with zeroes for arguments
 * two and three; no data relocations and not an export.
 */
extern int func_0005C4B4(unsigned int first,
                         unsigned int second,
                         unsigned int third);

int func_0006168C(unsigned int first)
{
    return func_0005C4B4(first, 0, 0);
}
