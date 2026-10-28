/* Internal EBOOT wrapper at .text[0x66318,0x66324): exact three-instruction
 * Ghidra boundary. Its tail call resolves to the EBOOT helper at 0x661C4; it
 * has no data relocations and is not an export.
 */
extern int func_000661C4(unsigned int mode, void *data);

int func_00066318(void *data)
{
    return func_000661C4(2, data);
}
