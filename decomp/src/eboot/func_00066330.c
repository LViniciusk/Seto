/* Internal EBOOT wrapper at .text[0x66330,0x6633C): exact three-instruction
 * Ghidra boundary. Its tail call resolves to 0x661C4; no data relocations and
 * not an export.
 */
extern int func_000661C4(unsigned int mode, void *data);

int func_00066330(void *data)
{
    return func_000661C4(5, data);
}
