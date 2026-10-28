/* Internal EBOOT wrapper at .text[0x28414,0x28420): exact three-instruction
 * Ghidra boundary. Its tail call resolves to the helper at 0x9104; no data
 * relocations and not an export.
 */
extern int func_00009104(unsigned int mode, void *data);

int func_00028414(void *data)
{
    return func_00009104(0x10, data);
}
