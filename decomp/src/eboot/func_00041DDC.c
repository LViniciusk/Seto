/* Internal EBOOT wrapper at .text[0x41DDC,0x41DE8): exact three-instruction
 * Ghidra boundary. Tail-calls the helper at 0x15924 with two zero arguments;
 * no data relocations and not an export.
 */
extern int func_00015924(unsigned int first, unsigned int second);

int func_00041DDC(void)
{
    return func_00015924(0, 0);
}
