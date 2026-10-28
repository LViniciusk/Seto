/* Internal EBOOT wrapper at .text[0x5AB88,0x5AB94): exact three-instruction
 * Ghidra boundary. Tail-calls the helper at 0x5A634 with constants 0x10/0x6F;
 * no data relocations and not an export.
 */
extern int func_0005A634(unsigned int first,
                         unsigned int second,
                         unsigned int third,
                         unsigned int fourth);

int func_0005AB88(unsigned int first, unsigned int second)
{
    return func_0005A634(first, second, 0x10, 0x6f);
}
