/* Internal EBOOT helper at .text[0x4DCF0,0x4DD10): exact eight-instruction
 * Ghidra boundary, no data relocations. Forwards its first argument and the
 * constant 255 to 0x4EF60, then returns zero; not an export.
 */
extern void func_0004EF60(int first, int second);

int func_0004DCF0(int first)
{
    func_0004EF60(first, 255);
    return 0;
}
