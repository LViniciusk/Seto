/* Internal EBOOT helper at .text[0x4EC48,0x4EC68): exact eight-instruction
 * Ghidra boundary, no data relocations. Clears field 28, calls 0x4EC84 with the
 * same structure and returns zero; not an export.
 */
extern void func_0004EC84(int *self);

int func_0004EC48(int *self)
{
    self[7] = 0;
    func_0004EC84(self);
    return 0;
}
