/* Internal EBOOT helper at .text[0x29004,0x29020): exact seven-instruction
 * Ghidra boundary, no data relocations. Tail-forwards the destination pointer,
 * a table base plus a 64-byte stride, and a count of 64 to 0x9D1C; not an
 * export.
 */
extern int func_00009D1C(int *destination, int *source, int count);

int func_00029004(int *self, int *destination, int index)
{
    return func_00009D1C(destination, (int *)(self[3] + (index << 6)), 64);
}
