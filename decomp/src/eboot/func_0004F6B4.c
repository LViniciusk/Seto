/* Internal EBOOT helper at .text[0x4F6B4,0x4F6D4): exact eight-instruction
 * Ghidra boundary, no calls or data relocations. Reads an indexed table entry
 * through two other structure fields, stores it through the output pointer and
 * returns zero; not an export.
 */
int func_0004F6B4(int *self, int *output)
{
    *output = ((int *)self[3])[self[5]];
    return 0;
}
