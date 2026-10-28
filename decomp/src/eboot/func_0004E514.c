/* Internal EBOOT helper at .text[0x4E514,0x4E534): exact eight-instruction
 * Ghidra boundary, no calls or data relocations. Reads an indexed table entry
 * through two structure fields, stores it through the output pointer and
 * returns zero; not an export.
 */
int func_0004E514(int *self, int *output)
{
    *output = ((int *)self[2])[self[4]];
    return 0;
}
