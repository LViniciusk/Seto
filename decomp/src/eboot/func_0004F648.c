/* Internal EBOOT helper at .text[0x4F648,0x4F698): exact twenty-instruction Ghidra boundary, two resolved calls to 0x4F738 and no data references. Returns the count and stores the selected table value, or zero when empty; not an export. */
extern int func_0004F738(int *self);
int func_0004F648(int *self, int *output)
{
    int count = func_0004F738(self);
    if (count > 0) *output = ((int *)self[2])[self[4]];
    else *output = 0;
    return count;
}
