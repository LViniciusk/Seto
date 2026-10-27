/* Internal EBOOT helper at .text[0x4E488,0x4E4D8): exact twenty-instruction Ghidra boundary, two resolved calls to 0x4E598 and no data references. Returns the count and stores the selected table value, or zero when empty; not an export. */
extern int func_0004E598(int *self);
int func_0004E488(int *self, int *output)
{
    int count = func_0004E598(self);
    if (count > 0) *output = ((int *)self[1])[self[3]];
    else *output = 0;
    return count;
}
