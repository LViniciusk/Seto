/* Internal EBOOT helper at .text[0x41870,0x418A0): exact twelve-instruction Ghidra boundary, no calls or data references. Returns the first zero-word count among 16 entries, or -1 when full; not an export. */
int func_00041870(const int *values)
{
    int index = 0;
    do {
        if (values[index] == 0) return index;
    } while (++index < 16);
    return -1;
}
