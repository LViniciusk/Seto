/* Internal EBOOT helper at .text[0x5A4EC,0x5A50C): exact eight-instruction Ghidra boundary, no calls or data references. Selects the base word for a zero selector, otherwise follows the 16-bit-relative entry; not an export. */
int func_0005A4EC(const void *base, int index)
{
    if (index == 0) return *(const int *)base;
    return *(const int *)((unsigned int)index + *(const unsigned short *)((const char *)base + 10) + 4);
}
