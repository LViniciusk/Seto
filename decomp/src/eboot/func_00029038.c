/* Internal EBOOT helper at .text[0x29038,0x29070): exact fourteen-instruction Ghidra boundary, no calls or data references. Validates two pointers and adjusts a selected field by a flag bit; not an export. */
int func_00029038(const unsigned int *self)
{
    const unsigned int *pointer;
    if (self == 0) return -1;
    pointer = (const unsigned int *)self[5];
    if (pointer == 0) return -2;
    return (int)pointer[12] - ((self[15] & 2) != 0);
}
