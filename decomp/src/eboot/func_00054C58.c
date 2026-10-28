/* Internal EBOOT helper at .text[0x54C58,0x54C7C): exact nine-instruction Ghidra boundary, no calls or data references. Copies four selected words between structures; not an export. */
void func_00054C58(unsigned int *destination, const unsigned int *source)
{
    destination[3] = source[35];
    destination[6] = source[38];
    destination[4] = source[36];
    destination[5] = source[37];
}
