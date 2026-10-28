/* Internal EBOOT helper at .text[0x25154,0x25184): exact twelve-instruction Ghidra boundary, no calls or data references. Copies two floats and a tag field, then three floats; not an export. */
void func_00025154(float *destination, const float *first, const float *second, unsigned int tag)
{
    destination[0] = first[0];
    destination[1] = first[1];
    *(unsigned int *)&destination[2] = tag;
    destination[3] = second[0];
    destination[4] = second[1];
    destination[5] = second[2];
}
