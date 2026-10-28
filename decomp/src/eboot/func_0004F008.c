/* Internal EBOOT helper at .text[0x4F008,0x4F020): exact six-instruction
 * Ghidra boundary, no calls or data relocations. Copies four arguments into
 * structure fields in the observed store order and returns zero; not export.
 */
int func_0004F008(unsigned int *data,
                  unsigned int first,
                  unsigned int second,
                  unsigned int third,
                  unsigned int fourth)
{
    data[0] = first;
    data[2] = third;
    data[1] = second;
    data[3] = fourth;
    return 0;
}
