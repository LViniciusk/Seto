/* EBOOT .text[0x31650,0x3165C), exported by libehsys NID 0x9EA6989A.
 * The verified Ghidra body has exactly three Allegrex instructions:
 * sw zero,0x8(a0); jr ra; sw zero,0xC(a0).  Both stores are literal zero
 * writes to successive words at offsets 8 and 12 of the argument, and the
 * original places the second store in the jr delay slot.
 */
void func_00031650(unsigned int *record)
{
    record[2] = 0;
    record[3] = 0;
}
