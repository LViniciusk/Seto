/*
 * EBOOT .text[0x4CAB0,0x4CAE0), exact twelve-instruction wrapper.
 * The callee label is address-derived and remains unnamed semantically. The
 * input word and local output are represented only as 32-bit values; the
 * return tests bit 2 of the word written by the callee.
 */
extern void func_0004EF68(unsigned int arg0, unsigned int *arg1);

int func_0004CAB0(unsigned int *param_1)
{
    unsigned int local_4;

    func_0004EF68(param_1[3], &local_4);
    return (local_4 & 4u) == 4u;
}
