/*
 * EBOOT .text[0x4DC90,0x4DCC4), exact thirteen-instruction wrapper.
 * The callee remains address-derived; the argument is represented as a raw
 * 32-bit ABI word, and the local output is tested only for bit 3.
 */
extern void func_0004EF68(unsigned int arg0, unsigned int *arg1);

int func_0004DC90(unsigned int param_1)
{
    unsigned int local_4;

    func_0004EF68(param_1, &local_4);
    return (local_4 & 8u) == 8u ? 1 : -1;
}
