extern unsigned int func_00054EE4(unsigned int, int, int, int);
extern void func_00054F60(unsigned int, int, int, unsigned int);

void func_00053BD4(unsigned int param_1, int param_2, int param_3, unsigned int param_4)
{
    unsigned int result;

    result = func_00054EE4(param_1, param_2, param_3, 1);
    func_00054F60(result, param_2 + 0xC, param_3 + 1, param_4);
}
