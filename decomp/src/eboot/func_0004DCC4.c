typedef unsigned int u32;

extern void func_0004EF68(void *arg0, u32 *out_value);

int func_0004DCC4(void *param_1)
{
    u32 local_4;

    func_0004EF68(param_1, &local_4);
    return -(int)((local_4 & 0x800u) != 0u);
}
