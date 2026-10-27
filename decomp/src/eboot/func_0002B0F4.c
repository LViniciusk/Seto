extern void func_0002B02C(void *, int, int, int);
extern void func_0006AEAC(void *, int, int);

void func_0002B0F4(int param_1, int param_2)
{
    unsigned char buffer[0x100];

    func_0002B02C(buffer, param_1, param_2, 0);
    func_0006AEAC(buffer, 0, 0);
}
