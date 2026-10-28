/*
 * EBOOT .text[0x4D2B0,0x4D2E8), exact fourteen-instruction wrapper.
 * The repeated local callee is kept under its address-derived name; its
 * semantic API identity is not inferred.
 */
extern void func_0005537C(int arg0);

int func_0004D2B0(void)
{
    func_0005537C(2);
    func_0005537C(3);
    func_0005537C(4);
    func_0005537C(5);
    return 0;
}
