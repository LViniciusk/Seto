/*
 * EBOOT .text[0x3C478,0x3C4A8), exact twelve-instruction helper.
 * The call target remains address-derived; only the returned byte pointer and
 * the low byte of the second ABI argument are represented.
 */
extern unsigned char *func_0003C424(void);

void func_0003C478(unsigned int param_1, unsigned char param_2)
{
    unsigned char *pb = func_0003C424();

    if (pb != 0) {
        *pb = param_2;
    }
}
