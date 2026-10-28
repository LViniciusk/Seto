/*
 * EBOOT .text[0x3B940,0x3B96C), exact eleven-instruction helper.
 * The callee remains address-derived; the returned byte is used only at
 * offset two and masked to its low two bits.
 */
extern unsigned char *func_0003B340(unsigned short arg0);

int func_0003B940(unsigned int param_1)
{
    unsigned char *pb = func_0003B340((unsigned short)param_1);

    return pb != 0 ? (pb[2] & 3) : 3;
}
