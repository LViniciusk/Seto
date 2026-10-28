/*
 * EBOOT .text[0x3B7A0,0x3B7D0), exact twelve-instruction helper.
 * The callee remains address-derived; unsigned shifts extract the observed
 * bit from the byte at offset zero.
 */
extern unsigned char *func_0003B340(unsigned short arg0);

int func_0003B7A0(unsigned int param_1)
{
    unsigned char *pb = func_0003B340((unsigned short)param_1);

    return pb != 0 ? (((unsigned int)pb[0] << 28) >> 31) : 0;
}
