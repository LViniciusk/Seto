/*
 * EBOOT .text[0x3B6CC,0x3B6FC), exact twelve-instruction helper.
 * The callee remains address-derived; the unsigned shifts extract the high
 * bit of the byte at offset one while retaining the observed instruction form.
 */
extern unsigned char *func_0003B340(unsigned short arg0);

int func_0003B6CC(unsigned int param_1)
{
    unsigned char *pb = func_0003B340((unsigned short)param_1);

    return pb != 0 ? (((unsigned int)pb[1] << 24) >> 31) : 0;
}
