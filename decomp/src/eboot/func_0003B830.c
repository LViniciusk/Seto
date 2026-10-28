/*
 * EBOOT .text[0x3B830,0x3B860), exact twelve-instruction helper.
 * The callee remains address-derived; unsigned shifts extract bits 4..6 of
 * the returned byte and produce zero when the pointer is null.
 */
extern unsigned char *func_0003B340(unsigned short arg0);

int func_0003B830(unsigned int param_1)
{
    unsigned char *pb = func_0003B340((unsigned short)param_1);

    return pb != 0 ? (((unsigned int)pb[0] << 25) >> 29) : 0;
}
