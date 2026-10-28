/*
 * EBOOT .text[0x3B738,0x3B764), exact eleven-instruction helper.
 * The callee remains address-derived; the returned byte is used only at
 * offset zero and masked to its low bit.
 */
extern unsigned char *func_0003B340(unsigned short arg0);

int func_0003B738(unsigned int param_1)
{
    unsigned char *pb = func_0003B340((unsigned short)param_1);

    return pb != 0 ? (pb[0] & 1) : 0;
}
