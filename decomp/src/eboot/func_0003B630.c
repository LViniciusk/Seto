/*
 * EBOOT .text[0x3B630,0x3B660), exact twelve-instruction helper.
 * The local call remains address-derived; the returned byte is treated only
 * as an unsigned byte whose high bit is extracted.
 */
extern unsigned char *func_0003B340(unsigned short arg0);

int func_0003B630(unsigned int param_1)
{
    unsigned char *pb = func_0003B340((unsigned short)param_1);

    return pb != 0 ? (((unsigned int)pb[0] << 24) >> 31) : 1;
}
