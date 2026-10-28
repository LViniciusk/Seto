/*
 * EBOOT .text[0x3B3B0,0x3B3DC), exact eleven-instruction helper.
 * The call remains address-derived; the returned byte is used only at offset
 * one and masked to its low seven bits.
 */
extern unsigned char *func_0003B340(unsigned short arg0);

int func_0003B3B0(unsigned int param_1)
{
    unsigned char *pb = func_0003B340((unsigned short)param_1);

    return pb != 0 ? (pb[1] & 0x7F) : 0;
}
