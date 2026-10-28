/*
 * EBOOT .text[0x3C518,0x3C544), exact eleven-instruction helper.
 * The callee remains address-derived; only the byte at offset one and its
 * low two bits are used.
 */
extern unsigned char *func_0003C424(void);

int func_0003C518(void)
{
    unsigned char *p = func_0003C424();

    return p != 0 ? (p[1] & 3) : 0;
}
