/* EBOOT .text[0x2C28C,0x2C2FC), libehsys export 0x7187E0F0. */
extern unsigned char *func_0002BD58(unsigned char *record);

void func_0002C28C(unsigned int *record, unsigned int *field_20, unsigned int *field_22)
{
    if (record == 0) {
        *field_22 = 0xFFFFFFFFu;
        *field_20 = 0xFFFFFFFFu;
        return;
    }
    record = (record[0] == 0x1A464845u)
        ? (unsigned int *)func_0002BD58((unsigned char *)record)
        : record;
    *field_20 = *(unsigned short *)(record + 8);
    *field_22 = *(unsigned short *)((unsigned char *)record + 0x22);
}
