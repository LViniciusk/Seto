extern const unsigned short *func_00049850(void);

int func_00049C10(void)
{
    unsigned int field = ((unsigned int)func_00049850()[1] << 17) >> 23;
    return field == 0x1ff ? 0xffff : field * 10;
}
