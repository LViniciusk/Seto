extern int func_0003A90C(void);

void func_0003D868(int index, unsigned char value)
{
    unsigned char *base;

    base = (unsigned char *)func_0003A90C();
    if (index < 0x18) {
        if (base[index + 0x97d0] < value) {
            base[index + 0x97d0] = value;
        }
    }
}
