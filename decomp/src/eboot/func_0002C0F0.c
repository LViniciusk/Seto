typedef unsigned int u32;
typedef unsigned char u8;

int func_0002C0F0(u32 *arg0)
{
    u32 first;
    u32 *base;
    u32 offset;

    if (arg0 == 0) {
        return -1;
    }

    first = *arg0;
    base = first == 0x1a464845u ? arg0 : (u32 *)first;
    offset = *(u32 *)((u8 *)base + 0x10);
    return *(u32 *)((u8 *)base + offset);
}
