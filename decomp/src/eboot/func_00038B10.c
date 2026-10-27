typedef unsigned int u32;
typedef unsigned char u8;

extern void func_00031308(void *cursor, u32 *words, u32 count);

void func_00038B10(void *param_1, u32 param_2)
{
    u32 local_4;
    u8 *p;
    u32 count;

    p = (u8 *)&local_4;
    count = 4;
    if (p != 0) {
        do {
            *p = 0;
            p++;
        } while (--count != 0);
    }
    local_4 = param_2 | 0xe6000000;
    func_00031308(param_1, &local_4, 1);
}
