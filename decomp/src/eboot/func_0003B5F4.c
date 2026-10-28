typedef struct {
    unsigned char flag0 : 1;
    unsigned char mode : 2;
    unsigned char flag3 : 1;
    unsigned char reserved : 3;
    unsigned char flag7 : 1;
} Status;

extern unsigned char *func_0003B340(unsigned short id);

void func_0003B5F4(int id)
{
    Status *entry = (Status *)func_0003B340((unsigned short)id);

    if (entry != 0) {
        entry->flag7 = 1;
    }
}
