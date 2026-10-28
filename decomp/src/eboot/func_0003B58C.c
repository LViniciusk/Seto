typedef struct {
    unsigned char flag0 : 1;
    unsigned char mode : 2;
    unsigned char flag3 : 1;
    unsigned char reserved : 3;
    unsigned char flag7 : 1;
} Status;

extern unsigned char *func_0003B340(unsigned short id);

int func_0003B58C(int id)
{
    Status *entry = (Status *)func_0003B340((unsigned short)id);

    return entry != 0 ? entry->mode == 1 : 0;
}
