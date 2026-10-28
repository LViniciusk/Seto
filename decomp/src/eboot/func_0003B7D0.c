typedef struct {
    unsigned char flag0 : 1;
    unsigned char mode : 2;
    unsigned char flag3 : 1;
    unsigned char field : 3;
    unsigned char flag7 : 1;
} Status;

extern unsigned char *func_0003B340(unsigned short id);

void func_0003B7D0(int id, int value)
{
    Status *entry = (Status *)func_0003B340((unsigned short)id);

    if (entry != 0 && value >= 0 && value < 8) {
        entry->field = value;
    }
}
