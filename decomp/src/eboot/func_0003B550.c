typedef struct {
    unsigned char flag0 : 1;
    unsigned char mode : 2;
    unsigned char rest : 5;
} Status;

extern unsigned char *func_0003B340(unsigned short id);

void func_0003B550(int id)
{
    Status *entry = (Status *)func_0003B340((unsigned short)id);

    if (entry != 0) {
        entry->mode = 2;
    }
}
