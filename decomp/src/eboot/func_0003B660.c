typedef struct {
    unsigned char status;
    unsigned char reserved : 7;
    unsigned char flag7 : 1;
} Entry;

extern unsigned char *func_0003B340(unsigned short id);

void func_0003B660(int id, int enabled)
{
    Entry *entry = (Entry *)func_0003B340((unsigned short)id);

    if (entry != 0) {
        if (enabled != 0) {
            entry->flag7 = 1;
        } else {
            entry->flag7 = 0;
        }
    }
}
