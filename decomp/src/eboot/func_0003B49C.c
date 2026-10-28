typedef struct {
    unsigned char flag0 : 1;
    unsigned char mode : 2;
    unsigned char flag3 : 1;
    unsigned char reserved : 3;
    unsigned char flag7 : 1;
} Status;

typedef struct {
    Status status;
    unsigned char low : 7;
    unsigned char high : 1;
} Entry;

extern unsigned char *func_0003B340(unsigned short id);

void func_0003B49C(int id, int value)
{
    Entry *entry = (Entry *)func_0003B340((unsigned short)id);

    if (entry != 0) {
        if (value != 0) {
            if (entry->status.mode == 0) {
                entry->status.mode = 1;
            }
            if (entry->low < 99) {
                entry->low = entry->low + 1;
            }
        } else {
            if (entry->low != 0) {
                entry->low = entry->low + 0xff;
            }
        }
    }
}
