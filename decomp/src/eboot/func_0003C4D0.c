typedef struct {
    unsigned char flags;
    unsigned char low2 : 2;
    unsigned char rest : 6;
} Entry;

extern unsigned char *func_0003C424(int index);

void func_0003C4D0(int index, int value)
{
    Entry *entry = (Entry *)func_0003C424(index);

    if (entry != 0) {
        entry->low2 = value & 3;
    }
}