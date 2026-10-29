typedef struct { unsigned char flag0:1; unsigned char mode:2; unsigned char flag3:1; unsigned char reserved:3; unsigned char flag7:1; } Status;
typedef struct { Status status; unsigned char low:7; unsigned char high:1; } Entry;
extern unsigned char *func_0003B340(unsigned short id);
void func_0003B3DC(int id, int value)
{
    Entry *entry = (Entry *)func_0003B340((unsigned short)id);
    unsigned char current;
    if (entry != 0) {
        if (value <= 99) {
        } else if (value < 0) {
            return;
        }
        current = entry->low;
        if (current == 0) {
            if (value != 0) entry->status.mode = 1;
            else entry->status.mode = 0;
        } else {
            entry->status.mode = 2;
        }
        entry->low = value;
    }
}