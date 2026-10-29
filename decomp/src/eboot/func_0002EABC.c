typedef struct {
    unsigned int prefix[2];
    unsigned int active;
    unsigned int reserved;
    unsigned int reset;
    unsigned int tail[5];
} Record;

typedef struct {
    unsigned int reserved;
    unsigned int *descriptor;
} Container;

Record *func_0002EABC(Container *container)
{
    Record *cursor = (Record *)((unsigned char *)container + 0x50);
    unsigned int span = *(unsigned int *)((unsigned char *)container->descriptor + 0x0c);
    Record *limit = (Record *)((unsigned char *)container + span - sizeof(Record));

    for (; cursor <= limit; ++cursor) {
        if (cursor->active == 0) {
            cursor->reset = 0;
            return cursor;
        }
    }
    return 0;
}
