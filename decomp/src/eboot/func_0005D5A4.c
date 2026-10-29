typedef struct {
    unsigned char pad0[0x1c];
    unsigned short value;
    unsigned char pad1[0x12];
    signed char format;
} Record;
unsigned int func_0005D5A4(const Record *record)
{
    if (record == 0)
        return 0;
    return 0x20000000u | (((unsigned int)(int)record->format << 16) | (unsigned int)record->value);
}