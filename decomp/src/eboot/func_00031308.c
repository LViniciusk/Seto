/*
 * Internal EBOOT .text[0x31308,0x31364): the exact 23-instruction body is
 * Ghidra-confirmed. This is not an export and intentionally has no NID.
 * The R_MIPS_26 at 0x3132c resolves to the internal helper at 0x3129c.
 * Parameter and return types below describe the observed Allegrex ABI only.
 */
extern unsigned int *func_0003129C(unsigned int *cursor, unsigned int word);

unsigned int *func_00031308(unsigned int *cursor,
                            const unsigned int *words,
                            int count)
{
    int i = 0;
    const unsigned int *word_cursor;

    if (count > 0) {
        word_cursor = words;
        do {
            cursor = func_0003129C(cursor, *word_cursor);
            i++;
            word_cursor++;
        } while (i < count);
    }
    return cursor;
}
