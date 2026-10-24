/* EBOOT .text[0x33D10,0x33D4C), exported by libehsys NID 0x20E340D9.
 * The bounded body clears the first word, derives a four-bit quantity from
 * byte 4, conditionally calls the internal routine at 0x92FC, and returns 1.
 */
extern void func_000092FC(void *address);

int func_00033D10(unsigned char *record)
{
    int count;

    *(unsigned int *)record = 0;
    count = (int)(((unsigned int)record[4] << 24) >> 26);
    if (count < 17) {
        func_000092FC(record - count);
    }
    return 1;
}
