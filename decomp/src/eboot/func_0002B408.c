/* Internal EBOOT helper at .text[0x2B408,0x2B424): exact seven-instruction
 * Ghidra boundary. It forwards three input words and a four-byte local output
 * buffer to 0x1B6E4; no data relocations and not an export.
 */
extern int func_0001B6E4(unsigned int first,
                         unsigned int second,
                         unsigned int third,
                         void *output);

int func_0002B408(unsigned int first,
                  unsigned int second,
                  unsigned int third)
{
    unsigned int output;
    return func_0001B6E4(first, second, third, &output);
}
