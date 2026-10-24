/* EBOOT .text[0x09C98,0x09D1C), exported by libehsys NID 0x1B00FB95.
 * Ghidra 12.1.3 confirmed the exact 33-instruction Allegrex function body.
 * The source follows its word-scan and byte-compare control flow without
 * assigning an inferred library-function name.
 */
int func_00009C98(unsigned char *left, unsigned char *right, unsigned int count)
{
    if (count >= 4 && (((unsigned int)left | (unsigned int)right) & 3) == 0) {
        while (count >= 4) {
            if (*(unsigned int *)left != *(unsigned int *)right) {
                break;
            }
            left += 4;
            right += 4;
            count -= 4;
        }
    }

    while (count != 0) {
        int difference = (int)*left - (int)*right;
        if (difference != 0) {
            return difference;
        }
        left++;
        right++;
        count--;
    }
    return 0;
}
