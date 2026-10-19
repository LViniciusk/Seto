/*
 * libtutoriallist.prx, .text [0x1E94, 0x1F10), 31 instructions.
 *
 * Ghidra 12.1.3 found an exact one-range function body. The listing has no
 * relocation-backed calls or static data references. The loop is a binary
 * search over 16-bit values with a byte stride; the argument names and semantic
 * role remain provisional. Its unsigned key/value comparison and signed
 * divide-by-two rounding are kept explicit from the observed instructions.
 */

int func_00001E94(
    unsigned short key,
    const unsigned short *values,
    int count,
    int stride_bytes
)
{
    int stride_halfwords;
    int low;
    int sum;
    int middle;
    unsigned short value;

    stride_halfwords = stride_bytes / 2;
    count -= 1;
    if (count < 0)
        goto not_found;
    low = 0;

search:
    sum = low + count;
    middle = sum / 2;
    value = values[middle * stride_halfwords];
    if (key != value) {
        if (value < key)
            low = middle + 1;
        else
            count = middle - 1;
        if (count >= low)
            goto search;
        goto not_found;
    }
    return middle;

not_found:
    return -1;
}
