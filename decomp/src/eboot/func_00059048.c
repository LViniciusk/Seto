int func_00059048(short *values)
{
    int total;
    int value;
    int count;

    count = 0x100;
    total = 0;

    do {
        value = *values;

        if (value < 0) {
            value = -value;
        }
        count--;
        total += value;
        values += 2;
    } while (count > 0);
    return total >> 8;
}
