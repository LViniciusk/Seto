/* Initialize the count before a nonzero precheck, then scan with do-while. */
int func_0003DF58(unsigned short *arg0)
{
    int count = 0;

    if (*arg0 != 0) {
        do {
            arg0++;
            count++;
        } while (*arg0 != 0);
    }

    return count;
}
