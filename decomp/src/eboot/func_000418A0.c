int func_000418A0(int **entries, int key)
{
    int index = 0;

    while (index < 16) {
        int *entry = *entries;
        if (entry != 0 && key == entry[2]) {
            return index;
        }
        entries++;
        index++;
    }
    return -1;
}