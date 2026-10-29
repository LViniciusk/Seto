int func_00055250(char *text)
{
    char line[128];
    int count = 0;
    char *output;
    char *base = line;

    while (1) {
        output = base;
        while (*text != '\n' && *text != '\0') {
            *output = *text;
            ++output;
            ++text;
        }
        if (output == base) {
            break;
        }
        *output = '\0';
        ++count;
        if (*text == '\0') {
            break;
        }
        ++text;
    }
    return count;
}
