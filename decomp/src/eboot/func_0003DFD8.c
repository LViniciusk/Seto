unsigned short *func_0003DFD8(unsigned short *destination,
                             const unsigned short *source,
                             unsigned int count)
{
    unsigned short *cursor = destination;
    unsigned int index = 0;

    if (count != 0) {
        do {
            unsigned short value = *source;
            if (value == 0) {
                *cursor = 0;
                cursor++;
            } else {
                *cursor = value;
                source++;
                cursor++;
            }
            index++;
        } while (index < count);
    }
    return destination;
}