typedef struct {
    unsigned int unknown0;
    unsigned int unknown4;
    unsigned int *values;
    unsigned int unknown12;
    int index;
    int remaining;
    int size;
} Sequence;

int func_0004ECF8(Sequence *sequence, unsigned int *out)
{
    int result = 0;

    *out = sequence->values[sequence->index];
    sequence->remaining--;
    sequence->index = (sequence->index + 1) % sequence->size;
    return result;
}