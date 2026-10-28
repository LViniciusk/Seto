extern int func_0002B02C(void *path, const char *input, int length, int zero);
extern int func_0002B3F0(const char *path);
extern int func_0002B920(const char *path, void *buffer, int length, int mode);
extern int func_0006AE1C(const char *path, int mode, int flags);
extern int func_0006AE34(int fd, long long offset, int whence);
extern int func_0006AD94(int fd);
extern int func_0006AD7C(int fd, void *buffer, int length);

int func_0002ADF8(const char *input, int length, void *buffer, int mode, int read_length)
{
    char path[0x80];
    int fd;
    int result;

    func_0002B02C(path, input, length, 0);
    if (func_0002B3F0(path) != 0) {
        return func_0002B920(path, buffer, mode, read_length);
    }

    fd = func_0006AE1C(path, 1, 0);
    if (fd < 0) {
        return -1;
    }
    if (mode > 0) {
        result = func_0006AE34(fd, mode, 0);
        if (result < 0) {
            func_0006AD94(fd);
            return -2;
        }
    }
    result = func_0006AD7C(fd, buffer, read_length);
    func_0006AD94(fd);
    return result;
}
