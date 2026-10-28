/* Internal EBOOT import wrapper at .text[0x2BC34,0x2BC3C): exact two-instruction
 * Ghidra boundary. Tail-calls the real IoFileMgrForUser import NID 0x810C4BC3
 * at stub 0x6AD94; this is not an export and has no data relocations.
 */
extern int func_0006AD94(void);

int func_0002BC34(void)
{
    return func_0006AD94();
}
