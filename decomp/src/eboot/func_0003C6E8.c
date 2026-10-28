/* Internal EBOOT helper at .text[0x3C6E8,0x3C70C): exact nine-instruction
 * Ghidra boundary, no data relocations. Returns byte one of the structure
 * returned by 0x3C65C masked with seven; not an export.
 */
extern unsigned char *func_0003C65C(void);

int func_0003C6E8(void)
{
    return func_0003C65C()[1] & 7;
}
