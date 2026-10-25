/* EBOOT .text[0x38DB4,0x38EB0), libehsys export 0xB4471B5E.
 * The twelve inputs follow the register/stack locations recovered from the
 * body. The command words intentionally retain their hardware field tags.
 */
extern void func_00031308(unsigned int address, unsigned int *command, int words);

void func_00038DB4(
    unsigned int address,
    unsigned int selector,
    unsigned int field_eb,
    unsigned int field_eb_high,
    unsigned int field_ee_low,
    unsigned int field_ee_high,
    unsigned int field_b3,
    unsigned int field_b2_b5,
    unsigned int field_ec_low,
    unsigned int field_ec_high,
    unsigned int field_b5_low,
    unsigned int field_b4_b5_high)
{
    unsigned int command[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    command[0] = (field_b2_b5 & 0x00FFFFFFu) | 0xB2000000u;
    command[1] = (((field_b2_b5 >> 24) & 0xFFu) << 16) | 0xB3000000u | field_b3;
    command[2] = (field_eb_high << 10) | 0xEB000000u | field_eb;
    command[3] = (field_b4_b5_high & 0x00FFFFFFu) | 0xB4000000u;
    command[4] = (((field_b4_b5_high >> 24) & 0xFFu) << 16) | 0xB5000000u | field_b5_low;
    command[5] = (field_ec_high << 10) | 0xEC000000u | field_ec_low;
    command[6] = ((field_ee_high - 1u) * 0x400u) | 0xEE000000u;
    command[6] |= field_ee_low - 1u;
    command[7] = (selector == 3u) | 0xEA000000u;

    func_00031308(address, command, 8);
}
