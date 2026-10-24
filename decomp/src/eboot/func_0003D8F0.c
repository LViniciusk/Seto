/* EBOOT [.text:0x3D8F0,0x3D8F8), exported by libehsys NID 0x31454993.
 * Ghidra confirmed one 8-byte function body with eight callers:
 * jr $ra; li $v0, 1 in the delay slot. The machine-level return value is
 * established; no semantic name is inferred.
 *
 * RESULT: MATCHED 2/2, 0 differences, relocations or limitations; 8 bytes.
 * Two MWCC 3.0.1 build 219 compilations with -O4,p -sdatathreshold 0 produced
 * object SHA-256 4ab73352e85ea72a45ca939bb8cc8806e862bb61b5aa4e34655b9398bca5b4bc.
 * The EBOOT's .comment reports 2.4.1.01; no historical compiler claim is made.
 */
int func_0003D8F0(void)
{
    return 1;
}
