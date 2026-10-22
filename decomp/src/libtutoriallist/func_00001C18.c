/* Two-word tail-call thunk [0x1C18,0x1C20). The old linear inventory merged
 * this direct-jump entry with its independently callable body at 0x1C20.
 *
 * RESULT: MATCHED 2/2, complete 8-byte symbol, zero differences/issues/
 * limitations. The `j 0x1C20` relocation is resolved by local symbol identity.
 */
extern void func_00001C20(void);

void func_00001C18(void)
{
    func_00001C20();
}
