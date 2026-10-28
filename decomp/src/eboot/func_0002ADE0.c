/* 2ADE0 adapts six incoming register arguments to the seven-register entry at
 * 2AEF0: insert zero in a3, then shift incoming a3/t0/t1 into t0/t1/t2.
 * Parameter names are positional only; no semantic identities are inferred.
 */

typedef unsigned int u32;

extern int func_0002AEF0(u32, u32, u32, u32, u32, u32, u32);

int func_0002ADE0(u32 arg0, u32 arg1, u32 arg2, u32 arg3, u32 arg4, u32 arg5)
{
    return func_0002AEF0(arg0, arg1, arg2, 0, arg3, arg4, arg5);
}