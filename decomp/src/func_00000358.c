/*
 * libhtml_view.prx, .text 0x358-0x39c (0x44 bytes, 17 instructions).
 *
 * EVIDENCE: the verified listing is a straight-line sequence of six calls and
 * their delay-slot nops: local `func_00000244`, four imports, then local
 * `func_00000134`. The import table proves the external identities as sceNetApctl
 * NID 0xB3EDD0EC, sceNetResolver NID 0x6138194A, sceNetInet NID 0xA9ED66B9 and
 * sceNet NID 0x281928A9. There are no data relocations or conditional branches.
 * The address is a direct local-call target and Ghidra confirmed the exact body.
 *
 * REAL COMPILE + MATCH: Metrowerks 3.0.1 build 219 with
 * `-O4,p -sdatathreshold 0` reproduces 17/17 words, with zero differences,
 * relocation issues or limitations. The four imported calls resolve by
 * (library, NID); both local calls resolve to their module addresses. This is a
 * verified decompilation for the observed compiler/flags. The local prototypes
 * are based on observed call usage; source declarations are absent in the PRX.
 * Provenance hashes are recorded in docs/decomp-progress.md.
 */

#include "sce_stubs.h"

extern void func_00000244(void);
extern void func_00000134(void);

void func_00000358(void)
{
    func_00000244();
    func_00002F14();
    func_00002F34();
    func_00002F2C();
    func_00002F44();
    func_00000134();
}
