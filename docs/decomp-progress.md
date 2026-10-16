# Decompilation progress

Status vocabulary, used strictly:

* **MATCHED** — an automated comparison proved the candidate identical to the
  original (every non-relocated word byte-equal, every relocated word equal in
  type and addend). Requires a real compile of the reconstruction.
* **NONMATCHING** — the comparison ran and found at least one proven divergence.
* **BLOCKED** — the comparison could not run because a required tool is missing.
  Never reported as success.

| Target | Method | Status |
| --- | --- | --- |
| `libhtml_view.prx` inventory (16 functions) | `seto functions` | **OK** |
| `libhtml_view.prx` layout (15 subsegments) | `seto split` + `seto check-layout` | **OK** |
| Comparator sanity check (`func_00000244` vs itself) | `seto match` | **MATCHED** |
| `func_00000244` reconstructed C vs original | `scripts/match_function.py` | **BLOCKED** (no `mwccpsp`) |

## What is actually proven

1. **Inventory and layout** are verified against the real bytes: `seto check-layout`
   confirms the layout covers the file exactly once, that every subsegment size
   and kind matches the ELF section table, and that the image delta is constant
   (`0x60`). These are reproducible facts, not claims.

2. **The comparator works.** Comparing `func_00000244` against the same bytes,
   with the module's own relocations on both sides, yields:

   ```
   function func_00000244 @ 0x244
     status:  MATCHED
     match:   100.00% (13/13 words)
     diffs:   0
   ```

   This proves the relocation-aware pipeline is self-consistent. It is **not** a
   claim that the reconstruction in `decomp/src/` matches — that still requires a
   compile.

## Matching semantics

Two instruction streams are compared word by word:

* a word covered by no relocation must be byte-identical;
* a word covered by a relocation must carry the same relocation *type* and the
  same in-place *addend* on both sides, and must agree outside the bits the
  relocation can change (`R_MIPS_26` → `0x03FFFFFF`, `R_MIPS_HI16`/`LO16` →
  `0x0000FFFF`, `R_MIPS_32` → all bits);
* when both sides expose a symbol name, the names must match; when only one side
  does, the difference is recorded as a **limitation**, never smoothed over;
* a relocation present on only one side is a hard **issue**, even if the words
  happen to be byte-identical.

The PSP PRX is stripped (`symbols: 0`), so every comparison against it currently
carries the limitation *"symbol available on only one side"* whenever a compiled
object supplies names. This is reported, not hidden. The match result is therefore
deliberately conservative: it never reports `MATCHED` when it cannot prove it.

## `func_00000244` (the worked example)

13 words, `0x34` bytes at `0x244`. Four `jal`s into `.sceStub.text` trampolines
(targets taken from the relocation table) surrounded by a standard 0x10-byte
frame. See `decomp/src/func_00000244.c` and `decomp/include/sce_stubs.h`.

Why it is a good first target:

* the call targets are **relocations**, so they are exact and cannot be guessed
  wrong — the failure mode "I picked the wrong function" is impossible;
* the body has no data flow, so the C structure is unambiguous;
* it exercises the relocation-aware comparator on all three MIPS relocation
  types used by the module.

The reconstruction is complete and readable but **unverified**: `mwccpsp` is not
available here, so no object file exists to compare. That is reported as
`BLOCKED`, not as a match.

To finish it once a licensed compiler is available:

```powershell
$env:SETO_MWCCPSP = "C:\tools\mwccpsp.exe"
py -3.12 scripts/match_function.py `
    --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx `
    --function 0x244 `
    --source decomp/src/func_00000244.c `
    --flag=-O4,p --flag=-sdatathreshold --flag=0
```

Exit `0` means `MATCHED`, `3` means `NONMATCHING` (with the differing words
printed), `4` means the compiler is still missing.

### Compiler-flag hypothesis

The exact Metrowerks flags are a *hypothesis* and must be settled by
experiment, not assumption:

* `-O4,p -sdatathreshold 0` — documented by `angelof-exe/ygo-tf-5-decomp`;
* `-O4,s -sdatathreshold 0` — suggested in the task text.

Both are recorded in `config/seto.toml` (`[match] flags` /
`alternative_flags`). A reconstruction is only `MATCHED` for whichever flag set
actually reproduces the bytes; the report should name the flag set that did.

## Blocked items and why

| Item | Blocker | Unblock by |
| --- | --- | --- |
| Any real `MATCHED` | `mwccpsp` is proprietary and absent | supply a licensed compiler, then run the command above |
| Running `splat` on `config/splat/*.yaml` | `splat` not installed | `pip install splat64` (or the reference `splat`) |
| Draft C for the other 15 functions | `m2c` not installed | install `m2c` |
| Allegrex-specific analysis (VFPU, `ghidra-allegrex`) | Ghidra not configured | set `GHIDRA_HOME` |
| MCP-driven analysis | REA refuses PSP PRX (`0xFFA0`) upstream; no MCP server configured | use Ghidra headless scripts instead |

## Next steps

1. Install `mwccpsp` and run `scripts/match_function.py` for `func_00000244`;
   record the real status and the flag set that produced it.
2. Validate `config/splat/libhtml_view.yaml` by actually running `splat` and
   diffing the regenerated `.text` against the original bytes.
3. Install `m2c` and iterate over the remaining functions in `.text`.
4. Recover real names for the `.sceStub.text` targets (via Ghidra/REA on a module
   whose imports resolve) and rename the declarations in `decomp/include/`.
