# Decompilation progress

Status vocabulary, used strictly:

* **MATCHED** — an automated comparison proved equivalence for the compared
  range. It is only a *verified decompilation* when the pipeline actually
  compiled the reconstruction in that run, compared the object it produced, and
  recorded the source/object hashes, the compiler and the flags. `seto match`
  alone can never establish that: it does not know where the candidate came from,
  so it always reports `evidence: binary-range` and must not be counted as a
  decompiled function.
* **NONMATCHING** — the comparison ran and found at least one proven divergence
  (including a relocation present on only one side).
* **INCONCLUSIVE** — the comparison ran but the evidence is insufficient to
  decide (a raw/non-ELF candidate, an unmodelled relocation type, a symbol
  exposed on only one side, a HI16/LO16 association that can only be inferred from
  relocation order, or several candidate functions and nothing selecting one).
* **BLOCKED** — the comparison could not run because a required tool is missing.
  Never reported as success.

| Target | Method | Status |
| --- | --- | --- |
| `libhtml_view.prx` inventory (16 functions) | `seto functions` | **OK** |
| `libhtml_view.prx` layout (15 subsegments) | `seto split` + `seto check-layout` | **OK** |
| Comparator sanity check (`func_00000244` vs itself) | `seto match` | **MATCHED** (`evidence: binary-range`, *not* a decompiled function) |
| `func_00000244` reconstructed C vs original | `scripts/match_function.py` | **BLOCKED** (no `mwccpsp`) |

## What is actually proven

1. **Inventory and layout** are verified against the real bytes: `seto check-layout`
   confirms the layout tiles the file exactly, with no gap and no overlap, that
   every subsegment size and kind matches the ELF section table, and that the
   image delta is constant (`0x60`). `SHT_NOBITS` sections (`.bss`) own no file
   bytes and are reported explicitly. These are reproducible facts, not claims.

2. **The comparator works.** Comparing `func_00000244` against the same bytes,
   with the module's own relocations on both sides, yields:

   ```
   function func_00000244 @ 0x244
     status:  MATCHED
     match:   100.00% (13/13 words)
     diffs:   0
     evidence: binary-range
   ```

   This proves the relocation-aware pipeline is self-consistent. It is **not** a
   claim that the reconstruction in `decomp/src/` matches — that still requires a
   compile, and it does not increase the count of decompiled functions.

## Matching semantics

Four outcomes are possible: `MATCHED`, `NONMATCHING`, `INCONCLUSIVE`, `BLOCKED`.
Two instruction streams are compared word by word:

* a word covered by no relocation must be byte-identical;
* a word covered by a relocation must carry the same relocation *type* and the
  same in-place *addend* on both sides, and must agree outside the bits the
  relocation can change (`R_MIPS_26` → `0x03FFFFFF`, `R_MIPS_HI16`/`LO16` →
  `0x0000FFFF`, `R_MIPS_32` → all bits);
* `R_MIPS_HI16`/`R_MIPS_LO16` are associated from the **relocation table**, never
  from adjacency: relocations are consumed in table order, a LO16 may sit far from
  its HI16 and may resolve several pending HI16 that name the same symbol, a HI16
  with no LO16 stays unresolved, and a LO16 that names a different symbol does not
  close it. The pair is compared as the combined 32-bit value it encodes, and its
  symbols are checked on **both** halves. It counts as matching only once every
  check has passed, so `percent` never reports a pair with a proven divergence;
* when both sides expose a symbol name, the names must match; when only one side
  does, the result is downgraded to `INCONCLUSIVE` — never silently accepted;
* a HI16/LO16 association that can only be inferred from relocation order (the
  stripped PRX exposes no symbol identity) is a limitation, not a proof: it
  downgrades the result to `INCONCLUSIVE` instead of fabricating a pair;
* a relocation present on only one side is a hard **issue** (`NONMATCHING`),
  even if the words happen to be byte-identical;
* an *unmodelled* relocation type (no known mask) makes the result
  `INCONCLUSIVE`, even when the bytes coincide: byte equality is not proof;
* duplicated relocations on the same word are rejected, not silently
  overwritten; a relocation that is misaligned inside the range or has no resolved
  section becomes a limitation instead of being dropped silently; relocations
  outside the compared range belong to another function and are ignored;
* `MATCHED` requires **zero** differences, issues and limitations. Any limitation
  downgrades it to `INCONCLUSIVE`.

Candidate location is proved, not guessed: `--candidate-symbol` is only accepted
when the symbol's `shndx` is exactly the requested section (`ET_REL` values are
section-relative; linked values are rebased by the section address), undefined,
absolute and special symbols are rejected, and an ambiguous symbol (same name and
section, different offsets) is `INCONCLUSIVE`. A symbol requested explicitly but
not found is `INCONCLUSIVE` unless `--candidate-symbol-fallback` asks for
automatic detection — and even then the ambiguity is recorded.

The PSP PRX is stripped (`symbols: 0`), so comparisons against it carry two
honest limitations whenever they involve data addresses: *"symbol available on
only one side"* and *"HI16/LO16 association relies on relocation order"*. Both are
reported, and the verdict is `INCONCLUSIVE` rather than a false `MATCHED`. This is
the intended conservative behaviour: the original file simply does not contain the
information needed to prove the association.

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
    --source decomp/src/func_00000244.c
```

The flags come from `[match] flags` in `config/seto.toml` unless `--flag`
overrides them. Exit `0` means `MATCHED`, `3` means `NONMATCHING` (the differing
words are printed), `4` means the compiler is still missing and `5` means
`INCONCLUSIVE`.

The script — not `seto match` — is what turns a `MATCHED` result into a *verified
decompilation*: it compiles, deletes any previous object, hashes the source and the
object it produced, compares exactly that object, checks that it did not change
during the comparison, and writes a JSON record with the status, compiler, flags,
hashes and function. A simulated compilation can therefore never be reported as a
real match.

### Compiler-flag hypothesis

The exact Metrowerks flags are a *hypothesis* and must be settled by
experiment, not assumption:

* `-O4,p -sdatathreshold 0` — documented by `angelof-exe/ygo-tf-5-decomp`;
* `-O4,s -sdatathreshold 0` — suggested in the task text.

Both are recorded in `config/seto.toml` (`[match] flags` /
`alternative_flags`). A reconstruction is only `MATCHED` for whichever flag set
actually reproduces the bytes; the report should name the flag set that did.
Neither is recorded as proven.

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
