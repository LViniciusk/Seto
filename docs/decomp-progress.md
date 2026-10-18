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
  relocation order, a call whose destination cannot be identified, or several
  candidate functions and nothing selecting one).
* **BLOCKED** — the comparison could not run because a required tool is missing.
  Never reported as success.

| Target | Method | Status |
| --- | --- | --- |
| `libhtml_view.prx` inventory (16 functions) | `seto functions` | **OK** |
| `libhtml_view.prx` layout (15 subsegments) | `seto split` + `seto check-layout` | **OK** |
| `config/splat/libhtml_view.yaml` consumed by `splat64[mips]` 0.50.1 | `seto split --run-splat` | **OK** (0 issues, `.text` 509 words + `.sceStub.text` 2536 words verified against the original bytes) |
| PSP import identity (8 libraries, 1268 trampolines) | `seto imports` | **OK** (0 limitations; every trampoline cross-checked against its bytes) |
| Call classification of `.text` (72 `R_MIPS_26`) | `seto imports` | **OK** (50 imported, 22 local, 0 unresolved) |
| The four `jal`s of `func_00000244` | `seto imports --function 0x244` | **PROVEN** — `(library, NID)` recovered for each |
| Comparator sanity check (`func_00000244` vs itself) | `seto match` | **MATCHED** (`evidence: binary-range`, *not* a decompiled function) |
| `mwccpsp 3.0.1 build 219` + `wibo 1.2.0` | WSL2 functional smoke | **READY** (version probe and ELF32 MIPS compile both run through wibo) |
| `func_00000244` reconstructed C vs original | real compile + `scripts/match_function.py` | **MATCHED**, 13/13 words, verified decompilation |
| `func_000004B8` reconstructed C vs original | real compile + `scripts/match_function.py` | **INCONCLUSIVE**, 18/20; data-object identity unproven |
| `func_000006E4` reconstructed C vs original | real compile + `scripts/match_function.py` | **INCONCLUSIVE**, 2/8; data-object identities unproven |
| `func_00000034` reconstruction | real compile + `scripts/match_function.py` | **MATCHED**, 20/20 words |
| `func_00000134` reconstruction | real compile + `scripts/match_function.py` | **MATCHED**, 17/17 words |
| `func_00000358` reconstruction | real compile + `scripts/match_function.py` | **MATCHED**, 17/17 words |
| `func_0000008C` reconstruction | real compile + `scripts/match_function.py` | **MATCHED**, 42/42 words |
| `func_00000178` reconstruction | real compile + `scripts/match_function.py` | **MATCHED**, 51/51 words |
| `func_00000278` reconstruction | real compile + `scripts/match_function.py` | **MATCHED**, 56/56 words |
| `func_0000039C` reconstruction | real compile + `scripts/match_function.py` | **INCONCLUSIVE**, 28/30; jump-table object identity unproven |
| `func_00000414` reconstruction | real compile + `scripts/match_function.py` | **INCONCLUSIVE**, 31/41; string-object identities unproven |
| `func_00000000` reconstruction | real compile + `scripts/match_function.py` | **INCONCLUSIVE**, 7/13; code/data address identities unproven |
| `func_00000634` reconstruction | real compile + `scripts/match_function.py` | **INCONCLUSIVE**, 42/44; buffer-object identity unproven |
| `func_00000508` reconstruction | real compile + `scripts/match_function.py` | **INCONCLUSIVE**, 63/75; data-object identities unproven, zero instruction differences |
| `func_00000704` reconstruction | real compile + `scripts/match_function.py` | **INCONCLUSIVE**, 40/60; state/pointer object identities unproven |
| `func_00000084` classification | `seto functions` + real Ghidra + a compiled probe | **no C reconstruction**: 8 bytes, `jr $ra; nop`; not modelled as a function, no C source |
| Global data-reference aggregation | `seto.datarefs.build_global_usage` / `scripts/global_usage.py` | **OK** (15 demonstrated locations, 6 order-only references kept visible) |
| Open-tool bootstrap | `scripts/bootstrap_toolchain.ps1` / `.sh` | **VERIFIED** (pinned installs, hashes, safe ZIP extraction, isolated Python/npm environments) |
| `splat`, `m2c`, MIPS `objdump` | synthetic functional smoke tests | **READY** (splat 0.50.1, m2c pinned commit, LLVM 21.1.8) |
| Ghidra native MIPS32 / Allegrex language | headless forced-language imports | **READY** (`MIPS:LE:32:default`, `Allegrex:LE:32:default`) |
| Ghidra automatic selection of the synthetic ELF32 ET_REL | `seto toolchain --smoke --tool ghidra` | **INCOMPATIBLE** (Ghidra selected `MIPS:LE:64:64-32R6addr`; this is not accepted as ELF32 proof) |
| Ghidra automatic selection of the real PSP PRX | `tests/integration/test_toolchain_real.py` | **PROVEN** (`libhtml_view.prx` selected `Allegrex:LE:32:default`) |
| REA MCP transport | initialize + `tools/list` handshake | **READY** (207 tools); native-provider analysis and REA PRX support remain unproven |
| `func_000006E4` reconstruction | m2c + verified splat + Ghidra + real compile | **INCONCLUSIVE** (global types provisional; data identities unresolved) |
| `func_000004B8` reconstruction | m2c + verified splat + Ghidra + real compile | **INCONCLUSIVE** (m2c missed an argument; C follows instructions; data identity unresolved) |

## What is actually proven

1. **Inventory and layout** are verified against the real bytes: `seto check-layout`
   confirms the layout tiles the file exactly, with no gap and no overlap, that
   every subsegment size and kind matches the ELF section table, and that the
   image delta is constant (`0x60`). `SHT_NOBITS` sections (`.bss`) own no file
   bytes and are reported explicitly. These are reproducible facts, not claims.

2. **The generated splat configuration is really consumed by splat.** The config
   `config/splat/libhtml_view.yaml` is written by `seto split` (not hand-edited)
   and `seto split --run-splat` runs `splat64[mips]` on it, then reads the
   listings splat produced and checks every word back against the original file:

   ```powershell
   py -3.12 -m seto split `
       --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx `
       --out build/split --run-splat
   ```

   Result: exit `0`, `Split 21 KB (100.00%)`, and the listing verification reports
   `0 issues` for `.text` (509 words) and `.sceStub.text` (2536 words) — i.e. the
   file offset, the address and the bytes of every listed word agree with the
   original. A listing that does not agree, or that fails to cover the segment, is
   an **error** (`EXIT_MISMATCH`), never a success. The generated `assets/`,
   `include/`, `asm/`, `undefined_*_auto.txt` and `.splache` are git-ignored:
   they are reproducible build output, not sources.

3. **The PSP import identities are recovered from the module itself.** The
   module declares its imports in `.lib.stub` (one `SceLibraryStubTable` per
   library), pointing at `.rodata.sceResident` (library name), `.rodata.sceNid`
   (one NID per imported function) and `.sceStub.text` (one 8-byte `jr $ra; nop`
   trampoline per imported function). `seto imports` walks that table, requires
   every pointer field to carry the `R_MIPS_32` relocation a loader would use,
   requires every pointer and count to lie inside the section it names, and
   checks the bytes at every trampoline address really are `jr $ra`. Result for
   `libhtml_view.prx`: **8 libraries, 1268 imported functions, 0 limitations**.

   The identity of an imported function is the **(library, NID)** pair. Two
   identical NIDs in different libraries are *not* the same function, and the
   comparison refuses to treat them as equivalent; the provisional
   `func_<address>` name only *names* an address and is never itself the proof.

   ```powershell
   py -3.12 -m seto imports `
       --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx `
       --out decomp/imports/libhtml_view.json
   ```

   Every `R_MIPS_26` in `.text` is classified: 50 reach an import trampoline, 22
   reach another function of the module, 0 are unresolved. An unresolved call is
   reported with the exact missing link and makes the command exit `5`.

4. **The comparator works.** Comparing `func_00000244` against the same bytes,
   with the module's own relocations on both sides, yields:

   ```
   function func_00000244 @ 0x244
     status:  MATCHED
     match:   100.00% (13/13 words)
     diffs:   0
     evidence: binary-range
   ```

    This proves the relocation-aware pipeline is self-consistent, but is not by
    itself a decompilation result. The later real compile-and-match is recorded
    separately below.

5. **The relocation format is understood, not assumed.** Every relocation table in
   `libhtml_view.prx` is the fixed-width PSP form (`SHT_PSPREL`, `0x700000A0`):
   181 entries, four known types, no unknown type, no compressed `SHT_PSPREL2`
   stream and no `PT_PSPREL*` payload segment. `r_info` packs type/segment/relative
   fields (never a symbol index) and `r_offset` is segment-relative, both
   reproduced from PPSSPP's loader and covered by synthetic fixtures. See
   [SETO-DECOMP-007](#seto-decomp-007--psp-relocation-semantics-and-runtime-memory-mapping).

6. **Real compilation and matching were run.** With licensed Metrowerks 3.0.1
   build 219 and `-O4,p -sdatathreshold 0`, `func_00000244` is `MATCHED` (13/13,
   zero differences/limitations); `func_000004B8` is `INCONCLUSIVE` (18/20,
   zero differences); and `func_000006E4` is `INCONCLUSIVE` (2/8, zero
   differences). The latter two have proved register-flow pairings, but no
   independent candidate-symbol-to-original-object link. Full hashes and
   reproduction commands are in [the real compile baseline](#real-compile-and-match-baseline).

7. **SETO-DECOMP-008 adds three more proven functions.** The 13 remaining `.text`
   functions were triaged from call/data-relocation reports and verified listings;
   three no-data candidates were compiled and each returned `MATCHED` with zero
   differences and limitations. There are now six real compilations, four
   `MATCHED`, two `INCONCLUSIVE`, zero `NONMATCHING`; the detailed selection and
   per-function hashes are in the SETO-DECOMP-008 section below.

8. **SETO-DECOMP-009 adds three more proven functions with real control flow.**
   The three intermediate-control-flow candidates `func_0000008C`,
   `func_00000178` and `func_00000278` were revalidated (boundaries, calls and
   relocations) and reconstructed with explicit error paths; each compiled and
   returned `MATCHED` with zero differences and zero limitations. There are now
   nine real compilations, seven `MATCHED`, two `INCONCLUSIVE` and zero
   `NONMATCHING`; the selection and per-function hashes are in the SETO-DECOMP-009
   section below, and a versioned summary of the seven remaining functions follows
   there too.

## SETO-DECOMP-005 — first function analysis and two new reconstructions

The real PRX was split with `splat64[mips]` and the emitted `.text` listing was
verified against all original words. Ghidra 12.1.3 with `ghidra-allegrex` v21.4
automatically selected `PSP Executable (ELF)` and
`Allegrex:LE:32:default`. `scripts/ghidra/SetoAnalyzeFunction.java` was run as a
Ghidra post-script for each selected range. It checks the requested entry point,
body minimum/maximum, addressable-unit size, byte count and address-range count
before emitting `SETO_BOUNDARY_STATUS=EXACT`; decompilation is marked `OK` only
when that exact function decompiles successfully. The integration test checks
those markers per function, as well as the real instruction listing. m2c's
output was reviewed against the listing rather than accepted blindly.

| Function | Interval / size | C source | Evidence and status | Next action |
| --- | --- | --- | --- | --- |
| `func_00000244` | `0x244–0x278`, `0x34` bytes, 13 instructions | `decomp/src/func_00000244.c` (existing C retained) | Ghidra, splat, `seto disasm`, m2c and the real compile-match agree. Four import identities are proven. **MATCHED**, 13/13. | Keep the verified source/object provenance; historical compiler version differs. |
| `func_000006E4` | `0x6E4–0x704`, `0x20` bytes, 8 instructions | `decomp/src/func_000006E4.c` | Three distinct module-relative addresses; register flow proves the pairs, while variable identities/types remain provisional. **INCONCLUSIVE**, 2/8, 0 differences. | Find independent object identity for the destinations. |
| `func_000004B8` | `0x4B8–0x508`, `0x50` bytes, 20 instructions | `decomp/src/func_000004B8.c` | Ghidra/assembly show the original argument and `/PSP/SAVEDATA/` passed in the delay slot; register flow proves the pair. **INCONCLUSIVE**, 18/20, 0 differences; candidate symbol identity is unlinked. | Confirm helper prototypes and obtain independent data-symbol linkage evidence. |

For `func_00000244`, the body has no explicit setup of `$a0`–`$a3`, does not read
`$v0` after any of its four calls, and m2c/Ghidra both render a no-argument,
no-return C body. Ghidra reports compiler-spec ID `default` for
`Allegrex:LE:32:default`; the actual PRX `.comment` identifies the MW MIPS
compiler. The real 3.0.1 build 219 compile-match now reproduces these bytes and
proves the four call targets for this function. It does not establish that 3.0.1
is the historical compiler (the PRX says 2.4.1.01) or prove all four imported
functions' SDK prototypes: the stripped import table carries only `(library,
NID)`.

The 8-byte candidate at `0x84` disassembles as `jr $ra; nop`, but Ghidra's
automatic analysis did not define a function there. It was excluded rather than
counted as a reconstruction without independent boundary evidence.

Reproduce the original listing and preliminary C with:

```powershell
py -3.12 -m seto split `
  --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx `
  --out build/seto005-split --run-splat

# Set this to the m2c executable reported by `seto toolchain`.
& $env:SETO_M2C -t mips-ido-c -f func_00000244 asm/libhtml_view/text.s
& $env:SETO_M2C -t mips-ido-c -f func_000006E4 asm/libhtml_view/text.s
& $env:SETO_M2C -t mips-ido-c -f func_000004B8 asm/libhtml_view/text.s

py -3.12 -m seto disasm `
  --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx `
  --function 0x244
```

The Ghidra integration test exercises the post-script on all three ranges and
checks each range independently: entry, body min/max, byte count, addressable
unit size, exact-boundary status, completed decompilation, and per-range
instruction count. A discontinuous/out-of-range body reports `MISMATCH` and is
not decompiled as if it were exact. The script prints an Allegrex
listing/decompilation for review; it does not change the input program.
Re-run the media-backed inspection with
`py -3.12 -m pytest tests/integration/test_toolchain_real.py -q -m integration`.

### Progress metrics at SETO-DECOMP-005

These numbers describe the state before a compiler was supplied; they are a
historical checkpoint, not the current status.

| Metric | Count |
| --- | ---: |
| Functions discovered in `.text` | 16 |
| C reconstructions proposed (including the existing `func_00000244`) | 3 |
| Compiled with `mwccpsp` | 0 |
| Proven `MATCHED` | 0 |
| Compilation-blocked reconstructions | 3 |

At that historical checkpoint `UNVERIFIED` meant a C reconstruction existed but
no real compile/match had been performed. The earlier self-comparison of original
bytes did not count.

## SETO-DECOMP-006 — symbol recovery, data relocations and matching readiness

This round recovers the *canonical identity* of the module's global/data
references, validates their destinations, and lets the comparator tell
semantically equivalent data references apart from wrong or inconclusive ones.

### The three reconstructions, reference by reference

`seto datarefs` replays the module's own relocation table and reports every data
reference of the three reconstructions. `R_MIPS_26` (calls) is left to the import
resolver; only HI16/LO16 pairs and `R_MIPS_32` are recovered here. Pairing and
numeric location are distinct confidence axes. A standalone report marks
cross-artifact object identity `NOT_APPLICABLE`; compile matching must prove that
third axis independently.

| Function | Site | Relocations | Combined addend | Destination | Location | Pairing | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `func_00000244` | — | — | — | — | — | — | no data reference (calls only) |
| `func_000004B8` | `0x4D0` | `R_MIPS_HI16@0x4C4` + `R_MIPS_LO16@0x4D0` | `0x00004830` | `.data + 0xC8` | PROVEN | PROVEN | PROVEN locally; cross-artifact identity unresolved |
| `func_000006E4` | `0x6EC` | `R_MIPS_HI16@0x6E8` + `R_MIPS_LO16@0x6EC` | `0x00604860` | load segment `0 + 0x604860` (zero-filled) | INFERRED | PROVEN | INFERRED |
| `func_000006E4` | `0x6F4` | `R_MIPS_HI16@0x6F0` + `R_MIPS_LO16@0x6F4` | `0x00004860` | load segment `0 + 0x4860` (zero-filled) | INFERRED | PROVEN | INFERRED |
| `func_000006E4` | `0x700` | `R_MIPS_HI16@0x6F8` + `R_MIPS_LO16@0x700` | `0x00604B9C` | load segment `0 + 0x604B9C` (zero-filled) | INFERRED | PROVEN | INFERRED |

`Location` is `PROVEN` when the combined addend lands in exactly one allocated ELF
section, `INFERRED` when no named section covers it but exactly one `PT_LOAD` span
does (so only its offset in that segment, and whether it is past `p_filesz`, can be
stated), and `UNKNOWN` when neither. `Pairing` is `PROVEN` when shared symbol
identity or a bounded LUI-to-LO16 register-flow check establishes the association;
otherwise relocation order is an `INFERRED` fallback. Register flow does not
prove cross-artifact object identity. An unpaired `R_MIPS_LO16` is reported too
(never dropped), as an incomplete reference with its address, type, addend and
reason.

A location inside `.data` and a register-proven pair make the reference locally
resolvable. They do **not** prove that a separately compiled candidate symbol
names that original object; that is a distinct cross-artifact identity axis.

### The `/PSP/SAVEDATA/` string is proven

The pair at `0x4C4`/`0x4D0` combines to `0x4830`. `.data` is at address `0x4768`
with size `0xE8`, so `0x4830` is `.data + 0xC8` (file offset `0x4890`), and the
fourteen bytes at that file offset really are `/PSP/SAVEDATA/`. The *location* and
the HI16/LO16 pairing are proven (register flow includes the `jal` delay slot).
The compiled object's undefined `D_00004830` symbol is still not linked to this
original object, so its actual compile comparison remains `INCONCLUSIVE`.

### The `0x600000` discrepancy is documented, not assumed away

`func_000006E4` stores `1` at `0x604860`, forms `0x4860`, and stores that at
`0x604B9C`. The two store targets and the value differ by exactly `0x600000`
(= the HI16 addend `0x60` shifted left 16 bits), which is **not** evidence of a
load base — every relocation receives the same runtime base, and `.data` ends at
`0x4850`.
The ELF `.bss` section is empty (size `0`), so `0x604860`, `0x604B9C` and `0x4860`
all fall in the zero-filled tail of the single `PT_LOAD` segment and in no named
section. The report keeps them distinct and marks all three `INFERRED`: it never
assumes `0x604860` and `0x4860` name the same object, and never promotes an
address-like name or a plausible-looking offset to an identity.

SETO-DECOMP-007 later shows that `0x600000` is not a transformation at all — see
[The `0x600000` difference is the high half of a different address](#the-0x600000-difference-is-the-high-half-of-a-different-address).

### How the comparator uses data identity

`compare`/`compare_region` accept optional `original_data_resolver` and
`candidate_data_resolver` callables. A resolver answers with a
`seto.datarefs.DataIdentity` — a `DataTarget` **plus the artifact it belongs to** —
because a location is not an identity: `(.data, 0x20)` in two independent ELF files
does not name the same object. They are consulted only for `R_MIPS_32` and for the
HI16/LO16 pair (with the *combined* pair addend, never one half):

* both sides answer in the **same artifact** and resolve to the same
  `(section, offset)` → a potential equivalence, recorded in `resolved_data`;
* both sides answer in the same artifact, to different targets → a real
  `NONMATCHING` difference;
* the two answers come from **different artifacts** → `INCONCLUSIVE`, never a
  match, however equal the section name and offset look;
* either side cannot be resolved → `INCONCLUSIVE` (equal numeric addends never
  prove identity);
* a destination difference on an order-only HI16/LO16 association stays
  `INCONCLUSIVE`, because the wrong LO16 could be closing the HI16; when bounded
  register flow proves the pair, a proven destination difference is
  `NONMATCHING`.

`seto match` builds the original resolver from the module itself. `--data-map`
can record a candidate-symbol-to-location hypothesis, but the JSON assertion or
evidence string is not independent validation and never resolves identity by
itself. Without an independently validated link, candidate data references stay
unresolved, so `func_000004B8` and `func_000006E4` remain `INCONCLUSIVE`, never
falsely `MATCHED`.

`MATCHED` still requires zero differences, zero errors and zero limitations, so a
byte-equal candidate whose references cannot be identified is never promoted. The
PRX is stripped (no symbol table), but the local register-flow analyzer proves
the HI16/LO16 associations in `func_000006E4`. A real comparison remains
`INCONCLUSIVE` because pairing evidence does not identify the original variables.

`scripts/match_function.py` forwards an optional `--data-map` and records it in the
provenance block of its JSON record, so a verified decompilation can name the
evidence that tied its data references to the module.

### Reproducing the report

```powershell
py -3.12 -m seto datarefs `
  --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx `
  --function 0x244 --function 0x4b8 --function 0x6e4 `
  --out build/datarefs.json
```

The JSON is deterministic (sorted keys, relocation-table order) and holds only
metadata: addresses, relocation types, addends and destinations. No byte of the
original module is copied. `build/` is git-ignored, so the report is regenerated
rather than versioned. The command exits `5` (inconclusive) when any reference is
not `PROVEN`, which is the case here.

### Progress metrics at the SETO-DECOMP-007 baseline

This snapshot is after the 007 register-flow work and the three original real
compiles, before SETO-DECOMP-008 added three functions.

| Metric | Count |
| --- | ---: |
| Data references recovered (three reconstructions) | 4 |
| Destinations proven (exactly one allocated section) | 1 |
| Destinations inferred (load segment only) | 3 |
| Destinations unknown | 0 |
| HI16/LO16 references with a proven pairing | 4 |
| References whose numeric destination is a named section | 1 |
| References whose destination is only in a load segment | 3 |
| Cross-artifact data identities proven for compiled candidates | 0 |
| Real compilations | 3 |
| Proven `MATCHED` | 1 |
| `INCONCLUSIVE` | 2 |
| `NONMATCHING` | 0 |

### Real compile-and-match baseline

The three current C files were compiled in WSL2 Ubuntu 3.12.3 with licensed
Metrowerks **3.0.1 build 219**, `wibo 1.2.0`, and:

```text
-O4,p -sdatathreshold 0
```

Persistent config: ignored `config/wsl/seto.toml` (template:
`config/wsl/seto.example.toml`). Run from the repository root in WSL2; the script
selects the configured wibo automatically:

```bash
PYTHONPATH=src python3 -m seto --config config/wsl/seto.toml \
  toolchain --smoke --tool mwccpsp --json

PYTHONPATH=src python3 scripts/match_function.py --config config/wsl/seto.toml \
  --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx \
  --function 0x244 --source decomp/src/func_00000244.c \
  --out build/match/func_00000244 --json
```

Repeat with `--function 0x4b8 --source decomp/src/func_000004B8.c` and
`--function 0x6e4 --source decomp/src/func_000006E4.c`. The local configuration,
compiler, original PRX, reports and ELF objects are not versioned; reports and
objects live under git-ignored `build/`.

| Function | Compile | Compared words | Differences | Status | Object SHA-256 | Source SHA-256 |
| --- | --- | ---: | ---: | --- | --- | --- |
| `func_00000244` | OK | 13/13 | 0 | **MATCHED**, verified decompilation | `5e7f5473890f18215341253125daafada03c43271e8760cc2d3c3744beff88b2` | `c463c8c4eb9aa16d7dc83057b668b97173c7fd989edfb9e5c44e65eccd91f7eb` |
| `func_000004B8` | OK | 18/20 | 0 | **INCONCLUSIVE** | `17cce92e8424bfded12b9ee4a26363ec7ac19c36f8bf795af02d05a22904425f` | `acc26a43f711f5cb2db2a1999851ff001afe1344302c97212c897c6e14bcd87c` |
| `func_000006E4` | OK | 2/8 | 0 | **INCONCLUSIVE** | `bf50e17cb96392886ad483b6383a05cb3d9b93639974cb00322f26b1b228fee3` | `4ddbde75b52c6c2359497b43bfebd93290139b3a844e35f86fbfecf11d8cc37a` |

For `func_00000244`, all four calls were resolved by `(library, NID)`:
`sceHttp/0x76D1363B`, `sceHttp/0xF9D8EB63`, `sceHttp/0xD1C8945E`, and
`sceSsl/0x191CDEFF`; there are no limitations. For `func_000004B8`, register
flow proves the HI16/LO16 pair (including the call delay slot), but the compiled
object's `D_00004830` symbol is `SHN_UNDEF` (index 0); both relocations name
candidate symbol-table index 3, but the object has no definition or link metadata
connecting it to original `.data+0xC8`. A JSON map cannot supply that missing
evidence. For `func_000006E4`, all three pairs are register-proven but the
three data-object identities are unresolved. The uncounted words are therefore
**not** proven divergences: both functions have zero byte differences and zero
relocation issues, but cannot be promoted to `MATCHED`.

The compiler prints `Environment variable 'MWCIncludes' not found` while compiling;
the exit code is zero and the expected ELF32 MIPS objects are produced. No dummy
environment variable is set to suppress the warning. The original PRX identifies
`MW MIPS C Compiler (2.4.1.01)`: these are real equivalences for the supplied 3.0.1
build and flags, not a claim that this is the historical compiler.

## SETO-DECOMP-007 — PSP relocation semantics and runtime memory mapping

This round reads the module's relocations *as the PSP loader does*, so the
addresses of the three reconstructions are explained instead of assumed. The
parser is unchanged in what it means by "a byte": `seto.elf` keeps the raw fields
of every entry, and `seto.psp_reloc` gives the PSP relocation section its own
meaning. No system is emulated and nothing is written into an image.

### What the module's relocation tables actually are

`seto datarefs` reports the inventory next to the references, and
`seto.psp_reloc.psp_inventory` produces it. For `libhtml_view.prx`:

| Fact | Value |
| --- | --- |
| Relocation section type | `SHT_PSPREL` (`0x700000A0`) for all 8 tables |
| Entry layout | fixed 8-byte `Elf32_Rel` (`r_offset`, `r_info`) |
| Entries | 181 (132 in `.rel.text`, 49 in the six data tables) |
| Types | `R_MIPS_26` x72, `R_MIPS_32` x49, `R_MIPS_HI16` x30, `R_MIPS_LO16` x30 |
| Unknown types | none |
| Known but unsupported relocation types | none |
| Compressed `SHT_PSPREL2` tables | none |
| `PT_PSPREL1`/`PT_PSPREL2` payload segments | none |

`r_info` is **not** a symbol index in this format. It packs three fields, which
PPSSPP's `ElfReader::LoadRelocations` masks exactly this way; `seto.elf` and
`seto.psp_reloc.decode_info` share one decoder:

```
bits  0..3    relocation type (R_MIPS_*)
bits  8..15   the segment the relocated word lives in
bits 16..23   the segment whose load base is added ("relative" segment)
```

Every entry in this module has both segment fields `0`, so nothing is rebased
locally. `r_offset` is an offset *inside* the segment named by bits 8..15, so the
byte the loader patches is `segments[segment].vaddr + r_offset`; the standard
`SHT_REL` layout, where the same bits are a symbol index and `r_offset` is an
absolute address, would misread both fields. `seto.elf` therefore records
`format`, the raw `info`, `segment_index` and `relative_index` on every
`Relocation`, and `seto.psp_reloc` decodes them. A relocation naming a segment the
file cannot back, or a non-`PT_LOAD` one, is reported as an observation instead of
being patched at an invented address.

The PSP type is the **low nibble**, not the low byte: `r_info = 0x112` decodes to
`R_MIPS_32`, segment `1`, relative segment `0`, with the other set bit reported
as reserved. HI16 arithmetic sign-extends the LO16, wraps the combined value to
32 bits, then rounds before extracting the high half:
`((combined + 0x8000) >> 16) & 0xffff`. This preserves LUI/opcode/register bits and
is tested at signed-low boundaries, with nonzero bases and wraparound.

If the application segment index is absent, non-`PT_LOAD`, out of its memory
range, or would overflow 32 bits, the raw `r_offset` remains diagnostic data only:
`application_valid` is false, no target/file offset or addend is resolved, and the
entry is listed as incomplete. It cannot become a location merely because that
raw number happens to land inside `.text`.

### The `0x600000` difference is the high half of a different address

`func_000006E4` has three HI16/LO16 pairs. Their addends are:

| Pair | HI16 | LO16 | Combined |
| --- | ---: | ---: | ---: |
| store target | `0x0060` | `0x4860` | `0x00604860` |
| value formed | `0x0000` | `0x4860` | `0x00004860` |
| store target | `0x0060` | `0x4b9c` | `0x00604b9c` |

Four hypotheses were tested against the format:

* **A — a relocation field was misread.** *Rejected.* `r_info`'s segment and
  relative fields are `0` for all 181 entries, so no segment base was introduced
  or omitted; the HI16/LO16 decode matches the loader's arithmetic.
* **B — the loaded image layout explains it.** *Rejected as an explanation.* The
  single `PT_LOAD` has `p_vaddr 0`, `p_filesz 0x4850`, `p_memsz 0x604c10`, and the
  `.bss` header is size `0`, so `0x4850`-`0x604c10` is a zero-filled tail. All
  three addresses are in it, at *distinct* segment offsets (`0x4860`, `0x604860`
  and `0x604b9c`, the last two being `0x600010` and `0x60034c` bytes past the end
  of the initialized data); the layout does not identify any of them with another.
* **C — the code genuinely forms different addresses.** *Proven.* The `0x600000`
  is `0x60 << 16`, the high half of `0x604860`; the other pair has HI16 `0x0000`.
  It is the difference between two addresses, not a base.
* **D — the two spaces differ by a base.** *Rejected.* The loader adds the same
  runtime `segmentVAddr[relative]` (`load_base + p_vaddr[relative]`) to every
  relocation. For this module `p_vaddr[0] == 0`; evaluating with explicit
  `load_base=0` reproduces the stored module-relative words, but that does **not**
  establish the PRX's real runtime base. Any common runtime base preserves
  differences between the three addresses, so they cannot collapse onto each
  other.

So `0x604860`, `0x4860` and `0x604B9C` are **three distinct module-relative
addresses**. What is *not* proven is their section identity — no named section
covers them — so `seto datarefs` still reports all three as `INFERRED`, with their
offset in the zero-filled segment, and never as a `.bss` variable (the `.bss`
section really is empty).

### The address spaces are kept apart

A report never conflates:

* the **file offset** of a byte (`section.offset + section_offset`);
* the **section offset** (`section_offset`, what `seto` compares);
* the **ELF virtual address** (`section.addr + section_offset`);
* the **PSP module-relative address** (`p_vaddr + segment-relative r_offset`);
* the **runtime load address** (`load_base + ELF virtual address`, where
  `load_base` is an explicit caller input and is not inferred from this ELF);
* the **PT_LOAD offset** (`address - segment.vaddr`, plus whether it is past
  `p_filesz` — the zero-filled tail);
* the **relocation destination** (the symbol/addend or the combined HI16/LO16
  addend, resolved only when exactly one allocated section contains it).

A segment whose `p_filesz` exceeds its `p_memsz` is rejected at parse time: its
bytes cannot be mapped, so no address derived from it would mean anything.
For a valid four-byte application inside `p_memsz` but past `p_filesz`, Seto keeps
the application/section location distinct from a file offset. A complete word in
the zero-fill tail has an initial addend of zero and no `file_offset`; a word
straddling `p_filesz` has `addend_valid: false`, is listed as incomplete, and
cannot participate in a proven match. The parser never reads adjacent file bytes
to fill the zero-initialized part.

### Reproducing the inventory

```
py -3.12 -m seto datarefs --prx <libhtml_view.prx> --function 0x6e4 --out build/datarefs.json
```

The JSON now carries `relocation_inventory` (formats, per-section counts, types,
unknown/unsupported types, segment indices, invalid application locations,
reserved fields, compressed/segment payloads, and an overall `complete` flag) and, for every
reference, the raw `r_offset`/`r_info`, the segment fields, the application
location, the combined addend, whether that addend is valid, the destination, the
pairing evidence, pairing and numeric-location confidence, cross-artifact
identity applicability, and the unresolved reason. Unsupported or malformed
relocation inventory also makes the command exit `5`; the report never claims
complete resolution merely because no reference happened to land in a selected
function.

## SETO-DECOMP-008 — três reconstruções novas e matching real

### Seleção reproduzível

Antes de escrever C, as 13 funções restantes foram cruzadas com os relatórios de
`seto functions`, `seto imports`, `seto datarefs`, o disassembly MIPS e o m2c
preliminar. A matriz completa, incluindo contagens de chamadas/relocations,
complexidade de fluxo, limites e motivos de inclusão/exclusão, foi gerada em
`build/seto008/selection.json` (artefato local ignorado pelo Git).

Foram priorizadas três funções sem references de dados e com todos os destinos
de call resolvidos:

| Prioridade | Função | Tamanho | Chamadas | Dados/fluxo | Decisão |
|---:|---|---:|---|---|---|
| 1 | `func_00000134` (`0x134–0x178`) | 17 instruções | seis chamadas a sceUtility / NID `0x64D50C56` | sem dados nem branches | reconstrução direta da sequência de constantes |
| 2 | `func_00000358` (`0x358–0x39c`) | 17 instruções | quatro imports resolvidos e duas chamadas locais | sem dados nem branches | sequência linear de chamadas |
| 3 | `func_00000034` (`0x34–0x84`) | 20 instruções | três imports e duas chamadas locais | sem relocations de dados; um branch condicional e um back-edge | inicialização e loop de status pequenos e fundamentados pelo listing/m2c |

Ghidra `SetoAnalyzeFunction` confirmou limites e corpos exatos dos três. A função
`0x84` foi excluída: seus dois words são apenas `jr $ra; nop`, sem evidência
independente de que sejam uma função reconstruível. `0x8c` ficou como quarta
candidata opcional (42 instruções e cinco caminhos de erro); as funções `0x39c`,
`0x414`, `0x508`, `0x634` e `0x704` têm referências a jump tables ou destinos
zero-filled sem identidade provada e foram adiadas. `0x178`/`0x278` têm mais
fluxo de erro/calls que as três prioridades.

### Resultados reais das novas funções

Metrowerks 3.0.1 build 219, `-O4,p -sdatathreshold 0`, pelo perfil local WSL2 e
wibo 1.2.0. Todas as relocations de calls abaixo foram resolvidas pelo
comparador; zero diferenças, zero relocation issues e zero limitações por função.

| Função | Fonte C | Compilação | Instruções | Status | Imports comprovados | Object SHA-256 | Source SHA-256 |
|---|---|---|---:|---|---|---|---|
| `func_00000034` | `decomp/src/func_00000034.c` | OK | 20/20 | **MATCHED** | `libehsys/0xEA748E31`, `libehsys/0xF1BC43DB`, `libehsys/0x08813E19`; locais `0x6e4`, `0x704` | `6e3df754182bf99bfa2c5d6b3c23a9a1e09fb8ecf29426750dc65f8fa9f09e9e` | `a48766d9ab066b1b09421c1fd2ba5d2660606abddb8dd27af9927af456c58650` |
| `func_00000134` | `decomp/src/func_00000134.c` | OK | 17/17 | **MATCHED** | `sceUtility/0x64D50C56` (seis chamadas) | `d082bed6976e3545edc84fec194c8b509a282e128fa55d77f3a8fc394b4c4627` | `908fd7826f026ba7af3a300a86942293023cf5560fed4fdc668978048769873a` |
| `func_00000358` | `decomp/src/func_00000358.c` | OK | 17/17 | **MATCHED** | `sceNetApctl/0xB3EDD0EC`, `sceNetResolver/0x6138194A`, `sceNetInet/0xA9ED66B9`, `sceNet/0x281928A9`; locais `0x244`, `0x134` | `56b90b3b9934fdb82bb43980721226e5060dabf4c5a0a3afba210334916b0afa` | `6d400f9440753a57cca756c9a587331b48e6c22f7d642e3c23e9d0a2eb860165` |

Durante a iteração inicial de `func_00000034`, `while (func_00000704() == 0)`
produziu sete palavras diferentes: o otimizador moveu o teste para o fim do loop
e duplicou a chamada. A listagem original testa o retorno no topo e volta
diretamente ao call. `for (;;)` com teste e `break` explícitos reproduziu as 20
palavras sem assembly ou `volatile`.

Assim, esta rodada adiciona **três `MATCHED` reais**; somados ao baseline, há
quatro. Os três resultados anteriores continuam iguais: `0x244` MATCHED,
`0x4b8` INCONCLUSIVE 18/20, `0x6e4` INCONCLUSIVE 2/8. As duas últimas não foram
promovidas por igualdade numérica nem por mapas manuais: a identidade entre seus
símbolos candidatos e os objetos originais continua sem evidência independente.
Os artefatos/transcrições permanecem em `build/seto008/` e não são versionados.

### Validação desta rodada

| Ambiente/gate | Resultado |
|---|---|
| Windows / `pytest -q` | 472 passou, 9 ignorados |
| Windows / `pytest -m integration -q` | 22 passou, 7 ignorados (WSL-only real matches não executados no host) |
| WSL2 / `pytest -m integration -q` | 26 passou, 3 ignorados (splat, Ghidra e REA não configurados no WSL) |
| Compilações reais 008 via wibo | 3 `MATCHED`, 54/54 palavras, 17 calls resolvidas, 0 diferenças/issues/limitações |
| `compileall -q src scripts tests` / `seto verify` / `git diff --check` | clean / OK / clean |

| Métrica acumulada | Contagem |
|---|---:|
| Reconstruções C com compilação real | 6 |
| `MATCHED` comprovados | 4 |
| `INCONCLUSIVE` (sem diferenças comprovadas) | 2 |
| `NONMATCHING` | 0 |
| Funções `.text` ainda sem reconstrução C | 10 |

## SETO-DECOMP-009 — reconstrução de fluxo de controle intermediário

### Seleção e revalidação

As três candidatas foram revalidadas antes de escrever C, como exige a tarefa:
`seto functions`, `seto imports --function <addr>` (para resolver cada `jal` a um
par `(library, NID)` ou a um endereço local) e o disassembly verificado. Os limites
`0x8c–0x134`, `0x178–0x244` e `0x278–0x358` vêm da mesma checagem Ghidra
`SetoAnalyzeFunction` usada na 008, agora com as três funções incluídas no teste de
integração. Nenhuma das três possui relocations de dados.

| Prioridade | Função | Tamanho | Chamadas | Fluxo | Resultado |
|---:|---|---:|---|---|---|
| 1 | `func_0000008C` (`0x8c–0x134`) | 42 instruções | seis `sceUtility/0x1579A159`; local `0x134` | seis `bltz` para um único bloco de limpeza | **MATCHED** |
| 2 | `func_00000178` (`0x178–0x244`) | 51 instruções | `sceSsl/0x957ECBE2` e quatro `sceHttp` (`0xAB1ABE07`, `0xE4D21302`, `0x87797BDD`, `0xF1657B22`); local `0x244` | cadeia de `bgez`/`bgezl`, um retorno direto e quatro limpezas | **MATCHED** |
| 3 | `func_00000278` (`0x278–0x358`) | 56 instruções | `sceNet/0x39AF39A6`, `sceNetInet/0x17943399`, `sceNetResolver/0xF3370E61`, `sceNetApctl/0xE2F91F9B`; locais `0x8c`, `0x178`, `0x358` | dois retornos diretos e quatro limpezas | **MATCHED** |

`func_00000278` chama duas reconstruções desta mesma rodada (`0x8c` e `0x178`) e a
`func_00000358` da 008; os destinos locais foram confirmados nos limites das
funções. Os imports novos foram declarados em `decomp/include/sce_stubs.h`
mantendo o nome derivado do endereço e o par `(library, NID)` no comentário — os
nomes reais continuam desconhecidos (o módulo guarda NIDs, não nomes).

### Resultados reais das novas funções

Metrowerks 3.0.1 build 219, `-O4,p -sdatathreshold 0`, perfil local WSL2 + wibo
1.2.0. Zero diferenças, zero relocation issues e zero limitações por função; as 26
chamadas (15 imports + 11 locais) foram resolvidas pelo comparador.

| Função | Fonte C | Compilação | Instruções | Status | Object SHA-256 | Source SHA-256 |
|---|---|---:|---|---|---|---|
| `func_0000008C` | `decomp/src/func_0000008C.c` | OK | 42/42 | **MATCHED** | `1bfb6ff695b201d8e657ac86a6a2b17b2e6b77d89fcbd7e3a164f1cc37d30439` | `4f50d83a2951cf3626ba76691a0c800cd966095750d7ccf11da134cac3cb9790` |
| `func_00000178` | `decomp/src/func_00000178.c` | OK | 51/51 | **MATCHED** | `8cbd1f45d40f4acd51f155cdce6f6790a8a089ec3f5db9470016ffc8a213c191` | `eb15db12c2b762ae3c684599cf05ec7bb6582b2eb9361d16f680b493ceed6391` |
| `func_00000278` | `decomp/src/func_00000278.c` | OK | 56/56 | **MATCHED** | `b157ff9e2ed1436e1a7d903f63ae27420303ba66f394c5c1ff0827438067e41f` | `9ce461da95f815150c2a83ce0e60e5b8c1ae835c19c3d33b1f23abf4840ae883` |

O `Source SHA-256` é calculado sobre o conteúdo normalizado para LF (o blob do
Git), para não depender do `core.autocrlf` do host; o `Object SHA-256` é o do `.o`
produzido pela própria execução.

### O que a reconstrução fixou

* Em `func_0000008C` a limpeza é única: os seis desvios `bltz` convergem para um
  único `jal 0x134`. Um `goto cleanup` com o bloco no fim reproduziu 42/42
  palavras, incluindo o `b` que salta o bloco e o `lw $ra` no slot de atraso.
* Em `func_00000178` e `func_00000278` o original **duplica** a limpeza em cada
  caminho de erro (quatro `jal 0x244` e quatro `jal 0x358`). A primeira tentativa,
  com um `goto` para um bloco único, gerou 8–9 instruções a menos e nem pôde ser
  comparada (o candidato ficou menor que a função). Repetir
  `limpeza(); return status;` dentro de cada `if` reproduziu exatamente as 51 e as
  56 palavras.
* Nenhuma exigiu assembly inline ou `volatile`; os valores das constantes e os
  tipos dos stubs permanecem provisórios.

### Validação desta rodada

| Ambiente/gate | Resultado |
|---|---|
| Windows / `pytest -q` | 479 passou, 12 ignorados |
| Windows / `pytest -m integration -q` | 22 passou, 10 ignorados |
| WSL2 / `pytest -m integration -q` | 29 passou, 3 ignorados |
| Compilações reais 009 via wibo | 3 `MATCHED`, 149/149 palavras, 26 calls resolvidas, 0 diferenças/issues/limitações |
| Baselines reconferidos (`0x244`, `0x34`, `0x134`, `0x358`, `0x4b8`, `0x6e4`) | inalterados: 4 `MATCHED`, 2 `INCONCLUSIVE` |
| `compileall -q src scripts tests` / `seto verify` / `git diff --check` | clean / OK / clean |

| Métrica acumulada | Contagem |
|---|---:|
| Reconstruções C com compilação real | 9 |
| `MATCHED` comprovados | 7 |
| `INCONCLUSIVE` (sem diferenças comprovadas) | 2 |
| `NONMATCHING` | 0 |
| Funções `.text` ainda sem reconstrução C | 7 |

### Funções `.text` restantes

Resumo versionado do que ainda falta (a matriz completa da 008 ficou em
`build/seto008/selection.json`, artefato local ignorado pelo Git):

| Função | Tamanho | Bloqueio principal |
|---|---:|---|
| `func_00000000` (`0x0`) | 52 bytes | referências de código provadas (`.text+0x34`, `.text+0x84`) e uma store no tail zero-filled (`0x4850`) sem identidade de seção |
| `func_00000084` (`0x84`) | 8 bytes | corpo é só `jr $ra; nop`; sem corpo reconstruível |
| `func_0000039C` (`0x39c`) | 120 bytes | referências a jump table / destinos zero-filled sem identidade provada |
| `func_00000414` (`0x414`) | 164 bytes | idem |
| `func_00000508` (`0x508`) | 300 bytes | idem; maior função, chama os locais `0x39C`, `0x414` e `0x4B8` |
| `func_00000634` (`0x634`) | 176 bytes | idem |
| `func_00000704` (`0x704`) | 240 bytes | idem; chama os locais `0x278`, `0x508`, `0x634` e `0x358` |

## SETO-DECOMP-010 — dados globais e reconstruções dependentes de dados

Esta rodada não adiciona abstrações: consolida o inventário de referências
globais das funções restantes, reconstrói as três funções cujo fluxo ficou
suficientemente compreendido e registra, sem forçar nada, por que nenhuma delas
pode ser `MATCHED` hoje.

### Inventário de referências globais

O relatório por função já existia (`seto datarefs`). A rodada acrescentou apenas a
agregação **pura** do próprio relatório,
`seto.datarefs.build_global_usage` (exposta pelo script fino
`scripts/global_usage.py`), que agrupa referências por **localização demonstrada
no módulo**. A chave de agrupamento só é produzida quando o par HI16/LO16 é
provado (ou não se aplica) *e* o addend combinado é recuperável; um par que
depende apenas da ordem das relocations nunca entra num grupo e fica em
`unresolved`. O agrupamento não promove localização a identidade de objeto, não
funde `section` com `segment` e preserva cada acesso individual — não inventa
tipo global, tamanho nem direção.

Resultado em `build/seto010/global-usage.json` (artefato local, 16 funções
`.text`): **15 localizações demonstradas, 6 referências mantidas fora dos grupos**.

| Localização | Funções | Acesso observado |
|---|---|---|
| `.data+0x3c` / `+0x68` / `+0x98` | `func_00000414` (`0x68` duas vezes: caso 1 e default) | base de string (`$a1`) passada a `libehsys/0x476FD94A` |
| `.data+0xc8` | `func_000004B8` | base de string (`$a1`) |
| `.data+0x8` / `+0x20` | `func_0000039C` / `func_00000414` | base de jump table (`lw` indexado) |
| `.text+0x34` / `.text+0x84` | `func_00000000` | endereços de código (`$a0`/`$a1`) |
| `segment 0 +0x4850` | `func_00000000` | início do tail zero-filled (`$a2`) |
| `segment 0 +0x4860` | `func_000006E4` | store de ponteiro (o objeto apontado) |
| `segment 0 +0x604860` | `func_000006E4`, `func_00000704` | palavra de estado lida/escrita |
| `segment 0 +0x604864` | `func_00000508`, `func_00000634` | base de um buffer de `0xa4` bytes |
| `segment 0 +0x604918` | `func_00000508` | segundo buffer de `0xa4` bytes |
| `segment 0 +0x604b18` | `func_00000508` | terceiro buffer (consumido por `func_000004B8`) |
| `segment 0 +0x604b9c` | `func_000006E4` | ponteiro de contexto |

As sete localizações `segment 0` estão no tail zero-filled (além de
`p_filesz = 0x4850`), então sua localização é `INFERRED`, não `PROVEN`; um mapa
manual não as promoveria. Três relações entre funções ficam visíveis sem serem
presumidas além dos bytes: `func_00000508` inicializa a base `+0x604864` (memset
de `0xa4` bytes seguido de stores em offsets `+0x0`…`+0x78`, incluindo o store de
`+0x604b18` no campo `+0x50`) e `func_00000634` lê o campo `+0x1c` da mesma base;
`func_000006E4` inicializa `+0x604860` e `+0x604b9c`, e `func_00000704` é uma
máquina de estados sobre eles. O conteúdo dos campos não é recuperável a partir do
PRX, então nenhum struct global foi declarado.

### Reconstruções

| Prioridade | Função | Tamanho | Chamadas | Resultado |
|---:|---|---:|---|---|
| 1 | `func_0000039C` (`0x39c–0x414`) | 30 instruções | `libehsys/0x31454993` | **INCONCLUSIVE**, 28/30 |
| 2 | `func_00000414` (`0x414–0x4b8`) | 41 instruções | `libehsys/0x1F190478`; `libehsys/0x476FD94A` (×4) | **INCONCLUSIVE**, 31/41 |
| 3 | `func_00000000` (`0x0–0x34`) | 13 instruções | `libehsys/0xB4471B5E` | **INCONCLUSIVE**, 7/13 |

* **`func_0000039C`** — `switch (func_00002364())` com `sltiu $v0,6`. A tabela
  está em `.data+0x8` (`0x4770`) e seus 6 words são exatamente
  `[0x3d4,0x3dc,0x3e4,0x3ec,0x3f4,0x3fc]`, ou seja, os casos `0..5` retornam
  `0,1,6,2,5,3` e o `default` retorna `1`. O comparador certifica 28 das 30
  palavras e não encontra nenhuma divergência comprovada; as 2 palavras não
  certificadas são o par HI16/LO16 que codifica o endereço da tabela. O intervalo
  usado pelo Seto é `[0x39C, 0x414)` (30 instruções, fim exclusivo = início da
  função seguinte). Ghidra, com o fluxo que ela mesma inferiu, reconhece um corpo
  de 116 bytes em **duas** regiões (`SETO_BOUNDARY_STATUS=MISMATCH`,
  `SETO_DECOMP_STATUS=NOT_RUN`) e não define a palavra `0x404`. Isso é
  **consistente** com o braço `default` ser código morto, mas não é confirmação de
  corpo `EXACT` nem prova isolada da intenção do código-fonte original.
* **`func_00000414`** — `switch (func_00002354())` com `sltiu $v0,7`; a tabela em
  `.data+0x20` (`0x4788`) é `[0x450,0x468,0x480,0x480,0x480,0x480,0x480]`. Cada
  caso chama `func_00008A4($s0, <destino>)`: caso 0 → `.data+0x3c`, caso 1 →
  `.data+0x68`, casos 2–6 → `.data+0x98`, `default` → `.data+0x68`. Ghidra
  reconhece o corpo exato (`0x414–0x4B8` como **uma** região de 164 bytes,
  `SETO_BOUNDARY_STATUS=EXACT`, 41 instruções). O comparador certifica 31 das 41
  palavras e não encontra divergência comprovada; as 10 não certificadas são cinco
  pares HI16/LO16 (a tabela e as três strings, com `0x68` repetido). As strings
  são URLs ASCII terminadas em NUL.
* **`func_00000000`** — `func_00001F04(func_00000034, func_00000084,
  D_00004850); return 0;`. Três pares HI16/LO16: `.text+0x34` e `.text+0x84`
  provados, `0x4850` apenas `segment 0`. O comparador certifica 7 das 13 palavras
  (0 divergências comprovadas); as 6 não certificadas são os três pares HI16/LO16.
  Ghidra não cria função em `0x0` (`SETO_BOUNDARY_STATUS=NOT_FOUND`): é o entry
  point e a auto-análise não o modela como função, de modo que o intervalo
  `[0x0, 0x34)` é do Seto e a listagem das 13 instruções nele confere — o que **não**
  é uma confirmação de corpo por Ghidra. Sobre o significado:
  o PRX mostra dois endereços de código e o início do tail zero-filled passados a
  um import. `0x84` contém apenas `jr $ra; nop`, e o único ponto que toma seu
  endereço é a própria instrução `0x18` desse par passado ao import — não há
  chamada direta —, o que é compatível com o *fim exclusivo* `[0x34, 0x84)`; a rodada
  registra isso como leitura possível e **não** presume registro de handler,
  thread ou exit — a reconstrução fixa a chamada e o retorno, nada além.

### Por que nenhum `MATCHED` novo

Toda função `.text` ainda sem reconstrução depende de pelo menos uma referência de
dados, e o comparador recusa certificar um destino de dados sem identidade
qualificada pelo artefato: o objeto candidato expõe apenas símbolos `D_...`
indefinidos e o PRX é stripped (`symbols: 0`). Um `--data-map` é uma **asserção**,
não uma prova, e não converte um resultado em `MATCHED`. Por isso as três
reconstruções ficam `INCONCLUSIVE`: o comparador certifica **66 das 84 palavras**
e não encontra nenhuma divergência comprovada nem issue de relocation; as 18
palavras restantes são pares HI16/LO16 cuja equivalência de relocação dependeria de
uma identidade de objeto qualificada pelo artefato que não existe aqui, portanto
permanece **não comprovada**. O número 66/84 descreve apenas as palavras que o
comparador consegue certificar: **não** afirma igualdade bruta dos bytes das 84
palavras nem equivalência semântica de relocations. Nenhum caminho foi forçado
(sem `extern` enganoso, sem global inventado, sem `--data-map`, sem assembly
inline, sem `volatile`).

### Proveniência das três compilações (wibo 1.2.0, `-O4,p -sdatathreshold 0`)

`Source SHA-256` sobre o conteúdo normalizado para LF (blob do Git); `Object
SHA-256` do `.o` produzido pela execução.

| Função | Fonte C | Compilação | Instruções | Status | Object SHA-256 | Source SHA-256 |
|---|---|---|---:|---|---|---|---|
| `func_00000000` | `decomp/src/func_00000000.c` | OK | 7/13 | **INCONCLUSIVE** | `e5aa6a69ed1fd6ceb01c3445bace376e841fcdfde497735ccb7f883ed8bfa543` | `6873203e1a24bc84bf4aee310cfb524386907486608f99f80ca4881086f8dbb7` |
| `func_0000039C` | `decomp/src/func_0000039C.c` | OK | 28/30 | **INCONCLUSIVE** | `776f161be72d985a3eef836141d45263ede9a991867a74699c9ac56cffbc09fd` | `231657872547cb99956ab015f99cbe529045a970f31d1e29cc0e02be2576b2d6` |
| `func_00000414` | `decomp/src/func_00000414.c` | OK | 31/41 | **INCONCLUSIVE** | `31ccca3915dd0339ebc9afe9579e6c313d4f406238cb70ea19364401ffc73e2a` | `98a58db171c55fb2e2696017b1d60d06ea3d93d21dde55a13ff5980734be0986` |

Os `Source SHA-256` acima são a revisão atual dos três arquivos (o endurecimento
de auditoria ajustou apenas comentários). As três fontes foram **recompiladas**
depois desses ajustes: os `Object SHA-256` permaneceram exatamente os mesmos, o
que confirma que a alteração foi inerte para o código gerado.

### Validação desta rodada

| Ambiente/gate | Resultado |
|---|---|
| Windows / `pytest -q` | 495 passou, 15 ignorados (endurecimento: +5 testes em `tests/test_datarefs.py`) |
| Windows / `pytest -m integration -q` | 22 passou, 13 ignorados |
| WSL2 / `pytest -m integration -q` | 32 passou, 3 ignorados |
| Determinismo da agregação (64 permutações do relatório real) | 1 payload canônico idêntico (15 localizações, 6 `unresolved`) |
| Recompilação das 3 fontes após ajuste de comentários | `Object SHA-256` inalterados |
| Ghidra real (`test_toolchain_real.py`) | 1 passou, 12 faixas, saída `0` |
| Compilações reais 010 via wibo | 3 `INCONCLUSIVE`, 66/84 palavras certificadas, 7 calls resolvidas, 0 divergências comprovadas/issues |
| Baselines reconferidos (as 9 anteriores) | inalteradas: 7 `MATCHED`, 2 `INCONCLUSIVE` |
| `compileall -q src scripts` / `git diff --check` | clean / clean |

| Métrica acumulada | Contagem |
|---|---:|
| Reconstruções C com compilação real | 12 |
| `MATCHED` comprovados | 7 |
| `INCONCLUSIVE` (sem diferenças comprovadas) | 5 |
| `NONMATCHING` | 0 |
| Funções `.text` ainda sem reconstrução C | 4 |

As quatro que faltam são `func_00000084` (só `jr $ra; nop`, usado como *fim* de
faixa por `func_00000000`), `func_00000508` (constrói o buffer de `0xa4` bytes),
`func_00000634` e `func_00000704` (leitura do campo `+0x1c` e máquina de estados
sobre os buffers zero-filled). Elas permanecem para a próxima rodada; nenhuma foi
decompilada aqui.

### Endurecimento de auditoria (revisão do PR #9)

* `build_global_usage()` passa a ordenar as referências de cada grupo e as não
  resolvidas por `(função, endereço *numérico* da instrução, tipo, pairing,
  location, status, unresolved)`, sem descartar duplicatas e sem ordenar
  endereços lexicograficamente. Cinco testes novos em `tests/test_datarefs.py`
  cobrem: referências no mesmo grupo recebidas em ordens invertidas, o mesmo
  para `unresolved`, a ordem `0x8 < 0x10 < 0x100`, tipos distintos no mesmo
  sítio e igualdade de `json.dumps(..., sort_keys=True)` sob permutações. O
  relatório real foi agregado sob 64 permutações (funções e referências
  embaralhadas) e produziu **um único** payload canônico.
* As afirmações de equivalência foram reescritas. Nenhum arquivo afirma
  igualdade bruta das 84 palavras nem equivalência semântica das relocations; o
  texto reporta **66/84 certificadas** e 18 não certificadas, mantendo 0
  divergências comprovadas, 0 relocation issues e o status `INCONCLUSIVE`.
* A descrição do Ghidra em `func_0000039C.c` agora distingue o intervalo do Seto
  `[0x39C, 0x414)` (30 instruções) do corpo de 116 bytes em **duas** regiões que
  Ghidra reconhece (`SETO_BOUNDARY_STATUS=MISMATCH`) e não apresenta a ausência
  de `0x404` como confirmação de corpo `EXACT` nem como prova isolada da intenção
  do código-fonte. As três classificações — `0x414=EXACT`, `0x39C=MISMATCH`,
  `0x0=NOT_FOUND` — permanecem explícitas e distintas.
* O endurecimento não tocou código executável: as três fontes foram
  recompiladas e os `Object SHA-256` permaneceram idênticos (ver acima).

## SETO-DECOMP-011 — estado compartilhado e as funções restantes

*(Shared State Reconstruction & Remaining Functions.)*

A rodada fecha o conjunto `.text`: reconstrói as três funções que ainda tinham
corpo a descrever (`0x634`, `0x508`, `0x704`) e **classifica** o fragmento de
`0x84`, sem forçar uma função C para ele. Nenhuma abstração nova entrou no
ferramental: as fontes usam o mesmo compilador, as mesmas flags, o mesmo
comparador e o mesmo modelo de evidência das rodadas 008–010.

**Revisão de endurecimento da auditoria (no mesmo PR #10).** Duas correções.
Primeiro, a representação C do bloco em `0x604864`: ele era declarado como **um**
`unsigned char` e acessado por `int *`/`void **` derivados por cast, apesar de a
função usar uma região de `0xA4` bytes — ver
[Representação C do bloco `0x604864`](#representação-c-do-bloco-0x604864). Depois,
a classificação de `0x84`: a rodada afirmava que nada no módulo a referencia, e
isso é falso, porque `func_00000000` calcula `.text+0x84` e o passa como
argumento — ver [`func_00000084`](#func_00000084-referenciado-mas-não-chamado). As
duas mudanças são de representação e de precisão de texto: nem o comparador, nem
o modelo de evidência, nem os resultados das outras treze reconstruções mudaram.

### Inventário de estado compartilhado

`seto datarefs` e a agregação pura `seto.datarefs.build_global_usage` foram
reexecutados sobre as 16 funções (artefato local `build/seto011/global-usage.json`,
ignorado pelo Git): **15 localizações demonstradas, 6 referências mantidas fora
dos grupos**. As seis não resolvidas são todas de `func_00000704` e todas do tipo
`hi16-lo16` — exatamente os pares cujo `lui` está separado do uso por uma
ramificação. O mecanismo já tem cobertura unitária
(`tests/test_matching.py::test_conditional_control_flow_keeps_order_pairing_inconclusive`);
as seis referências do módulo são a ocorrência real dele e continuam visíveis em
vez de agrupadas por engano.

| Localização | Acessos observados (endereço, instrução, largura) | Funções consumidoras | Papel nos bytes |
|---|---|---|---|
| `segment 0 +0x4860` | `addiu` de 32 bits em `0x6f4` (endereço calculado, nunca desreferenciado) | `func_000006E4` | endereço distinto, guardado como **valor** |
| `segment 0 +0x604860` | `lw`/`sw` de 32 bits em `0x6ec`, `0x710`, `0x768`, `0x788`, `0x78c`, `0x79c`, `0x7b4`, `0x7c4`, `0x7d4`, `0x7e0` | `func_000006E4`, `func_00000704` (agrupadas 5 de 10) | palavra de estado: `func_000006E4` escreve `1`; `func_00000704` despacha, relê a cada incremento e grava o literal `3` nas duas falhas |
| `segment 0 +0x604864` | bloco de `0xa4` bytes; `func_00000854(base,0,0xa4)` em `0x52c`; 24 `sw` e 1 `lw` de 32 bits | `func_00000508`, `func_00000634` | base do bloco: `+0x1c` lido por `0x634`; `+0x00`–`+0x78` escritos por `0x508` |
| `segment 0 +0x604918` | `addiu` de 32 bits em `0x594`, `0x5a4`, `0x600`; duas gravações de 32 bits em `+0x40`/`+0x68` do bloco `0x604864` | `func_00000508` | segundo bloco: endereço passado à chamada local `0x414` e guardado como valor |
| `segment 0 +0x604b18` | `addiu` de 32 bits em `0x5cc`, `0x5d4`; uma gravação de 32 bits em `+0x50` do bloco `0x604864` | `func_00000508` | terceiro bloco: endereço passado à chamada local `0x4B8` e guardado como valor |
| `segment 0 +0x604b9c` | `sw` de 32 bits em `0x700` (valor `0x4860`); `lw` de 32 bits em `0x770` | `func_000006E4` (agrupada), `func_00000704` (só ordem de relocation, fora do grupo) | ponteiro/valor de contexto: `func_00000704` o carrega em `$a0` para `0x508` |

O relatório local completo — `build/seto011/shared-state.json`, gerado por
`build/seto011/shared_state.py` a partir do disassembly validado, do
`datarefs.json` e do `global-usage.json`, sem versionamento — registra os **48
acessos** das seis localizações, cada um com endereço da instrução, registrador
base, `operation`, `width_bits`, `field_offset`, valor e confiança. O gerador
recusa ser executado se uma linha transcrita não bate com o disassembly ou se
uma referência HI16/LO16 do `datarefs` fica sem acesso correspondente, de modo
que nenhuma referência (resolvida ou só de ordem) desaparece do relatório.

As demais nove localizações agrupadas vêm das rodadas 005–010 e não mudaram. As
seis localizações acima estão além de `p_filesz = 0x4850`, então continuam
`INFERRED`; o Ghidra real também as reporta `UNMAPPED`, o que confirma que nenhum
nome de objeto é recuperável a partir deste módulo. As larguras acima vêm da
instrução que faz cada acesso, não de um tipo inferido. A revisão de
endurecimento declarou, para o bloco `0x604864` apenas, a descrição provisória
`SetoObservedBlock` — uma hipótese de layout derivada dessas larguras, com
verificação em tempo de compilação, e não a recuperação do tipo original (ver
[Representação C do bloco `0x604864`](#representação-c-do-bloco-0x604864)). É a
única representação de struct introduzida, e ela existe porque as duas funções
que tocam o bloco precisam de objetos válidos e alinhados, não porque um tipo
tenha sido recuperado.

### Reconstruções

| Prioridade | Função | Tamanho | Chamadas | Resultado |
|---:|---|---:|---|---|
| 1 | `func_00000634` (`0x634–0x6e4`) | 44 instruções | `libehsys/0xE8D57DC6`, `sceUtility/0xBDA7D894`, `sceUtility/0x05AFB9E4`, `sceUtility/0xF5CE1134` | **INCONCLUSIVE**, 42/44 |
| 2 | `func_00000508` (`0x508–0x634`) | 75 instruções | `libehsys/0x10F3BB61`, `libehsys/0x8171F765`, `sceUtility/0xCDC3AA41`, locais `0x39C`, `0x414`, `0x4B8` | **INCONCLUSIVE**, 63/75 |
| 3 | `func_00000704` (`0x704–0x7f4`) | 60 instruções | locais `0x278`, `0x358`, `0x508`, `0x634` | **INCONCLUSIVE**, 40/60 |
| 4 | `func_00000084` (`0x84–0x8c`) | 2 instruções | nenhuma | **classificado**, sem fonte C |

* **`func_00000634`** — forma o endereço `0x604864`, chama
  `libehsys/0xE8D57DC6(0, 0)` e depois `sceUtility/0xBDA7D894()`, e sobre o
  resultado compila um `switch` de cinco casos: o caso 2 chama
  `sceUtility/0x05AFB9E4(2)`, o caso 3 chama `sceUtility/0xF5CE1134()`, o caso 0
  (cujo `lw` fica no *delay slot* do `beql`) devolve
  `base->words_00_2c[7] == 0 ? 1 : 2` — o offset `+0x1c` do bloco tipado, isto é,
  o `unsigned int` de índice 7 do primeiro campo da estrutura —, e o `default`
  junto com os casos 1 e 4 cai no bloco compartilhado `move $v0, $zero`. Três
  formas de fonte são forçadas pelas palavras: a leitura do bloco precisa ser
  feita por um **ponteiro local** para a estrutura (um acesso direto ao global,
  `D_00604864.words_00_2c[7]`, deixa este build materializar o endereço no ponto
  de uso e o corpo sai com 41 instruções, sem salvar `$s0` — ver a subseção de
  representação); o argumento `2` da chamada do caso 2 (a constante é
  materializada uma única vez e compartilhada com a comparação); e a ordem das
  labels — medida na 010 sobre as 120 ordens de um `switch` de cinco casos, este
  build emite a cadeia na ordem **inversa** da fonte, de modo que a cadeia
  observada `(0, 3, 2, 4, 1)` sai da fonte `1, 4, 2, 3, 0`.

* **`func_00000508`** — inicializa o bloco de `0xa4` bytes em `0x604864`:
  `func_00000854(base, 0, 0xa4)` limpa e então `+0x00 = 0xa4`,
  `+0x04 = func_0000039C()`,
  `+0x08 = (func_0000235C(0) & 0xffff) == 0x2000 ? 0 : 1`, os literais
  `+0x18/+0x0c/+0x14/+0x10 = 0x10/0x11/0x12/0x13`, `+0x34 = 0x600000` (**sem
  relocation**: é o valor literal, não um endereço), `+0x30 = arg0` (no *delay
  slot* da chamada `0x414`), `+0x40 = &0x604918`, `+0x44/+0x48/+0x4c = 3/2/0x2ba`,
  `+0x50 = &0x604b18`, `+0x60/+0x64 = 3/0x200`, `+0x6c/+0x70/+0x74 = 1`,
  `+0x68 = &0x604918`, zera `+0x54/+0x5c/+0x58/+0x78` e devolve o resultado de
  `sceUtility/0xCDC3AA41(base)` — o valor que o chamador `func_00000704` testa com
  `< 0`. Uma forma de fonte é forçada: os dois primeiros stores precisam de um
  **ponteiro de palavra nomeado** para o início do bloco
  (`unsigned int *words = (unsigned int *)base;`, que é a forma explícita de
  `base->words_00_2c`, o primeiro campo da estrutura). Escrevê-los como
  `base->words_00_2c[0]`/`[1]`, ou ligar o ponteiro por decaimento de array
  (`= base->words_00_2c`), faz este build rematerializar o endereço constante
  (`lui` + `lo` em vigor) em vez de reusar `$s0` e acrescenta duas instruções (77
  palavras, não 75). **Resultado `INCONCLUSIVE`, 63/75 palavras, zero divergências
  comprovadas.** As 12 palavras não certificadas são os seis pares HI16/LO16 do
  bloco e dos dois endereços passados às chamadas: 0x604864 (1), 0x604918 (3: o
  argumento de `0x414`, `+0x40` e `+0x68`) e 0x604b18 (2: o argumento de `0x4b8` e
  `+0x50`).
  A revisão de endurecimento também corrigiu uma leitura da rodada: com a
  representação anterior (um `unsigned char` + casts), este build emitia
  `move $a0, $s0` **depois** dos três stores `sw $zero, 0x54/0x5c/0x58($s0)`,
  uma diferença de quatro palavras (64–67) que a rodada atribuiu a uma mudança de
  escalonamento entre o `2.4.1.01` do PRX e o `3.0.1 build 219` disponível. Com os
  membros do bloco tipados, as cinco instruções finais saem exatamente onde o
  módulo as coloca — `move $a0, $s0` antes dos três stores, e
  `sw $zero, 0x78($s0)` no *delay slot* do `jal` — e as quatro palavras passam a
  certificar. A atribuição anterior estava errada e fica registrada como
  correção, não apagada.

* **`func_00000704`** — máquina de estados sobre a palavra em `0x604860`, com
  `switch` de quatro casos (cadeia emitida `4, 3, 2, 1` ⇒ fonte `1, 2, 3, 4`): o
  caso 1 guarda com `func_00000278() < 0` e depois com
  `func_00000508(*(void **)0x604b9c) < 0`, gravando o literal `3` em qualquer
  falha e senão incrementando o estado; o caso 2 chama `func_00000634()` e
  incrementa apenas se o resultado for diferente de zero; o caso 3 chama
  `func_00000358()` e incrementa; o caso 4 **retorna 1** (o `beql` salta por cima
  do bloco `move $v0, $zero`); todo o resto retorna 0. Três formas são forçadas:
  os guardas são `... < 0` (o compilador emite `bgezl` para os dois, *branch
  likely* com *delay slot* anulado quando o desvio não é tomado; inverter o sinal
  não reproduz as palavras — o guarda do caso 2 é um `beqz` simples); cada
  incremento **relê** a palavra
  de
  `0x604860` e grava a soma, logo a fonte lê o global em vez de manter uma cópia
  local viva através das chamadas; e o argumento de `func_00000508` é o **valor**
  carregado de `0x604b9c`.

#### Representação C do bloco `0x604864`

**Causa.** As duas fontes declaravam o objeto como **um** byte
(`extern unsigned char D_00604864;`) enquanto `func_00000508` limpava e escrevia
uma região de `0xA4` bytes, e os acessos eram feitos por `int *`/`void **`
derivados dessa declaração por cast. A declaração não descrevia um objeto que
contém os offsets usados, e converter um objeto de alinhamento 1 em ponteiros de
4 bytes não é válido no modelo de objetos da linguagem — não era só estética.

**Representação provisória.** `decomp/include/seto_shared_state.h` declara
`SetoObservedBlock` e o símbolo (`extern SetoObservedBlock D_00604864;`), e as
duas fontes passaram a usá-la; as declarações duplicadas do objeto saíram das
fontes. A estrutura **não é o tipo original recuperado**: é o registro dos
offsets observados, e o nome e o dos campos são descritivos. `D_00604918` e
`D_00604B18` continuam sendo apenas endereços (`unsigned char`, e a fonte só
toma `&`), porque nada acessa elemento posterior deles.

| Offset | Membro | Largura | Evidência (instrução) |
|---|---|---|---|
| `+0x00`–`+0x2F` | `words_00_2c[0..11]` | `unsigned int` | 6 `sw` em `0x53c`, `0x540`, `0x560`/`0x564`, `0x568`, `0x570`, `0x578`, `0x580`; `+0x1c` é o `lw` de `0x660` |
| `+0x30` | `field_30` | `void *` | `sw $s1, 0x30($s0)` em `0x59c` (argumento de entrada) |
| `+0x34`–`+0x3F` | `words_34_3c[0..2]` | `unsigned int` | `sw` em `0x590`; o `lui $v0, 0x60` de `0x588` **não** tem relocation: é o literal `0x00600000` |
| `+0x40` | `field_40` | `void *` | `sw` em `0x5a8`, do par `lui`/`addiu` de `0x5a0`/`0x5a4` |
| `+0x44`–`+0x4F` | `words_44_4c[0..2]` | `unsigned int` | `sw` em `0x5ac`, `0x5b4`, `0x5bc` |
| `+0x50` | `field_50` | `void *` | `sw` em `0x5d8`, do par de `0x5d0`/`0x5d4` |
| `+0x54`–`+0x67` | `words_54_64[0..4]` | `unsigned int` | `sw` em `0x5dc`, `0x5e4`, `0x60c`, `0x610`, `0x614` |
| `+0x68` | `field_68` | `void *` | `sw` em `0x604`, do par de `0x5fc`/`0x600` |
| `+0x6C`–`+0x7B` | `words_6c_78[0..3]` | `unsigned int` | `sw` em `0x5ec`, `0x5f0`, `0x5f4`, `0x61c` |
| `+0x7C`–`0xA3` | `reserved[0x28]` | `unsigned char` | coberto pela limpeza de `0xA4` bytes (`func_00000854(base, 0, 0xa4)` em `0x52c`), nunca acessado por campo |

**Comprovação do layout no ABI alvo.** O header verifica em tempo de compilação,
com o idiom de array de tamanho negativo (o Metrowerks 3.0.1 build 219 é anterior
a `_Static_assert`), que `sizeof(SetoObservedBlock) == 0xA4`, que
`sizeof(unsigned int) == 4` e `sizeof(void *) == 4`, e os offsets `0x00`, `0x1C`,
`0x30`, `0x34`, `0x40`, `0x50`, `0x68` e `0x78`. O compilador **executa** essas
verificações nas duas compilações reais. Um detalhe do ambiente fica registrado:
`<stddef.h>` não é alcançável (o compilador reporta `Environment variable
'MWCIncludes' not found`) e portanto `offsetof` não existe; o header define
`SETO_OFFSETOF` com a mesma expressão, e ela é de fato constante para este
compilador — uma verificação deliberadamente falsa falha com `illegal constant
expression`, o que foi conferido antes de adotá-la. O layout também é conferido
sem mídia em `tests/test_decomp_shared_state.py`, que recompõe os offsets a partir
da declaração e confere que cada offset documentado tem verificação.

**Recompilações e hashes.** As duas funções foram recompiladas com Metrowerks
3.0.1 build 219, `-O4,p -sdatathreshold 0`, via wibo 1.2.0 no WSL2:

| Função | Antes | Depois | Diferenças antes → depois |
|---|---|---|---|
| `0x634` | `INCONCLUSIVE`, 42/44, 0 diferenças | `INCONCLUSIVE`, 42/44, 0 diferenças | nenhuma |
| `0x508` | `NONMATCHING`, 59/75, **4 diferenças** (palavras 64–67) | `INCONCLUSIVE`, **63/75, 0 diferenças** | as 4 palavras de escalonamento passaram a certificar |

Nenhuma divergência nova de instrução ou de relocation apareceu (`relocation_issues == []`
nas duas). A mudança obrigou a registrar **uma forma de fonte forçada** em cada
função, ambas de declaração de ponteiro, e ambas explicadas nos cabeçalhos das
fontes: em `0x634`, o acesso precisa passar por um ponteiro local para a
estrutura; em `0x508`, os dois primeiros stores precisam de um ponteiro de palavra
nomeado. Nenhuma das duas usa `volatile`, assembly inline ou pragma, e nenhuma
introduz comportamento indefinido (o ponteiro de palavra aponta para o primeiro
membro da estrutura, que as verificações fixam em `+0x00`).

#### `func_00000084`: referenciado, mas não chamado

O intervalo `0x84–0x8C` contém `jr $ra; nop`. **Não há chamada direta comprovada**
ao endereço — nenhum `jal`/`j`/`b` chega a `0x84` e nenhuma relocation de salto o
tem como destino. Mas ele **é referenciado**: `func_00000000` calcula
`.text+0x84` (par HI16/LO16 nas instruções `0x14`/`0x18`, pairing `PROVEN`,
destino `DataTarget(".text", 0x84)`, status `PROVEN`) e o passa como argumento
(`$a1`) a um import de `libehsys` em `0x20`/`0x24`. O **uso posterior** desse
endereço não é conhecido, e a rodada não presume registro de handler, thread ou
`exit`. A forma é compatível tanto com uma função C vazia — um probe compilado,
`void func_00000084(void) {}`, produz exatamente essas duas palavras, 8 bytes de
`jr $ra`/`nop` — quanto com um simples limite exclusivo; as duas leituras são
hipóteses e nenhuma é afirmada como fato. O Ghidra real também **não** modela
`0x84` como função (`SETO_BOUNDARY_STATUS=NOT_FOUND`,
`SETO_DECOMP_STATUS=NOT_RUN`), a identidade permanece indeterminada e o intervalo
fica como **classificação**, sem `func_00000084.c`. A revisão corrigiu o texto da
rodada que dizia que nada no módulo a alcança ou que não há referências a ela: a
ausência de chamada direta não é ausência de referência. O teste
`test_func_00000084_is_referenced_as_an_argument_by_func_00000000` fixa a
referência de forma objetiva a partir do `datarefs` do PRX.

### Evidência Ghidra e hashes

O Ghidra real (12.1.3, `Allegrex:LE:32:default`) foi consultado nas quatro faixas
novas: `0x634` (176 endereços, 44 instruções), `0x508` (300, 75) e `0x704` (240,
60) são `EXACT` em uma única região, e `SETO_ADDRESS_MAP` responde `UNMAPPED` para
`0x604864`, `0x604918`, `0x604b18`, `0x604860` e `0x604b9c`; `0x84` é `NOT_FOUND`.

| Função | Fonte C | Compilação | Instruções | Status | Object SHA-256 | Source SHA-256 |
|---|---|---|---:|---|---|---|---|
| `func_00000634` | `decomp/src/func_00000634.c` | OK | 42/44 | **INCONCLUSIVE** | `1505c2cf3756867f0a0448dbcf6db5c7b1bf3c06606e8458753ef9ab3aedda0a` | `f784efc3d772ad54df6128cfdfa4e8248b11f6533a8aac52a9db0de6fd79782e` |
| `func_00000508` | `decomp/src/func_00000508.c` | OK | 63/75 | **INCONCLUSIVE** | `870d430533321b28541dcce4ad859515362ba693225348f177d206996adae791` | `1395bb35360c75cd0ea41373036f781b164ee8ad3d77d6ce0075d7c746e7fe08` |
| `func_00000704` | `decomp/src/func_00000704.c` | OK | 40/60 | **INCONCLUSIVE** | `f3d36449bf372d194197e6b4d7f31ca8b6317fa0232d502c04fabad7984df65f` | `d541eedf6a206f96c30869697c2e089987c4c0d0580c68a6da9f9069796623d5` |

Os `Source SHA-256` são a revisão atual das fontes. A revisão de endurecimento
mudou o código gerado de `0x634` e `0x508`, e seus `Object SHA-256` mudaram com
ele; `func_00000704` não usa o header e continua idêntica. Recompilações repetidas
das três fontes reproduzem os mesmos `Object SHA-256`.

A tabela de pendências da 010 fica como registro daquele ponto. Depois desta
rodada, a única função `.text` sem fonte C é `func_00000084`, e por classificação,
não por bloqueio.

### Validação desta rodada

| Ambiente/gate | Resultado |
|---|---|
| Windows / `pytest -q` | 504 passou, 19 ignorados (as comparações reais são WSL-only; +8 testes unitários de layout, +1 integração de `0x84`) |
| Windows / `pytest -m integration -q` | 23 passou, 17 ignorados |
| WSL2 / `pytest -m integration -q` | 37 passou, 3 ignorados (inclui as 15 entradas de `REAL_MATCH_CASES`, a verificação de assinatura de `0x508` e a referência a `0x84`) |
| Ghidra real (`test_toolchain_real.py`) | 1 passou, 16 faixas, `SETO_LANGUAGE` 16×; `0x84` continua `NOT_FOUND` |
| Compilações reais 011 via wibo | 3 `INCONCLUSIVE` (0 divergências comprovadas), 14 chamadas resolvidas, 0 `relocation_issues` |
| Baselines reconferidos | as 12 reconstruções anteriores e `func_00000704` foram reexecutadas sem mudança de status |
| Determinismo | uma segunda compilação independente das três fontes reproduz os mesmos `Object SHA-256` |
| `compileall -q src scripts tests` / `git diff --check` | clean / clean |

#### Cobertura de regressão

A rodada **não alterou nenhum código de ferramenta** (`src/`, `scripts/`): as
mudanças são três fontes C, um protótipo em `decomp/include/sce_stubs.h`, o novo
`decomp/include/seto_shared_state.h`, a documentação e os testes. Nenhum
comportamento de ferramenta mudou, logo as dez áreas de regressão pedidas
continuam cobertas pela suíte existente (e foram reexecutadas com o mesmo
resultado):

| Área | Teste que cobre |
|---|---|
| Endereços distintos não colapsam em uma identidade | `test_global_usage_keeps_the_same_offset_in_different_segments_apart`, `test_reference_key_names_a_segment_only_location` |
| Offset/largura de `base+0x1c` sem tipo semântico | `test_recover_references_keeps_pairing_and_location_apart`, `test_global_usage_preserves_each_access_without_inventing_a_type` |
| Larguras diferentes na mesma base não provam uma declaração C | `test_global_usage_preserves_each_access_without_inventing_a_type`, `test_global_usage_never_merges_duplicate_accesses` |
| Localização zero-filled continua `INFERRED` | `test_load_location_reports_the_segment_offset_and_zero_fill`, `test_reference_key_names_a_segment_only_location` |
| Pares provados preservados; só-ordem continua inconclusivo | `test_matching.py::test_conditional_control_flow_keeps_order_pairing_inconclusive`, `test_global_usage_keeps_unkeyable_references_visible` |
| Artefatos diferentes não viram equivalentes | `test_undefined_symbol_requires_an_explicit_original_binary_mapping`, `test_an_unverified_symbol_link_is_an_assertion_not_a_proof` |
| Referências não resolvidas não desaparecem | `test_global_usage_keeps_unkeyable_references_visible`, `test_global_usage_orders_the_unresolved_references_too` |
| Ordenação e serialização determinísticas | `test_reference_report_groups_by_function_deterministically`, `test_global_usage_serialises_equivalent_permutations_identically` |
| Símbolos/relocations impedem falso `MATCHED` | `test_an_unverified_symbol_link_is_an_assertion_not_a_proof` e a suíte `test_matching.py` |
| ELF inválido não lê fora dos limites | `test_elf.py` |
| Representação C do bloco: tamanho `0xA4`, offsets, lvalues, nenhum acesso fora da região | `tests/test_decomp_shared_state.py` (8 testes, sem mídia) mais as verificações de layout executadas pelo compilador no header |
| Preservação dos resultados e das relocations de `0x634`, `0x508` e `0x704` | `test_real_mwccpsp_function_baselines` e `test_real_mwccpsp_func_00000508_certifies_every_word_but_relocation_identity` (WSL-only) |
| Referência a `0x84` na função `0x0` | `test_func_00000084_is_referenced_as_an_argument_by_func_00000000` |

Os testes de integração foram ampliados como pedido: as faixas do Ghidra exigem
o resultado **observado** (`EXACT` em região única para as três funções,
`NOT_FOUND` para `0x84`), `func_00000508` entrou em `REAL_MATCH_CASES` só depois
da compilação real, e a referência a `0x84` virou uma verificação objetiva sobre
o `datarefs` do PRX, em vez de uma afirmação em prosa.

| Métrica acumulada | Contagem |
|---|---:|
| Reconstruções C com compilação real | 15 |
| `MATCHED` comprovados | 7 |
| `INCONCLUSIVE` (sem diferenças comprovadas) | 8 |
| `NONMATCHING` | 0 |
| Funções `.text` sem fonte C | 1 (`func_00000084`, classificado) |

### Pendências para a SETO-DECOMP-012

1. **Símbolos de dados.** Nada pode chegar a `MATCHED` enquanto o módulo estiver
   `strip`ado: as seis localizações acima não têm identidade de objeto e o objeto
   candidato expõe apenas `D_...` indefinidos. O caminho é encontrar uma tabela de
   símbolos original (ou um artefato que a carregue) que cubra `0x4860`,
   `0x604860`, `0x604864`, `0x604918`, `0x604B18` e `0x604B9C`. Para o bloco
   `0x604864` há um passo adicional: mesmo com símbolos, a igualdade de objeto
   entre o PRX e o `ET_REL` compilado continua sendo uma asserção, não uma prova.
2. **Nomes reais dos imports.** As sete chamadas importadas das três fontes
   resolvem por `(library, NID)` (mais sete chamadas locais resolvidas por
   endereço); os nomes continuam desconhecidos enquanto a tabela exportadora não
   for recuperada.
3. **`func_00000084`.** A identidade permanece indeterminada: o endereço é
   passado como argumento por `func_00000000` e o uso posterior desse argumento
   não é conhecido. Só uma segunda referência de código (ou um metadado de
   linker) mudaria a leitura de "8 bytes `jr $ra; nop`" para uma função com
   corpo.
4. **Duas formas de fonte forçadas.** Tanto o ponteiro local de `0x634` quanto o
   ponteiro de palavra de `0x508` existem porque o `3.0.1 build 219` decide
   rematerializar o endereço sem eles. São declarações de ponteiro válidas e
   documentadas, mas continuam sendo *formas* e não semântica recuperada; se o
   compilador histórico (`2.4.1.01`) aparecer, vale reconferir se alguma delas
   deixa de ser necessária.

Nenhuma dessas pendências exige infraestrutura nova: as quatro se resolvem com
evidência externa (símbolos, compilador histórico, tabela de NIDs) ou com a
releitura dos mesmos relatórios.

## Matching semantics

Four outcomes are possible: `MATCHED`, `NONMATCHING`, `INCONCLUSIVE`, `BLOCKED`.
Two instruction streams are compared word by word:

* a word covered by no relocation must be byte-identical;
* a word covered by a relocation must carry the same relocation *type* and the
  same in-place *addend* on both sides, and must agree outside the bits the
  relocation can change (`R_MIPS_26` → `0x03FFFFFF`, `R_MIPS_HI16`/`LO16` →
  `0x0000FFFF`, `R_MIPS_32` → all bits);
* `R_MIPS_HI16`/`R_MIPS_LO16` are associated from relocation evidence, never
  adjacency alone. Shared symbol identity can pair several pending HI16 entries;
  when symbols are stripped, a bounded straight-line register-flow check can prove
  a relocated `lui` reaches the LO16-consuming instruction. It respects writes and
  unconditional control-transfer delay slots; a conditional transfer, unknown
  effect, or intermediate redefinition prevents that proof. Relocation-order
  fallback remains `INCONCLUSIVE`. A HI16 with no LO16 and an isolated LO16 both
  remain unresolved. Register flow proves *which instructions pair*, not the
  cross-artifact identity of the object they address;
* when both sides expose a symbol name, the names must match; when only one side
  does, the result is downgraded to `INCONCLUSIVE` — never silently accepted;
* `R_MIPS_32` and HI16/LO16 data references need artifact-qualified data
  resolvers. Without them they stay `INCONCLUSIVE`, even when the encoded
  addends or candidate symbol spellings happen to match;
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

### Calls: one reference, two encodings

A call is the one field that is legitimately encoded differently on the two
sides. A linked module stores the **address of the trampoline** it calls; a
compiled object stores a **symbol name**, because no address exists yet. Comparing
those literally would report a false `NONMATCHING` for every function that calls
an imported function.

`compare()` therefore takes an optional *call resolver*
(`seto.imports.resolve_call_target`) which is consulted **only** when the two
in-place targets differ, and which returns a proven identity or nothing:

* both sides resolve to the same `(library, NID)` → the word counts as matching,
  and the resolution is recorded in the result (`resolved_calls`) as evidence;
* both resolve, but to different identities → `NONMATCHING` (a call to the wrong
  stub can never match);
* either side cannot be resolved → `INCONCLUSIVE`, never `MATCHED`.

The resolver is authoritative only about what the *module* proves. An address is
accepted when the module's validated table claims it (and its bytes are a
trampoline), or when it lies inside the module's own code (then the identity is
the address itself, so a call to a sibling function can be compared without either
side pretending to know a name). Anything else — a gap between the two — has no
proven identity and stays `INCONCLUSIVE`.

### What a `MATCHED` claims

A compiled `ET_REL` object cannot be byte-identical to a linked module: the field
a relocation covers holds a symbol reference instead of an address. Every
`MATCHED` therefore carries an explicit `equivalence`:

* `binary equality of the compared range` — nothing had to be resolved;
* `function equivalence with canonically resolved relocations` — the instruction
  streams agree and every call resolves to the same proven identity.

`full binary equality after linking` is **never** claimed, because the pipeline
does not link: it compares the object as the compiler emitted it.

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
surrounded by a standard 0x10-byte frame. See `decomp/src/func_00000244.c` and
`decomp/include/sce_stubs.h`.

The four call targets are relocations, and each one now has a proven identity
taken from the module's own import tables — not from its provisional name:

| Call site | Trampoline | Library | NID | Stub index |
| --- | --- | --- | --- | --- |
| `0x24c` | `0x2edc` | `sceHttp` | `0x76D1363B` | 0 |
| `0x254` | `0x2f0c` | `sceHttp` | `0xF9D8EB63` | 6 |
| `0x25c` | `0x2ef4` | `sceHttp` | `0xD1C8945E` | 3 |
| `0x264` | `0x2f54` | `sceSsl` | `0x191CDEFF` | 0 |

Reproduce it with:

```powershell
py -3.12 -m seto imports `
    --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx `
    --function 0x244
```

The machine-readable report is committed at `decomp/imports/libhtml_view.json`
(regenerate it with `--out`; it is deterministic and uses POSIX paths).

Why this is a good first target:

* the call targets are **relocations**, so they are exact and cannot be guessed
  wrong — the failure mode "I picked the wrong function" is impossible;
* the imported identities are **confirmed by the module's own tables**, so the
  four calls are no longer hypotheses;
* the body has no data flow, so the C structure is unambiguous;
* it exercises the relocation-aware comparator on all three MIPS relocation
  types used by the module.

The reconstruction is complete and readable. At the SETO-DECOMP-005 checkpoint the
licensed compiler was not yet wired in, so no object file existed to compare and
the state was `BLOCKED` — never a match. Since the SETO-DECOMP-007 toolchain work
it compiles through wibo and matches 13/13 words (see the real compile baseline).
The *names* of the four imported functions are still unknown: the module stores
NIDs, not names, so a name would have to come from the exporting library's table
in another module. The declarations in `decomp/include/sce_stubs.h` therefore stay
keyed by address and carry the recovered `(library, NID)` in their comments.

The external-tool status is equally explicit. The bootstrap installed `splat`,
`m2c`, LLVM `objdump`, Ghidra 12.1.3 with `ghidra-allegrex` v21.4, and the REA
6.5.0 CLI into machine-local tool directories. Synthetic smoke tests prove
splitting, decompilation, ELF32 MIPS inspection, the Ghidra headless runtime, and
forced MIPS32/Allegrex language loads. The Ghidra integration test additionally
proves that the real `libhtml_view.prx` is automatically loaded as Allegrex. The
synthetic smoke report still labels `ghidra:prx` `BLOCKED`, because it deliberately
does not consume `private/`; the integration evidence is reported separately.
REA's MCP handshake succeeds, but that alone proves neither a configured native
analysis provider nor PSP-PRX support.

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
`INCONCLUSIVE`. The record it writes names the `equivalence` the match claims.

The script — not `seto match` — is what turns a `MATCHED` result into a *verified
decompilation*: it compiles, deletes any previous object, hashes the source and the
object it produced, compares exactly that object, checks that it did not change
during the comparison, and writes a JSON record with the status, compiler, flags,
hashes and function. A simulated compilation can therefore never be reported as a
real match.

### Compiler-flag hypothesis

The observed real matches used `-O4,p -sdatathreshold 0` with Metrowerks 3.0.1
build 219. That exact set is verified for `func_00000244`; it is not evidence that
the same compiler/flags reproduce the entire PRX or the historical compiler's
output:

* `-O4,p -sdatathreshold 0` — documented by `angelof-exe/ygo-tf-5-decomp`;
* `-O4,s -sdatathreshold 0` — suggested in the task text.

Both are recorded in `config/seto.toml` (`[match] flags` /
`alternative_flags`). `-O4,s -sdatathreshold 0` remains untested. A source is only
`MATCHED` for a flag set that the report records as actually reproducing the
bytes.

## Blocked items and why

| Item | Blocker | Unblock by |
| --- | --- | --- |
| Matching the historical compiler exactly | PRX `.comment` says 2.4.1.01; supplied compiler is 3.0.1 build 219 | obtain the historically matching licensed compiler, if available |
| Cross-artifact data identity in every data-dependent reconstruction (`func_000004B8`, `func_000006E4`, the SETO-DECOMP-010 `func_00000000`, `func_0000039C`, `func_00000414`, and the SETO-DECOMP-011 `func_00000634`, `func_00000508`, `func_00000704`) | no independent link from candidate data symbols to original objects; the PRX is stripped (`symbols: 0`) and manual JSON maps are assertions only | find original object/linker metadata or another independent artifact proving the link; until then every such function stays `INCONCLUSIVE` with 0 differences |
| Two forced source forms in the SETO-DECOMP-011 reconstructions | with a struct-typed local it is 3.0.1 build 219, not the source, that decides to reuse or rematerialise the block address, so `0x634` needs a local struct pointer and `0x508` a named word pointer to reproduce the words; both are valid C, but they are source *forms*, not recovered semantics | the historical compiler, or a future build whose address materialisation reproduces the words without the extra pointer declaration |
| Ghidra automatic selection for generic ELF32 MIPS `ET_REL` | this Ghidra build selects `MIPS:LE:64:64-32R6addr` for the synthetic object | use the validated MIPS32/Allegrex languages explicitly; retain the real-PRX integration check |
| Real *names* for the imported functions | the module stores NIDs, not names | read the exporting library's table from a module/firmware that has it |
| Identity of the two `func_000006E4` globals | SETO-DECOMP-007 proved the `0x600000` is the high half of a different address, so the three are distinct module-relative addresses; their *section* identity is still unproven because no named section covers them | find another reference to the same offsets, or an original object/symbol table that shows a section; until then they stay `INFERRED` |
| Python 3.11 run of the suite | no 3.11 interpreter in the development environment (`py -3.11` is unavailable); the suite was run on 3.12 | run `python -m pytest` on 3.11 (CI does, on Ubuntu and Windows) |
| REA native analysis / PSP PRX | MCP transport is connected, but no native provider or PRX analysis is demonstrated | configure/test a native provider separately; do not infer PRX support from MCP connectivity |

`seto toolchain` reports the exact state of every tool, so this table can be
re-derived rather than trusted.

## Next steps

1. Recover real *names* for the `(library, NID)` pairs from a module or firmware
   image that carries the exporting libraries' tables, and rename the declarations
   in `decomp/include/`. The seven imported calls resolved by the SETO-DECOMP-011
   reconstructions are the current inventory (the round's other seven calls are
   module-local and resolve by address).
2. Move the six shared `segment 0` locations (`0x4860`, `0x604860`, `0x604864`,
   `0x604918`, `0x604B18`, `0x604B9C`) from segment-only to section-backed
   resolution by finding a named section (or an original symbol table) that covers
   them; SETO-DECOMP-007 showed they are distinct module-relative addresses, so
   the open question is their section, not their relationship. `seto datarefs`
   plus `build/seto011/shared_state.py` are the regression check for that change —
   as soon as a location becomes section-backed, the corresponding functions can
   leave `INCONCLUSIVE` without weakening the comparator.
3. Revisit the two forced source forms (`0x634`'s local struct pointer and
   `0x508`'s named word pointer) if the historical compiler becomes available: the
   address materialisation they work around is a property of 3.0.1 build 219, not
   a claim about the original source.
4. Keep `func_00000084` classified until a second code reference or linker
   metadata appears; the single argument reference that `func_00000000` makes is
   now pinned by `test_func_00000084_is_referenced_as_an_argument_by_func_00000000`.

## SETO-DECOMP-012 — Cross-Artifact Evidence and Matching Gap Audit

### Baseline reproduzido

A branch 012 parte da `main` que contém a SETO-DECOMP-011 (`92e6369`). O baseline
continua com **15 reconstruções C compiladas**, 7 `MATCHED`, 8 `INCONCLUSIVE`, 0
`NONMATCHING`; `func_00000084` continua classificada, sem identidade funcional
comprovada. As oito funções inconclusivas foram recompiladas em WSL2 com
Metrowerks `mwccpsp 3.0.1 build 219`, wibo `1.2.0`, flags `-O4,p
-sdatathreshold 0` e o perfil local `config/wsl/seto.toml`. As 15 entradas de
`REAL_MATCH_CASES` também passaram pela compilação real em WSL2.

`seto functions` terminou com código 0. `seto datarefs` terminou com código **5**,
o resultado esperado para as seis referências inconclusivas; o JSON foi
preservado e parseado, sem ignorar erro de leitura/parsing. `scripts/global_usage.py`
reproduziu **15 localizações e 6 referências não agrupadas**; as seis são os
pareamentos dependentes de ordem em `func_00000704`.

### Matriz das 60 palavras

`build/seto012/matching-gaps.json` é o relatório detalhado ignorado pelo Git,
gerado por `scripts/audit_data_identity.py` a partir dos relatórios frescos de
`scripts/match_function.py`, `relocation_sites()`, `pair_hi16_lo16()`,
`recover_references()`, `DataTarget`, `DataIdentity` e `build_global_usage()`.
Cada par contém dois registros de palavra com endereço, bytes original/candidato,
relocation, campo afetado, símbolo do candidato (incluindo `shndx`/offset quando
definido), addends, destino/confiança original, limitação exata e resultado da
busca de identidade. Os índices vêm das limitações por palavra do comparador e
dos pares efetivamente localizados — **não** de `total_words - matching_words`.

| Função | Resultado reproduzido | Pares HI16→LO16 (índices de palavra) | Palavras pendentes |
|---|---:|---|---:|
| `0x0` | 7/13, `INCONCLUSIVE` | `1→5`, `2→6`, `3→8` | 6 |
| `0x39C` | 28/30, `INCONCLUSIVE` | `7→9` | 2 |
| `0x414` | 31/41, `INCONCLUSIVE` | `8→10`, `15→18`, `21→24`, `27→30`, `33→36` | 10 |
| `0x4B8` | 18/20, `INCONCLUSIVE` | `3→6` | 2 |
| `0x508` | 63/75, `INCONCLUSIVE` | `4→6`, `33→35`, `38→39`, `46→49`, `50→51`, `61→62` | 12 |
| `0x634` | 42/44, `INCONCLUSIVE` | `3→7` | 2 |
| `0x6E4` | 2/8, `INCONCLUSIVE` | `1→2`, `3→4`, `5→7` | 6 |
| `0x704` | 40/60, `INCONCLUSIVE` | `2→3`, `21→27`, `23→25`, `29→34`, `31→33`, `35→38`, `43→44`, `45→48`, `51→52`, `53→55` | 20 |
| **Total** | **231/291** | **30 pares distintos** | **60** |

Reconciliação: 231 palavras certificadas + 60 pendentes = 291; 8 funções
`INCONCLUSIVE`; zero divergências comprovadas e zero `relocation_issues`. São 24
pareamentos originais demonstrados por fluxo de registradores e **6**
`relocation-order` apenas em `0x704`; esses seis continuam `INFERRED`. A confiança
de pareamento não promove localização nem identidade: 9 destinos estão em seção
nomeada (`.text`/`.data`, localização `PROVEN`), 21 ficam apenas no segmento 0
zero-filled (localização `INFERRED`), e **nenhum** dos 30 pares tem identidade
entre os artefatos comprovada. A identidade candidata dos destinos de dados
continua ausente porque os símbolos `D_...` são indefinidos (`SHN_UNDEF`,
`shndx=0`) nos objetos compilados.

### Investigação de evidência independente

**`.data`, na ordem pedida.**

* `func_0000039C` referencia `.data+0x8`, uma tabela original de seis entradas
  `R_MIPS_32` que apontam para `.text+0x3D4`, `+0x3DC`, `+0x3E4`, `+0x3EC`,
  `+0x3F4`, `+0x3FC`. O objeto candidato tem uma tabela local em `.rodata+0`,
  seis relocations para `func_0000039C+0x38..+0x60`; todos os seis destinos
  relativos à função coincidem. As representações cruas não são iguais (uma é
  PRX linkado, a outra `ET_REL`) e não há símbolo original/mapa que ligue os
  objetos: **correlação estrutural e de conteúdo, não identidade**.
* `func_00000414` referencia `.data+0x20`; as sete entradas originais apontam
  para `.text+0x450`, `+0x468` e `+0x480` cinco vezes. O `.rodata+0` candidato tem
  as relocations correspondentes para `func_00000414+0x3C`, `+0x54`, `+0x6C` ×5.
  Também é uma correspondência de destinos relativos, não uma prova independente
  de que as duas tabelas são o mesmo objeto.
* As strings originais em `.data+0x3C`, `+0x68` e `+0x98` começam com `http`; o
  candidato usa símbolos externos `D_000047A4`, `D_000047D0` e `D_00004800` sem
  dados correspondentes. `func_000004B8` referencia `.data+0xC8`, cujo conteúdo
  original é `/PSP/SAVEDATA/\0`; `D_00004830` também é indefinido no objeto. O
  conteúdo original é verificável, mas não há bytes candidatos/link independente.

**Código e início do zero-fill.** `.text+0x34` e `.text+0x84` têm localização
`PROVEN`, mas os símbolos candidatos correspondentes estão indefinidos em
`func_00000000.o`. `func_00000034` ter seu próprio baseline `MATCHED` 20/20 é
evidência da comparação daquele corpo, não de um vínculo independente da
relocation indefinida em `func_00000000.o`; não foi convertido em `SymbolLink`.
`0x84` é passado como argumento, não chamado diretamente, e sua classificação
não prova identidade funcional. `segment 0 +0x4850` continua apenas `INFERRED`,
sem seção nomeada.

**Globais zero-filled.** `0x4860`, `0x604860`, `0x604864`, `0x604918`, `0x604B18`
e `0x604B9C` não pertencem a seção ELF nomeada. Os `D_...` candidatos são
indefinidos. `SetoObservedBlock` documenta uma representação C alinhada
consistente com os acessos a `0x604864`; não prova o objeto original nem cria uma
seção `.bss`.

**Artefatos locais delimitados.** `PARAM.SFO` identifica a extração como
`ULUS10136`, versão 1.03, *Yu-Gi-Oh!  GX Tag Force*; seu SHA-256 é
`ffabd23c4c6cc5a2be094cd28a4ab1b603cbb8551e60992637ce4c3b6495fc42`. Isso
contextualiza o pacote, mas não relaciona símbolos de objeto candidato aos
originais. `libhtml_view.prx`
tem SHA-256 `319901ff13bc9a44be29596bcb64e4c0c7333dad9fb36bdafceb8c2aed611f26`,
`.comment` `MW MIPS C Compiler (2.4.1.01)`, zero símbolos e nenhuma seção debug.
O PRX irmão `libtutoriallist.prx` tem SHA-256
`2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49`, o mesmo
`.comment`, zero símbolos/debug; seu único import table expõe `libehsys`/NIDs,
não símbolos de dados. `libadler.prx` (SHA-256
`dcb2765c0e99f18a326b62b7b1cbcf960d5e970c8b587e100cbf4d1457a841d1`) não tem
magic ELF e não foi decodificado. `EBOOT.BIN` (SHA-256
`9a5bbf89419b6ba13494318fce4adb6279d099bda54fbf40b9c2dc178b96809a`, assinatura
`~PSP`) não foi executado nem descriptografado. Não há mapa de linker, objeto
original ou arquivo de símbolos/debug nas entradas imediatas inspecionadas de
`PSP_GAME`, `USRDIR`, `gmodule`, `module` e `SYSDIR`.

`config/splat/libhtml_view.yaml` se declara gerado por `seto split`, e
`build/libhtml_view.ld` referencia `build/asm`/`build/assets`; ambos foram
descartados como outputs gerados, não como mapa original. Os relatórios `datarefs`
e de estado compartilhado também são projeções do mesmo PRX, não uma terceira
fonte independente. Busca delimitada: nenhum artefato local autenticado foi
encontrado que prove o vínculo candidato↔original. Não foi criada associação
verificada, resolução manual ou `verified=True`.

O campo `evidence_search_status` separa a classificação da execução em
`NO_CANDIDATES`, `CANDIDATES_UNVERIFIED` e `VERIFIED_EVIDENCE`. Este último é
somente um estado conceitual: o script não implementa verificador independente e
**nunca** o emite. Na busca delimitada efetivamente executada para este PR, o
resultado é `NO_CANDIDATES` (`candidate_count = 0`) nas entradas imediatas
inspecionadas. Se um `.map`, `.o`, `.elf`, `.sym`, `.dbg`, `.pdb` ou `.dwo` surgir
ali, a saída passa a `CANDIDATES_UNVERIFIED`, lista diretório/nome em ordem
determinística e informa que presença/extensão não autentica origem, versão ou
identidade. Outputs Seto/Splat são listados separadamente como gerados e não
entram como candidatos independentes. Em ambos os estados,
`independent_identity_verified` e `independent_cross_artifact_link_found` ficam
`false`, e nenhum vínculo é promovido.

### Status individual e hashes das compilações

Os estados e resultados não mudaram: as oito funções continuam
`INCONCLUSIVE`, sem diferenças comprovadas. SHA-256 completos das compilações
frescas em WSL2 (Source / Object):

| Função | Source SHA-256 | Object SHA-256 |
|---|---|---|
| `func_00000000` | `f6cf2a5fef789d48360302af89c24638eee9c28db8c9320499da50d8c30965fb` | `e5aa6a69ed1fd6ceb01c3445bace376e841fcdfde497735ccb7f883ed8bfa543` |
| `func_0000039C` | `7d00c468822426f875ea366c9bc89714b20740e72a0c6e78eff3645695e69b89` | `776f161be72d985a3eef836141d45263ede9a991867a74699c9ac56cffbc09fd` |
| `func_00000414` | `90dd395c4bf06d01f21bcafe0cc8985774b9b6f05b9bf9c97eb19b34526832af` | `31ccca3915dd0339ebc9afe9579e6c313d4f406238cb70ea19364401ffc73e2a` |
| `func_000004B8` | `71b84bca92e2f2fd084e0a4a18849a6c7bc169e07faf856d9d808068bf52e9a8` | `17cce92e8424bfded12b9ee4a26363ec7ac19c36f8bf795af02d05a22904425f` |
| `func_00000508` | `1395bb35360c75cd0ea41373036f781b164ee8ad3d77d6ce0075d7c746e7fe08` | `870d430533321b28541dcce4ad859515362ba693225348f177d206996adae791` |
| `func_00000634` | `f784efc3d772ad54df6128cfdfa4e8248b11f6533a8aac52a9db0de6fd79782e` | `1505c2cf3756867f0a0448dbcf6db5c7b1bf3c06606e8458753ef9ab3aedda0a` |
| `func_000006E4` | `b2bf0dd2231cb5e5b08e7d4f2228a173d17235b75bd3c4e8f1df120acd11fd92` | `bf50e17cb96392886ad483b6383a05cb3d9b93639974cb00322f26b1b228fee3` |
| `func_00000704` | `d541eedf6a206f96c30869697c2e089987c4c0d0580c68a6da9f9069796623d5` | `f3d36449bf372d194197e6b4d7f31ca8b6317fa0232d502c04fabad7984df65f` |

### Implementação, regressões e bloqueios para a 013

`scripts/audit_data_identity.py` é uma projeção somente-leitura dos relatórios e
APIs atuais; não muda `matching.py`, `elf.py`, `psp_reloc.py`, `datarefs.py`, as
fontes C ou a semântica de `SymbolLink`. Antes de consumir cada relatório, valida
função/endereço/status, propriedades do baseline, os caminhos esperados de fonte
e objeto e ambos os SHA-256 gravados. Arquivo ausente, caminho de outra função,
hash inválido ou fonte/objeto alterado interrompe a auditoria com `ParseError`;
`elf.parse()` só recebe o objeto depois dessas verificações. As observações das
jump tables reutilizam os mesmos objetos ELF já validados, sem segunda leitura.
Esses hashes verificam consistência local relatório↔arquivo; **não autenticam** o
relatório, o compilador nem a relação com o artefato original. A opção
`--reproduce` continua chamando `scripts/match_function.py`, que remove qualquer
`.o` anterior antes de compilar, e os relatórios recém-gerados passam pelas
mesmas verificações.

`tests/test_audit_data_identity.py` tem **16 casos**: os quatro testes existentes
de índices, mais 12 casos para fonte/objeto corretos, adulteração dos dois
arquivos detectada antes do parse, arquivos ausentes, hash ausente/malformado,
relatório de outra função e busca vazia/com um ou vários candidatos. Os testes de
candidatos afirmam ordenação, mensagem coerente, classificação sempre não
verificada e exclusão dos outputs Seto gerados. Os testes existentes continuam
cobrindo links não verificados, destinos zero-filled e pareamento por ordem;
nenhum verificador de identidade foi criado.

Bloqueios concretos para a SETO-DECOMP-013: obter mapa de linker, objetos ou
metadados de debug originais autenticados e compatíveis com a versão, além de
provar a correspondência inequívoca de cada símbolo candidato (incluindo seção,
offset, intervalo e relocations). Para zero-fill, também é necessário evidenciar
qual seção/objeto cobre os endereços, sem fabricar `.bss`. Até isso existir,
**manter 231/291 certificados e 60 pendentes; os oito resultados continuam
`INCONCLUSIVE`**. Não promover por nome, addend, endereço numérico ou bytes de
tabela coincidentes.

### Testes, gates e reprodutibilidade

`tests/test_audit_data_identity.py` acrescenta quatro testes puros: usa somente
limitações sintéticas, não lê `private/`, e verifica que a projeção seleciona
índices reais, ignora limitações de pareamento que não são de identidade e rejeita
duplicatas/índices fora do intervalo. Os testes existentes que protegem a decisão
de identidade foram reutilizados: `test_equal_numeric_pairs_without_object_identity_stay_inconclusive`,
`test_two_artifacts_answering_the_same_offset_are_not_equal`,
`test_two_artifacts_answering_the_same_pair_offset_are_not_equal`,
`test_an_unverified_symbol_link_is_an_assertion_not_a_proof` e
`test_match_data_reference_with_an_unverified_map_stays_inconclusive`. Nenhum
verificador novo ou framework ABI foi criado.

| Gate | Resultado |
|---|---|
| Auditoria unitária (`tests/test_audit_data_identity.py`) | 16 passaram |
| Windows / `pytest -q` | 520 passaram, 19 ignorados |
| Windows / `pytest -m integration -q` | 23 passou, 17 ignorados |
| WSL2 / `pytest -m integration -q` | 37 passou, 3 ignorados; 15 `REAL_MATCH_CASES` preservados |
| `compileall -q src scripts tests` | clean |
| `seto verify` | ISO status OK (SHA-256 `FB22D0F06BB9F45A2D0EFF0EF66D541E61210599105037063DB60421E1A3C906`) |
| `git diff --check` | clean (aviso LF→CRLF do checkout Windows, sem whitespace error) |
| Regeração independente da matriz | 231/291, 60 palavras, 30 pares e hashes source/object idênticos |

Executado a partir da raiz do repositório no WSL2:

```bash
PYTHONPATH=src python3 scripts/audit_data_identity.py \
  --reproduce \
  --config config/wsl/seto.toml \
  --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx \
  --build-dir build/seto012 \
  --out build/seto012/matching-gaps.json
```

Isso regenera o inventário, os relatórios, as oito compilações frescas e a
matriz. A opção chama os scripts versionados já existentes, sem `shell=True`;
`match_function.py` remove cada objeto anterior antes de compilar. `build/seto012/`
continua ignorado, sem PRX, ISO ou objetos no commit. Nenhum código de
`src/seto/matching.py`, `src/seto/datarefs.py`, `src/seto/elf.py` ou
`src/seto/psp_reloc.py` foi alterado.

**Validação de integridade.** A execução sem `--reproduce` sobre os relatórios
existentes aceitou os oito pares fonte/objeto e preservou os 30 pares e as 60
palavras. `--reproduce`, em diretório novo, compilou as mesmas oito fontes e
produziu os mesmos Source/Object SHA-256. Em uma cópia temporária dos relatórios e
objetos, o objeto de `func_00000000` foi alterado sem atualizar o registro; a CLI
falhou explicitamente antes de `elf.parse()` com `object SHA-256 mismatch` (exit
1; expected `e5aa6a69…`, actual `80c23d24…`). Os testes também cobrem alteração
da fonte, arquivo ausente, hash inválido e relatório de outra função. O hash do
JSON não é prova externa de autenticidade; a verificação só garante consistência
entre o relatório local e os arquivos que serão consumidos.

Na busca real desta execução, `evidence_search_status = NO_CANDIDATES` e
`candidate_count = 0`. A árvore sintética com `symbols.map`/objetos dá
`CANDIDATES_UNVERIFIED`, lista os nomes de forma determinística e continua com
`independent_identity_verified = false` e zero `verified_symbol_links_created`.
Nenhum desses arquivos é tratado como `VERIFIED_EVIDENCE` por sua extensão ou
presença.

## SETO-DECOMP-013 — Auditoria de cobertura integral e reprodutibilidade

### Baseline reproduzido

A branch 013 parte da `main` com a SETO-DECOMP-012 (`c586ad4`). Nenhum novo
`MATCHED` foi buscado, nenhuma reconstrução nova foi escrita e a investigação de
símbolos da 012 não foi repetida. O baseline permanece: 15 fontes C compiladas, 7
`MATCHED`, 8 `INCONCLUSIVE`, 0 `NONMATCHING`, `func_00000084` classificada sem
identidade funcional provada, e 231/291 palavras certificadas com 60 pendentes.

A auditoria é uma projeção somente-leitura montada sobre as mesmas APIs públicas já
existentes: `mips.find_functions`, `imports.build_import_table`/`call_references`,
`psp_reloc.psp_inventory`, `split.build_layout`/`validate_layout` e os relatórios de
`datarefs`. Não foi criado parser, matcher, disassembler nem verificador de
identidade. O relatório fica em `build/seto013/module-audit.json` (ignorado pelo
Git).

### Cobertura das 509 palavras

`scripts/audit_module_coverage.py` fatia `.text` em intervalos de função e prova,
por tiling, que são contíguos, alinhados e cobrem exatamente `[0x0, 0x7F4)` =
509 palavras em 16 intervalos. Cada intervalo recebe no máximo uma fonte C canônica
(`decomp/src/func_XXXXYYYY.c`) ou uma classificação explícita.

- `text.total_words = 509`, `text.interval_count = 16`, `text.c_sources = 15`,
  `coverage_status = PASS`.
- 1 fragmento classificado sem fonte: `func_00000084` (`0x84`–`0x8C`, 2 palavras),
  `CLASSIFIED_WITHOUT_C_SOURCE`, `functional_identity = UNKNOWN`. Essas são as 2
  palavras não reconstruídas.

### Status de matching preservado

| Resultado | Funções | Palavras |
|---|---:|---:|
| `MATCHED` | 7 | 216 |
| `INCONCLUSIVE` | 8 | 291 (231 certificadas + 60 pendentes) |
| `NONMATCHING` | 0 | 0 |
| Classificado sem fonte | 1 | 2 |
| **Total** | **16** | **509** |

Nenhuma palavra `INCONCLUSIVE` foi promovida. Os 60 índices pendentes vêm da
projeção da 012 (`scripts/audit_data_identity.py`), não de
`total_words - matching_words`; a auditoria confere, palavra por palavra, que os 15
relatórios recompilados continuam casando com `REAL_MATCH_CASES`.

### Imports, chamadas, stubs e relocations

- 72 call sites dentro de `.text`: 50 resolvem para imports (libehsys, sceHttp,
  sceSsl, sceUtility, sceNet, sceNetInet, sceNetResolver, sceNetApctl), 22 para
  funções locais do módulo e 0 sem identidade.
- 1268 imports em 8 bibliotecas; `.sceStub.text` tem 2536 palavras = 1268
  trampolins de 8 bytes.
- 181 relocations PSP: 72 `R_MIPS_26`, 49 `R_MIPS_32`, 30 `R_MIPS_HI16` e 30
  `R_MIPS_LO16`. A soma dos grupos por seção-alvo reconcilia com 181 e cada
  registro individual é preservado (inclusive duplicatas). `psp_inventory` marca
  `complete = true`, sem tipos desconhecidos ou omitidos.

### Layout do PRX: dados inicializados e zero-fill

- 25 seções, 14 alocadas; as 13 arquivo-suportadas mapeiam para o único `PT_LOAD`
  como `FILE_BACKED`.
- `.bss` é `SHT_NOBITS` com tamanho 0 — **não** cobre os globais zero-filled.
- O `PT_LOAD` tem `p_filesz = 0x4850` e `p_memsz = 0x604C10`: `[0x0, 0x4850)` é
  arquivo-suportado e `[0x4850, 0x604C10)` é zero-fill. Os spans são calculados
  diretamente de `p_filesz`/`p_memsz`; nenhum byte `SHT_NOBITS` é lido.
- As 21 referências de dados em zero-fill ocorrem em 7 endereços distintos
  (`0x4850`, `0x4860`, `0x604860`, `0x604864`, `0x604918`, `0x604B18`, `0x604B9C`),
  consistente com a 012.
- `seto split` + `seto check-layout` terminam com código 0 (`layout_issues = []`).
- As classificações do Ghidra seguem `{'0x0': NOT_FOUND, '0x39c': MISMATCH,
  '0x84': NOT_FOUND}`, sem conversão em identidade.

### Reprodutibilidade

Executado a partir da raiz do repositório, em WSL2:

```bash
PYTHONPATH=src python3 scripts/audit_module_coverage.py \
  --reproduce \
  --config config/wsl/seto.toml \
  --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx \
  --build-dir build/seto013/full \
  --out build/seto013/module-audit.json
```

Saída: `audit=PASS text_words=509`. Duas execuções consecutivas produziram
`build/seto013/module-audit.json` byte a byte idêntico, SHA-256
`108ae293355bf9ed84302a0e754461bfe6c2cd4227fe0b8cb359d389d8c1e653`.

`--reproduce` reaproveita os testes reais existentes em vez de recompilar por fora:

- os 15 `REAL_MATCH_CASES` são compilados uma única vez; cada `report.json` recebe
  `module_sha256` e é conferido contra `REAL_MATCH_CASES` (7/8/0 preservados);
- `seto imports`, `seto split` e `seto check-layout` regeneram os inventários;
- Splat e Ghidra rodam pelos testes de integração existentes. Como só passam no
  Windows, a tentativa WSL2 registra `BLOCKED` com o motivo (`splat is not
  installed` / `Ghidra is not configured`) e as evidências `PASS` `win32`
  persistidas por `SETO013_EVIDENCE_DIR` são mescladas: cada ferramenta externa
  fica `PASS` com **as duas** tentativas registradas. Um `FAIL` nunca é
  sobrescrito para `PASS`.

| Verificação externa | Resultado | Plataforma |
|---|---|---|
| `real_matches` (15 casos) | PASS | WSL2 (linux) |
| `splat` (`.text`/`.sceStub.text`) | PASS | win32 |
| `ghidra` (boundaries/decompilação) | PASS | win32 |
| `seto check-layout` | PASS | WSL2 |

Módulo auditado: SHA-256
`319901ff13bc9a44be29596bcb64e4c0c7333dad9fb36bdafceb8c2aed611f26`.

### Testes e gates

`tests/test_audit_module_coverage.py` tem **23 casos**, todos com dados sintéticos
(nunca `private/`): tiling contíguo; gap, overlap, intervalo vazio/desalinhado e
intervalo fora de `.text`; fonte C sem intervalo e intervalo sem fonte/classificação;
fragmento `0x84` aceito como classificação; reconciliação de contagens; relocation
agrupada não pode sumir nem deixar registro sem grupo; relatório consistente aceito;
relatório de outra versão de módulo rejeitado; `skip` vira `BLOCKED` e `failure`
vira `FAIL`; entrada ausente vira `BLOCKED`; JSON canônico não depende da ordem de
inserção. `tests/test_audit_data_identity.py` passa a 17 casos.

| Gate | Resultado |
|---|---|
| `compileall -q` (scripts/tests alterados) | clean |
| `tests/test_audit_module_coverage.py` | 23 passaram |
| `tests/test_audit_data_identity.py` | 17 passaram |
| Windows / `pytest -q` | 544 passaram, 19 ignorados |
| Windows / `pytest -m integration -q` | 23 passaram, 17 ignorados |
| WSL2 / `pytest -m integration -q` | 37 passaram, 3 ignorados |
| Auditoria `--reproduce` WSL2 | `PASS`, 509 palavras, idêntica em duas execuções |

### Bloqueios mantidos

A 013 não cria identidade nova. Sem mapa de linker, objetos ou metadados de debug
originais autenticados e sem correspondência inequívoca símbolo↔objeto, os 60
índices pendentes continuam pendentes e os 8 resultados seguem `INCONCLUSIVE`.
Nenhum nome, addend, endereço ou byte coincidente promove `SymbolLink` ou identidade
cross-artifact; o estado anterior é preservado exatamente.

### Endurecimento da auditoria (precedência e `datarefs`)

O endurecimento corrige duas falhas do relatório original, sem alterar o matching,
a cobertura, a reprodutibilidade nem as classificações conservadoras.

**1. Precedência `FAIL > BLOCKED > PASS`.** A decisão do veredito foi centralizada
em `overall_audit_status(baseline_checks, external_checks)` e é usada pelo
`_build_audit()`. Antes, o externo era avaliado primeiro, então uma ferramenta
indisponível (`BLOCKED`) podia mascarar um `FAIL` interno já comprovado. Agora todos
os estados dos dois lados entram numa única cadeia de precedência; conjunto vazio ou
estado desconhecido é erro (`ParseError`), nunca `PASS`. A decisão de precedência usa
apenas testes de pertinência (`in`) sobre os estados, sem valor padrão que transforme
ausência de evidência em aprovação. Demonstração real:
com `splat`/`ghidra` `BLOCKED` e um `FAIL` interno (projeção de pares pendentes), a
auditoria retorna `audit=FAIL` (código 3) em vez de `BLOCKED`; sem o `FAIL`, o mesmo
cenário continua `BLOCKED`.

**2. Comparação canônica integral de `datarefs.json`.** `_load_inputs()` passou a
reconstruir o relatório esperado com a API existente —
`datarefs.build_reference_report(module, ".text", [...])`, exatamente como o CLI
`seto datarefs` — e a exigir igualdade de `section`, `relocation_inventory` e
`functions` por meio de `validate_datarefs_report()`. Isso rejeita `instruction`,
`pairing`, `combined_addend`, `target`/`load_offset`, `location`/`status`, dados de
relocation, referência removida ou duplicada e ordem alterada **mesmo quando o
relatório declara o SHA-256 correto do PRX**. A checagem do `sha256` declarado é
mantida: ela prova a versão; a comparação canônica prova o conteúdo. Removido de
`_load_inputs()`: a construção manual de `expected_dataref_ranges`, o laço que só
conferia `start <= instruction < end` e a comparação separada de
`psp_reloc.psp_inventory(module)` — todos cobertos pela comparação integral.

**Testes.** `tests/test_audit_module_coverage.py` passa de 23 para **45 casos**: 7
parametrizados de precedência (incluindo `FAIL` + `BLOCKED` → `FAIL`),
vazio/estado inválido → `ParseError`, relatório íntegro aceito, 10 categorias de
adulteração rejeitadas sobre o relatório canônico real
(`build_reference_report` de um objeto sintético de `seto.synthetic`), ordem
alterada rejeitada, e `_load_inputs()` aceitando relatório íntegro e rejeitando
referência adulterada que mantém o SHA-256 do PRX.

**Baseline e determinismo.** Sobre dados íntegros e **sem** `--reproduce`, a
auditoria retorna `audit=PASS`, 509 palavras, e byte a byte o mesmo
`module-audit.json`
(`sha256 108ae293355bf9ed84302a0e754461bfe6c2cd4227fe0b8cb359d389d8c1e653`). A
reprodução completa em WSL2 (15 recompilações + fusão das evidências Splat/Ghidra
do Windows) produz o mesmo hash. Nenhum indicador mudou: 509/509 palavras, 16
intervalos, 15 fontes, 7 `MATCHED`, 8 `INCONCLUSIVE`, 0 `NONMATCHING`, 447
certificadas, 60 pendentes, 30 pares, 72 chamadas, 1268 imports, 181 relocations,
`0x84` classificado sem fonte.

| Gate (endurecimento) | Resultado |
|---|---|
| `tests/test_audit_module_coverage.py` | 45 passaram |
| `tests/test_audit_data_identity.py` | 17 passaram |
| `tests/test_datarefs.py` | 27 passaram |
| Windows / `pytest -q` | 566 passaram, 19 ignorados |
| Windows / `pytest -m integration -q` | 23 passaram, 17 ignorados |
| WSL2 / `pytest -m integration -q` | 37 passaram, 3 ignorados |
| `compileall -q src scripts tests` | clean |
| `seto verify` | ISO OK (`FB22D0F0…C906`) |
| `git diff --check` | clean (só avisos LF→CRLF) |
| Precedência `FAIL` + externo `BLOCKED` | `audit=FAIL` (exit 3) |
| `datarefs.json` adulterado (SHA-256 íntegro) | erro explícito, exit 1 |
| `--reproduce` WSL2 com endurecimento | `PASS`, `sha256 108ae293…d8c1e653` |

**Limitações remanescentes.** Splat/Ghidra continuam indisponíveis no WSL2; a
evidência `PASS` vem do Windows (`win32`) e as tentativas `BLOCKED` seguem
registradas. Sem prova independente de identidade, os 60 índices pendentes e os 8
`INCONCLUSIVE` permanecem inalterados.

## SETO-DECOMP-014 — Link-Time Equivalence Feasibility

**Resultado: `BLOCKED` por ausência de linker MIPS utilizável no ambiente
inspecionado.** O compilador produziu um candidato novo e o matching preservou o
baseline `INCONCLUSIVE` de `func_000004B8`; nenhuma linkedição foi executada, nenhum
endereço foi imposto e não há resultado pós-link. Ausência de ferramenta não é
evidência de incompatibilidade do objeto nem divergência de código.

### Inventário e diagnóstico reproduzível

| Ferramenta examinada | Versão/estado observado | Capacidade relevante comprovada |
|---|---|---|
| Metrowerks `mwccpsp` | 3.0.1 build 219, instalado | Compila o candidato MIPS/PSP; a instalação contém `mwccpsp.exe` e `LMGR8C.DLL`, sem `mwld` ou outro linker encontrado na árvore do toolchain. |
| `wibo` | 1.2.0, configurado | Executa o compilador Win32 em WSL2; não é linker. |
| GNU `ld` em WSL2 | Binutils 2.42 | `ld -V` lista apenas emulações x86-64/i386; `mips*-linux-gnu-ld` não está instalado. |
| GNU `ld.exe`/`ld.bfd.exe` em MSYS2 UCRT64 e MINGW64 | Binutils 2.46 | `-V` lista somente `i386pep`/`i386pe`; nenhum alvo MIPS. |
| LLVM em MSYS2 UCRT64 | 21.1.8 | `llvm-objdump` registra alvos MIPS/MIPSel e pode ser usado para análise; não há `ld.lld.exe`/`lld.exe` instalado. A presença de suporte MIPS no disassembler não prova capacidade de linkedição. |
| Pacote `binutils-mips-linux-gnu` no apt do WSL2 | Candidato 2.42-2ubuntu1cross5; não instalado | Não faz parte das ferramentas presentes e verificadas nesta rodada. Não foi instalado um novo toolchain para contornar o STOP obrigatório por ausência de ferramenta essencial. |

Verificações para reproduzir o diagnóstico, sem alterar o repositório:

```bash
# WSL2
command -v ld.lld lld mipsel-linux-gnu-ld mips-linux-gnu-ld
ld --version
ld -V
apt-cache policy binutils-mips-linux-gnu

# Windows / MSYS2 UCRT64
C:\msys64\ucrt64\bin\ld.exe -V
C:\msys64\ucrt64\bin\llvm-objdump.exe --version
```

Os comandos `-V` não apresentam emulação MIPS nos linkers encontrados. Portanto,
não existe executável elegível para o smoke test exigido (objeto MIPS sintético com
par HI16/LO16), e esse smoke test **não foi executado**. Não se conclui que GNU
MIPS binutils seria incompatível com o ET_REL Metrowerks: essa compatibilidade
continua **não testada**. Também não foi gerado `build/seto014/link-equivalence.json`,
pois não há um resultado de link a relatar.

### Compilação fresca e baseline observado

A compilação foi feita nesta rodada, sem reutilizar o objeto de execuções
anteriores. Nesta máquina, `python3` no comando abaixo corresponde ao ambiente
`/home/vinicius/.seto/venvs/seto008-test/bin/python` do WSL2:

```bash
PYTHONPATH=src python3 scripts/match_function.py \
  --config config/wsl/seto.toml \
  --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx \
  --function 0x4B8 \
  --source decomp/src/func_000004B8.c \
  --out build/seto014/f4b8 \
  --json
```

O comando terminou com código 5, o resultado normal para o baseline `INCONCLUSIVE`,
não com erro de compilação. Proveniência observada:

| Item | Valor |
|---|---|
| SHA-256 do PRX | `319901ff13bc9a44be29596bcb64e4c0c7333dad9fb36bdafceb8c2aed611f26` |
| SHA-256 de `func_000004B8.c` | `71b84bca92e2f2fd084e0a4a18849a6c7bc169e07faf856d9d808068bf52e9a8` |
| SHA-256 do objeto fresco `func_000004B8.o` | `17cce92e8424bfded12b9ee4a26363ec7ac19c36f8bf795af02d05a22904425f` |
| Compilador / loader / flags | Metrowerks 3.0.1 build 219 / wibo 1.2.0 / `-O4,p -sdatathreshold 0` |
| Matching original | `INCONCLUSIVE`, 18/20 palavras, 0 diferenças, 0 problemas de relocation, 4 chamadas resolvidas pelo comparador, 0 referências de dados resolvidas |

O objeto candidato é ELF32 `ET_REL`, little-endian, máquina MIPS R3000, flags
`0x10970001` (`noreorder`, `mips2`). Em `.rel.text` há seis entradas: `R_MIPS_HI16`
no offset de objeto `0x0C` e `R_MIPS_LO16` em `0x18`, ambas para o símbolo undefined
`D_00004830`; quatro `R_MIPS_26` para `func_00000894`, `func_00000854`,
`func_00002D0C` e `func_000008A4`. `.rel.mwcats` contém ainda um `R_MIPS_32` de
metadados para o símbolo definido `func_000004B8`. Os quatro endereços de chamada
que o comparador resolve no baseline são, respectivamente, `0x894`, `0x854`,
`0x2D0C` e `0x8A4`; essa resolução do matcher não é uma linkedição do objeto.

### Alcance probatório e próxima etapa

No PRX, as instruções originais em `0x4C4` (`lui $a1`) e `0x4D0`
(`addiu $a1,$a1,0x4830`) formam o par HI16/LO16 já associado pelo fluxo de
registradores. A referência original recuperada é `.data+0xC8`, VA `0x4830`; os
bytes nesse objeto de dados, no offset de arquivo `0x4890`, são `/PSP/SAVEDATA/`.
Isso prova o destino numérico e o conteúdo do PRX, não que o símbolo candidato
`D_00004830` seja a identidade do objeto/string original. O relatório atual ainda
registra zero dados resolvidos e mantém os dois words pendentes.

Não há instruções “depois do link”, endereço efetivo produzido pelo linker,
comparação pós-link, execução dos controles negativos `0x4830` versus `0x4834`,
nem teste positivo/negativo de linker nesta rodada. Não se atribuiu endereço a
`D_00004830` nem às chamadas e não se fabricaram stubs. Se uma futura rodada
obtiver um linker validado e impor essas definições, tal igualdade será
`ASSUMPTION_DEPENDENT`; atribuir `D_00004830 -> 0x4830` não estabelece identidade
independente. A diferença entre o endereço virtual escolhido para linkedição e a
base após carregamento do PRX, incluindo relocations de runtime, também terá de ser
tratada antes de comparar codificações como se ambas usassem a mesma base.

Assim, a conclusão desta investigação é **viabilidade não determinada** (não
`UNSUPPORTED`): não foi possível testar a compatibilidade do formato/ABI/relocations
Metrowerks com GNU MIPS binutils ou LLD porque nenhum linker MIPS estava disponível.
Não há evidência nova que altere os baselines 013: 7 `MATCHED`, 8 `INCONCLUSIVE`,
0 `NONMATCHING` e 60 words pendentes. Próxima ação técnica: disponibilizar e
autorizar uma instalação isolada de um linker MIPS real; primeiro executar o smoke
test HI16/LO16 com saída ELF e relocation efetivamente aplicada, e só então decidir
se o objeto Metrowerks pode ser linkado para este experimento. Mesmo se esse teste
passar, a identidade original de `D_00004830` continuará sem prova independente.

### Gates de repositório desta rodada

Estes gates verificam o estado do repositório; eles **não** substituem o smoke test
de linker, que permanece não executado pelo bloqueio acima.

| Gate | Resultado |
|---|---|
| Windows / `pytest -q` | 566 passaram, 19 ignorados |
| Windows / `pytest -m integration -q` | 23 passaram, 17 ignorados |
| WSL2 / `pytest -m integration -q` | 37 passaram, 3 ignorados |
| `compileall -q src scripts tests` | clean |
| `seto verify` | ISO OK (`FB22D0F0…C906`) |
| Linker smoke HI16/LO16 e controles `0x4830`/`0x4834` | Não executados: linker MIPS ausente; nenhum resultado afirmado |

### R2 — Controlled Link-Time Comparison

**Resultado operacional: `PASS`; comparação A: 20/20 words iguais sob endereços
controlados; alegação: `ASSUMPTION_DEPENDENT`.** Esta continuação usa o linker GNU
MIPSel validado na ENV-014, recompila o candidato neste próprio run e compara
literalmente os 20 words do ELF linkado com os bytes file-backed do PRX em
`.text[0x4B8:0x508]`. Não altera o comparador nem os relatórios oficiais de
matching.

#### Compilação fresca e proveniência

Comando reproduzível nesta configuração WSL2:

```bash
PYTHONPATH=src python3 scripts/probe_link_equivalence.py \
  --config config/wsl/seto.toml \
  --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx \
  --source decomp/src/func_000004B8.c \
  --build-dir build/seto014/r2/integration-real \
  --out build/seto014/link-equivalence.json
```

O script remove o objeto de saída local antes de invocar `scripts/match_function.py`;
esse último só compara depois de validar o exit code zero do compilador. A invocação
completa terminou em 5, que é o exit code esperado do matcher para `INCONCLUSIVE`.
O relatório JSON confirmou 18/20 words, zero diferenças e zero problemas de
relocation no baseline estrito.

| Artefato/parâmetro | Valor observado |
|---|---|
| PRX SHA-256 | `319901ff13bc9a44be29596bcb64e4c0c7333dad9fb36bdafceb8c2aed611f26` |
| Fonte C SHA-256 | `71b84bca92e2f2fd084e0a4a18849a6c7bc169e07faf856d9d808068bf52e9a8` |
| Objeto fresco SHA-256 | `17cce92e8424bfded12b9ee4a26363ec7ac19c36f8bf795af02d05a22904425f` |
| Linker script SHA-256 | `8d62c76a039a7fde59be6d80515610c7ce859aa9adb8cc29ae8eb023edceffaa` |
| GNU linker/emulação | GNU ld 2.42 / `elf32ltsmip` |
| Compilador/loader/flags | Metrowerks 3.0.1 build 219 / wibo 1.2.0 / `-O4,p -sdatathreshold 0` |

O objeto novo foi conferido como ELF32 little-endian MIPS `ET_REL`; contém o par
`R_MIPS_HI16`/`R_MIPS_LO16` para `D_00004830`, quatro `R_MIPS_26` de chamadas e
`.rel.mwcats` com `R_MIPS_32` para `func_000004B8`. Esse SHA coincide com o artefato
anterior porque o compilador reproduziu os mesmos bytes; o run atual removeu e
recriou o objeto e validou seu hash contra o registro de `match_function.py`.

#### Linkedição e comparação observada

O script temporário, gerado somente sob `build/seto014/`, fixa
`.text 0x4B8 : SUBALIGN(4)`, exige tamanho `0x50` e endereço do símbolo, mantém
`.mwcats` e verifica que apenas `.text` é executável. O linker não inseriu código,
stubs ou trampolins; o ELF de saída é ELF32 little-endian MIPS `ET_EXEC`, com 20
words e sem relocations remanescentes ou símbolos indefinidos. Os únicos símbolos
externos definidos para a linkedição foram:

```text
D_00004830      = 0x4830   (varia para B/C)
func_00000894   = 0x894
func_00000854   = 0x854
func_00002D0C   = 0x2D0C
func_000008A4   = 0x8A4
```

As quatro chamadas foram correlacionadas com entradas `libehsys` do import table
original (`0x894`/NID `0xEC6F1CF2`, `0x854`/`0x10F3BB61`, `0x2D0C`/`0x57018B7C`,
`0x8A4`/`0x476FD94A`). Os endereços fornecidos ao linker continuam sendo
**atribuições controladas** para o candidato, não prova de identidade dos seus
símbolos.

| Caso | Atribuição de `D_00004830` | Comparação literal com PRX | HI16/LO16 observado |
|---|---:|---:|---|
| A | `0x4830` | **20/20 iguais**, nenhuma diferença | HI `0x0000`, LO `0x4830`, efetivo `0x4830` |
| B | `0x4834` | **19/20 iguais**, word `0x4D0`: `0x24A54830` → `0x24A54834` | LO muda; o par, como unidade semântica, passa a apontar a `0x4834` |
| C | `0x8004` | **18/20 iguais**, words `0x4C4` e `0x4D0` diferem | HI `0x0001`, LO `0x8004`, signed LO `-32764`, efetivo `0x8004` |

O controle adicional copiou o objeto fresco e alterou somente o word não relocável em
`0x4B8` (`0x27BDFFD0` → `0x27BDFFD1`). A comparação detectou exatamente essa
diferença; o objeto original e a fonte C não foram alterados. O caso C valida carry,
não representa uma hipótese sobre o endereço real.

#### Coordenadas do PRX e alcance probatório

As APIs existentes do Seto confirmaram o par original em `0x4C4`/`0x4D0`, com
pareamento por fluxo de registradores, e o destino original `.data+0xC8`, VA
`0x4830`, offset de arquivo `0x4890`. Os 14 bytes foram lidos diretamente da seção
original e são `/PSP/SAVEDATA/`; nenhum dado foi copiado para o candidato. A
identidade entre o símbolo candidato `D_00004830` e esse objeto original continua
**não comprovada**.

As seis relocations PSP no intervalo (`HI16`, `LO16` e quatro `R_MIPS_26`) referem-se
ao segmento relativo 0. `psp_reloc.relative_base(..., load_base=0)` e
`apply_relocation()` registram apenas o modelo module-relative, que preserva os
words file-backed; isso não afirma que o módulo seja carregado em base zero. A base
real em runtime não foi inferida. Portanto, os 20/20 de A são uma comparação válida
dos bytes no arquivo sob o layout escolhido, mas **não demonstram equivalência de
runtime**. As relocations PSP não foram aplicadas uma segunda vez aos bytes
linkados.

O relatório canônico `build/seto014/link-equivalence.json` tem SHA-256
`ebffa9dcb227071c58f0e8e3d7fead35ad94544e060268a9e2ee56cf7ba098f6`. Duas execuções
frescas produziram JSONs byte a byte idênticos. O status estrito original permanece
`INCONCLUSIVE`; o resultado não usa `MATCHED`, `verified_decompilation=True`, nem
identidade verificada.

### Testes, gates e revisão da R2

| Gate | Resultado |
|---|---|
| `tests/test_probe_link_equivalence.py` | 18 passaram |
| WSL2 integração R2 (`SETO_LINK_EQUIVALENCE_REAL=1`) | 2 passaram; smoke GNU + compile/link/compare real e determinismo |
| Windows / `pytest -q` | 583 passaram, 21 ignorados |
| Windows / `pytest -m integration -q` | 23 passaram, 19 ignorados |
| WSL2 / `pytest -m integration -q` com opt-in real | 39 passaram, 3 ignorados |
| `compileall -q src scripts tests` | clean |
| `seto verify` | ISO OK (`FB22D0F0…C906`) |
| Auditoria global 013, saída separada em `build/` | `PASS`, hash inalterado `108ae293…d8c1e653` |

No `pytest -q` completo em WSL2 sobre este checkout montado pelo Windows, foram
observados 588 passes, 9 falhas e 8 skips. As falhas foram nos testes não alterados
`test_match_script::test_resolve_loaders_uses_wsl_configuration_and_preserves_spaces`,
cinco casos de `test_smoke.py`, um de `test_toolchain.py` que observou Wibo visível
neste WSL, e os dois testes POSIX de `test_toolchain_bootstrap.py` que receberam
scripts `.sh` com CRLF no checkout montado. Nenhum código ou configuração alheios à
R2 foi alterado para mascarar essas falhas. A suíte completa Windows passou; a CI
Ubuntu/Windows é registrada nos checks do PR.

**Test-Auditor:** não encontrou lacunas materiais após a revisão dos controles e
proveniência; confirmou que as atribuições não promovem identidade. A revisão foi
estática e não executou os artifacts independentemente. **Reviewer:** `APPROVE`;
após correção do offset do controle tamper, a ferramenta exige `.text` de `0x50`
bytes com o símbolo-alvo no offset zero e o teste verifica o ELF linkado negativo.

**Próximo passo técnico:** obter evidência independente que relacione
`D_00004830` ao objeto original (por exemplo, objeto/linker map ou metadados de
debug autenticados) e, para uma conclusão de runtime, o load base real usado pelo
PSP. Os 20/20 words sob as hipóteses atuais não bastam para avançar a classificação
estrita nem justificam ampliar esta rodada às outras funções.
