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
| `tests/test_probe_link_equivalence.py` | 27 passaram |
| WSL2 integração R2 (`SETO_LINK_EQUIVALENCE_REAL=1`) | 2 passaram; smoke GNU + compile/link/compare real e determinismo |
| Windows / `pytest -q` | 593 passaram, 21 ignorados |
| Windows / `pytest -m integration -q` | 23 passaram, 19 ignorados |
| WSL2 / `pytest -m integration -q` com opt-in real | 39 passaram, 3 ignorados |
| `compileall -q src scripts tests` | clean |
| `seto verify` | ISO OK (`FB22D0F0…C906`) |
| Auditoria global 013, saída separada em `build/` | `PASS`, hash inalterado `108ae293…d8c1e653` |
| CI GitHub Ubuntu / Python 3.11 e 3.12 | 4/4 checks passaram |
| CI GitHub Windows / Python 3.11 e 3.12 | 4/4 checks passaram |

No `pytest -q` completo em WSL2 sobre este checkout montado pelo Windows, foram
observados 597 passes, 9 falhas e 8 skips. As falhas foram nos testes não alterados
`test_match_script::test_resolve_loaders_uses_wsl_configuration_and_preserves_spaces`,
cinco casos de `test_smoke.py`, um de `test_toolchain.py` que observou Wibo visível
neste WSL, e os dois testes POSIX de `test_toolchain_bootstrap.py` que receberam
scripts `.sh` com CRLF no checkout montado. Nenhum código ou configuração alheios à
R2 foi alterado para mascarar essas falhas. A suíte completa Windows passou; a CI
Ubuntu/Windows do PR #13 passou integralmente (8/8 checks).

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

**Hardening local dos artefatos R2:** `scripts/probe_link_equivalence.py` agora
valida `build` e `build/seto014` antes de resolver a raiz; symlinks existentes ou
quebrados e arquivos no lugar de diretórios são rejeitados. A raiz ausente é aceita
sem criação pelo helper. `_validate_arguments`, linkedição, inspeção, gravação de
relatório e o tratamento de erro usam o helper único. Se a raiz for inválida, o
erro original vai para stderr com exit não zero e o programa não tenta gravar
relatório ali nem escolhe outro destino.

Os testes cobrem raiz real/ausente, symlinks externos/quebrados em ambos os níveis,
arquivos nos caminhos de raiz e uma chamada pelo fluxo de `main()` com sentinela
externa intacta e nenhuma escrita redirecionada. O experimento R2 permanece
determinístico e com o mesmo SHA-256; nenhum teste altera o PRX ou o objeto fonte.
Essas verificações protegem contra redirecionamentos já existentes na árvore local;
**não** alegam proteção contra alterações concorrentes (TOCTOU) do filesystem.

O output dos logs `seto-toolchain.stdout.txt`/`.stderr.txt` agora usa
`_write_build_text()`: symlinks preexistentes para cada arquivo são rejeitados e
arquivos regulares legítimos continuam sendo gravados. A gravação redundante
posterior de `controlled-link.ld` foi removida; o script é criado uma vez através
do helper protegido.

Neste hardening: `tests/test_probe_link_equivalence.py` passou 31/31 em Windows e
WSL2; a suíte Windows passou 597 testes (21 skips), a integração Windows passou
23/19 e a integração WSL2 R2 passou 39/3. A suíte WSL2 completa teve 601 passes,
9 falhas e 8 skips; são as mesmas falhas ambientais já descritas acima e não
envolvem os caminhos alterados. Reviewer: `APPROVE`;
Test-Auditor: sem bloqueios, revisão estática. CI Ubuntu/Windows Python 3.11/3.12
do commit `a895c35` passou 8/8.

## SETO-DECOMP-015 — Jump-Table and Initialized Data Equivalence

**Resultado operacional: `PASS`; comparação A: 30/30 words de código e 6/6
entradas da jump table iguais sob endereços controlados; alegação:
`ASSUMPTION_DEPENDENT`.** O experimento estende a linkedição controlada da
SETO-DECOMP-014 para o código *e* os dados gerados pelo compilador para
`func_0000039C`. Ele recompila a função neste próprio run, monta a `.rodata`
gerada pelo Metrowerks e o código em `.text` com GNU MIPSel, e compara ambos
literalmente com as regiões correspondentes do PRX original. Não altera o
comparador, o parser ELF/relocation, as reconstruções C nem as classificações; o
status estrito original permanece `INCONCLUSIVE`.

### Compilação fresca e proveniência

Comando reproduzível nesta configuração WSL2 (`python3` = ambiente
`/home/vinicius/.seto/venvs/seto008-test/bin/python`):

```bash
PYTHONPATH=src python3 scripts/probe_jump_table_equivalence.py \
  --config config/wsl/seto.toml \
  --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx \
  --source decomp/src/func_0000039C.c \
  --build-dir build/seto015/experiment \
  --out build/seto015/jump-table-equivalence.json
```

O script remove o objeto de saída antes de invocar `scripts/match_function.py`;
só compara depois de validar exit code 5 (`INCONCLUSIVE`) do matcher, 28/30
words, zero diferenças e zero problemas de relocation no baseline estrito.

| Artefato/parâmetro | Valor observado |
|---|---|
| PRX SHA-256 | `319901ff13bc9a44be29596bcb64e4c0c7333dad9fb36bdafceb8c2aed611f26` |
| Fonte C SHA-256 | `7d00c468822426f875ea366c9bc89714b20740e72a0c6e78eff3645695e69b89` |
| Objeto fresco SHA-256 | `776f161be72d985a3eef836141d45263ede9a991867a74699c9ac56cffbc09fd` |
| Linker script A / B SHA-256 | `bb24d72b97a49deb8195383e6fc478781ba3e086fb6e029d3bdbdac13f9e784e` / `5632ead40c9dc3c1efa4d87dd1cef791ec6fe5a74e4c7379ded621cf52e555a5` |
| GNU linker/emulação | GNU ld 2.42 / `elf32ltsmip` |
| Compilador/loader/flags | Metrowerks 3.0.1 build 219 / wibo 1.2.0 / `-O4,p -sdatathreshold 0` |

O objeto fresco é ELF32 `ET_REL` little-endian MIPS, `ET_REL`. `.text` tem `0x78`
bytes (30 words) e `.rodata` tem `0x18` bytes (6 words). As relocations do objeto
são:

- `.rel.rodata`: seis `R_MIPS_32` para o símbolo definido `func_0000039C`, em
  offsets de seção `0x0,0x4,…,0x14`, com addends (words in-place)
  `0x38,0x40,0x48,0x50,0x58,0x60` (offsets relativos ao início da função);
- `.rel.text`: `R_MIPS_26` no word 2 (`0x3A4`) para o símbolo externo
  `func_00002364`; `R_MIPS_HI16` no word 7 (`0x3B8`) e `R_MIPS_LO16` no word 9
  (`0x3C0`) para o símbolo local `@13` (`STT_OBJECT` em `.rodata`, tamanho 24).

Esses seis addends foram re-validados contra o baseline registrado nesta rodada,
sem construir o resultado a partir deles: o vínculo é conferido no ELF linkado.

### Linkedição controlada e comparação observada

O linker script gerado sob `build/seto015/` fixa `.text 0x39c : SUBALIGN(4)`,
exige tamanho `0x78`, exige `ADDR/SIZEOF(.rodata)` e o símbolo no endereço; a
`.rodata` recebe um endereço **atribuído** (`0x4770`, e `0x4774` no controle B).
`.mwcats` é preservada e só `.text` é executável. A única definição externa
fornecida ao linker é `func_00002364 = 0x2364`, derivada da stub original
(`libehsys`, NID `0x31454993`) — uma **atribuição controlada**, não prova de
identidade.

| Caso | `.rodata` | Resultado literal vs PRX |
|---|---:|---|
| A | `0x4770` | **30/30 words e 6/6 entradas iguais**; par HI16/LO16 reconstrói `0x4770`; `R_MIPS_26` aponta `0x2364` |
| B | `0x4774` | **29/30 words**; só o word `0x3C0` muda (`0x24634770` → `0x24634774`); as entradas da tabela **não** mudam |

As entradas da tabela linkada coincidem com as relocations `R_MIPS_32` do próprio
objeto aplicadas ao `.text` posicionado (`0x39C + addend`); isso é uma
consistência necessária, não prova de proveniência por si só. A evidência de que o
linker consumiu a tabela do compilador é o inventário de relocations validado
(seis `R_MIPS_32` em ordem contra `func_0000039C`) somado à igualdade literal com
a tabela original: `0x3D4,0x3DC,0x3E4,0x3EC,0x3F4,0x3FC`.

### Controles negativos

| Controle | Manipulação | Detecção |
|---|---|---|
| A (baseline) | tabela `.rodata` em `0x4770` | 6/6 entradas nos corpos de `case` |
| B (layout) | `.rodata` movida para `0x4774` | só o word LO16 (`0x3C0`) muda |
| C (troca) | addends in-place das entradas 0 e 1 trocados em cópia do objeto | diferenças exatamente nas entradas 0 e 1; código inalterado (30/30) |
| D (endereço errado) | entrada 3 redirecionada para `0x3E0` (dentro de `.text`, fora dos `case`) | detectada na entrada 3; endereço não é um corpo de `case` |
| E (word não relocado) | bit flip no word 0 em cópia do objeto | detectada exatamente no word 0; tabela inalterada (6/6) |

C, D e E são adulterações **pré-link de uma cópia** do objeto; o script preserva e
reconfere o inventário de relocations (mesmos tipos/offsets/símbolos) antes de
linkar. Casos negativos adicionais são cobertos por testes unitários sintéticos:
ELF de arquitetura/tipo/endianness errados, `.rodata` ausente/tamanho errado,
contagem de relocations ≠ 6, tipo ≠ `R_MIPS_32`, símbolo inesperado, símbolos
indefinidos/relocations não consumidas no ELF linkado, seções executáveis extras,
symlink redirecionando a saída e divergência de hash de proveniência.

### Coordenadas do PRX e alcance probatório

As APIs existentes confirmaram o par HI16/LO16 original (`0x3B8`/`0x3C0`,
pareamento `PROVEN`, addend combinado `0x00004770`) e o destino `.data+0x8`, VA
`0x4770`, file offset `0x47d0`, com as seis entradas `0x3D4..0x3FC`. As seis
relocations PSP `R_MIPS_32` da tabela estão no segmento relativo 0; em
coordenadas module-relative (`psp_reloc.relative_base(..., load_base=0)` +
`apply_relocation`) os words aplicados coincidem com os bytes file-backed
(`0x3D4..0x3FC`). Isso registra o modelo de relocation e confirma os bytes, mas
**não** afirma base de carregamento zero nem aplica as relocations PSP ao ELF
GNU: `runtime_comparison = NOT_DEMONSTRATED`. A identidade de objeto entre o
candidato e o módulo original permanece **não comprovada**.

O relatório canônico `build/seto015/jump-table-equivalence.json` tem SHA-256
`6b38d24de1614ff1b54d518ef5aa49190207925198314038564c07caa84b554c`; duas
execuções frescas produziram JSON byte a byte idêntico. O status estrito original
permanece `INCONCLUSIVE`; `promoted_to_matched=false` e
`independent_identity_proven=false`.

### Reuso e hardening compartilhados

`scripts/probe_common.py` extrai apenas os helpers comprovadamente reutilizáveis:
execução controlada de processo (argv, timeout, sem `shell=True`), JSON canônico,
validação de ELF/símbolo indefinido, comparação literal de words, pareamento
HI16/LO16 efetivo e as proteções de caminho de build. `scripts/probe_link_equivalence.py`
passou a consumi-los por wrappers que preservam seus nomes/assinaturas públicos; a
suíte da 014 continuou passando 31/31 e o relatório canônico da 014 foi regenerado
com o **mesmo** SHA-256 `ebffa9dc…7ba098f6`. O novo experimento reutiliza os mesmos
controles de filesystem: rejeição de `build`/`build/seto015` como symlink
(existente, externo ou quebrado) e como arquivo, validação da raiz antes de
`resolve()`, confinamento da saída e ausência de caminho alternativo de escrita
após erro. **Não** alega proteção contra TOCTOU.

### Gates de repositório desta rodada

| Gate | Resultado |
|---|---|
| `tests/test_probe_jump_table_equivalence.py` | 39 passaram (Windows e WSL2) |
| `tests/test_probe_link_equivalence.py` | 31 passaram (Windows e WSL2) |
| Windows / `pytest -q` | 636 passaram, 23 ignorados |
| WSL2 integração GNU (objeto sintético) | 1 passou (`-k gnu`) |
| WSL2 015 real (`SETO_JUMP_TABLE_EQUIVALENCE_REAL=1`) | 2 passaram (GNU + compile/link/compare e determinismo) |
| WSL2 014 real (`SETO_LINK_EQUIVALENCE_REAL=1`) | 2 passaram |
| `compileall -q src scripts tests` | clean |
| `git diff --check` | clean |

A suíte completa WSL2 mantém apenas as falhas ambientais já descritas na 014
(`test_match_script`, `test_smoke`/`test_toolchain` de inventário e
`test_toolchain_bootstrap` POSIX com `.sh` CRLF no checkout montado); nenhum
teste ou módulo adicional foi alterado para mascarar essas falhas.

**Limitações e próximo passo.** A igualdade de código e tabela vale apenas sob o
layout imposto; a `.rodata` do candidato em `0x4770` é um posicionamento
experimental, não uma localização original recuperada. Não há demonstração de
recarregamento de runtime do PSP (a base de carga do módulo não está no arquivo)
nem prova de identidade entre o candidato e o original. A extensão a `0x414`
**não** foi tentada nesta rodada: exigiria novas hipóteses de layout/tabela e
infraestrutura não comprovadamente reutilizável, o que a própria especificação
coloca fora do escopo enquanto a identidade independente permanece sem prova.

**Revisão.** Reviewer: findings de severidade baixa resolvidos — a linguagem de
proveniência do cross-check `linked == .text + addend` foi reescrita como
consistência necessária (não prova por si só); os diretórios de teste passaram a
ser criados pelos guards compartilhados de build; e a cobertura unitária foi
ampliada (`.rodata` ausente/curta, seções executáveis extras, classe ELF errada,
layout `.text` errado e confinamento do `--out`). Test-Auditor: após os
acréscimos, a matriz requisito→teste não apresenta lacunas materiais; as
ausências restantes são de baixo risco e o script falha fechado.

## SETO-DECOMP-015-R2 — Divergence Reporting & Control Validation

**Resultado operacional: `PASS` inalterado; nenhuma evidência da 015 foi
reclassificada ou promovida.** Esta rodada resolve dois apontamentos da auditoria
final da 015 com correções pequenas e testes sintéticos de regressão, sem tocar
fontes C, o comparador estrito, os parsers ELF/relocation, as reconstruções C nem
`scripts/probe_common.py` / `scripts/probe_link_equivalence.py`.

### 1. Divergência real preservada (não substituída por `FAIL` genérico)

Antes, `run_experiment()` lançava `ProbeError("FAIL", …)` assim que o artefato A
diferia do original; o `main()` capturava a exceção e gravava um `_base_report()`
genérico, **descartando** os 30 words, as 6 entradas e as diferenças já
calculados. Agora a comparação é classificada explicitamente:

| Situação | `experiment_status` | `equivalence_claim` | Exit code |
|---|---|---|---|
| 30/30 words **e** 6/6 entradas | `PASS` | `ASSUMPTION_DEPENDENT` | `0` |
| Experimento válido com diferença de código e/ou tabela | `DIVERGENCE` | `DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS` | `3` |
| ELF/relocation/layout inválidos | `FAIL` / `UNSUPPORTED` (via `ProbeError`) | — | `1` |
| Ferramenta externa ausente | `BLOCKED` | — | `4` |

- `finalize_experiment_report(report)` é uma função pura que deriva a igualdade de
  `report["code"]`/`report["jump_table"]`, fixa status/alegação e devolve o exit
  code; o relatório é **gravado antes** de `run_experiment` retornar, então uma
  divergência nunca vira um relatório vazio.
- O código de saída de divergência (`DIVERGENCE_EXIT_CODE = 3`) reutiliza a
  convenção já documentada do repositório para "a verificação rodou e o resultado
  não é igual" (`seto.cli.EXIT_MISMATCH`), distinto de erro operacional (`1`) e de
  bloqueio (`4`).
- As diferenças continuam registradas em `code.differences` /
  `jump_table.differences`; `promoted_to_matched=false`,
  `independent_identity_proven=false` e `original_match_status="INCONCLUSIVE"`
  permanecem, com `PASS` falso impossível (a alegação de igualdade só existe sob o
  layout imposto).
- Os controles C/D/E **pressupõem** que A esteja íntegro e igual ao original. Quando
  o baseline diverge, eles **não são executados** e são registrados como
  `{status: "NOT_RUN", reason: "baseline comparison diverged", detected: false,
  promoted_to_matched: false}` (`not_run_controls()`), em vez de afirmar que
  passaram. Os controles de integridade estrutural (ELF inválido, relocation
  inconsistente, símbolo não resolvido, layout incompatível, par A→B que não
  muda só o word LO16) continuam falhando imediatamente como `ProbeError`.

### 2. Validação explícita do endereço do controle B

O controle B só provava que mover a `.rodata` produzia *alguma* diferença em
relação a A. `validate_layout_destination(baseline_words, moved_words,
assigned_address=…)` agora recomputa o destino efetivo das instruções linkadas com
o decodificador compartilhado `paired_effective_address` e **rejeita** um par que
reconstrua outro endereço: um par A→B que reconstrói `0x4778` (diferença no índice
esperado `9`, mas destino errado) falha com
`moved .rodata reconstructs 0x4778, expected 0x4774`. Um par HI16/LO16 inválido
(HI que não é `LUI`, LO que não consome o registrador) continua rejeitado pelas
validações já disponíveis. No run real, `variants["B"]
.hi16_lo16_effective_address == "0x4774"` e a reconstrução é `true`.

### Verificação

O relatório canônico da 015 permaneceu **byte a byte idêntico** (o caminho `PASS`
não mudou de forma): SHA-256 `6b38d24de1614ff1b54d518ef5aa49190207925198314038564c07caa84b554c`,
exit code `0`. Os arquivos `probe_common.py` e `probe_link_equivalence.py` não
foram alterados, então a 014 (relatório `ebffa9dc…7ba098f6`) e o comportamento
compartilhado seguem intactos.

| Gate | Resultado |
|---|---|
| `tests/test_probe_jump_table_equivalence.py` | 54 passaram (39 + 15 casos novos de R2) |
| `tests/test_probe_link_equivalence.py` | 31 passaram |
| Windows / `pytest -q` | 651 passaram, 23 ignorados |
| Windows / `pytest -m integration -q` | 23 passaram, 21 ignorados |
| WSL2 unit (015 + 014) | 85 passaram |
| WSL2 015 real (`SETO_JUMP_TABLE_EQUIVALENCE_REAL=1`) | 2 passaram (GNU + compile/link/compare, determinismo e controle B em `0x4774`) |
| WSL2 014 real (`SETO_LINK_EQUIVALENCE_REAL=1`) | 2 passaram |
| `compileall -q scripts tests` | clean |
| `git diff --check` | clean |

Os 15 casos novos cobrem: as quatro combinações 30/30×6/6, 29/30×6/6, 30/30×5/6 e
29/30×5/6 (classificação, exit code, campos preservados e escrita do relatório via
`finalize_experiment_report` + `_write_report`); o controle B positivo (`0x4774`),
negativo (diferença no índice `9` mas reconstrói `0x4778`, rejeitado) e par
HI16/LO16 inválido, inclusive propagado através de `validate_layout_destination`;
a forma literal de `not_run_controls()` (`NOT_RUN`/`detected=false`); que um layout
inválido continua falhando como `UNSUPPORTED`/`FAIL` (nunca `DIVERGENCE`); e que
`DIVERGENCE_EXIT_CODE` é o código de mismatch do repositório, distinto de `0/1/4/5`.

**Limitação de cobertura residual.** O gating dos controles C/D/E dentro de
`run_experiment` (o ramo `else: control_records = not_run_controls()`) e a
derivação de `false_positive_controls` são verificados por construção e pelos
testes de forma/nível unitário, **não** por um teste de pipeline completo: forçar
uma divergência real exigiria substituir compilador/linker/matcher e o parsing do
PRX. Os testes sintéticos fixam a forma exata do relatório divergente e o caminho
de finalização/gravação, mas não exercitam `run_experiment` de ponta a ponta
(fechada na R3, abaixo).

**Apontamentos de revisão resolvidos.** Reviewer e Test-Auditor (read-only) não
encontraram bloqueadores, major, regressões de segurança nem violações de escopo;
os achados menores aplicados nesta rodada foram: `false_positive_controls` passa a
ser derivado dos controles efetivamente executados (em divergência, `code=[]` e
`jump_table=["B"]`, já que B é sempre validado e C/D não rodam) em vez de anunciar
C/D/E que ficaram `NOT_RUN`; a forma de `not_run_controls()` passou a ser asserida
literalmente; e o controle B ganhou a verificação explícita do índice de diferença
e a cobertura do par inválido através do validador. A duplicação do literal `3`
(com o teste que o ata a `seto.cli.EXIT_MISMATCH`) e as duas noções de igualdade
(contagens vs listas de diferenças, que não podem divergir com os produtores
atuais) foram mantidas por serem fail-safe e mínimas.

**Limitações.** Uma divergência continua sendo um resultado do experimento sob o
layout imposto, não prova de identidade; `INCONCLUSIVE` não vira `MATCHED` e a
extensão a `0x414` segue fora de escopo. A suíte completa WSL2 mantém apenas as
falhas ambientais já descritas acima.

## SETO-DECOMP-015-R3 — Preserve Valid Jump-Table Divergences

**Resultado operacional: `PASS` inalterado; a 015 continua 30/30 words e 6/6
entradas no caso A, e o relatório canônico permanece byte a byte idêntico
(`6b38d24d…`).** A R2 já classificava `DIVERGENCE`, mas duas checagens anteriores
ainda rejeitavam tabelas **estruturalmente válidas** cujos valores diferiam do PRX
original, impedindo que a divergência chegasse ao relatório. Esta rodada separa
"invariante estrutural" de "igualdade histórica" nesses dois pontos, sem alterar
o resultado positivo nem a semântica do matcher estrito.

### 1. Removida a exigência de addends históricos no candidato

Em `run_experiment()` a condição
`addends != EXPECTED_OFFSETS or table_words != EXPECTED_OFFSETS → FAIL` foi
substituída por `validate_candidate_table_invariants(table_relocations,
table_words)`, que aceita qualquer tabela estruturalmente íntegra:

- `relocation.addend_valid` falso → `UNSUPPORTED`;
- addends que não batem com os words armazenados no objeto → `FAIL`;
- destino relativo desalinhado (`% 4 != 0`) ou fora de `[0, FUNCTION_SIZE)` → `FAIL`.

A quantidade, o tipo (`R_MIPS_32`), o símbolo (`func_0000039C`) e a ordem das seis
relocations continuam garantidos por `candidate_table_relocations()` (`.rodata`
presente, tamanho `0x18`, uma por entrada nos offsets `0x0..0x14`); não são repetidos
no helper de invariantes — apenas os testes de rejeição ganharam a asserção do status
`UNSUPPORTED`.

`EXPECTED_OFFSETS` permanece como referência histórica e alimenta o controle
negativo C; não é mais condição de igualdade do candidato. A sequência
`(0x38,0x40,0x48,0x44,0x58,0x60)` agora é aceita, linkada e identificada como
diferente.

### 2. Destino válido separado de destino historicamente equivalente

`validate_case_destinations(baseline_entries)` foi substituída, na checagem de
baseline, por `validate_structural_destinations(baseline_entries)`, que exige seis
entradas alinhadas e dentro de `.text[0x39C:0x414)`. `entry_destination_rows()`
segue como fonte de diagnóstico, preservando `inside_function` e
`matches_expected_case`; uma entrada como `0x3E0` (dentro da função, diferente do
`case` esperado `0x3EC`) passa a produzir a linha
`{inside_function: true, matches_expected_case: false}` — evidência de divergência,
não motivo para descartar o relatório. `validate_case_destinations()` foi mantida
intacta (ainda usada pelos testes de controle negativo), apenas deixou de ser
precondição de produção.

### 3. Propagação até o relatório final

A checagem de que o linker resolveu as **próprias** relocations do candidato
(`resolved_entries == baseline_entries → FAIL`) foi preservada. A partir daí o
fluxo R2 trabalha normalmente: `compare_table_entries()` acha as diferenças →
`baseline_equal=False` → controles C/D/E ficam `NOT_RUN` → controles estruturais e
o controle B continuam verificados → `finalize_experiment_report()` produz
`DIVERGENCE` → `_write_report()` grava tudo antes do retorno → exit code `3`. O
relatório preserva words originais/linkados, as seis entradas, diferenças,
relocations/addends, hashes e destinos efetivos.

### 4. Controles anunciados apenas quando executados

Em R2, `false_positive_controls` era derivado da **presença da chave** em
`control_records`; como `not_run_controls()` mantém as chaves `C`/`D`/`E`, um
relatório divergente anunciava `C`/`D`/`E` como evidência executada, embora
estivessem `NOT_RUN`. Agora o campo deriva dos controles cujo `detected` é verdadeiro,
de modo que uma divergência reporta `code.false_positive_controls=[]` e
`jump_table.false_positive_controls=["B"]` (B é o controle de layout sempre
validado), coerente com o mapa `controls` gravado. O relatório `PASS` permanece
idêntico (ali `C`/`D`/`E` de fato rodaram).

### Verificação e testes

| Gate | Resultado |
|---|---|
| `tests/test_probe_jump_table_equivalence.py` | 66 passaram (+12 de R3) |
| `tests/test_probe_link_equivalence.py` | 31 passaram |
| Windows / `pytest -q` | 663 passaram, 23 ignorados |
| Windows / `pytest -m integration -q` | 23 passaram, 21 ignorados |
| WSL2 unit (015 + 014) | 97 passaram |
| WSL2 015 real (`SETO_JUMP_TABLE_EQUIVALENCE_REAL=1`) | 2 passaram (A 30/30+6/6, B `0x4774`, C/D/E detectados) |
| WSL2 014 real (`SETO_LINK_EQUIVALENCE_REAL=1`) | 2 passaram (20/20, relatório canônico sem regressão) |
| Canonical 015 report | inalterado, sha256 `6b38d24de1614ff1b54d518ef5aa49190207925198314038564c07caa84b554c`, exit `0` |
| `compileall -q src scripts tests` | clean |
| `git diff --check` | clean |

Os 12 casos novos cobrem: tabela válida mas divergente (addend da entrada 3 de
`0x50` para `0x44`) com código 30/30, tabela 5/6, diferença exata na entrada 3
(`0x000003EC` → `0x000003E0`), `DIVERGENCE`, exit code `3`, controles C/D/E
`NOT_RUN`, `false_positive_controls` reduzido a `[]`/`["B"]` e sem promoção a
`MATCHED`; duas entradas divergentes preservadas de ponta a ponta;
`validate_structural_destinations` aceitando divergência válida e rejeitando
desalinhamento/fora-de-faixa/contagem errada; `validate_candidate_table_invariants`
aceitando a tabela divergente válida e rejeitando addend desalinhado, fora da
função, inconsistente com o word e inválido (`UNSUPPORTED`); resolução do linker
divergente dos addends → `FAIL`; contagens que contradizem as listas de diferenças →
nunca `PASS`; e o baseline 30/30 + 6/6 → `PASS` com A/B/C/D/E preservados,
`false_positive_controls` honesto e controle B recomputando `0x4774`.

**Caminho de ponta a ponta.** Pela primeira vez um teste unitário percorre
`run_experiment()` inteiro (comparação + montagem + gravação) usando **apenas
fixtures ELF sintéticas** e `monkeypatch` apenas nas bordas não sintetizáveis
(subprocesso do `match_function`, versões de toolchain, disponibilidade das
ferramentas GNU, a linkagem e os extratores de evidência do PRX
`_original_table_evidence`/`_original_call_evidence`/`_psp_region_relocations`).
Isso fecha a "limitação de cobertura residual" da R2; não há opção de CLI para
injetar objetos arbitrários na execução de produção.

**Preservações.** O matcher estrito e os parsers ELF/MIPS não foram tocados
(nenhuma mudança sob `src/`), então o baseline do audit 013 (7 `MATCHED`, 8
`INCONCLUSIVE`, 0 `NONMATCHING`, 60 words pendentes) segue válido por construção;
não foi reexecutado nesta rodada. `probe_common.py` e a 014 permanecem intactos. A
suíte WSL2 completa mantém apenas as falhas ambientais já descritas.

## SETO-DECOMP-016 — Multi-Reference Link & Data Equivalence

**Resultado operacional: `PASS`; comparação A: 41/41 words de código e 7/7
entradas da jump table iguais sob layout e símbolos controlados; alegação:
`ASSUMPTION_DEPENDENT`.** O experimento estende a linkedição controlada das
rodadas 014 e 015 para `func_00000414` (`0x414–0x4b8`, 164 bytes, 41 words), a
função com referências combinadas mais rica entre as que apontam apenas para
dados inicializados file-backed: uma jump table `.rodata` de 7 entradas (com o
offset `0x6c` repetido nas entradas `2..6`), cinco pares `R_MIPS_HI16`/`R_MIPS_LO16`
(incluindo o símbolo compartilhado `D_000047D0` usado tanto no `case 1` quanto no
`default`), três regiões de strings ASCII terminadas em NUL em `.data` e cinco
chamadas `R_MIPS_26` para duas stubs importadas de `libehsys`. Não altera o
comparador estrito, os parsers ELF/relocation, as fontes C nem `probe_common.py` /
`probe_link_equivalence.py` / `probe_jump_table_equivalence.py`; o status estrito
original permanece `INCONCLUSIVE` (`31/41` words certificadas).

### Compilação fresca e proveniência

Comando reproduzível nesta configuração WSL2 (`python3` = ambiente
`/home/vinicius/.seto/venvs/seto008-test/bin/python`):

```bash
PYTHONPATH=src python3 scripts/probe_multi_reference_equivalence.py \
  --config config/wsl/seto.toml \
  --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx \
  --source decomp/src/func_00000414.c \
  --build-dir build/seto016/experiment \
  --out build/seto016/multi-reference-equivalence.json
```

O script remove qualquer `.o` e `match-record.json` anteriores antes de invocar
`scripts/match_function.py`, exigindo exit code `5` (`INCONCLUSIVE`), `31/41`
words certificadas, zero diferenças e zero `relocation_issues` antes de iniciar a
linkedição controlada.

| Artefato/parâmetro | Valor observado |
|---|---|
| PRX SHA-256 | `319901ff13bc9a44be29596bcb64e4c0c7333dad9fb36bdafceb8c2aed611f26` |
| Fonte C (`decomp/src/func_00000414.c`) SHA-256 | `90dd395c4bf06d01f21bcafe0cc8985774b9b6f05b9bf9c97eb19b34526832af` |
| Objeto fresco (`func_00000414.o`) SHA-256 | `31ccca3915dd0339ebc9afe9579e6c313d4f406238cb70ea19364401ffc73e2a` |
| Linker script A (`0x4788`) / B (`0x4784`) SHA-256 | `e8b8a88df3a3ebb3b799772bf3fcb65b96f4d27ae290a4256ba37d8dc8f325ab` / `5df31cbd0bf6f3f0620b89f7dd0a9a0e25288c28f1dc7ea11408d33d405cb838` |
| ELF linkado A / B SHA-256 | `ee79924454cfbb69e3ec494940525f78d43327f789c3350c738075cf9c799ef0` / `e18f895be61d4ab7945e5ca7f6dcfc072fe7020016c058ee2142176910a0f008` |
| Relatório canônico (`multi-reference-equivalence.json`) SHA-256 | `469865af2d6632ec0969a819c6eaff6b5fc87a2a36aa9061e498b34970647d35` |
| GNU linker/emulação | GNU ld (GNU Binutils for Ubuntu) 2.42 / `elf32ltsmip` |
| Compilador/loader/flags | Metrowerks 3.0.1 build 219 / wibo 1.2.0 / `-O4,p -sdatathreshold 0` |

O objeto fresco é ELF32 `ET_REL` little-endian MIPS com `.text` de `0xa4` bytes
(41 words), `.rodata` de `0x1c` bytes (7 words, símbolo local `@15` em offset
`0x0`, tamanho `28`) e `.mwcats` de `0x8` bytes:

- `.rel.rodata`: sete `R_MIPS_32` em offsets `0x0..0x18` contra o símbolo definido
  `func_00000414`, com addends in-place `0x3c, 0x54, 0x6c, 0x6c, 0x6c, 0x6c, 0x6c`
  (validados por invariantes estruturais sem hardcode de igualdade histórica na
  admissão do candidato);
- `.rel.text`: 15 relocations com addend in-place zero — cinco `R_MIPS_26` (word
  `3` para `func_00002354`; words `17, 23, 29, 35` para `func_000008A4`) e cinco
  pares `R_MIPS_HI16`/`R_MIPS_LO16` (`8->10` para `@15`, `15->18` para
  `D_000047A4`, `21->24` para `D_000047D0`, `27->30` para `D_00004800` e `33->36`
  para `D_000047D0`).

### Linkedição controlada, pares HI16/LO16 e chamadas

O linker script gerado sob `build/seto016/` posiciona `.text` em `0x414` (tamanho
`0xa4`), `.rodata` em `0x4788` no caso A (`0x4784` no controle B, tamanho `0x1c`)
e preserva `.mwcats` (`0x8` bytes). As cinco definições externas fornecidas via
`--defsym` são atribuições controladas derivadas das coordenadas observadas no PRX:

| Símbolo / seção | Endereço atribuído | Sítios na função (`word_index` / endereço) | Evidência no PRX original | Resultado linkado (caso A) |
|---|---:|---|---|---|
| `@15` (`.rodata`) | `0x4788` (layout) | `8->10` (`0x434->0x43c`) | `.data+0x20` (`0x4788`, file `0x47e8`), 7 words `R_MIPS_32` | `0x3c030000` / `0x24634788` → `0x4788`; 7/7 entradas `0x450, 0x468, 0x480×5` |
| `D_000047A4` | `0x47a4` (`--defsym`) | `15->18` (`0x450->0x45c`) | `.data+0x3c` (`0x47a4`, file `0x4804`), `case 0` | `0x3c050000` / `0x24a547a4` → `0x47a4` |
| `D_000047D0` (compartilhado) | `0x47d0` (`--defsym`) | `21->24` (`0x468->0x474`) e `33->36` (`0x498->0x4a4`) | `.data+0x68` (`0x47d0`, file `0x4830`), `case 1` e `default` | ambos os pares `0x3c050000` / `0x24a547d0` → `0x47d0` |
| `D_00004800` | `0x4800` (`--defsym`) | `27->30` (`0x480->0x48c`) | `.data+0x98` (`0x4800`, file `0x4860`), `cases 2..6` | `0x3c050000` / `0x24a54800` → `0x4800` |
| `func_00002354` | `0x2354` (`--defsym`) | word `3` (`0x420`) | stub `libehsys` NID `0x1F190478` em `0x2354` | `0x0c0008d5` (`jal 0x2354`) |
| `func_000008A4` | `0x8a4` (`--defsym`) | words `17, 23, 29, 35` (`0x458, 0x470, 0x488, 0x4a0`) | stub `libehsys` NID `0x476FD94A` em `0x8a4` | `0x0c000229` ×4 (`jal 0x8a4`) |

No caso A (`.rodata` em `0x4788`), **41/41 words de código e 7/7 entradas da jump
table são literalmente idênticos ao PRX**. No caso B (`.rodata` em `0x4784`),
**40/41 words e 7/7 entradas** coincidem: apenas o word `10` (`0x43c`, `LO16` da
tabela) muda de `0x24634788` para `0x24634784` (reconstruindo `0x4784`), enquanto
as 7 entradas da tabela permanecem `0x450, 0x468, 0x480×5`.

### Regiões de strings em `.data` no PRX original

O objeto candidato não contém bytes de string (`D_000047A4`, `D_000047D0` e
`D_00004800` são declarações `extern` indefinidas resolvidas por `--defsym`). O
experimento verifica diretamente no PRX original (sem copiar o conteúdo textual
bruto para o repositório nem para o JSON) que os três alvos provados em `.data`
estão dentro dos limites da seção, não se sobrepõem, são ASCII imprimível
terminado em NUL e correspondem aos cinco pares `HI16/LO16`:

| Símbolo candidato | Offset em `.data` (fim exclusivo) | VA / file offset | Bytes (sem / com NUL) | Pares `HI16->LO16` | SHA-256 sem NUL | SHA-256 com NUL |
|---|---|---|---:|---|---|---|
| `D_000047A4` | `0x3c` (`0x67`) | `0x47a4` / `0x4804` | 42 / 43 | `15->18` | `7b9aaf8792d178885891c3c614b20e3550ac98ea3cbde80a4d544921e59445b8` | `9f6c41eb3583eaf9e732248cac6336d303908cb3659995672ab1edbe5351813c` |
| `D_000047D0` | `0x68` (`0x95`) | `0x47d0` / `0x4830` | 44 / 45 | `21->24`, `33->36` (compartilhado) | `d37fbd796cb48b25d00c60c5dd369aa4312a4931b1c5d231311d339ac9d127e7` | `38a83bf45a8e9dff2011ce7341cbfb2754a16550f8989e185df345b6a621ab16` |
| `D_00004800` | `0x98` (`0xc5`) | `0x4800` / `0x4860` | 44 / 45 | `27->30` | `c196ecc3cb47ca326a8240e3bf75d98402bbcfa9691b58e69e3644f2aae88688` | `24d2091e4d4901a5a1eae76c487e1d5a31c24615c61ca49cce5b12a82a900e35` |

Em todos os três casos, `candidate_string_bytes_proven = false` e
`cross_artifact_identity = UNPROVEN`.

### Controles negativos A–E

| Controle | Manipulação | Resultado observado | Artefato / ELF SHA-256 |
|---|---|---|---|
| A (baseline) | `.rodata` em `0x4788` e `--defsym` nominais | 41/41 words e 7/7 entradas iguais | ELF `ee79924454cfbb69e3ec494940525f78d43327f789c3350c738075cf9c799ef0` |
| B (layout `.rodata`) | `.rodata` movida para `0x4784` | 40/41 words (só word `10` em `0x43c` muda, reconstruindo `0x4784`); 7/7 entradas inalteradas | ELF `e18f895be61d4ab7945e5ca7f6dcfc072fe7020016c058ee2142176910a0f008` |
| C (símbolo compartilhado) | `D_000047D0` reatribuído de `0x47d0` para `0x47d4` via `--defsym` | 39/41 words: mudam **exatamente** os dois `LO16` compartilhados nos words `24` (`0x474`) e `36` (`0x4a4`), ambos reconstruindo `0x47d4`; `D_000047A4`, `D_00004800` e as 7 entradas da tabela permanecem intactos | ELF `397f2024ef4ccf87159693a4ecb0c04a4449965663091fbea7a861d5abdac2e6` |
| D (troca na tabela) | addends in-place das entradas `0` (`0x3c`) e `1` (`0x54`) trocados em cópia pré-link do `.o` | diferenças exatamente nas entradas `0` e `1` (`0x468, 0x450`); código 41/41 inalterado; inventário de relocations preservado | `.o` `148539c3d7a89a0356f737ad22bbc13aaf246d6b15b44c0286d669bc44e4bdee` / ELF `6be7cf6fb04a0f5226b42f2c05cf5e92aca8a3a4dd553572624ab9d5df8d6720` |
| E (word não relocado) | bit 0 invertido no word `0` (`0x27bdfff0` → `0x27bdfff1`) em cópia pré-link do `.o` | diferença exatamente no word `0` (`0x414`); 7/7 entradas inalteradas; inventário de relocations preservado | `.o` `9d01c2b7c72fbc8fe443e366d334a6920384b6bd0e8ae1b8c2461b1bd7da78dc` / ELF `0bebc3d275f0782218bd2ba3b2efaeb1e8e890a1adad7f006b9d8b26d8184814` |

O pipeline preserva toda a semântica introduzida nas rodadas 015-R2 e 015-R3:
divergências estruturalmente válidas de código ou tabela retornam `DIVERGENCE`
(exit code `3`, `equivalence_claim = DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS`),
gravam os controles C/D/E como `NOT_RUN` e anunciam em `false_positive_controls`
apenas os controles efetivamente executados (`detected == True`).

### Alcance probatório, limitações e verificação

As 15 relocations PSP de `.text` e as 7 relocations PSP `R_MIPS_32` da tabela em
`.data+0x20` foram verificadas em coordenadas module-relative (`load_base=0`
apenas como modelo da representação em disco); `runtime_comparison =
NOT_DEMONSTRATED`. A igualdade 41/41 e 7/7 vale **exclusivamente sob o layout e
as atribuições `--defsym` impostos**: não prova identidade independente entre os
símbolos candidatos (`@15`, `D_000047A4`, `D_000047D0`, `D_00004800`,
`func_00002354`, `func_000008A4`) e o módulo original, não prova bytes de string no
candidato e **não promove `func_00000414` de `INCONCLUSIVE` para `MATCHED`**
(`original_match_status = "INCONCLUSIVE"`, `promoted_to_matched = false`,
`independent_identity_proven = false`).

| Gate | Resultado |
|---|---|
| `tests/test_probe_multi_reference_equivalence.py` | 27 passaram (Windows e WSL2) |
| `tests/test_probe_jump_table_equivalence.py` | 66 passaram (Windows e WSL2) |
| `tests/test_probe_link_equivalence.py` | 31 passaram (Windows e WSL2) |
| Windows / `pytest -q` | 690 passaram, 25 ignorados |
| Windows / `pytest -m integration -q` | 23 passaram, 23 ignorados |
| WSL2 integração 016 (`SETO_MULTI_REFERENCE_EQUIVALENCE_REAL=1`) | 2 passaram (GNU sintético sem `private/` + Metrowerks/PRX real e determinismo) |
| WSL2 integração 014 + 015 + 016 reais | 6 passaram |
| Relatórios canônicos 015 / 016 | `6b38d24de1614ff1b54d518ef5aa49190207925198314038564c07caa84b554c` (inalterado) / `469865af2d6632ec0969a819c6eaff6b5fc87a2a36aa9061e498b34970647d35` (determinístico em 2 runs frescos); `probe_common.py` e 014 intocados |
| `compileall -q src scripts tests` / `git diff --check` | clean / clean |

## SETO-DECOMP-017 — Integrated Module Reconstruction & Link-Time Equivalence

**Resultado operacional: `PASS`; comparação A: 509/509 words de `.text` e 13/13
entradas de jump table em `.rodata` literalmente idênticos ao PRX sob layout e
símbolos controlados; alegação: `ASSUMPTION_DEPENDENT`.** O experimento conclui a
integração global de todo o módulo `.text` (`[0x0, 0x7F4)`, 2036 bytes, 509 words),
reunindo os 15 objetos candidatos compilados de C (`REAL_MATCH_CASES`), o
fragmento não-reconstruído em `0x84–0x8C` (`jr $ra; nop`), as duas jump tables
geradas pelo compilador em `.rodata` (`0x4770`, 13 entradas, 52 bytes), a resolução
cruzada de 22 chamadas locais entre os próprios objetos, 50 chamadas de importação
resolvidas via 35 stubs de biblioteca derivadas da tabela de imports do PRX, e 11
símbolos externos de dados (`D_...`). Não altera o comparador estrito, os parsers
ELF/relocation, as fontes C nem os probes anteriores (`probe_common.py`,
`probe_link_equivalence.py`, `probe_jump_table_equivalence.py`,
`probe_multi_reference_equivalence.py`); as 15 funções preservam rigorosamente seus
status originais (7 `MATCHED`, 8 `INCONCLUSIVE`).

### 1. Metodologia de reconstrução integrada e layout global

A compilação fresca de todas as 15 fontes C em `decomp/src/` é realizada
diretamente via Metrowerks 3.0.1 build 219 (`-O4,p -sdatathreshold 0`) sob wibo no
WSL2. O script `scripts/probe_integrated_module_equivalence.py` valida primeiro o
baseline individual de cada objeto contra `REAL_MATCH_CASES` (7 `MATCHED`, 8
`INCONCLUSIVE`), exigindo zero diferenças e zero `relocation_issues` antes de admitir
os objetos à linkagem integrada.

O layout de `.text` é particionado em 16 intervalos disjuntos e contíguos que cobrem
estritamente `[0x0, 0x7F4)`:

| Intervalo VA | Tamanho | Símbolo de entrada | Classificação | Status baseline | Relocations `.rel.text` no PRX |
|---|---:|---|---|---|---:|
| `0x000–0x034` | 52 B (13 w) | `func_00000000` | Reconstrução C | `INCONCLUSIVE` (7/13) | 7 (1 call, 3 HI/LO) |
| `0x034–0x084` | 80 B (20 w) | `func_00000034` | Reconstrução C | `MATCHED` (20/20) | 5 (5 calls) |
| `0x084–0x08C` | 8 B (2 w) | `func_00000084` | Fragmento original | `ORIGINAL_UNRECONSTRUCTED_FRAGMENT` | 0 |
| `0x08C–0x134` | 168 B (42 w) | `func_0000008C` | Reconstrução C | `MATCHED` (42/42) | 7 (7 calls) |
| `0x134–0x178` | 68 B (17 w) | `func_00000134` | Reconstrução C | `MATCHED` (17/17) | 6 (6 calls) |
| `0x178–0x244` | 204 B (51 w) | `func_00000178` | Reconstrução C | `MATCHED` (51/51) | 9 (9 calls) |
| `0x244–0x278` | 52 B (13 w) | `func_00000244` | Reconstrução C | `MATCHED` (13/13) | 4 (4 calls) |
| `0x278–0x358` | 224 B (56 w) | `func_00000278` | Reconstrução C | `MATCHED` (56/56) | 10 (10 calls) |
| `0x358–0x39C` | 68 B (17 w) | `func_00000358` | Reconstrução C | `MATCHED` (17/17) | 6 (6 calls) |
| `0x39C–0x414` | 120 B (30 w) | `func_0000039C` | Reconstrução C | `INCONCLUSIVE` (28/30) | 3 (1 call, 1 HI/LO) |
| `0x414–0x4B8` | 164 B (41 w) | `func_00000414` | Reconstrução C | `INCONCLUSIVE` (31/41) | 15 (5 calls, 5 HI/LO) |
| `0x4B8–0x508` | 80 B (20 w) | `func_000004B8` | Reconstrução C | `INCONCLUSIVE` (18/20) | 6 (4 calls, 1 HI/LO) |
| `0x508–0x634` | 300 B (75 w) | `func_00000508` | Reconstrução C | `INCONCLUSIVE` (63/75) | 18 (6 calls, 6 HI/LO) |
| `0x634–0x6E4` | 176 B (44 w) | `func_00000634` | Reconstrução C | `INCONCLUSIVE` (42/44) | 6 (4 calls, 1 HI/LO) |
| `0x6E4–0x704` | 32 B (8 w) | `func_000006E4` | Reconstrução C | `INCONCLUSIVE` (2/8) | 6 (0 calls, 3 HI/LO) |
| `0x704–0x7F4` | 240 B (60 w) | `func_00000704` | Reconstrução C | `INCONCLUSIVE` (40/60) | 24 (4 calls, 10 HI/LO) |
| **Total** | **2036 B (509 w)** | — | **15 C + 1 fragmento** | **7 M, 8 I, 0 NM** | **132 relocations `.text` (72 calls, 30 HI, 30 LO)** |

O fragmento `0x84–0x8C` é inserido diretamente no linker script com `. = 0x84; LONG(0x03E00008); LONG(0x00000000);` e o símbolo local `func_00000084 = 0x84;`, de modo que `func_00000000` (que toma o endereço `0x84` como argumento `$a1` para `libehsys`) resolve sua referência sem criar uma função C falsa. O fragmento é explicitamente classificado como `ORIGINAL_UNRECONSTRUCTED_FRAGMENT` e nunca recebe status `MATCHED`.

### 2. Resolução de chamadas locais, imports e dados externos

O módulo possui 72 chamadas `jal` (`R_MIPS_26`):
- **22 chamadas locais:** resolvidas pelo GNU linker através das definições reais dos símbolos exportados pelos 15 objetos candidatos no layout (por exemplo, `func_0000008C` chamando `func_00000134`, `func_00000178` chamando `func_00000244`, `func_00000278` chamando `func_0000008C`, `func_00000178` e `func_00000358`, `func_00000508` chamando `func_0000039C`, `func_00000414` e `func_000004B8`, e `func_00000704` chamando `func_00000278`, `func_00000508`, `func_00000634` e `func_00000358`).
- **50 chamadas de importação:** resolvidas via `--defsym` apontando para os 35 stubs de importação no segmento de stubs do PRX (`libehsys`, `sceUtility`, `sceHttp`, `sceSsl`, `sceNet`, `sceNetInet`, `sceNetResolver`, `sceNetApctl`).

Todas as 11 referências a símbolos de dados externos emitidos pelos candidatos (`D_000047A4`, `D_000047D0`, `D_00004800`, `D_00004830`, `D_00004850`, `D_00004860`, `D_00604860`, `D_00604864`, `D_00604918`, `D_00604B18`, `D_00604B9C`) são atribuídas via `--defsym` aos seus endereços correspondentes demonstrados no PRX.

### 3. Coexistência de Jump Tables em `.rodata` (`0x4770`)

As duas jump tables geradas pelo compilador são co-linkadas em uma única seção `.rodata` contígua iniciando em `0x4770` com tamanho total de `0x34` (52 bytes, 13 palavras de 32 bits):
1. **`func_0000039C` (`0x4770–0x4788`, 24 B / 6 entradas):** entradas `0..5` direcionadas a `[0x3D4, 0x3DC, 0x3E4, 0x3EC, 0x3F4, 0x3FC]`.
2. **`func_00000414` (`0x4788–0x47A4`, 28 B / 7 entradas):** entradas `0..6` direcionadas a `[0x450, 0x468, 0x480, 0x480, 0x480, 0x480, 0x480]`.

O linker script posiciona `*func_0000039C*(.rodata)` seguido imediatamente por `*func_00000414*(.rodata)`, reproduzindo a sequência exata de 13 entradas observada em `libhtml_view.prx`. Ambas as funções referenciam suas respectivas tabelas através de pares `R_MIPS_HI16`/`R_MIPS_LO16` que resolvem corretamente para `0x4770` e `0x4788`.

### 4. Controles Negativos A–E

| Controle | Manipulação | Resultado observado |
|---|---|---|
| **A (Baseline)** | Layout e símbolos nominais | **509/509 words de `.text` e 13/13 entradas de jump table iguais** |
| **B (Dados externos)** | `D_000047D0` alterado de `0x47D0` para `0x47D4` via `--defsym` | Mudança isolada exatamente nos 2 sítios `LO16` que consom `D_000047D0` em `func_00000414` (endereços `0x474` e `0x4A4`); 0 divergências na jump table |
| **C (Jump table)** | Addends in-place das entradas 0 e 1 de `func_00000414.o` trocados em `.rodata` | Diferença isolada nas entradas de índice global 6 e 7 da jump table (`0x4788` e `0x478C`); 0 divergências em `.text` |
| **D (Word não-relocado)** | Bit 0 invertido no word 0 de `func_00000034.o` (`0x27BDFFE8` → `0x27BDFFE9`) | Diferença isolada no endereço `0x34` (word 13 do módulo); 0 divergências na jump table |
| **E (Chamada local cruzada)** | Chamada local em `func_0000008C.o` mutada de `func_00000134` para `func_00000244` | Diferença isolada no sítio de chamada `0x118` (instrução muda de `jal 0x134` para `jal 0x244`); 0 divergências na jump table |

Todos os controles B, C, D e E confirmam a sensibilidade e especificidade da sonda: nenhuma mutação escapa e nenhuma causa falsos positivos em regiões não relacionadas.

### 5. Proveniência e Parâmetros da Execução

| Artefato / Parâmetro | Valor / Hash |
|---|---|
| PRX SHA-256 | `319901ff13bc9a44be29596bcb64e4c0c7333dad9fb36bdafceb8c2aed611f26` |
| Linker script (`build/seto017/integrated.ld`) SHA-256 | `015f10cce6f726eab12661e09639b1e8af98ffd82e3aaa65cd10413af193317a` |
| ELF linkado integrado SHA-256 | `4488ae63d41071d0b30bb2a62888bf4f73809633e25b3991207e9d722d42aa52` (**obsoleto**; ver correção na seção SETO-DECOMP-017-R2, valor reproduzido `6b447e5e4c543a1cf55db84c8d8f9b48140a71fbf19695fd627bdb2bb935d239`) |
| Relatório canônico (`integrated-module-equivalence.json`) SHA-256 | `7a3ddf01ee9d8d683b5ec960931d40fa7e4bd5c197a2ef58719f0cc319c96556` (determinístico e idêntico em execuções repetidas) |
| Compilador / Loader / Flags | Metrowerks 3.0.1 build 219 / wibo 1.2.0 / `-O4,p -sdatathreshold 0` (forma da 017; a 017-R2 passa a derivar dos 15 registros: `mwccpsp.exe` / `wibo` / mesmas flags) |
| Linker / Emulação | GNU ld (GNU Binutils for Ubuntu) 2.42 / `elf32ltsmip` |

### 6. Limites Epistemológicos e Probabilidade Científica

1. **Ausência de promoção:** Nenhuma das 8 funções classificadas como `INCONCLUSIVE` foi promovida a `MATCHED` (`original_match_status` preservado; `promoted_to_matched = false`).
2. **Identidade não-independente:** A equivalência em tempo de linkagem é demonstrada exclusivamente sob o conjunto controlado de layout e atribuições (`equivalence_claim = "ASSUMPTION_DEPENDENT"`, `independent_identity_proven = false`).
3. **Fragmento `0x84–0x8C`:** As duas palavras `0x03E00008` (`jr $ra`) e `0x00000000` (`nop`) permanecem classificadas como `ORIGINAL_UNRECONSTRUCTED_FRAGMENT`. O projeto não alega ter decompilado este fragmento como C.
4. **Comparação de runtime:** `runtime_comparison = "NOT_DEMONSTRATED"`. As asserções são restritas à equivalência estática dos bytes resultantes da linkagem em coordenadas module-relative.

### 7. Validação desta rodada

| Gate | Resultado |
|---|---|
| `tests/test_probe_integrated_module_equivalence.py` | 17 passaram (Windows e WSL2) |
| `tests/integration/test_integrated_module_equivalence_real.py` | 2 passaram (GNU sintético sem `private/` + Metrowerks/PRX real e determinismo) |
| `tests/test_probe_multi_reference_equivalence.py` | 27 passaram (sem regressão) |
| `tests/test_probe_jump_table_equivalence.py` | 66 passaram (sem regressão) |
| `tests/test_probe_link_equivalence.py` | 31 passaram (sem regressão) |
| Windows / `pytest -q` | 707 passaram, 27 ignorados |
| WSL2 suíte real 014 + 015 + 016 + 017 | 8 passaram |
| Standalone probe (`probe_integrated_module_equivalence.py`) | Exit code 0, canonical JSON emitido e verificado |
| `compileall -q src scripts tests` / `git diff --check` | clean / clean |

## SETO-DECOMP-017-R2 — Endurecimento Semântico Final

**Resultado operacional: `PASS`; a mesma comparação integrada (`509/509` words de
`.text` e `13/13` entradas de `.rodata` literalmente idênticas ao PRX) permanece;
alegação inalterada (`ASSUMPTION_DEPENDENT`); 7 `MATCHED`, 8 `INCONCLUSIVE`,
0 `NONMATCHING`.** Esta revisão fecha quatro lacunas objetivas apontadas pela
auditoria ao experimento 017 sem alterar a semântica estrita do matcher, as fontes
C, o comparador, os parsers ELF/relocation nem os probes anteriores. O ELF linkado
é **byte-a-byte idêntico** ao produzido pelo script em `a592e32` (confirmado
restaurando o script antigo sobre os mesmos objetos e comparando `sha256`), de modo
que nenhum byte do artefato observado mudou.

### 1. Reconciliação do inventário `R_MIPS_26` e resolução de chamadas

O inventário de chamadas deixou de ser um par de contagens constantes e passou a ser
reconciliado a partir das evidências efetivas:

- `collect_candidate_call_sites()` percorre os 15 objetos candidatos, coleta cada
  `R_MIPS_26` de `.text` e o mapeia ao endereço de módulo (início da função + offset
  de seção), exigindo que o sítio caia dentro da própria função, com addend in-place
  nulo, símbolo nomeado e sem sítios duplicados entre objetos, produzindo
  exatamente **72 sítios**.
- `reconcile_call_inventory()` exige que o conjunto de sítios dos objetos seja
  **idêntico** ao das 72 chamadas recuperadas do PRX (`set` simétrico) e, por sítio:
  - **chamada local:** o símbolo precisa ser uma função **definida** do módulo
    linkado (símbolo de `.text`), o alvo recuperado do PRX precisa coincidir com o
    endereço final do símbolo, e a instrução efetivamente linkada precisa ser um
    `jal` com `jump_target` igual a esse endereço;
  - **importação:** o símbolo `func_<stub>` precisa nomear exatamente o stub
    (`parse_function_name`), o stub precisa resolver na tabela de imports do PRX
    (`seto.imports.ImportTable.resolve`) devolvendo uma identidade
    `(library, NID)` definida e igual à da chamada do PRX, e o destino controlado
    (`--defsym`) precisa ser o próprio stub com a instrução `jal` correspondente.
- `validate_controlled_imports()` compara `CONTROLLED_IMPORTS` com o mapa derivado
  da tabela recuperada do PRX (`{func_<stub>: stub}` para as 50 chamadas de
  importação) e **rejeita entradas ausentes, excedentes ou incorretas** — os 35
  stubs declarados coincidem exatamente com os 35 stubs reais.

As linhas reconciliadas (sítio, tipo, símbolo, stub/alvo, biblioteca, NID, alvo da
instrução linkada) são emitidas em `calls.reconciled_call_sites`; nenhuma flag
booleana pré-definida substitui a verificação.

### 2. Preservação obrigatória de `.mwcats`

`validate_linked_structure()` agora **exige** a seção `.mwcats` e a associa aos
objetos que a produziram:

- ausência da seção, `size` incompatível (diferente de `15 × 8 = 0x78`) ou seção
  executável são rejeitadas;
- cada um dos 15 registros de 8 bytes é decodificado como
  `(size_bytes << 16) | tag` seguido de um ponteiro `R_MIPS_32` relocado, e precisa
  casar **com o objeto daquele índice**: `tag = 0x2`, `size_bytes` igual ao tamanho
  real da função e ponteiro igual ao endereço final da função.

Os 15 registros reais foram verificados contra o PRX (tag `0x2`, `size` idêntico ao
símbolo e ponteiro resolvido ao endereço do intervalo). Nada é reinterpretado como
código executável.

### 3. Finalização fail-closed

`finalize_experiment_report()` foi reescrita para rejeitar relatórios incompletos:
`{}`, ausência de `code`/`jump_table`, campos nulos, campos de tipo inválido
(`bool`/`str`), totais diferentes de **509 words e 13 entradas**, contagens iguais
fora da faixa e inconsistências entre `equal_*` e o tamanho das listas de diferenças
(`len(differences) == total − equal`) elevam `ProbeError("FAIL")`. Um relatório só
retorna `PASS` quando `equal_words == 509` e `equal_entries == 13` com listas de
diferenças vazias e coerentes; uma divergência genuína e completa preserva o exit
code `3` (`DIVERGENCE_EXIT_CODE`) e o relatório integral.

### 4. Proveniência e segurança

- `consistent_provenance()` extrai **compilador, loader, flags e includes dos 15
  registros reais** de `match_function.py`, exige que os 15 concordem
  (divergência → `FAIL`) e reduz caminhos absolutos a basenames
  (`mwccpsp.exe`, `wibo`), mantendo o JSON canônico sanitizado; nenhuma versão ou
  parâmetro é inventado como fallback.
- O JSON canônico passa a incluir caminho e `sha256` do **ELF integrado** e de
  **cada artefato linkado** (`variant-a` e os controles `control-b`…`control-e`),
  além do `sha256` do linker script.
- `prepare_build_file()` é chamado **antes do linker** para cada caminho de saída
  (inclusive os das variantes), rejeitando symlinks e saídas inesperadas.
- Duas execuções frescas completas produzem relatórios **idênticos** (inclusive os
  `sha256` dos ELFs), comprovando determinismo.

### 5. Limpeza

Removidos: o dicionário `func_symbols` não consumido, as cópias duplicadas dos
inventários de tabela (`table_relocs_39c/414`, `table_words_39c/414`), o bloco
`compiler_info` com parâmetros sintetizados, a invocação de `seto toolchain` usada
para sintetizar versões, os valores de retorno (`cmd_a`…`_cmd_e`) não utilizados de
`_execute_link`, as constantes `READELF`/`OBJDUMP`/`FILE` não referenciadas, a
verificação redundante de executabilidade de `.mwcats` (já coberta pelo invariante
de que apenas `.text` é executável) e o `import json` não usado nos testes.

### 6. Artefatos e hashes (R2)

| Artefato / Parâmetro | Valor / Hash |
|---|---|
| PRX SHA-256 | `319901ff13bc9a44be29596bcb64e4c0c7333dad9fb36bdafceb8c2aed611f26` |
| Linker script (`build/seto017/integrated.ld`) SHA-256 | `015f10cce6f726eab12661e09639b1e8af98ffd82e3aaa65cd10413af193317a` |
| ELF integrado (`build/seto017/links/variant-a/linked.elf`) SHA-256 | `6b447e5e4c543a1cf55db84c8d8f9b48140a71fbf19695fd627bdb2bb935d239` |
| Relatório canônico (`integrated-module-equivalence.json`) SHA-256 | `7a3ddf01ee9d8d683b5ec960931d40fa7e4bd5c197a2ef58719f0cc319c96556` |
| Compilador / Loader / Flags | `mwccpsp.exe` / `wibo` / `-O4,p -sdatathreshold 0` (derivados dos 15 registros) |
| Linker / Emulação | GNU ld (GNU Binutils for Ubuntu) 2.42 / `elf32ltsmip` |

> Correção de registro: o digest do ELF integrado anotado na seção 017 anterior
> (`4488ae63…`) estava obsoleto. O valor acima é o do link reproduzido, confirmado
> **idêntico** ao gerado pelo script em `a592e32` sobre os mesmos objetos.

### 7. Validação desta rodada (R2)

| Gate | Resultado |
|---|---|
| `tests/test_probe_integrated_module_equivalence.py` | 24 passaram (Windows e WSL2) |
| Regressões 014–016 (`test_probe_link/jump_table/multi_reference_equivalence.py`) | 124 passaram (31 + 66 + 27) |
| Probes 014–017 juntos | 148 passaram (31 + 66 + 27 + 24) |
| Integração GNU sintética (`tests/integration`, sem opt-in) | 41 passaram, 7 ignorados |
| WSL2 real 014 + 015 + 016 + 017 (opt-ins ligados) | 45 passaram, 3 ignorados |
| Windows `pytest -q` | 714 passaram, 27 ignorados |
| WSL2 `pytest -q` | 720 passaram, 12 ignorados, 9 falhas ambiente pré-existentes (`test_match_script`, `test_smoke`, `test_toolchain`, `test_toolchain_bootstrap`; arquivos não tocados, reproduzidas em worktree limpo do baseline) |
| Probe standalone (`probe_integrated_module_equivalence.py`) | exit code `0`, relatório canônico determinístico |
| `compileall -q src scripts tests` / `git diff --check` | clean / clean |

## SETO-DECOMP-017-R3 — Guarda de Caminho de Saída

**Resultado: `PASS` (inalterado); nenhum resultado científico mudou.** Fecha uma
lacuna objetiva de confinamento de escrita em `build/seto017/`.

### 1. Vulnerabilidade

Antes de invocar `match_function.py` por função, a sonda apagava os artefatos
antigos com `if obj_path.exists(): obj_path.unlink()` (e o mesmo para
`report_path`). Como `Path.exists()` segue symlinks, um symlink **quebrado** é
invisível para ele: o wipe não acontece, e `relative(report_path, REPO_ROOT)`
resolve o link para o seu alvo. Se o alvo estiver dentro do repositório, mas
fora de `build/seto017/`, o subprocesso grava o relatório nesse alvo — **fora
da árvore de build permitida** — e as verificações seguintes
(`report_path.is_file()` / `read_text()`) leem de volta através do link, de modo
que a fuga passa despercebida e o experimento ainda termina com sucesso.

Demonstração A/B (symlink quebrado para `<repo>/build/r3-escape-demo.json`):

| Versão | Exit code | Arquivo externo criado |
|---|---|---|
| `7216376` (pré-R3) | `0` (sucesso silencioso) | **sim** — `build/r3-escape-demo.json` |
| R3 | `1` (`FAIL`) | **não** |

### 2. Correção

Nova função `_wipe_stale_build_artifacts(paths, build_root)` reutiliza
`prepare_build_file()` (que rejeita symlink — quebrado ou não — via
`is_symlink()`, caminhos fora de `build_root` e não-arquivos regulares) **antes**
de `unlink(missing_ok=True)`. Ela é aplicada aos caminhos do objeto e do
relatório antes de `match_function.py`, exatamente como o idioma já usado pelos
probes 014 (`probe_link_equivalence.py:590-593`) e 016
(`probe_multi_reference_equivalence.py:1200-1204`). A recompilação fresca é
preservada (o arquivo regular obsoleto continua sendo removido).

### 3. Testes

- `test_wipe_stale_build_artifacts_rejects_broken_symlink_without_creating_target`: symlink quebrado → falha fechada, destino externo inexistente permanece inexistente.
- `test_wipe_stale_build_artifacts_rejects_when_the_report_path_is_a_symlink`: comprova a guarda do caminho vulnerável do relatório, antes de invocar o subprocesso.
- `test_wipe_stale_build_artifacts_rejects_valid_symlink_and_preserves_target`: symlink válido → rejeitado, alvo intacto.
- `test_wipe_stale_build_artifacts_removes_stale_regular_files_for_fresh_compilation`: objetos/relatórios regulares obsoletos → removidos; idempotente.
- `test_wipe_stale_build_artifacts_rejects_a_path_outside_the_build_root`: caminho fora de `build_root` → rejeitado.
- `test_wipe_stale_build_artifacts_rejects_a_directory_at_the_output_path`: diretório no caminho de saída → rejeitado.

### 4. Portões (R3)

| Gate | Ambiente | Resultado |
|---|---|---|
| `tests/test_probe_integrated_module_equivalence.py` | Windows & WSL2 | **30/30** |
| Suíte completa | Windows (`pytest -q`) | 720 passaram, 27 ignorados |
| Suíte completa | WSL2 (`pytest -q`) | 726 passaram, 12 ignorados, 9 falhas ambiente pré-existentes |
| Integração real 014 + 015 + 016 + 017 (opt-ins ligados) | WSL2 | 45 passaram, 3 ignorados |
| Relatório canônico / ELF integrado | WSL2 | `7a3ddf01…` / `6b447e5e…` (inalterados) |
| A/B com symlink quebrado para arquivo dentro do repositório | WSL2 | Pré-R3: `rc=0`, arquivo fora de `build/seto017/` criado; R3: `rc=1`, nenhum arquivo fora da árvore de build criado |
| `compileall -q src scripts tests` / `git diff --check` | Windows | clean / clean |

## SETO-DECOMP-018 — Baseline, Triagem e Primeiras Reconstruções de `libtutoriallist.prx`

**Módulo analisado:** `private/original/PSP_GAME/USRDIR/gmodule/libtutoriallist.prx`.
**SHA-256 recalculado:**
`2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49` (igual ao
hash fixado pela TASK). Nenhum arquivo de `private/` foi modificado; o PRX foi
somente lido pelas APIs Seto, GNU objdump e Ghidra.

### 1. Baseline estrutural real

`scripts/triage_libtutoriallist.py` reutiliza `elf.parse()`,
`mips.find_functions()`, `imports.build_import_table()` / `call_references()`,
`datarefs.build_reference_report()` e `split.build_layout()` /
`validate_layout()`. Não contém parser ELF, matcher ou linker próprios. O baseline
estrutural pode ser gerado **sem Ghidra** com `--baseline-only`. A triagem só é
produzida quando existe um relatório de limites validado. Os relatórios são
serializados com `canonical_json()` e escritos sob os guards de `probe_common.py`
em `build/seto018/`.

| Campo | Observação medida |
|---|---|
| ELF/PRX | ELF32 little-endian, MIPS `e_machine=8`, `ET_MIPS_PSP_PRX (0xFFA0)`, `e_entry=0`, `e_flags=0x10A23001` |
| Arquivo | 30 234 bytes (`0x761A`); SHA-256 acima |
| Seções / program headers / símbolos | 25 / 1 `PT_LOAD` / 0 (stripped) |
| `PT_LOAD` | `offset=0x60`, `vaddr=0`, `filesz=0x6190`, `memsz=0x6290` |
| `.text` | `offset=0x60`, VA `0`, `size=0x25B0` = 9 648 bytes = 2 412 words, executável e alinhado a 16 |
| `.sceStub.text` | VA `0x25B0`, size `0x26E8` = 9 960 bytes = 1 245 trampolines de 8 bytes |
| `.data` / `.bss` | `.data` VA `0x610C`, 164 bytes, quatro `R_MIPS_32`; `.bss` `SHT_NOBITS`, tamanho 0 |
| `.comment` | `MW MIPS C Compiler (2.4.1.01)` |
| Layout `split` | image delta `0x60`; sem gaps/sobreposições/erros de layout |
| Relocações PSP | 474 entradas parseadas; inventário `complete=true`, sem entradas inválidas/incompletas, compressed sections ou tipos desconhecidos |
| `.rel.text` | 451: 237 `R_MIPS_26`, 107 `R_MIPS_HI16`, 107 `R_MIPS_LO16` |
| Outras relocações | 23 `R_MIPS_32` em `.data`, `.lib.ent`, `.lib.stub`, `.rodata.sceModuleInfo`, `.rodata.sceResident` e `.rodata.sceVstub` |
| Chamadas `.text` | 237: **205 importadas**, **32 locais**, **0 unknown** |
| Imports recuperados | uma tabela `libehsys`, 1 245 stubs, sem limitações na tabela; nomes de função continuam address-derived |

`.rodata.sceResident` contém quatro relocations `R_MIPS_32` para `.text` em `0x8`,
`0x154`, `0x2C8` e `0x2F4` (sites `0x4D48–0x4D54`). São ponteiros do próprio
módulo; não são nomes nem prova de identidade C cross-artifact.

O parser registra explicitamente que `sh_link`/`sh_info` das tabelas de relocation
PSP não são significativos e determina as seções-alvo por `.rel.<section>` e faixas
de endereços. O inventário completo, as 474 linhas de relocation com provenance,
as 237 referências de chamada, os datarefs e o resumo de layout estão em
`build/seto018/baseline.json` (SHA-256
`6ef4ee553ce21205ed7ba738db519086c140a1374097a77e59e39a9cbf4fa043`). O arquivo
não contém timestamps nem caminhos absolutos.

#### Reproduzir os limites Ghidra e gerar `triage.json`

1. Gere/atualize o baseline estrutural usando somente o PRX; o hash é verificado
   antes da escrita e nenhum arquivo Ghidra é necessário:

   ```powershell
   python scripts/triage_libtutoriallist.py --baseline-only
   ```

2. Em um checkout WSL/Windows com Ghidra configurado, use um diretório de projeto
   **novo e vazio** sob `build/seto018/`. O snippet abaixo chama o script
   existente uma vez para cada intervalo do baseline e guarda apenas o log bruto
   em `build/seto018/`:

   ```powershell
   $env:PYTHONPATH = "src;scripts"
   py -3.12 -c "from pathlib import Path; from probe_common import validated_build_root,ensure_build_dir,prepare_build_file; r=Path.cwd(); b=validated_build_root(r,subdir='seto018'); ensure_build_dir(b,b); ensure_build_dir(b/'ghidra-run',b); p=b/'ghidra-output.log'; prepare_build_file(p,b); p.unlink(missing_ok=True)"
   $baseline = Get-Content build/seto018/baseline.json -Raw | ConvertFrom-Json
   $ghidraArgs = @("build/seto018/ghidra-run", "libtutoriallist", "-import",
       "private/original/PSP_GAME/USRDIR/gmodule/libtutoriallist.prx",
       "-scriptPath", "scripts/ghidra")
   foreach ($f in $baseline.functions) {
       $ghidraArgs += @("-postScript", "SetoAnalyzeFunction.java", $f.start, $f.end)
   }
   $toolchain = py -3.12 -m seto --config config/seto.toml toolchain --json | ConvertFrom-Json
   $ghidra = ($toolchain.tools | Where-Object name -eq "ghidra").path
   if (-not $ghidra) { throw "Configure Ghidra before running the boundary scan" }
   & $ghidra @ghidraArgs 2>&1 | Out-File build/seto018/ghidra-output.log -Encoding utf8
   if ($LASTEXITCODE -ne 0) { throw "Ghidra boundary scan failed" }
   py -3.12 scripts/triage_libtutoriallist.py --ghidra-log build/seto018/ghidra-output.log
   ```

   `--ghidra-log` extracts the `SETO_*` markers printed by
   `SetoAnalyzeFunction.java` (no second MIPS analyzer). It binds the result to
   the freshly hash-checked baseline, requires all 25 exact start/end intervals,
   validates each status and the full body range/count for `EXACT`, then writes
   `ghidra-boundaries.json` and `triage.json`. The log and Ghidra project are
   local build outputs; choose a fresh project directory instead of reusing a
   previous analyzer database. The SHA field is a local consistency binding,
   not a signature or external authenticity proof.

### 2. Triagem técnica das 25 faixas

Os intervalos abaixo são os 25 resultados contíguos de `mips.find_functions()`;
“intervalo descoberto” não é uma promoção automática a função C. A análise
Ghidra 12.1.3 usou `Allegrex:LE:32:default`, compiler spec `default`, e o script
read-only `SetoAnalyzeFunction.java`. Confirmou 21 corpos exatos em uma faixa,
três starts sem função reconhecida (`0x0`, `0x2C8`, `0x1E84`) e uma faixa com corpo
descontíguo (0x2F4: quatro ranges). `build/seto018/ghidra-boundaries.json`
registra essas observações com o mesmo SHA do módulo; SHA-256
`b78951ff923321ae7885c06c8b27d6b1e104f425e8672ddaacbe0cb2e07697e5`.
O relatório é uma captura local do console Ghidra read-only; a associação de SHA
é consistência local, não assinatura/autenticação criptográfica do processo ou
dos resultados.

`L/I/U` = chamadas locais/importadas/unknown; `P/I/U` em datarefs = status
`PROVEN`/`INFERRED`/`UNKNOWN` **dentro do próprio PRX**. Mesmo `PROVEN` aqui não
prova identidade de objeto entre o PRX e o ELF candidato:
`object_identity=NOT_APPLICABLE`. Os NIDs são identidades `(libehsys, NID)` da
tabela recuperada, não nomes SDK. Targets locais são destinos numéricos do PRX;
quando não são início de intervalo, isso aparece como risco e não como nova
função presumida.

| Intervalo | Bytes / words | Fluxo (branches / backedges) | Chamadas e identidades importadas | Datarefs P/I/U | Decisão e justificativa |
|---|---:|---|---|---:|---|
| `0x0–0x8` | 8 / 2 | linear (0 / 0) | L0/I0/U0; — | 0/0/0 | **FRAGMENT** — `jr $ra; addu $v0,$zero,$zero`; sem função Ghidra, caller direto ou ponteiro relocação `.rodata.sceResident`. Não é promovido a C apenas por começar `.text`. |
| `0x8–0x154` | 332 / 83 | condicional (7 / 0) | L1→`0x1B0C`; I15: `10F3BB61,1856E536,31454993,33ED567B,4AA58320,74CA1190,AB962AE7,C07BB470,C859D5FE,C9D9E989,D853F15C,D979E9BF,EA748E31` | 1/9/0 | **DEFERRED** — dez referências estáticas; localizações do PRX não provam identidade de dados no candidato. |
| `0x154–0x280` | 300 / 75 | condicional (16 / 0) | L4→`0x280,0x1B70,0x1F10,0x21F8`; I5: `13A4081A,450CD6C5,BE3756D0,D470D0B2` | 0/5/0 | **DEFERRED** — cinco HI/LO sem identidade externa de dados; vários ramos por estado. |
| `0x280–0x2C8` | 72 / 18 | condicional (1 / 0) | L1→`0x1C18`; I2: `ED1410E0,F6414A71` | 0/3/0 | **DEFERRED** — três referências inferidas a dados, embora a faixa Ghidra seja exata. |
| `0x2C8–0x2F4` | 44 / 11 | condicional (2 / 0) | L0/I0/U0; — | 0/1/2 | **DEFERRED** — sem função Ghidra e três datarefs incompletos; há `R_MIPS_32` em `.rodata.sceResident` no sítio `0x4D50` apontando à faixa, portanto não é descartado como fragmento. |
| `0x2F4–0x6E8` | 1 012 / 253 | loop (15 / 2) | L6→`0x6E8,0x7A4,0x8F0,0xE24,0x1254,0x1764`; I18: `09794DF0,1D98951B,1EC5342B,399AC68A,4175E3DB,42110BF9,5CBB9E43,878EE1D3,C62F9EAC,DFCA450B,E6E4401F,F462EE6E` | 0/13/0 | **DEFERRED** — resident pointer em `0x4D54`; Ghidra body ocupa quatro ranges; 13 referências de dados inferidas e fluxo grande. |
| `0x6E8–0x7A4` | 188 / 47 | condicional (2 / 0) | L1→`0x1D08`; I8: `09794DF0,10F3BB61,5CBB9E43,7187E0F0,85F89FE8,89812D8A,B2B9FEFA,F462EE6E` | 0/0/0 | **SELECTED #2** — Ghidra exato; imports íntegros por `(library,NID)`, um call local para função descoberta e nenhum dataref estático. |
| `0x7A4–0x8F0` | 332 / 83 | condicional (2 / 0) | L2→`0x1D08`; I14: `60B55A50,8EA6B1E7,942B03D0,9EA6989A,A4AFF8E6,B89D38DC,B8AD96EA,CABEA834,E58C0FDC,E6E4401F,FDD168CA` | 0/0/0 | **DEFERRED** — tecnicamente elegível sem datarefs, mas ranked após os três menores; 16 call sites e maior custo de protótipos. Próxima candidata recomendada. |
| `0x8F0–0xE24` | 1 332 / 333 | loop (10 / 1) | L3→`0x1D08`; I40: `20560342,4175E3DB,60B55A50,8EA6B1E7,942B03D0,9EA6989A,A4AFF8E6,B89D38DC,B8AD96EA,CABEA834,E58C0FDC,E6E4401F,F462EE6E,FDD168CA` | 0/3/0 | **DEFERRED** — função longa, 40 imports e três referências inferidas. |
| `0xE24–0xFF0` | 460 / 115 | condicional (6 / 0) | L4→`0xFF0,0x1A3C,0x1D08`; I17: `31454993,3BB2BAC6,60B55A50,8EA6B1E7,942B03D0,9EA6989A,A4AFF8E6,AB962AE7,B8AD96EA,CABEA834,E58C0FDC,E6E4401F,FDD168CA` | 0/1/0 | **DEFERRED** — uma referência inferida a dados. |
| `0xFF0–0x1254` | 612 / 153 | condicional (2 / 0) | L1→`0x1D08`; I17: `8EA6B1E7,9EA6989A,CABEA834,E6E4401F,FDD168CA` | 0/0/0 | **DEFERRED** — sem datarefs, mas 153 words/18 calls; acima da janela de menor complexidade. |
| `0x1254–0x14E0` | 652 / 163 | condicional (3 / 0) | L1→`0x1D08`; I15: `8EA6B1E7,9EA6989A,B2B9FEFA,CABEA834,E6E4401F,FDD168CA` | 0/0/0 | **DEFERRED** — sem datarefs; 163 words e 16 call sites. |
| `0x14E0–0x1764` | 644 / 161 | condicional (19 / 0) | L0/I8; `8EA6B1E7,9EA6989A,CABEA834,E6E4401F,FDD168CA` | 0/0/0 | **DEFERRED** — sem datarefs, mas conversões FPU e 19 ramos condicionais. |
| `0x1764–0x1A3C` | 728 / 182 | condicional (4 / 0) | L3→`0x14E0,0x1D08`; I17: `8EA6B1E7,9EA6989A,B2B9FEFA,CABEA834,E6E4401F,FDD168CA` | 0/0/0 | **DEFERRED** — sem datarefs, porém 182 words e 20 call sites. |
| `0x1A3C–0x1B0C` | 208 / 52 | loop (5 / 2) | L0/I1: `libehsys/0xB89D38DC` (stub `0x42A0`, site `0x1AC0`) | 0/0/0 | **SELECTED #3** — Ghidra exato; 52 words, uma import identity recuperada, sem static data. |
| `0x1B0C–0x1B70` | 100 / 25 | linear (0 / 0) | L0/I2: `10F3BB61,1B00FB95` | 2/3/0 | **DEFERRED** — cinco referências, inclusive localizações `.data`/`.text`; continuam sem objeto cross-artifact identificado. |
| `0x1B70–0x1C18` | 168 / 42 | condicional (6 / 0) | L1→`0x1C58`; I0 | 0/4/0 | **DEFERRED** — quatro referências HI/LO inferidas. |
| `0x1C18–0x1C58` | 64 / 16 | condicional (1 / 0) | L1→`0x1C20` (não é início de intervalo); I1: `20E340D9` | 0/3/0 | **DEFERRED** — local target intra-função não resolvido como função descoberta e três datarefs inferidos. |
| `0x1C58–0x1D08` | 176 / 44 | condicional (3 / 0) | L0/I3: `41AABF28,8288EEBC,D2A768F4` | 3/5/0 | **DEFERRED** — oito datarefs; os três `PROVEN` indicam localização no módulo, não identidade de objeto. |
| `0x1D08–0x1DF4` | 236 / 59 | loop (7 / 1) | L2→`0x1C58,0x1E94`; I3: `31454993,7661E728,C6C15111` | 3/0/0 | **DEFERRED** — três destinos de dados localizados no módulo; objeto cross-artifact não comprovado. |
| `0x1DF4–0x1E84` | 144 / 36 | condicional (2 / 0) | L0/I1: `4B0DABFA` | 0/4/0 | **DEFERRED** — quatro datarefs inferidos. |
| `0x1E84–0x1E94` | 16 / 4 | linear (0 / 0) | L0/I0/U0; — | 0/0/0 | **FRAGMENT** — quatro instruções parecem comparar dois halfwords, mas Ghidra não achou função, não há caller direto nem ponteiro resident relocado para o start. |
| `0x1E94–0x1F10` | 124 / 31 | loop (7 / 1) | L0/I0/U0; — | 0/0/0 | **SELECTED #1** — Ghidra exato; binary search sem calls ou datarefs, primeiro no ranking de baixa complexidade. |
| `0x1F10–0x21F8` | 744 / 186 | loop (16 / 3) | L1→`0x1D08`; I5: `2FD4863E,63E8C033,8B6EA5EC,942B03D0,E58C0FDC` | 0/19/0 | **DEFERRED** — 19 referências inferidas. |
| `0x21F8–0x25B0` | 952 / 238 | loop (26 / 1) | L0/I13: `2AE3C0AD,5998BFD7,6367AE39,8171F765,F5E3080C` | 0/24/0 | **DEFERRED** — 24 referências inferidas e 238 words. |

Todas as NIDs acima pertencem à biblioteca recuperada `libehsys`; os 1 245
stubs não chamados também permanecem no inventário completo. Os endereços e
nomes `func_XXXXXXXX` são provisórios; a classificação local de um call significa
alvo dentro do `.text`, não prova por si só um entrypoint semântico.

### 3. Reconstruções C efetivamente trabalhadas

Novas fontes, sem mover nem alterar os C de `libhtml_view.prx`:

| Fonte / intervalo | Reconstrução sustentada pela listagem | Resultado primário |
|---|---|---|
| `decomp/src/libtutoriallist/func_00001E94.c`, `[0x1E94,0x1F10)` | Busca binária em vetor de `unsigned short`, com passo em bytes/halfwords e retorno de índice ou `-1`; 31 words, zero calls/datarefs. Decompilação Ghidra/MIPS e m2c só auxiliaram a leitura; nomes e tipos permanecem provisórios. | `NONMATCHING`, exit `3`, **7/31** words iguais, 24 diferenças, 0 relocation issues/limitations. A divergência principal é a forma de branch/control-flow e atribuição de registradores na busca; não houve máscara nem alteração do comparador. |
| `decomp/src/libtutoriallist/func_000006E8.c`, `[0x6E8,0x7A4)` | Helper de setup/render: chama local `func_00001D08(0x1011)`, retorna o argumento se o status é zero; caso contrário limpa 0x60 bytes, lê um word via import 0x37E0 e encadeia oito imports. 47 words, zero datarefs. | **`MATCHED`**, exit `0`, **47/47** words, 0 diferenças, 0 relocation issues/limitations. `verified_decompilation=true` pelo matcher estrito. |
| `decomp/src/libtutoriallist/func_00001A3C.c`, `[0x1A3C,0x1B0C)` | Rotina decimal: limpa buffer local de quatro bytes, ajusta coordenada em 4/8 e chama o import de rendering por cada dígito positivo. 52 words, um import, zero datarefs. | Compilação Metrowerks produziu objeto de **204 bytes/51 words**; o comparator recusou entrada de tamanho diferente dos 208 bytes/52 esperados, exit `1`, sem report de status. Registrado como **ERROR/sem veredito**, não como `NONMATCHING` ou `INCONCLUSIVE`. |

IDs e sites importados nas candidatas escolhidas:

| Função | Chamadas importadas observadas no PRX |
|---|---|
| `0x1E94` | nenhuma |
| `0x6E8` | local site `0x6FC→0x1D08`; imports: `0x71C→(libehsys,0x10F3BB61,stub 0x2610)`, `0x724→(libehsys,0xB2B9FEFA,0x37E0)`, `0x734→(libehsys,0x85F89FE8,0x3768)`, `0x748→(libehsys,0x7187E0F0,0x3758)`, `0x750→(libehsys,0x89812D8A,0x3770)`, `0x75C→(libehsys,0xF462EE6E,0x3AA8)`, `0x76C→(libehsys,0x09794DF0,0x3BC8)`, `0x788→(libehsys,0x5CBB9E43,0x3C70)` |
| `0x1A3C` | `0x1AC0→(libehsys,0xB89D38DC,stub 0x42A0)` |

As assinaturas em `libtutoriallist_stubs.h` são exclusivamente as usadas pelas
três fontes e continuam anotações de ABI provisórias, não protótipos SDK.
O descompilador/pseudocódigo não estabelece identidade de dados; nenhum desses
arquivos usa globais, `volatile`, assembly inline, padding ou bytes copiados do
PRX.

### 4. Hashes de fonte/objeto e cobertura

| Função | Source SHA-256 | Object SHA-256 | Comparação primária |
|---|---|---|---|
| `0x6E8` | `f316481d7ba11e1314046f1b13154cb4302686e99127b6c3287a771be7f04e63` | `6c8d2775ef7356c123628f5e69a91d12b6875f399afcdbcf52f6e6539f6ff2e4` | `MATCHED` 47/47 |
| `0x1E94` | `e7a4adeba0a573cf8c3f9f87143ebc5ca549ccc44e1ea484d66c34ff2f335d63` | `2d24f9d26ad4e8375d5f1a781857e1b0d6676f1dd0eefc466dfe35e34909dfef` | `NONMATCHING` 7/31 |
| `0x1A3C` | `96fb838f1abf255240c0a2508518333250080f16de8cafb80b9d791ae126fc17` | `d420abbe958a282f78d5b6cd9df23fc08b73bcc3fd8d1fd897369a991463d402` | Comparator input-size error, 51 candidate words vs 52 original |

Cada candidata foi recompilada **duas vezes** em diretórios de tentativa distintos;
os hashes de source/object, os status e a evidência de comparação foram idênticos
entre as execuções. `match_function.py` registrou o compiler Metrowerks
3.0.1 build 219 via WSL2 `wibo` 1.2.0, flags `-O4,p -sdatathreshold 0` e
`decomp/include`. O warning de `MWCIncludes` não foi escondido.

**Cobertura:** 130 words em três C candidatas. 47 words estão certificados como
uma função nova `MATCHED`; outras 7 words de `0x1E94` são literalmente iguais,
mas não promovem a função `NONMATCHING` a reconstrução verificada. As 24 words
divergentes permanecem pendentes. As 52 words de `0x1A3C` não receberam
comparação porque o matcher recusou o tamanho do objeto; não são `INCONCLUSIVE`
nem `NONMATCHING`.

Contagens novas: **1 `MATCHED`, 0 `INCONCLUSIVE`, 1 `NONMATCHING`, 1 erro de
comparação sem veredito**. O resultado do módulo anterior `libhtml_view.prx`
permanece inalterado: sete `MATCHED`, oito `INCONCLUSIVE`, zero `NONMATCHING`.

### 5. Determinismo e limites epistemológicos

Hashes dos relatórios ignorados gerados em `build/seto018/`:

| Arquivo | SHA-256 |
|---|---|
| `baseline.json` | `6ef4ee553ce21205ed7ba738db519086c140a1374097a77e59e39a9cbf4fa043` |
| `triage.json` | `51e194b965b68b678217aa1d1207cd2adb9c410d09bb9500fa236c40d71affca` |
| `ghidra-boundaries.json` | `b78951ff923321ae7885c06c8b27d6b1e104f425e8672ddaacbe0cb2e07697e5` |
| `match-results.json` | `6e37987dde0eb16613731184a0997e62d65c4fc2cb3c5598a86ab9b855717ccf` |

`baseline.json`/`triage.json` foram regenerados deterministicamente, sem caminhos
absolutos nem timestamps. Os relatórios individuais, objetos e projeto Ghidra
permanecem em `build/` e não são commitados. Nomes de função, tipos dos parâmetros
e semântica dos imports são provisórios. O JSON Ghidra é evidência local não
autenticada, não autoridade independente; o código verifica apenas SHA/ranges
declarados. Uma localização `.data` do PRX ou um endereço numérico igual não prova
identidade independente de objeto. A exceção de
0x1A3C permanece sem verdict porque o comparator exige o tamanho original inteiro.

### 6. Validação e limitações ambientais

| Gate | Ambiente | Resultado |
|---|---|---|
| `tests/test_libtutoriallist_triage.py` + teste estrutural real | Windows / WSL2 | 17 passed, 1 opt-in skipped |
| Full suite `pytest -q` | Windows | 737 passed, 28 skipped |
| Full suite `pytest -q` | WSL2 | 743 passed, 13 skipped, 9 falhas ambientais |
| `pytest -m integration -q` | Windows | 24 passed, 26 skipped |
| `pytest -m integration -q` | WSL2 | 42 passed, 8 skipped |
| Integração real opt-in 014–018 | WSL2 | 47 passed, 3 skipped |
| Integração real nova (`SETO_LIBTUTORIALLIST_REAL=1`) | WSL2 | 2 passed; 3 funções × 2 builds |
| `compileall -q src scripts tests` / `git diff --check` | Windows & WSL2 | clean / clean |

As nove falhas do full suite WSL2 foram comparadas com um worktree limpo no
baseline `8d646e78`. O subset dos quatro módulos relevantes teve os mesmos IDs no
baseline (9 failed, 101 passed, 2 skipped):

- `test_match_script::test_resolve_loaders_uses_wsl_configuration_and_preserves_spaces`
- `test_smoke::test_headless_is_proved_without_claiming_the_allegrex_processor`
- `test_smoke::test_the_allegrex_processor_is_claimed_only_when_ghidra_loads_it`
- `test_smoke::test_a_ghidra_that_refuses_allegrex_does_not_get_the_capability`
- `test_smoke::test_a_64_bit_mips_fallback_does_not_prove_automatic_elf32_recognition`
- `test_smoke::test_failure_details_do_not_leak_the_smoke_workspace`
- `test_toolchain::test_a_tool_that_is_not_needed_here_is_still_looked_for`
- `test_toolchain_bootstrap::test_posix_dry_run_is_selective_and_does_not_write_tool_config`
- `test_toolchain_bootstrap::test_posix_bootstrap_never_uses_sudo_without_an_explicit_notice`

As causas observadas são expectativa de loader/inventário, ausência de Ghidra
Allegrex funcional no WSL e CRLF nos scripts POSIX do checkout Windows-mounted.
Esses arquivos não foram alterados; as falhas não foram classificadas como
preexistentes sem a execução comparativa.

Disponibilidade observada: Metrowerks 3.0.1 build 219 e `wibo` 1.2.0 em WSL2;
GNU MIPSel objdump/binutils 2.42 em WSL2; Ghidra 12.1.3 e m2c 0.1.0 no host
Windows (Ghidra importou o PRX como Allegrex). `splat` não está instalado em WSL2;
`seto.split` ainda validou o layout sem erros. Nenhuma integração PSP foi
executada pelo CI público.

Um teste exploratório separado com `-O4,s -sdatathreshold 0` para `0x1A3C`
produziu 48 candidate words e também recebeu erro de tamanho; os resultados
primários acima continuam sendo apenas os de `-O4,p -sdatathreshold 0`.

### 7. Próximas candidatas

1. `0x7A4–0x8F0` — Ghidra exato, zero datarefs, imports resolvidos, 83 words e
   16 calls (14 imports, dois locais); próxima candidata de baixa ambiguidade,
   após tipar os imports pelos registradores.
2. `0xFF0–0x1254` — 153 words, 17 imports + um local, sem datarefs; mais custosa
   pelo número de chamadas.
3. `0x14E0–0x1764` — oito imports, sem datarefs, mas 161 words, 19 branches e
   conversões FPU; requer cuidado extra com roundings/ABI.

`0x2C8` deve permanecer adiada até que sua função (apontada por
`.rodata.sceResident`, mas não reconhecida pelo Ghidra e com HI/LO órfãos) seja
compreendida. `0x0` e `0x1E84` seguem `FRAGMENT` até haver evidência independente
de entrypoint/função.

## SETO-DECOMP-018-R2 — Validação Semântica e Conclusão das Reconstruções

Esta seção registra a atualização da mesma PR #17. A R2 preserva os critérios
de `src/seto/matching.py`, o resultado `MATCHED` de 47/47 para `0x6E8`, e os
resultados/documentação histórica de 017–018 acima. O PRX continuou somente
leitura e manteve SHA-256
`2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49`.

### Validação do envelope do matcher

`validate_match_envelope()` não deduz diferenças a partir de palavras sem
crédito: palavras podem ficar sem crédito ou diferença quando a comparação é
limitada por evidência de relocation/identidade. A lista detalhada pode ser
truncada por `max_differences`. A validação exige contagens inteiras não
negativas, `0 <= matching_words <= total_words`, ausência de sobreposição entre
contagens de matches e diferenças, detalhes não maiores que `difference_count`,
e combinações coerentes de status. `MATCHED` continua exigindo evidência externa
`compiled-object`, igualdade de todas as palavras, zero diferenças/issues/
limitações e uma das duas equivalências emitidas pelo matcher. `INCONCLUSIVE`
exige limitações sem divergência comprovada; `NONMATCHING` exige diferença
comprovada ou problema de relocation. Nenhum veredito é criado pelo validador.

Regressões sintéticas cobrem `INCONCLUSIVE` 18/20 com zero diferenças e
limitações, `NONMATCHING` com seis diferenças e apenas dois detalhes, o caso
`MATCHED` 47/47 e relatórios negativos, booleanos, truncados em excesso ou com
status/evidência inconsistentes.

### Baseline independente do Ghidra

`python scripts/triage_libtutoriallist.py --baseline-only` agora recalcula o
hash fixado do PRX e grava apenas `baseline.json`; não lê nem exige um relatório
Ghidra. Para a triagem completa, `--ghidra-log` analisa os marcadores reais
`SETO_*` do console de `SetoAnalyzeFunction.java`, reutilizando aquele script
read-only. A validação liga o relatório ao SHA local do baseline, exige cobertura
única de cada um dos 25 intervalos e verifica status, unidade endereçável,
intervalo completo, número de endereços e uma faixa para corpos `EXACT`. Não foi
implementado outro analisador MIPS. O log bruto e o projeto Ghidra permanecem
apenas em `build/seto018/`; o JSON não contém caminhos absolutos. SHA é
consistência local, não autenticação da origem.

O procedimento PowerShell reproduzível de geração está na seção “Reproduzir os
limites Ghidra e gerar `triage.json`” acima. O resultado estrutural permanece 25
intervalos; a triagem seleciona os mesmos três candidatos.

### Reavaliação das candidatas

| Função | Resultado verificado nesta R2 | Evidência/limite |
|---|---|---|
| `func_000006E8` | **MATCHED 47/47**, zero diferenças, issues e limitações | Duas compilações frescas; resultado/promoção estritos preservados. |
| `func_00001A3C` | **NONMATCHING 46/52**, seis divergências nos words `[8, 9, 10, 12, 13, 14]` | O C inicial compilava 51 words (204 bytes) e falhava antes de qualquer veredito. O disassembly original mostra um loop de quatro bytes em `0x1A68–0x1A74`; o compilador havia desenrolado as quatro stores. Formas pequenas equivalentes com trip count constante continuaram gerando o objeto de 51 words. A forma corrigida calcula o ponteiro final do buffer local e limpa até esse limite, sem inserir instrução artificial: gera 52 words e permite comparação real. Os seis desvios restantes estão exclusivamente na inicialização/controle do loop de limpeza; a checagem de faixa, o ramo de número positivo, o resto e a divisão por dez mantêm seus fluxos observados. Sem promoção a `MATCHED`. |
| `func_00001E94` | **NONMATCHING 7/31**, 24 divergências | A versão R2 usa `high = count - 1` e midpoint `low + (high - low) / 2`, evitando overflow assinado de `low + high` para entradas válidas; o invariante do loop mantém `high >= low`. Preserva busca binária, limites inclusivos, comparação unsigned de 16 bits e stride em halfwords. A divisão de `stride_bytes` por dois continua arredondando em direção a zero como MIPS/C; não há relocations. Os words divergentes são `[4, 5, 6, 8–20, 22–29]`: sequências de predicados/branches, delay slots, atualização de limites e retorno. Permanece `NONMATCHING`. |

Para `0x1A3C`, os bytes de delay slot da divisão por dez e do call não foram
preenchidos artificialmente; o compilador continua gerando `div`/`mfhi` para o
resto, a sequência de multiplicação por constante para `/ 10`, e os updates de
coordenada nos delay slots. A decisão de buffer explica o erro de tamanho
anterior; a nova comparação real continua divergente apenas no bloco de limpeza.

### Hashes das reproduções R2

| Artefato local ignorado em `build/seto018/` | SHA-256 |
|---|---|
| PRX original | `2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49` |
| `baseline.json` | `6ef4ee553ce21205ed7ba738db519086c140a1374097a77e59e39a9cbf4fa043` |
| `triage.json` | `fb1cc157ada5448dfb8e88e2b73bd4d26b6d665d9ff11ef667e2298158aa17a5` |
| `ghidra-boundaries.json` (inclui unidade endereçável/status validados) | `e86fb8c954421a4f2923e8409adcec8ec2578bef6a0941dfa6f95ef390bb671b` |
| `match-results.json` (duas execuções frescas por candidata) | `26abe66c5d12f22b60222d0504fc4a4e33685952acac88e609a75a52c30ae1d3` |

| Compilação representativa | SHA-256 da fonte | SHA-256 do objeto |
|---|---|---|
| `0x1A3C` original, 51 words/erro de tamanho | `96fb838f1abf255240c0a2508518333250080f16de8cafb80b9d791ae126fc17` | `d420abbe958a282f78d5b6cd9df23fc08b73bcc3fd8d1fd897369a991463d402` |
| `0x1A3C` limite de buffer R2, 46/52 | `fb218f97da4e37df99408f049d1b5feefa6b149edbf5425ef355512dd6cfe8c9` | `8aedd88b985aa98551fc0edf36d3c80df198702a492f20f999135d0c8903356b` |
| `0x1E94` fonte anterior à correção de midpoint, 7/31 | `e7a4adeba0a573cf8c3f9f87143ebc5ca549ccc44e1ea484d66c34ff2f335d63` | `2d24f9d26ad4e8375d5f1a781857e1b0d6676f1dd0eefc466dfe35e34909dfef` |
| `0x1E94` midpoint sem overflow assinado, 7/31 | `90d4e079e616572b40b7349b7d4f8e2a0afdb7d1e02f383eb5dd33f9ef5f314f` | `2ca13c407d52329349857d30ecf813892735882eac7b2f5156d57660a4220f22` |

Os hashes de fonte/objeto são proveniência local de compilação, não prova de
identidade entre artefatos. O matcher e `src/` não foram modificados; nenhum
objeto, log, relatório ou projeto Ghidra é parte do commit.

### Testes e gates da R2

| Gate | Ambiente | Resultado |
|---|---|---|
| Testes focados de triagem + estrutura real | Windows / WSL2 | 21 passed; 1 opt-in skipped |
| `SETO_LIBTUTORIALLIST_REAL=1` em 018 | WSL2 | 2 passed; as três candidatas foram testadas duas vezes |
| `pytest -m integration -q` | Windows | 24 passed, 26 skipped, 719 deselected |
| `pytest -m integration -q` | WSL2 | 42 passed, 8 skipped, 719 deselected |
| Integrações reais opt-in 014–018 | WSL2 | 47 passed, 3 skipped (splat, Ghidra e REA não configurados no WSL) |
| Suíte completa `pytest -q` | Windows | 741 passed, 28 skipped |
| Suíte completa `pytest -q` | WSL2 | 747 passed, 13 skipped, 9 falhas preexistentes |
| `compileall -q src scripts tests` / `git diff --check` | Windows | clean / clean |

As nove falhas WSL são as mesmas já reproduzidas em checkout limpo do baseline
`8d646e78`: `test_resolve_loaders_uses_wsl_configuration_and_preserves_spaces`,
cinco casos de smoke/Ghidra (`test_headless_is_proved_without_claiming_the_allegrex_processor`,
`test_the_allegrex_processor_is_claimed_only_when_ghidra_loads_it`,
`test_a_ghidra_that_refuses_allegrex_does_not_get_the_capability`,
`test_a_64_bit_mips_fallback_does_not_prove_automatic_elf32_recognition`,
`test_failure_details_do_not_leak_the_smoke_workspace`), `test_a_tool_that_is_not_needed_here_is_still_looked_for`, e os dois testes
POSIX bootstrap (`test_posix_dry_run_is_selective_and_does_not_write_tool_config`,
`test_posix_bootstrap_never_uses_sudo_without_an_explicit_notice`). Não foram
introduzidas por esta R2.

## SETO-DECOMP-019 — R.E.A., toolchain e novas reconstruções

Esta rodada partiu de `main` após o merge da 018-R2 (merge commit `eaf6cd3`, com
`5dee4eb` como HEAD da branch 018). O PRX foi novamente copiado apenas para a
worktree isolada, lido sem alteração e conferido pelo SHA-256
`2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49`. Os
artefatos gerados, objetos, projetos Ghidra, logs e `REPORT.md` permanecem em
`build/seto019/`.

### Auditoria das ferramentas e do R.E.A.

Windows e WSL2 foram medidos separadamente. No Windows, Node 24.21.0 e npm
11.19.0 atendem ao engine declarado pelo pacote `rea-agents` 6.5.0
(`^22.19.0 || ^24.11.0 || >=26.0.0`). Ghidra 12.1.3, Allegrex v21.4, JDK
Corretto 25.0.3, m2c, splat e LLVM objdump passaram os respectivos smoke tests.
O Metrowerks 3.0.1 build 219 foi detectado, mas a compilação nativa é
`BLOCKED`: o próprio driver recusou a licença. A recusa é reportada sem incluir
o caminho local do arquivo de licença. Os builds reais foram feitos em WSL2.

No WSL2, Metrowerks + wibo 1.2.0, GNU MIPSel binutils/objdump 2.42, splat
0.50.1 e m2c no commit fixado passaram os smoke tests. Splat/m2c ausentes foram
instalados pelos bootstrap existentes em ambientes isolados; o bootstrap
selecionado por `--config config/wsl/seto.toml` grava seu overlay ignorado ao
lado desse profile. Ghidra 12.1.3 + Allegrex v21.4 também foram instalados dos
arquivos SHA-256 fixados; a detecção agora escolhe o launcher POSIX e preserva
permissões executáveis seguras. Ghidra continua `BLOCKED` no WSL por ausência de
Java. Node 18.19.1 não satisfaz o engine do REA e o npm visível é um shim Windows
que não inicia no WSL; npm foi detectado, mas fica `BLOCKED` pela incompatibilidade
do Node, e o pacote REA não foi instalado nesse ambiente.

REA 6.5.0 no Windows passou CLI help, MCP initialize + `tools/list` (207
ferramentas) e `doctor --provider ghidra` com Ghidra/JDK configurados. O setup
Codex foi primeiro inspecionado com `--dry-run`, depois registrado preservando
os outros servidores; `doctor --client codex` confirmou o registro. Uma análise
real do fixture sintético autorizado (raw 6502, SHA-256
`17615cd64f58233cc395245337bc74a8af40b9741bdb212f294b51e4cb05edb5`) recuperou
as funções `0x8000` e `0x8008`, ranges, instruções e o call entre elas. O PRX
original foi recusado pelo provider Ghidra com `target_format_unsupported`,
classificado `UNSUPPORTED`; nenhum byte/cabeçalho/relocation foi alterado para
contornar a limitação. CLI/MCP/provider instalado não promovem por si sós
`native-analysis` ou suporte PRX.

### Reconstruções efetivamente trabalhadas

| Função | Candidata/evidência | Resultado fresco (duas execuções idênticas) |
|---|---|---|
| `func_000007A4`, `[0x7A4,0x8F0)` | 83 words, um range Ghidra exato, 16 chamadas (14 imports, 2 locais), sem datarefs. C representa o early-return e a cadeia de configuração/renderização; protótipos/semântica continuam provisórios. | **MATCHED 83/83**, zero diferenças, issues de relocation ou limitações; exit `0`, `verified_decompilation=true`. Source SHA-256 `e5db3876fd470297a058d86535b9adce7e8bf354023fc91d75c596a5cf66351c`; object SHA-256 `41d3d8e253c45f41fa383a94447c12aaf0e590a7638b9081d8f73e5034067238`. |
| `func_00000FF0`, `[0xFF0,0x1254)` | 153 words, um range Ghidra exato, 18 chamadas (17 imports, 1 local), sem datarefs. C registra a hipótese de desenho/renderização; dimensões e assinaturas são provisórias. Variantes de tipo/vida de variáveis não eliminaram a diferença de alocação de registradores. | **NONMATCHING 122/153**, 31 diferenças, zero issues/limitações; exit `3`, sem promoção. Source SHA-256 `82b444011d5e304e29d28ad01a3545fcac64045a6dbd37afb03ff9224489a5f2`; object SHA-256 `41ad805e28b3598486cd8d550f79df191bd772a3494c69d90ff29c53e8d8baa7`. |

Foram efetivamente trabalhadas duas novas funções, ambas com compilação real pelo
Metrowerks em WSL2 e comparação estrita. A cobertura combinada é 205/236 words
iguais; apenas as 83 words de `0x7A4` estão certificadas como função reconstruída.
As 31 divergências de `0xFF0` permanecem abertas. Não houve tentativa de relaxar
matcher, canonicalização de relocation ou identidade de dados. Uma terceira
candidata (`0x14E0`) foi analisada como alternativa, mas não foi promovida a
fonte/tentativas de build após os resultados de 0x7A4 e 0xFF0 satisfazerem o
lote 2–4.

### Revalidação da R2, tempos e gates

O baseline estrutural e a triagem Ghidra da R2 foram regenerados sem modificar
as fontes da 018: baseline SHA-256 `6ef4ee553ce21205ed7ba738db519086c140a1374097a77e59e39a9cbf4fa043`,
triage `fb1cc157ada5448dfb8e88e2b73bd4d26b6d665d9ff11ef667e2298158aa17a5` e
boundaries `e86fb8c954421a4f2923e8409adcec8ec2578bef6a0941dfa6f95ef390bb671b`.
As integrações reais confirmaram novamente `0x6E8 MATCHED 47/47`, `0x1A3C
NONMATCHING 46/52` e `0x1E94 NONMATCHING 7/31`. O caso histórico de `0x1A3C`
continua distinto: a fonte original produziu 51/52 words e erro de tamanho sem
veredito; a fonte R2 atual compila 52 words e recebe comparação NONMATCHING.
Resultados anteriores de `libhtml_view.prx` foram preservados.

Tempos medidos no mesmo checkout: headless Ghidra + decompilação, 20.100 s para
`0x7A4` e 16.307 s para `0xFF0`; cada build + matching levou 2.760–2.894 s para
`0x7A4` e 3.167–3.708 s para `0xFF0` nas duas execuções. A integração REA
Windows mediu 21.490 s para a função sintética `0x8000`, 20.010 s para `0x8008`
e 1.750 s para a recusa do PRX. Esses valores incluem inicialização do provider
e não são benchmarks isolados do decompilador.

Gates finais, motivos exatos e a matriz de skips estão registrados no relatório
operacional ignorado `build/seto019/REPORT.md`; ele também contém o diff unificado
Git exato contra a base da PR. Nenhuma regressão de mídia foi observada. Os
opt-ins REA/Metrowerks dependem dos recursos locais e não são exigidos pelo CI
público.

## SETO-DECOMP-020 — Matching completion e reconstrução avançada

Esta rodada começou de uma branch nova `feat/seto-decomp-020` em `main` após o
merge da PR #18/019. HEAD-base `e11f8c0d2ccced2477cdc1460463d53ff55ba63e`; o
SHA do PRX continua `2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49`.
Os resultados históricos 018-R2 e 019 acima foram copiados/verificados antes
dos novos experimentos e preservados em `build/seto020/history/`; nenhuma
mudança foi feita em `matching.py`, em flags ou em critérios de equivalência.

### Baseline antes da primeira alteração

| Função | Status reproduzido na base 019 |
|---|---|
| `0x6E8` | `MATCHED` 47/47 |
| `0x7A4` | `MATCHED` 83/83 |
| `0x1A3C` | `NONMATCHING` 46/52; palavras `[8,9,10,12,13,14]` |
| `0xFF0` | `NONMATCHING` 122/153; 31 diferenças concentradas na alocação de saved registers |
| `0x1E94` | `NONMATCHING` 7/31; 24 diferenças de midpoint/CFG/branches |
| `libhtml_view.prx` | 15 integrações reais: 7 `MATCHED`, 8 `INCONCLUSIVE`, 0 `NONMATCHING` |

`baseline-only` confirmou 25 intervalos e `triage.json` continuou selecionando
os mesmos três candidatos. Os hashes de baseline, triage e Ghidra são os mesmos
reproduzidos em 019 (tabela da seção anterior). As integrações do baseline usam
objetos/logs de `build/seto020` ou a cópia preservada; a fonte original em
`private/` permaneceu intacta.

### `func_00001A3C` — cleanup por contador

O diagnóstico estruturado está em `build/seto020/diagnostics/function-divergences.md`
e `.json`. Para cada divergência, registra word index/endereço, instruções e
words, basic block, predecessors/successors originais e candidatos, delay-slot
relation, registradores e hipótese. A faixa divergente `[0x1A5C,0x1A78)` é um
único problema de controle/agendamento do loop: o original inicializa o contador
de quatro bytes no delay slot do teste de ponteiro, decrementa o contador no
corpo, e executa o incremento do ponteiro no delay slot do `bne`. O C R2 usava
ponteiro de término e branch-likely; os seis words divergiam na comparação,
incremento/decremento e store atrasado.

Foram compiladas as três formas direcionadas pedidas:

| Variante | Hipótese | Resultado real |
|---|---|---|
| A — ponteiro de término sem guarda | `cursor`/`end` e `do { *cursor++=0; } while (cursor != end)` | Objeto de 204 bytes/51 words; o matcher recusou tamanho versus 208 bytes/52 words (exit 1, sem veredito). Source `26030c1c…6001ae`; object `7099285d…562d3182`. |
| B — índice crescente com guarda | `bytes[index++]`, condição `index < sizeof(digits)` | 204 bytes/51 words; mesmo erro de tamanho, sem veredito. Source `3b943dac…488a3a`; object `d420abbe…463d402`. |
| C — contador decrescente unsigned | `unsigned int remaining=sizeof(digits)`; zero store por byte; `while (--remaining != 0)` | **MATCHED 52/52**, zero diferenças/issues/limitações, `verified_decompilation=true`. O código C manteve `short digits[2]`, guarda e acesso legal por `unsigned char`; sem padding/asm/UB. |

A variante C reproduz exatamente o schedule observado, inclusive `li v1,4` no
delay slot do `beq` e o incremento de `cursor` no delay slot do `bne`. Source C
versionada SHA-256 `f7c851816953ab26c60e91cc71c9c07ddeecae467feb1b6b65a4dbb1c7e45e11`,
object `c2932f8ca2a37486833c44796e45fba0725062eb53ee12ac1749a7d40e7e2407`.
Duas compilações/matches frescos produziram os mesmos hashes e resultado.

### `func_00000FF0` — vida útil e alocação de registradores

O diagnóstico word-a-word e CFG também está no relatório estruturado acima.
As 31 diferenças R19 eram todas substitutions no conjunto de `s0–s4` em
operações com os mesmos opcodes; prologue/stack, aritmética e calls permaneciam
iguais. O mapeamento observado target→candidato era `s0→s4`, `s1→s0`, `s2→s1`,
`s3→s2`, `s4→s3`. Isso relaciona as divergências a uma única decisão de
alocação/liveness, não a 31 falhas semânticas independentes.

Os hints `register` nos parâmetros não mudaram o objeto. Uma versão com um
handle local separado ficou quatro bytes menor (608 versus 612) e foi recusada
antes de veredito. Reordenar apenas as declarações dos dois temporários reais,
mantendo todas as expressões/efeitos e a assinatura O32, fez o Metrowerks mapear
os mesmos valores para os mesmos saved registers do PRX. Não foi introduzida
operação dummy nem mudada a otimização.

Resultado atual: **MATCHED 153/153**, zero divergências/issues/limitações,
`verified_decompilation=true`; duas compilações e matches frescos idênticos.
Source SHA-256 `da4715fedcf351efc48b3f3e850e63f52920e744198d95efef38fb11c53717fd`,
object SHA-256 `5c7a2f176d71b89cd3921aa43ca0e05bfe692cf485d1f4782dc6f4fc70b39496`.

### `func_00001E94` — busca binária permanece não equivalente

O diagnóstico CFG está em `function-divergences.md`: a região inicial difere
na validação/ordem de `count`, a região central no midpoint/endereço/igualdade,
e o final na polaridade dos branches e atualização dos limites/backedge. A
busca usa `lhu`, comparação unsigned e stride; não há calls/datarefs. O único
caller local recuperado (`func_00001D08`, site `0x1D24`) passa `count=4` e
`stride_bytes=0xC`, mas o C mantém midpoint sem overflow assinado para todos os
inputs representáveis; não foi enfraquecida a semântica por causa desse caller.

Experimentos temporários, compilados com o profile oficial, pioraram a cobertura
e foram descartados: midpoint via soma unsigned `5/31` (26 diferenças), comparar
primeiro e materializar a condição `4/31` (27), estrutura com `goto` de igualdade
`6/31` (25), e laço `while` estruturado `4/31` (27). A fonte R2 original permanece
o melhor resultado: `NONMATCHING 7/31`, 24 diferenças `[4,5,6,8–20,22–29]`, sem
issues/limitações. Source final SHA-256
`90d69616d10e982da6169d9c5df4beade008e1cb734c8d471d3b088fb3b82889`; object
`2ca13c407d52329349857d30ecf813892735882eac7b2f5156d57660a4220f22`.

### `func_000014E0` — triagem independente

Como candidatas anteriores já atingiram `MATCHED`, foi iniciada a prioridade 4.
Ghidra/Allegrex confirma body exato de 161 words, frame de 48 bytes, oito
chamadas importadas e lógica de preenchimento com conversões unsigned→float,
clamps e FPU. A listagem associa argumentos O32 a renderer/x/y/mode/total/flags/
current/context; o único caller local `0x1764` fornece total/current via
`func_000037E0`, mas a identidade/garantia de não-zero desses dados não está
provada. m2c alerta para argumentos de registers sem contexto e não deve ser
tratado como protótipo.

Um C experimental não versionado em `build/seto020/experiments/14e0/` compilou,
mas obteve apenas `NONMATCHING 30/161`, 131 diferenças e 11 relocation issues.
Como a conversão FPU/unsigned e o domínio dos valores ainda não estão
comprovados, nenhuma fonte `func_000014E0.c` especulativa foi versionada. A
triagem word-a-word, CFG e delay slots está em
`build/seto020/diagnostics/func_000014E0-experiment.md`; os 131 detalhes foram
obtidos com maior limite de serialização no `compare` existente apenas para
diagnóstico (sem alterar o veredito/critério oficial). As limitações são
preservadas para uma rodada futura.

### Total verificado após 020

| Módulo / estado | Contagem |
|---|---:|
| `MATCHED` acumulados (7 `libhtml_view` + 4 `libtutoriallist`) | **11 funções** |
| `INCONCLUSIVE` em `libhtml_view` | **8 funções**, 231/291 words certificados; 60 continuam limitados por identidade de dados |
| `NONMATCHING` atual | **1 função**: `0x1E94`, 7/31 |
| Novos words certificados em 020 | **205**: 52 (`0x1A3C`) + 153 (`0xFF0`) |
| Words MATCHED acumulados nestes conjuntos | **551**: 216 `libhtml_view` + 335 `libtutoriallist` |

O status histórico de R19 para `0x1A3C` (46/52) e `0xFF0` (122/153) permanece nas
seções anteriores. A atualização 020 substitui as expectativas correntes dos
testes por matches estritos, não apaga o histórico e mantém `0x1E94` como
`NONMATCHING`.

### Gates e regressões 020

| Gate | Ambiente | Resultado |
|---|---|---|
| `pytest -q -rs` | Windows | 761 passed, 35 skipped |
| `pytest -q -rs` | WSL2 | 779 passed, 17 skipped |
| `pytest -m integration -q -rs` | Windows | 23 passed, 30 skipped, 743 deselected |
| `pytest -m integration -q -rs` | WSL2 | 42 passed, 11 skipped, 743 deselected |
| Opt-ins reais 018 + 019 + 020 | WSL2 | 4 passed; `0x6E8`, `0x7A4`, `0x1A3C`, `0xFF0`, `0x1E94` reproduzidos |
| `compileall -q src scripts tests` | Windows / WSL2 | clean |
| `git diff --check` | Windows Git | clean (WSL Git cannot resolve this Windows-linked worktree's common-dir path) |

Os skips restantes são requisitos de plataforma, ISO ausente, opt-ins intencionais,
Java/REA indisponíveis no WSL2 e três testes YAML opcionais sem PyYAML; nenhum
skip foi promovido a aprovação de matching. `build/seto020/REPORT.md` contém a
lista detalhada dos skips, hashes, medições e diff exato contra `main`.

## SETO-DECOMP-021 — Renderer, FPU e controle de fluxo

A rodada começou de uma branch nova `feat/seto-decomp-021` em `main` após o
merge da PR #19 (020). HEAD-base `175a3dcf64516edbafa122f91df9a4d1fedcfa89`; o
SHA do PRX continua
`2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49`. As seções
018-R2, 019 e 020 acima não foram reescritas; nenhuma mudança foi feita em
`matching.py`, nas flags do compilador ou nos critérios de equivalência. Todo
artefato novo (objetos, listagens, experimentos, medições e logs) fica em
`build/seto021/`.

### Baseline antes da primeira alteração

| Função | Status reproduzido na base 020 |
|---|---|
| `0x6E8` | `MATCHED` 47/47 |
| `0x7A4` | `MATCHED` 83/83 |
| `0xFF0` | `MATCHED` 153/153 |
| `0x1A3C` | `MATCHED` 52/52 |
| `0x1E94` | `NONMATCHING` 7/31; diferenças `[4,5,6,8–20,22–29]` |
| `0x1254` | não reconstruída (163 words) |
| `0x14E0` | experimento 020 descartado: `NONMATCHING` 30/161, 131 diferenças, 11 issues de relocation |
| `0x1764` | não reconstruída (182 words) |
| `libhtml_view.prx` | 15 integrações reais: 7 `MATCHED`, 8 `INCONCLUSIVE`, 0 `NONMATCHING` |

O hash do PRX, o `baseline.json`, o `triage.json` e o `ghidra-boundaries.json`
de 018 foram revalidados nas integrações reais: as suítes recompõem
baseline/triage a partir do PRX e dos arquivos preservados antes de comparar.

### `func_00001254` — MATCHED 163/163

A função inicializa o renderer com `func_00001D08(0x1003)` e retorna cedo
quando o resultado é zero; deriva uma margem de dois pixels do bit 3 do
contexto devolvido por `func_000037E0` (`extra = ((*ctx >> 3) & 1) * 2`) e
emite o quadro externo mais as guias internas. São 15 sites de import e uma
chamada local (`0x1D08`), zero datarefs estáticos; os imports usam os
trampolines `libehsys` já declarados em `libtutoriallist_stubs.h`, validados
call site a call site.

A reconstrução versionada reproduz as 163 words — prólogo/epílogo, geometria
(`half = extra / 2`, `left/top/right/bottom`), os quatro guias de canto
(`0x19`/`0x28` × `0x14`/`0x29`), a barra `func_00003AF0(6, 1, 6,
height + extra - 4)`, as guias internas e a barra horizontal final. Resultado
real: **MATCHED 163/163**, zero diferenças/issues/limitações,
`verified_decompilation=true`, com duas compilações frescas independentes
(`build/seto021/matches/f1254/attempt-{1,2}`). Source SHA-256
`d9082eb8cd22c4550d369d2a6ddcd767cb5b5b021b4874b1a62a31c65f4a7db7`; object
SHA-256 `78ab23a040226e1217487d08d6cfb5ccc5b6812e4ea8c4bdac368e3dcbcb2c06`.

### `func_00001E94` — MATCHED 31/31

As 24 diferenças históricas eram de forma, não de algoritmo. A leitura das
words originais (`addu v1,a3,a2` em `0x1EB4`, `bltz a2` no retorno
compartilhado em `0x1F04`, `bnel a0,v1` na igualdade e o backedge `slt
at,a2,a3` em `0x1EF8`) mostra que: o midpoint é a soma direta `(low + high) /
2` e não a forma segura contra overflow; o laço é um `do/while` com guarda
positiva `if (high >= 0) { ... }` e um único `return -1` depois do bloco; e
`low` é declarado e inicializado antes de `high`, o que mapeia `high` para o
`a2` do chamador (contagem decrementada) e `low` para `a3`. A variante E7
(`build/seto021/experiments/1e94/e7-wrapper-low-first.c`) é exatamente essa
forma e fecha as 31 words; nenhuma variante fracassada da 020 foi repetida.

Resultado: **MATCHED 31/31**, zero diferenças/issues/limitações,
`verified_decompilation=true`, em duas compilações frescas. Source versionada
SHA-256
`6dc89326fde1e8aa0f12cb4edd80bb6ab0e8c3b6e86675b71275ad700392f565`; object
SHA-256 `24df0bdbcc2926ef4c5e8bf0c18231dcf9047068447ed978e68916f834c8fcc4`. As
expectativas correntes das suítes 018/020 foram atualizadas para o resultado
comprovado; o histórico 7/31 permanece nas seções 020 acima.

### `func_000014E0` — MATCHED 161/161

O diagnóstico completo de FPU, argumentos e relocations está em
`build/seto021/diagnostics/func_000014E0-analysis.md` e resumido no relatório
da rodada. O que faltava à 020: (1) os quatro blocos de conversão
`unsigned int → float` com o padrão guardado por `bltzl` + `srl/or` + `add.s`,
que provam que `total`, `current` e `half` são unsigned; (2) o mapa de
argumentos O32 completo, incluindo o nono argumento `context` em `48(sp)`
encaminhado a `func_00003850`; (3) o guard exato `if (progress == 0) return
renderer;`, que o Metrowerks baixa como `bnel s2,zero,corpo` com o `divu` no
delay slot tomado — a forma wrapper produz `beql s2,zero,epílogo` e um word a
menos, que é precisamente o erro estrutural do candidato c1; (4) o clamp
[0,1] por `c.lt.s`/`c.ngt.s` e a volta `float → unsigned` pelo caminho
2^31/`trunc.w.s`; (5) a origem dos 11 relocation issues da 020: os 8 sites
`jal` (cinco trampolines `libehsys`: `0x3850`, `0x3BC0`, `0x3B78` ×2, `0x3AF0`
×2, `0x3AE8` ×2) só pareiam quando o corpo tem o layout exato, e o candidato
020 estava deslocado desde o guard.

Dois experimentos fecharam a função: c1 (wrapper, 160 words — o comparador
recusou o tamanho 644 vs 640 bytes) e c2 (early return, 161 words,
**MATCHED 161/161**, zero diferenças/issues/limitações). Source versionada
SHA-256
`009dcba008c5ded30eecfb5ed32a149bcd4801a7a076da5f3e65897f195a6248`; object
SHA-256 `301afd4c338e0ac606c065e05150e6c336a030be61bc01f9fcd64d7905e9bd69`;
evidência canônica em `build/seto021/matches/f14e0/attempt-{1,2}`.

### `func_00001764` — NONMATCHING 42/182

A reconstrução está completa e versionada, mas permanece `NONMATCHING 42/182`
com 140 diferenças e 32 problemas de pairing de relocation. As três words de
clamp (`max`/`min` em `0x17F4`, `0x1818`, `0x181C`) são as únicas `max`/`min`
do PRX e só são emitidas pelos intrínsecos Allegrex
(`__builtin_allegrex_max`/`min`), confirmados por experimento; nenhuma forma
`if`/ternário produziu essas words em nenhum nível de otimização.

O bloqueio restante é uma permutação global de registradores: o original usa
`renderer s7`, `x s5`, `y s4`, `width s3`, `height` spillado em `76(sp)`,
`full s8`, `ready s6`, `filled s0`, enquanto a família de fontes que reproduz
o schedule original (`full` calculado no delay slot da chamada `0x1D08`)
seleciona a rotação alternativa (`renderer s6`, `x s5`, `y s4`, `width s7`,
`height s8`, `full s7`, `ready s0`), e as formas em dois passos que mantêm os
parâmetros nos registradores originais afundam o cálculo para depois do
branch de `ready`. Foram testadas 31 variantes de estrutura (`v1`–`v31`), 24
permutações de declaração, 4 ordenações de parâmetros, 6 micro-formas `q1`–`q6`
e os níveis `-O0`–`-O4,p`: nenhum reproduz o mapa de registradores original.
O corpus está em `build/seto021/experiments/1764/` e `build/seto021/matches/f1764/`
com as tabelas de mapeamento. A fonte versionada documenta o bloqueio no
cabeçalho e é o melhor resultado real da rodada (sem inflar a contagem de
`MATCHED`). Source SHA-256
`e8e9a4a5834a9b84d6ccb38c21125361641e491114c9ddc4efaf526aa0718cdd`; object
SHA-256 `0a8d3235b28413127ed1d653d1236dff684f552e327d00b87a940485f88746ea`.

### Total verificado após 021

| Módulo / estado | Contagem |
|---|---:|
| `MATCHED` acumulados (7 `libhtml_view` + 7 `libtutoriallist`) | **14 funções** |
| `INCONCLUSIVE` em `libhtml_view` | **8 funções**, 231/291 words certificados |
| `NONMATCHING` atual | **1 função**: `0x1764`, 42/182 |
| Novos words certificados em 021 | **355**: 163 (`0x1254`) + 31 (`0x1E94`) + 161 (`0x14E0`) |
| Words MATCHED acumulados nestes conjuntos | **906**: 216 `libhtml_view` + 690 `libtutoriallist` |

O status histórico de 020 para `0x1E94` (7/31) e do experimento descartado de
`0x14E0` (30/161) permanece nas seções anteriores. A atualização 021 substitui
as expectativas correntes dos testes pelos matches estritos e adiciona a
suíte real 021, sem apagar histórico.

### Gates e regressões 021

| Gate | Ambiente | Resultado |
|---|---|---|
| `pytest -q -rs` | Windows | 761 passed, 36 skipped |
| `pytest -q -rs` | WSL2 | 779 passed, 18 skipped |
| `pytest -m integration -q -rs` | Windows | 23 passed, 31 skipped, 743 deselected |
| `pytest -m integration -q -rs` | WSL2 | 42 passed, 12 skipped, 743 deselected |
| Opt-ins reais 018 + 019 + 020 + 021 | WSL2 | 5 passed (2+1+1+1); `0x6E8`, `0x7A4`, `0x1A3C`, `0xFF0`, `0x1E94`, `0x1254`, `0x14E0`, `0x1764` reproduzidos |
| Baselines reais `test_toolchain_runtime.py` | WSL2 | 17 passed, 2 skipped; 7 `MATCHED` + 8 `INCONCLUSIVE` de `libhtml_view` preservados |
| `compileall -q src scripts tests` | Windows | clean |
| `git diff --check` | Windows Git | clean (WSL Git não resolve o common-dir deste worktree linkado ao Windows) |

Os skips restantes são requisitos de plataforma, ISO ausente, opt-ins
intencionais e provedores REA/Ghidra não instalados no WSL2; nenhum skip foi
promovido a aprovação de matching. `build/seto021/REPORT.md` contém a lista
detalhada dos skips, hashes, medições e o diff exato contra a base.

### SETO-DECOMP-021-R2 — Input Contracts & Provenance Correction

Correção documental posterior à auditoria da 021, aplicada sobre a mesma
branch/PR #20: apenas comentários em `decomp/src/libtutoriallist/
func_000014E0.c` e `decomp/src/libtutoriallist/func_00001E94.c`
(54 inserções / 10 remoções), sem qualquer statement, assinatura, constante,
import ou header alterado. A verificação mecânica (fonte de `HEAD` × working
tree, com comentários removidos) resulta em texto idêntico, e a recompilação
produz objetos byte a byte idênticos aos certificados na 021 — `301afd4c…`
para `0x14E0` e `24df0bdb…` para `0x1E94`.

**Afirmações corrigidas**

1. O cabeçalho de `func_000014E0.c` afirmava que o chamador `0x1764`
   "protege os contadores" antes da chamada. Isso não está demonstrado: o
   único chamador é `0x1764` (call sites `0x19C4` e `0x1A04`), que obtém
   `total` de `context[1]` do resultado de `func_000037E0` e deriva
   `progress` de comparações de altura, sem verificar explicitamente
   `total >= 2`.
2. O cabeçalho de `func_00001E94.c` não documentava os limites aritméticos e
   de memória do midpoint direto (`(low + high) / 2`) e do índice sem guarda
   (`values[middle * stride_halfwords]`).
3. Os SHA-256 embutidos nos cabeçalhos tinham proveniência ambígua/circular:
   o de `0x14E0` era o hash da variante experimental vencedora
   (`c2-early-return`), não o da fonte versionada, e o "Source SHA-256" de
   `0x1E94` era o hash da variante E7 do experimento
   (`e7-wrapper-low-first`). Nenhuma fonte C carrega mais hashes; a
   proveniência fica neste documento, em `build/seto021/REPORT.md` e na
   descrição da PR #20.

**Pré-condições de comportamento definido de `0x14E0`** (documentadas, não
impostas em runtime; nenhum guard, clamp, cast ou branch foi adicionado):

| Entrada | Comportamento |
|---|---|
| `progress == 0` | retorna antes do módulo e antes de qualquer divisão de ponto flutuante, independentemente de `total` |
| `progress != 0`, `total == 0` | atinge `current % total` — divisão inteira por zero, indefinida em C; o original executa `divu` com divisor zero, caso que a arquitetura também não define |
| `progress != 0`, `total == 1` | `half == 0` e o braço `else` executa `(float)(total - rem) / (float)half`, uma divisão de ponto flutuante por zero, não um quociente normal |
| `progress != 0`, `total >= 2` | `half >= 1`; ambos os braços dividem por um denominador não nulo |

`half = total / 2` é seguro para `total == 0` (divisão unsigned definida,
resulta 0); o risco começa no módulo. O comentário versionado não afirma que
entradas fora do domínio sejam impossíveis — apenas registra o domínio no
qual a reconstrução C tem comportamento definido.

**Limites de `0x1E94`**: `count` não negativo e pequeno o suficiente para
`count - 1` e `low + high` caberem em `int` — sob o invariante
`0 <= low <= high < count`, `count <= 2^30` (1073741824) é limite suficiente
para a soma; `middle * stride_halfwords` precisa caber em `int`;
`stride_bytes / 2` preserva a divisão assinada com truncamento do original
(stride negativo e ímpar inclusos); `values` precisa apontar para
armazenamento válido, alinhado a halfword e suficientemente extenso para
todos os índices acessados (`lhu`, operandos em `[0, 0xFFFF]`); `count == 0`
retorna `-1` sem acessar memória. O caller local conhecido (`func_00001D08`)
usa `count = 4` e `stride_bytes = 0xC` — evidência de uso, não contrato
universal. O midpoint direto foi mantido por corresponder à sequência MIPS
original; a forma segura `low + (high - low) / 2` da 020 não corresponde ao
binário.

**Matching binário × comportamento C definido**: a equivalência certificada
é a das instruções originais; o código C tem comportamento definido apenas
no domínio documentado acima, para entradas arbitrárias. Nenhum critério de
matching, flag, relocação, toolchain, assinatura de import ou política de
comparação foi alterado, e os 14 `MATCHED` / 906 words permanecem os da 021.

**Hashes finais** (recalculados após todas as alterações; objetos inalterados
em relação à certificação da 021):

| Distinção | Artefato | SHA-256 |
|---|---|---|
| 1. variante experimental | `c2-early-return` de `0x14E0` | `61917f9d5bda564baa3ed45dd6fece1fba3d2c1e86810c1d93cb856f02b611b3` |
| 1. variante experimental | `e7-wrapper-low-first` de `0x1E94` | `fc0e0b93f7ac4f2ef9cd7f8b72191093ed7c2f35336244ce172c98864365b155` |
| 2. fonte final versionada (R2) | `func_000014E0.c` | `464b158ef133b8f589cf875236bc47a0f4657f4f24a2be2fb6322936152a8b97` |
| 2. fonte final versionada (R2) | `func_00001E94.c` | `34722bc5e04dc6e6f8da79d4768a122879a04fd4bc48ce4ce941ac0f1f18563a` |
| 2b. fonte versionada da R1 (histórico) | `func_000014E0.c` R1 | `009dcba008c5ded30eecfb5ed32a149bcd4801a7a076da5f3e65897f195a6248` |
| 2b. fonte versionada da R1 (histórico) | `func_00001E94.c` R1 | `6dc89326fde1e8aa0f12cb4edd80bb6ab0e8c3b6e86675b71275ad700392f565` |
| 3. objeto compilado (inalterado) | `0x14E0` | `301afd4c338e0ac606c065e05150e6c336a030be61bc01f9fcd64d7905e9bd69` |
| 3. objeto compilado (inalterado) | `0x1E94` | `24df0bdbcc2926ef4c5e8bf0c18231dcf9047068447ed978e68916f834c8fcc4` |
| 4. PRX original | `libtutoriallist.prx` | `2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49` |

Fontes inalteradas nesta correção: `0x1254` `d9082eb8…` (objeto `78ab23a0…`)
e `0x1764` `e8e9a4a5…` (objeto `0a8d3235…`).

**Matching após a correção**: duas compilações/matches frescas por função,
nos mesmos moldes da 021 — `0x14E0` `MATCHED` 161/161 e `0x1E94` `MATCHED`
31/31, com `differences == []`, `relocation_issues == []`,
`limitations == []` e `verified_decompilation is True` (`0x1254` 163/163 e
`0x1764` `NONMATCHING` 42/182 inalterados). Os objetos recém-compilados são
idênticos aos da certificação original, o que demonstra materialmente que a
correção foi apenas documental.

**Testes após a correção**:

| Gate | Ambiente | Resultado |
|---|---|---|
| `pytest -q -rs` | Windows | 761 passed, 36 skipped |
| `pytest -q -rs` | WSL2 | 779 passed, 18 skipped |
| `pytest -m integration -q -rs` | Windows | 23 passed, 31 skipped, 743 deselected |
| `pytest -m integration -q -rs` | WSL2 | 42 passed, 12 skipped, 743 deselected |
| Opt-ins reais 018 + 019 + 020 + 021 | WSL2 | 5 passed (2+1+1+1) |
| Baselines reais `test_toolchain_runtime.py` | WSL2 | 17 passed, 2 skipped |
| `compileall -q src scripts tests` | Windows | clean |
| `git diff --check` | Windows Git | clean |
| fonte sem comentários × `HEAD` | Windows | idêntica (`r2-code-only-check.log`) |

Nenhum teste novo foi necessário: a R2 não introduz comportamento novo e as
suítes 018–021 já recompilam e comparam as quatro funções a cada execução com
as fontes corrigidas. Os logs WSL2 frescos ficam em `build/seto021/gates/`
(`wsl-full.log`, `wsl-integration.log`, `018`–`021`, `baselines`); os números
históricos das rodadas 018–021 permanecem como registrados acima.

## SETO-DECOMP-022 — Register Allocation & Data Identity Recovery

A rodada começou de uma branch nova `feat/seto-decomp-022` em `main`, após o
merge da PR #20 (021-R2). HEAD-base
`12eed4e2998fb403a63cd04ce20a976955ec9acd`; o SHA do PRX continua
`2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49`. As seções
018–021 acima não foram reescritas; nenhuma mudança foi feita em `matching.py`,
nas flags do compilador, nos critérios de equivalência ou no tratamento de
relocations. Todo artefato novo (baseline, listagens, experimentos, matches e
logs) fica em `build/seto022/`.

### Baseline antes da primeira alteração

| Função | Status reproduzido na base 021-R2 |
|---|---|
| `0x1254` | `MATCHED` 163/163 |
| `0x14E0` | `MATCHED` 161/161 |
| `0x1E94` | `MATCHED` 31/31 |
| `0x1764` | `NONMATCHING` 42/182, 140 diferenças, 32 relocation issues |
| `libhtml_view.prx` | 15 integrações reais: 7 `MATCHED`, 8 `INCONCLUSIVE`, 0 `NONMATCHING` |

O total de partida era **14 `MATCHED` / 906 words**. O hash do PRX, o
`baseline.json`, o `triage.json` e o `ghidra-boundaries.json` de 018 foram
revalidados nas integrações reais. Os logs de baseline (018–021, baselines e
opt-ins) estão em `build/seto022/baseline/`.

### `func_00000E24` — INCONCLUSIVE 113/115

Rotina de renderer que inicializa o painel de tutorial, desenha o quadro e um
segmento de progresso, formata o número da página atual e restaura o estado de
display. São 115 words, 21 call sites (17 imports + 4 locais: `0x1D08` duas
vezes com `0x1003` e `0x1020`, `0xFF0` e `0x1A3C`), 6 instruções de branch
(3 condicionais + 3 saltos incondicionais) e 1 dataref estático.

Três correções de forma foram necessárias para fechar as 115 words:

1. O quinto argumento de `0x42A8` é o **retorno** de
   `func_000041D8(func_00001D08(0x1020), index + 4)`, não o resultado direto
   de `0x1D08`. A forma anterior copiava o handle e gastava uma word.
2. O ramo de display precisa ser
   `if (func_00004120() == 0) func_00004340(0x280); else
   func_00004340(0x180);` para preservar o fall-through e o alvo originais.
3. O bloco `value` precisa da forma else-first
   `if (index >= 8) value = index - 8; else value = index;`. A forma
   then-first equivalente compila com os dois caminhos trocados; a forma
   else-first reproduz `bne v0,zero,0x0F64` com `v0 = index - 8` no delay do
   salto incondicional do caminho then.

Resultado real: **INCONCLUSIVE 113/115**, `difference_count = 0`,
`differences = []`, `relocation_issues = []`, 21 calls resolvidas e uma única
limitação: o par HI16/LO16 em `0x0ECC`/`0x0ED4` combina para o offset de
módulo `0x00006204`, que está no segmento de load zerado, fora de uma seção
nomeada. O símbolo candidato não tem identidade cross-artifact; o comparador
exclui as duas words do par, então 113/115 é o máximo sem inventar identidade.
Source SHA-256
`46dd819022ff312a75af47f783b5c6866428489790c51f226901f1f12f5f1a10`; object
SHA-256 `3a237eb0a42d20429506963862c5f6a08ed22d59443d92b802f89fd6be312d63`.
Duas compilações frescas (`attempt-1`/`attempt-2`) produziram o mesmo objeto e
o mesmo resultado.

### `func_00001D08` — INCONCLUSIVE 53/59

A função consulta uma tabela de quatro entradas de 12 bytes por meio de
`func_00001E94` (count 4, stride 12), devolve o valor cacheado em `+4` e, na
ausência de cache, obtém um handle de `func_00001C58`, copia seis bytes de
`.data+0x80` para `name[6]`, formata um caractere escolhido por
`func_00004120` em um buffer de 256 bytes via `func_000025D0`, converte por
`func_00003790` e grava o resultado no campo `+4`. São 59 words, 7 instruções
de branch (incluindo o backedge `bgtz a0,0x1D80` do loop de cópia), 5 calls
(3 imports + 2 locais: `0x1E94` e `0x1C58`) e 3 datarefs.

Duas descobertas de alocação de registradores fecharam a função:

1. A **ordem dos grupos de declaração** é load-bearing. Com buffers primeiro,
   depois os ponteiros do loop e por fim os escalares, o compilador atribui
   `entry = s0` e `handle = s1`, como no original. Colocando os escalares
   primeiro, a atribuição espelha (`entry = s1`, `handle = s0`) e sete words
   divergem; 24 permutações de declaração e 6 hints `register` foram testados,
   e somente a ordem dos grupos corrige o mapa.
2. O guard `if (index < 0) return 0;` é necessário. A forma wrapper positiva
   escolhe outro layout de branch e economiza uma word (58 vs 59), mesmo com
   semântica equivalente.

Resultado real: **INCONCLUSIVE 53/59**, `difference_count = 0`,
`differences = []`, `relocation_issues = []`, 5 calls resolvidas e três
limitações: `.data+0x34` nas words 2 e 15 e `.data+0x80` na word 25. As
localizações são `PROVEN` dentro da seção `.data` original, mas não existe
símbolo candidato ligado a elas; o comparador exclui as duas words de cada
par, então 53/59 é o máximo sem identidade cross-artifact. Source SHA-256
`75cd5d01b8448f8f8a8dc85c92f4d7858dff4fdd5b3655a6f5657b9503c83012`; object
SHA-256 `49bd56ade7ea183703b7e02655ec5f072d563312a62fef0b67dbf10ea3d9ef16`.
Duas compilações frescas produziram o mesmo objeto e o mesmo resultado.

### `func_00001764` — NONMATCHING 42/182 (diagnóstico)

A reconstrução continua completa e versionada, com os três intrínsecos
Allegrex `max`/`min` preservados (`0x17F4`, `0x1818`, `0x181C`). O resultado
real permanece **NONMATCHING 42/182**, com 140 diferenças e 32 problemas de
pairing de relocation. O bloqueio não é semântico: é uma permutação global de
registradores acoplada ao schedule do delay slot.

#### Mapa de registradores

| Valor | Original | Candidato rastreado | Família delay-slot (`v1`/`p00`) |
|---|---|---|---|
| `renderer` | `s7` | `s6` | `s5` |
| `width` | `s3` | `s3` | `s7` |
| `x` | `s5` | `s5` | `s4` |
| `y` | `s4` | `s4` | `s3` |
| `height` | `76(sp)` | `s8` | `76(sp)` |
| `start_value` | `s2` | `s2` | `s2` |
| `end_value` | `s1` | `s1` | `s1` |
| `ready` | `s6` | `s0` | `s0` |
| `full` → `start` | `s8` (reuso) | `s7` (`full`/`filled`); `start` em `76(sp)` | `s8` |
| `filled` | `s0` | `s7` | `s6` |
| `full = width - 2` | `addiu s8,s3,-2` no delay do `jal 0x1D08` (`0x17B4`) | `addiu s7,s3,-2` no delay do `beql` (`0x68`), depois do branch de `ready` | `addiu s8,s7,-2` no delay do `jal` (`0x50`) |

#### Por que `height` vai para `76(sp)` e `renderer` fica em `s7`

O original ocupa os nove registradores salvos com nove valores vivos:
`filled=s0`, `end=s1`, `start=s2`, `width=s3`, `y=s4`, `x=s5`, `ready=s6`,
`renderer=s7` e `full`/`start=s8`. `height` é o décimo valor: entra em `t0`,
é usado em `0x17F8` para calcular `start` e só volta a ser usado em `0x19A4` e
`0x19DC`, nas duas chamadas a `func_000014E0`. O vão entre esses usos atravessa
todas as chamadas de renderer, então o alocador escolhe spillar `height` e
manter `start` no registrador. O candidato faz a escolha oposta: mantém
`height` em `s8` e spilla `start` em `76(sp)`.

`renderer` precisa sobreviver a todas as chamadas de import: cada uma devolve
o novo renderer em `v0` e clobbera os caller-saved, então o valor tem de ficar
em um registrador salvo (`s7` no original, `s6` no candidato). Isso consome um
dos nove registradores e é parte da pressão que expulsa `height`.

O cálculo `full = width - 2` é independente da chamada `0x1D08` e cabe no
delay slot do `jal` (`0x17B4`), executando incondicionalmente antes do teste
de `ready`. A forma de dois passos (`full = width; full -= 2;`) mantém os
parâmetros originais, mas o compilador afunda o cálculo para o delay do
`beql` (`0x68`), depois do branch de `ready`. A forma de um passo
(`full = width - 2;`) ocupa o delay do `jal`, mas seleciona a rotação
alternativa de parâmetros (`renderer=s5`, `width=s7`, `x=s4`, `y=s3`,
`filled=s6`). Nenhuma fonte testada combina o delay slot original com o mapa
`renderer/x/y/width` original.

#### Experimentos da 022

Além do corpus da 021 (31 variantes `v1`–`v31`, 24 permutações `perm-*`,
5 micro-formas `q1`–`q6` e o candidato rastreado = 61 objetos), a 022 gerou
**35 variantes de contexto/inlining** (posição de `context`/`total`/`current`,
inlining de `func_000037E0`, cinco formas de `ready`) em
`build/seto022/experiments/1764/new/` e **30 variantes de declaração/hint**
(24 permutações puras + 6 `register` em `full`/`filled`/`height`/`ready`/
`renderer`/`start`) em `build/seto022/experiments/1764/decl/`. O corpus total
tem 126 candidatos montados e pontuados por `score_variants.py`.

Todos os melhores candidatos empatam em **42 words exatas, 81 de mesma forma,
primeira diferença na instrução 14** (a word `sw t0,76(sp)` do original contra
`addu s8,t0,zero` do candidato): nenhuma variante superou 42. A família
delay-slot (`v1`/`p00`) cai para 19 exatas, com primeira diferença na word 26,
justamente porque a rotação de parâmetros atinge mais words. O resultado
confirma que o bloqueio é uma decisão global do alocador, não uma ordem de
declaração, um contexto inlineado ou uma micro-forma de expressão.

#### Pré-condições aritméticas e de memória

O código C reproduz as instruções originais; ele não adiciona guards. Para
comportamento C definido:

| Entrada / operação | Requisito |
|---|---|
| `full = width - 2` | `width - 2` representável em `int`; `width < 2` produz `full` negativo, que é passado às chamadas de renderer sem guarda |
| `start_value < end_value` | o ramo de cálculo usa `filled = start_value * full / end_value`; `end_value != 0` é necessário para divisão definida (o original executa `div` por zero se `end_value == 0`) |
| `end_value - start_value` | divisor de `height * (full - filled) / (end_value - start_value)`; no ramo, `start_value < end_value` implica diferença positiva, mas a subtração pode overflow se os extremos forem `INT_MIN`/`INT_MAX` |
| Produtos `start_value * full` e `height * (full - filled)` | devem caber em `int`; o original usa `mult`/`mflo` e mantém os 32 bits baixos do produto de 64 bits |
| Divisões | são `div` assinado com truncamento em direção a zero; `INT_MIN / -1` é o caso excepcional da arquitetura |
| `context = func_000037E0()`, `current_context = func_000037E0()` | devem retornar ponteiros válidos; `context[1]` e `*current_context` são desreferenciados sem checagem de null |
| `ready = func_00001D08(0x1003)` | se `ready == 0`, a função retorna o `renderer` de entrada antes de qualquer divisão ou desreferência; caso contrário, `ready` é o nono argumento de `func_000014E0` |
| `height` | usado como booleano (`height > 0`) e em `height < end_value - start_value`; a comparação herda o possível overflow da subtração |

Os intrínsecos `__builtin_allegrex_max`/`min` são a construção mínima fiel às
três words `dadd`/`daddu` de `0x17F4`/`0x1818`/`0x181C`; nenhuma forma
`if`/ternário os reproduziu em nenhum nível de otimização testado.

### Total verificado após 022

| Módulo / estado | Contagem |
|---|---:|
| `MATCHED` acumulados (7 `libhtml_view` + 7 `libtutoriallist`) | **14 funções** |
| `INCONCLUSIVE` novos em 022 | **2 funções**: `0xE24` 113/115 e `0x1D08` 53/59 |
| Words com instruções equivalentes nos dois novos `INCONCLUSIVE` | **166** (113 + 53), com zero diferenças de instrução |
| Words excluídas por pares HI16/LO16 não resolvidos | **8** (2 em `0xE24`, 6 em `0x1D08`) |
| `NONMATCHING` atual | **1 função**: `0x1764`, 42/182 |
| Novos `MATCHED` em 022 | **0** |
| Words `MATCHED` acumulados | **906** (inalterado) |

A meta de 15–16 `MATCHED` não foi atingida. As duas funções novas têm zero
diferenças de instrução, mas a identidade dos objetos de dados não é
demonstrável cross-artifact; convertê-las a `MATCHED` exigiria inventar um
símbolo ou afrouxar o critério, o que não foi feito. `0x1764` continua sendo a
única função ainda não certificada sem datarefs e, portanto, a única rota
restante para um novo `MATCHED` estrito neste módulo.

### Gates e regressões 022

| Gate | Ambiente | Resultado |
|---|---|---|
| `pytest -q -rs` | Windows | 761 passed, 37 skipped |
| `pytest -q -rs` | WSL2 | 779 passed, 19 skipped |
| `pytest -m integration -q -rs` | Windows | 23 passed, 32 skipped, 743 deselected |
| `pytest -m integration -q -rs` | WSL2 | 42 passed, 13 skipped, 743 deselected |
| Opt-ins reais 018 + 019 + 020 + 021 + 022 | WSL2 | 6 passed (2+1+1+1+1) |
| Objetos 021 após a rodada | WSL2 | SHA-256 idênticos: `78ab23a0…`, `24df0bdb…`, `301afd4c…`, `0a8d3235…` |
| `compileall -q src scripts tests` | Windows | clean |
| `git diff --check` | Windows Git | clean |

Os logs dos gates ficam em `build/seto022/final/` e nos diretórios
`build/seto022/matches/f0e24/`, `f1d08/` e `f1764/`. Os skips restantes são
requisitos de plataforma, ISO ausente, opt-ins intencionais e provedores
REA/Ghidra não instalados; nenhum skip foi promovido a aprovação.

### Hashes finais

| Distinção | Artefato | SHA-256 |
|---|---|---|
| 1. PRX original | `libtutoriallist.prx` | `2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49` |
| 1. evidência 018 | `baseline.json` | `6ef4ee553ce21205ed7ba738db519086c140a1374097a77e59e39a9cbf4fa043` |
| 1. evidência 018 | `triage.json` | `fb1cc157ada5448dfb8e88e2b73bd4d26b6d665d9ff11ef667e2298158aa17a5` |
| 1. evidência 018 | `ghidra-boundaries.json` | `e86fb8c954421a4f2923e8409adcec8ec2578bef6a0941dfa6f95ef390bb671b` |
| 2. fonte 022 | `func_00000E24.c` | `46dd819022ff312a75af47f783b5c6866428489790c51f226901f1f12f5f1a10` |
| 2. fonte 022 | `func_00001D08.c` | `75cd5d01b8448f8f8a8dc85c92f4d7858dff4fdd5b3655a6f5657b9503c83012` |
| 2. fonte 022 (inalterada) | `func_00001764.c` | `e8e9a4a5834a9b84d6ccb38c21125361641e491114c9ddc4efaf526aa0718cdd` |
| 3. objeto 022 | `0xE24` | `3a237eb0a42d20429506963862c5f6a08ed22d59443d92b802f89fd6be312d63` |
| 3. objeto 022 | `0x1D08` | `49bd56ade7ea183703b7e02655ec5f072d563312a62fef0b67dbf10ea3d9ef16` |
| 3. objeto 022 (inalterado) | `0x1764` | `0a8d3235b28413127ed1d653d1236dff684f552e327d00b87a940485f88746ea` |
| 3. objeto 021 (inalterado) | `0x1254` | `78ab23a040226e1217487d08d6cfb5ccc5b6812e4ea8c4bdac368e3dcbcb2c06` |
| 3. objeto 021 (inalterado) | `0x1E94` | `24df0bdbcc2926ef4c5e8bf0c18231dcf9047068447ed978e68916f834c8fcc4` |
| 3. objeto 021 (inalterado) | `0x14E0` | `301afd4c338e0ac606c065e05150e6c336a030be61bc01f9fcd64d7905e9bd69` |

As fontes 021 não foram tocadas nesta rodada; os quatro objetos 021
permanecem byte a byte idênticos aos certificados na 021-R2.

### Próximo candidato

`func_00001B70` (42 words) é o próximo front viável. Ele tem zero imports, uma
única chamada local (`0x1C58`), nenhuma dependência de tabela e quatro
referências a um único byte de estado global no offset `0x6250` do segmento de
load; o corpo testa/atualiza um bitfield em `0x1B70–0x1C14`. A reconstrução
deve chegar a zero diferenças de instrução e ficar limitada apenas pelas words
dos pares HI16/LO16 daquele global. Em seguida, `func_00001DF4` (36 words, um
import `0x3780`, o mesmo global) reusa o mesmo estado.

Todas as funções EXACT ainda não reconstruídas têm datarefs; não há outra
função não certificada com zero datarefs além de `0x1764`. Portanto, um novo
`MATCHED` estrito exige resolver o bloqueio de alocação de `0x1764` ou provar a
identidade do objeto global — não basta reconstruir mais uma função.

### SETO-DECOMP-022-R2 — Prototype Compatibility & Memory Contracts

Correção posterior à auditoria da PR #21, aplicada sobre a mesma branch/PR:
`feat/seto-decomp-022`, HEAD-base
`716d89bfaebbc6b534e9b1829a1ff126d6fa37b6`. Não há função nova, mudança de
critério de matching, flag, toolchain, relocation ou equivalência. Dos oito
arquivos de código e header alterados, seis são chamadores que apenas perderam
a declaração local duplicada de `0x1D08`; nenhum statement, constante, import
ou corpo de função foi alterado. A única mudança de código é a largura do
parâmetro `key` de `0x1D08` e os protótipos locais compartilhados no header.

**Compatibilidade de protótipos**

A definição certificada de `0x1E94` usa `unsigned short key` e o objeto
original mascara o argumento com `andi a0,a0,0xffff` em `0x1EB0`. O call site
original de `0x1D08` em `0x1D24` passa `a0` sem qualquer máscara. O domínio do
chamador é, portanto, 16 bits.

A primeira tentativa manteve `func_00001D08(int key)` e alterou apenas o
protótipo de `0x1E94` para `unsigned short key`. O Metrowerks inseriu uma
máscara redundante `andi a0,a0,0xffff` em `0x1D10`, deslocando o corpo: o
resultado caiu para **NONMATCHING 3/59**, com 51 diferenças e a primeira
divergência já na word 2 (associação HI16/LO16). A conversão do argumento
`int` para `unsigned short` no caller não é gratuita.

A correção usa o mesmo domínio de 16 bits nos dois lados: `0x1D08` e `0x1E94`
são declarados em `libtutoriallist_stubs.h` com `unsigned short key`, e as seis
declarações locais duplicadas de `0x1D08` foram removidas. Os callers passam
constantes que cabem em 16 bits (`0x1003`, `0x1011`, `0x1020`), então a
conversão é compile-time e não gera instrução. O objeto de `0x1D08` ficou byte
a byte idêntico ao certificado; a divergência acima é a justificativa para a
largura do parâmetro do caller, não um cast artificial.

**Contratos de memória**

Nenhum guard, clamp, cast ou branch foi adicionado. Os comentários distinguem
o que o binário demonstra do que é apenas domínio de entrada necessário:

| Acesso | Demonstrado | Hipótese / obrigação do chamador |
|---|---|---|
| `name[func_00004120()]` em `0x1D08` | o fragmento tem seis bytes copiados de `.data+0x80`; o byte é lido em `buffer+index`; não há clamp nem bounds check | `func_00004120()` deve retornar `0..5`; o artefato não prova essa faixa; outros usos da função no módulo a comparam com zero; fora da faixa o original lê bytes adjacentes da stack |
| `func_00000E24_extents[index]` em `0x0E24` | a base combina para o offset de módulo `0x00006204`; o load de halfword usa `index` diretamente; não há bounds check | `index` deve selecionar um elemento válido; o tamanho e a posse da tabela não estão provados; a faixa dos chamadores não foi estabelecida |

A tabela de `0x1D08` (quatro entradas, stride 12) tem count/stride
demonstrados pelos argumentos da chamada e pela reconstrução de `0x1E94`; a
extensão e a posse continuam hipóteses. Nenhum limite foi inventado para
`name` ou para os extents.

**Resultados e limitações**

| Função | Resultado | Objeto SHA-256 |
|---|---|---|
| `0x0E24` | `INCONCLUSIVE` 113/115, zero diferenças | `3a237eb0…` (inalterado) |
| `0x1D08` | `INCONCLUSIVE` 53/59, zero diferenças | `49bd56ad…` (inalterado) |
| `0x1764` | `NONMATCHING` 42/182, 140 diferenças / 32 relocation issues | `0a8d3235…` (inalterado) |

O total continua **14 `MATCHED` / 906 words**. As seis funções chamadoras de
`0x1D08` — `0x6E8` 47/47, `0x7A4` 83/83, `0xFF0` 153/153, `0x1254` 163/163,
`0xE24` 113/115 e `0x1764` 42/182 — mantiveram status, contagem e objeto byte
a byte. Os objetos de `0x14E0` `301afd4c…`, `0x1E94` `24df0bdb…` e `0x1A3C`
`c2932f8c…` também permaneceram idênticos. A limitação de identidade de dados
de `0xE24`/`0x1D08` e o bloqueio de alocação de `0x1764` não foram alterados;
nenhum deles foi promovido a `MATCHED`.

**Hashes finais da R2**

| Distinção | Artefato | SHA-256 |
|---|---|---|
| 1. PRX original | `libtutoriallist.prx` | `2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49` |
| 2. fonte R2 | `func_00000E24.c` | `7b09c23e70ac9e668a7633f236cd3811fe1231d815096f40ea02243c89e097f4` |
| 2. fonte R2 | `func_00001D08.c` | `a65b41419346eab1e817f118243c2f1bec6dff30c52f2183ed3a6d7614a47911` |
| 2. fonte R2 | `func_00001764.c` | `2a1126ed3dd3d2f62fca54b956f0496e44f55866df6097e3b406a9066b36eb62` |
| 2. fonte R2 | `libtutoriallist_stubs.h` | `638ce2d1880cecfd33d8b497fcf6d167143043029f3c8948f6aa44061988f9d0` |
| 2b. chamador R2 (declaração removida) | `func_000006E8.c` | `7323db7f0f6b36b254b0ba67c9babd63b972981e9ac2096c7c84957ed0bd06d5` |
| 2b. chamador R2 (declaração removida) | `func_000007A4.c` | `f10766ab55eb459650052c642c74de73291d3da1152651b6f612b67b25f01ac0` |
| 2b. chamador R2 (declaração removida) | `func_00000FF0.c` | `a0cad5d06ea90126440847da770191f79ad389d7c735b356989d7840a2f80195` |
| 2b. chamador R2 (declaração removida) | `func_00001254.c` | `8fd98ea08087f1471951ac75a0d2f63362e3152926cbc284a0434b62b99f7397` |
| 2b. fonte 021-R2 (inalterada) | `func_000014E0.c` | `464b158ef133b8f589cf875236bc47a0f4657f4f24a2be2fb6322936152a8b97` |
| 2b. fonte 021-R2 (inalterada) | `func_00001E94.c` | `34722bc5e04dc6e6f8da79d4768a122879a04fd4bc48ce4ce941ac0f1f18563a` |
| 3. objeto | `0x0E24` | `3a237eb0a42d20429506963862c5f6a08ed22d59443d92b802f89fd6be312d63` |
| 3. objeto | `0x1D08` | `49bd56ade7ea183703b7e02655ec5f072d563312a62fef0b67dbf10ea3d9ef16` |
| 3. objeto | `0x1764` | `0a8d3235b28413127ed1d653d1236dff684f552e327d00b87a940485f88746ea` |
| 3. objeto 021-R2 (inalterado) | `0x1254` | `78ab23a040226e1217487d08d6cfb5ccc5b6812e4ea8c4bdac368e3dcbcb2c06` |
| 3. objeto 021-R2 (inalterado) | `0x1E94` | `24df0bdbcc2926ef4c5e8bf0c18231dcf9047068447ed978e68916f834c8fcc4` |
| 3. objeto 021-R2 (inalterado) | `0x14E0` | `301afd4c338e0ac606c065e05150e6c336a030be61bc01f9fcd64d7905e9bd69` |

As fontes de `0x14E0`/`0x1E94` continuam com os hashes da 021-R2; a fonte de
`0x1254` mudou apenas pela remoção da declaração local de `0x1D08`, com objeto
inalterado. A fonte de `0x1764` mudou apenas pela remoção da mesma declaração;
o corpo e o objeto continuam os da 022.

**Testes após a correção**

| Gate | Ambiente | Resultado |
|---|---|---|
| `pytest -q -rs` | Windows | 761 passed, 37 skipped |
| `pytest -q -rs` | WSL2 | 779 passed, 19 skipped |
| `pytest -m integration -q -rs` | Windows | 23 passed, 32 skipped, 743 deselected |
| `pytest -m integration -q -rs` | WSL2 | 42 passed, 13 skipped, 743 deselected |
| Opt-ins reais 018 + 019 + 020 + 021 + 022 | WSL2 | 6 passed (2+1+1+1+1) |
| `compileall -q src scripts tests` | Windows | clean |
| `git diff --check` | Windows Git | clean |

Cada função afetada foi compilada e comparada em duas tentativas frescas por
execução; a suíte 022 também recompila `0x0E24`, `0x1D08` e `0x1764` duas vezes
e compara os resultados. Os logs da R2 ficam em `build/seto022/r2/` e o
detalhe operacional em `build/seto022/REPORT.md`.

## SETO-DECOMP-023 — Shared State Reconstruction & Data Identity Recovery

Branch `feat/seto-decomp-023`, criada de `main` atualizado para
`3e154b0d51b3c602ab4626e1530aa085f1980ab8`. O PRX original manteve o SHA-256
`2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49`. Antes
das alterações, a baseline real 018 foi reconstruída e comparada canonicamente
com `baseline.json`/`triage.json`; os boundaries Ghidra preservados também
revalidaram. Os opt-ins reais 018–022 passaram (6 testes), reproduzindo as
certificações anteriores.

### Baseline

| Estado antes da 023 | Resultado reproduzido |
|---|---|
| `MATCHED` acumulados | **14 funções / 906 instruções** (7 `libhtml_view`, 7 `libtutoriallist`) |
| `libhtml_view` | 8 `INCONCLUSIVE`, preservadas |
| `0xE24` | `INCONCLUSIVE` 113/115, zero diferenças, 1 par de dados sem identidade |
| `0x1D08` | `INCONCLUSIVE` 53/59, zero diferenças, 3 pares sem identidade |
| `0x1764` | `NONMATCHING` 42/182, 140 diferenças, 32 relocation issues |

O hash do PRX, a baseline/triage 018 e os limites Ghidra estão em
`build/seto023/baseline/`. A compilação usa a configuração local WSL2 existente
e as flags oficiais `-O4,p -sdatathreshold 0`; matcher, critérios, relocations e
toolchain não foram alterados.

**Histórico da R1 (commit `e43f52b`):** o teste 023 aceitava `ERROR` para os
objetos curtos: `0x1B70` 156/168 bytes e a forma compacta `return enabled` de
`0x1DF4` 140/144 bytes. A R2 preserva esse diagnóstico histórico e muda o teste
para exigir comparação real; `ERROR`/`BLOCKED` não são resultados aceitos.

### `func_00001B70` — NONMATCHING 5/42

Intervalo Ghidra exato `[0x1B70,0x1C18)`, 42 instruções; nenhuma importação e
uma chamada local em `0x1BA4` para `0x1C58`. A função não recebe argumentos e
retorna 0 ou 1. O C versão a operação observável: testa o bit 0 do byte em
`0x6250`; se os bits 1–7 são não-zero, limpa o campo e retorna 1; se o campo é
zero, chama `0x1C58` e, quando o retorno é não-zero, incrementa o campo modulo
128 antes de retornar 0. Os nomes “flag”/“count” descrevem somente a forma dos
bits; semântica de nível superior não foi atribuída.

As quatro referências originais são pares HI16/LO16 para o mesmo endereço de
módulo `0x6250`. Loads/stores diretos são byte (`lbu`/`sb`) em `0x1B7C`,
`0x1BB8`, `0x1BE4` e `0x1BFC`. Três pares são confirmados pelo fluxo de
registradores; `0x1BD8/0x1BE4` depende da ordem das relocations. O slot de delay
em `0x1BE4` é o `sb` que grava o byte antes do salto para o retorno.

**Resultado R2, duas tentativas frescas:** `NONMATCHING` 5/42, 30 diferenças,
8 relocation issues e 2 limitações de pairing; `resolved_calls = []`,
`resolved_data = []`, `verified_decompilation = false`. A comparação efetivamente
compara os 42 words, mas não certifica a função.

Os primeiros desvios mostram a hipótese de retorno/branch: o original usa
`beql v0,zero,epílogo` com `move v0,zero` no delay slot; o candidato inverte o
branch-likely e usa um salto separado para o epílogo. O count extraído como
`unsigned short` introduz `andi 0xffff` após `srl`; o original chega diretamente
ao teste de zero. No caminho count-nonzero, o original agenda o clear da
contagem e o `sb` no delay slot do salto; o candidato distribui stores e
retorno por blocos diferentes. O call a `0x1C58` deixa de coincidir no mesmo
word, e os HI16/LO16 seguintes ficam desalinhados. A localização do estado
continua no mesmo PT_LOAD, mas a comparação não comprova equivalência.

Hipóteses C testadas, sem padding: retorno antecipado vs wrapper ativo; retorno
comum em local e `goto` para o clear; layout comum/separado do store; `count`
`unsigned int`/`unsigned char`/`unsigned short`; `state` byte vs word. O retorno
comum/`result` atingiu 42 words, e a combinação byte-state/short-count/byte-result
é a melhor comparação observada (5/42). As formas compactas com `unsigned int`
foram menores e geravam `ERROR`; nenhuma variante testada superou 5 palavras
comparáveis.

#### Blocos e registradores de `0x1B70`

| Bloco original | Candidato R2 | Divergência observada |
|---|---|---|
| Entrada: `lbu a0`; `andi`; `beql` para retorno-zero com `move v0,zero` no delay | `lbu v1`; `andi`; `bnel` com `sll v0,v1,24` no delay e salto ao epílogo | desvio de GPR/branch no início; o delay slot de retorno não é reproduzido |
| Campo: `sll`/`srl`, depois `beq count,zero,call` | `sll`/`srl`, `andi 0xffff` da conversão de `count`, depois branch | count deixa de estar imediatamente no formato de 7 bits original |
| Count nonzero: salto com `andi zero,0x7f` no delay para clear posterior; `sll zero`, mask, `or`, store | clear inline com resultado local; store/return em blocos distintos | call e stores deslocam; o call `0x1C58` não alinha no mesmo word |
| Call/zero-count: `beq v0,zero,return`; update e `sb` no delay do salto | branch-likely inverso e salto separado; atualização/retorno em outros blocos | delay slots e pairing HI16/LO16 divergem |

O original não usa registradores `$s*`; a fonte R2 também compila sem salvá-los.
O objeto final e as 30 diferenças completas estão em
`build/seto023/matches/f1b70/attempt-{1,2}`.

### `func_00001DF4` — NONMATCHING 19/36

Boundary Ghidra exato `[0x1DF4,0x1E84)`, 36 instruções, argumentos assinados
`(arg0,arg1)`. O retorno é o predicado assinado `arg1 > 0`. Quando esse
predicado é verdadeiro e `arg0 != 0`, chama o import `libehsys`, NID
`0x4B0DABFA`, stub `0x3780`, com `(0,arg0)`; o retorno do import é ignorado. Em
seguida incrementa modulo 128 os bits 1–7 do byte compartilhado e, em todos os
caminhos, força o bit 0 para 1. A declaração `void func_00003780(int,int)` no
header registra apenas os argumentos observados e o retorno não utilizado;
não afirma um protótipo SDK.

Os quatro pares em `0x1E20/0x1E24`, `0x1E44/0x1E4C`, `0x1E50/0x1E54` e
`0x1E6C/0x1E70` são confirmados por fluxo de registradores. As referências
`0x1E24`/`0x1E54` são `lbu`; `0x1E4C`/`0x1E70` são `sb`.

**Resultado R2, duas tentativas frescas:** `NONMATCHING` 19/36, 11 diferenças,
3 relocation issues e 2 limitações HI16/LO16 de identidade nos dados
`0x6250`; a chamada importada foi resolvida por NID. `resolved_data = []` e
`verified_decompilation = false`. O símbolo `func_00001DF4` no objeto tem 152
bytes (38 words); o matcher compara os 36 words/144 bytes do intervalo original.
Os dois words extras no objeto não são certificados como parte do intervalo.

A divergência começa na word 23, no registrador base (`lui v0` vs `lui v1`), e
continua no bloco final de atualização/retorno: candidato e original escolhem
ordem e registradores diferentes para `state & ~1`, o bit de ativação, store e
retornos. Os três relocation issues nos words 23/27/30 mostram a mudança de
pairing/alinhamento no final. A forma compacta `return enabled` foi testada e
compilou 140 bytes (4 bytes curta), logo produziu `ERROR`; a versão atual usa
retornos explícitos 0/1 para que o matcher compare o intervalo completo.

Também foram testados estado local byte/word, ordem de declarações,
`state &= ~1; state |= 1;` versus `(state & ~1) | 1`, e formas aritméticas de
setar o bit. O Metrowerks manteve os mesmos desvios no bloco final; a comparação
R2 sobre o intervalo de 36 words é a mais próxima observada. Não foram
adicionados guards, operações de padding ou assembly inline.

#### Bloco final e registradores de `0x1DF4`

Até o teste de `arg0` e o import, `$s0` contém o predicado signed `arg1 > 0` e
sobrevive ao call, como no original. A primeira diferença é word 23: original
`lui v1`/`lbu a1`, candidato `lui v0`/`lbu a0`. Depois o original prepara `1` em
`a0`, copia `$s0` para `v0`, calcula `state & -2` em `v1`, faz
`or a0,v1,a0`, grava e cai no epílogo comum. O candidato mascara em `a0`, usa
`ori`, grava e emite branches explícitos para os retornos 0/1. Isso explica as
diferenças de words 25–35 e os relocation issues nos words 23/27/30.

### `func_00001C58` — análise condicionada

O intervalo original tem 44 instruções e foi inspecionado porque é a chamada
local de `0x1B70`. O fast path carrega a word em `0x6248` e retorna-a se
não-zero. Sem essa word, só prossegue se o bit 0 de `0x6250` estiver set; nesse
caminho limpa o bit, chama imports `0x36A0` (NID `D2A768F4`), `0x3A00` (NID
`41AABF28`) e `0x3668` (NID `8288EEBC`), grava o resultado em `0x6248` e
retorna zero. Isso explica por que `0x1B70` só incrementa o campo quando
`0x1C58` encontra um estado já inicializado; a rotina de inicialização pode
limpar o bit de atividade.

Não foi versionado `func_00001C58.c`: além de oito referências de dados, o call
site de `0x3668` carrega `0x1DF4` em `t0` no delay slot. A função importada não
tem protótipo local equivalente que permita modelar esse uso de `t0` com a ABI C
observada sem inventar uma assinatura ou argumento. A análise acima é evidência
de instruções, não uma reconstrução compilada.

### Identidade estrutural dos quatro destinos

O ELF tem um único `PT_LOAD` com `p_filesz=0x6190`, `p_memsz=0x6290` e `vaddr=0`.
`.data` cobre `[0x60EC,0x6190)` e `.bss` é `SHT_NOBITS` de tamanho zero.
Assim, `0x6204` e `0x6250` estão no tail zero-filled do segmento 0 (offsets
`0x6204` e `0x6250`), não em seção nomeada; o valor numérico não cria um
`DataTarget`.

| Destino original | Referências encontradas no módulo | Evidência binária | Identidade cross-artifact |
|---|---|---|---|
| `0x6250` | 13 pares em `0x1B0C` (3), `0x1B70` (4), `0x1C58` (2), `0x1DF4` (4) | mesmo endereço no PT_LOAD; acessos diretos são byte; 12 pares têm pairing provado e entram no grupo de localização do segmento, 1 par de `0x1B70` depende da ordem da relocation | **não provada** |
| `0x6204` | 3 pares em `0x2F4`, `0x0E24`, `0x21F8` | todos localizados no tail do mesmo PT_LOAD; loads da tabela são `lhu` em `0x664`, `0xEDC` e `0x2518` | **não provada**; tamanho/posse da tabela seguem desconhecidos |
| `.data+0x34` (`0x6120`) | `0x1B0C` em `0x1B50`; `0x1D08` em `0x1D18` e `0x1D48` | três referências `PROVEN` à mesma localização `.data` no PRX; `0x1D08` usa tabela count 4/stride 12; `0x1B0C` passa o endereço ao call local `0x2638` | **não provada** |
| `.data+0x80` (`0x616C`) | `0x1D08` em `0x1D74` | uma localização `PROVEN`; código consome um fragmento de seis bytes | **não provada** |

`datarefs.build_global_usage` foi reutilizado para agrupar somente localizações
do PRX, sem as promover a identidade. O teste real tenta resolvers de módulo e
um `SymbolLink` com `verified=False`; ambos retornam `None`. As fontes candidatas
referem o símbolo provisório `func_00006250_state`, que é um nome criado nesta
reconstrução, não um vínculo independente. Nenhum link foi marcado
`verified=True`.

### Busca limitada de evidência independente

Foi inspecionada somente a árvore imediata `PSP_GAME`, `USRDIR`, `gmodule`,
`module` e `SYSDIR`, sem execução ou busca de sistema. Não há `.map`, `.o`,
`.elf`, `.sym`, `.dbg`, `.pdb` ou `.dwo` que estabeleça o layout de link.
`libtutoriallist.prx` e o PRX irmão `libhtml_view.prx` não têm símbolos nem
seções de debug; `libadler.prx` e `EBOOT.BIN` são payloads PSP e não foram
desempacotados nem executados. Os artefatos gerados do próprio PRX, nomes
escolhidos pelo decompilador, bytes iguais, mesma seção/offset e referências
múltiplas não demonstram identidade cross-artifact. A busca não encontrou
evidência independente; nenhum dos quatro destinos foi resolvido.

### Regressores preservados e totais

Os opt-ins reais 018–022 foram repetidos depois das declarações compartilhadas:
**6 passaram**. Na R2, os hashes dos objetos certificados não mudaram; em particular
`0xE24` segue `INCONCLUSIVE` 113/115, `0x1D08` segue `INCONCLUSIVE` 53/59 e
`0x1764` segue `NONMATCHING` 42/182. Os oito `INCONCLUSIVE` de `libhtml_view`
também permanecem. O total continua **14 `MATCHED` / 906 instruções**; a 023
não acrescentou instruções certificadas nem novos `MATCHED`.

O opt-in 023 (`SETO_LIBTUTORIALLIST_023_REAL=1`) passou a validação de contratos
e duas tentativas frescas por função. Ele agora exige comparações reais
`NONMATCHING`, verifica counts/diferenças/relocation issues/limitações e
`verified_decompilation=false`; `ERROR` e `BLOCKED` não são aceitos como
sucesso.

### Hashes da 023

| Artefato | SHA-256 |
|---|---|
| PRX original | `2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49` |
| Fonte `func_00001B70.c` | `3f593557c7f40441b17ee0e2503a098dfd231135e9d0b3e8d758934f103a398f` |
| Objeto `0x1B70` (`NONMATCHING` 5/42) | `fbca086054040a74bc25c3a60c5b31d8b3d35d8a91e025f3e47e5731b0ed1c20` |
| Fonte `func_00001DF4.c` | `206691cdfcb332ea72205794447d0e6da617a64458db0bfb427d9df4eff44bf8` |
| Objeto `0x1DF4` (`NONMATCHING` 19/36) | `085fea270aa437d117dc8f2e310dfccca3463519c6414cffd337c5d68c97ec00` |
| `libtutoriallist_stubs.h` | `dfd25c5a41aa789576b7a24d88017fa885f9ca734d74503d9e66cd2da7879735` |
| Teste real 023 | `c636ba603a07493e2ae56a8ebe52a0654ca775f0c75e08586f770aa5d99afeef` |

### Testes e skips

| Gate | Ambiente | Resultado |
|---|---|---|
| `pytest -q -rs` | Windows | 761 passed, 38 skipped |
| `pytest -q -rs` | WSL2 | 778 passed, 21 skipped |
| `pytest -m integration -q -rs` | Windows | 23 passed, 33 skipped, 743 deselected |
| `pytest -m integration -q -rs` | WSL2 | 41 passed, 15 skipped, 743 deselected |
| Opt-ins reais 018–023 | WSL2 | 7 passed (2+1+1+1+1+1; o 023 verifica comparações `NONMATCHING` estáveis) |
| `compileall -q src scripts tests` | Windows | clean |
| `git diff --check` | Windows Git | clean |

Os skips incluem opt-ins deliberadamente inativos, plataforma, ISO ausente,
Ghidra/REA/Splat não configurados e, no full WSL, três testes de YAML porque
`PyYAML` não está instalado no venv. Nenhum desses skips foi contado como
matching. Logs, baseline, auditorias e objetos ficam em `build/seto023/`.

### Próximo bloqueio

Antes de promover esta rodada como reconstrução comparada, é necessário achar
formas C fiéis de `0x1B70`/`0x1DF4` que reproduzam branches, delay slots,
registradores e stores sem padding, e aumentar a comparação além de 5/42 e
19/36. Os diffs e relocation issues R2 já são comparação real; não devem ser
escondidos. Mesmo após resolver o codegen, a identidade de `0x6250`, `0x6204`,
`.data+0x34` e `.data+0x80` continua pendente sem prova independente.

## SETO-DECOMP-024 — Control-Flow & Register Matching

Branch `feat/seto-decomp-024`, criado sobre `main` em
`721a802ec5cd3ad3425e34d51c9a6605f0fdbde4`, após o merge da PR #22. O PRX
original tem SHA-256
`2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49`. A rodada
reproduziu a baseline com Metrowerks `mwccpsp_3.0.1_219`, WSL2/wibo e flags
oficiais `-O4,p -sdatathreshold 0`, sem alterar compilador, flags, comparador,
imports, assinaturas ou identidade de dados.

### Resultado

| Função | Baseline pré-024 | Final reproduzido (2 compilações) | Tamanho do símbolo candidato | Estado |
|---|---|---|---:|---|
| `0x1DF4` | `NONMATCHING` 19/36; 11 diferenças; 3 relocation issues | `NONMATCHING` 19/36; 11 diferenças; 3 relocation issues; 2 limitações | 152 bytes (38 words); compara-se o intervalo original de 144 bytes | **sem avanço** |
| `0x1B70` | `NONMATCHING` 5/42; 30 diferenças; 8 relocation issues | `NONMATCHING` 5/42; 30 diferenças; 8 relocation issues; 2 limitações | 168 bytes (42 words) | **sem avanço** |

As duas tentativas frescas de cada fonte produziram status, diferenças, limitações,
relocations e hashes estáveis. Nenhum resultado `ERROR`/`BLOCKED` foi contado como
comparação final. Os experimentos curtos listados abaixo são explicitamente
`ERROR`, não resultados de matching. Nenhuma variante foi mantida nas fontes C:
o código executável continua sendo o melhor candidato da R2; `func_00001DF4.c`
recebe somente uma correção de comentário sobre o tamanho real do símbolo.

O total certificado continua em **14 `MATCHED` / 906 instruções**. As oito
funções `libhtml_view` `INCONCLUSIVE`, os resultados da 022 e as certificações
anteriores permanecem inalterados. Não há nova função `MATCHED` nem equivalência
alegada para estes dois alvos. A identidade cross-artifact do byte `0x6250`
continua sem prova.

### Comparação alinhada por blocos

Mapas com todos os words/opcodes originais e candidatos, razões do matcher e
limitações estão em `build/seto024/final/aligned-instructions.md`.

#### `0x1DF4`

As words 0–22 mantêm a sequência de prólogo, predicado signed, guards, chamada
importada e incremento do campo. O import em `0x1E18` segue resolvido como
`libehsys/0x4B0DABFA`, stub `0x3780`, com retorno não usado. A primeira diferença
é a word 23 (`0x1E50`): `lui v1` original versus `lui v0` candidato, com palavra
relocada diferente fora do campo. O bloco original `[23,36)` carrega em `a1`,
prepara `1` em `a0`, copia `s0` para `v0`, mascara e combina o byte, armazena e
cai no epílogo comum. O candidato carrega em `a0`, usa `ori`, armazena no delay
slot de um branch e emite branches/constantes distintos para os retornos; o
epílogo é deslocado. As diferenças agrupam-se no bloco final, não no import nem
no cálculo do contador. Relocation issues nas words 23, 27 e 30; as duas
limitações de identidade permanecem nas words 11 e 20.

**Correção de tamanho:** o símbolo candidato atual mede 152 bytes (38 words),
embora o intervalo original tenha 144 bytes (36 words). A comparação R2/024
alinha e compara os 36 words solicitados, mas os dois words excedentes impedem
afirmar tamanho binário exato. A forma compacta `return enabled` mede 140 bytes
e resulta em `ERROR` por ser curta.

#### `0x1B70`

A primeira diferença é a word 2 (`0x1B78`): o opcode `lui v0` coincide, mas o
valor relocável não, pois o destino original zero-fill `0x6250` não tem
identidade cross-artifact demonstrada. Na word 4, `andi v0,a0,1` original vira
`andi v0,v1,1`; a word 5 troca `beql` para o epílogo, com `move v0,zero` no
delay slot, por `bnel` em direção ao corpo, com a extração `sll` no delay slot.
Esse grupo (words 4–12) altera registradores, sucessores e retorno-zero inicial;
o candidato também introduz `andi 0xffff` por `count` `unsigned short`.

O call local original é a word 13 (`0x1BA4`); na R2 candidata a relocation do
call aparece na word 19 (`0x1BBC`). O original testa o campo, salta ao clear
posterior com `andi zero,0x7f` no delay slot, chama `0x1C58` no caso zero e
coloca o `sb` em `0x1BE4` no delay slot do salto ao retorno-zero. O candidato
emite blocos clear/call/retorno em outra ordem, deslocando os HI16/LO16 do
restante da atualização. Os oito relocation issues são nas words 2, 13, 15, 17,
19, 22, 26 e 34; a associação de word 29 continua limitada por fluxo de controle
que cruza o scan. `resolved_calls=[]`, portanto não se afirma que o call local
foi alinhado/provado pelo matcher.

### Hipóteses novas e variantes refutadas

| Função / hipótese | Evidência compilada em duas tentativas | Decisão |
|---|---|---|
| `0x1DF4`: acesso direto `func_00006250_state = (global & ~1u) | 1u`, retorno compacto | Final do bloco aproximou `lui v1`, `lbu a1` e `addu v0,s0`, mas o Metrowerks usou a máscara como operando e `ori`; objeto 140 bytes, `ERROR` (5aa1c36a…). | Rejeitada: não há comparação completa. |
| `0x1DF4`: limpar bit e somar 1 no mesmo lvalue | Também 140 bytes, `ERROR`; o candidato emite `addiu`, não a combinação `or` necessária, e continua um word curto. | Rejeitada; não é evidência de match. |
| `0x1DF4`: acesso direto com retornos explícitos | O otimizador emitiu o objeto R2 `085fea27…`, 152 bytes, sem qualquer mudança nos 19/36, 11 diffs e 3 relocations. | Rejeitada: volta ao codegen baseline. |
| `0x1DF4`: habilitar bit por condição sobre seu estado anterior | Introduziu branch no update e manteve `NONMATCHING` 19/36, 11/3; não corrigiu o bloco final nem o pairing. | Rejeitada. |
| `0x1B70`: count-zero/call antes do clear, `count` `unsigned int`, retornos antecipados | Call aproximou-se da word original (candidato word 12, original word 13), mas o objeto mede 152 bytes/38 words e retorna `ERROR`; entry/count branches e delay slots continuam distintos. | Rejeitada: `ERROR`, não comparação. |
| `0x1B70`: retorno comum com resultado local e `count` `unsigned int` | 152 bytes/38 words (`ERROR`); ainda organiza clear/call incorretamente e a variante de resultado local salva `$s0`, ao contrário do original. | Rejeitada. |
| `0x1B70`: retorno comum com `count` `unsigned short`/resultado byte | 160 bytes/40 words (`ERROR`); reaparecem dois `andi 0xffff`, e o CFG não se alinha. | Rejeitada. |
| `0x1B70`: `goto` para os blocos call/clear e expressões explícitas para limpar/preservar o bit | O compilador otimizou as expressões/gotos para os mesmos objetos de 38 words; não gerou a sequência de branches/slots necessária. | Rejeitada; nenhum status `ERROR` foi usado como comparação. |

Variantes não comparáveis foram descartadas e não são aceitas pelo teste. Não
foram adicionados NOPs, padding, código morto, `volatile`, assembly inline,
casts artificiais, mudanças de flags ou lógica no comparador.

### Hashes e reprodutibilidade

| Artefato | SHA-256 |
|---|---|
| PRX original | `2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49` |
| Fonte final `func_00001B70.c` | `0ae3b52221d31266984227ab17e0e7759765020ff23e1ee0ad5e1cb294f2d39f` |
| Objeto `0x1B70`, tentativas 1 e 2 (168 bytes) | `fbca086054040a74bc25c3a60c5b31d8b3d35d8a91e025f3e47e5731b0ed1c20` |
| Fonte final `func_00001DF4.c` | `d3dcf4766df569e99649415bca71943ace9cfa870e227353e7915e58c8c97949` |
| Objeto `0x1DF4`, tentativas 1 e 2 (152 bytes) | `085fea270aa437d117dc8f2e310dfccca3463519c6414cffd337c5d68c97ec00` |

O opt-in 024 (`SETO_LIBTUTORIALLIST_024_REAL=1`) usa duas compilações frescas
por função e compara exatamente os campos estáveis; exige estado `NONMATCHING`
medido e grava diferenças/relocations completas sob `build/seto024/`. Não
interpreta `matching_words` como certificação. A validação 023 continua verde;
como o código C executável não mudou, seus contratos históricos 19/36 e 5/42
seguem válidos.

### Testes e preservação

| Gate | Ambiente | Resultado |
|---|---|---|
| `pytest -q -rs` | Windows | 761 passed, 40 skipped |
| `pytest -q -rs` | WSL2 | 778 passed, 23 skipped |
| `pytest -m integration -q -rs` | Windows | 23 passed, 35 skipped, 743 deselected |
| `pytest -m integration -q -rs` | WSL2 | 41 passed, 17 skipped, 743 deselected |
| Opt-ins reais 018–024 | WSL2 | 9 passed; 023 e 024 repetidos após a correção do comentário |
| `compileall -q src scripts tests` | Windows | clean |
| `git diff --check` | Windows Git | clean |

Os três skips YAML na suíte WSL permanecem por ausência de `PyYAML`; skips de
ISO/Splat, Ghidra/REA e opt-ins não ativados continuam sendo skips, não matching.
Relatórios, disassemblies, objetos e mapas ficam em `build/seto024/`; PRX e
objetos não são versionados.

### Bloqueio e próxima hipótese

O objetivo principal desta rodada não foi atingido: `0x1DF4` não chegou a zero
diferenças e o símbolo candidato ainda excede o tamanho original; `0x1B70` não
avançou além de 5/42. Não há ganho a promover como matching. A próxima tentativa
deve encontrar uma expressão C semanticamente natural que mantenha o retorno em
`v0`, produza o operando `1` em `a0` e o mask em `v1` sem branches explícitos em
`0x1DF4`; para `0x1B70`, deve reproduzir o `beql`/delay slot inicial, o branch
ordinary zero-count para o call na word 13, o `sb` em delay slot e o clear
posterior, sem `$s*`. Não relaxar a identidade do byte `0x6250`.

### SETO-DECOMP-024-R3 — Deep Decompilation Push

Executada na mesma branch `feat/seto-decomp-024` e PR #23, partindo de
`547c5b0a9037e73beb8df97c2ab0f0548707274d`. O PRX mantém SHA-256
`2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49`. Compilador,
wibo, includes e flags oficiais `-O4,p -sdatathreshold 0` foram preservados;
nenhum código em `matching.py`, `datarefs.py` ou na infraestrutura Python de
produção foi alterado. Todos os artefatos operacionais da R3 ficam em
`build/seto024/deep-push/`.

**Resultado:** os dois alvos antes bloqueados agora têm zero diferenças e
tamanho exato; duas funções conectadas foram reconstruídas também sem
diferenças, e o callback comparador recuperado acrescentou **um `MATCHED` / 4
words**. O total certificado passou de **14/906 para 15 funções/910 words**.
Os pares de dados/endereços de callback sem identidade continuam inconclusivos.

#### Antes/depois e tamanho integral

| Função | Antes da R3 | Resultado final, duas compilações | Bytes original / símbolo candidato | Diferenças / relocation issues | Limitações |
|---|---|---|---:|---:|---|
| `0x1DF4` | `NONMATCHING` 19/36 | **`INCONCLUSIVE` 28/36** | **144 / 144** (antes 152) | **0 / 0** (antes 11 / 3) | 4 pares de identidade de dados |
| `0x1B70` | `NONMATCHING` 5/42 | **`INCONCLUSIVE` 34/42** | **168 / 168** | **0 / 0** (antes 30 / 8) | 4 pares de identidade + 2 avisos de pairing |
| `0x1C58` | somente analisada | **`INCONCLUSIVE` 28/44** | **176 / 176** | **0 / 0** | 8 pares de identidade + 2 avisos de pairing |
| `0x1B0C` | não reconstruída | **`INCONCLUSIVE` 15/25** | **100 / 100** | **0 / 0** | 5 pares de identidade |
| `0x1E84` | fragmento sem caller direto reconhecido | **`MATCHED` 4/4** | **16 / 16** | **0 / 0** | nenhuma; `verified_decompilation=true` |
| `0x1764` | `NONMATCHING` 42/182 | inalterado, **42/182** | **728 / 728** | 140 / 32, inalterados | nenhuma; não certificado |

Cada comparação final cobre o símbolo inteiro, não apenas um prefixo. Os cinco
alvos novos/melhorados foram recompilados duas vezes com objetos e campos
estáveis idênticos. Os quatro `INCONCLUSIVE` têm `verified_decompilation=false`,
`resolved_data=[]` e nenhuma diferença de instrução ou relocation issue; as
words dos pares sem identidade não são contadas como certificadas.

#### Descoberta principal: inserções de bitfield, não máscaras inteiras

A representação mínima fiel é uma struct de **dois bitfields `unsigned char`**:
bit 0 `active:1`, bits 1–7 `count:7`. Com o Metrowerks oficial ela ocupa um byte
e produz os acessos `lbu`/`sb`, shifts e inserções observados. Os nomes continuam
descritivos e provisórios; o tipo não demonstra identidade cross-artifact nem
semântica de subsistema.

Em `0x1DF4`, `state.count++` mantém o incremento modulo 128 e
`state.active = 1` preserva a operação de inserção do compilador. A segunda
atribuição precisa de uma constante em registrador e de um OR de registradores,
ao contrário da máscara inteira que era otimizada para `ori`. Isso explica por
que as permutações anteriores repetiam o mesmo objeto errado: modificavam
expressões dentro de outro grafo de dependências.

| Valor no bloco final `0x1DF4` | Definição / último uso | Original = R3 | Candidato anterior |
|---|---|---|---|
| predicado assinado | word 3 / retorno | `s0` → `v0` na word 26 | `s0` testado por branches de retorno |
| endereço do load | word 23 / word 24 | `v1` | `v0` |
| byte carregado | word 24 / máscara na word 28 | `a1` | `a0` |
| valor 1 a inserir no bit baixo | word 25 / OR na word 29 | `a0` | immediate de `ori` |
| máscara/bits preservados | word 27 / OR na word 29 | `v1` | `v1`, outra ordem |
| byte atualizado | word 29 / store na word 31 | `a0` | `v1` |
| endereço do store | word 30 / word 31 | `v1` | `v0`, materializado na word 27 |

Após o load, o endereço em `v1` está morto e pode ser reutilizado pela máscara,
pelos bits preservados e depois pelo endereço do store. O bit de inserção fica
vivo em `a0` enquanto o retorno é preparado em `v0`; o resultado cai diretamente
no epílogo comum. Desaparecem os branches extras, as três relocation issues e
as duas words excedentes. As quatro limitações restantes estão nas words
11/20/23/30 e são somente de identidade.

#### `0x1B70`: o CFG original vem de um `switch`

Somente a troca para bitfields não basta. Um `if` do campo não-zero compila o
clear antes da chamada; a forma call-first usa `bnel` diretamente para o bloco
clear. Ambas emitem 40 words/160 bytes e são **`ERROR` por tamanho**, não
comparações válidas.

O `switch (state.count)` com `case 0` e `default` gera exatamente o dispatch
original: `beq` para a chamada, delay slot vazio e salto separado ao clear
posterior com `andi v0,zero,0x7f` no delay slot. Com isso:

- entrada: `beql` e retorno-zero no delay slot;
- extração: `sll`/`srl` sem `andi 0xffff`;
- chamada local `0x1C58` na word 13 (`0x1BA4`), agora resolvida pelo matcher;
- releitura do byte depois da chamada, antes do incremento;
- `sb` no delay slot em `0x1BE4` e clear posterior em `0x1BE8`;
- nenhum save de registrador `$s*`; símbolo inteiro de 42 words.

O clear só ocorre no caminho não-zero; o incremento só ocorre após retorno
não-zero de `0x1C58`. Nenhuma leitura cruzou o call nem foi adicionado store.
O pairing original em words 26/29 continua associado por ordem, sem ser
artificialmente promovido a prova.

#### `0x1C58`: seis argumentos observados, callback natural em `t0`

A hipótese de quinto argumento é correta mas incompleta: o call site também
prepara `t1`. A chamada de `libehsys/0x8288EEBC`, stub `0x3668`, usa o seguinte
conjunto de argumentos observados:

| Registrador | Valor / evidência original |
|---|---|
| `a0` | constante 3 em `0x1CDC` |
| `a1` | endereço `.data+0x64` (path), HI/LO em `0x1CCC`/`0x1CE0` |
| `a2` | handle retornado por `0x3A00`, `move a2,v0` em `0x1CE4` |
| `a3` | token retornado por `0x36A0`, mantido em `s0` e copiado em `0x1CD4` |
| `t0` | endereço de `func_00001DF4`, low em **`0x1CF0`, delay slot do `jal`** |
| `t1` | o mesmo handle de `a2`, `move t1,v0` em `0x1CE8` |

Um protótipo de seis argumentos reproduz as 44 words sem casts, assembly ou
mudança de ABI. O retorno do import é ignorado: a instrução seguinte prepara
zero em `v0`. Esse é um contrato de uso do caller, não uma assinatura SDK nem
prova de que o import nunca consome outros argumentos.

A reconstrução preserva o fast path que retorna o cache em `0x6248`, o guard
do bit ativo, o clear antes dos imports, `0x36A0` (`D2A768F4`), `0x3A00`
(`41AABF28`), o store do handle antes do registro e o retorno-zero do slow path.
`func_00001DF4(int,int)` permanece com sua assinatura compatível, compartilhada
no header. Os globals `0x6238`/`0x6248`, o path e o endereço de callback são
declarados como referências provisórias; nenhum asset foi recriado.

#### `0x1B0C` e o comparador recuperado `0x1E84`

O PRX confirma o intervalo de 25 words e dois **imports**: `0x2610`
(`libehsys/10F3BB61`) e `0x2638` (`libehsys/1B00FB95`). A menção anterior a
`0x2638` como chamada local era incorreta. A função passa `(endereço do byte,
0,1)` ao primeiro, ativa o bit baixo e passa `(tabela,4,12,comparador)` ao segundo.
A tabela usa o mesmo símbolo provisório de `0x1D08`, sem forjar `.data`.

O primeiro parâmetro de `0x2610` passou de `int *` para `void *`: o mesmo import
recebe buffers de inteiros nos callers anteriores e este objeto de um byte.
Isso evita um cast incompatível; os argumentos/ABI e todos os objetos anteriores
continuam idênticos. Os dois imports têm retorno não utilizado nestes usos.

A relocation `0x1B30`/`0x1B60` fornece o endereço `0x1E84` em `a3` como
comparador. O corpo `[0x1E84,0x1E94)` contém dois `lhu` e `subu` no delay slot
do retorno: a forma natural é `return *arg0 - *arg1` para dois ponteiros válidos
e alinhados a `unsigned short`. A diferença fica em `[-65535,65535]`, sem
overflow de `int`.

A triagem histórica classificava esse intervalo como `FRAGMENT`: Ghidra não
o havia identificado e a seleção buscava callers diretos ou pointers da tabela
resident. A referência de callback no call site agora estabelece o papel de
função; nem a triagem de produção nem os artefatos Ghidra foram modificados.
O símbolo completo de 16 bytes é **`MATCHED` 4/4**. Esse match **não** resolve
automaticamente o par do endereço de callback em `0x1B0C`, que continua
`INCONCLUSIVE`.

#### Investigação limitada de `0x1764`

Após consultar as gerações 021/022 de hints, declarações, contexto inlineado e
ordenação de `full`/`ready`, foi testado um grafo diferente: reutilizar o span
como posição final, mantendo os intrínsecos `max/min` e sem aritmética nova.
O resultado spillou `height` em `76(sp)` e colocou `full` no delay slot do
`jal`, mas também spillou a posição em `72(sp)` e manteve a rotação errada
(`renderer=s5`, `width=s7`, `ready=s0`, `filled=s6`). Emitiu 732 bytes e
`NONMATCHING` 19/182, 163 diferenças e 38 relocation issues. Foi descartado;
a fonte e o objeto baseline de 728 bytes/42 words coincidentes não mudaram.
Não foi repetida uma busca de dezenas de permutações equivalentes.

#### Regressões e evidência TDD

O opt-in 023 foi executado antes das alterações para capturar os objetos reais
que falhavam nas propriedades alvo: zero diferenças/tamanho exato do bloco
final e dispatch/slots corretos em `0x1B70`. Os diagnósticos RED existentes e a
baseline fresca ficam preservados, não aceitos como resultados novos. Depois
das correções, as asserções ativas de 023 passaram a exigir os resultados
medidos `INCONCLUSIVE`, zero diffs/issues, limitações exatas e **tamanho do
símbolo inteiro em ambas as tentativas**. O histórico 19/36 e 5/42 permanece
apenas documental, não impede melhorias futuras.

O teste duplicado `test_libtutoriallist_024_real.py` foi removido. O novo teste
focado `test_libtutoriallist_callbacks_real.py`, opt-in
`SETO_LIBTUTORIALLIST_CALLBACKS_REAL=1`, cobre somente `0x1B0C`, `0x1C58` e
`0x1E84`; usa `run_real_match`, duas compilações frescas, símbolos integrais,
determinismo e as limitações reais. Não há teste unitário superficial nem
mudança de Python de produção. `ERROR`/`BLOCKED` não são resultados aceitos.

#### Cobertura e certificações

| Métrica | Antes | Depois |
|---|---:|---:|
| C reconstruído/compilado/comparado em `libtutoriallist` | 12 funções / 1124 words originais | **15 funções / 1197 words** (+3 / +73) |
| Funções `libtutoriallist` sem diferenças de instrução | 9 (7 `MATCHED` + 2 `INCONCLUSIVE`) | **14 (8 `MATCHED` + 6 `INCONCLUSIVE`)** |
| Words originais nas cinco funções novas/melhoradas sem diferenças | — | **151**; não somados a certificação |
| `MATCHED` `libtutoriallist` | 7 / 690 words | **8 / 694 words** |
| `MATCHED` acumulados com `libhtml_view` | 14 / 906 words | **15 / 910 words** |
| `libhtml_view` | 7 `MATCHED`, 8 `INCONCLUSIVE` | inalterado |

Os sete objetos `libtutoriallist` anteriormente certificados mantiveram seus
SHA-256; `0xE24` continua `INCONCLUSIVE` 113/115 e `0x1D08` 53/59 com objetos
idênticos, e `0x1764` conserva 42/182. As quinze funções de `libhtml_view` foram
recompiladas/comparadas, mantendo sete `MATCHED`/216 words e oito
`INCONCLUSIVE`. Os 271 words contados nas seis funções `libtutoriallist`
inconclusivas não são adicionados aos 910 words de funções certificadas.

#### Hashes finais (bytes das fontes no worktree Windows)

| Função / artefato | Fonte SHA-256 | Objeto SHA-256, idêntico nas tentativas 1/2 |
|---|---|---|
| `0x1DF4` | `9e4d4fba6e7c5e089f6cf5eff970861a7ee7c4cac71f6cb973f32ccac47db6e7` | `f0fe0bf974bca659c892847d1b8bc6db8aeaccac8481006aa5475ad7b4063791` |
| `0x1B70` | `a67e83a6736e469c53914defe49c2acaa3b3e473b67d52071dbcbb9a9ced191e` | `0f2188eb9e3105753a90424adad71406a5bba68b1331b91f04b9e47ca466f491` |
| `0x1C58` | `e99748be52320e19591f93ae0d50dea33159967b870b9e3f44556c1b19ea5e13` | `807134dfd1ee244300d69df3be325b1aa64127c9a432f8418d14fa04689124d7` |
| `0x1B0C` | `bdcad2972c39d7e484734957f2831e246c67518cb187e3a0feffb631c86bcc70` | `baf774c761c17ad7a917d883ec09c99e5c54276ba194d0f3328c328cf31d5334` |
| `0x1E84` | `0ed720acd46dacf6b0b5eb68e1efe82a8b4ab73e3a4f9f9ade4b6c311bd0bdd8` | `ace41b323481c0b6ff7887b74ef339f7473f5ed0dd88ee0dfcac90ca59ff9ce7` |

Header compartilhado:
`a07e2711fa860efc843f75343957057aa55da5abe3c6e1a604f06151bfc12fb0`.
Hashes de fonte dependem de LF/CRLF; os registros guardam os bytes efetivamente
compilados, sem hashes circulares nos comentários C. `final-results.json`
consolida objetos, tamanho integral, calls, limitações e comparação dos hashes
anteriores; disassemblies completos por tentativa ficam em `matches/`.

#### Gates finais

| Gate | Ambiente | Resultado |
|---|---|---|
| `pytest -q -rs` | Windows | **761 passed, 39 skipped** |
| `pytest -q -rs` | WSL2 | **778 passed, 22 skipped** |
| `pytest -m integration -q -rs` | Windows | **23 passed, 34 skipped, 743 deselected** |
| `pytest -m integration -q -rs` | WSL2 | **41 passed, 16 skipped, 743 deselected** |
| Opt-ins reais 018–023 + callbacks R3 | WSL2 | **8 passed**; cada alvo alterado/novo compilado duas vezes |
| `test_toolchain_runtime.py -k real_mwccpsp` | WSL2 | **16 passed, 3 deselected** (15 funções `libhtml_view`; caso `0x508` também validado isoladamente) |
| `compileall -q src scripts tests` | Windows e WSL2 | clean |
| `git diff --check` | Windows Git | clean |

Os três skips YAML do full WSL continuam por ausência de PyYAML. ISO/Splat,
Ghidra/REA e opt-ins inativos continuam explicitamente não executados; nenhum
requisito ausente foi transformado em aprovação. Não foram versionados objetos,
PRXs, dumps de assets, variantes descartadas ou ferramentas genéricas novas.

#### Bloqueios restantes

`0x1DF4`, `0x1B70`, `0x1C58` e `0x1B0C` não têm mais bloqueio de codegen;
permanecem sem identidade independente para globals/tabelas/endereços de
callback. O comparador continua estrito, inclusive para o endereço de um
callback cujo corpo já é `MATCHED`. `0x1764` conserva o bloqueio global de
alocação/spill. Os próximos passos devem tratar essas provas ou um novo grafo
de interferência de `0x1764`, não repetir máscaras/retornos/permutações já
refutados. Esta rodada entrega implementação real, não apenas gates verdes.

---

## SETO-DECOMP-025 — Full-Scale One-Shot Decompilation Offensive

### 1. Base, artefatos e escopo

A rodada parte de `origin/main` em
`e3c5935009867657af7cae4a92fee1971d8da8a6`, no branch
`feat/seto-decomp-025-oneshot`. O HEAD inicial e o merge-base são o mesmo
commit; nenhum merge ou reescrita de histórico foi feito.

| Artefato | Tamanho | SHA-256 | Papel |
|---|---:|---|---|
| `libtutoriallist.prx` | 30 234 | `2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49` | módulo principal, `.text` 0x0–0x25B0 |
| `libhtml_view.prx` | 21 426 | `319901ff13bc9a44be29596bcb64e4c0c7333dad9fb36bdafceb8c2aed611f26` | auditoria de cobertura e preservação |
| `EBOOT.BIN` | 1 110 624 | `9a5bbf89419b6ba13494318fce4adb6279d099bda54fbf40b9c2dc178b96809a` | `~PSP`, não-ELF |
| `libadler.prx` | 1 088 | `dcb2765c0e99f18a326b62b7b1cbcf960d5e970c8b587e100cbf4d1457a841d1` | `~SCE`, não-ELF |

O `.text` de `libtutoriallist.prx` tem 9 648 bytes (2 412 words) e termina em
0x25B0, onde começa `.sceStub.text` (9 960 bytes). O `.text` de
`libhtml_view.prx` tem 2 036 bytes (509 words). O `.comment` do tutorial
registra `MW MIPS C Compiler (2.4.1.01)`; a reconstrução usa o compilador
disponível `mwccpsp 3.0.1 build 219` com `-O4,p -sdatathreshold 0`. Isso é
equivalência para o compilador/flags observados, não uma alegação de
equivalência com o compilador histórico.

A baseline de 024 — **15 `MATCHED` / 910 instruções certificadas**, sendo
8 funções de tutorial / 694 words e 7 de `libhtml_view` / 216 words — foi
preservada. Nenhum objeto certificado anterior foi substituído. Os cinco
objetos de 024 (`0x1DF4`, `0x1B70`, `0x1C58`, `0x1B0C`, `0x1E84`) foram
recompilados duas vezes nesta rodada; status, words, source SHA-256 e object
SHA-256 coincidiram com `build/seto024/deep-push/final-results.json`.

### 2. Inventário linear: 0x1C18 é um thunk, 0x1C20 é seu corpo

O inventário linear antigo tratava `[0x1C18,0x1C58)` como uma única entrada de
16 words. Os bytes originais mostram duas entidades:

- `[0x1C18,0x1C20)` — `08 07 00 08 00 00 00 00`, ou seja `j 0x1C20; nop`;
- `[0x1C20,0x1C58)` — 14 words, começando por `addiu sp,sp,-16;
  sw ra,12(sp)` e terminando em 0x1C58, com prólogo/epílogo próprios.

A evidência de chamada é `func_00000280` word 2, que chama 0x1C18; o alvo do
salto direto é 0x1C20. O corpo de 0x1C20 é uma função completa, não um label
interno: ele testa o handle provisório em 0x6248, chama o import
`libehsys/0x20E340D9` (stub 0x3A08) com o contexto em 0x6238 e o handle, e zera
o handle. A divisão correta é, portanto, **2 + 14 words**, não 16 words com um
único dono.

Para comparar o intervalo autêntico de 2 words sem alterar o comparador, foi
adicionado um pass-through `--size` ao `scripts/match_function.py`. A CLI
`seto match` já aceitava `--size`; o script apenas não o encaminhava. O
`run_real_match` do triage também aceita `function_size` e valida que ele é
um múltiplo positivo de 4 e que `function_size // 4 == expected_total_words`.
Isso não muda regras de matching, não mascara diferenças e não é um novo
critério de certificação.

O resultado oficial é:

- `0x1C18`: **`MATCHED` 2/2**, objeto de 8 bytes, zero diferenças/issues/
  limitações. A equivalência é `function equivalence with canonically resolved
  relocations`, porque o salto local para 0x1C20 é resolvido por identidade de
  símbolo; não é igualdade binária bruta do campo de relocation.
- `0x1C20`: **`INCONCLUSIVE` 8/14**, objeto de 56 bytes, zero diferenças/
  issues, três limitações HI16/LO16 (words 2, 6 e 9). O call para 0x3A08
  resolve por `libehsys/0x20E340D9`.

### 3. Novas reconstruções C e comparações de símbolo completo

Foram adicionadas dez fontes novas em `decomp/src/libtutoriallist/`, cobrindo
1 213 words originais. Todas compilam com o compilador oficial e foram
comparadas duas vezes a partir de objetos recém-gerados.

Para as funções cujo símbolo completo difere do intervalo antigo (0x2F4 é
menor; 0x8F0, 0x1F10 e 0x21F8 são maiores), a CLI pública truncaria ou
recusaria a comparação. Esses quatro casos usam `seto.matching.compare` sobre
o símbolo completo do candidato e o intervalo original explícito — a mesma
API de comparação de produção, sem regra nova. `ERROR`/`BLOCKED` nunca foram
aceitos como veredito.

| Intervalo | Fonte | Words originais | Objeto candidato | Status | Words iguais | Diferenças | Issues de relocation | Limitações |
|---|---:|---:|---:|---|---:|---:|---:|---:|
| `0x8–0x154` | `func_00000008.c` | 83 | 332 B / 83 | `INCONCLUSIVE` | 63/83 | 0 | 0 | 16 |
| `0x154–0x280` | `func_00000154.c` | 75 | 300 B / 75 | `INCONCLUSIVE` | 65/75 | 0 | 0 | 9 |
| `0x280–0x2C8` | `func_00000280.c` | 18 | 72 B / 18 | `INCONCLUSIVE` | 12/18 | 0 | 0 | 3 |
| `0x2C8–0x2F4` | `func_000002C8.c` | 11 | 44 B / 11 | `NONMATCHING` | 7/11 | 1 | 1 | 4 |
| `0x2F4–0x6E8` | `func_000002F4.c` | 253 | 996 B / 249 | `NONMATCHING` | 93/253 | 137 | 35 | 2 |
| `0x8F0–0xE24` | `func_000008F0.c` | 333 | 1 368 B / 342 | `NONMATCHING` | 50/342 | 286 | 70 | 1 |
| `0x1C18–0x1C20` | `func_00001C18.c` | 2 | 8 B / 2 | **`MATCHED`** | **2/2** | **0** | **0** | **0** |
| `0x1C20–0x1C58` | `func_00001C20.c` | 14 | 56 B / 14 | `INCONCLUSIVE` | 8/14 | 0 | 0 | 3 |
| `0x1F10–0x21F8` | `func_00001F10.c` | 186 | 748 B / 187 | `NONMATCHING` | 70/187 | 81 | 3 | 21 |
| `0x21F8–0x25B0` | `func_000021F8.c` | 238 | 964 B / 241 | `NONMATCHING` | 119/241 | 78 | 11 | 21 |

Os quatro `INCONCLUSIVE` com zero diferenças (0x8, 0x154, 0x280 e 0x1C20)
não são promovidos: as words não-iguais são pares HI16/LO16 cuja identidade
de dados não pode ser provada a partir do PRX stripped. O `0x1C18` é a única
nova certificação estrita; seu match é por equivalência de relocation local
resolvida, explicitamente registrada no teste.

### 4. `0x2C8`: limitação de associação do comparador, não erro de fonte

`0x2C8` compila para as mesmas palavras de instrução do original e usa o mesmo
layout de relocations:

| Sítio original | Offset candidato | Relocation | Addend original | Addend candidato |
|---|---:|---|---|---|
| `0x2C8` | 0 | `R_MIPS_HI16` | 0 | 0 |
| `0x2CC` | 4 | `R_MIPS_LO16` | 0x6194 | 4 (símbolo `func_00006190_panel` + 4) |
| `0x2DC` | 20 | `R_MIPS_HI16` | 0 | 0 |
| `0x2E8` | 32 | `R_MIPS_LO16` | 0x6196 | 6 (símbolo `func_00006190_panel` + 6) |

A word 7 (`addiu v0,zero,-1`) redefine o registrador-base da LO16 antes de
`0x2E8`. O comparador, do lado original, perde a associação entre a HI16 de
`0x2DC` e a LO16 de `0x2E8`; do lado candidato, a associação sobrevive por
identidade do símbolo. O resultado é `NONMATCHING` 7/11 com uma diferença e uma
issue de relocation, embora os bytes sejam idênticos. O teste de integração
fixa essa limitação exata. **Não foi relaxada nenhuma regra do comparador nem
adicionada uma identidade de dados fabricada para promover a função.**

### 5. Funções grandes: divergência medida e hipóteses rejeitadas

- **`0x2F4` (93/253).** O candidato tem 996 bytes, quatro words menor que os
  1 012 bytes originais. As primeiras diferenças, words 32/34, são
  deslocamentos de branch causados por esse tamanho menor. A primeira
  divergência substancial é a word 81 (`lui v1` no candidato, `lui a0` no
  original), no setup de flags/lista. O original contém um `lhu a0,20(t3)`
  duplicado e aparentemente morto em 0x4B0, depois de um `beq` incondicional;
  o compilador candidato escolhe a forma bnel/fall-through mais compacta. Não
  foi inserido código morto, padding ou branch artificial para reproduzir o
  duplicado.
- **`0x8F0` (50/342).** O candidato tem 1 368 bytes, nove words maior que os
  1 332 bytes originais. A primeira diferença é a word 15: o original mantém
  `height` em `s2` desde a entrada até 0xb44 e depois reutiliza `s2` como
  contador do loop; o candidato spill-a `height` em `0x4c(sp)` e entrega `s2`
  a `top`. A forma de alocação/interferência não foi reproduzida sem alterar
  a semântica observável.
- **`0x1F10` (70/187).** O candidato tem 748 bytes, uma word maior que os
  744 originais. As words 0–95 são exatamente iguais; a word 96 (`andi t0` no
  candidato, `andi t2` no original) inicia a rotação da cauda, com `group` em
  `t0` em vez de `t2`. O accessor else-first melhorou o corpo, mas não fechou
  a alocação da cauda.
- **`0x21F8` (119/241).** O candidato tem 964 bytes, três words maior que os
  952 originais. As words extras deslocam branches desde cedo (word 32). A
  divergência estrutural está na rotação dos registradores de grupo/janela:
  o original mantém `group` em `a2`, `group*2` em `t2`, `&leading` em `a0` e
  `&count` em `a3`; o candidato usa `group` em `t0`, `group*2` em `a3`,
  `&leading` em `a1` e `&count` em `a2`. A forma else-first e a remoção das
  duplicações de guarda foram adotadas, mas a pressão de registradores continua
  diferente.
- **`0x1764` (42/182).** A fonte foi novamente compilada para confirmar que o
  resultado não regrediu: 728 bytes, 140 diferenças, 32 issues de relocation,
  primeira divergência na word 10 (alocação do prólogo). As mais de 120
  variantes de alocação/ordenação já refutadas não foram repetidas. A função
  permanece congelada até surgir um grafo de interferência novo.

### 6. ABI, layout e fatos de import recuperados

- **`func_00004118` retorna `unsigned short`.** Com `int`, o compilador omite
  o `andi v0,v0,0xffff` observado; com `unsigned short`, o `andi` aparece. A
  assinatura está no header compartilhado e é usada por `0x21F8` nos masks
  `pressed & func_00004118(1)` (fechamento) e `pressed & func_00004118(0)`
  (atualização de janela).
- **`func_00003A38` retorna `int *`.** `0x21F8` lê `input[1]` sem guarda de
  null, como no original. A assinatura é derivada do uso, não de um SDK.
- **Layout provisório do painel em 0x6190.** A estrutura de 0xB8 bytes usada
  pelas novas fontes tem `phase` em +0, `flags` em +4, `current` em +6,
  `leading[2]` em +8, `trailing[2]` em +0xC, `count[2]` em +0x10,
  `entries[2][24]` em +0x14 e `extents[26]` em +0x74. `0x8` zera os 0xB8
  bytes via import 0x2610. Isso prova **localização e uso**, não a identidade
  de um objeto de dados linkado; nenhuma definição `.data` foi inventada.
- **`0x1C20`** chama `libehsys/0x20E340D9` (stub 0x3A08) com o contexto em
  0x6238 e o handle em 0x6248, e então zera 0x6248. O handle é provisório.
- **`0x1C18`** é um salto direto para 0x1C20, com a word de delay `nop`; o
  objeto candidato reproduz oito bytes exatos.
- **`0x2F4`** passa o endereço do renderer local para 0x4908; a vida
  stack-backed observável foi mantida, sem `volatile`. O endereço do callback
  não ganhou uma identidade cross-artifact.
- **`0x8F0`** usa as constantes de cor observadas `0x80FFFFFF` e `0xFF808080`;
  não foi introduzida uma cor “semântica” nova.
- **Globais provisórios**: 0x6238 (contexto), 0x623C (file), 0x6240 (data),
  0x6248 (handle), 0x6250 (byte compartilhado), 0x60F0 (nome). Todos são
  referências por endereço; os testes e comentários não os promovem a objetos
  originais.

### 7. `libhtml_view.prx`: cobertura e o fragmento 0x84–0x8C

O módulo irmão foi recompilado e comparado por inteiro, sem alterar suas 15
fontes:

| Grupo | Funções | Words | Resultado |
|---|---:|---:|---|
| `MATCHED` | 7 | 216 | `0x244` 13, `0x34` 20, `0x134` 17, `0x358` 17, `0x8C` 42, `0x178` 51, `0x278` 56 |
| `INCONCLUSIVE` | 8 | 291 | 231 words iguais + 60 words limitadas por pares HI16/LO16 |
| `NONMATCHING` | 0 | 0 | — |
| Fragmento sem fonte | 1 | 2 | `[0x84,0x8C)` |

O único intervalo sem C é `[0x84,0x8C)`, oito bytes `jr ra; nop`. `func_00000000`
passa 0x84 como segunda address de código ao import `libehsys/0xB4471B5E`;
0x84 também é o fim exclusivo do corpo `[0x34,0x84)` de `func_00000034`. O
mesmo endereço é consistente com um callback no-op **ou** com um ponteiro de
fim de faixa. O PRX sozinho não distingue as duas leituras; não há caller
direto, outro site que tome o endereço, nem relocation que exija uma entry de
função. Por isso o fragmento não foi promovido, nenhuma fonte `func_00000084.c`
foi criada e as 2 words não entram na cobertura reconstruída. O bloqueio é de
**identidade independente**, não de compilação.

### 8. Expansão de módulos: `EBOOT.BIN` e `libadler.prx`

A árvore local contém apenas dois PRX ELF em `USRDIR/gmodule`:
`libtutoriallist.prx` e `libhtml_view.prx`. Os outros candidatos Executáveis
da mídia não são ELF:

- `EBOOT.BIN` começa com `~PSP` (`7e505350...`), tem 1 110 624 bytes e não
  contém a magic `\x7fELF`; `seto.elf.parse` falha com `bad ELF magic`.
- `libadler.prx` começa com `~SCE` (`7e534345...`), tem 1 088 bytes e também
  não contém `\x7fELF`; `seto.elf.parse` falha com `bad ELF magic`.

Não foram usadas chaves, decriptação caseira ou bypass de container. A
expansão para um terceiro módulo fica **bloqueada no decoding do container
PSP**, não por falta de uma função escolhida. Nenhum módulo foi inventado ou
promovido a partir de bytes não parseáveis.

### 9. TDD, ferramenta e teste de integração real

- O defeito observado foi `match_function.py` não expor o `--size` que a CLI
  já suportava, o que fazia o thunk autêntico de 2 words ser reportado como
  erro de tamanho. O teste RED
  `test_an_explicit_function_size_is_forwarded` falhou antes da implementação
  porque `build_match_argv` não aceitava o parâmetro; o teste
  `test_real_match_rejects_an_inconsistent_explicit_function_size` cobre a
  validação de consistência. Depois da correção, ambos passam.
- O novo teste opt-in
  `tests/integration/test_libtutoriallist_025_real.py`
  (`SETO_LIBTUTORIALLIST_025_REAL=1`) cobre as dez fontes novas. Seis usam a
  CLI oficial com duas compilações frescas; quatro usam o comparador de
  símbolo completo com duas compilações frescas. Ele verifica status, words
  iguais, diferenças, issues, limitações, tamanho integral do símbolo,
  determinismo dos objetos e a limitação exata de 0x2C8. Não é um teste que
  apenas reafirma contagens antigas: todas as dez fontes são novas.
- Nenhum arquivo de experimento descartado, objeto, PRX ou dump de asset foi
  versionado. Os artefatos completos ficam em `build/seto025/` (ignorado).

### 10. Métricas consolidadas

| Métrica | `libtutoriallist` | `libhtml_view` | Total |
|---|---:|---:|---:|
| Intervalos identificados | 26 / 2 412 words | 16 / 509 words | 42 / 2 921 words |
| Funções com C reconstruído | 25 / 2 410 words | 15 / 507 words | **40 / 2 917 words** |
| Funções compiladas | 25 | 15 | **40** |
| Funções comparadas por caminho de produção | 25 | 15 | **40** |
| Funções sem diferença de instrução | 19 | 15 | **34** |
| `MATCHED` estrito (words certificadas) | 9 / 696 words | 7 / 216 words | **16 / 912 words** |
| `INCONCLUSIVE` com zero diferenças | 10 / 511 words | 8 / 291 words | **18 / 802 words** |
| `NONMATCHING` (diferenças reais ou associação) | 6 / 1 203 words | 0 | **6 / 1 203 words** |
| Words reconstruídas não certificadas | 1 714 | 291 | **2 005** |
| Objetos de dados identificados separadamente | 0 | 0 | **0** |
| Fragmentos sem C | 1 / 2 words (`0x0`) | 1 / 2 words (`0x84`) | **2 / 4 words** |

Seis das dez funções novas usam a CLI oficial; duas delas, 0x1C18 e 0x1C20,
passam `--size` explícito para os intervalos divididos. As quatro funções de
símbolo maior ou menor usam `seto.matching.compare` sobre o símbolo completo.
O caminho de compilação é o mesmo em todos os casos.

A soma fecha exatamente: **912 certificadas + 802 zero-diferença não
certificadas + 1 203 nonmatching + 4 não reconstruídas = 2 921 words
identificadas**. As 802 words zero-diferença estão excluídas da certificação
apenas por limitações de identidade HI16/LO16. Das 1 203 `NONMATCHING`, 1 192
têm diferenças reais de instrução/relocation; as 11 de `0x2C8` são
byte-idênticas e ficam fora da certificação apenas pela associação HI16/LO16
do comparador. **Nenhum objeto de dados foi identificado separadamente**: o
painel em 0x6190 e os globais 0x6238/0x6248 são hipóteses de uso e layout, não
definições de dados provadas.

A baseline anterior de 15 `MATCHED` / 910 words permanece; a única nova
certificação estrita é `0x1C18` (2 words), levando a **16 / 912**. A contagem
de funções sem diferença sobe de 29 para **34** (16 `MATCHED` + 18
`INCONCLUSIVE`), e as funções `NONMATCHING` passam de 1 para **6**, todas no
tutorial.

### 11. Hashes de fonte e objeto

As fontes abaixo são os bytes finais do worktree, incluindo os comentários de
resultado; os objetos foram gerados em duas compilações independentes, e os
dois SHA-256 coincidiram. O compilador e os flags são os mesmos em todas as
linhas.

| Intervalo | Fonte | Fonte SHA-256 | Objeto SHA-256 (tentativas 1/2) |
|---|---|---|---|
| `0x8–0x154` | `func_00000008.c` | `b2cceab6fa81efe7673b4a3f6eda75a853429e6628db73ffcf7b9114a4e53f7d` | `e6686faca953a1410b1763071f47a144a99f30acd27b234c1ff0b205979c4fbe` |
| `0x154–0x280` | `func_00000154.c` | `2d7a6b4fc83407ee5cf1a46cf2a4be7a6cee3c51c22addfa43bd19e9ad0cf202` | `b5f6266ba2457d1a1e320a0ec6d63e6c813af7c0028501fddb118db2d55ccfbc` |
| `0x280–0x2C8` | `func_00000280.c` | `132a41a4576cf3b0c147bd651ab6caf4c62347a16cb939e9d3a9677c1fa40acb` | `4530e5d5dddba52f514f552dde5ec162f18737ffc96b33144e563f9d74a619d2` |
| `0x2C8–0x2F4` | `func_000002C8.c` | `288f212496e967c977b595fcf4f8f00e5d77e6485e4fc3a4236ae2620345a9cb` | `91ec22544572f806cc699186edb15a6bd2088184559f9115c5314c49997d7061` |
| `0x2F4–0x6E8` | `func_000002F4.c` | `b6de2d486169e933b96e6565d77216e4b5604fd4fd316b1475e75c0f180a556c` | `63814b2c9574503fe5afc1d93705bb554de865e9971c60e7dd49920fff79795c` |
| `0x8F0–0xE24` | `func_000008F0.c` | `b5b015bd6ee629882d5b3433221e8a4b39a016f91fb49ea1bd78d7cda5a7b0aa` | `fdebb87c3f3f9c97a25430f9a55f4584e6a8ebae1c54fd384377e7ea0de1c184` |
| `0x1C18–0x1C20` | `func_00001C18.c` | `f70c65c3a636136498030738b946f1ddce6e6ecd7bae64e00fcb8729e6bb7e45` | `ddc8d7426b2835563404dd42d09eac4ae251af9a95278176935b8b8ac273d7c7` |
| `0x1C20–0x1C58` | `func_00001C20.c` | `ca7968a4438db0f0ae332350db473d17c36d975404654c524b3ee63ed7d42813` | `9341110d4613d51de998aa23aee2e188eb411fae3d34aca6308b311680a4dd7a` |
| `0x1F10–0x21F8` | `func_00001F10.c` | `9324fa585a924be4efe62b72eae872206fedc9fe04679d210789c6e02462f282` | `ad4d8719b5e4e9fc6ad0b2b177d96587876047963e016a9af0363a0d534a3a1c` |
| `0x21F8–0x25B0` | `func_000021F8.c` | `aef3982506454100b98db2fdf1f4d9f440b3b1da7032a2d798d259abd1c5831d` | `ef45a3c3cc0288ee6b0ce1f81ca28030e014bf4c8f93eb8b4494567e3a6cf94c` |

Header provisório do painel:
`a1205bf9afa2f50d24b18bcf40b55b6f269bbb3caec18849d66cf4cf98088873`.
Header compartilhado de stubs:
`a07e2711fa860efc843f75343957057aa55da5abe3c6e1a604f06151bfc12fb0`.
Hashes de fonte dependem dos bytes efetivamente compilados (CRLF/LF); os
objetos e relatórios completos estão em `build/seto025/final/` e
`build/seto025/integration-results.json`, ambos ignorados.

### 12. Gates finais

| Gate | Ambiente | Resultado |
|---|---|---|
| `pytest -q -rs` | Windows | **763 passed, 40 skipped** |
| `pytest -q -rs` | WSL2 | **780 passed, 23 skipped** |
| `pytest -m integration -q -rs` | Windows | **23 passed, 35 skipped, 745 deselected** |
| `pytest -m integration -q -rs` | WSL2 | **41 passed, 17 skipped, 745 deselected** |
| Opt-ins reais 018–023 + callbacks + 025 | WSL2 | **9 passed**; cada alvo novo compilado duas vezes |
| Preservação 024 (5 funções) | WSL2 | **5/5** com status, words e source/object SHA-256 idênticos |
| `test_toolchain_runtime.py -k real_mwccpsp` | WSL2 | **16 passed, 3 deselected**; 15 funções de `libhtml_view` preservadas |
| `compileall -q src scripts tests` | Windows e WSL2 | clean |
| `git diff --check` | Windows Git | clean |

Os skips restantes são requisitos de plataforma (WSL2), ausência das
ferramentas GNU MIPSel, três testes YAML sem PyYAML, ISO/Splat e Ghidra/REA
não configurados, e opt-ins inativos. Nenhum skip foi convertido em aprovação. O teste 025 é opt-in e aparece como skip nas suítes sem a variável
`SETO_LIBTUTORIALLIST_025_REAL=1`.

### 13. Bloqueios restantes e próximos alvos

1. **Alocação de registradores/spill (maior payoff):** `0x21F8` (119/241),
   `0x1F10` (70/187) e `0x8F0` (50/342) já têm estrutura semântica e
   divergem na rotação/spill. Um novo grafo de interferência ou uma forma de
   acesso que reduza a pressão pode recuperar muitas words de uma vez.
2. **Layout de branches/código morto:** `0x2F4` (93/253) precisa de uma forma
   de fonte que reproduza o `lhu` duplicado em 0x4B0 sem inserir código morto.
   `0x1764` (42/182) precisa de uma alocação nova, não de mais permutações.
3. **Associação HI16/LO16 do comparador:** `0x2C8` é byte-idêntico e continua
   `NONMATCHING` 7/11 apenas pela associação original. Um conserto principiado
   do comparador (sem afrouxar as regras) poderia promover o caso; não foi
   feito nesta rodada.
4. **Identidade de dados:** `0x8`, `0x154`, `0x280`, `0x1C20` e as funções
   `INCONCLUSIVE` de `libhtml_view` dependem de pares HI16/LO16 sem objeto
   cross-artifact. A estrutura do painel em 0x6190 e os globais 0x6238/0x6248
   continuam provisórios.
5. **Fragmentos:** `0x0` (2 words, `jr ra; return 0`) e `0x84` (2 words,
   `jr ra; nop`) não têm evidência independente de entrypoint. O primeiro não
   tem caller nem ponteiro resident; o segundo é ambíguo entre callback no-op e
   fim de faixa.
6. **Expansão de módulos:** `EBOOT.BIN` (`~PSP`) e `libadler.prx` (`~SCE`)
   exigem decoding de container que o repositório não possui. Sem isso, não há
   um terceiro módulo ELF para reconstruir.

Ordem sugerida para a próxima rodada: `0x21F8` → `0x1F10` → `0x2F4` →
`0x8F0` → `0x1764` (somente com grafo novo) → `0x2C8` (comparador) →
identidade de dados → decoding de container. Nenhuma dessas funções foi
descrita como concluída; as certificações novas são apenas as 2 words de
`0x1C18`.

---

## SETO-DECOMP-026 — Maximum Matching Offensive

### 1. Base, artefatos e escopo

- HEAD inicial e merge-base: `96b941fdd6a4a07cc8128abe14ea61133557e2e0`
  (merge da PR #24). Branch: `feat/seto-decomp-026-matching-offensive`.
- HEAD final de implementação: `15eb59fbac5a71fbc19eadf29b66430ddeea0a53`.
  Atualizações posteriores de gates/proveniência são somente documentação na
  [PR #25](https://github.com/LViniciusk/Seto/pull/25), sem merge automático.
- PRX original: `libtutoriallist.prx`, SHA-256
  `2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49`;
  `.text` em `[0, 0x25B0)`.
- Toolchain e flags inalterados: mwccpsp 3.0.1.219 via wibo, `-O4,p
  -sdatathreshold 0`, include `decomp/include`.
- Nenhum flag, binário original, regra de comparação ou identidade de dados
  foi alterado para promover funções. As mudanças de produção são o
  pareamento HI16/LO16 e formas de C equivalentes em `0x1F10`, `0x21F8`, `0x2F4` e `0x8F0`.

### 2. Pareamento HI16/LO16 com CFG local (0x2C8)

O pareamento anterior era estritamente linear: qualquer transferência
condicional entre o `lui` e o `lhu`/`addiu` fazia o par cair em
`relocation-order` ou em “controle de fluxo incerto”. Em `0x2C8`, a word 7
(`addiu v0,zero,-1`) redefine o registrador-base do LO16 em um caminho, mas os
quatro sítios HI16/LO16 estão em caminhos mutuamente exclusivos:

- o `beql` leva ao LO16 e seu delay slot instala a base HI16;
- o caminho não tomado redefine o mesmo registrador no delay slot de um `beq`
  incondicional que salta o LO16.

Foi adicionado um CFG intraprocedural mínimo em `src/seto/matching.py`
(`_cfg_*`), com análise de definições alcançantes apenas para o registrador
fonte do LO16. O CFG:

- entende branches, branch-likely, jumps, `jr`/`jalr`, delay slots e
  redefinições explícitas;
- só devolve prova positiva quando um único `lui` realocado alcança o LO16 em
  todos os caminhos modelados;
- devolve `definite-none` para uma redefinição inequívoca;
- devolve `None` (fallback linear) quando há chamada antes do LO, instrução desconhecida,
  alvo fora da região ou fluxo que não pode ser modelado.

Controles sintéticos novos: prova através de um branch condicional; prova
através de delay slots mutuamente exclusivos (a forma de `0x2C8`); rejeição
de uma redefinição que cai no LO16; e separação entre um alvo diferente em par
provado pelo CFG (vira `NONMATCHING`) e um par apenas order-only (continua
`INCONCLUSIVE`). `tests/test_matching.py`: **77 casos aprovados** na suíte final.

A revisão de strictness acrescentou controles para backedges após o LO, retorno
de `jal`/`jalr` e entrada normal em um delay slot. A propriedade dos delay slots
agora cobre a janela inteira; chamadas posteriores ao LO propagam registradores
desconhecidos após seu delay slot, sem apagar o possível caminho de retorno.
Branches que entram em delay slots caem no fallback conservador, pois essa
entrada não herda o destino pendente do branch dono. Também foi corrigida a
classificação de SPECIAL `0x18`: é `mult`, não `eret`. Nenhuma dessas provas
confere identidade a dados; os resultados reais de `0x2C8`/callbacks se mantêm.
As quatro variantes de REGIMM branch-and-link são chamadas condicionais:
novos controles reproduziram falsas provas quando eram tratadas como branches
locais. Elas agora usam o fallback conservador, sem ignorar o retorno do callee.

Resultado real de `0x2C8` (duas compilações independentes, objeto idêntico):

| Antes | Depois |
|---|---|
| `NONMATCHING` 7/11, 1 diferença, 1 relocation issue, 4 limitações | **`INCONCLUSIVE` 7/11, 0 diferenças, 0 relocation issues, 2 limitações** |

As duas limitações restantes são exatamente:

```text
word 0: HI16/LO16 data identity cannot be proven (original: unresolved; candidate: unresolved)
word 5: HI16/LO16 data identity cannot be proven (original: unresolved; candidate: unresolved)
```

As quatro words de HI16/LO16 ficam fora de `matching_words`, por isso o
resultado é 7/11 e não 11/11. **`INCONCLUSIVE` é o resultado correto**: o
símbolo provisório do painel em 0x6190 não tem identidade cross-artifact
independente. Nenhuma identidade foi fabricada para transformar o caso em
`MATCHED`.

### 3. `0x1C58`: pares provados, avisos removidos

O mesmo CFG provou o par HI da word 6 / LO da word 9, antes apenas order-only. O
resultado real permanece `INCONCLUSIVE` 28/44, com 8 pares de dados, 3
chamadas diretas resolvidas e **0 avisos de pareamento** (antes: 2). As 8
limitações de identidade de dados continuam, e nenhuma foi promovida. O caso
ativo em `tests/integration/test_libtutoriallist_callbacks_real.py` passou de
`(44, 28, 8, 3, 2)` para `(44, 28, 8, 3, 0)`.

### 4. `0x1F10`: tamanho exato recuperado, alocação da cauda ainda aberta

A expressão do teste de saída do loop interno foi escrita como
`j > trailing[group]` (equivalente a `trailing[group] < j`). Isso reproduz o
único merge de `sum + extent` depois do loop, em vez de duplicar a soma no
delay slot do `break`, e elimina a word extra:

| Antes | Depois |
|---|---|
| `NONMATCHING` 70/187, 81 diferenças, 3 relocation issues, 21 limitações, 748 bytes | **`NONMATCHING` 73/186, 76 diferenças, 2 relocation issues, 21 limitações, 744 bytes** |

O candidato agora tem exatamente as 186 words / 744 bytes originais. A
primeira diferença continua na word 96: o original usa `andi t2,...` e o
candidato `andi t0,...`; o compilador colore `group` em `t0` em vez de `t2`,
o que gira os registradores da cauda e mantém 76 diferenças. Cerca de 30
formas de fonte foram testadas com o compilador real (ordem da soma, acesso
direto ao bitfield, acessor explícito, `else-first`, ponteiros locais,
`while`, tipos de `j`/`group`, ordem de declaração, escopos aninhados,
`register`, blocos com inicializadores). Nenhuma fechou a word 96; a melhor
alternativa continuou em 73/186. Não foi inserido código morto, padding,
`volatile` ou assembly para forçar a alocação.

As 21 limitações são de identidade HI16/LO16 ou de pareamento order-only; as
duas relocation issues restantes (`word 106` e `word 109`) são consequência
direta da rotação de registradores, não de uma associação de dados inventada.

### 5. `0x21F8`: o loop da janela passa a coincidir

O quinto ramo (`input[3] & 0x40`) foi reescrito para cachear
`leading[group]` antes do loop e usar o accessor compartilhado dentro dele:

```c
lead = func_00006190_panel.leading[group];
for (j = 0; j < 8; j++) {
    entry = libtutoriallist_panel_key(group, lead + j);
    if (func_00006190_panel.trailing[group] < j)
        break;
    sum += func_00006190_panel.extents[entry];
}
```

Isso é semanticamente idêntico: o loop não contém chamadas nem escritas no
painel, e `leading[group]` não muda durante a execução. O original também
carrega `leading` uma vez antes do loop (`v1` em 0x248c). A sequência de
instruções do loop agora coincide com a original, exceto pelo `sum + extent`
duplicado no delay slot do `break`:

| Antes | Depois |
|---|---|
| `NONMATCHING` 119/241, 78 diferenças, 11 relocation issues, 21 limitações, 964 bytes | **`NONMATCHING` 127/240, 66 diferenças, 9 relocation issues, 23 limitações, 960 bytes** |

O candidato ainda tem **2 words extras** (240 versus 238): (1) o accessor
`libtutoriallist_panel_key` recebe `unsigned char group`, o que gera um `andi
0xff` redundante antes da indexação; (2) o compilador agenda `sum + extent` no
delay slot do `break` e o repete depois do loop, em vez de carregar o extent no
delay slot e compartilhar um único `sum + extent` na saída, como no original.
As primeiras diferenças (words 32, 70, 103, 119, 138, 143, 149, 151) são
deslocamentos de branch induzidos por essas 2 words; a primeira divergência
**substancial** é a word 157 (`lui`/`andi` no agendamento do quinto ramo).
Formas alternativas (índice sem accessor, accessor com `int group`, `while`,
`goto`, soma pós-loop em `sum`/`extent`, ordem da soma e do break) foram
compiladas; nenhuma removeu a duplicação sem perder a alocação do loop.

### 6. Alvos grandes restantes

| Função | Original / candidato | Resultado | Primeira diferença |
|---|---:|---|---:|
| `0x2F4` | 253 / 253 | `NONMATCHING` 134/253, 99 diferenças, 20 relocation issues, 4 limitações | word 81 |
| `0x8F0` | 333 / 342 | `NONMATCHING` 52/342, 284 diferenças, 68 relocation issues, 1 limitação | word 15 |
| `0x1764` | 182 / 182 | `NONMATCHING` 42/182, 140 diferenças, 32 relocation issues | word 10 |

Em `0x2F4`, somente a consulta da linha visível passou ao accessor compartilhado:
**93/253 → 134/253**, **137 → 99 diferenças**, **35 → 20 relocation issues**,
996 → 1 012 bytes. Duas compilações independentes produziram o mesmo objeto.
As conversões/reloads do accessor corrigem o tamanho e os deslocamentos iniciais,
mas isso não prova igualdade do CFG. As cópias originais em `0x4B0`, `0x560` e
`0x634` são inalcançáveis pelo CFG intraprocedural: ambos os predecessores saltam
suas instruções. Elas continuam ausentes; nenhum código morto foi inserido.
Accessors alternativos e os dois pares de acumuladores/cursores não melhoraram
o candidato. A primeira divergência agora é a word 81, não as words 32/34.

Em `0x8F0`, antecipar `top = y + 15` para antes da configuração coloca a soma
no delay slot original: **50/342 → 52/342**, 286 → 284 diferenças e 70 → 68
relocation issues, com objeto determinístico em duas compilações. O spill de
`height` na word 15 permanece. A análise distinguiu os temporários que o
candidato mantém vivos (`x+6`, `atlas+11`, `width-20`, `height-27`) das somas
recomputadas no original. Reuso entre fases, escopos, indução por índice,
inicialização do contador e expressões encadeadas não recuperaram `height=s2`.
Reusar `height` como contador removeu seu spill, mas mudou-o para `s3` e
introduziu outros spills; essa variante não foi adotada.

Nenhuma dessas funções foi promovida nem teve a semântica alterada nesta
rodada. `0x1764` permanece congelada após mais de 120 variantes refutadas em
025; só deve ser revisitada com uma hipótese estrutural nova.

### 7. Métricas globais

A reclassificação de `0x2C8` move 11 words de `NONMATCHING` para
`INCONCLUSIVE` sem alterar o total reconstruído:

| Métrica | 025 | 026 |
|---|---:|---:|
| Funções com C reconstruído | 40 / 2 917 words | **40 / 2 917 words** |
| `MATCHED` estrito | 16 / 912 words | **16 / 912 words** |
| `INCONCLUSIVE` com zero diferenças | 18 / 802 words | **19 / 813 words** |
| `NONMATCHING` | 6 / 1 203 words | **5 / 1 192 words** |
| Funções sem diferença de instrução | 34 | **35** |
| Words reconstruídas não certificadas | 2 005 | **2 005** |
| Objetos de dados identificados separadamente | 0 | **0** |
| Fragmentos sem C | 2 / 4 words | **2 / 4 words** |

A soma continua exata: **912 certificadas + 813 zero-diferença não
certificadas + 1 192 nonmatching + 4 não reconstruídas = 2 921 words
identificadas**. Não houve nova certificação estrita; a contagem permanece
**16 MATCHED / 912 words**. O ganho de `0x2C8` é de classificação correta e de
comparador, não de certificação.

A melhoria de `0x21F8` é interna a uma função que permanece `NONMATCHING`: ela
não altera as contagens globais de status nem o total de words (a função
continua contribuindo com 238 words originais), mas reduz as diferenças
daquela função de 78 para 66 e aumenta as words coincidentes de 119 para 127.
O quadro de status/words acima permanece o mesmo; o progresso é medido dentro
da função, não por uma promoção artificial.

### 8. Hashes de fonte e objeto

| Intervalo | Fonte | Fonte SHA-256 | Objeto SHA-256 |
|---|---|---|---|
| `0x2C8–0x2F4` | `func_000002C8.c` | `f344cdfcb576fa4df6b6f701ef2740ed09d04063139bdb834b7166eaddc8237e` | `91ec22544572f806cc699186edb15a6bd2088184559f9115c5314c49997d7061` |
| `0x1C58–0x1D08` | `func_00001C58.c` | `e99748be52320e19591f93ae0d50dea33159967b870b9e3f44556c1b19ea5e13` | `807134dfd1ee244300d69df3be325b1aa64127c9a432f8418d14fa04689124d7` |
| `0x1F10–0x21F8` | `func_00001F10.c` | `0ff65a4f12d2e84e99a163b6abf10dc760abe022ad9662b30761f0948c5cf890` | `3f4f3789ed471bfd69c491106bc982712e11e3b30e39820aa61c70ad33b4f613` |
| `0x21F8–0x25B0` | `func_000021F8.c` | `b59a92d80c06de4e656449e7fec59ca30e555c93958a5bb7352e77eb42479300` | `9eb6aee66d6ed6c1dcabb0a7cf6576bfc78a76993ddc79f0eae3f37f003e6aca` |
| `0x2F4–0x6E8` | `func_000002F4.c` | `a80470ddc1f0653e6a3c3555be5d01670b6ebbd3d710e5e221eecd1319c9da42` | `eeb9bcccaaa2345bdad6b0c20680218d3389f613b827b083408c77649af4d25c` |
| `0x8F0–0xE24` | `func_000008F0.c` | `53d38ec10f50b75c1afa396689b942dd2ed64eac06ff80649e191a8adf53dd0c` | `591face818cb8f1958f17c43821228029887908f3d317ce41df6e176c40f91dc` |

O objeto de `0x2C8` é o mesmo medido em 025; o hash de fonte registrado
na tabela de 025 para essa função (`288f2124...`) não corresponde ao arquivo
atual (`f344cdfc...`), mas o objeto reproduzido permanece `91ec2254...`.
O registro anterior de hash de fonte está desatualizado, não o objeto. O
objeto de `0x1C58` também é o mesmo de 025. `0x1F10` mudou de 748 para 744
bytes; as duas compilações independentes do teste 025 produziram o mesmo
`3f4f3789...`. `0x21F8` mudou de 964 para 960 bytes; as duas compilações
independentes do teste 025 produziram o mesmo `9eb6aee6...`.

### 9. Validação executada

| Gate | Ambiente | Resultado |
|---|---|---|
| `pytest -q -rs` (suíte completa) | Windows, `PYTHONPATH=src` | **773 passed, 42 skipped** |
| `pytest -q -rs` com opt-ins de tutorial ativos | WSL2 | **800 passed, 15 skipped** (735,91 s) |
| `pytest -m integration -q -rs` com opt-ins de tutorial ativos | WSL2 | **49 passed, 9 skipped, 753 deselected** (448,97 s) |
| Opt-ins reais 018–025 + callbacks | WSL2 | **9 casos aprovados**, incluídos na suíte acima |
| Runtime real mwccpsp / `libhtml_view` | WSL2 | **16 casos aprovados**, incluídos na suíte acima |
| `compileall -q src scripts tests` | Windows e WSL2 | clean |
| `git diff --check` | Windows | clean |

Os skips continuam sendo requisitos de plataforma/ferramentas ausentes ou
opt-ins inativos, incluindo três casos YAML sem PyYAML no WSL2; nenhum skip
foi convertido em aprovação. Os 9 opt-ins reais
incluem `0x2C8` (`INCONCLUSIVE` 7/11, 0 diferenças), `0x1F10` (73/186, 744
bytes), `0x21F8` (127/240, 960 bytes), `0x2F4` (134/253, 1 012 bytes) e `0x8F0`
(52/342, 1 368 bytes), todos compilados duas vezes com objetos determinísticos.
Os oito checks hospedados do commit de implementação `15eb59f` também passaram
(Ubuntu/Windows, Python 3.11/3.12, eventos push e pull request).

### 10. Bloqueios restantes e ordem de ataque

1. **`0x1F10` (word 96):** a alocação de `group` em `t0` versus `t2` continua
   sendo o bloqueio principal. A cauda já tem o tamanho exato e o merge de
   saída correto; falta uma forma de fonte que mude a coloração sem código
   artificial.
2. **`0x21F8` (127/240):** o loop do quinto ramo já coincide com o original;
   restam duas words extras — o `andi 0xff` do accessor (`unsigned char
   group`) e o `sum + extent` duplicado no delay slot do `break`. A primeira
   divergência substancial é a word 157; os deslocamentos de branch anteriores
   são consequência das 2 words.
3. **`0x2F4` (134/253):** tamanho exato, mas o CFG ainda difere. Primeira
   divergência na word 81; faltam as cópias do scheduler em 0x4B0/0x560/0x634,
   enquanto o accessor emite conversões/reloads diferentes. Não inserir padding.
4. **`0x8F0` (52/342):** spill de `height` e nove words extras; o grafo de
   interferência global precisa de uma representação de fonte que preserve o
   `s2` original.
5. **`0x1764` (42/182):** congelada; só revisitar com uma hipótese nova de
   alocação global.
6. **Identidade de dados:** 0x6190, 0x6238, 0x6248, 0x6250, 0x6204,
   `.data+0x34`, `.data+0x80` e os pares de `libhtml_view` continuam sem
   identidade cross-artifact. Nenhum objeto de dados foi promovido.
7. **Fragmentos e containers:** `0x0`/`0x84` continuam sem evidência
   independente de entrypoint; `EBOOT.BIN` (`~PSP`) e `libadler.prx` (`~SCE`)
   continuam bloqueados por formato de container.

Nenhuma dessas funções foi descrita como concluída. O resultado principal da
026 é a correção principiada do pareamento HI16/LO16, a reclassificação
honesta de `0x2C8`, a remoção dos avisos de `0x1C58`, a recuperação do loop de
`0x21F8`, o tamanho exato de `0x1F10`, as melhorias parciais de `0x2F4`/`0x8F0`
e os controles adicionais de strictness do CFG. A PR #25 permanece aberta,
sem merge; os hashes do HEAD e dos commits estão publicados na própria PR.

## SETO-DECOMP-026-R2 — Maximum Recovery Campaign

Início: `f68c86e23d76b59c576930c4db32da4aa54fa623`, mesma branch e PR #25.
O PRX original foi revalidado com SHA-256
`2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49`.

### Correção obrigatória de ambiguidade do CFG

Um CFG já analisado não volta ao scan linear quando encontra múltiplas
definições HI16, HI16 misturado com definição comum, valor de entrada ou
clobber de chamada. Esses casos retornam `uncertain`; `definite-none` exige
que **todas** as definições alcançantes sejam comuns, e `match` exige um único
HI16. Construções não suportadas ainda podem recorrer ao scan anterior;
evidência independente de símbolo ELF continua prevalecendo.

RED: quatro novos casos reproduziram a promoção indevida ou a falsa exclusão
de um HI16. GREEN: **83 testes de matching aprovados**, incluindo controles
de múltiplas definições comuns e símbolo ELF. Destinos de dados diferentes
não viram uma divergência definitiva por meio de um par ambíguo.

Os testes reais 025 e callbacks passaram (**2 passed**, 108,09 s), preservando
`0x2C8` em `INCONCLUSIVE` 7/11, zero diferenças/issues, e `0x1C58` em
`INCONCLUSIVE` 28/44, zero avisos de pareamento. Os cinco alvos `NONMATCHING`
mantiveram os resultados de partida. Nenhuma certificação foi acrescentada.

### `0x21F8`: duas words extras eliminadas

O `group` local passou a `unsigned char`, compatível com o nibble carregado.
O loop agora carrega o extent em `next` antes de `j > trailing[group]`, como
o `lhu` original no delay slot do break. Juntas, as mudanças removem o mask
do accessor e a soma de saída duplicada, sem alterar imports ou side effects.

| Antes R2 | Depois | Diferença restante |
|---|---|---|
| 127/240, 960 bytes, 66 diferenças, 9 relocation issues, 23 limitações | **187/238, 952 bytes, 3 diferenças, 0 relocation issues, 26 limitações** | words 165/166: ordem dos loads; word 168: ordem dos operandos da soma |

A etapa intermediária 159/238 passou no teste real 025 (73,68 s). Inicializar
`position` com `trailing`, cachear `leading` e somá-lo a `position` recuperou
depois o mapa original de registradores e todos os pares HI16/LO16: **187/238**.
Duas compilações integrais independentes (ensaio e fonte final) produziram o
mesmo objeto. Só diferem `lhu` em 0x248C/0x2490 e a ordem dos operandos do
`addu` em 0x2498. Continua `NONMATCHING`; não houve certificação artificial.
Fonte SHA-256: `7e2fb7ef84a076ce3e46c3fb710ab1021347ca0e88a3e25b913833fdfa876343`.
Objeto SHA-256: `14d25c2ec2caf36ccd6de7cfa12d714f24434a377027e71625d99a4576bde0dc`.

### `0x1F10`: contrato estreito/amplo do `group` recuperado

O original guarda o nibble `group` como valor amplo (`andi t2,a1,0xf`) e o
converte para byte somente na leitura de `count[]` (`andi v1,t2,0xff` em
0x20C8); o acesso a `leading`/`trailing`/`entries` usa o valor amplo. A fonte
passou a usar `int group` com dois helpers locais, um para `count[]` (parâmetro
`unsigned char`) e outro para a linha (parâmetro `int`), preservando exatamente
esse contrato. O valor de `leading` é carregado uma vez por iteração externa e
usado no loop interno, como o registrador original em a3.

| Antes R2 | Depois | Diferença restante |
|---|---|---|
| 73/186, 744 bytes, 76 diferenças, 2 relocation issues, 21 limitações | **89/186, 744 bytes, 60 diferenças, 1 relocation issue, 22 limitações** | word 96: permutação de registradores (grupo t4/t2, posição t2/t4 e rotação dependente) |

A cauda é isomórfica ao original instrução a instrução; não há diferença de
tamanho, CFG, imports ou operandos de memória. Foram testadas mais de 40 variantes
equivalentes de ordem de expressão, ordem de declaração, locais de valor,
`count`/`index` explícitos, ponteiros persistentes e invertidos, sem remover a
permutação. Duas compilações integrais independentes produziram o mesmo objeto.
Continua `NONMATCHING`; nenhuma identidade de dados foi promovida.
Fonte SHA-256: `ea6b98ab326eb0464775cd62081664d9a6dc4976aae75ae1784d0644742c612b`.
Objeto SHA-256: `0bbd97b264dad8b7bf9ae6cfa619791a765a2148c9f59fccb786616229fbb086`.

### Resultados consolidados da R2

HEAD inicial `f68c86e23d76b59c576930c4db32da4aa54fa623`; HEAD de código
`b977cc0054ef6c208ea435817fde467fb2451744`, mais o commit de documentação.
Nenhuma certificação estrita mudou: continuam **16 `MATCHED` / 912 words**,
**19 `INCONCLUSIVE` / 813**, **5 `NONMATCHING` / 1.192** e dois fragmentos / 4
words; **35 funções com zero diferenças**. As melhorias são estritamente dentro
de `NONMATCHING`.

| Função | Antes R2 | Depois R2 | Primeira diferença restante |
|---|---|---|---|
| `0x2C8` | `INCONCLUSIVE` 7/11 | **`INCONCLUSIVE` 7/11, 0 diferenças** | duas identidades de dados |
| `0x1C58` | `INCONCLUSIVE` 28/44 | **`INCONCLUSIVE` 28/44, 0 avisos** | oito pares de dados |
| `0x1F10` | 73/186, 76 dif., 2 reloc., 744 B | **89/186, 60 dif., 1 reloc., 744 B** | word 96: permutação de registradores |
| `0x21F8` | 127/240, 66 dif., 9 reloc., 960 B | **187/238, 3 dif., 0 reloc., 952 B** | words 165/166 e 168 |
| `0x2F4` | 134/253, 99 dif., 20 reloc., 1.012 B | **134/253, 99 dif., 20 reloc., 1.012 B** | word 81; cópias inalcançáveis do scheduler |
| `0x8F0` | 52/342, 284 dif., 68 reloc. | **52/342, 284 dif., 68 reloc.** | word 15: spill de `height` |

Objetos reproduzidos (SHA-256): `0x2C8`
`91ec22544572f806cc699186edb15a6bd2088184559f9115c5314c49997d7061`;
`0x1C58` `807134dfd1ee244300d69df3be325b1aa64127c9a432f8418d14fa04689124d7`;
`0x1F10` `0bbd97b264dad8b7bf9ae6cfa619791a765a2148c9f59fccb786616229fbb086`;
`0x21F8` `14d25c2ec2caf36ccd6de7cfa12d714f24434a377027e71625d99a4576bde0dc`;
`0x2F4` `eeb9bcccaaa2345bdad6b0c20680218d3389f613b827b083408c77649af4d25c`;
`0x8F0` `591face818cb8f1958f17c43821228029887908f3d317ce41df6e176c40f91dc`.
Cada objeto aceito foi produzido por duas compilações oficiais independentes.

Validação executada: Windows **779 passed, 42 skipped**; WSL com opt-ins reais
**806 passed, 15 skipped**; integração WSL **49 passed, 9 skipped, 763
deselected**; matching **83 passed**; `compileall` limpo em Windows e WSL2;
`git diff --check` limpo. Nenhum skip foi convertido em aprovação e nenhuma
regra do matcher foi enfraquecida. Os CHECKs hospedados da rodada anterior
permanecem verdes; os novos commits foram enviados para a mesma PR #25, que
segue aberta e não deve ser mesclada automaticamente.

Bloqueios restantes: identidades de dados de `0x2C8`/`0x1C58` e dos pares de
`libhtml_view`; permutação de registradores em `0x1F10`; três instruções de
ordem em `0x21F8`; cópias inalcançáveis de `0x2F4` (não inserir dead code);
pressão de registradores de `0x8F0`; `0x1764` congelada; fragmentos sem
entrypoint; containers `~PSP`/`~SCE`.

---

## SETO-DECOMP-027 — Final Codegen Recovery

Base: `05b71ef8ca8cda4027af888cf02a876496cfc312` (main após a 026), branch
`feat/seto-decomp-027-codegen`. PRX original revalidado com SHA-256
`2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49`.

| Function | Before | After | Codegen discovery | Remaining blocker |
|---|---|---|---|---|
| `0x21F8` | `NONMATCHING` 187/238, 3 dif., 0 reloc., 26 lim., 952 B | **`INCONCLUSIVE` 190/238, 0 dif., 0 reloc., 26 lim., 952 B** | A expressão única `position = leading[group] + trailing[group];` seguida de `lead = leading[group];` restaura a carga de `leading` antes de `trailing` e o `addu` `leading+trailing`; a forma dividida `position = trailing[...]; lead = leading[...]; position += lead;` carrega `trailing` primeiro e soma `trailing+leading`. | 26 limitações de identidade HI16/LO16; permanece `INCONCLUSIVE`, sem certificação `MATCHED`. |
| `0x1F10` | `NONMATCHING` 89/186, 60 dif., 1 reloc., 22 lim., 744 B | 89/186 inalterado (nenhuma variante aceita) | Refutadas hoje: expressão `trailing[group] + leading[group]` com `lead` atribuído e `lead` antes de `position` com soma explícita (`lead + position`) produzem 80/187 e 748 B (rotação extra do loop); a cópia coalescível do byte de flags (`selected_group_copy`) coloca `group` em t2 nas words 96–98, mas colapsa as bases em a0/v1 nas words 99–100 (73/186). Variantes R2 que referenciavam `lead` sem atribuí-lo eram C inválido e não contam. | Permutação global de alocação a partir da word 96: `group` t4 vs t2, `position` t2 vs t4 e rotação dependente; a cauda é isomórfica, sem diferença de tamanho, CFG ou memória. |
| `0x2F4` | `NONMATCHING` 134/253, 99 dif., 20 reloc., 4 lim., 1.012 B | inalterado | A word 81 é o registrador da base do painel (candidato `lui v1`, original `lui a0`), seguida da reordenação do scheduler em torno do call `0x8F0`; depois vêm as cópias inalcançáveis do scheduler em `0x4B0`/`0x560`/`0x634`. | Não inserir dead code para reproduzir cópias inalcançáveis; base do painel e ordem de zeroing/count do primeiro bloco. |
| `0x8F0` | `NONMATCHING` 52/342, 284 dif., 68 reloc., 1 lim., 1.368 B vs 1.332 B | inalterado | O candidato retém `x+6`, `atlas+11`, `width-20` e `height-27` entre chamadas (um callee-saved a mais), forçando o spill de `height` em `0x4C(sp)`; o original recalcula essas expressões nos pontos de uso. | Spill de `height` na word 15 e as 9 words extras; sem nova explicação de dependência para reduzir a pressão. |
| `0x1764` | `NONMATCHING` 42/182, 140 dif., 32 reloc., 728 B | inalterado | Confirmada hoje a permutação de prólogo já a partir da word 10. | Congelada; mais de 120 variantes já refutadas nas rodadas anteriores. |

### `0x21F8` — zero diferenças de instrução

O conserto decisivo veio da descoberta da 027: o original trata a soma como
**uma única expressão** com `leading` à esquerda, não como duas etapas com
`+=`. A forma dividida anterior (`position = trailing[...]; lead =
leading[...]; position += lead;`) era estruturalmente errada: ela fixa a carga
de `trailing` primeiro e força `addu` com `trailing+leading`. Com a expressão
única mais o cache `lead = leading[group];`, a word 103 vira
`addu t4, a3, v1` (`leading+trailing`) e as words 165/166 passam a carregar
`leading` antes de `trailing`, exatamente como o original.

A função permanece `INCONCLUSIVE` (não `MATCHED`) porque 26 pares HI16/LO16
continuam sem identidade de dados comprovável; nenhuma regra do matcher foi
enfraquecida e nenhuma identidade foi inventada.

Evidência de duas compilações oficiais independentes (`wibo` +
`mwccpsp_3.0.1_219`, `-O4,p -sdatathreshold 0`): objeto SHA-256
`599b39cc6218e1cca1f1c9f44f5c555a8ba728ae20c0ee53e6eedc337e7b8ca7` idêntico nas
duas. Fonte (`decomp/src/libtutoriallist/func_000021F8.c`) SHA-256
`de5cd15f0742ea30683b0fd84cfb98e9ace27c34e08cc4ac19906299080966b9`; teste
025 (`tests/integration/test_libtutoriallist_025_real.py`) SHA-256
`cf62fbc3268b38da45a27809945e6a613458903f19955727c7db37e9127f8991`; commit
`7ce38901f16583774b39f0e6f92badf9ffa65630`.

### `0x1F10` — variantes novas refutadas

Além das mais de 40 variantes da R2, a 027 testou as formas que faltavam com
`lead` realmente atribuído: `position = trailing[group] + leading[group]` e
`lead = leading[group]; position = trailing[group]; position = lead +
position;`. Ambas produzem 80/187, 748 B e giram o loop (o `bne` vira `bnel`
com a primeira instrução do corpo no delay slot), ficando piores que o split
atual. A cópia coalescível do flags em `selected_group_copy` mostra que o
alocador *pode* escolher t2 para `group` (words 96–98 idênticas), mas então
reutiliza as bases a0/v1 em vez de t0/t1 nas words 99–100. Ou seja, a escolha
t2/t4 é consequência da prioridade global do alocador, não de ordem textual de
expressão ou declaração. Nenhuma fonte foi promovida.

### `0x2F4` e `0x8F0` — bloqueios confirmados

Em `0x2F4` a primeira divergência de hoje continua na word 81 (base do painel
em `v1` em vez de `a0`) e o restante da diferença é dominado pela rotação de
endereços das cópias inalcançáveis do scheduler; em `0x8F0` a word 15 mostra o
spill de `height` porque o candidato mantém um valor derivado a mais vivo entre
chamadas. Ambos permanecem sem fonte aceita; nenhum dead code ou padding foi
introduzido.

### Validação, hashes e cobertura

- Windows: `python -m pytest -q -rs` → **779 passed, 42 skipped**;
  `compileall` e `git diff --check` limpos.
- WSL2: suíte de integração com todos os opt-ins reais
  (019–023, 025, callbacks, real) → **14 passed, 24 skipped**, incluindo
  `test_libtutoriallist_025_real.py` que recompila duas vezes e agora afirma
  `INCONCLUSIVE 190/238`, 0 diferenças, 0 relocações, 26 limitações e 952 B
  para `0x21F8`. A suíte foi executada a partir de uma cópia WSL-nativa do
  mesmo commit porque o guard anti-symlink rejeita a junção `private/` do
  worktree; fontes e PRX idênticos ao commit.
- Cobertura estrita preservada: **16 `MATCHED` / 912 words**; nenhuma
  certificação nova, nenhuma promovida a `MATCHED` sem evidência independente.
  `0x21F8` deixa de ser um `NONMATCHING` com 3 diferenças e passa a
  zero diferenças (`INCONCLUSIVE` por identidade), elevando de 35 para **36**
  as funções com zero diferenças; os cinco `NONMATCHING` da R2 caem para
  quatro, todos listados acima.
- Bloqueios restantes, por retorno provável: (1) prioridade global do alocador
  em `0x1F10` (t2/t4); (2) pressão de callee-saved em `0x8F0`
  (`x+6`/`atlas+11`/`width-20`/`height-27`); (3) cópias inalcançáveis do
  scheduler e base do painel em `0x2F4`; (4) `0x1764` congelada; (5) pares de
  identidade `0x2C8`/`0x1C58`, fragmentos sem entrypoint e containers
  `~PSP`/`~SCE`.

---

## SETO-DECOMP-028 — Recuperação de codegen (0x1F10)

Base: `a1a971cce8137762ab062b196d92b9aad15d53b1` (main após a 027), branch
`feat/seto-decomp-028-codegen`. PRX original revalidado com SHA-256
`2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49`.

| Function | Before | After | Codegen discovery | Remaining blocker |
|---|---|---|---|---|
| `0x1F10` | `NONMATCHING` 89/186, 60 dif., 1 reloc., 22 lim., 744 B | **`NONMATCHING` 97/186, 52 dif., 1 reloc., 22 lim., 744 B** | Inverter a ordem das dez declarações locais sem inicializador coloca `group` em `t2` e `position` em `t4`, como no original; a ordem direta os deixava trocados (`group` `t4`, `position` `t2`). As words 0–96 ficam idênticas, com o mesmo tamanho e a mesma única relocação. | Restam 52 words: o candidato faz CSE de `2*group` entre o preheader e o corpo do loop e o mantém em `t1`; o original recalcula `2*group` por iteração (`a1` no preheader, `v1` na cauda), o que fixa `&trailing` em `t1`, a base do painel em `a2` e `lead` em `a3`. |
| `0x2F4` | `NONMATCHING` 134/253, 99 dif., 20 reloc., 4 lim., 1.012 B | inalterado | A word 81 continua sendo a base do painel (`lui v1` vs `lui a0`) e as seguintes são a rotação do scheduler; as cópias inalcançáveis de `0x4B0`/`0x560`/`0x634` não foram inseridas. | Mesmo bloqueio: artefatos do scheduler e ordem de zeroing/count do primeiro bloco; trocas de declaração/expressão não mudaram o CFG. |
| `0x8F0` | `NONMATCHING` 52/342, 284 dif., 68 reloc., 1 lim., 1.368 B vs 1.332 B | inalterado | A word 15 continua sendo o spill de `height` em `0x4C(sp)`. O candidato mantém `atlas+11` em `s7` e `x+6` em `s6` entre chamadas (CSE), enquanto o original recalcula cada argumento no ponto de uso; variáveis por uso (`tile`, `tile_top`/`tile_bottom`, `inner`), antecipação de `bottom` e 40 permutações de declaração deram o mesmo objeto ou pior. | Pressão de callee-saved; sem mecanismo novo para impedir o CSE sem introduzir código ou identidade fabricada. |
| `0x1764` | `NONMATCHING` 42/182, 140 dif., 32 reloc., 728 B | inalterado | Congelada; nenhuma evidência nova de alocação. | Prólogo permutado; mais de 120 variantes já refutadas. |

### `0x1F10` — ordem de declaração como alavanca de alocação

A hipótese aceita é estritamente de codegen: as dez declarações locais sem
inicializador foram invertidas (`extent, key, j, sum, next, position, lead,
group, i, metric`). Isso não altera a semântica nem o tamanho; muda apenas a
prioridade global de alocação. Com a ordem direta o candidato mantinha
`group` em `t4` e `position` em `t2`; com a ordem invertida eles passam a
`t2`/`t4`, e as words 0–96 ficam idênticas (antes, 0–95). O resultado é
**97/186 words**, **52 diferenças** (antes 60), 1 relocação e 22 limitações,
com 744 B.

O que resta é uma única decisão de CSE do compilador: o candidato mantém
`2*group` vivo do preheader até a base de `trailing` dentro do loop (`t1`),
enquanto o original recalcula `2*group` no corpo (a base `panel + 2*group`
fica em `a1` no preheader e é recalculada em `v1` na cauda). Consequência:
`&trailing` vai para `a3` (original `t1`), a base do painel para `a1`
(original `a2`) e `lead` para `t3` (original `a3`). Foram refutadas 30
permutações aleatórias de declaração, as 90 movimentações simples de uma
declaração a partir da ordem aceita, a troca explícita de operandos
(`lead + position`, objeto idêntico) e a ordem `lead` antes de `position`
(86/187, 748 B); a forma de expressão única com `lead` atribuído já havia sido
refutada na 027 (80/187). Nenhuma mudou essa alocação ou reduziu as 52
diferenças.

Evidência de duas compilações oficiais independentes (`wibo` +
`mwccpsp_3.0.1_219`, `-O4,p -sdatathreshold 0`): objeto SHA-256
`e8b84d266e5b288d71d67188e2e98be839e3fe2bfba18705547c176053a1feb8` idêntico nas
duas. Fonte SHA-256
`b0e6985a3dc998efee467bdfc801041bfedb0d939ac384b7b0a2038361425459`;
teste 025 SHA-256
`65378c72bd279119ec8665639960e41318e2e48f5d715745599fe22938aad95a`.

### `0x2F4`, `0x8F0` e `0x1764` — sem fonte promovida

Em `0x2F4` a ordem de declaração não altera o artefato de duas words do
scheduler; em `0x8F0` a busca de 40 permutações de declaração não moveu a
primeira diferença além da word 15 (no máximo +1 word, não adotado), e as
variantes de rematerialização produziram o mesmo objeto `591face8…`; em
`0x1764` não surgiu nenhuma evidência nova. Nenhum padding, NOP, branch morto,
`volatile` injustificado ou asm inline foi introduzido.

### Validação, hashes e cobertura

- WSL2 (cópia nativa, `PYTHONPATH=src`): `python -m pytest -q` →
  **798 passed, 23 skipped**.
- `SETO_LIBTUTORIALLIST_025_REAL=1` sobre
  `tests/integration/test_libtutoriallist_025_real.py` → **1 passed** (duas
  compilações independentes por caso); a suíte completa sem opt-in continua
  verde. Os opt-ins 019–023/real ficam `BLOCKED` nesta árvore limpa porque
  exigem artefatos `build/seto018`/`seto023/baseline/018` de rodadas
  anteriores, ausentes no worktree; não são falhas de comparação.
- Hashes de produção confirmados no gate 025: `0x1F10`
  `e8b84d266e5b288d71d67188e2e98be839e3fe2bfba18705547c176053a1feb8`;
  `0x2F4`
  `eeb9bcccaaa2345bdad6b0c20680218d3389f613b827b083408c77649af4d25c`;
  `0x8F0`
  `591face818cb8f1958f17c43821228029887908f3d317ce41df6e176c40f91dc`;
  `0x21F8`
  `599b39cc6218e1cca1f1c9f44f5c555a8ba728ae20c0ee53e6eedc337e7b8ca7`
  (952 B, 190/238, 0 diferenças) — inalterado.
- Cobertura estrita preservada: **16 `MATCHED` / 912 words** e **36 funções
  com zero diferenças**; `0x21F8` continua `INCONCLUSIVE` pelas 26 identidades
  HI16/LO16, sem promoção a `MATCHED`.

---

## SETO-DECOMP-029 — Recuperação de CSE e reprodutibilidade (0x1F10/0x8F0)

Base: `d9386d6c2a4c33aca68a32cefd4654d9ffc4947a` (main após a 028), branch
`feat/seto-decomp-029-compiler-recovery`. PRX original revalidado com SHA-256
`2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49`.

| Function | Before | After | Codegen discovery | Remaining blocker |
|---|---|---|---|---|
| `0x1F10` | `NONMATCHING` 97/186, 52 dif., 1 reloc., 22 lim., 744 B | **`NONMATCHING` 137/186, 11 dif., 0 reloc., 23 lim., 744 B** | O cast estreito `(unsigned char)group` no uso autêntico da word 91 separa o índice da cauda larga; a ordem de declaração `extent, key, sum, j, next, position, group, lead, i, metric` fixa `group=t2`/`position=t4`. As words 0–99 ficam idênticas. | Resta a troca dependente `&trailing` (`t1` no original, `a3` no candidato) ↔ `lead` (`a3`/`t1`), com a ordem dos operandos de `addu` e os usos de `j`/`sum`. |
| `0x8F0` | `NONMATCHING` 52/342, 284 dif., 68 reloc., 1 lim., 1.368 B vs 1.332 B | **`INCONCLUSIVE` 327/333, 0 dif., 0 reloc., 3 lim., 1.332 B** | O original rematerializa cada offset derivado no ponto de uso; o candidato faz CSE dos valores repetidos. Identidades de 32 bits distintas na primeira/segunda/terceira ocorrência (`int`/`unsigned int`/`long`) reproduzem essas fronteiras sem alterar o encoding `addiu`. A ordem `top` antes de `atlas`, a ordem das locais do loop `left_tile, i, icon, row, half, dim, right_tile` e `i=0` antes de `row`/`icon` completam a alocação: `height` fica em `s2` e o loop usa `i=s2`, `icon=s1`, `left_tile=s3`, `right_tile=s7`, `dim=s6`, `half=s0`, `row=0x44(sp)`. | Nenhum bloqueio de instrução: as 6 words não comparadas são três pares HI16/LO16 de identidade de dados do painel (words 37, 184 e 254), sem diferença de instrução. |
| `0x2F4` | `NONMATCHING` 134/253, 99 dif., 20 reloc., 4 lim., 1.012 B | inalterado | A primeira causa confirmada é a word 81 (`lui v1` vs `lui a0`): o candidato usa `v1` para a base de `flags.group` e antecipa o `lui` da base de `count[]` para o delay slot do `lbu`; o original guarda `renderer` nesse slot e reutiliza `a0`. | O scheduler ainda escolhe a base de `count[]` no delay slot; ordens de `group`/`count`, local `count` e inicialização de `i` deram o mesmo resultado ou pior (mínimo 132/253, 101 dif.). Sem mecanismo novo para essa decisão. |
| `0x1764` | `NONMATCHING` 42/182, 140 dif., 32 reloc., 728 B | inalterado (congelada) | O primeiro desvio é a permutação global dos parâmetros em saved registers (`renderer` `s7`↔`s6`, `width` `s3`↔`s7`, `ready` `s6`↔`s0`, `filled` `s0`↔`s7`, `height` em `s8` vs spill). A alavanca de tipos/CSE da 029 não se aplica a essa permutação de prólogo. | Mais de 120 variantes de prólogo já refutadas; nenhuma evidência nova de alocação. |

### `0x1F10` — fronteira de CSE estreita

O cast `(unsigned char)group` foi aplicado apenas no uso da word 91, onde o
original indexa `trailing` com o mesmo byte estreito de `count[]`; o preheader
e a cauda continuam largos. Isso permite ao MWCC reutilizar a base estreita
(`a1`) nesse check e manter a base larga (`2*group`) para a cauda, como no
original. A ordem de declaração aceita é `extent, key, sum, j, next, position,
group, lead, i, metric`.

O resultado é **137/186 words**, **11 diferenças**, **0 relocações**, 23
limitações e 744 B; as words 0–99 são idênticas. O resíduo é estritamente a
troca dependente `&trailing`/`lead` (`t1`↔`a3`), com a ordem dos operandos de
`addu` e os usos de `j`/`sum`. A alavanca de tipos foi testada apenas nesse
resíduo: `lead` como `unsigned int`/`unsigned long` levou a 73/187 (77 dif.,
748 B); `lead` como `unsigned short` e `position` como `unsigned int` deram
125/186 (23 dif.); `position` como `unsigned short` e os dois como `unsigned
int` ficaram piores (66–69/188, 82–85 dif.). Nenhuma variante foi aceita; a
fonte 028 permanece.

### `0x8F0` — identidades de 32 bits contra o CSE

O spill de `height` era sintoma de pressão: o candidato mantinha valores
derivados vivos entre chamadas porque CSE-ava expressões idênticas repetidas.
A reconstrução separa essas expressões por **tipo aritmético de 32 bits** na
primeira, segunda e terceira ocorrência:

```c
/* primeira: int; segunda: unsigned int; terceira: long */
renderer = func_00003AE8(renderer, x + 6,  top, 0, 0x46, atlas, 0, 0);
renderer = func_00003AE8(renderer, x + 6u, bottom, 0, 0x46, atlas + 11u, 0, 0);
renderer = func_00003AE8(renderer, right, top + 6u, 0, 0x62, atlas + 6u, 0, 0);
renderer = func_00003AF0(renderer, 1, 1, width - 20u, height - 27L);
renderer = func_00003AE8(renderer, x + 6L, top + 6L, 0, 0x46, atlas + 6L, 0, 0);
```

As conversões são para `unsigned int` na ABI das importações e os valores são
geométricos positivos de 32 bits; o padrão de bits e o `addiu` não mudam. O
binário prova as fronteiras: qualquer partição de duas identidades ainda
deixa um par em CSE; três identidades distintas por offset eliminam o valor
vivo atravessando chamadas. A troca de `top`/`atlas` na declaração e a ordem
`left_tile, i, icon, row, half, dim, right_tile` no loop completam a alocação;
`i = 0;` antes de `row = 0; icon = 0;` e `for (; i < 2; i++)` reproduzem a
ordem de inicialização `i, icon, row`.

O resultado é **`INCONCLUSIVE` 327/333**, **0 diferenças de instrução**, **0
relocações**, 3 limitações HI16/LO16 (words 37/184/254) e **1.332 B**, o mesmo
tamanho do original. O prólogo e o loop ficam word-a-word, com `height` em
`s2`. As 3 limitações são apenas a identidade de dados do painel não resolvida
no PRX original — a mesma classe da `0x21F8`, que já é certificada com zero
diferenças. Duas compilações oficiais independentes produziram o objeto
SHA-256 `4d34461a3af5e6740b895dc7810bc1eccef88918646b7f70ff1f90ee16b6ee67`;
fonte SHA-256 `312d1cdd8a3add03e29989aef357373b717dbb3b03460afc41d20ab70d7d048b`.

### `0x2F4` e `0x1764` — sem fonte promovida

Em `0x2F4`, a primeira diferença continua na word 81; a ordem das declarações
não muda o artefato de scheduler, e as variantes de ordem de `group`/`count[]`
e de `count` local não fixaram a primeira diferença (ficaram em 134/253 ou
pioraram para 132/253). Em `0x1764`, o primeiro desvio é a permutação dos
parâmetros em saved registers; a alavanca de tipos/CSE não incide nesse
prólogo e as 120+ variantes anteriores continuam refutadas. Nenhuma fonte foi
alterada para essas duas funções.

### Reprodutibilidade 019–023

O helper `scripts/triage_libtutoriallist.ensure_018_reports(repo_root)` gera os
fixtures derivados que antes vinham apenas de `build/seto018/` ignorado:

- o baseline é reconstruído do PRX original fixado, com o SHA-256 verificado;
- a evidência Ghidra vem do `build/seto018/ghidra-boundaries.json` existente ou
  é parseada do log autorizado `build/seto018/ghidra-output.log`;
- os arquivos ausentes são gravados somente sob o `build/seto018/` validado e
  ignorado; arquivos existentes nunca são sobrescritos, preservando a
  comparação stored-vs-rebuilt;
- se o log/evidência autorizado não existir, o helper levanta
  `ProbeError("BLOCKED", ...)` e o teste falha explicitamente como `BLOCKED`,
  nunca como skip.

O teste 023 passou a usar a evidência canônica de `build/seto018/` em vez de
exigir uma cópia redundante em `build/seto023/baseline/018/`. Nenhum artefato
de build é versionado. Na cópia nativa com `private/` real, os opt-ins reais
019–023 passaram: **5 passed em 16,63 s**. O worktree usa um junction para
`private/`; `run_real_match` mantém a rejeição anti-symlink existente, por
isso a execução real usa a cópia nativa com diretório real (proteção
preservada, não relaxada).

### Validação, hashes e cobertura

- WSL2 (cópia nativa, `PYTHONPATH=src`): `python -m pytest -q` →
  **798 passed, 23 skipped** (85,58 s); o worktree também fecha **798 passed,
  23 skipped** (103,01 s).
- `SETO_LIBTUTORIALLIST_025_REAL=1` sobre
  `tests/integration/test_libtutoriallist_025_real.py` → **1 passed** (9,50 s,
  duas compilações independentes por caso).
- Opt-ins reais 019–023 → **5 passed** (16,63 s), com o reparo de fixtures.
- Hashes de produção: `0x1F10`
  `792311995a19dac2e7f65bfa96e891de42aead748d56c3b7237dc2477924d942`
  (fonte `9ac8ce6d684fa583469ea7e2c60baf9419e4c85f38b034ba7495e16061ef68c2`);
  `0x8F0`
  `4d34461a3af5e6740b895dc7810bc1eccef88918646b7f70ff1f90ee16b6ee67`
  (fonte `312d1cdd8a3add03e29989aef357373b717dbb3b03460afc41d20ab70d7d048b`);
  `0x2F4` `eeb9bcccaaa2345bdad6b0c20680218d3389f613b827b083408c77649af4d25c`
  e `0x1764` `0a8d3235b28413127ed1d653d1236dff684f552e327d00b87a940485f88746ea`
  inalterados; `0x21F8`
  `599b39cc6218e1cca1f1c9f44f5c555a8ba728ae20c0ee53e6eedc337e7b8ca7`
  (952 B, 190/238, 0 diferenças) inalterado.
- Cobertura estrita preservada: **16 `MATCHED` / 912 words**; as **36 funções
  com zero diferenças** anteriores continuam, e a `0x8F0` entra como a 37ª
  (`INCONCLUSIVE` com 0 diferenças, ao lado da `0x21F8`); a `0x1F10` continua
  `NONMATCHING` com 11 diferenças. Nenhum padding, NOP, branch morto, código
  morto, `volatile` injustificado, asm inline, UB, cast que mude semântica,
  identidade de dados fabricada ou alias artificial foi introduzido.

## SETO-DECOMP-030 — Register Allocation & Scheduler Recovery Analysis

Esta rodada investigou a fundo os mecanismos de alocação de registradores e scheduling do compilador oficial Metrowerks (`mwccpsp_3.0.1_219`, `-O4,p -sdatathreshold 0`), com foco em `0x1F10` (Priority A), `0x2F4` (Priority B) e `0x1764` (Priority C).

### Tabela de Progresso e Evidência

| Função | Antes | Depois | Mecanismo investigado / recuperado | Bloqueador remanescente |
|---|---|---|---|---|
| `0x1F10` | NONMATCHING (137/186, 11 diffs, 744 B) | NONMATCHING (137/186, 11 diffs, 744 B) | Recuperada ordem de operandos `addu` (`lead + trailing`) nas words 103 e 175; liveness e alocação isolados para swap puro `a3`/`t1` | Heurística de alocação de temporários CSE no pool de registradores voláteis (`lead` em `t1` vs `a3`; `&trailing` em `a3` vs `t1`) |
| `0x2F4` | NONMATCHING (134/253, 99 diffs, 1012 B) | NONMATCHING (134/253, 99 diffs, 1012 B) | Diagnóstico da word 81 (`lui a0` vs `lui v1`): hoisting de `&count` no delay slot de `lbu` | Prioridade do scheduler do MWCC entre store de spill (`sw v0`) e antecipação de endereço constante |
| `0x1764` | NONMATCHING (42/182, 140 diffs, 728 B) | NONMATCHING (42/182, 140 diffs, 728 B) | Congelado conforme TASK.md; sem novas evidências de alocador | Conflito simultâneo entre mapa de saved registers e schedule de delay slot |
| `0x8F0` | INCONCLUSIVE (327/333, 0 diffs, 1332 B) | INCONCLUSIVE (327/333, 0 diffs, 1332 B) | Preservado integralmente (baseline 029) | Identidade de dados HI16/LO16 |
| `0x21F8` | INCONCLUSIVE (190/238, 0 diffs, 952 B) | INCONCLUSIVE (190/238, 0 diffs, 952 B) | Preservado integralmente | Identidade de dados HI16/LO16 |

### Análise Aprofundada

#### 1. Priority A (`func_00001F10.c`)
- Na análise inicial (R1), levantou-se a hipótese de que todas as 11 diferenças decorreriam de um swap simétrico `a3`/`t1`. Essa conclusão revelou-se incompleta perante a descompilação de máquina:
  - Nas words 103 e 175, o original emite `addu t4, a3, v1` (`rs = lead`, `rt = trailing`).
  - O candidato anterior emitia `addu t4, v1, t1` gerado a partir de `position += lead;`. Mesmo mapeando `t1` para `a3`, a ordem dos operandos de adição permanecia invertida (`rs = trailing`, `rt = lead`).
- **Recuperação Efetuada (R2)**:
  - Testou-se a hipótese de materialização explícita de `trailing` e `lead` em `position = lead + trailing;`.
  - O MWCC PSP gerou exatamente `addu t4, t1, v1` (`rs = lead`, `rt = trailing`) tanto na word 103 quanto na word 175.
  - Isso **recupera com 100% de fidelidade a ordem dos operandos da instrução original**.
  - Com essa correção, todas as 11 diferenças de instrução remanescentes (words 100, 101, 102, 103, 135, 143, 161, 167, 173, 174, 175) tornaram-se estritamente e comprovadamente o swap 1-para-1 de alocação de registradores entre `lead` (original `a3`, candidato `t1`) e o ponteiro temporário `&trailing[group]` (original `t1`, candidato `a3`).
- **Linha do tempo de liveness comprovada**:
  - `&trailing[group]` é definido na word 100 (`addu t1, a0, a1`), utilizado na 101 (`lhu v1, 0(t1)`), sobrevive a todo o loop interno, utilizado na 161 (`lhu v1, 0(t1)`) e 167 (`sh v1, 0(t1)`), e redefinido na continuação em 174 (`addiu t1, a1, 12`).
  - `lead` é definido na word 102 (`lhu a3, 0(t0)`), utilizado na 103 (`addu t4, a3, v1`), 135 (`sll t2, a3, 1`) e 143 (`addu a1, a3, t3`), morrendo dentro do loop na word 143 antes de ser recarregado na 173 (`lhu a3, 8(a1)`).
- **Hipóteses adicionais testadas e refutadas**:
  - Inversão de declaração `leading`/`trailing`: quebra a ordem de carga e desestabiliza a word 99.
  - Permutação de posição de declaração de `trailing`: mantem idênticas as 11 diferenças sem alterar a preferência de registrador do MWCC.
  - Qualificador `register int lead;`: ignorado pelo otimizador de alocação global (`-O4,p`), gerando binário idêntico.
- **Conclusão**: O código-fonte aceito incorpora `position = lead + trailing;`, recuperando a ordem de operandos de adição, preservando rigorosamente o tamanho exato de 744 B, 0 problemas de relocação e equivalência funcional completa.

#### 2. Priority B (`func_000002F4.c`)
- O desvio inicial na word 81 (`lui a0, ...` vs `lui v1, ...`) foi completamente dissecado.
- Causa identificada: após a chamada `func_000008F0`, o original armazena imediatamente `renderer` no stack (`sw v0, 44(sp)`) preenchendo o load delay slot de `lbu a1, 24980(a0)` (flags), liberando `a0` para ser reutilizado na carga de `count`.
- No candidato, o compilador antecipa o cálculo do endereço base constante de `&count` no delay slot, necessitando de um registrador adicional (`v1`) para a base de `flags` e postergando o store de `v0` para a word 89.
- Hipóteses testadas em R2:
  - Reordenação de inicialização de acumuladores (`total`, `preceding`, `leading`): o agendador do MWCC mantém o hoisting de endereços invariantes.
  - Substituição da estrutura de loop por `while (i < count)`: produz representação intermediária equivalente, mantendo as 99 diffs e o desvio na word 81.
  - Variável local explícita `count = func_00006190_panel.count[group]`: piorou as diferenças de 99 para 101.
- Conclusão: a representação de 1012 B com lifetime stack-backed para `&renderer` permanece como o melhor baseline verificado. O objetivo de recuperação do scheduler em `0x2F4` permanece não resolvido a nível de fonte C sem constructs sintéticos ou inline asm inadmissíveis.

#### 3. Priority C (`func_00001764.c`)
- Mantida rigorosamente congelada conforme estipulado em TASK.md Section 3, visto que nenhuma nova mecânica de alocador foi evidenciada nas funções primárias aplicável a seu prólogo.
- Preservados os intrinsics Allegrex max/min e o ABI de 9 argumentos de `func_000014E0`.

### Validação e Cobertura
- **Suíte de Testes Windows (`py -3.12 -m pytest -q`)**: 790 passed, 39 skipped em 197 s.
- **Suíte de Testes WSL2 (`pytest -q tests/integration/test_libtutoriallist_025_real.py`)**: 1 passed (todas as 10 verificações de compilação limpas, incluindo asserção estrita dos opcodes `addu t4, t1, v1` nas words 103 e 175 de `0x1F10`).
- **Opt-ins Reais WSL2 (019–023)**: 5 passed em 91 s.
- **Opt-ins Reais Callbacks/Real WSL2**: 3 passed em 41 s.
- **Integridade da Certificação**: Preservadas rigorosamente as **16 funções `MATCHED` / 912 certified words** e as **37 funções com zero diferenças de instrução**.
- **SHA-256 dos Objetos Verificados**:
  - `0x1F10`: `b569edc7730675e8f17614803b951fe6e4a468264ada92831aae23f321f5f307` (fonte `d024c56a52319e61298916e4f3717b864ab25d88c6ade4b20c2f8e8fd14a3f60`)
  - `0x2F4`: `eeb9bcccaaa2345bdad6b0c20680218d3389f613b827b083408c77649af4d25c`
  - `0x1764`: `0a8d3235b28413127ed1d653d1236dff684f552e327d00b87a940485f88746ea`
  - `0x8F0`: `4d34461a3af5e6740b895dc7810bc1eccef88918646b7f70ff1f90ee16b6ee67`
  - `0x21F8`: `599b39cc6218e1cca1f1c9f44f5c555a8ba728ae20c0ee53e6eedc337e7b8ca7`

## SETO-DECOMP-031 — Data Identity & Matching Completion

Esta rodada investigou a viabilidade de evidências independentes de identidade de dados para `0x39C` e `0x414` (`libhtml_view.prx`) e realizou uma recuperação concreta de codegen e scheduling em `0x2F4` (`func_000002F4.c`).

### Tabela de Progresso e Evidência

| Target | Antes | Depois | Verified improvement | Remaining blocker |
|---|---|---|---|---|
| `0x2F4` | NONMATCHING (134/253, 99 diffs, 20 reloc, 1012 B) | NONMATCHING (140/253, 92 diffs, 17 reloc, 1012 B) | Recuperado primeiro bloco do scheduler (words 81–92): `sw v0, 44(sp)` no load delay slot de `lbu a1`, eliminação de `lui v1`; primeira divergência avançou para word 93 | CFG de loop original com cópias inacessíveis do agendador (`0x4B0`, `0x560`, `0x634`) e desvio de branch em 93 |
| `0x39C` | INCONCLUSIVE (28/30, 0 diffs, 120 B) | INCONCLUSIVE (28/30, 0 diffs, 120 B) | Investigação de proveniência de dados concluída; confirmado `ASSUMPTION_DEPENDENT` em links controlados | Ausência de metadados independentes de linker/símbolo para prova estrita de identidade cruzada |
| `0x414` | INCONCLUSIVE (31/41, 0 diffs, 164 B) | INCONCLUSIVE (31/41, 0 diffs, 164 B) | Investigação de proveniência de dados concluída; confirmado `ASSUMPTION_DEPENDENT` para tabela e strings | Ausência de metadados independentes de linker/símbolo para símbolos `D_000047*` |
| `0x1F10` | NONMATCHING (137/186, 11 diffs, 744 B) | NONMATCHING (137/186, 11 diffs, 744 B) | Preservada baseline recuperada em 030-R2 (`lead + trailing`, opcodes `addu` idênticos) | Swap de alocação `a3`/`t1` |
| `0x1764` | NONMATCHING (42/182, 140 diffs, 728 B) | NONMATCHING (42/182, 140 diffs, 728 B) | Congelado conforme TASK.md Section 4 | Rotação de registradores salvos e delay slot acoplado |
| `0x8F0` | INCONCLUSIVE (327/333, 0 diffs, 1332 B) | INCONCLUSIVE (327/333, 0 diffs, 1332 B) | Preservado integralmente | Identidade de dados HI16/LO16 |
| `0x21F8` | INCONCLUSIVE (190/238, 0 diffs, 952 B) | INCONCLUSIVE (190/238, 0 diffs, 952 B) | Preservado integralmente | Identidade de dados HI16/LO16 |

### Análise Aprofundada

#### 1. Priority A — Identidade de Dados (`0x39C`, `0x414`)
- Realizou-se uma auditoria completa através de `audit_data_identity.py` e das ferramentas de análise de relocação/proveniência.
- Para `0x39C`, a tabela de saltos gerada pelo compilador em `.rodata` offset `0x0` contém destinos idênticos aos da tabela em `.data+0x8` do PRX original, mas a equivalência observada em links controlados decorre da imposição de layout (`0x4770`), tratando-se de evidência `ASSUMPTION_DEPENDENT`. Nenhum artefato independente de linker ou símbolo comprova a identidade do objeto fora do próprio executável analisado.
- Para `0x414`, os rótulos de strings `D_000047A4`, `D_000047D0` e `D_00004800` são nomes provisórios derivados do endereço. Embora o linking integrado com `--defsym` reproduza os bytes exatos, não há mapa independente ou metadados de símbolo externos que estabeleçam identidade autêntica.
- Em conformidade estrita com o portão de viabilidade de TASK.md Section 1.4, a investigação de promoção de identidade foi encerrada sem alterar a política estrita de certificação. O status de ambas as funções permanece legitimamente `INCONCLUSIVE`.

#### 2. Priority B — Recuperação Concreta de Codegen em `0x2F4` (`func_000002F4.c`)
- **Mecanismo Causal**: A discrepância na word 81 (`lui v1` vs `lui a0`) devia-se à disponibilidade prematura do registrador temporário `$v1`. Como a variável `i` só era inicializada no cabeçalho do `for`, `$v1` estava livre no ponto de leitura de `flags.group`, permitindo que o MWCC usasse `$v1` para `flags` e realizasse o hoisting da base invariante `&count` para o delay slot da carga `lbu`.
- **Correção Aceita**: A inicialização explícita `i = 0;` antes da leitura de `flags.group` ativa a liveness de `i` em `$v1`. Sem `$v1` livre, o MWCC aloca `$a0` para a base de `flags`.
- **Efeito no Agendamento**: Devido à dependência de base em `$a0`, o compilador não pode antecipar a carga de `count` para o delay slot. Em seu lugar, agenda o store de spill `sw v0, 44(sp)` na word 83 e `addu t2, zero, zero` (`total = 0`) na word 84, exatamente como no original.
- **Resultado Comprovado**:
  - Words 81 a 92 agora coincidem instrução por instrução com o binário original.
  - Primeira divergência avançou da word 81 para a word 93 (`blez a0, 31` vs `blez a0, 33`).
  - Palavras coincidentes subiram de 134 para 140/253 (+6).
  - Diferenças de instrução caíram de 99 para 92 (-7).
  - Problemas de relocação caíram de 20 para 17 (-3).
  - Tamanho preservado em exatos 1012 bytes.

### Validação e Cobertura
- **Suíte de Testes Windows (`py -3.12 -m pytest -q`)**: 790 passed, 39 skipped.
- **Suíte de Testes WSL2 (`pytest -q tests/integration/test_libtutoriallist_025_real.py`)**: 1 passed (10 compilações limpas, com novas expectativas para 0x2F4).
- **Opt-ins Reais WSL2 (019–023, Callbacks, Módulo)**: 9 passed.
- **Testes de Equivalência WSL2**: 8 passed.
- **Integridade da Certificação**: Preservadas rigorosamente as **16 funções `MATCHED` / 912 certified words** e as **37 funções com zero diferenças de instrução**.
- **SHA-256 dos Objetos Verificados**:
  - `0x2F4`: `ca6fdd7cbedd08f88cbed50a23a67684bb67cf5cebe6af5fc60e5bf5839c434f` (fonte `f15a10c558d1326d4ad0f855dfa68186e3f1d630081b114eb2e9a233b2621d82`)
  - `0x1F10`: `b569edc7730675e8f17614803b951fe6e4a468264ada92831aae23f321f5f307` (fonte `d024c56a52319e61298916e4f3717b864ab25d88c6ade4b20c2f8e8fd14a3f60`)
  - `0x1764`: `0a8d3235b28413127ed1d653d1236dff684f552e327d00b87a940485f88746ea`
  - `0x8F0`: `4d34461a3af5e6740b895dc7810bc1eccef88918646b7f70ff1f90ee16b6ee67`
  - `0x21F8`: `599b39cc6218e1cca1f1c9f44f5c555a8ba728ae20c0ee53e6eedc337e7b8ca7`
