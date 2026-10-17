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

The reconstruction is complete and readable but **unverified**: `mwccpsp` is not
available here, so no object file exists to compare. That is reported as
`BLOCKED`, not as a match. The *names* of the four imported functions are also
still unknown: the module stores NIDs, not names, so a name would have to come
from the exporting library's table in another module. The declarations in
`decomp/include/sce_stubs.h` therefore stay keyed by address and carry the
recovered `(library, NID)` in their comments.

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
| Draft C for the other 13 discovered functions | not yet iterated; m2c output is preliminary and must be reviewed against Ghidra | select small, independently bounded functions and validate each listing |
| Cross-artifact data identity in `func_000004B8` and `func_000006E4` | no independent link from candidate data symbols/variables to original objects; manual JSON maps are assertions only | find original object/linker metadata or another independent artifact proving the link |
| Ghidra automatic selection for generic ELF32 MIPS `ET_REL` | this Ghidra build selects `MIPS:LE:64:64-32R6addr` for the synthetic object | use the validated MIPS32/Allegrex languages explicitly; retain the real-PRX integration check |
| Real *names* for the imported functions | the module stores NIDs, not names | read the exporting library's table from a module/firmware that has it |
| Identity of the two `func_000006E4` globals | SETO-DECOMP-007 proved the `0x600000` is the high half of a different address, so the three are distinct module-relative addresses; their *section* identity is still unproven because no named section covers them | find another reference to the same offsets, or an original object/symbol table that shows a section; until then they stay `INFERRED` |
| Python 3.11 run of the suite | no 3.11 interpreter in the development environment (`py -3.11` is unavailable); the suite was run on 3.12 | run `python -m pytest` on 3.11 (CI does, on Ubuntu and Windows) |
| REA native analysis / PSP PRX | MCP transport is connected, but no native provider or PRX analysis is demonstrated | configure/test a native provider separately; do not infer PRX support from MCP connectivity |

`seto toolchain` reports the exact state of every tool, so this table can be
re-derived rather than trusted.

## Next steps

1. Review helper/global prototypes in the two new reconstructions and use the
   installed `m2c` as a preliminary aid for the remaining `.text` functions.
2. Recover real *names* for the `(library, NID)` pairs from a module or firmware
   image that carries the exporting libraries' tables, and rename the declarations
   in `decomp/include/`.
3. Move `func_000006E4`'s three destinations from segment-only to section-backed
   resolution by finding a named section (or an original symbol table) that covers
   `0x4860`, `0x604860`
   and `0x604B9C`; SETO-DECOMP-007 showed they are distinct module-relative
   addresses, so the open question is their section, not their relationship. The
   `seto datarefs` report is the regression check for that change.
