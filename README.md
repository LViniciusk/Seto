# Seto

Reproducible, *matching* decompilation infrastructure for **Yu-Gi-Oh! GX Tag
Force 1** (PSP, USA — `ULUS10136`).

Seto is the scaffolding around the decompilation, not the decompilation itself.
It builds a deterministic inventory and baseline of the original disc, safely
parses the containers it can (`PARAM.SFO`, ELF32 / PSP PRX), derives and
*validates* a splat layout, and runs a relocation-aware comparator that can prove
a reconstructed function only once you supply a real compiler.

It is deliberately conservative and distinguishes two different things:

* **binary-range equivalence** — the original bytes equal some other bytes;
* **verified decompilation** — a relocatable object actually produced by
  compiling the reconstructed C is equivalent to the original.

It never reports success it cannot prove.

## Scope

In scope: binary fidelity, reproducible inventories, safe parsers, layout/splat
configuration, relocation-aware matching, and honest progress reporting.

Out of scope: a native PC port, multiplayer, extra cards, or any gameplay change.

## Requirements

* Python **3.11+** (developed and tested with 3.12). The core is **stdlib-only**.
* Optional: `capstone` (listings), `PyYAML` (YAML cross-check), `pytest` (tests).
* Optional, to run the open splitter end to end: `splat64[mips]`
  (`pip install "splat64[mips]"`).
* Optional, for real matching: a licensed Metrowerks `mwccpsp` (proprietary) and,
  on Linux/WSL2, `wibo` or `wine`.

## Install

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,disasm,yaml]"
```

Everything below then works as `seto ...`; without installing,
`py -3.12 -m seto ...` is equivalent.

## Quick start

```powershell
seto verify                                   # check TF1.iso against the baseline
seto inventory --extracted private/original/PSP_GAME --no-verify
seto toolchain                                # what external tools are available
seto detect private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx
seto functions --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx
seto split --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx --out build/split
seto split --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx --out build/split --run-splat
seto check-layout --layout build/split/layout.json --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx
seto imports --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx --function 0x244
seto disasm --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx --function 0x244
seto match --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx --function 0x244 --candidate build/match/func_00000244.o
```

`private/`, `build/`, `*.iso` and `*.zip` are git-ignored: **no original game data
is ever committed**, and Seto never writes to it.

## Commands

### `seto verify` — baseline check

Recomputes size and SHA-256 of the ISO and compares against
`config/seto.toml [baseline]`.

```text
$ seto verify
TF1.iso
  size:   701693952
  sha256: FB22D0F06BB9F45A2D0EFF0EF66D541E61210599105037063DB60421E1A3C906
  status: OK
```

### `seto inventory` — deterministic manifest and report

Writes `build/inventory/manifest.json` (sorted keys, no timestamps, byte-identical
across runs) and `build/inventory/report.md`.

```text
$ seto inventory --extracted private/original/PSP_GAME --no-verify
manifest: build\inventory\manifest.json
report:   build\inventory\report.md
files: 5  modules: 2  functions: 41
```

### `seto detect` — signature identification

```text
$ seto detect private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx private/original/PSP_GAME/SYSDIR/EBOOT.BIN
...\libhtml_view.prx: ELF - ELF object or module
...\EBOOT.BIN: PSP - ~PSP encrypted/compressed PSP executable
```

Encrypted containers (`~PSP`, `~SCE`) are identified but intentionally not parsed.

### `seto functions` — function discovery

Boundaries come from the ABI only (section start, in-section `jal` targets, the
instruction after `jr $ra`), never from byte-pattern heuristics.

```text
$ seto functions --prx ...\libhtml_view.prx
...\libhtml_view.prx :: .text (0x7f4 bytes at 0x0)
name                  start   size  calls
func_00000000           0x0     52  0x1f04
...
func_00000244         0x244     52  0x2edc, 0x2f0c, 0x2ef4, 0x2f54
...
total: 16 functions
```

Add `--json` for machine-readable output.

### `seto split` / `seto check-layout` — layout and splat config

`split` derives the layout from the *real* ELF section table, validates it, and
emits `layout.json` plus a splat YAML. `check-layout` re-validates a saved layout
against the module.

```text
$ seto split --prx ...\libhtml_view.prx --out build/split
layout: build\split\layout.json
splat:  build\split\libhtml_view.yaml
segments: 3  subsegments: 15  image delta: 0x60
layout validated against the real module
```

The committed config is `config/splat/libhtml_view.yaml`. It is generated from the
validated layout, never hand-edited, and `--run-splat` proves it is really
consumable: it runs `splat64[mips]` on it, then reads the listings splat wrote and
checks every word back against the original file.

```text
$ seto split --prx ...\libhtml_view.prx --out build/split --run-splat
layout: build\split\layout.json
splat:  build\split\libhtml_view.yaml
segments: 3  subsegments: 15  image delta: 0x60
splat:  ...\Scripts\splat.EXE (splat 0.50.1)
  Split 21 KB (100.00%) in defined segments
listing: text.s 509 words (verified against the original bytes)
listing: sceStub_text.s 2536 words (verified against the original bytes)
layout validated against the real module
```

A listing that disagrees with the file, or that fails to cover a whole segment, is
an **error** (exit `3`), never a success. Without splat installed the command
reports `BLOCKED` (exit `4`). The `assets/`, `include/`, `asm/`, `.splache` and
`undefined_*_auto.txt` output is git-ignored: it is reproducible build output.

`check-layout` validates the layout model against the real ELF section table —
nothing more. It does **not** mean `splat` ran, nor that the module recompiles.

### `seto imports` — PSP import identity

Every imported function a PSP module declares is recovered from the module's own
tables: `.lib.stub` (one `SceLibraryStubTable` per library) points at the library
name in `.rodata.sceResident`, at the NID array in `.rodata.sceNid`, and at one
8-byte `jr $ra; nop` trampoline in `.sceStub.text` per imported function.

```text
$ seto imports --prx ...\libhtml_view.prx --function 0x244
...\libhtml_view.prx :: libhtml_view.prx
library           stubs  stub range           nid range
libehsys           1245  [0x7f4, 0x2edc)      [0x3128, 0x449c)
sceHttp               7  [0x2edc, 0x2f14)     [0x449c, 0x44b8)
sceSsl                2  [0x2f54, 0x2f64)     [0x44d8, 0x44e0)
...
total: 8 libraries, 1268 imported functions
calls in func_00000244:
  0x00024c  R_MIPS_26  +4:00000000 -> 0x002edc  sceHttp/0x76D1363B (stub #0)
  0x000254  R_MIPS_26  +4:00000000 -> 0x002f0c  sceHttp/0xF9D8EB63 (stub #6)
  0x00025c  R_MIPS_26  +4:00000000 -> 0x002ef4  sceHttp/0xD1C8945E (stub #3)
  0x000264  R_MIPS_26  +4:00000000 -> 0x002f54  sceSsl/0x191CDEFF (stub #0)
```

The identity of an imported function is the **(library, NID)** pair — two
identical NIDs in different libraries are *not* the same function. Every pointer
and count is required to lie inside the section it names, every pointer field must
carry the `R_MIPS_32` relocation a loader would use, and the bytes at every
trampoline address must really be `jr $ra`. Structural damage (a truncated entry,
a length that overruns the section, a missing section) is a loud parse error; a
pointer without its relocation or a trampoline whose bytes disagree is a
*limitation*, and the entry is dropped rather than guessed.

`--json` emits the full deterministic report, `--out <path>` writes it (the
committed one is `decomp/imports/libhtml_view.json`), and `--function <addr>`
limits the call listing to one function. Exit `0` when every call was classified,
`5` when any call has no proven destination — an unresolved call is reported with
the exact missing link, never as a match.

Each call site is also validated before it is trusted: the relocation must land
inside the section, the instruction it describes must really be `j`/`jal`, the
relocation type must be the modelled `R_MIPS_26`, and the call must have a delay
slot inside the section.

### `seto disasm` — relocation-annotated listing (needs capstone)

```text
$ seto disasm --prx ...\libhtml_view.prx --function 0x244
00000244: f0 ff bd 27 addiu      $sp, $sp, -0x10
00000248: 0c 00 bf af sw         $ra, 0xc($sp)
0000024c: b7 0b 00 0c jal        0x2edc  ; R_MIPS_26 addend=0x2edc
...
```

Without capstone the command prints `BLOCKED` and exits `4`.

### `seto match` — relocation-aware comparison

Compares a function's original bytes against a candidate. The candidate is
located unambiguously:

* `--candidate-offset` — absolute **file** offset (must lie inside the section);
* `--candidate-section-offset` — offset relative to the candidate's section;
* `--candidate-symbol` — the ELF symbol that starts the function (preferred for
  `ET_REL` objects). The symbol is only accepted when its `shndx` **is** the
  requested section: a numeric value that merely fits inside `.text` proves
  nothing, and undefined, absolute and other special symbols are rejected. A
  symbol requested explicitly but not found makes the run `INCONCLUSIVE` — it
  never silently picks another function (`--candidate-symbol-fallback` opts in to
  automatic detection, still recording the ambiguity);
* otherwise an `ET_REL` object with exactly one discovered function is used, and
  a linked module defaults to the original's section-relative offset. If an
  `ET_REL` object contains several functions and nothing selects one, the result
  is `INCONCLUSIVE` (never an arbitrary pick).

Relocated words are compared by relocation type and addend. `R_MIPS_HI16` and
`R_MIPS_LO16` are associated from the relocation table — a LO16 may sit far from
its HI16 and may resolve several HI16 — instead of assuming the next instruction
is the partner; both halves' symbols are checked, and the pair is counted as
matching only after every check passes. A relocation present on only one side is
a divergence; a symbol exposed on only one side, a HI16 with no resolvable LO16,
or an association that can only be inferred from relocation order is a
limitation, never silently accepted. Raw (non-ELF) candidates are compared as
bytes but always flagged.

`seto match` compares instructions and relocations; it cannot know where the
candidate came from, so its evidence is always `binary-range` and a `MATCHED`
result here is **never** by itself a verified decompilation.

A *call* is the one field that is legitimately encoded differently on the two
sides: a linked module stores the trampoline **address**, a compiled object stores
a **symbol name**. When the two in-place targets differ, `seto match` consults the
module's recovered import table (see `seto imports`) and compares the proven
identities instead: the same `(library, NID)` matches, a different one is
`NONMATCHING`, and anything that cannot be identified is `INCONCLUSIVE`. Each
resolved call is listed in the result as evidence.

Every `MATCHED` names what it proves: `binary equality of the compared range` when
nothing had to be resolved, or `function equivalence with canonically resolved
relocations` when a call identity was resolved. *Full binary equality after
linking* is never claimed — the pipeline does not link.

```text
$ seto match --prx ...\libhtml_view.prx --function 0x244 --candidate ...\libhtml_view.prx
function func_00000244 @ 0x244
  status:  MATCHED
  match:   100.00% (13/13 words)
  diffs:   0
  evidence: binary-range
  located: assumed identical layout (section-relative 0x244)
  result: MATCHED (binary-range equivalence only; not a verified decompilation)
```

Add `--json` for the full deterministic result (including `status`, `evidence`
and the candidate `location`).

### `seto toolchain` — external tool status

```text
$ seto toolchain
external tools
  mwccpsp   MISSING  not found (looked for mwccpsp, mwccpsp.exe, ...)
  splat     OK       ...\Scripts\splat.EXE  (splat 0.50.1)
  ...
  node      OK       C:\Program Files\nodejs\node.exe  (v24.21.0)
  java      OK       ... (openjdk 25.0.3)
missing: mwccpsp, m2c, wibo, wine, objdump, rea, ghidra
```

### `scripts/match_function.py` — automated compile + compare

Compiles a reconstruction with `mwccpsp` (optionally through `wibo`/`wine`) and
compares the resulting object with `seto match`, propagating its verdict and exit
code. If the compiler is missing it reports `BLOCKED`.

This script is the **only** place that may call a match a *verified
decompilation*: it performed the compilation, so it can attest to the
provenance. It removes any previous object first (so the artefact it compares was
produced by this run), hashes the source and the object with SHA-256, asks
`seto match` to compare exactly that object, checks that the object did not change
while it was being read, and writes a JSON record (by default
`<out>/<source>.match.json`, override with `--report`) holding the status, the
compiler, the flags, both hashes and the function.

```powershell
$env:SETO_MWCCPSP = "C:\tools\mwccpsp.exe"
py -3.12 scripts/match_function.py `
    --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx `
    --function 0x244 `
    --source decomp/src/func_00000244.c
```

The script uses the `[match] flags`/`[match] includes` from `config/seto.toml`
unless you override them with `--flag`/`--include`, forwards `--config` to
`seto match` in the correct position, locates the function in the object by its
`func_XXXXXXXX` symbol (override with `--symbol`, or disable with `--no-symbol`),
and propagates the match exit code unchanged. The provenance record is a
verifiable log of a local execution, not an unforgeable attestation.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success; for `match`, a proven `MATCHED`. |
| `1` | Usage, I/O or parse error (including a malformed ELF or layout JSON). |
| `3` | The check ran and the answer is "not equal" (baseline mismatch, layout error, `NONMATCHING`). |
| `4` | `BLOCKED`: a required external tool is unavailable. |
| `5` | `INCONCLUSIVE`: the comparison ran but the evidence is insufficient to decide. |

## Repository layout

```text
src/seto/            stdlib-only package (sfo, elf, mips, matching, imports, split, inventory, toolchain, cli)
config/seto.toml     baseline values and tool paths
config/splat/        generated splat configs (verified by `seto split --run-splat`)
decomp/src/          reconstructed C
decomp/include/      shared reconstruction headers
decomp/imports/      recovered PSP import identities (generated JSON)
scripts/             compile+compare automation
docs/                baseline, toolchain, decomp progress
tests/               unit tests (synthetic fixtures) + tests/integration (real media)
private/             original game data (git-ignored)
build/               generated outputs (git-ignored)
```

## Tests

```powershell
python -m pytest                  # unit tests only; no game data needed
python -m pytest -m integration   # against private/ (and TF1.iso for verify)
python -m compileall -q src scripts tests
```

Unit tests build every fixture byte-by-byte in memory, so they are deterministic
and never touch the commercial media. Integration tests skip automatically when
the media is absent. CI (`.github/workflows/tests.yml`) runs the unit suite on
Python 3.11 and 3.12, on Ubuntu and Windows, with `pip install -e ".[dev]"` —
no ISO, no commercial PRX and no proprietary compiler are ever downloaded.

## Documentation

* [`docs/baseline.md`](docs/baseline.md) — measured facts about the disc, SFO and modules.
* [`docs/toolchain.md`](docs/toolchain.md) — tool resolution, subprocess safety, Windows and WSL2 setup.
* [`docs/decomp-progress.md`](docs/decomp-progress.md) — MATCHED / NONMATCHING / INCONCLUSIVE / BLOCKED report.
* [`decomp/imports/libhtml_view.json`](decomp/imports/libhtml_view.json) — recovered `(library, NID)` identities.

## Licence

MIT (see [`LICENSE`](LICENSE)). No proprietary tools or game data are included or
redistributed.
