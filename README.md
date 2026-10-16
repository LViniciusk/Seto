# Seto

Reproducible, *matching* decompilation infrastructure for **Yu-Gi-Oh! GX Tag
Force 1** (PSP, USA — `ULUS10136`).

Seto is the scaffolding around the decompilation, not the decompilation itself.
It builds a deterministic inventory and baseline of the original disc, safely
parses the containers it can (`PARAM.SFO`, ELF32 / PSP PRX), derives and
*validates* a splat layout, and runs a relocation-aware comparator that can prove
a reconstructed function byte-for-byte — once you supply a real compiler.

It is deliberately conservative: it never reports success it cannot prove.

## Scope

In scope: binary fidelity, reproducible inventories, safe parsers, layout/splat
configuration, relocation-aware matching, and honest progress reporting.

Out of scope: a native PC port, multiplayer, extra cards, or any gameplay change.

## Requirements

* Python **3.11+** (developed and tested with 3.12). The core is **stdlib-only**.
* Optional: `capstone` (listings), `PyYAML` (YAML cross-check), `pytest` (tests).
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
seto check-layout --layout build/split/layout.json --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx
seto disasm --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx --function 0x244
seto match --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx --function 0x244 --candidate <candidate.o>
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

The committed config is `config/splat/libhtml_view.yaml`. It is a *candidate*
until `splat` is actually run on it.

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

Compares a function's original bytes against a candidate (a compiled `.o`, another
module, or a raw blob). Relocated words are compared by relocation type and
addend; one-sided symbols are reported as limitations, never ignored.

```text
$ seto match --prx ...\libhtml_view.prx --function 0x244 --candidate ...\libhtml_view.prx
function func_00000244 @ 0x244
  status:  MATCHED
  match:   100.00% (13/13 words)
  diffs:   0
  result: MATCHED (no divergence proven in the validated range)
```

Add `--json` for the full result.

### `seto toolchain` — external tool status

```text
$ seto toolchain
external tools
  mwccpsp   MISSING  not found (looked for mwccpsp, mwccpsp.exe, ...)
  ...
  node      OK       C:\Program Files\nodejs\node.exe  (v24.21.0)
  java      OK       ... (openjdk 25.0.3)
missing: mwccpsp, splat, m2c, wibo, wine, objdump, rea, ghidra
```

### `scripts/match_function.py` — automated compile + compare

Compiles a reconstruction with `mwccpsp` (optionally through `wibo`/`wine`) and
feeds the resulting object straight into `seto match`, propagating its verdict and
exit code. If the compiler is missing it reports `BLOCKED`.

```powershell
$env:SETO_MWCCPSP = "C:\tools\mwccpsp.exe"
py -3.12 scripts/match_function.py `
    --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx `
    --function 0x244 `
    --source decomp/src/func_00000244.c `
    --flag=-O4,p --flag=-sdatathreshold --flag=0
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Usage, I/O or parse error. |
| `3` | The check ran and the answer is "not equal" (baseline mismatch, layout error, `NONMATCHING`). |
| `4` | `BLOCKED`: a required external tool is unavailable. |

## Repository layout

```text
src/seto/            stdlib-only package (sfo, elf, mips, matching, split, inventory, toolchain, cli)
config/seto.toml     baseline values and tool paths
config/splat/        generated, candidate splat configs
decomp/src/          reconstructed C
decomp/include/      shared reconstruction headers
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
```

Unit tests build every fixture byte-by-byte in memory, so they are deterministic
and never touch the commercial media. Integration tests skip automatically when
the media is absent.

## Documentation

* [`docs/baseline.md`](docs/baseline.md) — measured facts about the disc, SFO and modules.
* [`docs/toolchain.md`](docs/toolchain.md) — tool resolution, Windows and WSL2 setup.
* [`docs/decomp-progress.md`](docs/decomp-progress.md) — MATCHED / NONMATCHING / BLOCKED report.

## Licence

MIT (see [`LICENSE`](LICENSE)). No proprietary tools or game data are included or
redistributed.
