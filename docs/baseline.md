# Baseline: Yu-Gi-Oh! GX Tag Force (PSP, USA)

Everything in this document was measured from the real media present in the
reference environment. No value is copied from a wiki or another project, and
nothing here is committed to Git (the ISO and the extracted tree are ignored).

Reproduce every fact below with:

```powershell
py -3.12 -m seto verify
py -3.12 -m seto inventory --extracted private/original/PSP_GAME --no-verify
```

## Disc image

| Field | Value |
| --- | --- |
| File | `TF1.iso` |
| Size | `701693952` bytes |
| SHA-256 | `FB22D0F06BB9F45A2D0EFF0EF66D541E61210599105037063DB60421E1A3C906` |
| Filesystem | ISO 9660 (`CD001` volume descriptor at `0x8001`) |
| Region | USA (`ULUS10136`) |

`seto verify` recomputes size and SHA-256 and exits `0` (match) or `3`
(mismatch). The expected values live in `config/seto.toml` under `[baseline]`.

## `PARAM.SFO`

10 entries, version `0x00000101`.

| Key | Format | Value |
| --- | --- | --- |
| `BOOTABLE` | int32 | `1` |
| `CATEGORY` | string | `UG` |
| `DISC_ID` | string | `ULUS10136` |
| `DISC_NUMBER` | int32 | `1` |
| `DISC_TOTAL` | int32 | `1` |
| `DISC_VERSION` | string | `1.03` |
| `PARENTAL_LEVEL` | int32 | `3` |
| `PSP_SYSTEM_VER` | string | `2.81` |
| `REGION` | int32 | `32768` |
| `TITLE` | string | `Yu-Gi-Oh!  GX Tag Force` |

Format constants follow the Sony / pspsdk convention actually observed in the
file: `0x0004` binary, `0x0204` UTF-8 string, `0x0404` int32. (The opposite
assignment sometimes quoted from a wiki does not parse this file.)

## Modules analysed

The extracted tree contains five files; two of them are ELF modules that Seto
parses. `libadler.prx` starts with the `~SCE` magic and `EBOOT.BIN` with `~PSP`:
both are encrypted/signed containers that Seto *identifies* but deliberately does
not parse.

| File | Format | Functions in `.text` |
| --- | --- | --- |
| `USRDIR/gmodule/libhtml_view.prx` | ELF32 `ET_MIPS_PSP_PRX` | 16 |
| `USRDIR/gmodule/libtutoriallist.prx` | ELF32 `ET_MIPS_PSP_PRX` | 25 |

Totals reported by `seto inventory`: 5 files, 2 modules, 41 functions.

### `libhtml_view.prx` (primary matching target)

| Field | Value |
| --- | --- |
| Class | ELF32, little-endian, MIPS (machine `8`) |
| `e_type` | `0xFFA0` (`ET_MIPS_PSP_PRX`) |
| Sections | 25 |
| Program headers | 1 |
| Symbols | 0 (stripped) |
| Relocations | 181 |
| `.text` | file offset `0x60`, size `0x7f4` (2036 bytes), vaddr `0x0` |
| Image delta (offset − vaddr) | `0x60` |
| `.comment` | `MW MIPS C Compiler (2.4.1.01)` |

Relocations of `.text` (132 entries):

| Type | Count |
| --- | --- |
| `R_MIPS_26` | 72 |
| `R_MIPS_HI16` | 30 |
| `R_MIPS_LO16` | 30 |

All relocation sections in this PRX carry the same meaningless `sh_link`/`sh_info`
(PSP quirk). Seto resolves targets from the standard `.rel.<name>` naming and
validates them against the section address ranges, and records the ambiguity as an
observation rather than trusting the header fields.

### Function boundaries in `libhtml_view.prx` `.text`

Discovered purely from the ABI (section start, `jal` targets inside the section,
and the instruction after a `jr $ra`), with no heuristic pattern matching:

```
0x000 0x034 0x084 0x08C 0x134 0x178 0x244 0x278
0x358 0x39C 0x414 0x4B8 0x508 0x634 0x6E4 0x704
```
