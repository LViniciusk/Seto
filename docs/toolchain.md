# Toolchain

Seto's core is **stdlib-only**. It never bundles or redistributes any proprietary
component. The optional bootstrap downloads only pinned open tools and keeps them
outside the repository; the licensed Metrowerks compiler is supplied by the user.

```powershell
py -3.12 -m seto toolchain
py -3.12 -m seto toolchain --json
py -3.12 -m seto toolchain --smoke
py -3.12 -m seto toolchain --smoke --tool ghidra --json
```

The ordinary command only detects tools. `--smoke` uses generated fixtures to
prove what they actually do; it is deliberately opt-in because Ghidra starts a
JVM and imports the fixture several times. Smoke tests never read `private/` or
the ISO. `--tool NAME` is repeatable, `--smoke-workspace DIR` retains the
synthetic input/output, and `--json --out PATH` writes the deterministic report.

## What each tool is for

| Tool | Kind | Role in Seto | Proprietary |
| --- | --- | --- | --- |
| `mwccpsp` | compiler | Compiles a reconstruction so `match` can prove it byte-for-byte. | **Yes** |
| `splat` | splitter | Consumes `config/splat/*.yaml` to produce `.s` and linker scripts. | No |
| `m2c` | decompiler | Turns a function body into draft C for a human to refine. | No |
| `wibo` | loader | Runs the 32-bit `mwccpsp.exe` under Linux/WSL2. | No |
| `wine` | loader | Alternative Win32 compatibility layer for `mwccpsp.exe`. | No |
| `mips*-objdump` | binutils | Relocation-aware disassembly of compiled `.o` files. | No |
| `ghidra` | analyzer | Headless analysis + `ghidra-allegrex` for Allegrex specifics. | No |
| `rea` | analyzer-mcp | MCP analysis server (runs on Node.js). | No |
| `node` | runtime | JavaScript runtime; must satisfy the pinned REA package engine. | No |
| `npm` | package manager | Installs the pinned open REA package; version output alone does not prove installation. | No |
| `java` | runtime | Required by Ghidra. | No |

Nothing proprietary is ever downloaded or redistributed. `splat` is the open
`splat64[mips]` distribution (`pip install "splat64[mips]"`), which brings the
MIPS dependencies Seto relies on (Rabbitizer for the Allegrex instruction set,
spimdisasm for the listings) without any proprietary component.

## Resolution order

For every tool Seto tries, in order:

1. the path in `config/seto.toml` (e.g. `[tools.mwccpsp] path = "C:/..."`) — a
   directory is accepted and the executable is looked up inside it;
2. the tool's environment variable (`SETO_MWCCPSP`, `SETO_SPLAT`, `SETO_M2C`,
   `SETO_WIBO`, `SETO_WINE`, `SETO_OBJDUMP`, `SETO_NODE`, `SETO_NPM`,
   `SETO_JAVA`, `SETO_REA`; Ghidra uses `SETO_GHIDRA_HOME`, `GHIDRA_HOME`,
   `GHIDRA_INSTALL_DIR`);
3. `PATH`.

Ghidra is special: it wants the *installation directory*, and Seto verifies that
`support/analyzeHeadless[.bat]` exists before reporting it as available. The
version is read from `Ghidra/application.properties`.

## Capability states

| State | Meaning |
| --- | --- |
| `MISSING` | Not found in configuration, environment or `PATH`. |
| `INSTALLED` | Located and launchable; its function has not yet been demonstrated. |
| `READY` | Its functional smoke test passed. |
| `INCOMPATIBLE` | Present, but failed the test or has the wrong architecture/version. |
| `UNSUPPORTED` | Works, but the required capability is not provided/demonstrated. |
| `BLOCKED` | A prerequisite or test input is unavailable. |
| `NOT_APPLICABLE` | Not needed on this platform. |

Installing a binary or printing `--version` is never enough for `READY`. The JSON
keeps its historical `state` field (`available`/`missing`) and adds
`capability`/`capabilities`, so existing consumers remain compatible. A command
that needs an unavailable tool still exits `4` (`BLOCKED`).

For a Windows PE compiler on POSIX, `path` remains the detected compiler binary,
`loader` identifies wibo/Wine, `version_probe` reports the probe result, and
`capabilities` reports the independent compile smoke. Seto never attempts the
version probe by executing the PE directly on Linux, and a version string alone
does not promote compilation to `READY`.

## Reference environment status (2026-10-17)

Measured on the Windows 11 host and its WSL2 Ubuntu environment. `READY` is tied
to the named functional check, not inferred from a file existing or printing a
version:

| Tool | Functional evidence |
| --- | --- |
| `mwccpsp` via WSL2 | **READY**; version probe and synthetic ELF32 MIPS compilation both run through wibo 1.2.0; Metrowerks 3.0.1 build 219. |
| `mwccpsp` native Windows | Version probe **READY**, but the functional compiler smoke exceeded its 120s timeout on this host; use the tested WSL2+wibo route rather than claiming native compile readiness. |
| `splat` | **READY**; pinned 0.50.1 split the synthetic ELF and Seto verified all emitted words. |
| `m2c` | **READY**; pinned commit `708d2d2` produced C for the synthetic MIPS function. |
| `objdump` | **READY**; LLVM 21.1.8 read the ELF32 MIPS header, sections, symbol, relocation and instructions. |
| `ghidra` | 12.1.3 headless **READY**; forced `MIPS:LE:32:default` and `Allegrex:LE:32:default` imports **READY**. Automatic selection for the synthetic ET_REL object chose `MIPS:LE:64:64-32R6addr`, so `mips-auto` is **INCOMPATIBLE**, not silently accepted. |
| Real PSP PRX | **PROVEN** separately by integration test: automatic import of `libhtml_view.prx` selected `Allegrex:LE:32:default`. The general smoke report keeps `prx: BLOCKED` because it uses only synthetic input. |
| `rea` | 6.5.0 CLI **READY** and stdio MCP initialize/`tools/list` **READY** (207 tools); native-provider analysis and PSP-PRX support remain **BLOCKED**/unproven. |
| `node` / `java` | **READY**; Node 24.21.0, Java Corretto 25.0.3. |
| `wibo` / `wine` | `NOT_APPLICABLE` for native Windows execution; WSL2 `wibo` 1.2.0 is installed and used for the real builds. |

## SETO-DECOMP-019 toolchain and REA audit (2026-10-19)

The machine-local REA installation is the lockfile version 6.5.0, and the
installed package metadata matches it. Its `package.json` declares Node engines
`^22.19.0 || ^24.11.0 || >=26.0.0`; Seto now rejects an older/unparseable Node
as an REA runtime instead of letting a generic JavaScript execution smoke imply
REA compatibility. `npm` is needed to install the CLI; installed REA itself is
executed by Node.

The pinned 6.5.0 documentation was checked at
[`rea-agents-6.5.0`](https://github.com/morluto/rea/tree/rea-agents-6.5.0/docs):
Ghidra's released PSP profile is Linux x64 and accepts only its specified
little-endian ELF32 `ET_EXEC` declaration; PRX/`ET_DYN` images are explicitly
outside that profile. Windows Ghidra P0 is a separate read-only lane for PE and
selected raw 6502 inputs, not MIPS. This matches the live provider result below.

On the Windows host, Node 24.21.0/npm 11.19.0, Ghidra 12.1.3, Allegrex v21.4,
JDK 25.0.3, Metrowerks 3.0.1 build 219, m2c, splat, and LLVM objdump were
present. Seto's real smoke proved Ghidra Allegrex, m2c, splat, and objdump. The
native Metrowerks version probe works, but compilation is **BLOCKED** because
the required license is unavailable on this host; Seto now classifies an
explicit license refusal as `BLOCKED` without echoing its machine path. Real
compilation remains on WSL2+wibo. REA 6.5.0 CLI help and MCP initialize plus
`tools/list` passed (207 tools). A scoped `doctor --provider ghidra` passed its
installation/JDK/native-decompiler checks when given the configured Ghidra/JDK
paths, but that is not itself an analysis request. The actual local Ghidra P0
test analyzed a source-owned raw-6502 fixture; a read-only open attempt on the
original PSP PRX was rejected with `target_format_unsupported` (ELF/MIPS), as
the pinned PSP profile predicts. Neither MCP catalog presence nor provider
installation is treated as PRX support.

The Seto npm detector prefers `npm.cmd` on Windows: the extensionless `npm`
PowerShell shim was discoverable but not directly executable by the bounded
process runner (`WinError 193`). The `.cmd` entry passed the non-installing npm
smoke and reported `INSTALLED`; no package was installed or updated by that
smoke.

On WSL2, the existing Metrowerks+wibo toolchain and GNU MIPSel objdump passed
functional smoke. The locked splat 0.50.1 and m2c commit were missing; they were
installed into the existing isolated `~/.seto/venvs` using the POSIX bootstrap.
The bootstrap now accepts `--config PATH` and writes its ignored overlay beside
the selected profile; this fixes the previous root-overlay/explicit-WSL-profile
mismatch. With the WSL profile selected, splat, m2c, wibo and the compiler all
passed smoke. Ghidra 12.1.3 and Allegrex v21.4 were also installed in WSL from
the pinned, SHA-verified archives. The bootstrap/extractor now preserve only
safe archive execute bits and repair the owned headless launchers; the profile
resolves to the POSIX `analyzeHeadless`, not its Windows `.bat`. Ghidra remains
`BLOCKED` because WSL has no Java installation. WSL Node 18.19.1 is outside REA
6.5.0's declared engines, and its visible npm shim is a Windows launcher that
refused the WSL invocation. REA is therefore not installed there; no JDK was
installed with administrative privileges, and decompilation continued with the
verified host Ghidra and WSL Metrowerks.

The `--config` profile option is also safety-checked to remain inside `config/`
and rejects symlinked config/overlay paths. Bootstrap smoke uses the same
explicit profile that was installed, so a WSL run no longer reports a tool as
missing merely because its local path was written beside a different config.

The smoke report deliberately keeps different claims separate: REA installed is
not the same as an MCP connection; an MCP connection does not prove native binary
analysis; Ghidra loading an architecture does not prove that it recognizes a PSP
PRX. See `docs/decomp-progress.md` for the remaining data-identity blockers.

## Reproducible bootstrap

Pinned releases and digests live in `config/toolchain.lock`. The scripts default to
report-only; `--dry-run` prints a selective plan, and only `--install` changes the
external tool directory. They do not elevate silently, edit `PATH`/the registry,
or download `mwccpsp`. Downloads are SHA-256 checked and ZIP members are validated
before extraction. Python tools use isolated environments under `%USERPROFILE%\.seto`
or `~/.seto`. The generated, ignored `config/seto.bootstrap.toml` holds their
paths; the optional user `config/seto.local.toml` is merged last and wins.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bootstrap_toolchain.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bootstrap_toolchain.ps1 `
    -Install -Tool splat,m2c,objdump,ghidra,rea
py -3.12 -m seto toolchain --smoke --json --out build/toolchain-report.json
```

```bash
bash scripts/bootstrap_toolchain.sh --dry-run
bash scripts/bootstrap_toolchain.sh --install --tool splat --tool m2c --tool wibo
# For a local WSL profile, write the ignored overlay beside that profile:
bash scripts/bootstrap_toolchain.sh --install --tool splat --tool m2c --tool wibo \
    --config config/wsl/seto.toml
python3 -m seto toolchain --smoke --json --out build/toolchain-report.json
```

On POSIX, the bootstrap prefers the official `decompals/wibo` release where a
pinned host binary exists; otherwise it leaves Wine/build-from-source as a
documented operator choice. REA is installed into an isolated npm prefix only when
selected, from the official npm registry with lifecycle scripts disabled. No REA
client configuration is written by the bootstrap. `--config PATH` selects the
Seto profile used for detection and its adjacent ignored `seto.bootstrap.toml`
overlay; this matters for explicit WSL profiles, which do not merge the
root-level Windows overlay.

The pinned REA 6.5.0 package declares Node engines
`^22.19.0 || ^24.11.0 || >=26.0.0`. Seto's Node smoke now reports runtimes
outside that range as `INCOMPATIBLE`, and REA remains `BLOCKED` rather than
promoting MCP/provider readiness from an incompatible engine. npm is needed to
install REA; after installation, the CLI runs under Node directly.

## Reproducing on Windows

1. Install Python 3.12: `py -3.12 --version`.
2. Create and activate a virtual environment, then install Seto editable:

   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -e ".[dev,disasm,yaml]"
   ```

3. Extract `PSP_GAME` from your own copy of `TF1.iso` into
   `private/original/PSP_GAME` (git-ignored), or point `[baseline] extracted_root`
   at wherever you extracted it.
4. Bootstrap the open tools, then place a licensed `mwccpsp.exe` somewhere and
   register it. The bootstrap never downloads the proprietary compiler:

   ```powershell
    $env:SETO_MWCCPSP = "C:\tools\mwccpsp.exe"
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bootstrap_toolchain.ps1 `
        -Install -Tool splat,m2c,objdump,ghidra,rea
    py -3.12 -m seto toolchain --smoke
   ```

5. Run the suite:

   ```powershell
   python -m pytest                 # unit tests, no media required
   python -m pytest -m integration  # needs private/ (and the ISO for verify)
   ```

## Reproducing on WSL2

The compiler is a 32-bit Windows binary, so on Linux it is run through a loader.

Install Python/Seto and wibo if this WSL distribution is not configured yet:

```bash
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv build-essential
python3.12 -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[dev,disasm,yaml]"
bash scripts/bootstrap_toolchain.sh --install --tool wibo
```

Use the persistent, ignored WSL profile instead of recreating a `/tmp` config:

```bash
cp config/wsl/seto.example.toml config/wsl/seto.toml
# Edit tools.mwccpsp.path and tools.wibo.path for this machine.
PYTHONPATH=src python3 -m seto --config config/wsl/seto.toml \
    toolchain --smoke --tool mwccpsp --json
```

The profile is selected explicitly and does not merge the Windows-only
`config/seto.local.toml`; its personal-path copy is git-ignored. In the validated
environment the values are the licensed PE compiler under `/mnt/c/Users/...`
and `/home/.../.local/bin/wibo`. Those machine-specific paths are **not** in the
tracked example or tracked configuration.

`scripts/match_function.py` automatically picks configured/discovered `wibo`
(preferred) or Wine on POSIX when `--loader` is omitted. An explicit
`--loader /path/to/wibo` still overrides it. If neither loader is available, the
script exits `4` (`BLOCKED`) before attempting to run the PE compiler. Argument
lists are passed directly; no shell is used.

For the three local integration runs, from the repository root in WSL2:

```bash
PYTHONPATH=src python3 scripts/match_function.py \
  --config config/wsl/seto.toml \
  --prx private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx \
  --function 0x244 --source decomp/src/func_00000244.c \
  --out build/match/func_00000244 --json
```

Repeat with functions `0x4B8` / `func_000004B8.c` and `0x6E4` /
`func_000006E4.c`. Reports and objects are written under ignored `build/`; smoke
uses synthetic input and never reads `private/` or the ISO.

The real compiler emits `Environment variable 'MWCIncludes' not found`; it still
exits successfully and produces the expected ELF32 MIPS object through WSL2+wibo.
No dummy environment variable is set to hide that warning.

## Subprocess safety

Every external process is spawned with an argument list and **never**
`shell=True`. `seto.toolchain.run` uses `subprocess.Popen` with two pipes, drained
concurrently by two daemon reader threads. This matters: if a chatty child filled
the OS pipe buffer while we blocked on `wait()`, the call would deadlock. Each
stream keeps at most `max_output` bytes in memory (the rest is counted and
discarded) so a runaway tool cannot exhaust memory; on timeout the child is
killed and the readers are joined, so the call always returns.

A missing tool is `MISSING`; a file that exists but cannot be launched is
`INCOMPATIBLE`. Neither can look like `READY` or make a required command report
success.

## Optional Python extras

| Extra | Package | Used for |
| --- | --- | --- |
| `disasm` | `capstone>=5.0` | Human-readable listings in `seto disasm`. Never a matching input. |
| `yaml` | `PyYAML>=6.0` | Cross-checking the emitted `config/splat/*.yaml`. |
| `dev` | `pytest>=8.0` | The test suite. |

Without them Seto still works: `seto disasm` reports `BLOCKED` and the YAML
cross-check is skipped, while `check-layout` keeps validating the model, which is
the reproducible part.
