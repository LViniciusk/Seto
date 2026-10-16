# Toolchain

Seto is **stdlib-only**. It never bundles, downloads or redistributes any
proprietary component, and every external tool is optional: Seto does useful,
verifiable work with none of them installed and reports a precise, honest status
for each one it can use when it *is* present.

```powershell
py -3.12 -m seto toolchain
py -3.12 -m seto toolchain --json
```

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
| `rea` / `node` | analyzer-mcp | MCP analysis server (needs Node.js). | No |
| `java` | runtime | Required by Ghidra. | No |

## Resolution order

For every tool Seto tries, in order:

1. the path in `config/seto.toml` (e.g. `[tools.mwccpsp] path = "C:/..."`) — a
   directory is accepted and the executable is looked up inside it;
2. the tool's environment variable (`SETO_MWCCPSP`, `SETO_SPLAT`, `SETO_M2C`,
   `SETO_WIBO`, `SETO_WINE`, `SETO_OBJDUMP`, `SETO_NODE`, `SETO_JAVA`,
   `SETO_REA`; Ghidra uses `SETO_GHIDRA_HOME`, `GHIDRA_HOME`, `GHIDRA_INSTALL_DIR`);
3. `PATH`.

Ghidra is special: it wants the *installation directory*, and Seto verifies that
`support/analyzeHeadless[.bat]` exists before reporting it as available. The
version is read from `Ghidra/application.properties`.

When a tool is missing, `seto toolchain` prints `MISSING` with the reason, and a
command that genuinely needs it exits with code `4` (`BLOCKED`) — never `0`.

## Reference environment status

Measured with `seto toolchain` in the environment this repo was developed in:

| Tool | Status |
| --- | --- |
| `mwccpsp` | **MISSING** (proprietary; must be supplied by the user) |
| `splat` | MISSING |
| `m2c` | MISSING |
| `wibo` | MISSING |
| `wine` | MISSING |
| `mips*-objdump` | MISSING |
| `rea` | MISSING |
| `ghidra` | MISSING (not configured) |
| `node` | available |
| `java` | available |

Consequently, real compilation and real matching are **BLOCKED** in this
environment. `seto match` still runs and still proves things (self-comparison,
raw-blob comparison, relocation-type comparison); it only cannot compare against
a freshly compiled object. See `docs/decomp-progress.md`.

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
4. Place a licensed `mwccpsp.exe` somewhere and register it:

   ```powershell
   $env:SETO_MWCCPSP = "C:\tools\mwccpsp.exe"
   py -3.12 -m seto toolchain
   ```

5. Run the suite:

   ```powershell
   python -m pytest                 # unit tests, no media required
   python -m pytest -m integration  # needs private/ (and the ISO for verify)
   ```

## Reproducing on WSL2

The compiler is a 32-bit Windows binary, so on Linux it is run through a loader.

```bash
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv build-essential

git clone <this repo> seto && cd seto
python3.12 -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[dev,disasm,yaml]"

# Win32 loader for mwccpsp.exe
cargo install wibo   # or download a release binary and put it on PATH

export SETO_MWCCPSP=/mnt/c/tools/mwccpsp.exe
export SETO_WIBO="$(command -v wibo)"
seto toolchain
```

`wibo` (or `wine`) is prepended to the compiler command line by
`scripts/match_function.py --loader wibo`. No shell is ever involved: every
process is spawned with an argument list, a timeout, and bounded output
(`seto.toolchain.run`).

## Optional Python extras

| Extra | Package | Used for |
| --- | --- | --- |
| `disasm` | `capstone>=5.0` | Human-readable listings in `seto disasm`. Never a matching input. |
| `yaml` | `PyYAML>=6.0` | Cross-checking the emitted `config/splat/*.yaml`. |
| `dev` | `pytest>=8.0` | The test suite. |

Without them Seto still works: `seto disasm` reports `BLOCKED` and the YAML
cross-check is skipped, while `check-layout` keeps validating the model, which is
the reproducible part.
