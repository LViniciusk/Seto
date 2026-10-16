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
| `rea` / `node` | analyzer-mcp | MCP analysis server (needs Node.js). | No |
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
   `SETO_WIBO`, `SETO_WINE`, `SETO_OBJDUMP`, `SETO_NODE`, `SETO_JAVA`,
   `SETO_REA`; Ghidra uses `SETO_GHIDRA_HOME`, `GHIDRA_HOME`, `GHIDRA_INSTALL_DIR`);
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

## Reference environment status (2026-10-16)

Measured with `seto toolchain --smoke` on Windows 11 in the development
environment. `READY` below means the named functional check passed, not that all
PSP workflows are ready:

| Tool | Functional evidence |
| --- | --- |
| `mwccpsp` | **MISSING**; proprietary compiler not supplied. First real compilation/match remains blocked. |
| `splat` | **READY**; pinned 0.50.1 split the synthetic ELF and Seto verified all emitted words. |
| `m2c` | **READY**; pinned commit `708d2d2` produced C for the synthetic MIPS function. |
| `objdump` | **READY**; LLVM 21.1.8 read the ELF32 MIPS header, sections, symbol, relocation and instructions. |
| `ghidra` | 12.1.3 headless **READY**; forced `MIPS:LE:32:default` and `Allegrex:LE:32:default` imports **READY**. Automatic selection for the synthetic ET_REL object chose `MIPS:LE:64:64-32R6addr`, so `mips-auto` is **INCOMPATIBLE**, not silently accepted. |
| Real PSP PRX | **PROVEN** separately by integration test: automatic import of `libhtml_view.prx` selected `Allegrex:LE:32:default`. The general smoke report keeps `prx: BLOCKED` because it uses only synthetic input. |
| `rea` | 6.5.0 CLI **READY** and stdio MCP initialize/`tools/list` **READY** (207 tools); native-provider analysis and PSP-PRX support remain **BLOCKED**/unproven. |
| `node` / `java` | **READY**; Node 24.21.0, Java Corretto 25.0.3. |
| `wibo` / `wine` | `NOT_APPLICABLE` on native Windows; not installed here. |

The smoke report deliberately keeps different claims separate: REA installed is
not the same as an MCP connection; an MCP connection does not prove native binary
analysis; Ghidra loading an architecture does not prove that it recognizes a PSP
PRX. See `docs/decomp-progress.md` for the current decompilation blocker.

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
python3 -m seto toolchain --smoke --json --out build/toolchain-report.json
```

On POSIX, the bootstrap prefers the official `decompals/wibo` release where a
pinned host binary exists; otherwise it leaves Wine/build-from-source as a
documented operator choice. REA is installed into an isolated npm prefix only when
selected, from the official npm registry with lifecycle scripts disabled. No REA
client configuration is written by the bootstrap.

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

```bash
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv build-essential

git clone <this repo> seto && cd seto
python3.12 -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[dev,disasm,yaml]"

# Install the pinned wibo release where a binary exists; the script warns before
# a package-manager command that needs root.
bash scripts/bootstrap_toolchain.sh --install --tool wibo

export SETO_MWCCPSP=/mnt/c/tools/mwccpsp.exe
export SETO_WIBO="$(command -v wibo)"
seto toolchain
```

`wibo` (or `wine`) is prepended to the compiler command line by
`scripts/match_function.py --loader wibo`.

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
