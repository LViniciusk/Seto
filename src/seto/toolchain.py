"""External tool discovery, configuration and bounded process execution.

Seto never bundles, downloads or redistributes proprietary toolchains.  It
locates what the user already has (through ``config/seto.toml``, an environment
variable, or ``PATH``), records the exact version it found, and reports a
precise diagnosis when a required tool is missing instead of faking success.

All processes are launched with argument lists (never ``shell=True``), with a
configurable timeout and bounded output capture.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

DEFAULT_CONFIG_PATH = Path("config/seto.toml")
DEFAULT_TIMEOUT = 60.0
DEFAULT_MAX_OUTPUT = 64 * 1024
VERSION_TIMEOUT = 15.0


@dataclass(frozen=True)
class ToolSpec:
    """A tool Seto knows how to locate and describe."""

    name: str
    kind: str
    description: str
    env_var: str
    names: tuple[str, ...]
    version_args: tuple[str, ...] | None = None
    license_note: str = ""


TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "mwccpsp",
        "compiler",
        "Metrowerks CodeWarrior for PSP (``MW MIPS C Compiler``)",
        "SETO_MWCCPSP",
        ("mwccpsp", "mwccpsp.exe", "mwcceppc", "mwcceppc.exe"),
        None,
        "proprietary; must be supplied and licensed by the user",
    ),
    ToolSpec(
        "splat",
        "splitter",
        "splat binary splitter",
        "SETO_SPLAT",
        ("splat", "splat64"),
        ("--version",),
    ),
    ToolSpec(
        "m2c",
        "decompiler",
        "m2c MIPS-to-C decompiler",
        "SETO_M2C",
        ("m2c",),
        ("--version",),
    ),
    ToolSpec(
        "wibo",
        "loader",
        "wibo Win32 binary loader (runs mwccpsp on Linux/WSL)",
        "SETO_WIBO",
        ("wibo",),
        None,
    ),
    ToolSpec(
        "wine",
        "loader",
        "Wine Win32 compatibility layer",
        "SETO_WINE",
        ("wine64", "wine"),
        ("--version",),
    ),
    ToolSpec(
        "objdump",
        "binutils",
        "MIPS GNU objdump (relocation-aware disassembly of .o files)",
        "SETO_OBJDUMP",
        ("mips-linux-gnu-objdump", "mipsel-linux-gnu-objdump", "mips-none-elf-objdump"),
        ("--version",),
    ),
    ToolSpec(
        "node",
        "runtime",
        "Node.js (required by REA)",
        "SETO_NODE",
        ("node",),
        ("--version",),
    ),
    ToolSpec(
        "java",
        "runtime",
        "Java runtime (required by Ghidra)",
        "SETO_JAVA",
        ("java",),
        ("-version",),
    ),
    ToolSpec(
        "rea",
        "analyzer-mcp",
        "Reverse Engineer Anything (REA) MCP server",
        "SETO_REA",
        ("rea",),
        ("--version",),
    ),
)

GHIDRA_ENV_VARS = ("SETO_GHIDRA_HOME", "GHIDRA_HOME", "GHIDRA_INSTALL_DIR")
GHIDRA_HEADLESS_NAMES = ("analyzeHeadless.bat", "analyzeHeadless")


@dataclass(frozen=True)
class ToolStatus:
    name: str
    kind: str
    found: bool
    path: str | None = None
    version: str | None = None
    reason: str | None = None

    @property
    def state(self) -> str:
        return "available" if self.found else "missing"

    def summary(self) -> dict[str, object]:
        return {
            "name": self.name,
            "kind": self.kind,
            "state": self.state,
            "path": self.path,
            "version": self.version,
            "reason": self.reason,
        }

    def line(self) -> str:
        if not self.found:
            return f"{self.name:<9} MISSING  {self.reason or 'not found'}"
        version = f"  ({self.version})" if self.version else ""
        return f"{self.name:<9} OK       {self.path}{version}"


@dataclass(frozen=True)
class RunResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def combined(self) -> str:
        return (self.stdout + self.stderr).strip()


def run(
    argv: Sequence[str | Path],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    max_output: int = DEFAULT_MAX_OUTPUT,
) -> RunResult:
    """Run a command with an argument list, no shell, a timeout and bounded output.

    ``subprocess`` gives the child two OS pipes.  They must be consumed *while*
    the child runs: a chatty compiler that fills the ~64 KiB pipe buffer would
    otherwise block on ``write`` forever while we block on ``wait`` (a classic
    deadlock).  Two daemon reader threads drain stdout and stderr concurrently
    and keep at most ``max_output`` bytes *per stream* in memory; the rest is
    counted and discarded.  On timeout the child is killed and the readers are
    joined, so the call always returns.
    """
    arguments = tuple(str(part) for part in argv)
    if not arguments:
        raise ValueError("argv must not be empty")
    child_env = None
    if env is not None:
        child_env = dict(os.environ)
        child_env.update(env)
    try:
        process = subprocess.Popen(
            list(arguments),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd) if cwd is not None else None,
            env=child_env,
            shell=False,
        )
    except FileNotFoundError as exc:
        return RunResult(arguments, None, "", f"failed to launch: {exc}")
    except PermissionError as exc:
        return RunResult(arguments, None, "", f"permission denied: {exc}")
    except OSError as exc:
        return RunResult(arguments, None, "", f"failed to launch: {exc}")

    assert process.stdout is not None and process.stderr is not None
    out_chunks: list[bytes] = []
    out_stats = [0, 0]
    err_chunks: list[bytes] = []
    err_stats = [0, 0]
    threads = [
        threading.Thread(
            target=_drain, args=(process.stdout, out_chunks, out_stats, max_output), daemon=True
        ),
        threading.Thread(
            target=_drain, args=(process.stderr, err_chunks, err_stats, max_output), daemon=True
        ),
    ]
    for thread in threads:
        thread.start()

    timed_out = False
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        returncode = process.wait()
    for thread in threads:
        thread.join(timeout=5.0)

    return RunResult(
        arguments,
        returncode,
        _join(out_chunks),
        _join(err_chunks),
        timed_out=timed_out,
        truncated=out_stats[0] > max_output or err_stats[0] > max_output,
    )


def _drain(stream, chunks: list[bytes], stats: list[int], limit: int) -> None:
    """Read a pipe to EOF, keeping at most ``limit`` bytes (stats[0] = total)."""
    read = getattr(stream, "read1", stream.read)
    try:
        while True:
            chunk = read(65536)
            if not chunk:
                break
            stats[0] += len(chunk)
            remaining = limit - stats[1]
            if remaining > 0:
                kept = chunk[:remaining]
                chunks.append(kept)
                stats[1] += len(kept)
    finally:
        stream.close()


def _join(chunks: list[bytes]) -> str:
    return b"".join(chunks).decode("utf-8", "replace")


@dataclass(frozen=True)
class Settings:
    """Parsed ``config/seto.toml`` plus its origin."""

    data: Mapping[str, Any] = field(default_factory=dict)
    path: Path | None = None

    def get(self, *keys: str, default: Any = None) -> Any:
        current: Any = self.data
        for key in keys:
            if not isinstance(current, Mapping) or key not in current:
                return default
            current = current[key]
        return current

    def tool_path(self, name: str) -> str | None:
        value = self.get("tools", name, "path")
        return str(value) if value else None

    @property
    def baseline(self) -> Mapping[str, Any]:
        value = self.get("baseline", default={})
        return value if isinstance(value, Mapping) else {}


def load_settings(path: str | Path | None = None) -> Settings:
    """Load settings from ``path`` (or ``config/seto.toml`` when present)."""
    candidate = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    if not candidate.is_file():
        if path is not None:
            raise FileNotFoundError(f"configuration file not found: {candidate}")
        return Settings()
    with open(candidate, "rb") as handle:
        data = tomllib.load(handle)
    return Settings(data=data, path=candidate)


def find_tool(
    spec: ToolSpec,
    configured: str | None = None,
    *,
    env: Mapping[str, str] | None = None,
    probe: bool = True,
) -> ToolStatus:
    """Locate ``spec`` through config, then environment, then ``PATH``."""
    source = dict(os.environ if env is None else env)
    candidates: list[tuple[str, str]] = []
    if configured:
        candidates.append(("configured path", configured))
    if source.get(spec.env_var):
        candidates.append((spec.env_var, source[spec.env_var]))

    for origin, value in candidates:
        resolved = Path(value)
        if resolved.is_dir():
            resolved = _resolve_in_directory(spec, resolved) or resolved
        if resolved.is_file():
            return _status_with_version(spec, resolved, probe)
        return ToolStatus(
            spec.name,
            spec.kind,
            False,
            reason=f"{origin} {value!r} does not exist",
        )

    for name in spec.names:
        found = shutil.which(name)
        if found:
            return _status_with_version(spec, Path(found), probe)
    return ToolStatus(
        spec.name,
        spec.kind,
        False,
        reason=f"not found (looked for {', '.join(spec.names)} on PATH)",
    )


def _resolve_in_directory(spec: ToolSpec, directory: Path) -> Path | None:
    for name in spec.names:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def _status_with_version(spec: ToolSpec, path: Path, probe: bool) -> ToolStatus:
    version: str | None = None
    reason: str | None = None
    if probe:
        arguments = () if spec.version_args is None else spec.version_args
        result = run([path, *arguments], timeout=VERSION_TIMEOUT, max_output=4096)
        if result.timed_out:
            reason = "version probe timed out"
        else:
            text = result.stdout + "\n" + result.stderr
            version = next((line.strip() for line in text.splitlines() if line.strip()), None)
            if version:
                version = version[:160]
            else:
                reason = "no version output"
    return ToolStatus(
        spec.name, spec.kind, True, path=str(path), version=version, reason=reason
    )


def find_ghidra(configured_home: str | None = None, *, env: Mapping[str, str] | None = None) -> ToolStatus:
    """Locate a Ghidra installation and its headless launcher."""
    source = dict(os.environ if env is None else env)
    home: str | None = configured_home
    if not home:
        home = next((source[var] for var in GHIDRA_ENV_VARS if source.get(var)), None)
    if not home:
        return ToolStatus(
            "ghidra",
            "analyzer",
            False,
            reason=f"not configured (set {' or '.join(GHIDRA_ENV_VARS)})",
        )
    root = Path(home)
    if not root.is_dir():
        return ToolStatus("ghidra", "analyzer", False, reason=f"GHIDRA home {home!r} does not exist")
    launcher = next((root / "support" / name for name in GHIDRA_HEADLESS_NAMES if (root / "support" / name).is_file()), None)
    if launcher is None:
        return ToolStatus(
            "ghidra",
            "analyzer",
            False,
            reason=f"no analyzeHeadless launcher under {root / 'support'}",
        )
    return ToolStatus(
        "ghidra",
        "analyzer",
        True,
        path=str(launcher),
        version=ghidra_version(root),
    )


def ghidra_version(home: Path) -> str | None:
    """Read the Ghidra version from the installation's properties file."""
    for relative in ("Ghidra/application.properties", "application.properties"):
        properties = home / relative
        if not properties.is_file():
            continue
        for line in properties.read_text("utf-8", errors="replace").splitlines():
            if line.startswith("application.version="):
                return line.split("=", 1)[1].strip()
    return None


def detect_all(
    settings: Settings | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> tuple[ToolStatus, ...]:
    """Locate every known tool, in a deterministic order."""
    active = settings or Settings()
    statuses = [
        find_tool(spec, active.tool_path(spec.name), env=env) for spec in TOOL_SPECS
    ]
    ghidra_home = active.get("tools", "ghidra", "path")
    statuses.append(
        find_ghidra(str(ghidra_home) if ghidra_home else None, env=env)
    )
    return tuple(statuses)


def mwcc_argv(
    compiler: str | Path,
    source: str | Path,
    output: str | Path,
    *,
    flags: Sequence[str] = (),
    includes: Sequence[str] = (),
    defines: Sequence[str] = (),
    loader: Sequence[str] = (),
) -> tuple[str, ...]:
    """Build the ``mwccpsp`` command line (optionally wrapped in wibo/wine)."""
    arguments = [
        *loader,
        str(compiler),
        "-c",
        str(source),
        "-o",
        str(output),
        *flags,
        *(f"-I{include}" for include in includes),
        *(f"-D{define}" for define in defines),
    ]
    return tuple(arguments)


def splat_argv(splat: str | Path, config: str | Path) -> tuple[str, ...]:
    """Build the ``splat split`` command line for one configuration file."""
    return (str(splat), "split", str(config))


def ghidra_headless_argv(
    launcher: str | Path,
    project_dir: str | Path,
    project_name: str,
    binary: str | Path,
    *,
    scripts: Sequence[str] = (),
    script_path: str | Path | None = None,
    delete_project: bool = False,
    analysis_timeout: int | None = None,
) -> tuple[str, ...]:
    """Build the ``analyzeHeadless`` command line for importing a binary."""
    arguments = [str(launcher), str(project_dir), project_name, "-import", str(binary)]
    if script_path is not None:
        arguments += ["-scriptPath", str(script_path)]
    for script in scripts:
        arguments += ["-postScript", script]
    if delete_project:
        arguments.append("-deleteProject")
    if analysis_timeout is not None:
        arguments += ["-analysisTimeoutPerFile", str(analysis_timeout)]
    return tuple(arguments)
