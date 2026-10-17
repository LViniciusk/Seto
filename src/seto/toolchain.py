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
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Mapping, Sequence

DEFAULT_CONFIG_PATH = Path("config/seto.toml")
DEFAULT_TIMEOUT = 60.0
DEFAULT_MAX_OUTPUT = 64 * 1024
VERSION_TIMEOUT = 15.0

# ---------------------------------------------------------------- tool states
#
# Locating an executable is not the same as knowing it works.  The vocabulary
# below separates the two, and ``seto toolchain`` only ever reports what the
# evidence supports: nothing is ``READY`` because a process happened to print a
# version string.

#: Not found anywhere Seto looks.
MISSING = "MISSING"
#: Located, but not yet shown to do anything useful.
INSTALLED = "INSTALLED"
#: A functional smoke test for the tool's role in Seto passed.
READY = "READY"
#: Present, but the wrong version or architecture for the job.
INCOMPATIBLE = "INCOMPATIBLE"
#: Present and working, but unable to handle what Seto needs (e.g. a PRX).
UNSUPPORTED = "UNSUPPORTED"
#: Present, but a dependency it needs is unavailable.
BLOCKED = "BLOCKED"
#: Not needed on this platform at all.
NOT_APPLICABLE = "NOT_APPLICABLE"

#: Every state, in the order a report lists them.
TOOL_STATES = (MISSING, INSTALLED, READY, INCOMPATIBLE, UNSUPPORTED, BLOCKED, NOT_APPLICABLE)


def platform_family() -> str:
    """``"nt"`` on native Windows, ``"posix"`` everywhere else."""
    return "nt" if os.name == "nt" else "posix"


@dataclass(frozen=True)
class Capability:
    """One thing a tool can (or cannot) do, and the evidence for that claim."""

    name: str
    state: str
    detail: str = ""

    def summary(self) -> dict[str, object]:
        return {"name": self.name, "state": self.state, "detail": self.detail}

    def line(self) -> str:
        detail = f"  {self.detail}" if self.detail else ""
        return f"    {self.name:<16} {self.state:<14}{detail}"


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
    #: Platform families the tool is needed on; empty means every platform.
    applies_to: tuple[str, ...] = ()
    #: Names of other tools this one needs to be usable.
    requires: tuple[str, ...] = ()

    def applies(self, platform: str | None = None) -> bool:
        if not self.applies_to:
            return True
        return (platform or platform_family()) in self.applies_to


TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "mwccpsp",
        "compiler",
        "Metrowerks CodeWarrior for PSP (``MW MIPS C Compiler``)",
        "SETO_MWCCPSP",
        # Only the PSP/MIPS compiler counts.  ``mwcceppc`` is the PowerPC
        # compiler of the same family and is deliberately NOT a candidate: it
        # cannot produce a MIPS object, so accepting it would report a compiler
        # that can never match.
        ("mwccpsp", "mwccpsp.exe"),
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
        # Only needed to run the Windows compiler on Linux/WSL2.
        applies_to=("posix",),
    ),
    ToolSpec(
        "wine",
        "loader",
        "Wine Win32 compatibility layer",
        "SETO_WINE",
        ("wine64", "wine"),
        ("--version",),
        applies_to=("posix",),
    ),
    ToolSpec(
        "objdump",
        "binutils",
        "MIPS GNU objdump (relocation-aware disassembly of .o files)",
        "SETO_OBJDUMP",
        (
            "mipsel-linux-gnu-objdump",
            "mips-linux-gnu-objdump",
            "mips-none-elf-objdump",
            "llvm-objdump",
        ),
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
        requires=("node",),
    ),
)

GHIDRA_ENV_VARS = ("SETO_GHIDRA_HOME", "GHIDRA_HOME", "GHIDRA_INSTALL_DIR")
GHIDRA_HEADLESS_NAMES = ("analyzeHeadless.bat", "analyzeHeadless")
#: Ghidra needs a JDK, and recent releases need a recent one.
GHIDRA_MIN_JAVA = 21


@dataclass(frozen=True)
class ToolStatus:
    name: str
    kind: str
    found: bool
    path: str | None = None
    version: str | None = None
    reason: str | None = None
    #: The state from :data:`TOOL_STATES`.  Without a smoke test the best that
    #: can be said is MISSING / NOT_APPLICABLE / INSTALLED / BLOCKED.
    state: str = MISSING
    #: What the tool was shown to do (filled in by a smoke test).
    capabilities: tuple[Capability, ...] = ()
    #: Loader used for a non-native version probe (compiler executable path stays
    #: in ``path`` and the actual compile capability stays in ``capabilities``).
    loader: str | None = None
    #: Version probing is diagnostic and separate from functional capability.
    version_probe: Capability | None = None

    @property
    def detection(self) -> str:
        """The legacy ``available``/``missing`` value of ``seto toolchain --json``."""
        return "available" if self.found else "missing"

    def summary(self) -> dict[str, object]:
        """The JSON report.  ``state`` keeps its original meaning; ``capability``
        carries the richer :data:`TOOL_STATES` value, so an existing consumer is
        never broken."""
        return {
            "name": self.name,
            "kind": self.kind,
            "state": self.detection,
            "capability": self.state,
            "path": self.path,
            "version": self.version,
            "reason": self.reason,
            "capabilities": [item.summary() for item in self.capabilities],
            "loader": self.loader,
            "version_probe": None if self.version_probe is None else self.version_probe.summary(),
        }

    def line(self) -> str:
        detail = self.reason or "not found"
        if self.found:
            version = f"  ({self.version})" if self.version else ""
            detail = f"{self.path}{version}"
            if self.reason:
                detail += f" [{self.reason}]"
        if self.loader:
            detail += f" [version probe via {self.loader}]"
        if self.version_probe is not None and self.version_probe.state != READY:
            detail += f" [version probe {self.version_probe.state}: {self.version_probe.detail}]"
        return f"{self.name:<9} {self.state:<15}{detail}"

    def with_capabilities(self, capabilities: tuple[Capability, ...]) -> ToolStatus:
        """A copy carrying smoke-test results (the first one sets the state)."""
        state = capabilities[0].state if capabilities else self.state
        return ToolStatus(
            self.name,
            self.kind,
            self.found,
            self.path,
            self.version,
            self.reason,
            state=state,
            capabilities=capabilities,
            loader=self.loader,
            version_probe=self.version_probe,
        )


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
    #: The machine-local overlay that was merged on top, when there was one.
    overlay: Path | None = None

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


#: The overlay the bootstrap writes next to the configuration it found.
LOCAL_OVERLAY_NAME = "seto.local.toml"
BOOTSTRAP_OVERLAY_NAME = "seto.bootstrap.toml"


def _deep_merge(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    """Merge ``overlay`` over ``base``, section by section."""
    merged = dict(base)
    for key, value in overlay.items():
        current = merged.get(key)
        if isinstance(current, Mapping) and isinstance(value, Mapping):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = value
    return merged


def load_settings(path: str | Path | None = None) -> Settings:
    """Load settings from ``path`` (or ``config/seto.toml`` when present).

    A generated ``seto.bootstrap.toml`` is merged over the tracked file, then
    ``seto.local.toml`` (when present) is merged last so a user's explicit local
    override wins. The bootstrap never writes machine-specific paths into the
    tracked config or overwrites a user's local settings.
    """
    candidate = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    if not candidate.is_file():
        if path is not None:
            raise FileNotFoundError(f"configuration file not found: {candidate}")
        return Settings()
    # ``utf-8-sig`` so a byte-order mark written by a Windows editor or script is
    # tolerated rather than turning into a parse error.
    data = tomllib.loads(candidate.read_text(encoding="utf-8-sig"))
    overlays = tuple(
        candidate.with_name(name)
        for name in (BOOTSTRAP_OVERLAY_NAME, LOCAL_OVERLAY_NAME)
        if candidate.with_name(name) != candidate and candidate.with_name(name).is_file()
    )
    for overlay_path in overlays:
        data = _deep_merge(data, tomllib.loads(overlay_path.read_text(encoding="utf-8-sig")))
    return Settings(data=data, path=candidate, overlay=overlays[-1] if overlays else None)


def find_tool(
    spec: ToolSpec,
    configured: str | None = None,
    *,
    env: Mapping[str, str] | None = None,
    probe: bool = True,
    platform: str | None = None,
    version_loader: Sequence[str | Path] = (),
) -> ToolStatus:
    """Locate ``spec`` through config, then environment, then ``PATH``.

    Presence is always a fact and is always reported; ``state`` is the verdict.
    A tool that is not needed on this platform is still looked for - so the
    report never claims something is absent when it was simply not searched for -
    but it is neither probed nor ever reported as usable here.

    ``platform`` overrides the platform family the tool is judged against, which
    is what makes the platform rules testable on either operating system.
    """
    applicable = spec.applies(platform)
    missing_state = MISSING if applicable else NOT_APPLICABLE
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
            return _status_with_version(
                spec,
                resolved,
                probe,
                applicable=applicable,
                version_loader=version_loader,
                platform=platform or platform_family(),
            )
        return ToolStatus(
            spec.name,
            spec.kind,
            False,
            reason=f"{origin} {value!r} does not exist",
            state=missing_state,
        )

    for name in spec.names:
        found = shutil.which(name)
        if found:
            return _status_with_version(
                spec,
                Path(found),
                probe,
                applicable=applicable,
                version_loader=version_loader,
                platform=platform or platform_family(),
            )
    reason = (
        f"not needed on this platform (needed on {'/'.join(spec.applies_to)})"
        if not applicable
        else f"not found (looked for {', '.join(spec.names)} on PATH)"
    )
    return ToolStatus(spec.name, spec.kind, False, reason=reason, state=missing_state)


def _resolve_in_directory(spec: ToolSpec, directory: Path) -> Path | None:
    for name in spec.names:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def _status_with_version(
    spec: ToolSpec,
    path: Path,
    probe: bool,
    *,
    applicable: bool = True,
    version_loader: Sequence[str | Path] = (),
    platform: str = "nt",
) -> ToolStatus:
    """Describe a located executable, probing it only when that is useful."""
    if not applicable:
        return ToolStatus(
            spec.name,
            spec.kind,
            True,
            path=str(path),
            reason=f"not needed on this platform (needed on {'/'.join(spec.applies_to)})",
            state=NOT_APPLICABLE,
        )
    if not probe:
        return ToolStatus(spec.name, spec.kind, True, path=str(path), state=INSTALLED)
    loader = tuple(str(item) for item in version_loader)
    if spec.name == "mwccpsp" and platform == "posix" and not loader:
        return ToolStatus(
            spec.name,
            spec.kind,
            True,
            path=str(path),
            reason="version probe skipped: no Win32 loader (wibo or wine) is available",
            state=INSTALLED,
            version_probe=Capability(
                "version-probe", BLOCKED, "no Win32 loader (wibo or wine) is available"
            ),
        )
    arguments = () if spec.version_args is None else spec.version_args
    result = run([*loader, path, *arguments], timeout=VERSION_TIMEOUT, max_output=4096)
    loader_path = loader[0] if loader else None
    via = f" via {loader_path}" if loader_path else " natively"
    if result.returncode is None:
        # A file that cannot be executed is not a usable tool, whatever its name.
        detail = result.stderr.strip() or "the process could not be started"
        return ToolStatus(
            spec.name,
            spec.kind,
            True,
            path=str(path),
            reason=detail,
            state=INCOMPATIBLE,
            loader=loader_path,
            version_probe=Capability("version-probe", INCOMPATIBLE, detail),
        )
    if result.timed_out:
        return ToolStatus(
            spec.name,
            spec.kind,
            True,
            path=str(path),
            reason="version probe timed out",
            state=INCOMPATIBLE,
            loader=loader_path,
            version_probe=Capability("version-probe", INCOMPATIBLE, "version probe timed out"),
        )
    text = result.stdout + "\n" + result.stderr
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if spec.name == "mwccpsp":
        version_line = next(
            (line for line in lines if line.lower().startswith("version ")), None
        )
        version = (
            f"{lines[0]} ({version_line})"
            if lines and version_line
            else (version_line or (lines[0] if lines else None))
        )
    else:
        version = lines[0] if lines else None
    if version:
        return ToolStatus(
            spec.name,
            spec.kind,
            True,
            path=str(path),
            version=version[:160],
            state=INSTALLED,
            loader=loader_path,
            version_probe=Capability("version-probe", READY, f"read version{via}"),
        )
    return ToolStatus(
        spec.name,
        spec.kind,
        True,
        path=str(path),
        reason="no version output",
        state=INSTALLED,
        loader=loader_path,
        version_probe=Capability("version-probe", INCOMPATIBLE, f"no version output{via}"),
    )


def find_ghidra(
    configured_home: str | None = None, *, env: Mapping[str, str] | None = None
) -> ToolStatus:
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
            state=MISSING,
        )
    root = Path(home)
    if not root.is_dir():
        return ToolStatus(
            "ghidra",
            "analyzer",
            False,
            reason=f"GHIDRA home {home!r} does not exist",
            state=MISSING,
        )
    launcher = next(
        (
            root / "support" / name
            for name in GHIDRA_HEADLESS_NAMES
            if (root / "support" / name).is_file()
        ),
        None,
    )
    if launcher is None:
        return ToolStatus(
            "ghidra",
            "analyzer",
            False,
            reason=f"no analyzeHeadless launcher under {root / 'support'}",
            state=MISSING,
        )
    return ToolStatus(
        "ghidra",
        "analyzer",
        True,
        path=str(launcher),
        version=ghidra_version(root),
        state=INSTALLED,
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


def spec_for(name: str) -> ToolSpec | None:
    """The spec of a known tool, or ``None`` for a tool detected separately."""
    return next((spec for spec in TOOL_SPECS if spec.name == name), None)


def detect_all(
    settings: Settings | None = None,
    *,
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
) -> tuple[ToolStatus, ...]:
    """Locate every known tool, in a deterministic order.

    A tool that is present but whose dependency is not usable is downgraded to
    ``BLOCKED`` here: an analyzer without its runtime is not an analyzer.
    """
    active = settings or Settings()
    current_platform = platform or platform_family()
    compiler_loader = _compiler_version_loader(active, env) if current_platform == "posix" else ()
    statuses = []
    for spec in TOOL_SPECS:
        statuses.append(
            find_tool(
                spec,
                active.tool_path(spec.name),
                env=env,
                platform=current_platform,
                version_loader=compiler_loader if spec.name == "mwccpsp" else (),
            )
        )
    ghidra_home = active.get("tools", "ghidra", "path")
    statuses.append(find_ghidra(str(ghidra_home) if ghidra_home else None, env=env))
    return tuple(_apply_dependencies(statuses, platform=platform))


def _compiler_version_loader(
    settings: Settings, env: Mapping[str, str] | None
) -> tuple[str, ...]:
    """Find the loader used to probe a PE compiler without changing its path."""
    for name in ("wibo", "wine"):
        spec = spec_for(name)
        assert spec is not None
        status = find_tool(
            spec,
            settings.tool_path(name),
            env=env,
            probe=False,
            platform="posix",
        )
        if status.found and status.path:
            return (status.path,)
    return ()


def _apply_dependencies(
    statuses: Sequence[ToolStatus], *, platform: str | None = None
) -> list[ToolStatus]:
    by_name = {status.name: status for status in statuses}
    resolved: list[ToolStatus] = []
    for status in statuses:
        spec = spec_for(status.name)
        required = list(spec.requires) if spec is not None else []
        if status.name == "ghidra":
            required.append("java")
        if (
            status.name == "mwccpsp"
            and status.state == INSTALLED
            and (platform or platform_family()) == "posix"
        ):
            loaders = [by_name.get("wibo"), by_name.get("wine")]
            if not any(loader and loader.state in (INSTALLED, READY) for loader in loaders):
                status = replace(
                    status,
                    state=BLOCKED,
                    reason="needs a Win32 loader (wibo preferred, or wine) on this platform",
                )
                resolved.append(status)
                continue
        if status.state == INSTALLED and required:
            unusable = [
                name
                for name in required
                if by_name.get(name) is None or by_name[name].state not in (INSTALLED, READY)
            ]
            if unusable:
                status = replace(
                    status,
                    state=BLOCKED,
                    reason=f"needs {', '.join(unusable)}, which is not usable here",
                )
        resolved.append(status)
    return resolved


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


def m2c_argv(
    m2c: str | Path,
    assembly: str | Path,
    *,
    target: str | None = None,
    extra: Sequence[str] = (),
) -> tuple[str, ...]:
    """Build the ``m2c`` command line that decompiles one assembly file.

    ``m2c`` needs a target to know the ABI, and its names have changed between
    releases, so the target is configuration, never a guess baked into the code.
    """
    arguments = [str(m2c)]
    if target:
        arguments += ["-t", target]
    arguments += list(extra)
    arguments.append(str(assembly))
    return tuple(arguments)


def objdump_argv(
    objdump: str | Path,
    binary: str | Path,
    *,
    options: Sequence[str] = ("-f", "-h", "-t", "-r", "-d"),
) -> tuple[str, ...]:
    """Build the ``objdump`` command line that inspects one object file."""
    return (str(objdump), *options, str(binary))


def ghidra_headless_argv(
    launcher: str | Path,
    project_dir: str | Path,
    project_name: str,
    binary: str | Path,
    *,
    processor: str | None = None,
    scripts: Sequence[str] = (),
    script_path: str | Path | None = None,
    delete_project: bool = False,
    analysis_timeout: int | None = None,
) -> tuple[str, ...]:
    """Build the ``analyzeHeadless`` command line for importing a binary.

    ``processor`` pins the language Ghidra must use.  A smoke test uses it to
    demand the Allegrex processor: if the language is not really installed and
    loadable, the import fails instead of quietly picking a MIPS fallback.
    """
    arguments = [str(launcher), str(project_dir), project_name, "-import", str(binary)]
    if processor:
        arguments += ["-processor", processor]
    if script_path is not None:
        arguments += ["-scriptPath", str(script_path)]
    for script in scripts:
        arguments += ["-postScript", script]
    if delete_project:
        arguments.append("-deleteProject")
    if analysis_timeout is not None:
        arguments += ["-analysisTimeoutPerFile", str(analysis_timeout)]
    return tuple(arguments)
