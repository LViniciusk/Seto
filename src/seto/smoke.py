"""Functional smoke tests: what each tool was shown to do, and the evidence.

``seto toolchain`` answers "is it there?".  ``seto toolchain --smoke`` answers
"does it work?", which is the question that matters before a tool is trusted with
the game's own files.  Every test here hands the tool a small input that Seto
builds itself (:mod:`seto.synthetic`) and records what came back.

Nothing is inferred.  A tool that prints a version string but cannot process the
synthetic input is ``INCOMPATIBLE``, a tool whose runtime is missing is
``BLOCKED``, and a capability nobody has demonstrated stays ``UNSUPPORTED`` or
``BLOCKED``.  Only a test that actually passed yields ``READY``, so a report can
never claim a tool is ready for PSP analysis when all it ever proved was that the
executable exists.

Every process goes through :func:`seto.toolchain.run`, so it inherits the
argument list, the timeout and the bounded output capture.  Nothing here
downloads anything, reads ``private/`` or changes the machine.
"""

from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from seto import elf, split, synthetic
from seto.binio import SetoError
from seto.toolchain import (
    BLOCKED,
    GHIDRA_MIN_JAVA,
    INCOMPATIBLE,
    MISSING,
    NOT_APPLICABLE,
    READY,
    UNSUPPORTED,
    Capability,
    RunResult,
    Settings,
    ToolStatus,
    detect_all,
    ghidra_headless_argv,
    m2c_argv,
    mwcc_argv,
    objdump_argv,
    run,
    splat_argv,
    platform_family,
)

#: Timeout for the tools that answer in seconds.
SMOKE_TIMEOUT = 120.0
#: ``analyzeHeadless`` starts a JVM, imports and analyses: give it room.
GHIDRA_TIMEOUT = 900.0
#: The Allegrex language the PSP extension declares (``allegrex.ldefs``).
ALLEGREX_LANGUAGE = "Allegrex:LE:32:default"
MIPS32_LANGUAGE = "MIPS:LE:32:default"
#: Where the extension puts that declaration once it is installed.
ALLEGREX_MARKER = Path("Ghidra/Extensions/ghidra-allegrex/data/languages/allegrex.ldefs")
MCP_MAX_MESSAGE = 4 * 1024 * 1024
#: ``m2c`` is a pure-Python decompiler; its cache is not wanted in a smoke test.
_JAVA_VERSION = re.compile(r'version "(\d+)(?:\.(\d+))?')
_LANGUAGE_MARKER = re.compile(r"SETO_LANGUAGE_ID=([^\s]+)")


@dataclass(frozen=True)
class _Context:
    """Everything a smoke test may look at."""

    settings: Settings
    inputs: synthetic.SmokeInputs
    workspace: Path
    run_root: Path
    detected: Mapping[str, ToolStatus]
    platform: str


def _failure(result: RunResult, timeout: float) -> str:
    """A one-line diagnosis of a failed run, never a bare exit code."""
    if result.timed_out:
        return f"timed out after {timeout:.0f}s"
    if result.returncode is None:
        return result.stderr.strip() or "the process could not be started"
    tail = (result.stderr.strip() or result.stdout.strip()).splitlines()
    detail = tail[-1].strip() if tail else ""
    return f"exit code {result.returncode}" + (f": {detail}" if detail else "")


def _without_workspace_paths(detail: str, workspace: Path) -> str:
    """Keep ephemeral smoke workspace names out of the stable JSON evidence."""
    candidates = {str(workspace), str(workspace.resolve()), workspace.as_posix()}
    result = detail
    for candidate in sorted(candidates, key=len, reverse=True):
        result = re.sub(re.escape(candidate), "<smoke-workspace>", result, flags=re.IGNORECASE)
    return result


def _tail(result: RunResult, lines: int = 3) -> str:
    text = result.combined().splitlines()
    return " | ".join(part.strip() for part in text[-lines:] if part.strip())


# ------------------------------------------------------------------- per tool


def _smoke_splat(status: ToolStatus, context: _Context) -> tuple[Capability, ...]:
    """Split the synthetic object and check the listing against its bytes."""
    parsed = elf.parse(context.inputs.object_path)
    layout = split.build_layout(parsed, "seto_smoke")
    work = context.run_root / "splat"
    work.mkdir(parents=True, exist_ok=True)
    target_path = os.path.relpath(context.inputs.object_path, work).replace("\\", "/")
    config = work / "seto_smoke.yaml"
    config.write_text(
        split.emit_splat_yaml(
            layout,
            base_path=".",
            target_path=target_path,
            asm_path="splat/asm",
            ld_script_path="splat/seto_smoke.ld",
        ),
        encoding="utf-8",
    )
    result = run(splat_argv(status.path or "", config), timeout=SMOKE_TIMEOUT, cwd=work)
    if not result.ok:
        return (Capability("split", INCOMPATIBLE, _failure(result, SMOKE_TIMEOUT)),)
    listings = split.verify_splat_output(
        layout, context.inputs.object_path.read_bytes(), work / "splat" / "asm"
    )
    if not listings:
        return (Capability("split", INCOMPATIBLE, "splat wrote no assembly listing"),)
    broken = [item for item in listings if not item.verified]
    if broken:
        return (
            Capability("split", INCOMPATIBLE, f"{broken[0].name}: {broken[0].issues[0].message}"),
        )
    words = sum(item.words for item in listings)
    return (
        Capability(
            "split",
            READY,
            f"consumed the generated config and {words} words matched the object",
        ),
    )


def _smoke_m2c(status: ToolStatus, context: _Context) -> tuple[Capability, ...]:
    """Decompile the synthetic function and require a C body back."""
    target = context.settings.get("tools", "m2c", "target")
    result = run(
        m2c_argv(status.path or "", context.inputs.assembly_path, target=str(target) if target else None),
        timeout=SMOKE_TIMEOUT,
    )
    if not result.ok:
        return (Capability("decompile", INCOMPATIBLE, _failure(result, SMOKE_TIMEOUT)),)
    text = result.stdout
    if "{" not in text or "}" not in text:
        return (Capability("decompile", INCOMPATIBLE, "the output holds no C function body"),)
    if synthetic.SMOKE_FUNCTION not in text:
        return (
            Capability("decompile", INCOMPATIBLE, "the output does not mention the function it was given"),
        )
    return (
        Capability("decompile", READY, f"{len(text.splitlines())} lines of C for the synthetic function"),
    )


def _smoke_objdump(status: ToolStatus, context: _Context) -> tuple[Capability, ...]:
    """Read the object back: header, sections, symbols, relocations, code."""
    result = run(objdump_argv(status.path or "", context.inputs.object_path), timeout=SMOKE_TIMEOUT)
    if not result.ok:
        return (Capability("mips-elf32", INCOMPATIBLE, _failure(result, SMOKE_TIMEOUT)),)
    text = (result.stdout + result.stderr).lower()
    for needle, complaint in (
        ("mips", "the object was not recognised as MIPS"),
        (".rodata", "the section table was not listed"),
        ("seto_smoke_func", "the symbol table was not listed"),
        ("mips_32", "the R_MIPS_32 relocation was not listed"),
        ("addiu", "the MIPS instructions were not disassembled"),
    ):
        if needle not in text:
            return (Capability("mips-elf32", INCOMPATIBLE, complaint),)
    return (
        Capability(
            "mips-elf32",
            READY,
            "ELF32 MIPS header, sections, symbols, relocations and instructions read back",
        ),
    )


def _smoke_compiler(status: ToolStatus, context: _Context) -> tuple[Capability, ...]:
    """Compile a two-line C file and require a real ELF32 MIPS object back."""
    output = context.run_root / "mwccpsp" / "seto_smoke.o"
    output.parent.mkdir(parents=True, exist_ok=True)
    flags = context.settings.get("tools", "mwccpsp", "flags", default=[]) or []
    loader: list[str] = []
    if context.platform == "posix":
        selected_loader = next(
            (
                context.detected[name]
                for name in ("wibo", "wine")
                if name in context.detected
                and context.detected[name].found
                and context.detected[name].state in ("INSTALLED", READY)
            ),
            None,
        )
        if selected_loader is None:
            return (
                Capability("compile", BLOCKED, "no usable Win32 loader (wibo or wine) is available"),
            )
        loader.append(selected_loader.path or "")
    result = run(
        mwcc_argv(
            status.path or "",
            context.inputs.source_path,
            output,
            flags=[str(flag) for flag in flags],
            loader=loader,
        ),
        timeout=SMOKE_TIMEOUT,
    )
    if not result.ok:
        return (Capability("compile", INCOMPATIBLE, _failure(result, SMOKE_TIMEOUT)),)
    if not output.is_file():
        return (Capability("compile", INCOMPATIBLE, "the compiler produced no object"),)
    try:
        produced = elf.parse(output)
    except SetoError as exc:
        return (Capability("compile", INCOMPATIBLE, f"the object is not a readable ELF: {exc}"),)
    if (
        produced.header.e_machine != synthetic.EM_MIPS
        or produced.header.ei_class != 1
        or produced.header.ei_data != 1
        or produced.header.e_type != elf.ET_REL
    ):
        return (
            Capability(
                "compile",
                INCOMPATIBLE,
                f"the object is ELF class {produced.header.ei_class} machine "
                f"{produced.header.e_machine}, byte order {produced.header.ei_data}, "
                "not a little-endian ELF32 MIPS relocatable object",
            ),
        )
    return (Capability("compile", READY, "produced an ELF32 little-endian MIPS object"),)


def _smoke_node(status: ToolStatus, context: _Context) -> tuple[Capability, ...]:
    """Run a line of JavaScript and require its output."""
    result = run(
        [status.path or "", "-e", "process.stdout.write(String(1 + 1))"],
        timeout=SMOKE_TIMEOUT,
    )
    if not result.ok:
        return (Capability("runtime", INCOMPATIBLE, _failure(result, SMOKE_TIMEOUT)),)
    if result.stdout.strip() != "2":
        return (Capability("runtime", INCOMPATIBLE, "the script did not run to completion"),)
    return (Capability("runtime", READY, "executed a script and returned its output"),)


def _smoke_java(status: ToolStatus, context: _Context) -> tuple[Capability, ...]:
    """Check that a JDK recent enough for Ghidra is installed."""
    result = run([status.path or "", "-version"], timeout=SMOKE_TIMEOUT)
    text = result.combined()
    match = _JAVA_VERSION.search(text)
    if not result.ok or match is None:
        return (Capability("runtime", INCOMPATIBLE, _failure(result, SMOKE_TIMEOUT)),)
    major = int(match.group(1))
    if major == 1:  # the pre-9 "1.8.0_401" spelling
        major = int(match.group(2) or 0)
    if major < GHIDRA_MIN_JAVA:
        return (
            Capability(
                "runtime",
                INCOMPATIBLE,
                f"Java {major} is too old: Ghidra needs {GHIDRA_MIN_JAVA} or newer",
            ),
        )
    return (Capability("runtime", READY, f"Java {major} can run Ghidra"),)


def _allegrex_installed(status: ToolStatus, context: _Context) -> bool:
    """Whether the Allegrex processor module is present on disk.

    Presence is not proof that Ghidra loads it - that is what the second headless
    run is for - but it is what decides whether that run is worth attempting.
    """
    if status.path is None:
        return False
    home = Path(status.path).resolve().parent.parent
    return (home / ALLEGREX_MARKER).is_file()


def write_language_probe_script(directory: str | Path) -> Path:
    """Write the tiny Ghidra post-script used to report the selected language."""
    scripts = Path(directory)
    scripts.mkdir(parents=True, exist_ok=True)
    probe = scripts / "SetoLanguage.java"
    probe.write_text(
        """import ghidra.app.script.GhidraScript;
public class SetoLanguage extends GhidraScript {
    @Override protected void run() throws Exception {
        println(\"SETO_LANGUAGE_ID=\" + currentProgram.getLanguageID().getIdAsString());
    }
}
""",
        encoding="utf-8",
    )
    return probe


def _smoke_ghidra(status: ToolStatus, context: _Context) -> tuple[Capability, ...]:
    """Start the headless analyser and import the synthetic object.

    Two separate claims are made, and neither borrows evidence from the other:
    the headless analyser works if it imported the object and left a project
    behind, and the Allegrex processor is loaded only if a second import that
    *demands* the Allegrex language succeeded.  Installing a ZIP is not proof.
    """
    project = context.run_root / "ghidra"
    project.mkdir(parents=True, exist_ok=True)
    scripts = context.run_root / "ghidra-scripts"
    write_language_probe_script(scripts)
    result = run(
        ghidra_headless_argv(
            status.path or "",
            project,
            "seto_smoke",
            context.inputs.object_path,
            scripts=("SetoLanguage.java",),
            script_path=scripts,
        ),
        timeout=GHIDRA_TIMEOUT,
    )
    if not result.ok:
        return (
            Capability("headless", INCOMPATIBLE, _failure(result, GHIDRA_TIMEOUT)),
            Capability("mips-auto", BLOCKED, "headless import did not complete"),
            Capability("mips", BLOCKED, "headless import did not complete"),
            Capability("allegrex", BLOCKED, "headless import did not complete"),
            Capability("prx", BLOCKED, "PSP PRX analysis has not been demonstrated"),
        )
    if not any(project.glob("*.gpr")):
        return (
            Capability("headless", INCOMPATIBLE, "the import left no Ghidra project behind"),
            Capability("mips-auto", BLOCKED, "no project was produced"),
            Capability("mips", BLOCKED, "no project was produced"),
            Capability("allegrex", BLOCKED, "no project was produced"),
            Capability("prx", BLOCKED, "PSP PRX analysis has not been demonstrated"),
        )
    capabilities = [
        Capability("headless", READY, "imported an ELF32 MIPS object into a project")
    ]
    match = _LANGUAGE_MARKER.search(result.combined())
    language = match.group(1) if match else None
    if language and language.startswith(("MIPS:LE:32:", "Allegrex:LE:32:")):
        capabilities.append(Capability("mips-auto", READY, f"Ghidra selected {language} for ELF32 MIPS"))
    else:
        capabilities.append(
            Capability(
                "mips-auto",
                INCOMPATIBLE,
                "automatic ELF32 MIPS language selection was not proved"
                + (f": Ghidra selected {language}" if language else ": no language id was returned"),
            )
        )

    allegrex_installed = _allegrex_installed(status, context)

    forced_mips = run(
        ghidra_headless_argv(
            status.path or "",
            project,
            "seto_mips32",
            context.inputs.object_path,
            processor=MIPS32_LANGUAGE,
            scripts=("SetoLanguage.java",),
            script_path=scripts,
        ),
        timeout=GHIDRA_TIMEOUT,
    )
    forced_mips_language = _LANGUAGE_MARKER.search(forced_mips.combined())
    if (
        forced_mips.ok
        and any(project.glob("seto_mips32.gpr"))
        and forced_mips_language is not None
        and forced_mips_language.group(1) == MIPS32_LANGUAGE
    ):
        capabilities.append(Capability("mips", READY, f"Ghidra loaded and used {MIPS32_LANGUAGE}"))
    else:
        capabilities.append(
            Capability(
                "mips",
                INCOMPATIBLE,
                f"Ghidra refused to load {MIPS32_LANGUAGE}: {_tail(forced_mips)}",
            )
        )

    if not allegrex_installed:
        capabilities.append(
            Capability(
                "allegrex",
                UNSUPPORTED,
                "the Allegrex processor module is not installed, so PSP analysis is unproven",
            )
        )
        capabilities.append(
            Capability("prx", BLOCKED, "not demonstrated: the module is not part of the smoke input")
        )
        return tuple(capabilities)

    forced = run(
        ghidra_headless_argv(
            status.path or "",
            project,
            "seto_allegrex",
            context.inputs.object_path,
            processor=ALLEGREX_LANGUAGE,
            scripts=("SetoLanguage.java",),
            script_path=scripts,
        ),
        timeout=GHIDRA_TIMEOUT,
    )
    forced_language = _LANGUAGE_MARKER.search(forced.combined())
    if (
        not forced.ok
        or not any(project.glob("seto_allegrex.gpr"))
        or forced_language is None
        or forced_language.group(1) != ALLEGREX_LANGUAGE
    ):
        capabilities.append(
            Capability(
                "allegrex",
                INCOMPATIBLE,
                f"Ghidra refused to load {ALLEGREX_LANGUAGE}: {_tail(forced)}",
            )
        )
    else:
        capabilities.append(
            Capability("allegrex", READY, f"Ghidra loaded and used {ALLEGREX_LANGUAGE}")
        )
    capabilities.append(
        Capability("prx", BLOCKED, "not demonstrated: the module is not part of the smoke input")
    )
    return tuple(capabilities)


def _smoke_loader(status: ToolStatus, context: _Context) -> tuple[Capability, ...]:
    """A loader is only proven by compiling a synthetic C file through it."""
    compiler = context.detected.get("mwccpsp")
    if compiler is None or not compiler.found:
        return (
            Capability(
                "win32",
                BLOCKED,
                "no Win32 program is available to run through it (the compiler is absent)",
            ),
        )
    output = context.run_root / status.name / f"seto_smoke_{status.name}.o"
    output.parent.mkdir(parents=True, exist_ok=True)
    flags = context.settings.get("tools", "mwccpsp", "flags", default=[]) or []
    result = run(
        mwcc_argv(
            compiler.path or "",
            context.inputs.source_path,
            output,
            flags=[str(flag) for flag in flags],
            loader=[status.path or ""],
        ),
        timeout=SMOKE_TIMEOUT,
    )
    if not result.ok:
        return (Capability("win32", INCOMPATIBLE, _failure(result, SMOKE_TIMEOUT)),)
    if not output.is_file():
        return (Capability("win32", INCOMPATIBLE, "the Win32 compiler produced no object"),)
    try:
        produced = elf.parse(output)
    except SetoError as exc:
        return (Capability("win32", INCOMPATIBLE, f"compiler output was not ELF: {exc}"),)
    if (
        produced.header.e_machine != synthetic.EM_MIPS
        or produced.header.ei_class != 1
        or produced.header.ei_data != 1
        or produced.header.e_type != elf.ET_REL
    ):
        return (Capability("win32", INCOMPATIBLE, "the loader ran, but output was not ELF32 MIPS"),)
    return (
        Capability("win32", READY, f"executed the Win32 compiler through {status.name} and produced ELF32 MIPS"),
    )


def _mcp_handshake(command: str, timeout: float = 30.0) -> tuple[bool, str]:
    """Start REA over stdio, initialize MCP, and fetch its tool catalog."""
    try:
        process = subprocess.Popen(
            [command, "mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except OSError as exc:
        return False, f"failed to launch MCP server: {exc}"
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    messages: queue.Queue[bytes | None] = queue.Queue(maxsize=8)
    stderr_chunks: list[bytes] = []

    def read_stdout() -> None:
        try:
            while True:
                line = process.stdout.readline(MCP_MAX_MESSAGE + 1)
                if not line:
                    break
                messages.put(line)
        finally:
            messages.put(None)

    def read_stderr() -> None:
        while True:
            chunk = process.stderr.read(8192)
            if not chunk:
                break
            if sum(map(len, stderr_chunks)) < 8192:
                stderr_chunks.append(chunk[: 8192 - sum(map(len, stderr_chunks))])

    stdout_thread = threading.Thread(target=read_stdout, daemon=True)
    stderr_thread = threading.Thread(target=read_stderr, daemon=True)
    stdout_thread.start()
    stderr_thread.start()

    def exchange(request: dict[str, object], response_id: int) -> dict[str, object]:
        process.stdin.write((json.dumps(request, separators=(",", ":")) + "\n").encode())
        process.stdin.flush()
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("MCP response timed out")
            try:
                line = messages.get(timeout=remaining)
            except queue.Empty as exc:
                raise TimeoutError("MCP response timed out") from exc
            if line is None:
                raise RuntimeError("MCP server closed stdout before replying")
            if len(line) > MCP_MAX_MESSAGE:
                raise RuntimeError("MCP server sent an oversized message")
            try:
                message = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise RuntimeError("MCP server wrote non-JSON data to stdout")
            if not isinstance(message, dict):
                raise RuntimeError("MCP server sent a non-object JSON message")
            if message.get("id") == response_id:
                if "error" in message:
                    raise RuntimeError(f"MCP error: {message['error']}")
                return message

    detail = ""
    try:
        initialize = exchange(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "seto-toolchain-smoke", "version": "0.1.0"},
                },
            },
            1,
        )
        if not isinstance(initialize.get("result"), dict):
            raise RuntimeError("MCP initialize returned no result")
        process.stdin.write(
            (json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n").encode()
        )
        process.stdin.flush()
        catalog = exchange(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, 2
        )
        result = catalog.get("result")
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            raise RuntimeError("MCP tools/list returned no tool catalog")
        detail = f"MCP initialize and tools/list succeeded ({len(tools)} tools)"
        return True, detail
    except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
        detail = str(exc)
        stderr = b"".join(stderr_chunks).decode("utf-8", "replace").strip()
        if stderr:
            detail += f"; stderr: {stderr.splitlines()[-1][:160]}"
        return False, detail
    finally:
        try:
            process.stdin.close()
        except OSError:
            pass
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        stdout_thread.join(timeout=1)
        stderr_thread.join(timeout=1)


def _smoke_rea(status: ToolStatus, context: _Context) -> tuple[Capability, ...]:
    """Prove REA CLI and MCP connectivity separately from analysis support."""
    result = run([status.path or "", "--help"], timeout=SMOKE_TIMEOUT)
    if not result.ok or "mcp" not in result.combined().lower():
        return (
            Capability("cli", INCOMPATIBLE, _failure(result, SMOKE_TIMEOUT)),
            Capability("mcp", BLOCKED, "the REA CLI could not be started"),
            Capability("native-analysis", BLOCKED, "not demonstrated"),
            Capability("prx", BLOCKED, "PSP PRX analysis has not been demonstrated"),
        )
    connected, detail = _mcp_handshake(status.path or "")
    return (
        Capability("cli", READY, "REA CLI help command completed"),
        Capability("mcp", READY if connected else INCOMPATIBLE, detail),
        Capability(
            "native-analysis",
            BLOCKED,
            "MCP connectivity does not prove a native analysis provider is configured",
        ),
        Capability("prx", BLOCKED, "PSP PRX analysis has not been demonstrated"),
    )


#: Which function proves which tool.  A tool that is not listed here is reported
#: with its detection state and no capability claim at all.
_SMOKE = {
    "mwccpsp": _smoke_compiler,
    "splat": _smoke_splat,
    "m2c": _smoke_m2c,
    "objdump": _smoke_objdump,
    "ghidra": _smoke_ghidra,
    "rea": _smoke_rea,
    "wibo": _smoke_loader,
    "wine": _smoke_loader,
    "node": _smoke_node,
    "java": _smoke_java,
}


@contextmanager
def _workspace(directory: str | Path | None) -> Iterator[Path]:
    """A place for the synthetic inputs: the caller's, or a temporary one."""
    if directory is not None:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        yield root
        return
    with tempfile.TemporaryDirectory(prefix="seto-smoke-") as created:
        yield Path(created)


def _with_smoke(status: ToolStatus, context: _Context) -> ToolStatus:
    """Run the smoke test of one tool and fold the result into its status."""
    if status.state == NOT_APPLICABLE:
        return status.with_capabilities(
            (Capability("applicable", NOT_APPLICABLE, status.reason or "not needed here"),)
        )
    if status.state == BLOCKED:
        if status.name == "ghidra":
            capabilities = (
                Capability("headless", BLOCKED, status.reason or "Ghidra runtime is unavailable"),
                Capability("mips-auto", BLOCKED, "Ghidra headless is blocked"),
                Capability("mips", BLOCKED, "Ghidra headless is blocked"),
                Capability("allegrex", BLOCKED, "Ghidra headless is blocked"),
                Capability("prx", BLOCKED, "Ghidra headless is blocked"),
            )
        elif status.name == "rea":
            capabilities = (
                Capability("cli", BLOCKED, status.reason or "REA runtime is unavailable"),
                Capability("mcp", BLOCKED, "REA server could not be started"),
                Capability("native-analysis", BLOCKED, "no native provider was exercised"),
                Capability("prx", BLOCKED, "PSP PRX analysis has not been demonstrated"),
            )
        elif status.name == "mwccpsp":
            capabilities = (Capability("compile", BLOCKED, status.reason or "compiler is blocked"),)
        else:
            capabilities = (Capability(status.kind, BLOCKED, status.reason or "a required dependency is unavailable"),)
        return status.with_capabilities(
            capabilities
        )
    runner = _SMOKE.get(status.name)
    if status.path is None or not status.found or runner is None:
        state = BLOCKED if status.state == BLOCKED else MISSING
        if status.name == "ghidra":
            capabilities = (
                Capability("headless", state, status.reason or "not found"),
                Capability("mips-auto", BLOCKED, "Ghidra is not installed"),
                Capability("mips", BLOCKED, "Ghidra is not installed"),
                Capability("allegrex", BLOCKED, "Ghidra is not installed"),
                Capability("prx", BLOCKED, "PSP PRX analysis has not been demonstrated"),
            )
        elif status.name == "rea":
            capabilities = (
                Capability("cli", state, status.reason or "not found"),
                Capability("mcp", BLOCKED, "REA is not installed"),
                Capability("native-analysis", BLOCKED, "no native provider was exercised"),
                Capability("prx", BLOCKED, "PSP PRX analysis has not been demonstrated"),
            )
        elif status.name == "mwccpsp":
            capabilities = (Capability("compile", state, status.reason or "not found"),)
        elif status.name in ("wibo", "wine"):
            capabilities = (Capability("win32", state, status.reason or "not found"),)
        else:
            capabilities = (Capability(status.kind, state, status.reason or "not found"),)
        return status.with_capabilities(
            capabilities
        )
    try:
        capabilities = runner(status, context)
    except Exception as exc:  # a smoke test must never take the whole report down
        capabilities = (Capability(status.kind, INCOMPATIBLE, f"smoke test failed: {exc}"),)
    capabilities = tuple(
        Capability(item.name, item.state, _without_workspace_paths(item.detail, context.workspace))
        for item in capabilities
    )
    return status.with_capabilities(capabilities)


def smoke_report(
    settings: Settings | None = None,
    *,
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    tools: Sequence[str] | None = None,
    workspace: str | Path | None = None,
) -> tuple[ToolStatus, ...]:
    """Detect every tool and then prove what it can do.

    ``tools`` narrows the report to the named tools, ``workspace`` keeps the
    synthetic inputs and the artefacts a tool produced (otherwise they are
    removed when the report is finished), and ``platform`` overrides the platform
    family the tools are judged against.
    """
    active = settings or Settings()
    detected = detect_all(active, env=env, platform=platform)
    wanted = set(tools) if tools else None
    known = {status.name for status in detected}
    unknown = sorted((wanted or set()) - known)
    if unknown:
        raise ValueError(f"unknown tool(s): {', '.join(unknown)}")
    selected = tuple(status for status in detected if wanted is None or status.name in wanted)
    with _workspace(workspace) as root:
        run_root = root / "runs" / uuid.uuid4().hex
        context = _Context(
            settings=active,
            inputs=synthetic.write_inputs(root / "inputs"),
            workspace=root,
            run_root=run_root,
            detected={status.name: status for status in detected},
            platform=platform or platform_family(),
        )
        return tuple(_with_smoke(status, context) for status in selected)
