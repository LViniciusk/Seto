"""Tests for the functional smoke tests.

Every tool here is a fake: a small script that Seto runs exactly the way it runs
the real thing.  What is under test is the *judgement*, because that is where a
report can lie.  A tool that only prints a version string, that fails, or that
returns the wrong kind of artefact must never be reported as ready - and a
capability nobody demonstrated must never borrow the evidence of one that was.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from seto import elf, smoke, synthetic
from seto.toolchain import (
    BLOCKED,
    INCOMPATIBLE,
    MISSING,
    NOT_APPLICABLE,
    READY,
    UNSUPPORTED,
    Settings,
)

PYTHON = sys.executable
SRC_ROOT = Path(__file__).resolve().parents[1] / "src"


def _write_launcher(path: Path, source: str) -> Path:
    """A script that behaves like ``source`` on whichever platform runs it."""
    implementation = path.parent / f"{path.name}_impl.py"
    implementation.write_text(source, encoding="utf-8")
    if os.name == "nt":
        path.write_text(
            f'@echo off\r\n"{PYTHON}" "{implementation}" %*\r\n', encoding="ascii"
        )
    else:
        path.write_text(
            f'#!/bin/sh\nexec "{PYTHON}" "{implementation}" "$@"\n', encoding="utf-8"
        )
        path.chmod(0o755)
    return path


def _fake(tmp_path: Path, name: str, source: str) -> Path:
    suffix = ".cmd" if os.name == "nt" else ""
    return _write_launcher(tmp_path / f"{name}{suffix}", source)


def _settings(**paths: Path) -> Settings:
    return Settings(
        data={"tools": {name: {"path": str(value)} for name, value in paths.items()}}
    )


def _capabilities(report, name):
    entry = next(item for item in report if item.name == name)
    return entry, {capability.name: capability for capability in entry.capabilities}


#: A compiler that writes ``payload`` where ``-o`` says.
COMPILER = """
import pathlib, sys
args = sys.argv[1:]
pathlib.Path(args[args.index('-o') + 1]).write_bytes({payload})
"""

#: A compiler that writes a real ELF32 MIPS object.
COMPILER_MIPS = (
    "import pathlib, sys\n"
    f"sys.path.insert(0, {str(SRC_ROOT)!r})\n"
    "from seto import synthetic\n"
    "args = sys.argv[1:]\n"
    "pathlib.Path(args[args.index('-o') + 1]).write_bytes(synthetic.build_mips_object())\n"
)

#: A headless analyser that leaves the project behind, and refuses a processor
#: it does not have.
GHIDRA = """
import pathlib, sys
args = sys.argv[1:]
if {refuse_processor} and '-processor' in args and args[args.index('-processor') + 1].startswith('Allegrex:'):
    sys.stderr.write('Language not found: ' + args[args.index('-processor') + 1] + chr(10))
    raise SystemExit(1)
project = pathlib.Path(args[0]) / (args[1] + '.gpr')
project.parent.mkdir(parents=True, exist_ok=True)
project.write_text('', encoding='utf-8')
language = args[args.index('-processor') + 1] if '-processor' in args else {auto_language}
print('SETO_LANGUAGE_ID=' + language)
print('INFO  REPORT: Import succeeded')
"""


def _ghidra_home(
    tmp_path: Path,
    *,
    allegrex: bool,
    refuse: bool = False,
    auto_language: str = "MIPS:LE:32:default",
) -> Path:
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    _write_launcher(
        support / name,
        GHIDRA.format(
            refuse_processor="True" if refuse else "False",
            auto_language=repr(auto_language),
        ),
    )
    if allegrex:
        marker = home / smoke.ALLEGREX_MARKER
        marker.parent.mkdir(parents=True)
        marker.write_text("<language_definitions/>", encoding="utf-8")
    return home


def _run(tmp_path: Path, settings: Settings, *names: str, **kwargs):
    return smoke.smoke_report(
        settings, tools=list(names), workspace=tmp_path / "work", **kwargs
    )


# ------------------------------------------------------------------ the compiler


def test_a_compiler_that_fails_is_not_ready(tmp_path) -> None:
    fake = _fake(tmp_path, "mwccpsp", "import sys\nsys.stderr.write('boom')\nsys.exit(1)\n")
    entry, capabilities = _capabilities(
        _run(tmp_path, _settings(mwccpsp=fake), "mwccpsp"), "mwccpsp"
    )
    assert capabilities["compile"].state == INCOMPATIBLE
    assert "exit code 1" in capabilities["compile"].detail
    assert entry.state == INCOMPATIBLE


def test_a_compiler_that_produces_something_other_than_an_elf_is_not_ready(tmp_path) -> None:
    fake = _fake(tmp_path, "mwccpsp", COMPILER.format(payload="b'not an elf at all'"))
    entry, capabilities = _capabilities(
        _run(tmp_path, _settings(mwccpsp=fake), "mwccpsp"), "mwccpsp"
    )
    assert capabilities["compile"].state == INCOMPATIBLE
    assert "not a readable ELF" in capabilities["compile"].detail
    assert entry.state == INCOMPATIBLE


def test_a_compiler_that_produces_no_object_is_not_ready(tmp_path) -> None:
    fake = _fake(tmp_path, "mwccpsp", "import sys\nsys.exit(0)\n")
    _, capabilities = _capabilities(
        _run(tmp_path, _settings(mwccpsp=fake), "mwccpsp"), "mwccpsp"
    )
    assert capabilities["compile"].state == INCOMPATIBLE
    assert "no object" in capabilities["compile"].detail


def test_a_failed_compile_cannot_pass_by_leaving_an_elf_object_behind(tmp_path) -> None:
    fake = _fake(tmp_path, "mwccpsp", COMPILER_MIPS + "import sys\nsys.exit(1)\n")
    _, capabilities = _capabilities(
        _run(tmp_path, _settings(mwccpsp=fake), "mwccpsp"), "mwccpsp"
    )
    assert capabilities["compile"].state == INCOMPATIBLE
    assert "exit code 1" in capabilities["compile"].detail


def test_a_compiler_that_produces_an_elf32_mips_object_is_ready(tmp_path) -> None:
    fake = _fake(tmp_path, "mwccpsp", COMPILER_MIPS)
    entry, capabilities = _capabilities(
        _run(tmp_path, _settings(mwccpsp=fake), "mwccpsp"), "mwccpsp"
    )
    assert capabilities["compile"].state == READY
    assert entry.state == READY


def test_a_stale_object_from_a_previous_smoke_run_cannot_fake_success(tmp_path) -> None:
    workspace = tmp_path / "kept"
    valid = _fake(tmp_path, "mwccpsp_valid", COMPILER_MIPS)
    invalid = _fake(tmp_path, "mwccpsp_invalid", "import sys\nsys.exit(0)\n")
    first, = smoke.smoke_report(
        _settings(mwccpsp=valid), tools=["mwccpsp"], workspace=workspace
    )
    second, = smoke.smoke_report(
        _settings(mwccpsp=invalid), tools=["mwccpsp"], workspace=workspace
    )
    first_cap = {item.name: item for item in first.capabilities}["compile"]
    second_cap = {item.name: item for item in second.capabilities}["compile"]
    assert first_cap.state == READY
    assert second_cap.state == INCOMPATIBLE
    assert "no object" in second_cap.detail


# -------------------------------------------------------------------- the rest


def test_a_decompiler_that_returns_c_is_ready(tmp_path) -> None:
    fake = _fake(tmp_path, "m2c", "print('void seto_smoke_func(void) { }')\n")
    entry, capabilities = _capabilities(_run(tmp_path, _settings(m2c=fake), "m2c"), "m2c")
    assert capabilities["decompile"].state == READY
    assert entry.state == READY


def test_a_decompiler_that_returns_no_c_is_not_ready(tmp_path) -> None:
    fake = _fake(tmp_path, "m2c", "print('usage: m2c [-t target] file')\n")
    _, capabilities = _capabilities(_run(tmp_path, _settings(m2c=fake), "m2c"), "m2c")
    assert capabilities["decompile"].state == INCOMPATIBLE
    assert "no C function body" in capabilities["decompile"].detail


def test_an_objdump_that_does_not_know_mips_is_not_ready(tmp_path) -> None:
    fake = _fake(tmp_path, "objdump", "print('file format elf32-i386')\n")
    entry, capabilities = _capabilities(
        _run(tmp_path, _settings(objdump=fake), "objdump"), "objdump"
    )
    assert capabilities["mips-elf32"].state == INCOMPATIBLE
    assert "not recognised as MIPS" in capabilities["mips-elf32"].detail
    assert entry.state == INCOMPATIBLE


def test_node_is_proved_by_running_a_script(tmp_path) -> None:
    fake = _fake(tmp_path, "node", "import sys\nsys.stdout.write('2')\n")
    _, capabilities = _capabilities(_run(tmp_path, _settings(node=fake), "node"), "node")
    assert capabilities["runtime"].state == READY


def test_a_node_that_does_not_run_a_script_is_not_ready(tmp_path) -> None:
    fake = _fake(tmp_path, "node", "print('not two')\n")
    _, capabilities = _capabilities(_run(tmp_path, _settings(node=fake), "node"), "node")
    assert capabilities["runtime"].state == INCOMPATIBLE


def test_a_java_too_old_for_ghidra_is_not_ready(tmp_path) -> None:
    fake = _fake(
        tmp_path,
        "java",
        "import sys\nsys.stderr.write('java version \"1.8.0_401\"')\n",
    )
    _, capabilities = _capabilities(_run(tmp_path, _settings(java=fake), "java"), "java")
    assert capabilities["runtime"].state == INCOMPATIBLE
    assert "too old" in capabilities["runtime"].detail


def test_a_modern_java_is_ready(tmp_path) -> None:
    fake = _fake(
        tmp_path,
        "java",
        "import sys\nsys.stderr.write('openjdk version \"25.0.3\" 2026-04-21 LTS')\n",
    )
    _, capabilities = _capabilities(_run(tmp_path, _settings(java=fake), "java"), "java")
    assert capabilities["runtime"].state == READY


def test_a_splitter_that_fails_is_not_ready(tmp_path) -> None:
    fake = _fake(tmp_path, "splat", "import sys\nsys.stderr.write('nope')\nsys.exit(2)\n")
    entry, capabilities = _capabilities(
        _run(tmp_path, _settings(splat=fake), "splat"), "splat"
    )
    assert capabilities["split"].state == INCOMPATIBLE
    assert "exit code 2" in capabilities["split"].detail
    assert entry.state == INCOMPATIBLE


# ------------------------------------------------------------------- the loader


def test_a_loader_is_not_applicable_on_native_windows() -> None:
    report = smoke.smoke_report(Settings(data={}), platform="nt", tools=["wibo"])
    _, capabilities = _capabilities(report, "wibo")
    assert capabilities["applicable"].state == NOT_APPLICABLE


def test_a_loader_without_a_windows_program_is_blocked(tmp_path) -> None:
    fake = _fake(tmp_path, "wibo", "import sys\nsys.exit(0)\n")
    entry, capabilities = _capabilities(
        smoke.smoke_report(
            _settings(wibo=fake),
            platform="posix",
            tools=["wibo"],
            workspace=tmp_path / "work",
        ),
        "wibo",
    )
    assert capabilities["win32"].state == BLOCKED
    assert "compiler is absent" in capabilities["win32"].detail
    assert entry.state == BLOCKED


# ------------------------------------------------------------------- the ghidra


def test_headless_is_proved_without_claiming_the_allegrex_processor(tmp_path) -> None:
    home = _ghidra_home(tmp_path, allegrex=False)
    entry, capabilities = _capabilities(
        _run(tmp_path, _settings(ghidra=home), "ghidra"), "ghidra"
    )
    assert capabilities["headless"].state == READY
    assert capabilities["mips-auto"].state == READY
    assert capabilities["mips"].state == READY
    # Nothing was installed, so nothing may be claimed for PSP analysis.
    assert capabilities["allegrex"].state == UNSUPPORTED
    assert capabilities["prx"].state == BLOCKED
    assert entry.state == READY


def test_the_allegrex_processor_is_claimed_only_when_ghidra_loads_it(tmp_path) -> None:
    home = _ghidra_home(tmp_path, allegrex=True)
    _, capabilities = _capabilities(
        _run(tmp_path, _settings(ghidra=home), "ghidra"), "ghidra"
    )
    assert capabilities["headless"].state == READY
    assert capabilities["mips-auto"].state == READY
    assert capabilities["mips"].state == READY
    assert capabilities["allegrex"].state == READY


def test_a_ghidra_that_refuses_allegrex_does_not_get_the_capability(tmp_path) -> None:
    # The module is on disk but Ghidra will not load it: the ZIP is not proof.
    home = _ghidra_home(tmp_path, allegrex=True, refuse=True)
    entry, capabilities = _capabilities(
        _run(tmp_path, _settings(ghidra=home), "ghidra"), "ghidra"
    )
    assert capabilities["headless"].state == READY
    assert capabilities["mips-auto"].state == READY
    assert capabilities["mips"].state == READY
    assert capabilities["allegrex"].state == INCOMPATIBLE
    assert "refused to load" in capabilities["allegrex"].detail
    assert entry.state == READY


def test_a_64_bit_mips_fallback_does_not_prove_automatic_elf32_recognition(tmp_path) -> None:
    home = _ghidra_home(
        tmp_path,
        allegrex=True,
        auto_language="MIPS:LE:64:64-32R6addr",
    )
    _, capabilities = _capabilities(
        _run(tmp_path, _settings(ghidra=home), "ghidra"), "ghidra"
    )
    assert capabilities["headless"].state == READY
    assert capabilities["mips-auto"].state == INCOMPATIBLE
    assert capabilities["mips"].state == READY
    assert capabilities["allegrex"].state == READY


def test_missing_rea_and_ghidra_still_show_separate_unproven_capabilities() -> None:
    statuses = smoke.smoke_report(Settings(data={}), tools=["rea", "ghidra"])
    _, rea = _capabilities(statuses, "rea")
    _, ghidra = _capabilities(statuses, "ghidra")
    assert rea["cli"].state == MISSING
    assert rea["mcp"].state == BLOCKED
    assert rea["native-analysis"].state == BLOCKED
    assert rea["prx"].state == BLOCKED
    assert ghidra["headless"].state == MISSING
    assert ghidra["mips-auto"].state == BLOCKED
    assert ghidra["mips"].state == BLOCKED
    assert ghidra["allegrex"].state == BLOCKED
    assert ghidra["prx"].state == BLOCKED


def test_smoke_rejects_unknown_tool_names() -> None:
    import pytest

    with pytest.raises(ValueError, match="unknown tool"):
        smoke.smoke_report(Settings(data={}), tools=["objdumpish"])


def test_rea_mcp_handshake_is_distinct_from_native_analysis_and_prx_support(tmp_path) -> None:
    fake_rea = _fake(
        tmp_path,
        "rea",
        """
import json, sys
if '--version' in sys.argv:
    print('rea-agents 6.5.0')
elif '--help' in sys.argv:
    print('rea commands: doctor, inspect, mcp')
elif 'mcp' in sys.argv:
    for line in sys.stdin:
        request = json.loads(line)
        if request.get('method') == 'initialize':
            print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':{'protocolVersion':'2025-06-18','capabilities':{},'serverInfo':{'name':'rea','version':'6.5.0'}}}), flush=True)
        elif request.get('method') == 'tools/list':
            print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':{'tools':[{'name':'probe'}]}}), flush=True)
""",
    )
    fake_node = _fake(tmp_path, "node", "print('v24.21.0')\n")
    _, capabilities = _capabilities(
        _run(tmp_path, _settings(rea=fake_rea, node=fake_node), "rea"), "rea"
    )
    assert capabilities["cli"].state == READY
    assert capabilities["mcp"].state == READY
    assert "tools/list succeeded (1 tools)" in capabilities["mcp"].detail
    assert capabilities["native-analysis"].state == BLOCKED
    assert capabilities["prx"].state == BLOCKED


# --------------------------------------------------------------- report shape


def test_an_absent_tool_is_reported_missing(tmp_path) -> None:
    entry, capabilities = _capabilities(
        _run(tmp_path, Settings(data={}), "m2c"), "m2c"
    )
    assert not entry.found
    assert capabilities["decompiler"].state == MISSING
    assert entry.state == MISSING


def test_the_workspace_keeps_the_synthetic_inputs(tmp_path) -> None:
    smoke.smoke_report(Settings(data={}), tools=["m2c"], workspace=tmp_path / "work")
    assert (tmp_path / "work" / "inputs" / "seto_smoke.o").is_file()
    assert (tmp_path / "work" / "inputs" / "seto_smoke.c").is_file()
    assert (tmp_path / "work" / "inputs" / "seto_smoke.s").is_file()


def test_the_report_is_deterministic_and_does_not_leak_the_workspace(tmp_path) -> None:
    fake = _fake(tmp_path, "m2c", "print('void seto_smoke_func(void) { }')\n")
    settings = _settings(m2c=fake)
    first = [status.summary() for status in _run(tmp_path, settings, "m2c")]
    second = [status.summary() for status in _run(tmp_path, settings, "m2c")]
    assert first == second
    workspace = str(tmp_path / "work")
    values = json.loads(json.dumps(first))

    def strings(value):
        if isinstance(value, dict):
            for item in value.values():
                yield from strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from strings(item)
        elif isinstance(value, str):
            yield value

    assert all(workspace not in value for value in strings(values))


def test_failure_details_do_not_leak_the_smoke_workspace(tmp_path) -> None:
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    _write_launcher(
        support / name,
        "import sys\nprint(sys.argv[1])\nsys.exit(1)\n",
    )
    workspace = tmp_path / "work"
    _, capabilities = _capabilities(
        smoke.smoke_report(
            _settings(ghidra=home), tools=["ghidra"], workspace=workspace
        ),
        "ghidra",
    )
    assert capabilities["headless"].state == INCOMPATIBLE
    assert str(workspace) not in capabilities["headless"].detail
    assert "<smoke-workspace>" in capabilities["headless"].detail


def test_the_synthetic_object_is_a_real_elf32_mips_object(tmp_path) -> None:
    path = tmp_path / "seto_smoke.o"
    path.write_bytes(synthetic.build_mips_object())
    parsed = elf.parse(path)
    assert parsed.header.e_machine == synthetic.EM_MIPS
    assert parsed.header.ei_class == 1
    assert [symbol.name for symbol in parsed.symbols] == [
        "",
        synthetic.SMOKE_FUNCTION,
        synthetic.SMOKE_DATA_SYMBOL,
    ]
    assert [item.type_name for item in parsed.relocations_for(".text")] == ["R_MIPS_32"]
    # The instructions are the ones the assembly listing claims.
    assert [word for word in synthetic.SMOKE_TEXT] == [0x27BDFFF0, 0x03E00008, 0x00000000]
