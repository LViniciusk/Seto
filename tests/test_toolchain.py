"""Tests for tool discovery and bounded, shell-free process execution."""

from __future__ import annotations

import sys

import pytest

from seto.toolchain import (
    BLOCKED,
    GHIDRA_ENV_VARS,
    INCOMPATIBLE,
    INSTALLED,
    MISSING,
    NOT_APPLICABLE,
    READY,
    TOOL_SPECS,
    Capability,
    Settings,
    ToolStatus,
    detect_all,
    find_ghidra,
    find_tool,
    ghidra_headless_argv,
    ghidra_version,
    load_settings,
    m2c_argv,
    mwcc_argv,
    objdump_argv,
    run,
)

PYTHON = sys.executable


def _node_spec():
    return next(spec for spec in TOOL_SPECS if spec.name == "node")


# ------------------------------------------------------------------------- run


def test_run_captures_stdout_and_status() -> None:
    result = run([PYTHON, "-c", "print('hello')"])
    assert result.ok
    assert result.returncode == 0
    assert result.stdout.strip() == "hello"
    assert result.truncated is False


def test_run_reports_a_nonzero_exit_code() -> None:
    result = run([PYTHON, "-c", "import sys; sys.exit(3)"])
    assert result.returncode == 3
    assert not result.ok


def test_run_truncates_bounded_output() -> None:
    result = run([PYTHON, "-c", "print('x' * 500)"], max_output=10)
    assert result.truncated is True
    assert len(result.stdout) == 10


def test_run_reports_a_missing_binary_without_raising() -> None:
    result = run(["seto-definitely-not-a-real-binary"])
    assert result.returncode is None
    assert "failed to launch" in result.stderr
    assert not result.ok


def test_run_enforces_the_timeout() -> None:
    result = run([PYTHON, "-c", "import time; time.sleep(30)"], timeout=0.5)
    assert result.timed_out is True
    assert not result.ok


def test_run_rejects_an_empty_argument_list() -> None:
    with pytest.raises(ValueError, match="argv"):
        run([])


def test_run_forwards_extra_environment() -> None:
    result = run(
        [PYTHON, "-c", "import os; print(os.environ['SETO_TEST_MARKER'])"],
        env={"SETO_TEST_MARKER": "42"},
    )
    assert result.stdout.strip() == "42"


def test_run_captures_stderr_separately_from_stdout() -> None:
    result = run(
        [PYTHON, "-c", "import sys; sys.stdout.write('out'); sys.stderr.write('err')"]
    )
    assert result.stdout == "out"
    assert result.stderr == "err"


def test_run_drains_output_larger_than_the_pipe_buffer_without_deadlocking() -> None:
    # 512 KiB is far larger than the OS pipe buffer; a naive wait() would
    # deadlock because the child blocks on write() once the buffer fills.
    result = run(
        [PYTHON, "-c", "import sys; sys.stdout.write('x' * (512 * 1024))"],
        timeout=30,
        max_output=1024,
    )
    assert result.timed_out is False
    assert result.returncode == 0
    assert result.truncated is True
    assert len(result.stdout) == 1024


def test_run_drains_stderr_larger_than_the_pipe_buffer() -> None:
    result = run(
        [PYTHON, "-c", "import sys; sys.stderr.write('e' * (512 * 1024))"],
        timeout=30,
        max_output=1024,
    )
    assert result.timed_out is False
    assert result.truncated is True
    assert len(result.stderr) == 1024


def test_run_still_times_out_while_the_child_is_chatty() -> None:
    result = run(
        [
            PYTHON,
            "-c",
            "import sys, time; sys.stdout.write('x' * (512 * 1024)); sys.stdout.flush(); time.sleep(30)",
        ],
        timeout=1.0,
    )
    assert result.timed_out is True
    assert not result.ok


# -------------------------------------------------------------------- settings


def test_settings_nested_lookup_and_defaults() -> None:
    settings = Settings(data={"tools": {"node": {"path": "C:/node"}}, "baseline": {"disc_id": "X"}})
    assert settings.tool_path("node") == "C:/node"
    assert settings.tool_path("m2c") is None
    assert settings.get("baseline", "disc_id") == "X"
    assert settings.get("missing", "deep", default="fallback") == "fallback"
    assert settings.baseline == {"disc_id": "X"}


def test_load_settings_reads_a_toml_file(tmp_path) -> None:
    path = tmp_path / "seto.toml"
    path.write_text('[baseline]\ndisc_id = "ULUS10136"\n', encoding="utf-8")
    settings = load_settings(path)
    assert settings.path == path
    assert settings.get("baseline", "disc_id") == "ULUS10136"


def test_load_settings_requires_an_explicit_path(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        load_settings(tmp_path / "absent.toml")


# -------------------------------------------------------------------- find_tool


def test_find_tool_prefers_the_configured_path() -> None:
    status = find_tool(_node_spec(), PYTHON, env={}, probe=False)
    assert status.found
    assert status.path == str(PYTHON)
    # ``state`` is the verdict, ``detection`` keeps the original JSON value.
    assert status.state == INSTALLED
    assert status.detection == "available"
    assert "MISSING" not in status.line()


def test_find_tool_reports_a_broken_configured_path() -> None:
    status = find_tool(_node_spec(), "C:/nope/nope.exe", env={}, probe=False)
    assert not status.found
    assert "does not exist" in (status.reason or "")
    assert status.state == MISSING
    assert "MISSING" in status.line()


def test_a_configured_binary_that_cannot_be_executed_is_incompatible(tmp_path) -> None:
    # A file that exists but is not a program is not a usable tool.
    broken = tmp_path / "node"
    broken.write_bytes(b"this is not an executable\n")
    status = find_tool(_node_spec(), str(broken), env={}, probe=True)
    assert status.found
    assert status.state == INCOMPATIBLE
    assert status.reason


def test_a_tool_that_is_not_needed_here_is_still_looked_for(tmp_path) -> None:
    # wibo only exists to run a Windows compiler on Linux/WSL2.
    spec = next(spec for spec in TOOL_SPECS if spec.name == "wibo")
    absent = find_tool(spec, None, env={}, platform="nt")
    assert absent.state == NOT_APPLICABLE
    assert not absent.found
    assert "not needed on this platform" in (absent.reason or "")

    present = tmp_path / "wibo"
    present.write_bytes(b"")
    found = find_tool(spec, str(present), env={}, probe=False, platform="nt")
    assert found.found  # presence is a fact
    assert found.state == NOT_APPLICABLE  # usability is the verdict
    assert "not needed on this platform" in (found.reason or "")


def test_a_tool_that_is_needed_elsewhere_is_missing_here() -> None:
    spec = next(spec for spec in TOOL_SPECS if spec.name == "wine")
    status = find_tool(spec, None, env={}, platform="posix")
    assert status.state == MISSING


def test_a_tool_whose_runtime_is_absent_is_blocked(monkeypatch) -> None:
    # REA is a Node package: without Node there is nothing to run.  PATH is
    # patched so the answer does not depend on what this machine happens to have.
    monkeypatch.setattr("seto.toolchain.shutil.which", lambda name: None)
    settings = Settings(data={"tools": {"rea": {"path": PYTHON}}})
    statuses = detect_all(settings, env={}, platform="nt")
    rea = next(status for status in statuses if status.name == "rea")
    assert rea.found  # it is installed...
    assert rea.state == BLOCKED  # ...but it cannot run
    assert "node" in (rea.reason or "")


def test_ghidra_without_a_jdk_is_blocked(monkeypatch, tmp_path) -> None:
    home = tmp_path / "ghidra"
    (home / "support").mkdir(parents=True)
    (home / "support" / "analyzeHeadless.bat").write_text("", encoding="utf-8")
    monkeypatch.setattr("seto.toolchain.shutil.which", lambda name: None)
    settings = Settings(data={"tools": {"ghidra": {"path": str(home)}}})
    statuses = detect_all(settings, env={}, platform="nt")
    ghidra = next(status for status in statuses if status.name == "ghidra")
    assert ghidra.found
    assert ghidra.state == BLOCKED
    assert "java" in (ghidra.reason or "")


def test_a_configured_windows_compiler_is_blocked_on_posix_without_a_loader(
    monkeypatch,
) -> None:
    monkeypatch.setattr("seto.toolchain.shutil.which", lambda name: None)
    settings = Settings(data={"tools": {"mwccpsp": {"path": PYTHON}}})
    statuses = detect_all(settings, env={}, platform="posix")
    compiler = next(status for status in statuses if status.name == "mwccpsp")
    assert compiler.found
    assert compiler.state == BLOCKED
    assert "wibo preferred, or wine" in (compiler.reason or "")


def test_the_powerpc_compiler_is_not_accepted_as_the_psp_one() -> None:
    spec = next(spec for spec in TOOL_SPECS if spec.name == "mwccpsp")
    # ``mwcceppc`` builds PowerPC objects and can never match a MIPS module.
    assert "mwcceppc" not in spec.names
    assert spec.names == ("mwccpsp", "mwccpsp.exe")


def test_the_summary_keeps_the_legacy_state_and_adds_the_capability() -> None:
    status = ToolStatus(
        "m2c",
        "decompiler",
        True,
        path="C:/m2c",
        state=READY,
        capabilities=(Capability("decompile", READY, "produced C"),),
    )
    summary = status.summary()
    assert summary["state"] == "available"
    assert summary["capability"] == READY
    assert summary["capabilities"] == [
        {"name": "decompile", "state": READY, "detail": "produced C"}
    ]


def test_find_tool_uses_the_environment_variable(tmp_path) -> None:
    fake = tmp_path / "node"
    fake.write_bytes(b"")
    status = find_tool(_node_spec(), None, env={"SETO_NODE": str(fake)}, probe=False)
    assert status.found
    assert status.path == str(fake)


def test_find_tool_resolves_a_directory(tmp_path) -> None:
    binary = tmp_path / "node"
    binary.write_bytes(b"")
    status = find_tool(_node_spec(), str(tmp_path), env={}, probe=False)
    assert status.found
    assert status.path == str(binary)


def test_find_tool_probes_the_version() -> None:
    status = find_tool(_node_spec(), PYTHON, env={}, probe=True)
    assert status.found
    assert status.version is not None
    assert status.version.startswith("Python")


def test_find_tool_reports_missing_when_nothing_matches() -> None:
    spec = next(spec for spec in TOOL_SPECS if spec.name == "mwccpsp")
    status = find_tool(spec, None, env={})
    # mwccpsp is proprietary and never part of this environment.
    assert not status.found
    assert "looked for" in (status.reason or "")


# ---------------------------------------------------------------------- ghidra


def test_find_ghidra_requires_configuration() -> None:
    status = find_ghidra(None, env={})
    assert not status.found
    assert "not configured" in (status.reason or "")


def test_find_ghidra_uses_an_environment_variable(tmp_path) -> None:
    home = tmp_path / "ghidra"
    (home / "support").mkdir(parents=True)
    (home / "support" / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
    properties = home / "Ghidra" / "application.properties"
    properties.parent.mkdir()
    properties.write_text("application.version=11.0.1\n", encoding="utf-8")

    status = find_ghidra(None, env={"GHIDRA_HOME": str(home)})
    assert status.found
    assert status.version == "11.0.1"
    assert status.path is not None and status.path.endswith("analyzeHeadless")
    assert ghidra_version(home) == "11.0.1"


def test_find_ghidra_reports_a_missing_home(tmp_path) -> None:
    status = find_ghidra(str(tmp_path / "absent"), env={})
    assert not status.found
    assert "does not exist" in (status.reason or "")


def test_find_ghidra_reports_a_missing_launcher(tmp_path) -> None:
    home = tmp_path / "ghidra"
    home.mkdir()
    status = find_ghidra(str(home), env={})
    assert not status.found
    assert "no analyzeHeadless" in (status.reason or "")


def test_ghidra_env_var_order_is_documented() -> None:
    assert GHIDRA_ENV_VARS[0] == "SETO_GHIDRA_HOME"


# ------------------------------------------------------------------- detect_all


def test_detect_all_covers_every_known_tool() -> None:
    statuses = detect_all(Settings(data={}), env={})
    names = [status.name for status in statuses]
    expected = [spec.name for spec in TOOL_SPECS] + ["ghidra"]
    assert names == expected


# ------------------------------------------------------------------- argv build


def test_mwcc_argv_layout() -> None:
    argv = mwcc_argv(
        "mwccpsp.exe",
        "src/f.c",
        "build/f.o",
        flags=["-O4,p", "-sdatathreshold", "0"],
        includes=["include"],
        defines=["VERSION=1"],
        loader=["wibo"],
    )
    assert argv == (
        "wibo",
        "mwccpsp.exe",
        "-c",
        "src/f.c",
        "-o",
        "build/f.o",
        "-O4,p",
        "-sdatathreshold",
        "0",
        "-Iinclude",
        "-DVERSION=1",
    )


def test_ghidra_headless_argv_layout() -> None:
    argv = ghidra_headless_argv(
        "analyzeHeadless",
        "build/ghidra",
        "seto",
        "module.prx",
        scripts=["Export.java"],
        script_path="tools/ghidra",
        delete_project=True,
        analysis_timeout=120,
    )
    assert argv == (
        "analyzeHeadless",
        "build/ghidra",
        "seto",
        "-import",
        "module.prx",
        "-scriptPath",
        "tools/ghidra",
        "-postScript",
        "Export.java",
        "-deleteProject",
        "-analysisTimeoutPerFile",
        "120",
    )


def test_ghidra_headless_argv_can_demand_a_processor() -> None:
    argv = ghidra_headless_argv(
        "analyzeHeadless", "build/ghidra", "seto", "smoke.o",
        processor="Allegrex:LE:32:default",
    )
    assert argv == (
        "analyzeHeadless",
        "build/ghidra",
        "seto",
        "-import",
        "smoke.o",
        "-processor",
        "Allegrex:LE:32:default",
    )


def test_m2c_argv_layout() -> None:
    assert m2c_argv("m2c", "f.s") == ("m2c", "f.s")
    assert m2c_argv("m2c", "f.s", target="mips-ido-c") == ("m2c", "-t", "mips-ido-c", "f.s")


def test_objdump_argv_layout() -> None:
    argv = objdump_argv("llvm-objdump", "smoke.o")
    assert argv == ("llvm-objdump", "-f", "-h", "-t", "-r", "-d", "smoke.o")
    assert objdump_argv("objdump", "smoke.o", options=("-f",)) == ("objdump", "-f", "smoke.o")


# ------------------------------------------------------------- local overlay


def test_a_local_overlay_is_merged_over_the_configuration(tmp_path) -> None:
    config = tmp_path / "seto.toml"
    config.write_text(
        '[baseline]\ndisc_id = "ULUS10136"\n[tools.m2c]\npath = ""\n', encoding="utf-8"
    )
    overlay = tmp_path / "seto.local.toml"
    overlay.write_text('[tools.m2c]\npath = "C:/m2c"\n', encoding="utf-8")

    settings = load_settings(config)
    # The overlay fills in the empty path and leaves everything else alone.
    assert settings.tool_path("m2c") == "C:/m2c"
    assert settings.get("baseline", "disc_id") == "ULUS10136"
    assert settings.path == config
    assert settings.overlay == overlay


def test_a_user_local_overlay_wins_over_bootstrap_paths(tmp_path) -> None:
    config = tmp_path / "seto.toml"
    config.write_text('[tools.m2c]\npath = ""\n', encoding="utf-8")
    generated = tmp_path / "seto.bootstrap.toml"
    generated.write_text('[tools.m2c]\npath = "C:/bootstrap/m2c"\n', encoding="utf-8")
    local = tmp_path / "seto.local.toml"
    local.write_text('[tools.m2c]\npath = "C:/local/m2c"\n', encoding="utf-8")

    settings = load_settings(config)

    assert settings.tool_path("m2c") == "C:/local/m2c"
    assert settings.overlay == local


def test_a_byte_order_mark_does_not_break_the_configuration(tmp_path) -> None:
    config = tmp_path / "seto.toml"
    config.write_text('[baseline]\ndisc_id = "X"\n', encoding="utf-8-sig")
    assert load_settings(config).get("baseline", "disc_id") == "X"


def test_without_an_overlay_nothing_is_merged(tmp_path) -> None:
    config = tmp_path / "seto.toml"
    config.write_text('[tools.m2c]\npath = ""\n', encoding="utf-8")
    settings = load_settings(config)
    assert settings.overlay is None
    assert settings.tool_path("m2c") is None
