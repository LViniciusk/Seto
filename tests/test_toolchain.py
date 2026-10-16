"""Tests for tool discovery and bounded, shell-free process execution."""

from __future__ import annotations

import sys

import pytest

from seto.toolchain import (
    GHIDRA_ENV_VARS,
    TOOL_SPECS,
    Settings,
    detect_all,
    find_ghidra,
    find_tool,
    ghidra_headless_argv,
    ghidra_version,
    load_settings,
    mwcc_argv,
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
    assert status.state == "available"
    assert "MISSING" not in status.line()


def test_find_tool_reports_a_broken_configured_path() -> None:
    status = find_tool(_node_spec(), "C:/nope/nope.exe", env={}, probe=False)
    assert not status.found
    assert "does not exist" in (status.reason or "")
    assert "MISSING" in status.line()


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
