"""Tests for the automated compile+compare script's command construction."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from seto.cli import EXIT_BLOCKED
from seto.toolchain import Settings

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "match_function.py"


@pytest.fixture(scope="module")
def script():
    spec = importlib.util.spec_from_file_location("seto_match_function", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_config_is_placed_before_the_subcommand(script, tmp_path) -> None:
    config = tmp_path / "seto.toml"
    argv = script.build_match_argv(
        python="python",
        prx=tmp_path / "m.prx",
        section=".text",
        function=0x244,
        candidate=tmp_path / "m.o",
        symbol="func_00000244",
        config=config,
    )
    assert argv[:5] == ["python", "-m", "seto", "--config", str(config)]
    assert argv[5] == "match"
    assert argv.index("--config") < argv.index("match")
    assert "--candidate-symbol" in argv
    assert argv[argv.index("--function") + 1] == "0x244"


def test_config_is_omitted_when_not_given(script, tmp_path) -> None:
    argv = script.build_match_argv(
        python="python",
        prx=tmp_path / "m.prx",
        section=".text",
        function=0x0,
        candidate=tmp_path / "m.o",
        symbol=None,
        config=None,
    )
    assert "--config" not in argv
    assert argv[3] == "match"
    assert "--candidate-symbol" not in argv


def test_json_flag_is_appended(script, tmp_path) -> None:
    argv = script.build_match_argv(
        python="python",
        prx=tmp_path / "m.prx",
        section=".text",
        function=0x0,
        candidate=tmp_path / "m.o",
        symbol="f",
        config=None,
        json_output=True,
    )
    assert argv[-1] == "--json"


def test_resolve_flags_prefers_explicit_flags(script) -> None:
    settings = Settings(data={"match": {"flags": ["-O4,p"]}})
    assert script.resolve_flags(["-O1"], settings) == ["-O1"]


def test_resolve_flags_falls_back_to_configuration(script) -> None:
    settings = Settings(data={"match": {"flags": ["-O4,p", "-sdatathreshold", "0"]}})
    assert script.resolve_flags([], settings) == ["-O4,p", "-sdatathreshold", "0"]


def test_resolve_flags_defaults_to_empty(script) -> None:
    assert script.resolve_flags([], Settings(data={})) == []


def test_resolve_includes_falls_back_to_configuration(script) -> None:
    settings = Settings(data={"match": {"includes": ["decomp/include", "include"]}})
    assert script.resolve_includes([], settings) == ["decomp/include", "include"]
    assert script.resolve_includes(["x"], settings) == ["x"]
    assert script.resolve_includes([], Settings(data={})) == ["decomp/include"]


def test_script_reports_blocked_without_a_compiler(script, tmp_path) -> None:
    code = script.main(
        [
            "--prx",
            str(tmp_path / "missing.prx"),
            "--function",
            "0x0",
            "--source",
            str(tmp_path / "missing.c"),
            "--compiler",
            str(tmp_path / "nope" / "mwccpsp.exe"),
        ]
    )
    assert code == EXIT_BLOCKED
