"""Tests for the automated compile+compare script.

Nothing here depends on CodeWarrior: the compiler and the comparator are replaced
by fakes that record what they were asked to do.  The point of these tests is that
a *simulated* compilation can never be reported as a real matching result - the
provenance record has to reflect what actually ran.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from seto.cli import EXIT_BLOCKED, EXIT_ERROR
from seto.hashing import sha256_file
from seto.toolchain import RunResult, Settings, ToolStatus

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "match_function.py"

MATCHED_JSON = json.dumps({"status": "MATCHED", "evidence": "binary-range"})


@pytest.fixture(scope="module")
def script():
    spec = importlib.util.spec_from_file_location("seto_match_function", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before executing so dataclasses in the script can resolve their
    # own module (see importlib docs).
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def compiler(script, monkeypatch):
    """Fake a native Windows compiler; loader cases are tested independently."""
    monkeypatch.setattr(
        script,
        "find_tool",
        lambda spec, configured: ToolStatus(
            name="mwccpsp", kind="compiler", found=True, path=configured or "mwccpsp.exe"
        ),
    )
    monkeypatch.setattr(script, "resolve_loaders", lambda _requested, _settings: ())


def _arguments(tmp_path: Path, *extra: str) -> list[str]:
    source = tmp_path / "func_00000244.c"
    source.write_text("void func_00000244(void) {}\n", encoding="utf-8")
    prx = tmp_path / "module.prx"
    prx.write_bytes(b"\x7fELF" + b"\x00" * 12)
    return [
        "--prx", str(prx),
        "--function", "0x244",
        "--source", str(source),
        "--compiler", str(tmp_path / "mwccpsp.exe"),
        "--out", str(tmp_path / "out"),
        *extra,
    ]


class FakeRunner:
    """Stand-in for ``toolchain.run`` that fakes a compile and/or a comparison."""

    def __init__(
        self,
        *,
        compile_ok: bool = True,
        write_object: bool = True,
        object_bytes: bytes = b"ELFBODY",
        match_stdout: str = MATCHED_JSON,
        match_returncode: int = 0,
    ) -> None:
        self.compile_ok = compile_ok
        self.write_object = write_object
        self.object_bytes = object_bytes
        self.match_stdout = match_stdout
        self.match_returncode = match_returncode
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv, **_kwargs) -> RunResult:
        argv = tuple(str(item) for item in argv)
        self.calls.append(argv)
        if "match" in argv:
            return RunResult(
                argv, self.match_returncode, self.match_stdout, "", timed_out=False, truncated=False
            )
        if self.write_object:
            Path(argv[argv.index("-o") + 1]).write_bytes(self.object_bytes)
        return RunResult(
            argv,
            0 if self.compile_ok else 1,
            "" if self.compile_ok else "mwcc: error",
            "",
            timed_out=False,
            truncated=False,
        )


# --------------------------------------------------------------- command building


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
    assert argv[-1] == "--json"


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
    assert "--data-map" not in argv
    assert "--candidate-section" not in argv


def test_an_explicit_function_size_is_forwarded(script, tmp_path) -> None:
    argv = script.build_match_argv(
        python="python",
        prx=tmp_path / "m.prx",
        section=".text",
        function=0x1C18,
        candidate=tmp_path / "m.o",
        symbol="func_00001C18",
        config=None,
        size=8,
    )
    assert argv[argv.index("--size") + 1] == "8"
    assert argv[-1] == "--json"


def test_candidate_section_is_forwarded_independently_of_original_section(
    script, tmp_path
) -> None:
    argv = script.build_match_argv(
        python="python",
        prx=tmp_path / "m.prx",
        section=".sceStub.text",
        function=0x3668,
        candidate=tmp_path / "m.o",
        symbol="func_00003668",
        config=None,
        candidate_section=".text",
    )

    assert argv[argv.index("--section") + 1] == ".sceStub.text"
    assert argv[argv.index("--candidate-section") + 1] == ".text"


def test_a_data_map_is_forwarded_to_seto_match(script, tmp_path) -> None:
    data_map = tmp_path / "data-map.json"
    argv = script.build_match_argv(
        python="python",
        prx=tmp_path / "m.prx",
        section=".text",
        function=0x0,
        candidate=tmp_path / "m.o",
        symbol=None,
        config=None,
        data_map=data_map,
    )
    assert argv[argv.index("--data-map") + 1] == str(data_map)
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


def test_resolve_loaders_uses_wsl_configuration_and_preserves_spaces(
    script, tmp_path, monkeypatch
) -> None:
    loader = tmp_path / "a path" / "wibo"
    loader.parent.mkdir()
    loader.write_text("loader fixture", encoding="utf-8")
    settings = Settings(data={"tools": {"wibo": {"path": str(loader)}}})
    monkeypatch.setattr(
        script.shutil,
        "which",
        lambda name: "/usr/bin/wibo" if name == "wibo" else None,
    )
    assert script.resolve_loaders([], settings, platform="posix") == (str(loader),)
    assert script.resolve_loaders(["wibo"], settings, platform="posix") == (str(loader),)
    assert script.resolve_loaders([], settings, platform="nt") == ()

    explicit = tmp_path / "explicit" / "wibo"
    explicit.parent.mkdir()
    explicit.write_text("explicit loader", encoding="utf-8")
    assert script.resolve_loaders([str(explicit)], settings, platform="posix") == (
        str(explicit),
    )


def test_resolve_loaders_reports_a_missing_explicit_loader(script, monkeypatch) -> None:
    monkeypatch.setattr(script.shutil, "which", lambda _name: None)
    assert script.resolve_loaders(["missing-wibo"], Settings(data={}), platform="posix") is None


# ---------------------------------------------------------------------- blocked


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


def test_blocked_run_writes_no_record(script, tmp_path, capsys) -> None:
    script.main(_arguments(tmp_path))
    assert "BLOCKED" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_script_is_blocked_on_posix_when_no_win32_loader_is_available(
    script, compiler, monkeypatch, tmp_path, capsys
) -> None:
    monkeypatch.setattr(script, "resolve_loaders", lambda _requested, _settings: None)
    runner = FakeRunner()
    monkeypatch.setattr(script, "run", runner)
    assert script.main(_arguments(tmp_path)) == EXIT_BLOCKED
    assert runner.calls == []
    assert "no usable Win32 loader" in capsys.readouterr().err


# ------------------------------------------------------------------- provenance


def test_successful_compile_records_provenance_and_verifies_the_match(
    script, compiler, monkeypatch, tmp_path, capsys
) -> None:
    runner = FakeRunner()
    monkeypatch.setattr(script, "run", runner)
    out = tmp_path / "out"
    # An isolated config keeps the assertion about flags deterministic.
    config = tmp_path / "seto.toml"
    config.write_text("[match]\nflags = []\nincludes = []\n", encoding="utf-8")
    assert script.main(_arguments(tmp_path, "--config", str(config))) == 0

    record = json.loads((out / "func_00000244.match.json").read_text(encoding="utf-8"))
    assert record["status"] == "MATCHED"
    assert record["evidence"] == "compiled-object"
    assert record["verified_decompilation"] is True
    assert record["function"] == "func_00000244"
    assert record["symbol"] == "func_00000244"
    assert record["address"] == "0x244"
    assert record["exit_code"] == 0

    provenance = record["provenance"]
    assert provenance["source_sha256"] == sha256_file(tmp_path / "func_00000244.c")
    assert provenance["object_sha256"] == sha256_file(out / "func_00000244.o")
    assert provenance["compiler"].endswith("mwccpsp.exe")
    assert provenance["flags"] == []

    # The compile ran first, then the comparison, against the object it produced.
    compile_argv, match_argv = runner.calls
    assert compile_argv[compile_argv.index("-o") + 1] == str(out / "func_00000244.o")
    assert match_argv[match_argv.index("--candidate") + 1] == str(out / "func_00000244.o")
    assert "verified decompilation: yes" in capsys.readouterr().out


def test_configuration_flags_are_recorded_and_used(script, compiler, monkeypatch, tmp_path) -> None:
    config = tmp_path / "seto.toml"
    config.write_text(
        '[match]\nflags = ["-O4,p", "-sdatathreshold", "0"]\nincludes = ["decomp/include"]\n',
        encoding="utf-8",
    )
    runner = FakeRunner()
    monkeypatch.setattr(script, "run", runner)
    out = tmp_path / "out"
    assert script.main(_arguments(tmp_path, "--config", str(config))) == 0

    record = json.loads((out / "func_00000244.match.json").read_text(encoding="utf-8"))
    assert record["provenance"]["flags"] == ["-O4,p", "-sdatathreshold", "0"]
    assert record["provenance"]["includes"] == ["decomp/include"]
    assert "-O4,p" in runner.calls[0]


def test_json_output_carries_the_record_and_the_match_payload(
    script, compiler, monkeypatch, tmp_path, capsys
) -> None:
    monkeypatch.setattr(script, "run", FakeRunner())
    assert script.main(_arguments(tmp_path, "--json")) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verified_decompilation"] is True
    assert payload["match"]["status"] == "MATCHED"


# ---------------------------------------------------------------------- failures


def test_failed_compilation_is_an_error_and_writes_no_record(
    script, compiler, monkeypatch, tmp_path, capsys
) -> None:
    monkeypatch.setattr(script, "run", FakeRunner(compile_ok=False))
    out = tmp_path / "out"
    assert script.main(_arguments(tmp_path)) == EXIT_ERROR
    assert "compilation failed" in capsys.readouterr().err
    assert not (out / "func_00000244.match.json").is_file()


def test_compiler_that_produces_no_object_is_an_error(
    script, compiler, monkeypatch, tmp_path, capsys
) -> None:
    monkeypatch.setattr(script, "run", FakeRunner(write_object=False))
    assert script.main(_arguments(tmp_path)) == EXIT_ERROR
    assert "produced no object" in capsys.readouterr().err


def test_a_stale_object_cannot_be_reused_as_a_new_result(
    script, compiler, monkeypatch, tmp_path, capsys
) -> None:
    out = tmp_path / "out"
    out.mkdir(parents=True)
    (out / "func_00000244.o").write_bytes(b"STALE")

    # The fake compiler writes nothing, so the only way to "succeed" would be to
    # pick up the stale artefact - which must not happen.
    monkeypatch.setattr(script, "run", FakeRunner(write_object=False))
    assert script.main(_arguments(tmp_path)) == EXIT_ERROR
    assert "produced no object" in capsys.readouterr().err
    assert not (out / "func_00000244.match.json").is_file()


def test_missing_source_is_an_error(script, compiler, tmp_path, capsys) -> None:
    code = script.main(
        [
            "--prx", str(tmp_path / "missing.prx"),
            "--function", "0x0",
            "--source", str(tmp_path / "missing.c"),
        ]
    )
    assert code == EXIT_ERROR
    assert "source not found" in capsys.readouterr().err


def test_missing_module_is_an_error(script, compiler, tmp_path, capsys) -> None:
    source = tmp_path / "f.c"
    source.write_text("int f(void) { return 0; }\n", encoding="utf-8")
    code = script.main(
        ["--prx", str(tmp_path / "missing.prx"), "--function", "0x0", "--source", str(source)]
    )
    assert code == EXIT_ERROR
    assert "module not found" in capsys.readouterr().err


def test_inconclusive_comparison_is_not_a_verified_decompilation(
    script, compiler, monkeypatch, tmp_path, capsys
) -> None:
    runner = FakeRunner(
        match_stdout=json.dumps({"status": "INCONCLUSIVE", "limitations": ["x"]}),
        match_returncode=5,
    )
    monkeypatch.setattr(script, "run", runner)
    out = tmp_path / "out"
    assert script.main(_arguments(tmp_path)) == 5
    record = json.loads((out / "func_00000244.match.json").read_text(encoding="utf-8"))
    assert record["status"] == "INCONCLUSIVE"
    assert record["verified_decompilation"] is False
    assert "verified decompilation: no" in capsys.readouterr().out


def test_comparator_failure_is_propagated(script, compiler, monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setattr(script, "run", FakeRunner(match_stdout="", match_returncode=EXIT_ERROR))
    out = tmp_path / "out"
    assert script.main(_arguments(tmp_path)) == EXIT_ERROR
    assert not (out / "func_00000244.match.json").is_file()


def test_an_inconsistent_comparator_verdict_is_an_error(
    script, compiler, monkeypatch, tmp_path, capsys
) -> None:
    # MATCHED must come with exit code 0: a contradictory pair is never trusted.
    monkeypatch.setattr(script, "run", FakeRunner(match_returncode=3))
    assert script.main(_arguments(tmp_path)) == EXIT_ERROR
    assert "exit code 3" in capsys.readouterr().err
    assert not (tmp_path / "out" / "func_00000244.match.json").is_file()


def test_an_unknown_comparator_status_is_an_error(
    script, compiler, monkeypatch, tmp_path, capsys
) -> None:
    monkeypatch.setattr(
        script, "run", FakeRunner(match_stdout=json.dumps({"status": "TOTALLY_OK"}))
    )
    assert script.main(_arguments(tmp_path)) == EXIT_ERROR
    assert "unknown status" in capsys.readouterr().err


def test_object_changing_during_the_comparison_is_an_error(
    script, compiler, monkeypatch, tmp_path, capsys
) -> None:
    object_path = tmp_path / "out" / "func_00000244.o"

    class MutatingRunner(FakeRunner):
        def __call__(self, argv, **kwargs):
            result = super().__call__(argv, **kwargs)
            if "match" in tuple(str(item) for item in argv):
                object_path.write_bytes(b"CHANGED")
            return result

    monkeypatch.setattr(script, "run", MutatingRunner())
    assert script.main(_arguments(tmp_path)) == EXIT_ERROR
    assert "changed during the comparison" in capsys.readouterr().err
    assert not (tmp_path / "out" / "func_00000244.match.json").is_file()
