"""Focused tests for the allowlisted SSH file/inference transport."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import decomp_ssh as decomp_ssh_module  # noqa: E402
from decomp_ssh import RemoteTarget, SSHExecutionError, SSHExecutor, handle_request  # noqa: E402


def test_remote_target_requires_absolute_nontraversing_directory() -> None:
    assert RemoteTarget("Alluka", "/home/operator/seto-worker").directory == "/home/operator/seto-worker"
    with pytest.raises(ValueError):
        RemoteTarget("Alluka", "~/seto-worker")
    with pytest.raises(ValueError):
        RemoteTarget("Alluka", "/home/operator/../other")


def test_ssh_request_uses_verified_noninteractive_transport_and_json_stdin(tmp_path: Path) -> None:
    observed: dict[str, object] = {}

    def fake_process(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["argv"] = argv
        observed["payload"] = json.loads(str(kwargs["input"]))
        observed["shell"] = kwargs.get("shell", False)
        observed["json_stdin"] = isinstance(kwargs.get("input"), str)
        observed["stdin_argument"] = kwargs.get("stdin")
        return subprocess.CompletedProcess(argv, 0, '{"ok":true}', "")

    executor = SSHExecutor(process_runner=fake_process)
    response = executor.request(
        RemoteTarget("Alluka", "/home/operator/seto-worker"),
        {"op": "ping"},
        cwd=tmp_path,
        timeout=3,
    )

    argv = observed["argv"]
    assert isinstance(argv, list)
    assert "BatchMode=yes" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert "-T" in argv
    assert "-n" not in argv  # SSH stdin carries the JSON helper request.
    assert "Alluka" in argv
    assert observed["shell"] is False
    assert observed["json_stdin"] is True
    assert observed["stdin_argument"] is None
    assert observed["payload"] == {
        "op": "ping",
        "root": "/home/operator/seto-worker",
    }
    assert response == {"ok": True}


def test_remote_exec_child_does_not_inherit_ssh_json_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "remote"
    root.mkdir()
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    observed: list[object] = []

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        observed.append(kwargs.get("stdin"))
        return subprocess.CompletedProcess(argv, 0, b"help", b"")

    monkeypatch.setattr(decomp_ssh_module.subprocess, "run", fake_run)
    response = handle_request(
        {
            "op": "exec",
            "root": str(root),
            "argv": ["opencode", "run", "--help"],
            "cwd": ".",
            "timeout": 5,
        }
    )

    assert response["returncode"] == 0
    assert observed == [subprocess.DEVNULL]
    assert decomp_ssh_module.REMOTE_HELPER.count("stdin=subprocess.DEVNULL") == 2


def test_remote_file_operations_hash_and_reject_escape_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "remote"
    root.mkdir()
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    request = {
        "op": "put",
        "root": str(root),
        "path": "build/decomp-campaign/luna/2c28c/evidence.txt",
        "sha256": hashlib.sha256(b"verified evidence").hexdigest(),
        "content": base64.b64encode(b"verified evidence").decode("ascii"),
        "mode": 0o444,
    }

    response = handle_request(request)
    assert response["sha256"] == request["sha256"]
    assert (root / request["path"]).read_bytes() == b"verified evidence"
    with pytest.raises(ValueError):
        handle_request({**request, "path": "../../private/decrypted/EBOOT.elf"})
    with pytest.raises(ValueError):
        handle_request({**request, "path": "private/credentials.env"})


def test_collect_file_verifies_hash_and_atomically_replaces_only_after_success(
    tmp_path: Path,
) -> None:
    target = RemoteTarget("Kita", "/home/operator/seto-worker")
    destination = tmp_path / "func_00002C28C.c"
    destination.write_bytes(b"previous source")
    content = b"int func_0002C28C(void) { return 1; }\n"
    response = {
        "content": base64.b64encode(content).decode("ascii"),
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
    }
    executor = SSHExecutor()
    executor.request = lambda *_args, **_kwargs: response  # type: ignore[method-assign]

    digest = executor.collect_file(
        target,
        "decomp/src/eboot/func_0002C28C.c",
        destination,
        cwd=tmp_path,
        expected_sha256=response["sha256"],
    )

    assert digest == response["sha256"]
    assert destination.read_bytes() == content
    assert not destination.with_name(destination.name + ".ssh-transfer.tmp").exists()

    destination.write_bytes(b"keep this source")
    with pytest.raises(SSHExecutionError, match="SHA-256"):
        executor.collect_file(
            target,
            "decomp/src/eboot/func_0002C28C.c",
            destination,
            cwd=tmp_path,
            expected_sha256="0" * 64,
        )
    assert destination.read_bytes() == b"keep this source"


def test_run_recovers_a_completed_remote_result_after_disconnect(tmp_path: Path) -> None:
    target = RemoteTarget("Alluka", "/home/operator/seto-worker")
    source = b"int func_00002C28C(void) { return 0; }\n"
    completed = {
        "completed": True,
        "address": "0x2c28c",
        "attempt_number": 3,
        "session_id": "ses_remote123",
        "returncode": 0,
        "stdout": '{"checkpoint":{"next_experiment":"check one branch"}}',
        "stderr": "",
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "source": base64.b64encode(source).decode("ascii"),
    }
    calls: list[str] = []

    def fake_request(_target: RemoteTarget, payload: dict[str, object], **_kwargs: object) -> dict[str, object]:
        calls.append(str(payload["op"]))
        if payload["op"] == "run":
            raise SSHExecutionError("connection lost", result_unknown=True)
        if payload["op"] == "get-result":
            return completed
        raise AssertionError(payload)

    executor = SSHExecutor()
    executor.request = fake_request  # type: ignore[method-assign]
    result = executor.run(
        target,
        address="0x2c28c",
        attempt_number=3,
        model="opencode/deepseek-v4.1-flash-free",
        agent="seto-decomp-worker",
        session_id="ses_remote123",
        prompt="reconstruct the function",
        timeout=15,
        cwd=tmp_path,
    )

    assert result["stdout"] == completed["stdout"]
    assert calls == ["run", "get-result"]


def test_unknown_remote_result_is_not_retried(tmp_path: Path) -> None:
    calls: list[str] = []

    def fake_request(_target: RemoteTarget, payload: dict[str, object], **_kwargs: object) -> dict[str, object]:
        calls.append(str(payload["op"]))
        if payload["op"] == "run":
            raise SSHExecutionError("connection lost", result_unknown=True)
        return {"completed": False}

    executor = SSHExecutor()
    executor.request = fake_request  # type: ignore[method-assign]
    with pytest.raises(SSHExecutionError, match="result is unknown"):
        executor.run(
            RemoteTarget("Kita", "/home/operator/seto-worker"),
            address="0x2c28c",
            attempt_number=3,
            model="opencode/deepseek-v4.1-flash-free",
            agent="seto-decomp-worker",
            session_id="ses_remote123",
            prompt="reconstruct the function",
            timeout=15,
            cwd=tmp_path,
        )

    assert calls == ["run", "get-result"]


def test_remote_helper_runs_one_opencode_attempt_and_caches_its_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "remote"
    root.mkdir()
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    source = b"int func_0002C28C(void) { return 9; }\n"
    calls = 0
    observed_stdin: list[object] = []
    observed_argv: list[list[str]] = []
    observed_cwd: list[object] = []

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        nonlocal calls
        calls += 1
        observed_stdin.append(_kwargs.get("stdin"))
        observed_argv.append(argv)
        observed_cwd.append(_kwargs.get("cwd"))
        candidate = root / "decomp/src/eboot/func_0002C28C.c"
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_bytes(source)
        return subprocess.CompletedProcess(argv, 0, b'{"checkpoint":{}}', b"")

    monkeypatch.setattr(decomp_ssh_module.subprocess, "run", fake_run)
    request = {
        "op": "run",
        "root": str(root),
        "opencode": "opencode",
        "address": "0x2c28c",
        "attempt_number": 4,
        "model": "opencode/deepseek-v4.1-flash-free",
        "agent": "seto-decomp-worker",
        "session_id": "ses_kita123",
        "prompt": "reconstruct only this function",
        "timeout": 30,
        "result_path": ".seto/results/2c28c-4.json",
    }

    first = handle_request(request)
    second = handle_request(request)

    assert calls == 1
    assert observed_stdin == [subprocess.DEVNULL]
    assert observed_cwd == [root]
    assert observed_argv[0][observed_argv[0].index("--session") + 1] == "ses_kita123"
    assert observed_argv[0][observed_argv[0].index("--agent") + 1] == "seto-decomp-worker"
    assert observed_argv[0][observed_argv[0].index("--model") + 1] == "opencode/deepseek-v4.1-flash-free"
    assert first == second
    assert first["completed"] is True
    assert first["source_sha256"] == hashlib.sha256(source).hexdigest()
    assert json.loads(first["stdout"]) == {"checkpoint": {}}
