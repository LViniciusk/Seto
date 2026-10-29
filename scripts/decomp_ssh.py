"""Small, non-interactive SSH transport for isolated OpenCode workers.

The remote side is a bounded stdlib helper sent over SSH stdin. It accepts
JSON data only; command arguments and file contents are never interpolated in
the remote shell command.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
import re
import shlex
import subprocess
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence


MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_REQUEST_BYTES = 20 * 1024 * 1024
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_PROMPT_BYTES = 4 * 1024 * 1024
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{1,8}$")
SESSION_RE = re.compile(r"^ses_[A-Za-z0-9_-]+$")
WORKER_RE = re.compile(r"^[a-z0-9-]{1,64}$")
MODEL_RE = re.compile(r"^[a-z0-9-]+/[A-Za-z0-9._-]+$")


@dataclass(frozen=True)
class RemoteTarget:
    host: str
    directory: str
    python: str = "python3"
    opencode: str = "opencode"

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", self.host):
            raise ValueError("SSH host must be a configured host alias")
        root = PurePosixPath(self.directory)
        if (
            not root.is_absolute()
            or ".." in root.parts
            or "~" in root.parts
            or len(str(root)) > 512
        ):
            raise ValueError("remote worker directory must be an absolute, non-traversing path")
        for name, command in (("python", self.python), ("OpenCode", self.opencode)):
            if (
                not isinstance(command, str)
                or not command
                or len(command) > 512
                or "\x00" in command
                or "\n" in command
                or not re.fullmatch(r"[A-Za-z0-9_./-]+", command)
            ):
                raise ValueError(f"remote {name} executable is invalid")

    def for_candidate(self, address: str) -> RemoteTarget:
        if not ADDRESS_RE.fullmatch(address):
            raise ValueError("remote task address is invalid")
        directory = str(PurePosixPath(self.directory) / "functions" / address[2:].lower())
        return RemoteTarget(self.host, directory, self.python, self.opencode)


class SSHExecutionError(RuntimeError):
    """Transport failure; result_unknown means inference may have completed remotely."""

    def __init__(self, message: str, *, result_unknown: bool = False):
        super().__init__(message)
        self.result_unknown = result_unknown


def _safe_remote_root(value: Any, *, create: bool) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("remote workspace root is invalid")
    root = Path(value)
    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("remote workspace root must be absolute and non-traversing")
    home = Path.home().resolve(strict=True)
    current = home
    try:
        relative = root.relative_to(Path.home())
    except ValueError:
        try:
            relative = root.resolve(strict=False).relative_to(home)
        except ValueError as exc:
            raise ValueError("remote workspace must remain below the SSH account home") from exc
    for part in relative.parts:
        if part in {"", ".", ".."}:
            raise ValueError("remote workspace path contains an unsafe component")
        current = current / part
        if current.is_symlink():
            raise ValueError("remote workspace path may not contain symlinks")
    if create:
        current.mkdir(parents=True, exist_ok=True)
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(home)
    except ValueError as exc:
        raise ValueError("remote workspace escaped the SSH account home") from exc
    if not resolved.is_dir():
        raise ValueError("remote workspace is not a directory")
    return resolved


def _safe_relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ValueError("remote file path is invalid")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("remote file path must be relative and non-traversing")
    if any(
        part == ".git"
        or part == "private"
        or part == ".env"
        or part.startswith(".env.")
        or part.lower().endswith((".iso", ".elf", ".prx", ".sqlite", ".sqlite3", ".db"))
        for part in relative.parts
    ):
        raise ValueError("remote file path is outside the allowed worker context")
    allowed = (
        relative.as_posix() == ".opencode/agents/seto-decomp-worker.md"
        or relative.as_posix() == ".opencode/opencode.json"
        or relative.as_posix() == "build/seto035/export-triage.json"
        or re.fullmatch(r"decomp/src/eboot/func_[0-9A-F]{8}\.c", relative.as_posix())
        or relative.as_posix().startswith("build/decomp-campaign/")
        or relative.as_posix().startswith("seto038/")
    )
    if not allowed:
        raise ValueError("remote file path is not an allowlisted worker-context path")
    return relative


def _safe_internal_relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ValueError("remote internal path is invalid")
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError("remote internal path must be relative and non-traversing")
    if relative.parts[0] != ".seto":
        raise ValueError("remote internal path is outside the transport state directory")
    return relative


def _safe_path(root: Path, relative: PurePosixPath, *, internal: bool = False) -> Path:
    candidate = root.joinpath(*relative.parts)
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("remote workspace paths may not contain symlinks")
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("remote path escaped the configured worker workspace") from exc
    if not internal:
        _safe_relative(relative.as_posix())
    return candidate


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    if mode not in {0o444, 0o600, 0o644}:
        raise ValueError("remote file mode is not allowed")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("remote file target is unsafe")
    fd, temporary_name = tempfile.mkstemp(prefix=".seto-transfer-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _bounded(value: bytes, maximum: int = MAX_OUTPUT_BYTES) -> tuple[str, bool]:
    truncated = len(value) > maximum
    return value[:maximum].decode("utf-8", errors="replace"), truncated


def handle_request(request: Mapping[str, Any]) -> dict[str, Any]:
    """Handle one stdlib-helper request; exported for isolated local tests."""
    if not isinstance(request, Mapping):
        raise ValueError("remote request must be a JSON object")
    operation = request.get("op")
    root = _safe_remote_root(
        request.get("root"),
        create=(
            operation in {"put", "run"}
            or (operation == "ping" and request.get("create_workspace") is True)
        ),
    )
    if operation == "ping":
        return {
            "ok": True,
            "python": list(__import__("sys").version_info[:3]),
            "architecture": __import__("platform").machine(),
            "workspace_writable": os.access(root, os.W_OK),
            "workspace": str(root),
        }
    if operation == "put":
        relative = _safe_relative(request.get("path"))
        encoded = request.get("content")
        digest = request.get("sha256")
        if not isinstance(encoded, str) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("remote file transfer metadata is invalid")
        content = base64.b64decode(encoded, validate=True)
        if len(content) > MAX_FILE_BYTES or hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("remote file transfer size or SHA-256 is invalid")
        target = _safe_path(root, relative)
        mode = request.get("mode", 0o444)
        if isinstance(mode, bool) or mode not in {0o444, 0o644}:
            raise ValueError("remote file mode is not allowed")
        unchanged = (
            target.is_file()
            and not target.is_symlink()
            and hashlib.sha256(target.read_bytes()).hexdigest() == digest
        )
        if not unchanged:
            _atomic_write(target, content, int(mode))
        else:
            os.chmod(target, int(mode))
        return {"sha256": digest, "size": len(content), "unchanged": unchanged}
    if operation == "get":
        relative = _safe_relative(request.get("path"))
        target = _safe_path(root, relative)
        maximum = request.get("max_bytes", MAX_FILE_BYTES)
        if isinstance(maximum, bool) or not isinstance(maximum, int) or not 0 < maximum <= MAX_FILE_BYTES:
            raise ValueError("remote read limit is invalid")
        if target.is_symlink() or not target.is_file() or target.stat().st_size > maximum:
            raise ValueError("remote file is missing, unsafe, or too large")
        content = target.read_bytes()
        return {
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
            "content": base64.b64encode(content).decode("ascii"),
        }
    if operation == "get-result":
        relative = _safe_internal_relative(request.get("path"))
        target = _safe_path(root, relative, internal=True)
        if target.is_symlink() or not target.is_file() or target.stat().st_size > MAX_RESPONSE_BYTES:
            return {"completed": False}
        try:
            result = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"completed": False}
        return result if isinstance(result, dict) else {"completed": False}
    if operation == "exec":
        argv = request.get("argv")
        if (
            not isinstance(argv, list)
            or not argv
            or len(argv) > 64
            or any(not isinstance(item, str) or not item or "\x00" in item for item in argv)
        ):
            raise ValueError("remote command argument vector is invalid")
        cwd_value = request.get("cwd", ".")
        if cwd_value == ".":
            cwd = root
        else:
            cwd = _safe_path(root, _safe_relative(cwd_value))
        timeout = request.get("timeout", 60)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 21600:
            raise ValueError("remote command timeout is invalid")
        try:
            result = subprocess.run(
                argv,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=float(timeout),
                check=False,
                shell=False,
            )
            stdout, stdout_truncated = _bounded(result.stdout)
            stderr, stderr_truncated = _bounded(result.stderr)
            return {
                "returncode": result.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "truncated": stdout_truncated or stderr_truncated,
                "timed_out": False,
            }
        except subprocess.TimeoutExpired as exc:
            stdout, _ = _bounded(exc.stdout or b"")
            stderr, _ = _bounded(exc.stderr or b"")
            return {"returncode": -1, "stdout": stdout, "stderr": stderr, "truncated": False, "timed_out": True}
    if operation == "run":
        address = request.get("address")
        attempt_number = request.get("attempt_number")
        model = request.get("model")
        agent = request.get("agent")
        session_id = request.get("session_id")
        prompt = request.get("prompt")
        opencode = request.get("opencode")
        result_path = _safe_internal_relative(request.get("result_path"))
        if (
            not isinstance(address, str)
            or not ADDRESS_RE.fullmatch(address)
            or isinstance(attempt_number, bool)
            or not isinstance(attempt_number, int)
            or attempt_number <= 0
            or not isinstance(model, str)
            or not MODEL_RE.fullmatch(model)
            or not isinstance(agent, str)
            or not WORKER_RE.fullmatch(agent)
            or not isinstance(session_id, str)
            or not SESSION_RE.fullmatch(session_id)
            or not isinstance(prompt, str)
            or len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES
            or not isinstance(opencode, str)
            or not opencode
            or "\x00" in opencode
        ):
            raise ValueError("remote OpenCode inference request is invalid")
        result_file = _safe_path(root, result_path, internal=True)
        if result_file.exists() or result_file.is_symlink():
            if result_file.is_symlink() or not result_file.is_file():
                raise ValueError("remote inference result marker is unsafe")
            try:
                previous = json.loads(result_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError("remote inference result marker is invalid; refusing a duplicate run") from exc
            if (
                isinstance(previous, dict)
                and previous.get("completed") is True
                and previous.get("address") == address.lower()
                and previous.get("attempt_number") == attempt_number
                and previous.get("session_id") == session_id
            ):
                return previous
            raise ValueError("remote attempt already has an incomplete result marker; refusing a duplicate run")
        timeout = request.get("timeout", 900)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 21600:
            raise ValueError("remote inference timeout is invalid")
        argv = [
            opencode,
            "run",
            "--model",
            model,
            "--agent",
            agent,
            "--format",
            "json",
            "--session",
            session_id,
            "--title",
            f"Seto EBOOT {address.lower()} attempt-{attempt_number}",
            prompt,
        ]
        try:
            result = subprocess.run(
                argv,
                cwd=root,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=float(timeout),
                check=False,
                shell=False,
            )
            stdout, stdout_truncated = _bounded(result.stdout)
            stderr, stderr_truncated = _bounded(result.stderr)
            source = root / "decomp" / "src" / "eboot" / f"func_{int(address, 0):08X}.c"
            source_hash = (
                hashlib.sha256(source.read_bytes()).hexdigest()
                if source.is_file() and not source.is_symlink() and source.stat().st_size <= MAX_FILE_BYTES
                else None
            )
            record = {
                "completed": True,
                "address": address.lower(),
                "attempt_number": attempt_number,
                "session_id": session_id,
                "returncode": result.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "truncated": stdout_truncated or stderr_truncated,
                "timed_out": False,
                "source_sha256": source_hash,
            }
        except subprocess.TimeoutExpired as exc:
            stdout, _ = _bounded(exc.stdout or b"")
            stderr, _ = _bounded(exc.stderr or b"")
            record = {
                "completed": False,
                "address": address.lower(),
                "attempt_number": attempt_number,
                "session_id": session_id,
                "returncode": -1,
                "stdout": stdout,
                "stderr": stderr,
                "timed_out": True,
            }
        result_file.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(
            result_file,
            json.dumps(record, separators=(",", ":")).encode("utf-8"),
            0o600,
        )
        return record
    raise ValueError("unsupported remote helper operation")


def _helper_main() -> None:
    import sys

    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("remote request exceeds the transfer limit")
    request = json.loads(raw.decode("utf-8"))
    response = handle_request(request)
    encoded = json.dumps(response, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise ValueError("remote response exceeds the output limit")
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


REMOTE_HELPER = textwrap.dedent(
    """\
    from __future__ import annotations
    import base64, hashlib, json, os, platform, re, subprocess, sys, tempfile
    from pathlib import Path, PurePosixPath
    from typing import Any, Mapping
    MAX_FILE_BYTES = 8 * 1024 * 1024
    MAX_REQUEST_BYTES = 20 * 1024 * 1024
    MAX_RESPONSE_BYTES = 16 * 1024 * 1024
    MAX_OUTPUT_BYTES = 1024 * 1024
    MAX_PROMPT_BYTES = 4 * 1024 * 1024
    ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{1,8}$")
    SESSION_RE = re.compile(r"^ses_[A-Za-z0-9_-]+$")
    WORKER_RE = re.compile(r"^[a-z0-9-]{1,64}$")
    MODEL_RE = re.compile(r"^[a-z0-9-]+/[A-Za-z0-9._-]+$")
    """
) + "\n".join(
    inspect.getsource(function)
    for function in (
        _safe_remote_root,
        _safe_relative,
        _safe_internal_relative,
        _safe_path,
        _atomic_write,
        _bounded,
        handle_request,
        _helper_main,
    )
) + "\n_helper_main()\n"


class SSHExecutor:
    """SSH JSON transport with strict host-key checking and content hashes."""

    def __init__(
        self,
        *,
        ssh_command: str = "ssh",
        process_runner: Callable[..., Any] | None = None,
    ):
        if not ssh_command or "\x00" in ssh_command:
            raise ValueError("SSH executable is invalid")
        self.ssh_command = ssh_command
        self.process_runner = process_runner or subprocess.run

    def request(
        self,
        target: RemoteTarget,
        payload: Mapping[str, Any],
        *,
        cwd: Path,
        timeout: float,
        stop_requested: Callable[[], bool] | None = None,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        request = {"root": target.directory, **dict(payload)}
        encoded = json.dumps(request, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_REQUEST_BYTES:
            raise SSHExecutionError("SSH request exceeds the bounded transfer limit")
        encoded_helper = base64.b64encode(REMOTE_HELPER.encode("utf-8")).decode("ascii")
        helper_expression = f"exec(__import__('base64').b64decode('{encoded_helper}'))"
        argv = [
            self.ssh_command,
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "LogLevel=ERROR",
            target.host,
            f"{shlex.quote(target.python)} -c {shlex.quote(helper_expression)}",
        ]
        # The SSH process needs stdin for this JSON request. The remote helper
        # closes stdin only for its child commands (including `opencode run`).
        process_arguments: dict[str, Any] = {
            "cwd": cwd,
            "input": encoded,
            "capture_output": True,
            "text": True,
            "timeout": timeout,
            "check": False,
            "shell": False,
        }
        if self.process_runner is not subprocess.run:
            process_arguments["stop_requested"] = stop_requested or (lambda: False)
            process_arguments["deadline"] = deadline
        try:
            result = self.process_runner(argv, **process_arguments)
        except subprocess.TimeoutExpired as exc:
            raise SSHExecutionError("SSH command timed out", result_unknown=True) from exc
        except OSError as exc:
            raise SSHExecutionError("SSH command could not start") from exc
        if getattr(result, "timed_out", False):
            raise SSHExecutionError("SSH command timed out", result_unknown=True)
        if getattr(result, "interrupted", False):
            raise SSHExecutionError("SSH command was interrupted", result_unknown=True)
        if result.returncode != 0:
            # SSH stderr can contain usernames, paths, and server banners. Keep
            # the public diagnostic stable and avoid copying it into SQLite.
            raise SSHExecutionError("SSH transport or remote helper failed")
        try:
            response = json.loads(result.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            raise SSHExecutionError("remote helper returned invalid JSON", result_unknown=True) from exc
        if not isinstance(response, dict):
            raise SSHExecutionError("remote helper returned an invalid response", result_unknown=True)
        return response

    def command(
        self,
        target: RemoteTarget,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout: float,
        stop_requested: Callable[[], bool] | None = None,
        deadline: float | None = None,
        remote_cwd: str = ".",
    ) -> dict[str, Any]:
        return self.request(
            target,
            {"op": "exec", "argv": list(argv), "cwd": remote_cwd, "timeout": timeout},
            cwd=cwd,
            timeout=timeout + 20,
            stop_requested=stop_requested,
            deadline=deadline,
        )

    def put_file(
        self,
        target: RemoteTarget,
        relative_path: str,
        source: Path,
        *,
        cwd: Path,
        writable: bool = False,
        timeout: float = 60,
        stop_requested: Callable[[], bool] | None = None,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("local worker context file is missing, unsafe, or too large")
        content = source.read_bytes()
        return self.put_bytes(
            target,
            relative_path,
            content,
            cwd=cwd,
            writable=writable,
            timeout=timeout,
            stop_requested=stop_requested,
            deadline=deadline,
        )

    def put_bytes(
        self,
        target: RemoteTarget,
        relative_path: str,
        content: bytes,
        *,
        cwd: Path,
        writable: bool = False,
        timeout: float = 60,
        stop_requested: Callable[[], bool] | None = None,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        if not isinstance(content, bytes) or len(content) > MAX_FILE_BYTES:
            raise ValueError("local worker context file is too large")
        digest = hashlib.sha256(content).hexdigest()
        return self.request(
            target,
            {
                "op": "put",
                "path": relative_path,
                "sha256": digest,
                "content": base64.b64encode(content).decode("ascii"),
                "mode": 0o644 if writable else 0o444,
            },
            cwd=cwd,
            timeout=timeout,
            stop_requested=stop_requested,
            deadline=deadline,
        )

    def collect_file(
        self,
        target: RemoteTarget,
        relative_path: str,
        destination: Path,
        *,
        cwd: Path,
        expected_sha256: str | None = None,
        timeout: float = 60,
        stop_requested: Callable[[], bool] | None = None,
        deadline: float | None = None,
    ) -> str:
        response = self.request(
            target,
            {"op": "get", "path": relative_path, "max_bytes": MAX_FILE_BYTES},
            cwd=cwd,
            timeout=timeout,
            stop_requested=stop_requested,
            deadline=deadline,
        )
        try:
            content = base64.b64decode(response["content"], validate=True)
            digest = str(response["sha256"])
        except (KeyError, TypeError, ValueError) as exc:
            raise SSHExecutionError("remote file response is malformed") from exc
        if (
            len(content) > MAX_FILE_BYTES
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or hashlib.sha256(content).hexdigest() != digest
            or (expected_sha256 is not None and digest != expected_sha256)
        ):
            raise SSHExecutionError("remote file failed its SHA-256 check")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_symlink():
            raise ValueError("local candidate source destination is a symlink")
        temporary = destination.with_name(destination.name + ".ssh-transfer.tmp")
        if temporary.exists() or temporary.is_symlink():
            raise ValueError("refusing to overwrite an existing local transfer temporary")
        try:
            temporary.write_bytes(content)
            if hashlib.sha256(temporary.read_bytes()).hexdigest() != digest:
                raise SSHExecutionError("local temporary source failed its SHA-256 check")
            os.replace(temporary, destination)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        return digest

    def run(
        self,
        target: RemoteTarget,
        *,
        address: str,
        attempt_number: int,
        model: str,
        agent: str,
        session_id: str,
        prompt: str,
        timeout: float,
        cwd: Path,
        stop_requested: Callable[[], bool] | None = None,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        if not ADDRESS_RE.fullmatch(address) or attempt_number <= 0:
            raise ValueError("remote attempt identity is invalid")
        result_path = f".seto/results/{address[2:].lower()}-{attempt_number}.json"
        payload = {
            "op": "run",
            "opencode": target.opencode,
            "address": address,
            "attempt_number": attempt_number,
            "model": model,
            "agent": agent,
            "session_id": session_id,
            "prompt": prompt,
            "timeout": timeout,
            "result_path": result_path,
        }
        try:
            result = self.request(
                target,
                payload,
                cwd=cwd,
                timeout=timeout + 30,
                stop_requested=stop_requested,
                deadline=deadline,
            )
            if result.get("completed") is True:
                return self._validate_run_result(result, address, attempt_number, session_id)
        except SSHExecutionError:
            pass
        try:
            result = self.request(
                target,
                {"op": "get-result", "path": result_path},
                cwd=cwd,
                timeout=30,
                stop_requested=stop_requested,
                deadline=deadline,
            )
        except SSHExecutionError as exc:
            raise SSHExecutionError("remote inference result is unknown", result_unknown=True) from exc
        if result.get("completed") is True:
            return self._validate_run_result(result, address, attempt_number, session_id)
        raise SSHExecutionError("remote inference result is unknown", result_unknown=True)

    @staticmethod
    def _validate_run_result(
        result: dict[str, Any], address: str, attempt_number: int, session_id: str
    ) -> dict[str, Any]:
        if (
            result.get("address") != address.lower()
            or result.get("attempt_number") != attempt_number
            or result.get("session_id") != session_id
            or not isinstance(result.get("returncode"), int)
            or not isinstance(result.get("stdout"), str)
            or not isinstance(result.get("stderr"), str)
        ):
            raise SSHExecutionError("remote result does not match this SQLite attempt", result_unknown=True)
        return result
