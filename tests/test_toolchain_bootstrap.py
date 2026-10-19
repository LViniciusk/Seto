"""Safety and dry-run checks for the two thin toolchain bootstrap wrappers."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "safe_extract.py"
_SPEC = importlib.util.spec_from_file_location("seto_safe_extract", HELPER_PATH)
assert _SPEC is not None and _SPEC.loader is not None
safe_extract = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = safe_extract
_SPEC.loader.exec_module(safe_extract)


def test_safe_zip_extract_writes_only_inside_destination(tmp_path: Path) -> None:
    archive = tmp_path / "safe.zip"
    destination = tmp_path / "tools"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("release/bin/tool", b"tool bytes")
        zipped.writestr("release/data/", b"")

    safe_extract.safe_extract_zip(archive, destination)
    safe_extract.safe_extract_zip(archive, destination)

    assert (destination / "release" / "bin" / "tool").read_bytes() == b"tool bytes"
    assert (destination / "release" / "data").is_dir()


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable bits are not represented on Windows")
def test_safe_zip_extract_preserves_only_safe_executable_bits(tmp_path: Path) -> None:
    archive = tmp_path / "launcher.zip"
    destination = tmp_path / "tools"
    info = zipfile.ZipInfo("release/support/analyzeHeadless")
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o4757) << 16
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr(info, b"#!/bin/sh\nexit 0\n")

    safe_extract.safe_extract_zip(archive, destination)
    mode = stat.S_IMODE((destination / "release/support/analyzeHeadless").stat().st_mode)

    assert mode == 0o755


@pytest.mark.parametrize(
    "member",
    ["../outside.txt", "/absolute.txt", "C:/outside.txt", r"..\outside.txt"],
)
def test_unsafe_zip_paths_are_rejected_before_any_file_is_written(
    tmp_path: Path, member: str
) -> None:
    archive = tmp_path / "unsafe.zip"
    destination = tmp_path / "tools"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("release/first.txt", b"first")
        zipped.writestr(member, b"escape")

    with pytest.raises(safe_extract.UnsafeArchiveError):
        safe_extract.safe_extract_zip(archive, destination)

    assert not destination.exists() or not any(destination.rglob("*"))
    assert not (tmp_path / "outside.txt").exists()


def test_corrupt_zip_crc_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "corrupt.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zipped:
        zipped.writestr("file.txt", b"known payload")
    data = archive.read_bytes().replace(b"known payload", b"badly payload")
    archive.write_bytes(data)

    with pytest.raises(safe_extract.UnsafeArchiveError, match="CRC"):
        safe_extract.safe_extract_zip(archive, tmp_path / "out")


def test_zip_symlinks_are_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("release/link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr(info, "../../outside")

    with pytest.raises(safe_extract.UnsafeArchiveError, match="file type"):
        safe_extract.safe_extract_zip(archive, tmp_path / "out")


def test_integrity_check_accepts_only_the_pinned_sha256(tmp_path: Path) -> None:
    payload = tmp_path / "release.zip"
    payload.write_bytes(b"pinned release bytes")
    expected = hashlib.sha256(payload.read_bytes()).hexdigest()
    assert safe_extract.verify_sha256(payload, expected)
    assert not safe_extract.verify_sha256(payload, "0" * 64)
    verified = subprocess.run(
        [sys.executable, str(HELPER_PATH), "--verify-sha256", str(payload), expected],
        check=False,
    )
    rejected = subprocess.run(
        [sys.executable, str(HELPER_PATH), "--verify-sha256", str(payload), "0" * 64],
        check=False,
    )
    assert verified.returncode == 0
    assert rejected.returncode == 1


def test_lockfile_pins_every_download_and_never_the_proprietary_compiler() -> None:
    lock = (REPO_ROOT / "config" / "toolchain.lock").read_text(encoding="utf-8")
    assert "pypi_index=https://pypi.org/simple" in lock
    assert "npm_registry=https://registry.npmjs.org/" in lock
    assert "splat=0.50.1" in lock
    assert "m2c_commit=708d2d2cb2698f091a92492b328f73b24209f72d" in lock
    assert "ghidra_sha256=" in lock
    assert "ghidra_allegrex_sha256=" in lock
    assert "wibo_linux_x86_64_sha256=" in lock
    assert "mwccpsp_url=" not in lock


@pytest.mark.skipif(os.name != "nt", reason="PowerShell bootstrap is the Windows variant")
def test_powershell_dry_run_is_selective_and_does_not_write_tool_config(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        pytest.skip("Windows PowerShell is unavailable")
    bootstrap_config = REPO_ROOT / "config" / "seto.bootstrap.toml"
    before = bootstrap_config.read_bytes() if bootstrap_config.exists() else None
    report = tmp_path / "powershell-report.json"
    env = dict(os.environ)
    env["SETO_PYTHON"] = sys.executable
    completed = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(REPO_ROOT / "scripts" / "bootstrap_toolchain.ps1"),
            "-DryRun",
            "-Tool",
            "splat,m2c",
            "-Report",
            str(report),
        ],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=300,
    )
    assert completed.returncode in (0, 4), completed.stdout + completed.stderr
    assert "splat64[mips]==0.50.1" in completed.stdout
    assert "m2c from commit" in completed.stdout
    assert "install LLVM" not in completed.stdout
    assert report.is_file()
    first_report = report.read_bytes()
    assert {item["name"] for item in json.loads(report.read_text())["tools"]} == {"splat", "m2c"}
    repeated = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(REPO_ROOT / "scripts" / "bootstrap_toolchain.ps1"),
            "-DryRun",
            "-Tool",
            "splat,m2c",
            "-Report",
            str(report),
        ],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=300,
    )
    assert repeated.returncode in (0, 4), repeated.stdout + repeated.stderr
    assert report.read_bytes() == first_report
    after = bootstrap_config.read_bytes() if bootstrap_config.exists() else None
    assert after == before


@pytest.mark.skipif(os.name != "nt", reason="PowerShell bootstrap is the Windows variant")
def test_powershell_runs_seto_from_checkout_without_an_editable_install(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        pytest.skip("Windows PowerShell is unavailable")
    venv = tmp_path / "python-without-seto"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, timeout=120)
    python = venv / "Scripts" / "python.exe"
    assert python.is_file()
    report = tmp_path / "checkout-only-report.json"
    env = dict(os.environ)
    env["SETO_PYTHON"] = str(python)
    completed = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(REPO_ROOT / "scripts" / "bootstrap_toolchain.ps1"),
            "-DryRun",
            "-Tool",
            "m2c",
            "-Config",
            "config/wsl/seto.example.toml",
            "-Report",
            str(report),
        ],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=300,
    )
    assert completed.returncode in (0, 4), completed.stdout + completed.stderr
    assert "No module named seto" not in completed.stdout + completed.stderr
    assert str(REPO_ROOT / "config" / "wsl" / "seto.example.toml") in completed.stdout
    assert {item["name"] for item in json.loads(report.read_text())["tools"]} == {"m2c"}


@pytest.mark.skipif(os.name != "nt", reason="PowerShell bootstrap is the Windows variant")
def test_powershell_bootstrap_rejects_config_outside_config_root(tmp_path: Path) -> None:
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        pytest.skip("PowerShell is unavailable")
    completed = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(REPO_ROOT / "scripts" / "bootstrap_toolchain.ps1"),
            "-DryRun",
            "-Tool",
            "m2c",
            "-Config",
            "../outside.toml",
            "-Report",
            str(tmp_path / "outside-config.json"),
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=120,
    )
    assert completed.returncode != 0
    assert "config must be under" in completed.stdout + completed.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX bootstrap is tested on Linux/macOS")
def test_posix_dry_run_is_selective_and_does_not_write_tool_config(tmp_path: Path) -> None:
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is unavailable")
    bootstrap_config = REPO_ROOT / "config" / "seto.bootstrap.toml"
    before = bootstrap_config.read_bytes() if bootstrap_config.exists() else None
    report = tmp_path / "posix-report.json"
    env = dict(os.environ)
    env["SETO_PYTHON"] = sys.executable
    completed = subprocess.run(
        [
            bash,
            str(REPO_ROOT / "scripts" / "bootstrap_toolchain.sh"),
            "--dry-run",
            "--tool",
            "splat",
            "--tool",
            "m2c",
            "--report",
            str(report),
        ],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=300,
    )
    assert completed.returncode in (0, 4), completed.stdout + completed.stderr
    assert "splat64[mips]==0.50.1" in completed.stdout
    assert "install LLVM" not in completed.stdout
    assert report.is_file()
    first_report = report.read_bytes()
    assert {item["name"] for item in json.loads(report.read_text())["tools"]} == {"splat", "m2c"}
    repeated = subprocess.run(
        [
            bash,
            str(REPO_ROOT / "scripts" / "bootstrap_toolchain.sh"),
            "--dry-run",
            "--tool",
            "splat",
            "--tool",
            "m2c",
            "--report",
            str(report),
        ],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=300,
    )
    assert repeated.returncode in (0, 4), repeated.stdout + repeated.stderr
    assert report.read_bytes() == first_report
    after = bootstrap_config.read_bytes() if bootstrap_config.exists() else None
    assert after == before

    wsl_config = REPO_ROOT / "config" / "wsl" / "seto.example.toml"
    wsl_overlay = wsl_config.with_name("seto.bootstrap.toml")
    overlay_before = wsl_overlay.read_bytes() if wsl_overlay.exists() else None
    profile_report = tmp_path / "wsl-profile-report.json"
    profile = subprocess.run(
        [
            bash,
            str(REPO_ROOT / "scripts" / "bootstrap_toolchain.sh"),
            "--dry-run",
            "--tool",
            "m2c",
            "--config",
            "config/wsl/seto.example.toml",
            "--report",
            str(profile_report),
        ],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=300,
    )
    assert profile.returncode in (0, 4), profile.stdout + profile.stderr
    assert str(wsl_config.resolve()) in profile.stdout
    assert {item["name"] for item in json.loads(profile_report.read_text())["tools"]} == {"m2c"}
    overlay_after = wsl_overlay.read_bytes() if wsl_overlay.exists() else None
    assert overlay_after == overlay_before


@pytest.mark.skipif(os.name == "nt", reason="POSIX bootstrap is tested on Linux/macOS")
def test_posix_bootstrap_rejects_config_outside_config_root(tmp_path: Path) -> None:
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is unavailable")
    env = dict(os.environ)
    env["SETO_PYTHON"] = sys.executable
    completed = subprocess.run(
        [
            bash,
            str(REPO_ROOT / "scripts" / "bootstrap_toolchain.sh"),
            "--dry-run",
            "--tool",
            "m2c",
            "--config",
            "../outside.toml",
            "--report",
            str(tmp_path / "outside-config.json"),
        ],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=120,
    )
    assert completed.returncode != 0
    assert "config must be a regular file under" in completed.stdout + completed.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX sudo guard is tested on Linux/macOS")
def test_posix_bootstrap_never_uses_sudo_without_an_explicit_notice(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("running as root does not exercise the sudo branch")
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is unavailable")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    sudo_log = tmp_path / "sudo.log"
    sudo = fake_bin / "sudo"
    sudo.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >>\"$SUDO_LOG\"\n"
        "exit 1\n",
        encoding="utf-8",
    )
    sudo.chmod(0o755)
    apt = fake_bin / "apt-get"
    apt.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    apt.chmod(0o755)

    env = dict(os.environ)
    env["PATH"] = str(fake_bin) + os.pathsep + env.get("PATH", "")
    env["SETO_PYTHON"] = sys.executable
    env["SUDO_LOG"] = str(sudo_log)
    env["SETO_OBJDUMP"] = str(tmp_path / "missing-objdump")
    completed = subprocess.run(
        [
            bash,
            str(REPO_ROOT / "scripts" / "bootstrap_toolchain.sh"),
            "--install",
            "--tool",
            "objdump",
            "--report",
            str(tmp_path / "sudo-report.json"),
        ],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=300,
    )
    assert completed.returncode == 4, completed.stdout + completed.stderr
    assert "NOTICE: checking non-interactive sudo" in completed.stdout
    assert "needs root; run this yourself" in completed.stdout
    attempts = sudo_log.read_text(encoding="utf-8").splitlines()
    assert attempts == ["-n true"]
