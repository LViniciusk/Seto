"""Optional end-to-end checks that do not need the original game media."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from seto import smoke
from seto.toolchain import NOT_APPLICABLE, detect_all, load_settings

pytestmark = pytest.mark.integration
REPO_ROOT = Path(__file__).resolve().parents[2]


def test_wibo_executes_the_psp_compiler_and_produces_an_elf32_mips_object(tmp_path) -> None:
    wsl_profile = REPO_ROOT / "config" / "wsl" / "seto.toml"
    config = (
        wsl_profile
        if os.name == "posix" and wsl_profile.is_file()
        else REPO_ROOT / "config" / "seto.toml"
    )
    settings = load_settings(config)
    detected = {status.name: status for status in detect_all(settings)}
    if detected["wibo"].state == NOT_APPLICABLE:
        pytest.skip("wibo is only applicable on POSIX hosts")
    if not detected["mwccpsp"].found:
        pytest.skip("licensed mwccpsp was not supplied")
    if not detected["wibo"].found:
        pytest.skip("wibo is not installed")

    report = smoke.smoke_report(
        settings,
        tools=["mwccpsp", "wibo"],
        workspace=tmp_path / "smoke",
    )
    by_name = {status.name: status for status in report}
    compiler_capabilities = {item.name: item for item in by_name["mwccpsp"].capabilities}
    loader_capabilities = {item.name: item for item in by_name["wibo"].capabilities}
    assert compiler_capabilities["compile"].state == "READY", compiler_capabilities
    assert loader_capabilities["win32"].state == "READY", loader_capabilities
    assert list((tmp_path / "smoke" / "runs").rglob("seto_smoke_wibo.o"))


def test_installed_rea_completes_the_stdio_mcp_handshake(tmp_path) -> None:
    settings = load_settings(REPO_ROOT / "config" / "seto.toml")
    detected = {status.name: status for status in detect_all(settings)}
    if not detected["rea"].found:
        pytest.skip("REA is not installed")

    report = smoke.smoke_report(
        settings,
        tools=["rea"],
        workspace=tmp_path / "smoke",
    )
    by_name = {item.name: item for item in report}["rea"]
    capabilities = {item.name: item for item in by_name.capabilities}
    assert capabilities["mcp"].state == "READY", capabilities["mcp"].detail
    # Connection is not analysis: neither the presence of a Ghidra provider nor
    # support for PSP PRX is inferred from an MCP tools/list response.
    assert capabilities["native-analysis"].state == "BLOCKED"
    assert capabilities["prx"].state == "BLOCKED"
