"""Optional end-to-end checks that do not need the original game media."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from seto import smoke
from seto.toolchain import NOT_APPLICABLE, detect_all, load_settings

pytestmark = pytest.mark.integration
REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = (
    REPO_ROOT
    / "private"
    / "original"
    / "PSP_GAME"
    / "USRDIR"
    / "gmodule"
    / "libhtml_view.prx"
)

REAL_MATCH_CASES = (
    (0x244, "func_00000244.c", "MATCHED", 13, 13),
    (0x4B8, "func_000004B8.c", "INCONCLUSIVE", 18, 20),
    (0x6E4, "func_000006E4.c", "INCONCLUSIVE", 2, 8),
    (0x34, "func_00000034.c", "MATCHED", 20, 20),
    (0x134, "func_00000134.c", "MATCHED", 17, 17),
    (0x358, "func_00000358.c", "MATCHED", 17, 17),
    (0x8C, "func_0000008C.c", "MATCHED", 42, 42),
    (0x178, "func_00000178.c", "MATCHED", 51, 51),
    (0x278, "func_00000278.c", "MATCHED", 56, 56),
)


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


@pytest.mark.parametrize("function,source,expected_status,matching_words,total_words", REAL_MATCH_CASES)
def test_real_mwccpsp_function_baselines(
    tmp_path, function, source, expected_status, matching_words, total_words
) -> None:
    """Compile+compare the real baselines only in the local WSL2/media environment."""
    if os.name != "posix":
        pytest.skip("real PE compiler integration uses WSL2+wibo, not native Windows")
    if not MODULE.is_file():
        pytest.skip("original PRX is absent; real matching is not run in public CI")

    profile = REPO_ROOT / "config" / "wsl" / "seto.toml"
    if not profile.is_file():
        pytest.skip("git-ignored config/wsl/seto.toml is not configured")
    settings = load_settings(profile)
    detected = {status.name: status for status in detect_all(settings)}
    compiler = detected["mwccpsp"]
    loader = detected["wibo"]
    if not compiler.found:
        pytest.skip("licensed mwccpsp is not configured in the WSL profile")
    if not loader.found:
        pytest.skip("wibo is not configured or discoverable in WSL")

    source_path = REPO_ROOT / "decomp" / "src" / source
    output = tmp_path / f"func_{function:08X}"
    argv = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "match_function.py"),
        "--config",
        str(profile),
        "--prx",
        str(MODULE),
        "--function",
        hex(function),
        "--source",
        str(source_path),
        "--out",
        str(output),
        "--json",
    ]
    result = subprocess.run(
        argv, cwd=REPO_ROOT, capture_output=True, text=True, timeout=600, check=False
    )
    report = json.loads(result.stdout)
    match = report["match"]
    expected_exit = 0 if expected_status == "MATCHED" else 5
    assert result.returncode == expected_exit, result.stderr
    assert report["status"] == expected_status
    assert report["verified_decompilation"] is (expected_status == "MATCHED")
    assert match["matching_words"] == matching_words
    assert match["total_words"] == total_words
    assert match["difference_count"] == 0
    assert match["relocation_issues"] == []
    if expected_status == "MATCHED":
        assert match["limitations"] == []
        assert match["matching_words"] == match["total_words"]
    else:
        assert match["limitations"], "an inconclusive result must state its limitation"
    provenance = report["provenance"]
    assert provenance["object_sha256"]
    assert provenance["source_sha256"]
    assert Path(provenance["source"]).name == source
    assert Path(provenance["object"]).is_file()
    assert provenance["flags"] == ["-O4,p", "-sdatathreshold", "0"]
    assert provenance["compiler"]
