"""Optional end-to-end checks that do not need the original game media."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from seto import smoke
from seto.hashing import sha256_file
from seto.toolchain import NOT_APPLICABLE, detect_all, load_settings
from scripts.probe_common import ensure_build_dir, validated_build_root, write_build_text
from scripts.match_baselines import REAL_MATCH_CASES, match_tag

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
PSP_MODULE = (
    REPO_ROOT
    / "private"
    / "original"
    / "PSP_GAME"
    / "USRDIR"
    / "gmodule"
    / "libtutoriallist.prx"
)

def _real_match_report(tmp_path, function: int, source: str):
    """Compile one decomp source and compare it against the original PRX."""
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
    report_root = os.environ.get("SETO_MATCH_REPORT_DIR")
    output = (
        Path(report_root) / match_tag(function)
        if report_root
        else tmp_path / f"func_{function:08X}"
    )
    output.mkdir(parents=True, exist_ok=True)
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
    report["module_sha256"] = sha256_file(MODULE)
    if report_root and isinstance(report.get("match"), dict):
        # The full module audit can reuse the exact objects produced by this
        # baseline test instead of compiling the same functions a second time.
        # Persist the stamped report: the module SHA-256 binds the reused
        # object to this PRX version.
        (output / "report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (output / "audit-stderr.txt").write_text(result.stderr, encoding="utf-8")
    return result, report


def _assert_provenance(report, source: str) -> None:
    provenance = report["provenance"]
    assert provenance["object_sha256"]
    assert provenance["source_sha256"]
    assert Path(provenance["source"]).name == source
    assert Path(provenance["object"]).is_file()
    assert provenance["flags"] == ["-O4,p", "-sdatathreshold", "0"]
    assert provenance["compiler"], "the report must name the compiler it used"


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


@pytest.mark.skipif(
    os.environ.get("SETO_REA_GHIDRA_REAL") != "1",
    reason="set SETO_REA_GHIDRA_REAL=1 for the local REA/Ghidra provider integration",
)
def test_rea_ghidra_provider_analyzes_synthetic_input_and_rejects_psp_prx(tmp_path) -> None:
    if os.name != "nt":
        pytest.fail("BLOCKED: this opt-in exercises the Windows Ghidra P0 provider")
    if not PSP_MODULE.is_file():
        pytest.fail("BLOCKED: the original PRX is absent while the REA provider opt-in is active")

    settings = load_settings(REPO_ROOT / "config" / "seto.toml")
    detected = {status.name: status for status in detect_all(settings)}
    rea, node, ghidra, java = (detected[name] for name in ("rea", "node", "ghidra", "java"))
    assert rea.version == "6.5.0", f"expected locked REA 6.5.0, found {rea.version!r}"
    for status in (rea, node, ghidra, java):
        if not status.found or not status.path:
            pytest.fail(f"BLOCKED: {status.name} is not available for the opt-in provider test")
    from seto.toolchain import rea_node_engine_compatible

    if not rea_node_engine_compatible(node.version):
        pytest.fail(f"BLOCKED: Node {node.version} is incompatible with REA 6.5.0")

    ghidra_home = Path(ghidra.path).parent.parent
    java_home = Path(java.path).parent.parent
    env = dict(os.environ)
    env["GHIDRA_INSTALL_DIR"] = str(ghidra_home)
    env["JAVA_HOME"] = str(java_home)
    smoke_report = smoke.smoke_report(settings, env=env, tools=["rea"], workspace=tmp_path / "smoke")
    rea_capabilities = {item.name: item for item in smoke_report[0].capabilities}
    assert rea_capabilities["cli"].state == "READY"
    assert rea_capabilities["mcp"].state == "READY"
    assert rea_capabilities["ghidra-provider"].state == "INSTALLED"
    assert rea_capabilities["native-analysis"].state == "BLOCKED"

    synthetic = tmp_path / "seto_rea_6502.bin"
    # 0x8000: JSR $8008; RTS. 0x8008: LDA #$2a; RTS. Never execute this file.
    expected_bytes = bytes.fromhex("20 08 80 60 ea ea ea ea a9 2a 60")
    synthetic.write_bytes(expected_bytes)
    rea_timings: list[dict[str, object]] = []
    function_started = time.perf_counter()
    function = subprocess.run(
        [
            rea.path,
            "function",
            str(synthetic),
            "0x8000",
            "--target-format",
            "raw-binary",
            "--architecture",
            "6502",
            "--entry-point",
            "0x8000",
            "--provider",
            "ghidra",
            "--json",
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=600,
        check=False,
    )
    rea_timings.append(
        {"procedure": "0x8000", "seconds": round(time.perf_counter() - function_started, 3)}
    )
    assert function.returncode == 0, function.stderr
    dossier = json.loads(function.stdout)["normalized_result"]
    assert dossier["procedure"]["address"] == "0x8000"
    assert dossier["procedure"]["body"]["ranges"] == [
        {"start": "0x8000", "end": "0x8003"}
    ]
    assert dossier["assembly"] == ["0x8000: JSR 0x8008", "0x8003: RTS"]
    assert dossier["callees"][0]["address"] == "0x8008"
    assert dossier["outgoing_references"][0]["kind"]["call"] is True
    assert sha256_file(synthetic) == json.loads(function.stdout)["subject"]["digest"]["sha256"]

    callee_started = time.perf_counter()
    callee = subprocess.run(
        [
            rea.path,
            "function",
            str(synthetic),
            "0x8008",
            "--target-format",
            "raw-binary",
            "--architecture",
            "6502",
            "--entry-point",
            "0x8000",
            "--provider",
            "ghidra",
            "--json",
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=600,
        check=False,
    )
    rea_timings.append(
        {"procedure": "0x8008", "seconds": round(time.perf_counter() - callee_started, 3)}
    )
    assert callee.returncode == 0, callee.stderr
    callee_dossier = json.loads(callee.stdout)["normalized_result"]
    assert callee_dossier["procedure"]["address"] == "0x8008"
    assert callee_dossier["procedure"]["body"]["ranges"] == [
        {"start": "0x8008", "end": "0x800a"}
    ]
    assert callee_dossier["assembly"] == ["0x8008: LDA #0x2a", "0x800a: RTS"]

    prx_started = time.perf_counter()
    prx = subprocess.run(
        [rea.path, "analyze", str(PSP_MODULE), "--provider", "ghidra", "--json"],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )
    rea_timings.append(
        {
            "procedure": "open_binary",
            "target": "libtutoriallist.prx",
            "seconds": round(time.perf_counter() - prx_started, 3),
        }
    )
    assert prx.returncode != 0
    rejection = json.loads(prx.stdout)
    assert rejection["error"] == "Analysis failed"
    assert rejection["code"] == "capability_unavailable"
    assert rejection["details"]["selection_reason"] == "target_unsupported"
    assert any(
        item["provider_id"] == "ghidra" and item["code"] == "target_format_unsupported"
        for item in rejection["details"]["rejections"]
    )
    prx_capability = smoke.classify_rea_target_error(rejection, provider_id="ghidra")
    assert prx_capability.state == "UNSUPPORTED"

    build_root = validated_build_root(REPO_ROOT, subdir="seto019")
    rea_root = build_root / "rea"
    ensure_build_dir(rea_root, build_root)
    timing_report = {
        "package_version": rea.version,
        "provider_id": "ghidra",
        "supported_synthetic": {
            "format": "raw-binary",
            "architecture": "6502",
            "sha256": sha256_file(synthetic),
            "procedures": ["0x8000", "0x8008"],
        },
        "psp_prx": {
            "classification": prx_capability.state,
            "reason": prx_capability.detail,
        },
        "measurements": rea_timings,
    }
    write_build_text(
        rea_root / "provider-timings.json",
        json.dumps(timing_report, indent=2, sort_keys=True) + "\n",
        build_root,
    )


@pytest.mark.parametrize("function,source,expected_status,matching_words,total_words", REAL_MATCH_CASES)
def test_real_mwccpsp_function_baselines(
    tmp_path, function, source, expected_status, matching_words, total_words
) -> None:
    """Compile+compare the real baselines only in the local WSL2/media environment."""
    result, report = _real_match_report(tmp_path, function, source)
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
    _assert_provenance(report, source)


def test_real_mwccpsp_func_00000508_certifies_every_word_but_relocation_identity(
    tmp_path,
) -> None:
    """func_00000508 reproduces every word; only data identity stays unproven.

    The audit hardening replaced the byte-typed view of the block with the
    ``SetoObservedBlock`` record in ``decomp/include/seto_shared_state.h``.  With
    the block's members typed, this build emits the closing block exactly as the
    module does - ``move $a0, $s0`` before the three zero stores, then the call
    with ``sw $zero, 0x78($s0)`` in its delay slot - so the four-word scheduling
    difference the previous revision recorded is gone.  The result is
    ``INCONCLUSIVE`` because twelve words are the six HI16/LO16 pairs whose data
    identity cannot be proven from the stripped module.  The test pins that shape
    instead of the old ``NONMATCHING`` one.
    """
    result, report = _real_match_report(tmp_path, 0x508, "func_00000508.c")
    match = report["match"]

    assert result.returncode == 5, result.stderr
    assert report["status"] == "INCONCLUSIVE"
    assert report["verified_decompilation"] is False
    assert match["total_words"] == 75
    assert match["matching_words"] == 63
    assert match["difference_count"] == 0
    assert match["differences"] == []
    # 63 certified + 12 uncertified = 75.  The twelve are six HI16/LO16 pairs:
    # one for 0x604864, three for 0x604918 (the 0x414 argument and the +0x40 and
    # +0x68 stores) and two for 0x604b18 (the 0x4b8 argument and the +0x50 store).
    assert match["total_words"] - match["matching_words"] == 12
    assert len(match["limitations"]) == 6
    for limitation in match["limitations"]:
        assert "HI16/LO16" in limitation
        assert "data identity cannot be proven" in limitation
    assert match["relocation_issues"] == []
    _assert_provenance(report, "func_00000508.c")
