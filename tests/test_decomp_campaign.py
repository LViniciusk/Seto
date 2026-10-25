"""Persistent campaign orchestration, failure policy, and safety regressions."""

from __future__ import annotations

import json
import hashlib
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from decomp_campaign import (  # noqa: E402
    CampaignRunner,
    CampaignStore,
    Candidate,
    Claim,
    Failure,
    FailureKind,
    Worker,
    campaign_build_path,
    classify_failure,
    is_strict_match,
    load_config,
    prepare_worker_worktrees,
    _assert_worker_changes_scoped,
    validate_export_evidence,
    validate_ghidra_log,
    validate_model_id,
)


def candidate(address: str, *, preferred_provider: str | None = None) -> Candidate:
    return Candidate(
        address=address,
        size_bytes=16,
        nid="0x12345678",
        priority=50,
        boundary_status="EXACT",
        preferred_provider=preferred_provider,
        evidence={"source": "test fixture"},
    )


def strict_report(address: str = "0x1000") -> dict[str, object]:
    numeric_address = int(address, 0)
    return {
        "status": "MATCHED",
        "verified_decompilation": True,
        "evidence": "compiled-object",
        "address": address,
        "symbol": f"func_{numeric_address:08X}",
        "provenance": {
            "source_sha256": "a" * 64,
            "object_sha256": "b" * 64,
            "compiler": "/tools/mwccpsp.exe",
            "flags": ["-O4,p", "-sdatathreshold", "0"],
        },
        "match": {
            "status": "MATCHED",
            "matching_words": 4,
            "total_words": 4,
            "difference_count": 0,
            "differences": [],
            "limitations": [],
            "relocation_issues": [],
        },
    }


def fake_opencode_command(tmp_path: Path, worker_script: Path | None = None) -> list[str]:
    """A strict no-provider CLI double: API-created sessions are required for run."""
    wrapper = tmp_path / "fake_opencode_wrapper.py"
    wrapper.write_text(
        "import json, os, pathlib, subprocess, sys, uuid\n"
        "args = sys.argv[1:]\n"
        "worker = None\n"
        "if args and pathlib.Path(args[0]).is_file(): worker = args.pop(0)\n"
        "state_path = pathlib.Path('.fake-opencode-sessions.json')\n"
        "state = json.loads(state_path.read_text()) if state_path.exists() else {'sessions': {}, 'created': [], 'runs': []}\n"
        "def save(): state_path.write_text(json.dumps(state))\n"
        "if args[:2] == ['api', 'post'] and args[2] == '/api/session':\n"
        " payload = json.loads(args[args.index('--data') + 1])\n"
        " session_id = 'ses_test' + uuid.uuid4().hex\n"
        " location = payload['location']['directory']\n"
        " state['sessions'][session_id] = {'location': location}\n"
        " state['created'].append(session_id)\n"
        " save(); print(json.dumps({'data': {'id': session_id, 'location': {'directory': location}}})); raise SystemExit(0)\n"
        "if args[:2] == ['api', 'get'] and args[2].startswith('/api/session/'):\n"
        " session_id = args[2].rsplit('/', 1)[-1]\n"
        " if session_id not in state['sessions']:\n"
        "  sys.stdout.write('{\"_tag\":\"SessionNotFoundError\"}\\n')\n"
        "  sys.stderr.write('HTTP 404 Not Found\\n')\n"
        "  raise SystemExit(1)\n"
        " print(json.dumps({'data': {'id': session_id, 'location': {'directory': state['sessions'][session_id]['location']}}})); raise SystemExit(0)\n"
        "if args and args[0] == 'run':\n"
        " session_id = args[args.index('--session') + 1]\n"
        " if session_id not in state['sessions']:\n"
        "  sys.stdout.write('{\"_tag\":\"SessionNotFoundError\"}\\n')\n"
        "  sys.stderr.write('HTTP 404 Not Found\\n')\n"
        "  raise SystemExit(1)\n"
        " state['runs'].append(session_id); save()\n"
        " if worker:\n"
        "  result = subprocess.run([sys.executable, worker, *args])\n"
        "  raise SystemExit(result.returncode)\n"
        " print(json.dumps({'type':'text','text':json.dumps({'checkpoint':{'next_experiment':'test checkpoint'}})}))\n"
        " raise SystemExit(0)\n"
        "sys.stderr.write('unsupported OpenCode invocation')\n"
        "raise SystemExit(2)\n",
        encoding="utf-8",
    )
    command = [sys.executable, str(wrapper)]
    if worker_script is not None:
        command.append(str(worker_script))
    return command


def ghidra_log(
    *,
    start: int = 0x1000,
    end: int = 0x1010,
    body_addresses: int = 16,
    ranges: int = 1,
    instruction_count: int = 4,
    instruction_addresses: list[int] | None = None,
    instruction_sizes: list[int] | None = None,
) -> str:
    addresses = instruction_addresses or list(range(start, end, 4))
    sizes = instruction_sizes or [4] * len(addresses)
    rows = [
        "SETO_LANGUAGE=Allegrex:LE:32:default",
        f"SETO_FUNCTION_START=0x{start:x}",
        f"SETO_FUNCTION_END={end:08x}",
        f"SETO_FUNCTION_BODY_START={start:08x}",
        f"SETO_FUNCTION_BODY_END={end:08x}",
        f"SETO_FUNCTION_BODY_ADDRESSES={body_addresses}",
        f"SETO_FUNCTION_BODY_RANGES={ranges}",
        "SETO_ADDRESSABLE_UNIT_SIZE=1",
        "SETO_BOUNDARY_STATUS=EXACT",
        "SETO_DECOMP_STATUS=OK",
        f"SETO_INSTRUCTION_COUNT={instruction_count}",
    ]
    rows.extend(
        f"SETO_INSN=0x{address:x} SIZE={size}"
        for address, size in zip(addresses, sizes)
    )
    return "\n".join(rows)


def test_sqlite_claim_is_atomic_and_each_task_has_one_owner(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "queue.sqlite3")
    store.seed([candidate("0x1000")])

    def claim(worker_id: int):
        return store.claim_next(f"worker-{worker_id}", "openai")

    with ThreadPoolExecutor(max_workers=8) as pool:
        claims = list(pool.map(claim, range(8)))

    successful = [item for item in claims if item is not None]
    assert len(successful) == 1
    assert successful[0].address == "0x1000"
    assert store.get_task("0x1000")["status"] == "running"


def test_checkpoint_survives_reopen_and_expired_claim_can_resume(tmp_path: Path) -> None:
    path = tmp_path / "queue.sqlite3"
    store = CampaignStore(path)
    store.seed([candidate("0x1000")])
    claim = store.claim_next("openai-1", "openai", lease_seconds=5, now=100)
    assert claim is not None
    store.save_checkpoint(
        claim,
        {"next_experiment": "preserved local hypothesis", "best_source_sha256": "a" * 64},
    )

    store = CampaignStore(path)
    assert store.recover_expired(now=106) == 1
    resumed = store.claim_next("deepseek-1", "deepseek", now=107)
    assert resumed is not None
    assert resumed.address == "0x1000"
    assert resumed.checkpoint["next_experiment"] == "preserved local hypothesis"


def test_resume_does_not_release_a_live_claim(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "queue.sqlite3")
    store.seed([candidate("0x1000")])
    claim = store.claim_next("worker-1", "openai")
    assert claim is not None
    store.request_stop()
    store.resume()
    assert store.get_task("0x1000")["status"] == "running"
    assert store.claim_next("worker-2", "deepseek") is None


@pytest.mark.parametrize(
    ("returncode", "stderr", "expected"),
    [
        (1, "insufficient_quota: quota exceeded", FailureKind.QUOTA_EXHAUSTED),
        (1, "HTTP 429 rate limit; Retry-After: 17", FailureKind.RATE_LIMIT),
        (1, "401 invalid API key", FailureKind.AUTH),
        (1, "connection reset by peer", FailureKind.NETWORK),
        (1, "unclassified worker failure", FailureKind.AGENT_ERROR),
    ],
)
def test_provider_failures_are_classified_without_guessing_quota(
    returncode: int, stderr: str, expected: FailureKind
) -> None:
    failure = classify_failure(returncode, "", stderr)
    assert failure.kind is expected
    if expected is FailureKind.RATE_LIMIT:
        assert failure.retry_after_seconds == 17
    else:
        assert failure.retry_after_seconds is None


def test_models_are_exact_allowlist_only() -> None:
    allowed = {"openai/gpt-6-luna", "opencode/deepseek-v4.1-flash-free"}
    assert validate_model_id("openai/gpt-6-luna", allowed) == "openai/gpt-6-luna"
    assert (
        validate_model_id("opencode/deepseek-v4.1-flash-free", allowed)
        == "opencode/deepseek-v4.1-flash-free"
    )
    with pytest.raises(ValueError, match="not explicitly allowlisted"):
        validate_model_id("openai/gpt-6-luna-fast", allowed)
    with pytest.raises(ValueError, match="not explicitly allowlisted"):
        validate_model_id("openai/gpt-7-paid", allowed)


def test_model_execution_is_disabled_until_separately_verified() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "config" / "decomp_campaign.toml")
    assert config["execution"]["enabled"] is False
    assert config["execution"]["provider_access_verified"] is False
    assert config["execution"]["worker_permissions_reviewed"] is False
    assert config["execution"]["continuous"] is False
    assert config["models"]["allowlist"] == [
        "openai/gpt-6-luna",
        "opencode/deepseek-v4.1-flash-free",
    ]


def test_only_complete_matcher_evidence_can_be_called_matched() -> None:
    assert is_strict_match(strict_report(), expected_address=0x1000, expected_size=16)

    partial = strict_report()
    partial["match"]["matching_words"] = 3  # type: ignore[index]
    assert not is_strict_match(partial, expected_address=0x1000, expected_size=16)

    artificial = strict_report()
    artificial["evidence"] = "agent-assertion"
    assert not is_strict_match(artificial, expected_address=0x1000, expected_size=16)

    limited = strict_report()
    limited["match"]["limitations"] = ["unresolved relocation"]  # type: ignore[index]
    assert not is_strict_match(limited, expected_address=0x1000, expected_size=16)


def test_ghidra_log_requires_one_exact_contiguous_allegrex_body() -> None:
    log = ghidra_log()
    evidence = validate_ghidra_log(log, 0x1000)
    assert evidence["size_bytes"] == 16
    assert evidence["instruction_count"] == 4

    with pytest.raises(ValueError, match="exact Allegrex"):
        validate_ghidra_log(log.replace("SETO_FUNCTION_BODY_RANGES=1", "SETO_FUNCTION_BODY_RANGES=2"), 0x1000)


def test_ghidra_log_rejects_a_truncated_instruction_listing() -> None:
    log = ghidra_log().replace("SETO_INSN=0x100c SIZE=4", "")
    with pytest.raises(ValueError, match="exact Allegrex"):
        validate_ghidra_log(log, 0x1000)


def test_ghidra_log_rejects_discontinuous_instruction_addresses() -> None:
    log = ghidra_log(instruction_addresses=[0x1000, 0x1004, 0x100C, 0x1010])
    with pytest.raises(ValueError, match="exact Allegrex"):
        validate_ghidra_log(log, 0x1000)


def test_ghidra_log_rejects_instruction_size_and_count_inconsistencies() -> None:
    wrong_size = ghidra_log(instruction_sizes=[4, 4, 2, 4])
    wrong_count = ghidra_log(instruction_count=5)
    duplicate_marker = ghidra_log() + "\nSETO_BOUNDARY_STATUS=EXACT"
    missing_listing = ghidra_log().replace("SETO_INSN=0x1008 SIZE=4\n", "")
    for log in (wrong_size, wrong_count, duplicate_marker, missing_listing):
        with pytest.raises(ValueError, match="exact Allegrex"):
            validate_ghidra_log(log, 0x1000)


def test_export_evidence_requires_unique_relocated_nid_and_real_prx_call(tmp_path: Path) -> None:
    path = tmp_path / "triage.json"
    row = {
        "address": "0x1000",
        "nid": "0x12345678",
        "library": "libehsys",
        "pointer_relocation": {
            "type": "R_MIPS_32",
            "addend_valid": True,
            "application_valid": True,
            "addend": 0x1000,
        },
        "importers": [{"call_sites": ["0x20"], "table_limitations": []}],
    }
    path.write_text(json.dumps({"exports": [row]}), encoding="utf-8")
    validate_export_evidence(path, "0x1000", "0x12345678")
    row["importers"][0]["call_sites"] = []
    path.write_text(json.dumps({"exports": [row]}), encoding="utf-8")
    with pytest.raises(ValueError, match="call sites"):
        validate_export_evidence(path, "0x1000", "0x12345678")


def test_campaign_build_paths_reject_traversal_and_symlink(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "build").mkdir(parents=True)
    assert campaign_build_path(repo, "decomp-campaign/worker/task").is_relative_to(
        repo / "build"
    )

    with pytest.raises(ValueError, match="escapes"):
        campaign_build_path(repo, "../../outside")

    (repo / "build" / "redirect").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        campaign_build_path(repo, "redirect/worker")


def test_worker_diff_guard_allows_only_its_source_and_private_build() -> None:
    claim = Claim("0x1000", 16, "0x12345678", 1, "EXACT", "openai", "openai", "ses-test", 1, 0, {}, {})
    _assert_worker_changes_scoped(
        {},
        {
            "decomp/src/eboot/func_00001000.c": ("??", "a" * 64),
            "build/decomp-campaign/openai/1000/evidence/ghidra.log": ("??", "b" * 64),
        },
        claim,
    )
    with pytest.raises(ValueError, match="outside"):
        _assert_worker_changes_scoped(
            {},
            {"scripts/match_function.py": (" M", "c" * 64)},
            claim,
        )


def test_unclassified_agent_failure_does_not_fallback_to_other_provider(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000", preferred_provider="opencode")])
    simulator = tmp_path / "unknown_error.py"
    simulator.write_text(
        "import sys\n"
        "sys.stderr.write('unexpected worker failure')\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    worktrees = {name: tmp_path / name for name in ("deepseek", "openai")}
    for path in worktrees.values():
        path.mkdir()
    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path, simulator),
        worktrees=worktrees,
        timeout_seconds=5,
    )
    result = runner.run(
        [
            Worker("deepseek", "opencode", "opencode/deepseek-v4.1-flash-free"),
            Worker("openai", "openai", "openai/gpt-6-luna"),
        ],
        max_tasks=4,
    )
    assert result["attempted"] == 1
    assert store.get_task("0x1000")["status"] == "blocked"
    assert [attempt["provider"] for attempt in store.list_attempts()] == ["opencode"]
    assert store.provider_status("opencode") == "active"


def test_provider_failures_cannot_exceed_candidate_attempt_limit(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])
    claim = store.claim_next("deepseek", "opencode", max_attempts_per_candidate=1)
    assert claim is not None
    store.fail(
        claim,
        Failure(FailureKind.QUOTA_EXHAUSTED),
        max_attempts_per_candidate=1,
    )
    assert store.get_task("0x1000")["status"] == "stalled"
    assert store.claim_next("openai", "openai", max_attempts_per_candidate=1) is None


def test_session_creation_uses_the_id_returned_by_the_open_code_api(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])
    worktree = tmp_path / "worker"
    worktree.mkdir()
    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path),
        worktrees={"worker": worktree},
        timeout_seconds=5,
    )
    claim = store.claim_next("worker", "openai")
    assert claim is not None
    assert claim.session_id is None

    bound = runner._ensure_session(claim, worktree, None)
    assert bound.session_id.startswith("ses_test")
    assert store.get_task("0x1000")["session_id"] == bound.session_id
    assert store.list_attempts()[0]["session_id"] == bound.session_id
    argv = runner._argv(Worker("worker", "openai", "openai/gpt-6-luna"), bound, "prompt")
    assert argv[argv.index("--session") + 1] == bound.session_id


def test_valid_session_is_reused_when_resuming_with_the_same_provider(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])
    worktree = tmp_path / "worker"
    worktree.mkdir()
    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path),
        worktrees={"worker": worktree},
        timeout_seconds=5,
    )
    first = store.claim_next("worker", "openai")
    assert first is not None
    bound = runner._ensure_session(first, worktree, None)
    store.save_checkpoint(bound, {"next_experiment": "resume from checkpoint"})
    store.fail(bound, Failure(FailureKind.INTERRUPTED))

    resumed = store.claim_next("worker", "openai")
    assert resumed is not None
    assert resumed.session_id == bound.session_id
    reused = runner._ensure_session(resumed, worktree, None)
    state = json.loads((worktree / ".fake-opencode-sessions.json").read_text())
    assert reused.session_id == bound.session_id
    assert state["created"] == [bound.session_id]
    assert store.get_task("0x1000")["checkpoint"]["next_experiment"] == "resume from checkpoint"


def test_provider_fallback_creates_an_independent_session_and_keeps_checkpoint(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000", preferred_provider="opencode")])
    worktrees = {name: tmp_path / name for name in ("deepseek", "openai")}
    for worktree in worktrees.values():
        worktree.mkdir()
    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path),
        worktrees=worktrees,
        timeout_seconds=5,
    )
    first = store.claim_next("deepseek", "opencode")
    assert first is not None
    bound_first = runner._ensure_session(first, worktrees["deepseek"], None)
    store.save_checkpoint(bound_first, {"next_experiment": "preserve across provider switch"})
    store.fail(bound_first, Failure(FailureKind.QUOTA_EXHAUSTED))

    fallback = store.claim_next("openai", "openai")
    assert fallback is not None
    assert fallback.session_id is None
    bound_fallback = runner._ensure_session(fallback, worktrees["openai"], None)
    assert bound_fallback.session_id != bound_first.session_id
    assert fallback.checkpoint["next_experiment"] == "preserve across provider switch"
    assert store.list_attempts()[0]["session_id"] == bound_first.session_id
    assert store.list_attempts()[1]["session_id"] == bound_fallback.session_id


def test_missing_session_is_replaced_once_without_losing_checkpoint(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])
    worktree = tmp_path / "worker"
    worktree.mkdir()
    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path),
        worktrees={"worker": worktree},
        timeout_seconds=5,
    )
    first = store.claim_next("worker", "openai")
    assert first is not None
    bound = runner._ensure_session(first, worktree, None)
    store.save_checkpoint(bound, {"next_experiment": "keep progress"})
    store.fail(bound, Failure(FailureKind.INTERRUPTED))

    state_path = worktree / ".fake-opencode-sessions.json"
    state = json.loads(state_path.read_text())
    state["sessions"].pop(bound.session_id)
    state_path.write_text(json.dumps(state))
    resumed = store.claim_next("worker", "openai")
    assert resumed is not None
    replacement = runner._ensure_session(resumed, worktree, None)

    updated = json.loads(state_path.read_text())
    assert replacement.session_id != bound.session_id
    assert updated["created"] == [bound.session_id, replacement.session_id]
    assert resumed.checkpoint["next_experiment"] == "keep progress"
    assert store.list_attempts()[1]["session_id"] == replacement.session_id


def test_stop_and_resume_preserve_checkpoint_and_reuse_same_provider_session(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000", preferred_provider="openai")])
    simulator = tmp_path / "interruptible.py"
    simulator.write_text(
        "import json, pathlib, sys, time\n"
        "marker = pathlib.Path('.started')\n"
        "if not marker.exists():\n"
        " marker.write_text('started')\n"
        " time.sleep(30)\n"
        "text = json.dumps({'checkpoint': {'next_experiment': 'resume safely'}})\n"
        "print(json.dumps({'type': 'text', 'text': text}))\n",
        encoding="utf-8",
    )
    worktrees = {"openai": tmp_path / "openai"}
    worktrees["openai"].mkdir()

    def verifier(_worktree: Path, task: Candidate, _checkpoint: dict[str, object]):
        report = strict_report(task.address)
        return {
            "status": "MATCHED",
            "source_sha256": report["provenance"]["source_sha256"],
            "matching_words": 4,
            "total_words": 4,
            "build_sha256": [report["provenance"]["object_sha256"], report["provenance"]["object_sha256"]],
            "reports": [report, report],
        }

    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path, simulator),
        worktrees=worktrees,
        verifier=verifier,
        timeout_seconds=10,
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(runner.run, [Worker("openai", "openai", "openai/gpt-6-luna")], max_tasks=1)
        marker = worktrees["openai"] / ".started"
        for _ in range(100):
            if marker.exists():
                break
            import time

            time.sleep(0.05)
        assert marker.exists(), "simulated OpenCode process did not start"
        store.request_stop()
        assert future.result(timeout=10)["attempted"] == 1

    interrupted = store.list_attempts()[0]
    assert interrupted["outcome"] == "interrupted"
    assert store.get_task("0x1000")["status"] == "pending"
    store.resume()
    runner.run([Worker("openai", "openai", "openai/gpt-6-luna")], max_tasks=1)
    attempts = store.list_attempts()
    assert attempts[1]["outcome"] == "matched"
    assert attempts[0]["session_id"] == attempts[1]["session_id"]
    assert all(task["status"] != "running" for task in store.list_tasks())


def test_worker_worktrees_are_distinct_and_receive_only_verified_local_inputs(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Campaign Test"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "campaign-test@example.invalid"],
        cwd=repo,
        check=True,
    )
    (repo / "README.md").write_text("tracked baseline\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "baseline"], cwd=repo, check=True, capture_output=True)
    remote = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    subprocess.run(["git", "remote", "add", "origin", str(remote)], cwd=repo, check=True)

    inputs = {
        "eboot": "private/decrypted/ULUS10136_EBOOT.elf",
        "libtutoriallist": "private/original/PSP_GAME/USRDIR/gmodule/libtutoriallist.prx",
        "libhtml_view": "private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx",
        "triage_report": "build/seto035/export-triage.json",
    }
    hashes: dict[str, str] = {}
    for name, relative in inputs.items():
        source = repo / relative
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(f"local-{name}".encode())
        hashes[name] = hashlib.sha256(source.read_bytes()).hexdigest()
    for relative in ("config/wsl/seto.toml", "config/decomp_campaign.local.toml"):
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("local-tool-paths\n", encoding="utf-8")

    config = {
        "workers": {"openai": {}, "deepseek": {}},
        "inputs": {
            **inputs,
            "eboot_sha256": hashes["eboot"],
            "libtutoriallist_sha256": hashes["libtutoriallist"],
            "libhtml_view_sha256": hashes["libhtml_view"],
        },
        "toolchain": {
            "mwcc_config": "config/wsl/seto.toml",
            "ghidra_local_config": "config/decomp_campaign.local.toml",
        },
        "worktrees": {
            "root": "build/decomp-campaign/worktrees",
            "branch_prefix": "seto/decomp-campaign",
        },
    }
    workers = prepare_worker_worktrees(repo, config)
    assert set(workers) == {"openai", "deepseek"}
    assert workers["openai"] != workers["deepseek"]
    for name, worktree in workers.items():
        assert subprocess.run(
            ["git", "branch", "--show-current"], cwd=worktree, check=True, capture_output=True, text=True
        ).stdout.strip() == f"seto/decomp-campaign/{name}"
        for input_name, relative in inputs.items():
            assert hashlib.sha256((worktree / relative).read_bytes()).hexdigest() == hashes[input_name]
        assert (worktree / "config/wsl/seto.toml").is_file()


def test_unverified_inventory_item_must_pass_ghidra_before_matching(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed(
        [
            Candidate(
                address="0x1000",
                size_bytes=12,
                nid="0x12345678",
                priority=10,
                boundary_status="UNVERIFIED",
                evidence={"source": "test"},
                initial_state="needs_boundary",
            )
        ]
    )
    simulator = tmp_path / "boundary_then_match.py"
    simulator.write_text(
        "import json, sys\n"
        "text = json.dumps({'checkpoint': {'next_experiment': 'preserve exact boundary'}})\n"
        "print(json.dumps({'type': 'text', 'text': text}))\n",
        encoding="utf-8",
    )
    worktree = tmp_path / "worker"
    worktree.mkdir()

    def verifier(_worktree: Path, claim, _checkpoint):
        if claim.boundary_status == "UNVERIFIED":
            store.update_boundary(claim, 16, {"source": "synthetic Ghidra test"})
            return {"status": "BOUNDARY_VALIDATED", "matching_words": -1, "total_words": 4}
        report = strict_report(claim.address)
        return {
            "status": "MATCHED",
            "source_sha256": report["provenance"]["source_sha256"],
            "matching_words": 4,
            "total_words": 4,
            "build_sha256": [report["provenance"]["object_sha256"], report["provenance"]["object_sha256"]],
            "reports": [report, report],
        }

    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path, simulator),
        worktrees={"openai": worktree},
        verifier=verifier,
    )
    result = runner.run([Worker("openai", "openai", "openai/gpt-6-luna")], max_tasks=2)
    task = store.get_task("0x1000")
    assert result["attempted"] == 2
    assert task["boundary_status"] == "EXACT"
    assert task["size_bytes"] == 16
    assert task["status"] == "matched"


def test_best_source_snapshot_survives_a_lower_scoring_retry(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "build").mkdir(parents=True)
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000", preferred_provider="openai")])
    simulator = tmp_path / "rewrite_source.py"
    simulator.write_text(
        "import json, pathlib\n"
        "source = pathlib.Path('decomp/src/eboot/func_00001000.c')\n"
        "source.parent.mkdir(parents=True, exist_ok=True)\n"
        "if source.exists(): source.write_text(source.read_text() + '\\nversion-two')\n"
        "else: source.write_text('version-one')\n"
        "print(json.dumps({'type':'text','text':json.dumps({'checkpoint':{'next_experiment':'compare first divergence'}})}))\n",
        encoding="utf-8",
    )
    worktree = tmp_path / "openai"
    worktree.mkdir()

    def verifier(path: Path, _task: Candidate, _checkpoint: dict[str, object]):
        source = path / "decomp/src/eboot/func_00001000.c"
        content = source.read_text(encoding="utf-8")
        return {
            "status": "NONMATCHING",
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "matching_words": 2 if content == "version-one" else 1,
            "total_words": 4,
            "build_sha256": [],
            "reports": [],
        }

    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path, simulator),
        worktrees={"openai": worktree},
        verifier=verifier,
        checkpoint_repo_root=repo,
    )
    result = runner.run([Worker("openai", "openai", "openai/gpt-6-luna")], max_tasks=2)
    assert result["attempted"] == 2
    checkpoint = store.get_task("0x1000")["checkpoint"]
    best_hash = hashlib.sha256(b"version-one").hexdigest()
    assert checkpoint["best_source_sha256"] == best_hash
    snapshot = repo / "build" / checkpoint["best_source_snapshot"]
    assert snapshot.read_text(encoding="utf-8") == "version-one"

    next_claim = store.claim_next("openai", "openai")
    assert next_claim is not None
    runner._restore_best_source(worktree, next_claim)
    assert (worktree / "decomp/src/eboot/func_00001000.c").read_text(encoding="utf-8") == "version-one"


def test_two_simulated_sessions_handle_distinct_tasks_and_quota_fallback(
    tmp_path: Path,
) -> None:
    db = tmp_path / "campaign.sqlite3"
    store = CampaignStore(db)
    store.seed(
        [
            candidate("0x1000", preferred_provider="opencode"),
            candidate("0x2000", preferred_provider="openai"),
        ]
    )

    simulator = tmp_path / "fake_opencode.py"
    simulator.write_text(
        "import json, sys, time\n"
        "args = sys.argv[1:]\n"
        "model = args[args.index('--model') + 1]\n"
        "time.sleep(0.08)\n"
        "if model.startswith('opencode/'):\n"
        " sys.stderr.write('insufficient_quota token=sk-supersecret')\n"
        " raise SystemExit(1)\n"
        "text = json.dumps({'checkpoint': {'next_experiment': 'retry from saved source'}})\n"
        "print(json.dumps({'type': 'text', 'text': text}))\n",
        encoding="utf-8",
    )
    worktrees = {name: tmp_path / name for name in ("deepseek", "openai")}
    for path in worktrees.values():
        path.mkdir()

    def verifier(worktree: Path, task: Candidate, _checkpoint: dict[str, object]):
        report = strict_report(task.address)
        return {
            "status": "MATCHED",
            "source_sha256": report["provenance"]["source_sha256"],
            "matching_words": 4,
            "total_words": 4,
            "build_sha256": [report["provenance"]["object_sha256"], report["provenance"]["object_sha256"]],
            "reports": [report, report],
        }

    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path, simulator),
        worktrees=worktrees,
        verifier=verifier,
        timeout_seconds=5,
    )
    result = runner.run(
        [
            Worker("deepseek", "opencode", "opencode/deepseek-v4.1-flash-free"),
            Worker("openai", "openai", "openai/gpt-6-luna"),
        ],
        max_tasks=4,
    )

    assert result["attempted"] == 3
    assert store.get_task("0x1000")["status"] == "matched"
    assert store.get_task("0x2000")["status"] == "matched"
    attempts = store.list_attempts()
    first_claims = [item for item in attempts if item["attempt_number"] == 1]
    assert {item["address"] for item in first_claims} == {"0x1000", "0x2000"}
    assert {item["worker_id"] for item in first_claims} == {"deepseek", "openai"}
    fallback = [item for item in attempts if item["address"] == "0x1000"]
    assert [item["provider"] for item in fallback] == ["opencode", "openai"]
    assert store.provider_status("opencode") == "suspended_quota"

    # Raw provider output is never persisted to the local event/attempt ledger.
    persisted = b"".join(p.read_bytes() for p in tmp_path.glob("campaign.sqlite3*"))
    assert b"sk-supersecret" not in persisted
