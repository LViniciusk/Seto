"""Persistent campaign orchestration, failure policy, and safety regressions."""

from __future__ import annotations

import json
import hashlib
import subprocess
import sys
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import decomp_campaign as decomp_campaign_module  # noqa: E402
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
    select_ready_workers,
    validated_cached_ghidra_boundary,
    worker_agent_policy_is_restricted,
    worker_readiness,
    _opencode_preflight,
    _append_promotion_documentation,
    _promotion_context,
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


def strict_report(address: str = "0x1000", *, word_count: int = 4) -> dict[str, object]:
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
            "matching_words": word_count,
            "total_words": word_count,
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
        " agent = payload.get('agent')\n"
        " model = payload.get('model')\n"
        " state['sessions'][session_id] = {'location': location, 'agent': agent, 'model': model}\n"
        " state['created'].append(session_id)\n"
        " save(); print(json.dumps({'data': {'id': session_id, 'location': {'directory': location}, 'agent': agent, 'model': model}})); raise SystemExit(0)\n"
        "if args[:2] == ['api', 'get'] and args[2].startswith('/api/session/'):\n"
        " session_id = args[2].rsplit('/', 1)[-1]\n"
        " if session_id not in state['sessions']:\n"
        "  sys.stdout.write('{\"_tag\":\"SessionNotFoundError\"}\\n')\n"
        "  sys.stderr.write('HTTP 404 Not Found\\n')\n"
        "  raise SystemExit(1)\n"
        " print(json.dumps({'data': {'id': session_id, 'location': {'directory': state['sessions'][session_id]['location']}, 'agent': state['sessions'][session_id].get('agent'), 'model': state['sessions'][session_id].get('model')}})); raise SystemExit(0)\n"
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


def promotable_campaign(
    tmp_path: Path, *, certified_retry: bool = True
) -> tuple[CampaignStore, dict[str, object], Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    store = CampaignStore(repo / "build" / "campaign.sqlite3")
    store.seed(
        [
            Candidate(
                address="0x1000",
                size_bytes=28 * 4,
                nid="0x12345678",
                priority=50,
                boundary_status="EXACT",
                evidence={"source": "tied certification test"},
            )
        ]
    )
    claim = store.claim_next("openai", "openai")
    assert claim is not None
    claim = store.bind_session(claim, "ses_test_nonmatching")

    worker_root = campaign_build_path(repo, "decomp-campaign/worktrees/openai")
    log_relative = "decomp-campaign/openai/1000/evidence/ghidra-attempt-1.log"
    log_path = campaign_build_path(worker_root, log_relative)
    log_path.parent.mkdir(parents=True)
    log_text = ghidra_log(end=0x1070, body_addresses=28 * 4, instruction_count=28)
    log_path.write_text(log_text, encoding="utf-8")
    log_hash = hashlib.sha256(log_path.read_bytes()).hexdigest()
    boundary = validate_ghidra_log(log_text, 0x1000)
    checkpoint = {
        "ghidra_log_path": log_relative,
        "ghidra_log_sha256": log_hash,
        "boundary_status": "EXACT",
    }

    source_hash = ""
    attempt_statuses = ["NONMATCHING", "MATCHED"] if certified_retry else ["NONMATCHING"]
    for attempt_index, attempt_status in enumerate(attempt_statuses, start=1):
        source_content = (
            b"int func_00001000(void) { return -1; }\n"
            if attempt_status == "NONMATCHING"
            else b"int func_00001000(void) { return 1; }\n"
        )
        source_hash = hashlib.sha256(source_content).hexdigest()
        source_relative = f"decomp-campaign/checkpoints/00001000/{source_hash}.c"
        source_path = campaign_build_path(repo, source_relative)
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_bytes(source_content)

        reports = [strict_report(word_count=28), strict_report(word_count=28)]
        for report in reports:
            report["provenance"]["source_sha256"] = source_hash  # type: ignore[index]
        if attempt_status == "NONMATCHING":
            for report in reports:
                report["status"] = "NONMATCHING"
                report["verified_decompilation"] = False
                report["match"]["status"] = "NONMATCHING"  # type: ignore[index]
                report["match"]["limitations"] = ["relocation evidence is incomplete"]  # type: ignore[index]
                report["match"]["relocation_issues"] = ["unresolved relocation"]  # type: ignore[index]

        result = {
            "status": attempt_status,
            "source_sha256": source_hash,
            "source_snapshot_path": source_relative,
            "ghidra_log_sha256": log_hash,
            "ghidra_boundary": boundary,
            "matching_words": 28,
            "total_words": 28,
            "build_sha256": ["b" * 64, "b" * 64],
            "reports": reports,
        }
        store.save_checkpoint(claim, checkpoint, trusted_evidence=True)
        assert store.complete(
            claim,
            checkpoint,
            result,
            max_attempts_without_progress=3,
            max_attempts_per_candidate=8,
        ) == ("matched" if attempt_status == "MATCHED" else "pending")

        if attempt_index < len(attempt_statuses):
            claim = store.claim_next("openai", "openai")
            assert claim is not None
            claim = store.bind_session(claim, "ses_test_promotion")

    eboot_path = repo / "private" / "decrypted" / "ULUS10136_EBOOT.elf"
    eboot_path.parent.mkdir(parents=True)
    eboot_path.write_bytes(b"test eboot")
    triage_path = repo / "build" / "seto035" / "export-triage.json"
    triage_path.parent.mkdir(parents=True)
    triage_path.write_text(
        json.dumps(
            {
                "exports": [
                    {
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
                ]
            }
        ),
        encoding="utf-8",
    )
    config: dict[str, object] = {
        "workers": {"openai": {"provider": "openai"}},
        "worktrees": {"root": "build/decomp-campaign/worktrees"},
        "inputs": {
            "eboot": "private/decrypted/ULUS10136_EBOOT.elf",
            "eboot_sha256": hashlib.sha256(eboot_path.read_bytes()).hexdigest(),
            "triage_report": "build/seto035/export-triage.json",
        },
    }
    return store, config, repo, source_hash


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
    assert config["execution"]["pilot_verified"] is False
    assert config["execution"]["productive_expansion_authorized"] is False
    assert config["pilot"]["max_tasks"] == 4
    assert config["pilot"]["max_duration_seconds"] == 1800
    assert config["pilot"]["candidate_addresses"] == ["0x2c28c", "0x4217c"]
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

    malformed = strict_report()
    malformed["provenance"] = None
    assert not is_strict_match(malformed, expected_address=0x1000, expected_size=16)

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


def test_cached_ghidra_evidence_is_reused_only_when_bound_to_address_and_hash(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])
    claim = store.claim_next("openai", "openai")
    assert claim is not None
    worktree = tmp_path / "worker"
    log_relative = "decomp-campaign/openai/1000/evidence/ghidra-attempt-1.log"
    log_path = campaign_build_path(worktree, log_relative)
    log_path.parent.mkdir(parents=True)
    log_path.write_text(ghidra_log(), encoding="utf-8")
    digest = hashlib.sha256(log_path.read_bytes()).hexdigest()
    cached = replace(
        claim,
        checkpoint={
            "ghidra_log_path": log_relative,
            "ghidra_log_sha256": digest,
        },
    )

    assert validated_cached_ghidra_boundary(worktree, cached)["size_bytes"] == 16  # type: ignore[index]
    log_path.write_text(ghidra_log(end=0x1020), encoding="utf-8")
    with pytest.raises(ValueError, match="hash"):
        validated_cached_ghidra_boundary(worktree, cached)
    unsafe = replace(cached, checkpoint={**cached.checkpoint, "ghidra_log_path": "../../outside.log"})
    with pytest.raises(ValueError, match="outside"):
        validated_cached_ghidra_boundary(worktree, unsafe)


def test_promotion_preflight_checks_snapshots_reports_ghidra_and_conflicts(tmp_path: Path) -> None:
    store, config, repo, source_hash = promotable_campaign(tmp_path)
    context = _promotion_context(store, repo, config, "0x1000")  # type: ignore[arg-type]
    assert context["source_hash"] == source_hash
    assert context["origin"]["session_id"] == "ses_test_promotion"

    context["destination"].parent.mkdir(parents=True, exist_ok=True)
    context["destination"].write_text("conflicting certified source", encoding="utf-8")
    with pytest.raises(ValueError, match="conflicts"):
        _promotion_context(store, repo, config, "0x1000")  # type: ignore[arg-type]


def test_equal_score_certification_replaces_best_attempt_and_is_promotable(
    tmp_path: Path,
) -> None:
    store, config, repo, certified_hash = promotable_campaign(tmp_path)
    task = store.get_task("0x1000")
    result = task["best_result"]
    checkpoint = task["checkpoint"]

    assert task["status"] == "matched"
    assert task["attempts_without_progress"] == 0
    assert result["status"] == "MATCHED"
    assert result["source_sha256"] == certified_hash
    assert result["campaign_origin"] == {
        "attempt_number": 2,
        "worker_id": "openai",
        "provider": "openai",
        "session_id": "ses_test_promotion",
    }
    assert result["build_sha256"] == ["b" * 64, "b" * 64]
    assert all(
        report["provenance"]["source_sha256"] == certified_hash
        for report in result["reports"]
    )
    assert checkpoint["best_source_sha256"] == certified_hash
    assert checkpoint["best_match"]["status"] == "MATCHED"
    assert checkpoint["best_match"]["source_sha256"] == certified_hash
    assert checkpoint["best_match"]["object_sha256"] == "b" * 64
    snapshot = campaign_build_path(repo, checkpoint["best_source_snapshot"])
    assert hashlib.sha256(snapshot.read_bytes()).hexdigest() == certified_hash

    context = _promotion_context(store, repo, config, "0x1000")  # type: ignore[arg-type]
    assert context["source_hash"] == certified_hash
    assert context["origin"] == result["campaign_origin"]


def test_28_of_28_nonmatching_best_attempt_is_not_promotable(tmp_path: Path) -> None:
    store, config, repo, _source_hash = promotable_campaign(
        tmp_path, certified_retry=False
    )
    task = store.get_task("0x1000")

    assert task["status"] == "pending"
    assert task["best_result"]["status"] == "NONMATCHING"
    assert task["best_result"]["matching_words"] == 28
    with pytest.raises(ValueError, match="MATCHED"):
        _promotion_context(store, repo, config, "0x1000")  # type: ignore[arg-type]


def test_promotion_rejects_nonmatched_and_corrupt_checkpoint_sources(tmp_path: Path) -> None:
    empty = CampaignStore(tmp_path / "empty.sqlite3")
    empty.seed([candidate("0x1000")])
    with pytest.raises(ValueError, match="MATCHED"):
        _promotion_context(empty, tmp_path, {}, "0x1000")

    store, config, repo, _source_hash = promotable_campaign(tmp_path / "corrupt")
    task = store.get_task("0x1000")
    snapshot = campaign_build_path(repo, task["checkpoint"]["best_source_snapshot"])
    snapshot.write_text("modified after certification", encoding="utf-8")
    with pytest.raises(ValueError, match="hash"):
        _promotion_context(store, repo, config, "0x1000")  # type: ignore[arg-type]


def test_promotion_rejects_missing_checkpoint_provenance(tmp_path: Path) -> None:
    store, config, repo, _source_hash = promotable_campaign(tmp_path)
    with store._connect() as db:
        db.execute("UPDATE candidates SET checkpoint_json='{}' WHERE address='0x1000'")
    with pytest.raises(ValueError, match="best-source"):
        _promotion_context(store, repo, config, "0x1000")  # type: ignore[arg-type]


def test_promotion_documentation_is_idempotent_and_keeps_session_and_hash(tmp_path: Path) -> None:
    progress = tmp_path / "docs" / "decomp-progress.md"
    progress.parent.mkdir()
    progress.write_text("# Progress\n", encoding="utf-8")
    record = {
        "address": "0x1000",
        "size_bytes": 16,
        "source_sha256": "a" * 64,
        "object_sha256": ["b" * 64, "b" * 64],
        "worker_id": "openai",
        "session_id": "ses_test_promotion",
    }

    _append_promotion_documentation(tmp_path, record)
    _append_promotion_documentation(tmp_path, record)
    text = progress.read_text(encoding="utf-8")
    assert text.count("`0x1000`") == 1
    assert "ses_test_promotion" in text
    assert "`" + "a" * 64 + "`" in text


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

    bound = runner._ensure_session(
        claim,
        worktree,
        None,
        agent="seto-decomp-worker",
        model="openai/gpt-6-luna",
    )
    assert bound.session_id.startswith("ses_test")
    assert store.get_task("0x1000")["session_id"] == bound.session_id
    assert store.list_attempts()[0]["session_id"] == bound.session_id
    session = json.loads((worktree / ".fake-opencode-sessions.json").read_text())[
        "sessions"][bound.session_id]
    assert session["agent"] == "seto-decomp-worker"
    assert session["model"] == {"providerID": "openai", "id": "gpt-6-luna"}
    argv = runner._argv(Worker("worker", "openai", "openai/gpt-6-luna"), bound, "prompt")
    assert argv[argv.index("--session") + 1] == bound.session_id
    assert argv[argv.index("--agent") + 1] == "seto-decomp-worker"


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


def test_resume_replaces_session_that_was_created_with_broad_agent(tmp_path: Path) -> None:
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
    assert bound.session_id is not None
    state_path = worktree / ".fake-opencode-sessions.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["sessions"][bound.session_id]["agent"] = "build"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    store.fail(bound, Failure(FailureKind.INTERRUPTED))

    resumed = store.claim_next("worker", "openai")
    assert resumed is not None
    replacement = runner._ensure_session(resumed, worktree, None)
    assert replacement.session_id != bound.session_id
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["sessions"][replacement.session_id]["agent"] == "seto-decomp-worker"


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
    runner.run([Worker("openai", "openai", "openai/gpt-6-luna")], max_tasks=2)
    attempts = store.list_attempts()
    assert attempts[1]["outcome"] == "matched"
    assert attempts[0]["session_id"] == attempts[1]["session_id"]
    assert all(task["status"] != "running" for task in store.list_tasks())


def test_fast_worker_claims_another_task_before_slow_worker_finishes(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed(
        [
            candidate("0x1000", preferred_provider="openai"),
            candidate("0x2000", preferred_provider="opencode"),
            candidate("0x3000", preferred_provider="openai"),
        ]
    )
    events = tmp_path / "events"
    events.mkdir()
    simulator = tmp_path / "timed_worker.py"
    simulator.write_text(
        "import json, pathlib, sys, time\n"
        "args = sys.argv[1:]\n"
        "title = args[args.index('--title') + 1].split()\n"
        "address, worker = title[2], title[3]\n"
        f"events = pathlib.Path({str(events)!r})\n"
        "events.joinpath(f'{worker}-{address}-start').write_text(str(time.time_ns()))\n"
        "if worker == 'slow': time.sleep(1.5)\n"
        "events.joinpath(f'{worker}-{address}-done').write_text(str(time.time_ns()))\n"
        "print(json.dumps({'type':'text','text':json.dumps({'checkpoint':{'next_experiment':'continue'}})}))\n",
        encoding="utf-8",
    )
    worktrees = {name: tmp_path / name for name in ("fast", "slow")}
    for worktree in worktrees.values():
        worktree.mkdir()

    def verifier(_worktree: Path, task: Candidate, _checkpoint: dict[str, object]):
        report = strict_report(task.address)
        return {
            "status": "MATCHED",
            "source_sha256": report["provenance"]["source_sha256"],
            "matching_words": 4,
            "total_words": 4,
            "build_sha256": [report["provenance"]["object_sha256"]] * 2,
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
            Worker("fast", "openai", "openai/gpt-6-luna"),
            Worker("slow", "opencode", "opencode/deepseek-v4.1-flash-free"),
        ],
        max_tasks=3,
    )

    fast_next = events / "fast-0x3000-start"
    slow_done = events / "slow-0x2000-done"
    assert result["attempted"] == 3
    assert fast_next.is_file() and slow_done.is_file()
    assert fast_next.stat().st_mtime_ns < slow_done.stat().st_mtime_ns
    attempts = store.list_attempts()
    assert len(attempts) == 3
    assert len({attempt["address"] for attempt in attempts}) == 3


def test_pilot_candidate_filter_does_not_drain_the_rest_of_inventory(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000"), candidate("0x2000"), candidate("0x3000")])
    worktree = tmp_path / "worker"
    worktree.mkdir()

    def verifier(_worktree: Path, task: Candidate, _checkpoint: dict[str, object]):
        report = strict_report(task.address)
        return {
            "status": "MATCHED",
            "source_sha256": report["provenance"]["source_sha256"],
            "matching_words": 4,
            "total_words": 4,
            "build_sha256": [report["provenance"]["object_sha256"]] * 2,
            "reports": [report, report],
        }

    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path),
        worktrees={"openai": worktree},
        verifier=verifier,
        candidate_addresses=["0x2000"],
    )
    result = runner.run([Worker("openai", "openai", "openai/gpt-6-luna")], max_tasks=4)

    assert result["attempted"] == 1
    assert [attempt["address"] for attempt in store.list_attempts()] == ["0x2000"]
    assert store.get_task("0x1000")["status"] == "pending"
    assert store.get_task("0x3000")["status"] == "pending"


def test_campaign_attempt_limit_is_atomic_across_joining_runners(tmp_path: Path) -> None:
    database = tmp_path / "campaign.sqlite3"
    store = CampaignStore(database)
    store.seed([candidate(f"0x{0x1000 + index * 0x10:x}") for index in range(8)])

    def verifier(_worktree: Path, task: Candidate, _checkpoint: dict[str, object]):
        report = strict_report(task.address)
        return {
            "status": "MATCHED",
            "source_sha256": report["provenance"]["source_sha256"],
            "matching_words": 4,
            "total_words": 4,
            "build_sha256": [report["provenance"]["object_sha256"]] * 2,
            "reports": [report, report],
        }

    runners = []
    for name, provider, model in (
        ("join-openai", "openai", "openai/gpt-6-luna"),
        ("join-opencode", "opencode", "opencode/deepseek-v4.1-flash-free"),
    ):
        worktree = tmp_path / name
        worktree.mkdir()
        runners.append(
            (
                CampaignRunner(
                    CampaignStore(database),
                    opencode_command=fake_opencode_command(tmp_path),
                    worktrees={name: worktree},
                    verifier=verifier,
                    timeout_seconds=5,
                ),
                [Worker(name, provider, model)],
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(runner.run, workers, max_tasks=3) for runner, workers in runners]
        results = [future.result(timeout=20) for future in futures]

    assert sum(result["attempted"] for result in results) == 3
    assert len(store.list_attempts()) == 3
    assert all(task["status"] != "running" for task in store.list_tasks())


def test_provider_preflight_selects_only_verified_free_worker() -> None:
    config = {
        "workers": {
            "openai": {
                "provider": "openai",
                "model": "openai/gpt-6-luna",
                "agent": "seto-decomp-worker",
                "usage_mode": "unknown",
                "access_verified": False,
            },
            "deepseek": {
                "provider": "opencode",
                "model": "opencode/deepseek-v4.1-flash-free",
                "agent": "seto-decomp-worker",
                "usage_mode": "free",
                "access_verified": True,
                "free_model_only": True,
            },
        },
        "models": {
            "allowlist": [
                "openai/gpt-6-luna",
                "opencode/deepseek-v4.1-flash-free",
            ]
        },
    }
    observed = {
        "openai": {"catalog": "available", "auth": "stored", "agent_policy": True},
        "deepseek": {
            "catalog": "available",
            "auth": "public",
            "public_model_metadata": True,
            "model_status": "active",
            "model_enabled": True,
            "model_cost_zero": True,
            "agent_policy": True,
        },
    }

    states = {
        name: worker_readiness(worker, observed[name], config["models"]["allowlist"])
        for name, worker in config["workers"].items()
    }
    selected = select_ready_workers(config["workers"], states, max_workers=2)

    assert states["openai"]["ready"] is False
    assert "usage_mode_unverified" in states["openai"]["blockers"]
    assert states["deepseek"]["ready"] is True
    assert selected == ["deepseek"]


def _preflight_model(
    provider: str,
    model_id: str,
    *,
    api_key: str | None = None,
    status: str = "active",
    enabled: bool = True,
    cost: object | None = None,
) -> dict[str, object]:
    return {
        "providerID": provider,
        "id": model_id,
        "settings": {"apiKey": api_key} if api_key is not None else {},
        "status": status,
        "enabled": enabled,
        "cost": (
            cost
            if cost is not None
            else [{"input": 0, "output": 0, "cache": {"read": 0, "write": 0}}]
        ),
    }


def _mock_opencode_preflight(
    monkeypatch: pytest.MonkeyPatch,
    models: list[dict[str, object]],
    *,
    api_stdout: str | None = None,
    auth_payload: object | None = None,
    provider_payload: object | None = None,
    integration_payload: object | None = None,
    worker_overrides: dict[str, object] | None = None,
    agent_policy: bool = True,
) -> dict[str, object]:
    config = {
        "opencode": {"command": ["opencode-test-double"]},
        "models": {
            "allowlist": [
                "openai/gpt-6-luna",
                "opencode/deepseek-v4.1-flash-free",
            ]
        },
        "workers": {
            "openai": {
                "provider": "openai",
                "model": "openai/gpt-6-luna",
                "agent": "seto-decomp-worker",
                "usage_mode": "unknown",
                "access_verified": False,
                **(worker_overrides or {}),
            },
            "deepseek": {
                "provider": "opencode",
                "model": "opencode/deepseek-v4.1-flash-free",
                "agent": "seto-decomp-worker",
                "usage_mode": "free",
                "access_verified": True,
                "free_model_only": True,
            },
        },
    }
    auth_payload = auth_payload if auth_payload is not None else [
        {
            "id": "openai",
            "name": "OpenAI",
            "connections": [
                {"id": "cred_test", "label": "primary", "method": "oauth", "type": "credential"}
            ],
        }
    ]
    provider_payload = provider_payload if provider_payload is not None else {
        "data": {
            "id": "openai",
            "package": "@opencode/ai/providers/openai",
            "activation": "auto",
            "settings": {"baseURL": "https://api.openai.com/v1"},
        }
    }
    integration_payload = integration_payload if integration_payload is not None else {
        "data": {
            "id": "openai",
            "methods": [
                {"id": "key", "type": "key"},
                {"id": "env", "type": "env"},
                {"id": "chatgpt-token-sharing", "type": "oauth"},
                {"id": "chatgpt-browser", "type": "oauth"},
                {"id": "chatgpt-headless", "type": "oauth"},
            ],
        }
    }

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        if command[1:] == ["models"]:
            stdout = "openai/gpt-6-luna\nopencode/deepseek-v4.1-flash-free\n"
        elif command[1:] in (["auth", "list"], ["auth", "list", "--format", "json"]):
            stdout = json.dumps(auth_payload)
        elif command[1:] == ["api", "get", "/api/model"]:
            stdout = api_stdout if api_stdout is not None else json.dumps({"data": models})
        elif command[1:] == ["api", "get", "/api/provider/openai"]:
            stdout = json.dumps(provider_payload)
        elif command[1:] == ["api", "get", "/api/integration/openai"]:
            stdout = json.dumps(integration_payload)
        elif command[1:] == ["debug", "agents"]:
            stdout = "[]"
        else:
            raise AssertionError(f"unexpected OpenCode command: {command}")
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(decomp_campaign_module.subprocess, "run", fake_run)
    monkeypatch.setattr(
        decomp_campaign_module,
        "worker_agent_policy_is_restricted",
        lambda *_args: agent_policy,
    )
    result = _opencode_preflight(config, Path.cwd())
    return result["workers"]  # type: ignore[return-value]


def test_public_zero_cost_deepseek_metadata_is_ready_without_stored_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _preflight_model(
        "opencode", "deepseek-v4.1-flash-free", api_key="public"
    )
    workers = _mock_opencode_preflight(monkeypatch, [model])

    assert workers["deepseek"]["auth"] == "public"
    assert workers["deepseek"]["ready"] is True
    assert workers["deepseek"]["blockers"] == []


def test_public_deepseek_with_nonzero_cost_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _preflight_model(
        "opencode",
        "deepseek-v4.1-flash-free",
        api_key="public",
        cost=[{"input": 0, "output": 0.01, "cache": {"read": 0, "write": 0}}],
    )
    workers = _mock_opencode_preflight(monkeypatch, [model])

    assert workers["deepseek"]["ready"] is False


@pytest.mark.parametrize(
    "case",
    [
        "disabled",
        "inactive",
        "absent",
        "invalid-json",
        "wrong-provider",
        "duplicate",
        "missing-cost-fields",
    ],
)
def test_deepseek_missing_or_invalid_model_metadata_is_blocked(
    monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    target = _preflight_model(
        "opencode",
        "deepseek-v4.1-flash-free",
        api_key="public",
        status="inactive" if case == "inactive" else "active",
        enabled=False if case == "disabled" else True,
    )
    if case == "absent":
        models = []
    elif case == "wrong-provider":
        models = [{**target, "providerID": "other-provider"}]
    elif case == "duplicate":
        models = [target, target]
    elif case == "missing-cost-fields":
        target["cost"] = [{"input": 0, "output": 0, "cache": {"read": 0}}]
        models = [target]
    else:
        models = [target]
    workers = _mock_opencode_preflight(
        monkeypatch,
        models,
        api_stdout="not valid JSON" if case == "invalid-json" else None,
    )

    assert workers["deepseek"]["ready"] is False


def test_openai_without_verified_no_additional_cost_stays_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    openai = _preflight_model("openai", "gpt-6-luna", cost=[])
    deepseek = _preflight_model(
        "opencode", "deepseek-v4.1-flash-free", api_key="public"
    )
    workers = _mock_opencode_preflight(monkeypatch, [openai, deepseek])

    assert workers["openai"]["auth"] == "stored"
    assert workers["openai"]["ready"] is False
    assert "additional_cost_not_excluded" in workers["openai"]["blockers"]


@pytest.mark.parametrize(
    "method",
    ["chatgpt-token-sharing", "chatgpt-browser", "chatgpt-headless"],
)
def test_confirmed_chatgpt_oauth_and_default_route_make_openai_ready(
    monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    openai = _preflight_model("openai", "gpt-6-luna", cost=[])
    deepseek = _preflight_model("opencode", "deepseek-v4.1-flash-free", api_key="public")
    workers = _mock_opencode_preflight(
        monkeypatch,
        [openai, deepseek],
        worker_overrides={
            "usage_mode": "subscription_included",
            "access_verified": True,
            "auth_method_confirmed": method,
        },
    )

    assert workers["openai"]["ready"] is True
    assert workers["openai"]["blockers"] == []
    assert workers["openai"]["chatgpt_oauth_verified"] is True
    assert workers["openai"]["model_status"] == "active"
    assert workers["openai"]["model_enabled"] is True
    assert workers["openai"]["model_cost_zero"] is False  # Empty catalog cost is not proof.
    assert workers["deepseek"]["ready"] is True


@pytest.mark.parametrize(
    ("stored_method", "confirmed_method"),
    [
        ("key", "chatgpt-token-sharing"),
        ("oauth", "unknown-oauth-method"),
        ("oauth", None),
    ],
)
def test_openai_api_key_unknown_or_unconfirmed_oauth_stays_blocked(
    monkeypatch: pytest.MonkeyPatch,
    stored_method: str,
    confirmed_method: str | None,
) -> None:
    model = _preflight_model("openai", "gpt-6-luna", cost=[])
    overrides: dict[str, object] = {
        "usage_mode": "subscription_included",
        "access_verified": True,
    }
    if confirmed_method is not None:
        overrides["auth_method_confirmed"] = confirmed_method
    workers = _mock_opencode_preflight(
        monkeypatch,
        [model],
        auth_payload=[
            {
                "id": "openai",
                "connections": [
                    {"id": "cred_test", "label": "primary", "method": stored_method, "type": "credential"}
                ],
            }
        ],
        worker_overrides=overrides,
    )

    assert workers["openai"]["ready"] is False
    assert workers["openai"]["chatgpt_oauth_verified"] is False
    assert "chatgpt_subscription_auth_unverified" in workers["openai"]["blockers"]


@pytest.mark.parametrize(
    "connections",
    [
        [{"id": "env", "label": "environment", "method": "env", "type": "environment"}],
        [
            {"id": "oauth-a", "label": "one", "method": "oauth", "type": "credential"},
            {"id": "oauth-b", "label": "two", "method": "oauth", "type": "credential"},
        ],
    ],
)
def test_openai_environment_or_ambiguous_accounts_cannot_prove_subscription(
    monkeypatch: pytest.MonkeyPatch,
    connections: list[dict[str, str]],
) -> None:
    workers = _mock_opencode_preflight(
        monkeypatch,
        [_preflight_model("openai", "gpt-6-luna", cost=[])],
        auth_payload=[{"id": "openai", "connections": connections}],
        worker_overrides={
            "usage_mode": "subscription_included",
            "access_verified": True,
            "auth_method_confirmed": "chatgpt-token-sharing",
        },
    )

    assert workers["openai"]["ready"] is False
    assert workers["openai"]["chatgpt_oauth_verified"] is False
    assert "chatgpt_subscription_auth_unverified" in workers["openai"]["blockers"]


def test_openai_custom_gateway_is_rejected_even_with_chatgpt_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _preflight_model("openai", "gpt-6-luna", cost=[])
    provider = {
        "data": {
            "id": "openai",
            "package": "@opencode/ai/providers/openai",
            "activation": "auto",
            "settings": {"baseURL": "https://gateway.example.test/v1"},
        }
    }
    workers = _mock_opencode_preflight(
        monkeypatch,
        [model],
        provider_payload=provider,
        worker_overrides={
            "usage_mode": "subscription_included",
            "access_verified": True,
            "auth_method_confirmed": "chatgpt-token-sharing",
        },
    )

    assert workers["openai"]["ready"] is False
    assert "provider_route_not_subscription_compatible" in workers["openai"]["blockers"]


def test_openai_model_level_gateway_override_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _preflight_model("openai", "gpt-6-luna", cost=[])
    model["settings"] = {"baseURL": "https://model-gateway.example.test/v1"}
    workers = _mock_opencode_preflight(
        monkeypatch,
        [model],
        worker_overrides={
            "usage_mode": "subscription_included",
            "access_verified": True,
            "auth_method_confirmed": "chatgpt-token-sharing",
        },
    )

    assert workers["openai"]["ready"] is False
    assert "provider_route_not_subscription_compatible" in workers["openai"]["blockers"]


def test_openai_provider_api_key_override_is_rejected_with_chatgpt_oauth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _preflight_model("openai", "gpt-6-luna", cost=[])
    provider = {
        "data": {
            "id": "openai",
            "package": "@opencode/ai/providers/openai",
            "activation": "auto",
            "settings": {
                "baseURL": "https://api.openai.com/v1",
                "apiKey": "configured",
            },
        }
    }
    workers = _mock_opencode_preflight(
        monkeypatch,
        [model],
        provider_payload=provider,
        worker_overrides={
            "usage_mode": "subscription_included",
            "access_verified": True,
            "auth_method_confirmed": "chatgpt-token-sharing",
        },
    )

    assert workers["openai"]["ready"] is False
    assert "provider_route_not_subscription_compatible" in workers["openai"]["blockers"]


@pytest.mark.parametrize(
    ("status", "enabled", "expected_blocker"),
    [
        ("inactive", True, "model_not_active"),
        ("active", False, "model_disabled_or_unverified"),
    ],
)
def test_openai_unavailable_model_or_unrestricted_agent_blocks_readiness(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    enabled: bool,
    expected_blocker: str,
) -> None:
    model = _preflight_model("openai", "gpt-6-luna", status=status, enabled=enabled, cost=[])
    worker = {
        "usage_mode": "subscription_included",
        "access_verified": True,
        "auth_method_confirmed": "chatgpt-token-sharing",
    }
    unavailable = _mock_opencode_preflight(monkeypatch, [model], worker_overrides=worker)
    assert unavailable["openai"]["ready"] is False
    assert expected_blocker in unavailable["openai"]["blockers"]

    denied = _mock_opencode_preflight(
        monkeypatch,
        [_preflight_model("openai", "gpt-6-luna", cost=[])],
        worker_overrides=worker,
        agent_policy=False,
    )
    assert denied["openai"]["ready"] is False
    assert "worker_permissions_not_restricted" in denied["openai"]["blockers"]


def test_two_ready_workers_are_selected_without_changing_pilot_scope_or_models() -> None:
    workers = {
        "openai": {"provider": "openai", "model": "openai/gpt-6-luna", "max_parallel": 1},
        "deepseek": {
            "provider": "opencode",
            "model": "opencode/deepseek-v4.1-flash-free",
            "max_parallel": 1,
        },
    }
    allowed_models = [worker["model"] for worker in workers.values()]
    candidates = ["0x2c28c", "0x4217c"]
    states = {name: {"ready": True} for name in workers}

    selected = select_ready_workers(workers, states, max_workers=2)

    assert selected == ["openai", "deepseek"]
    assert [worker["model"] for worker in workers.values()] == allowed_models
    assert [worker["max_parallel"] for worker in workers.values()] == [1, 1]
    assert candidates == ["0x2c28c", "0x4217c"]


def test_resumed_session_keeps_luna_model_and_restricted_agent(tmp_path: Path) -> None:
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
    bound = runner._ensure_session(
        claim,
        worktree,
        None,
        agent="seto-decomp-worker",
        model="openai/gpt-6-luna",
    )
    store.fail(bound, Failure(FailureKind.INTERRUPTED))

    resumed = store.claim_next("worker", "openai")
    assert resumed is not None
    reused = runner._ensure_session(
        resumed,
        worktree,
        None,
        agent="seto-decomp-worker",
        model="openai/gpt-6-luna",
    )

    assert reused.session_id == bound.session_id
    state = json.loads((worktree / ".fake-opencode-sessions.json").read_text())
    session = state["sessions"][reused.session_id]
    assert session["agent"] == "seto-decomp-worker"
    assert session["model"] == {"providerID": "openai", "id": "gpt-6-luna"}


@pytest.mark.parametrize(("variant", "should_reuse"), [("default", True), ("extended", False)])
def test_resumed_session_validates_opencode_model_variant_metadata(
    tmp_path: Path, variant: str, should_reuse: bool
) -> None:
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
    bound = runner._ensure_session(
        claim,
        worktree,
        None,
        agent="seto-decomp-worker",
        model="openai/gpt-6-luna",
    )
    state_path = worktree / ".fake-opencode-sessions.json"
    state = json.loads(state_path.read_text())
    state["sessions"][bound.session_id]["model"]["variant"] = variant
    state_path.write_text(json.dumps(state))
    store.fail(bound, Failure(FailureKind.INTERRUPTED))

    resumed = store.claim_next("worker", "openai")
    assert resumed is not None
    reused = runner._ensure_session(
        resumed,
        worktree,
        None,
        agent="seto-decomp-worker",
        model="openai/gpt-6-luna",
    )

    updated = json.loads(state_path.read_text())
    assert (reused.session_id == bound.session_id) is should_reuse
    assert len(updated["created"]) == (1 if should_reuse else 2)


def test_missing_restricted_worker_permissions_block_free_readiness() -> None:
    worker = {
        "provider": "opencode",
        "model": "opencode/deepseek-v4.1-flash-free",
        "usage_mode": "free",
        "access_verified": True,
        "free_model_only": True,
    }
    observed = {
        "catalog": "available",
        "auth": "public",
        "public_model_metadata": True,
        "model_status": "active",
        "model_enabled": True,
        "model_cost_zero": True,
        "agent_policy": False,
    }

    result = worker_readiness(
        worker, observed, ["opencode/deepseek-v4.1-flash-free"]
    )

    assert result["ready"] is False
    assert "worker_permissions_not_restricted" in result["blockers"]


def test_stored_auth_does_not_replace_public_model_metadata_for_free_worker() -> None:
    worker = {
        "provider": "opencode",
        "model": "opencode/deepseek-v4.1-flash-free",
        "usage_mode": "free",
        "access_verified": True,
        "free_model_only": True,
    }
    observed = {
        "catalog": "available",
        "auth": "stored",
        "public_model_metadata": False,
        "model_status": "active",
        "model_enabled": True,
        "model_cost_zero": True,
        "agent_policy": True,
    }

    result = worker_readiness(
        worker, observed, ["opencode/deepseek-v4.1-flash-free"]
    )

    assert result["ready"] is False
    assert "public_auth_metadata_unverified" in result["blockers"]


def test_single_worker_pilot_is_capped_at_two_attempts_and_keeps_candidates() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "config" / "decomp_campaign.toml")
    single_worker_limit = min(config["pilot"]["max_tasks"], 1 * 2)

    assert single_worker_limit == 2
    assert config["pilot"]["max_duration_seconds"] == 1800
    assert config["pilot"]["candidate_addresses"] == ["0x2c28c", "0x4217c"]


def test_worker_permission_audit_rejects_global_allow_and_shell_access() -> None:
    agent = {
        "id": "seto-decomp-worker",
        "permissions": [
            {"action": "*", "resource": "*", "effect": "allow"},
            {"action": "*", "resource": "*", "effect": "deny"},
            {"action": "read", "resource": "*", "effect": "allow"},
            {
                "action": "edit",
                "resource": "decomp/src/eboot/func_*.c",
                "effect": "allow",
            },
            {"action": "edit", "resource": "build/decomp-campaign/*", "effect": "allow"},
            {"action": "ai_memory_memory_query", "resource": "*", "effect": "allow"},
            {"action": "ai_memory_memory_read_page", "resource": "*", "effect": "allow"},
            {"action": "external_directory", "resource": "*", "effect": "deny"},
            {"action": "subagent", "resource": "*", "effect": "deny"},
            {"action": "read", "resource": "*.env", "effect": "deny"},
            {"action": "read", "resource": "*.env.*", "effect": "deny"},
        ],
    }
    assert worker_agent_policy_is_restricted([agent], "seto-decomp-worker")
    agent["permissions"].append({"action": "shell", "resource": "*", "effect": "allow"})
    assert not worker_agent_policy_is_restricted([agent], "seto-decomp-worker")
    assert not worker_agent_policy_is_restricted([], "missing-agent")


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
    task = store.get_task("0x1000")
    checkpoint = task["checkpoint"]
    best_hash = hashlib.sha256(b"version-one").hexdigest()
    assert checkpoint["best_source_sha256"] == best_hash
    assert task["best_result"]["source_sha256"] == best_hash
    assert task["best_result"]["matching_words"] == 2
    assert task["best_result"]["campaign_origin"]["attempt_number"] == 1
    assert checkpoint["best_match"]["source_sha256"] == best_hash
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
