"""Persistent campaign orchestration, failure policy, and safety regressions."""

from __future__ import annotations

import json
import hashlib
import subprocess
import sys
import threading
import time
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
    discover_proven_exports,
    is_strict_match,
    load_config,
    productive_candidate_selection,
    record_inventory_promotion,
    prepare_worker_worktrees,
    _assert_worker_changes_scoped,
    _extract_checkpoint,
    _explicit_inconclusive_match_report,
    _raise_matcher_process_error,
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


def operational_config_text(
    *, max_workers: str = "8", max_tasks: str = "261", duration: str = "21600"
) -> str:
    worker_sections = []
    for worker_id, provider, model in (
        *((f"luna-{index:02d}", "openai", "openai/gpt-6-luna") for index in range(1, 5)),
        *((f"deepseek-{index:02d}", "opencode", "opencode/deepseek-v4.1-flash-free") for index in range(1, 5)),
    ):
        usage_mode = "subscription_included" if provider == "openai" else "free"
        worker_sections.extend(
            [
                f"[workers.{worker_id}]",
                f'provider = "{provider}"',
                f'model = "{model}"',
                'agent = "seto-decomp-worker"',
                "max_parallel = 4",
                f'usage_mode = "{usage_mode}"',
            ]
        )
        if provider == "openai":
            worker_sections.append('auth_method_confirmed = "chatgpt-token-sharing"')
        else:
            worker_sections.append("free_model_only = true")
    return "\n".join(
        [
            "schema_version = 1",
            'inventory = "inventory.json"',
            'database = "build/campaign.sqlite3"',
            "",
            "[models]",
            'allowlist = ["openai/gpt-6-luna", "opencode/deepseek-v4.1-flash-free"]',
            "",
            *worker_sections,
            "",
            "[limits]",
            f"max_workers = {max_workers}",
            f"max_tasks = {max_tasks}",
            f"max_duration_seconds = {duration}",
            "lease_seconds = 3660",
            "agent_timeout_seconds = 900",
            "max_attempts_per_candidate = 8",
            "max_attempts_without_progress = 3",
            "max_output_bytes = 1048576",
            "max_retry_after_seconds = 900",
            "ghidra_parallelism = 2",
            "matcher_parallelism = 4",
            "",
            "[pilot]",
            "max_tasks = 4",
            "max_duration_seconds = 1800",
            'candidate_addresses = ["0x2c28c", "0x4217c"]',
        ]
    ) + "\n"


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


def detailed_ghidra_log() -> str:
    rows = [
        f"{line} nop" if line.startswith("SETO_INSN=") else line
        for line in ghidra_log().splitlines()
    ]
    rows.extend(
        [
            "SETO_DECOMP_C_BEGIN",
            "void func_00001000(void) {",
            "    return;",
            "}",
            "SETO_DECOMP_C_END",
        ]
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


def test_candidate_queue_gives_unattempted_functions_coverage_before_refinement(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "queue.sqlite3")
    store.seed(
        [
            Candidate("0x1000", 16, "0x11111111", 100, "EXACT"),
            Candidate("0x2000", 16, "0x22222222", 40, "EXACT"),
        ]
    )
    with store._connect() as db:
        db.execute(
            "UPDATE candidates SET attempt_count=1 WHERE address='0x1000'"
        )
        db.execute(
            "INSERT INTO attempts(address,attempt_number,worker_id,provider,session_id,started_at,ended_at,outcome) "
            "VALUES('0x1000',1,'luna-01','openai','ses_previous',1,2,'pending')"
        )

    claim = store.claim_next("luna-02", "openai")

    assert claim is not None
    assert claim.address == "0x2000"


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


def test_load_config_allows_operational_multi_instance_campaign_limits(tmp_path: Path) -> None:
    config_path = tmp_path / "campaign.toml"
    config_path.write_text(operational_config_text(), encoding="utf-8")

    config = load_config(config_path)

    assert len(config["workers"]) == 8
    assert len({worker["provider"] for worker in config["workers"].values()}) == 2
    assert len({worker["model"] for worker in config["workers"].values()}) == 2
    assert config["limits"]["max_workers"] == 8
    assert config["limits"]["max_tasks"] == 261
    assert config["limits"]["max_duration_seconds"] == 21600
    selected = select_ready_workers(
        config["workers"],
        {name: {"ready": True} for name in config["workers"]},
        max_workers=20,
    )
    assert len(selected) == 8
    assert selected[:4] == [f"luna-{index:02d}" for index in range(1, 5)]
    assert selected[4:] == [f"deepseek-{index:02d}" for index in range(1, 5)]


def test_load_config_has_no_permanent_worker_or_attempt_ceiling(tmp_path: Path) -> None:
    config_path = tmp_path / "campaign.toml"
    config_path.write_text(
        operational_config_text(max_workers="20", max_tasks="1000", duration="300000"),
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config["limits"]["max_workers"] == 20
    assert config["limits"]["max_tasks"] == 1000
    assert config["limits"]["max_duration_seconds"] == 300000


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("max_workers", "0"),
        ("max_workers", "1.5"),
        ("max_workers", "true"),
        ("max_tasks", "0"),
        ("max_duration_seconds", "0"),
        ("max_duration_seconds", "nan"),
    ],
)
def test_load_config_rejects_nonpositive_or_noninteger_operational_limits(
    tmp_path: Path, setting: str, value: str
) -> None:
    text = operational_config_text().replace(f"{setting} = 8", f"{setting} = {value}")
    text = text.replace(f"{setting} = 261", f"{setting} = {value}")
    text = text.replace(f"{setting} = 21600", f"{setting} = {value}")
    config_path = tmp_path / "campaign.toml"
    config_path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError):
        load_config(config_path)


def test_unverified_candidate_may_wait_for_ghidra_without_a_guessed_size() -> None:
    item = Candidate(
        address="0x1234",
        size_bytes=0,
        nid="0x12345678",
        priority=10,
        boundary_status="UNVERIFIED",
    )

    assert item.size_bytes == 0
    with pytest.raises(ValueError, match="EXACT"):
        Candidate(
            address="0x1234",
            size_bytes=0,
            nid="0x12345678",
            priority=10,
            boundary_status="EXACT",
        )


def test_export_discovery_requires_unique_relocated_nid_and_real_import_call_sites(
    tmp_path: Path,
) -> None:
    triage = {
        "exports": [
            {
                "address": "0x1000",
                "nid": "0x11111111",
                "library": "libehsys",
                "entry_index": 4,
                "slot_index": 2,
                "pointer_site": "0x5000",
                "pointer_relocation": {
                    "type": "R_MIPS_32",
                    "addend": 0x1000,
                    "addend_valid": True,
                    "application_valid": True,
                },
                "importers": [
                    {"module": "libtutoriallist.prx", "call_sites": ["0x20"], "table_limitations": []}
                ],
            },
            {
                "address": "0x2000",
                "nid": "0x22222222",
                "library": "libehsys",
                "pointer_relocation": {
                    "type": "R_MIPS_32",
                    "addend": 0x2000,
                    "addend_valid": True,
                    "application_valid": True,
                },
                "importers": [{"module": "libhtml_view.prx", "call_sites": ["0x24"], "table_limitations": []}],
            },
            {
                "address": "0x3000",
                "nid": "0x22222222",
                "library": "libehsys",
                "pointer_relocation": {
                    "type": "R_MIPS_32",
                    "addend": 0x3000,
                    "addend_valid": True,
                    "application_valid": True,
                },
                "importers": [{"module": "libhtml_view.prx", "call_sites": ["0x28"], "table_limitations": []}],
            },
            {
                "address": "0x4000",
                "nid": "0x44444444",
                "library": "libehsys",
                "pointer_relocation": {
                    "type": "R_MIPS_32",
                    "addend": 0x4000,
                    "addend_valid": True,
                    "application_valid": True,
                },
                "importers": [{"module": "libtutoriallist.prx", "call_sites": [], "table_limitations": []}],
            },
            {
                "address": "0x5000",
                "nid": "0x55555555",
                "library": "libehsys",
                "pointer_relocation": {
                    "type": "R_MIPS_32",
                    "addend": 0x5000,
                    "addend_valid": True,
                    "application_valid": True,
                },
                "importers": [{"module": "libtutoriallist.prx", "call_sites": ["0x2c"], "table_limitations": ["truncated"]}],
            },
        ]
    }
    triage_path = tmp_path / "triage.json"
    triage_path.write_text(json.dumps(triage), encoding="utf-8")
    existing = [Candidate("0x6000", 16, "0x66666666", 1, "EXACT")]

    discovered = discover_proven_exports(
        triage_path,
        existing,
        matched_addresses=["0x6000"],
    )

    assert [item.address for item in discovered] == ["0x1000"]
    assert discovered[0].size_bytes == 0
    assert discovered[0].boundary_status == "UNVERIFIED"
    assert discovered[0].initial_state == "needs_boundary"
    assert discovered[0].evidence["prx_call_sites"] == [
        {"module": "libtutoriallist.prx", "sites": ["0x20"]}
    ]


def test_export_discovery_and_inventory_append_are_idempotent(tmp_path: Path) -> None:
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_commit": "test",
                "baseline": {},
                "candidates": [],
            }
        ),
        encoding="utf-8",
    )
    triage_path = tmp_path / "triage.json"
    triage_path.write_text(
        json.dumps(
            {
                "exports": [
                    {
                        "address": "0x1000",
                        "nid": "0x11111111",
                        "library": "libehsys",
                        "pointer_relocation": {
                            "type": "R_MIPS_32",
                            "addend": 0x1000,
                            "addend_valid": True,
                            "application_valid": True,
                        },
                        "importers": [
                            {"module": "libtutoriallist.prx", "call_sites": ["0x20"], "table_limitations": []}
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    discovered = discover_proven_exports(triage_path, [], matched_addresses=[])

    assert decomp_campaign_module.append_inventory_candidates(inventory_path, discovered) == 1
    assert decomp_campaign_module.append_inventory_candidates(inventory_path, discovered) == 0
    candidates, _payload = decomp_campaign_module.load_inventory(inventory_path)
    assert [(item.address, item.size_bytes, item.boundary_status) for item in candidates] == [
        ("0x1000", 0, "UNVERIFIED")
    ]


def test_record_inventory_promotion_advances_only_a_new_certified_address(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])
    with store._connect() as db:
        db.execute(
            "UPDATE candidates SET status='matched',boundary_status='EXACT',size_bytes=16 "
            "WHERE address='0x1000'"
        )
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "baseline": {
                    "eboot_matched_functions": 1,
                    "eboot_matched_instructions": 5,
                    "eboot_matched_addresses": ["0x800"],
                    "eboot_matched_ranges": [
                        {"address": "0x800", "size_bytes": 20}
                    ],
                },
                "candidates": [],
            }
        ),
        encoding="utf-8",
    )

    assert record_inventory_promotion(inventory_path, store, "0x1000") is True
    assert record_inventory_promotion(inventory_path, store, "0x1000") is False
    baseline = json.loads(inventory_path.read_text(encoding="utf-8"))["baseline"]
    assert baseline == {
        "eboot_matched_functions": 2,
        "eboot_matched_instructions": 9,
        "eboot_matched_addresses": ["0x800", "0x1000"],
        "eboot_matched_ranges": [
            {"address": "0x800", "size_bytes": 20},
            {"address": "0x1000", "size_bytes": 16},
        ],
    }


def test_integration_failure_is_recorded_without_downgrading_matched_status(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])
    with store._connect() as db:
        db.execute(
            "UPDATE candidates SET status='matched',boundary_status='EXACT' WHERE address='0x1000'"
        )

    store.record_integration_result(
        "0x1000", "blocked", diagnostic_code="integration_failed"
    )

    task = store.get_task("0x1000")
    assert task["status"] == "matched"
    assert task["evidence"]["promotion"] == {
        "status": "blocked",
        "diagnostic": "integration_failed",
    }
    assert store.list_attempts() == []


def test_boundary_claim_and_failure_never_create_model_attempts(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed(
        [
            Candidate(
                address="0x1234",
                size_bytes=0,
                nid="0x12345678",
                priority=10,
                boundary_status="UNVERIFIED",
                initial_state="needs_boundary",
            )
        ]
    )

    claim = store.claim_boundary("ghidra-01")

    assert claim is not None
    assert claim.address == "0x1234"
    assert store.list_attempts() == []
    assert store.get_task("0x1234")["status"] == "boundary_checking"
    store.fail_boundary(claim, "ghidra_evidence_invalid")
    task = store.get_task("0x1234")
    assert task["status"] == "blocked"
    assert task["boundary_status"] == "UNVERIFIED"
    assert task["checkpoint"]["last_diagnostic"] == {
        "stage": "ghidra",
        "code": "ghidra_evidence_invalid",
    }
    assert store.list_attempts() == []


def test_measured_resource_finish_is_recorded_before_releasing_its_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    worktree = tmp_path / "luna-01"
    worktree.mkdir()
    runner = CampaignRunner(
        store,
        opencode_command=["unused"],
        worktrees={"luna-01": worktree},
        verifier=lambda *_args: {},
        matcher_parallelism=2,
    )
    semaphore = threading.BoundedSemaphore(2)
    claim = Claim(
        "0x1000", 16, "0x12345678", 10, "EXACT", "luna-01", "openai", "ses_test", 1, 0, {}, {}
    )
    events: list[str] = []
    remaining_during_finish: list[int] = []
    original_record_event = store.record_event

    def observe(kind: str, **kwargs: object) -> None:
        events.append(kind)
        if kind == "matcher_finished":
            available = int(semaphore.acquire(blocking=False))
            available += int(semaphore.acquire(blocking=False))
            remaining_during_finish.append(available)
            for _ in range(available):
                semaphore.release()
        original_record_event(kind, **kwargs)

    monkeypatch.setattr(store, "record_event", observe)

    assert runner._run_limited_operation(
        semaphore,
        "matcher",
        claim=claim,
        deadline=None,
        operation=lambda: "verified",
    ) == "verified"

    assert events == ["matcher_started", "matcher_finished"]
    assert remaining_during_finish == [1]
    available_after = int(semaphore.acquire(blocking=False))
    available_after += int(semaphore.acquire(blocking=False))
    assert available_after == 2
    semaphore.release()
    semaphore.release()


def test_seed_excludes_certified_addresses_from_new_sqlite_queue(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    candidates = [
        Candidate("0x2c28c", 112, "0x7187E0F0", 85, "EXACT"),
        Candidate(
            "0x31650",
            0,
            "0x9EA6989A",
            48,
            "UNVERIFIED",
            initial_state="needs_boundary",
        ),
        candidate("0x1000"),
        Candidate(
            "0x2000", 0, "0x22222222", 10, "UNVERIFIED", initial_state="needs_boundary"
        ),
    ]

    inserted = store.seed(
        candidates,
        excluded_addresses=frozenset({"0x2c28c", "0x31650"}),
    )

    tasks = store.list_tasks()
    assert inserted == 2
    assert {task["address"] for task in tasks} == {"0x1000", "0x2000"}
    assert store.get_task("0x1000")["status"] == "pending"
    assert store.get_task("0x2000")["status"] == "needs_boundary"
    assert store.claim_next(
        "luna-01", "openai", eligible_addresses=["0x2c28c", "0x31650"]
    ) is None
    assert store.claim_boundary("ghidra-01") is not None
    assert store.list_attempts() == []


def test_old_inventory_without_certified_address_list_remains_compatible(
    tmp_path: Path,
) -> None:
    inventory_path = tmp_path / "old-inventory.json"
    inventory_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "baseline": {
                    "eboot_matched_functions": 8,
                    "eboot_matched_instructions": 206,
                },
                "candidates": [candidate("0x1000").__dict__],
            }
        ),
        encoding="utf-8",
    )

    candidates, inventory = decomp_campaign_module.load_inventory(inventory_path)
    excluded = decomp_campaign_module.normalize_certified_addresses(
        inventory["baseline"]
    )
    store = CampaignStore(tmp_path / "campaign.sqlite3")

    assert excluded == frozenset()
    assert store.seed(candidates, excluded_addresses=excluded) == 1
    assert store.get_task("0x1000")["status"] == "pending"


def test_claims_ignore_certified_rows_already_present_in_an_older_sqlite(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed(
        [
            candidate("0x2c28c"),
            Candidate(
                "0x31650", 0, "0x9EA6989A", 48, "UNVERIFIED", initial_state="needs_boundary"
            ),
            candidate("0x1000"),
            Candidate(
                "0x2000", 0, "0x22222222", 10, "UNVERIFIED", initial_state="needs_boundary"
            ),
        ]
    )
    with store._connect() as db:
        db.execute(
            "UPDATE candidates SET attempt_count=8 WHERE address='0x2c28c'"
        )
    excluded = frozenset({"0x2c28c", "0x31650"})

    model_claim = store.claim_next(
        "luna-01", "openai", reserve_only=True, excluded_addresses=excluded
    )
    boundary_claim = store.claim_boundary(
        "ghidra-01", excluded_addresses=excluded
    )

    assert model_claim is not None and model_claim.address == "0x1000"
    assert boundary_claim is not None and boundary_claim.address == "0x2000"
    assert store.get_task("0x2c28c")["status"] == "pending"
    assert store.get_task("0x31650")["status"] == "needs_boundary"
    assert store.list_attempts() == []


def test_seed_exclusion_preserves_existing_matched_history_and_other_candidates(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    initial = [candidate("0x2c28c"), candidate("0x31650"), candidate("0x1000")]
    store.seed(initial)
    with store._connect() as db:
        for address, attempt_count, session_id in (
            ("0x2c28c", 3, "ses_2c28c"),
            ("0x31650", 1, "ses_31650"),
        ):
            checkpoint = {"next_experiment": f"checkpoint {address}"}
            best_result = {"status": "MATCHED", "matching_words": 3, "total_words": 3}
            db.execute(
                """UPDATE candidates SET status='matched',boundary_status='EXACT',size_bytes=12,
                   attempt_count=?,session_id=?,checkpoint_json=?,best_result_json=?,evidence_json=?
                   WHERE address=?""",
                (
                    attempt_count,
                    session_id,
                    json.dumps(checkpoint, sort_keys=True),
                    json.dumps(best_result, sort_keys=True),
                    json.dumps({"origin": address}, sort_keys=True),
                    address,
                ),
            )
            for number in range(1, attempt_count + 1):
                db.execute(
                    """INSERT INTO attempts(address,attempt_number,worker_id,provider,session_id,
                       started_at,ended_at,outcome) VALUES(?,?,?,?,?,?,?,?)""",
                    (
                        address,
                        number,
                        "luna-01",
                        "openai",
                        session_id,
                        float(number),
                        float(number) + 0.5,
                        "matched" if number == attempt_count else "pending",
                    ),
                )
        db.execute(
            "INSERT INTO events(created_at,kind,address,worker_id,provider,session_id) "
            "VALUES(1,'historical_match','0x2c28c','luna-01','openai','ses_2c28c')"
        )

    preserved = {address: store.get_task(address) for address in ("0x2c28c", "0x31650")}
    attempts_before = store.list_attempts()
    events_before = store.list_recent_events(limit=20)
    new_candidate = candidate("0x2000")

    inserted = store.seed(
        [
            Candidate("0x2c28c", 0, "0x7187E0F0", 1, "UNVERIFIED"),
            Candidate(
                "0x31650", 0, "0x9EA6989A", 1, "UNVERIFIED", initial_state="needs_boundary"
            ),
            new_candidate,
        ],
        excluded_addresses=frozenset({"0x2c28c", "0x31650"}),
    )

    assert inserted == 1
    assert {address: store.get_task(address) for address in preserved} == preserved
    assert store.list_attempts() == attempts_before
    assert store.list_recent_events(limit=20) == events_before
    assert store.get_task("0x2000")["status"] == "pending"


def test_main_excludes_baseline_addresses_from_all_eligible_seeding_and_claims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "campaign.toml"
    inventory_path = tmp_path / "inventory.json"
    database_path = tmp_path / "build" / "campaign.sqlite3"
    certified = ["0x2c28c", "0x31650"]
    baseline = {
        "eboot_matched_functions": 2,
        "eboot_matched_addresses": certified,
    }
    candidates = [
        candidate("0x1000"),
        candidate("0x2c28c"),
        Candidate(
            "0x31650", 0, "0x9EA6989A", 48, "UNVERIFIED", initial_state="needs_boundary"
        ),
        Candidate(
            "0x2000", 0, "0x22222222", 20, "UNVERIFIED", initial_state="needs_boundary"
        ),
    ]
    monkeypatch.setattr(decomp_campaign_module, "load_config", lambda _path: {})
    monkeypatch.setattr(
        decomp_campaign_module,
        "_config_paths",
        lambda *_args: (inventory_path, database_path),
    )
    monkeypatch.setattr(
        decomp_campaign_module,
        "load_inventory",
        lambda _path: (candidates, {"baseline": baseline}),
    )

    result = decomp_campaign_module.main(
        ["--config", str(config_path), "init"]
    )

    assert result == 0
    store = CampaignStore(database_path)
    assert {task["address"] for task in store.list_tasks()} == {"0x1000", "0x2000"}
    assert store.list_attempts() == []
    assert store.claim_next(
        "luna-01", "openai", eligible_addresses=certified
    ) is None
    boundary = store.claim_boundary("ghidra-01")
    assert boundary is not None and boundary.address == "0x2000"


@pytest.mark.parametrize(
    "baseline_addresses",
    [
        ["0x2c28c", "0X2C28C"],
        ["0x2c28c", "0x100000000"],
    ],
)
def test_main_rejects_invalid_certified_baseline_before_database_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    baseline_addresses: list[str],
) -> None:
    config_path = tmp_path / "campaign.toml"
    inventory_path = tmp_path / "inventory.json"
    database_path = tmp_path / "build" / "campaign.sqlite3"
    inventory = {
        "schema_version": 1,
        "baseline": {
            "eboot_matched_functions": 2,
            "eboot_matched_addresses": baseline_addresses,
        },
        "candidates": [],
    }
    monkeypatch.setattr(decomp_campaign_module, "load_config", lambda _path: {})
    monkeypatch.setattr(
        decomp_campaign_module,
        "_config_paths",
        lambda *_args: (inventory_path, database_path),
    )
    monkeypatch.setattr(
        decomp_campaign_module,
        "load_inventory",
        lambda _path: ([], inventory),
    )

    result = decomp_campaign_module.main(
        ["--config", str(config_path), "init"]
    )

    assert result == 2
    assert not database_path.exists()


def test_seeding_removes_old_provisional_size_without_touching_attempted_rows(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    provisional = Candidate(
        "0x1000", 12, "0x11111111", 10, "UNVERIFIED", initial_state="needs_boundary"
    )
    store.seed([provisional])
    store.seed(
        [
            Candidate(
                "0x1000", 0, "0x11111111", 10, "UNVERIFIED", initial_state="needs_boundary"
            )
        ]
    )

    task = store.get_task("0x1000")

    assert task["size_bytes"] == 0
    assert task["status"] == "needs_boundary"
    assert task["attempt_count"] == 0
    assert store.list_attempts() == []


def test_successful_boundary_claim_becomes_exact_without_spending_inference(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed(
        [
            Candidate(
                address="0x1234",
                size_bytes=0,
                nid="0x12345678",
                priority=10,
                boundary_status="UNVERIFIED",
                initial_state="needs_boundary",
            )
        ]
    )

    claim = store.claim_boundary("ghidra-01")
    assert claim is not None
    store.update_boundary(claim, 16, {"source": "verified Ghidra test log"})
    store.finish_boundary(claim)

    task = store.get_task("0x1234")
    assert task["status"] == "pending"
    assert task["boundary_status"] == "EXACT"
    assert task["size_bytes"] == 16
    assert task["attempt_count"] == 0
    assert store.list_attempts() == []
    boundary_events = [event["kind"] for event in store.list_recent_events(limit=10)]
    assert boundary_events.count("boundary_validated") == 1
    assert boundary_events.count("boundary_claim_finished") == 1
    model_claim = store.claim_next("luna-01", "openai")
    assert model_claim is not None
    assert model_claim.size_bytes == 16


def test_ghidra_boundary_is_rejected_when_it_overlaps_an_exact_export(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed(
        [
            candidate("0x1000"),
            Candidate("0x1008", 0, "0x22222222", 20, "UNVERIFIED", initial_state="needs_boundary"),
        ]
    )
    claim = store.claim_boundary("ghidra-01")
    assert claim is not None

    with pytest.raises(ValueError, match="overlaps EXACT"):
        store.update_boundary(claim, 16, {"source": "overlapping body"})

    store.fail_boundary(claim, "ghidra_evidence_invalid")
    task = store.get_task("0x1008")
    assert task["boundary_status"] == "UNVERIFIED"
    assert task["status"] == "blocked"
    assert store.list_attempts() == []


def test_model_reservation_does_not_count_until_inference_starts(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])

    reserved = store.claim_next("luna-01", "openai", reserve_only=True)

    assert reserved is not None
    assert reserved.attempt_number == 0
    assert store.list_attempts() == []
    store.release_preparation(reserved, diagnostic_code="ghidra_evidence_invalid")
    assert store.get_task("0x1000")["status"] == "blocked"
    assert store.get_task("0x1000")["attempt_count"] == 0
    assert store.list_attempts() == []


def test_paused_provider_releases_prepared_claim_without_counting_inference(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])
    reserved = store.claim_next("luna-01", "openai", reserve_only=True)
    assert reserved is not None
    with store._connect() as db:
        db.execute(
            "UPDATE providers SET status='suspended_quota',updated_at=? WHERE provider='openai'",
            (time.time(),),
        )

    assert store.start_attempt(reserved, max_total_attempts=10) is None
    task = store.get_task("0x1000")
    assert task["status"] == "pending"
    assert task["owner"] is None
    assert task["attempt_count"] == 0
    assert store.list_attempts() == []
    assert store.claim_next("luna-02", "openai") is None


def test_deadline_waiting_for_provider_slot_releases_reservation_safely(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])
    worktree = tmp_path / "luna-01"
    worktree.mkdir()
    runner = CampaignRunner(
        store,
        opencode_command=["unused"],
        worktrees={"luna-01": worktree},
        verifier=lambda *_args: {},
    )
    semaphore = threading.BoundedSemaphore(1)
    assert semaphore.acquire(blocking=False)
    runner.provider_slots = {"openai": semaphore}
    claim = store.claim_next("luna-01", "openai", reserve_only=True)
    assert claim is not None

    outcome = runner._run_claim(
        Worker("luna-01", "openai", "openai/gpt-6-luna"),
        claim,
        time.monotonic() + 0.05,
        max_total_attempts=10,
    )

    assert outcome == "interrupted"
    assert store.get_task("0x1000")["status"] == "pending"
    assert store.get_task("0x1000")["attempt_count"] == 0
    assert store.list_attempts() == []
    semaphore.release()


def test_session_setup_rate_limit_releases_reservation_without_model_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])
    worktree = tmp_path / "luna-01"
    worktree.mkdir()
    runner = CampaignRunner(
        store,
        opencode_command=["unused"],
        worktrees={"luna-01": worktree},
        verifier=lambda *_args: {},
    )
    claim = store.claim_next("luna-01", "openai", reserve_only=True)
    assert claim is not None

    def rate_limited(*_args, **_kwargs):
        raise ValueError("HTTP 429 rate limit; Retry-After: 17")

    monkeypatch.setattr(runner, "_ensure_session", rate_limited)

    result = runner._run_claim(
        Worker("luna-01", "openai", "openai/gpt-6-luna"),
        claim,
        None,
        max_total_attempts=10,
    )

    task = store.get_task("0x1000")
    assert result == "failed"
    assert task["status"] == "pending"
    assert task["attempt_count"] == 0
    assert task["owner"] is None
    assert task["preferred_provider"] == "openai"
    assert store.provider_status("openai") == "rate_limited"
    assert store.list_attempts() == []


def test_session_setup_agent_error_blocks_candidate_without_model_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000"), candidate("0x2000")])
    worktree = tmp_path / "luna-01"
    worktree.mkdir()
    runner = CampaignRunner(
        store,
        opencode_command=["unused"],
        worktrees={"luna-01": worktree},
        verifier=lambda *_args: {},
    )
    claim = store.claim_next("luna-01", "openai", reserve_only=True)
    assert claim is not None
    monkeypatch.setattr(
        runner,
        "_ensure_session",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("invalid session response")),
    )

    result = runner._run_claim(
        Worker("luna-01", "openai", "openai/gpt-6-luna"),
        claim,
        None,
        max_total_attempts=10,
    )

    task = store.get_task("0x1000")
    next_claim = store.claim_next("luna-02", "openai")
    assert result == "blocked"
    assert task["status"] == "blocked"
    assert task["attempt_count"] == 0
    assert next_claim is not None and next_claim.address == "0x2000"
    assert [item for item in store.list_attempts() if item["address"] == "0x1000"] == []


def test_prepared_session_rebind_does_not_rewrite_previous_attempt_history(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])
    first = store.claim_next("luna-01", "openai")
    assert first is not None
    first = store.bind_session(first, "ses_previous")
    store.fail(first, Failure(FailureKind.INTERRUPTED))
    history_before = store.list_attempts()
    assert history_before[0]["session_id"] == "ses_previous"

    reservation = store.claim_next("luna-02", "openai", reserve_only=True)
    assert reservation is not None
    rebound = store.bind_session(reservation, "ses_current")
    started = store.start_attempt(rebound, max_total_attempts=10)

    assert started is not None
    attempts = store.list_attempts()
    assert attempts[0]["session_id"] == "ses_previous"
    assert attempts[1]["session_id"] == "ses_current"
    assert attempts[1]["attempt_number"] == 2


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


def test_ghidra_log_accepts_and_identifies_reconstruction_details() -> None:
    log = detailed_ghidra_log()

    evidence = validate_ghidra_log(log, 0x1000)

    assert evidence["instruction_count"] == 4
    assert decomp_campaign_module._ghidra_log_has_reconstruction_details(log)


def test_prepare_claim_refreshes_boundary_only_cached_ghidra_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000", preferred_provider="openai")])
    worktree = tmp_path / "worker"
    eboot = worktree / "private" / "decrypted" / "ULUS10136_EBOOT.elf"
    eboot.parent.mkdir(parents=True)
    eboot.write_bytes(b"test EBOOT")
    triage = worktree / "build" / "seto035" / "export-triage.json"
    triage.parent.mkdir(parents=True)
    triage.write_text(
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
                            "addend": 0x1000,
                            "application_valid": True,
                        },
                        "importers": [
                            {"call_sites": [{"address": "0x20"}], "table_limitations": []}
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    first = store.claim_next("openai", "openai")
    assert first is not None
    old_log_relative = "decomp-campaign/openai/1000/evidence/ghidra-attempt-1.log"
    old_log = campaign_build_path(worktree, old_log_relative)
    old_log.parent.mkdir(parents=True)
    old_log.write_text(ghidra_log(), encoding="utf-8")
    store.save_checkpoint(
        first,
        {
            "ghidra_log_path": old_log_relative,
            "ghidra_log_sha256": hashlib.sha256(old_log.read_bytes()).hexdigest(),
            "boundary_status": "EXACT",
        },
        trusted_evidence=True,
    )
    store.fail(first, Failure(FailureKind.INTERRUPTED))
    retry = store.claim_next("openai", "openai")
    assert retry is not None
    assert retry.attempt_number == 2

    observed: dict[str, object] = {}

    def fake_ghidra(argv, **_kwargs):
        observed["argv"] = list(argv)
        console_lines = []
        for line in detailed_ghidra_log().splitlines():
            if line.startswith("SETO_") or line == "}":
                line += " (GhidraScript)"
            console_lines.append(line)
        return decomp_campaign_module.WorkResult(0, "\n".join(console_lines), "")

    monkeypatch.setattr(decomp_campaign_module, "_run_process", fake_ghidra)
    if decomp_campaign_module.os.name == "nt":
        ghidra_home = tmp_path / "ghidra"
        (ghidra_home / "support").mkdir(parents=True)
        (ghidra_home / "support" / "analyzeHeadless.bat").touch()
        (worktree / "scripts").mkdir()
        (worktree / "scripts" / "run_ghidra_headless.ps1").touch()
        monkeypatch.setattr(
            decomp_campaign_module.shutil,
            "which",
            lambda name: "powershell.exe" if name == "powershell.exe" else None,
        )
        runner = CampaignRunner(
            store,
            opencode_command=["opencode"],
            worktrees={"openai": worktree},
            ghidra_windows_home=str(ghidra_home),
            ghidra_parallelism=2,
        )
    else:
        runner = CampaignRunner(
            store,
            opencode_command=["opencode"],
            worktrees={"openai": worktree},
            ghidra_home="/ghidra",
            ghidra_parallelism=2,
        )

    original_record_event = store.record_event

    def observe_slot_at_finish(kind: str, **kwargs: object) -> None:
        if kind == "ghidra_finished":
            first = runner.ghidra_slots.acquire(blocking=False)
            second = runner.ghidra_slots.acquire(blocking=False)
            observed["ghidra_slots_available_at_finish_event"] = int(first) + int(second)
            if second:
                runner.ghidra_slots.release()
            if first:
                runner.ghidra_slots.release()
        original_record_event(kind, **kwargs)

    # The finish event must be durably recorded before the slot is released, so
    # telemetry never reports more concurrent Ghidra processes than the semaphore.
    monkeypatch.setattr(store, "record_event", observe_slot_at_finish)
    prepared = runner._prepare_claim(worktree, retry, None)
    new_log = campaign_build_path(worktree, prepared.checkpoint["ghidra_log_path"])

    assert observed["argv"]
    assert observed["ghidra_slots_available_at_finish_event"] == 1
    assert "SetoAnalyzeEntry.java" in observed["argv"]
    assert "/evidence/ghidra-run-" in prepared.checkpoint["ghidra_log_path"]
    assert prepared.checkpoint["ghidra_log_path"].endswith(".log")
    assert "SETO_INSN=0x1000 SIZE=4 nop" in new_log.read_text(encoding="utf-8")
    assert "SETO_DECOMP_C_BEGIN" in new_log.read_text(encoding="utf-8")
    assert decomp_campaign_module._ghidra_log_has_reconstruction_details(
        new_log.read_text(encoding="utf-8")
    )


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
    assert "## SETO-DECOMP-045 — Promoções certificadas" in text
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
        verifier=lambda *_args: {},
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
    assert store.list_attempts()[0]["outcome"] == "context_unavailable"
    assert store.get_task("0x1000")["checkpoint"]["last_diagnostic"] == {
        "stage": "context",
        "code": "context_unavailable",
    }
    assert store.provider_status("opencode") == "active"


def test_extract_checkpoint_accepts_fenced_multiline_json() -> None:
    text = (
        "Worker summary.\n\n```json\n"
        "{\n"
        '  "checkpoint": {\n'
        '    "next_experiment": "compare the full object",\n'
        '    "limitations": [],\n'
        '    "evidence_paths": []\n'
        "  }\n"
        "}\n"
        "```\n"
    )
    output = json.dumps({"type": "text", "text": text})

    checkpoint = _extract_checkpoint(output)

    assert checkpoint == {
        "next_experiment": "compare the full object",
        "limitations": [],
        "evidence_paths": [],
    }


def test_worker_can_continue_from_local_evidence_when_aimemory_is_unavailable(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000", preferred_provider="openai")])
    local_experiment = {
        "origin_kind": "local_experiment",
        "worker_id": "openai",
        "status": "MATCHED",
        "source_path": "build/decomp-campaign/experiments/1000/variant.c",
        "source_sha256": "a" * 64,
        "matching_words": 4,
        "total_words": 4,
        "report_paths": [
            "build/decomp-campaign/experiments/1000/verify-1/full.json",
            "build/decomp-campaign/experiments/1000/verify-2/full.json",
        ],
        "object_sha256s": ["b" * 64, "b" * 64],
    }
    with store._connect() as db:
        db.execute(
            "UPDATE candidates SET checkpoint_json=? WHERE address='0x1000'",
            (json.dumps({"local_experiments": [local_experiment]}),),
        )
    simulator = tmp_path / "local_evidence_only.py"
    simulator.write_text(
        "import json, pathlib\n"
        "source = pathlib.Path('decomp/src/eboot/func_00001000.c')\n"
        "source.parent.mkdir(parents=True, exist_ok=True)\n"
        "source.write_text('void func_00001000(void) { return; }\\n')\n"
        "print(json.dumps({'type':'text','text':json.dumps({'checkpoint':{"
        "'next_experiment':'inspect the proven call site',"
        "'limitations':['AIMemory tools unavailable; using local evidence only']}})}))\n",
        encoding="utf-8",
    )
    worktree = tmp_path / "worker"
    worktree.mkdir()
    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path, simulator),
        worktrees={"openai": worktree},
        verifier=lambda *_args: {"status": "BOUNDARY_VALIDATED"},
    )

    result = runner.run([Worker("openai", "openai", "openai/gpt-6-luna")], max_tasks=1)

    assert result["attempted"] == 1
    assert store.get_task("0x1000")["status"] == "pending"
    assert store.get_task("0x1000")["checkpoint"]["next_experiment"] == (
        "inspect the proven call site"
    )
    assert store.get_task("0x1000")["checkpoint"]["local_experiments"] == [
        local_experiment
    ]


def test_successful_worker_without_candidate_source_preserves_checkpoint_and_diagnosis(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000", preferred_provider="openai")])
    simulator = tmp_path / "success_without_source.py"
    simulator.write_text(
        "import json\n"
        "checkpoint = {'next_experiment':'inspect block delay slot', 'limitations':['Ghidra evidence only']}\n"
        "print(json.dumps({'type':'text','text':json.dumps({'checkpoint':checkpoint})}))\n",
        encoding="utf-8",
    )
    worktree = tmp_path / "worker"
    worktree.mkdir()
    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path, simulator),
        worktrees={"openai": worktree},
        verifier=lambda *_args: pytest.fail("matcher must not run without a source"),
    )
    claim = store.claim_next("openai", "openai")
    assert claim is not None

    assert runner._run_claim(Worker("openai", "openai", "openai/gpt-6-luna"), claim, None) == "blocked"

    task = store.get_task("0x1000")
    attempt = store.list_attempts()[0]
    assert task["status"] == "blocked"
    assert task["checkpoint"]["next_experiment"] == "inspect block delay slot"
    assert task["checkpoint"]["limitations"] == ["Ghidra evidence only"]
    assert task["checkpoint"]["last_diagnostic"] == {
        "stage": "worker_return",
        "code": "candidate_source_missing",
    }
    assert attempt["outcome"] == "candidate_source_missing"
    assert attempt["failure_kind"] == "agent_error"
    with store._connect() as db:
        event_kinds = [row[0] for row in db.execute("SELECT kind FROM events ORDER BY id")]
    assert "candidate_source_missing" in event_kinds


def test_successful_worker_with_incomplete_matcher_result_is_local_error_without_leaks(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000", preferred_provider="openai")])
    simulator = tmp_path / "source_with_checkpoint.py"
    simulator.write_text(
        "import json\n"
        "checkpoint = {'next_experiment':'recover missing function body', 'limitations':['compiled object has only 8 bytes']}\n"
        "print(json.dumps({'type':'text','text':json.dumps({'checkpoint':checkpoint})}))\n",
        encoding="utf-8",
    )
    worktree = tmp_path / "worker"
    source = worktree / "decomp" / "src" / "eboot" / "func_00001000.c"
    source.parent.mkdir(parents=True)
    source.write_text("void func_00001000(void) { return; }\n", encoding="utf-8")
    checkpoint_repo = tmp_path / "checkpoint-repo"
    checkpoint_repo.mkdir()

    def matcher_incomplete(*_args):
        raise ValueError("candidate .text is 8 bytes; private token sk-sensitive-secret")

    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path, simulator),
        worktrees={"openai": worktree},
        verifier=matcher_incomplete,
        checkpoint_repo_root=checkpoint_repo,
    )
    claim = store.claim_next("openai", "openai")
    assert claim is not None

    assert runner._run_claim(Worker("openai", "openai", "openai/gpt-6-luna"), claim, None) == "pending"

    task = store.get_task("0x1000")
    attempt = store.list_attempts()[0]
    assert task["status"] == "pending"
    assert task["checkpoint"]["next_experiment"] == "recover missing function body"
    assert task["checkpoint"]["limitations"] == ["compiled object has only 8 bytes"]
    assert task["checkpoint"]["last_diagnostic"] == {
        "stage": "matcher",
        "code": "matcher_incomplete",
    }
    latest_snapshot = task["checkpoint"]["latest_source_snapshot"]
    assert task["checkpoint"]["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert not task["checkpoint"].get("best_source_snapshot")
    assert (checkpoint_repo / "build" / latest_snapshot).read_bytes() == source.read_bytes()
    assert attempt["outcome"] == "matcher_incomplete"
    assert attempt["failure_kind"] == "agent_error"
    persisted = json.dumps(task["checkpoint"]) + json.dumps(attempt)
    assert "sk-sensitive-secret" not in persisted
    assert "8 bytes" in persisted  # safe, agent-provided limitation is retained


def test_unknown_local_exception_is_classified_without_persisting_message(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000", preferred_provider="openai")])
    simulator = tmp_path / "source_with_checkpoint.py"
    simulator.write_text(
        "import json\n"
        "print(json.dumps({'type':'text','text':json.dumps({'checkpoint':{'next_experiment':'retry'}})}))\n",
        encoding="utf-8",
    )
    worktree = tmp_path / "worker"
    source = worktree / "decomp" / "src" / "eboot" / "func_00001000.c"
    source.parent.mkdir(parents=True)
    source.write_text("void func_00001000(void) { return; }\n", encoding="utf-8")

    def broken_verifier(*_args):
        raise RuntimeError("private path C:/Users/private/secret-token")

    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path, simulator),
        worktrees={"openai": worktree},
        verifier=broken_verifier,
    )
    claim = store.claim_next("openai", "openai")
    assert claim is not None
    runner._run_claim(Worker("openai", "openai", "openai/gpt-6-luna"), claim, None)

    task = store.get_task("0x1000")
    assert task["checkpoint"]["last_diagnostic"] == {
        "stage": "internal",
        "code": "internal_error",
    }
    assert "C:/Users/private" not in json.dumps(task["checkpoint"])
    assert "secret-token" not in json.dumps(task["checkpoint"])


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
        "source = pathlib.Path('decomp/src/eboot/func_00001000.c')\n"
        "source.parent.mkdir(parents=True, exist_ok=True)\n"
        "source.write_text('void func_00001000(void) { return; }\\n')\n"
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
        matcher_parallelism=2,
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
    fast_next_claim = next(
        event
        for event in store.list_recent_events(limit=100)
        if event["kind"] == "inference_started" and event["address"] == "0x3000"
    )
    assert int(float(fast_next_claim["created_at"]) * 1_000_000_000) < slow_done.stat().st_mtime_ns


def test_successive_matcher_improvements_refine_same_function_and_session(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000", preferred_provider="openai")])
    worktree = tmp_path / "luna-01"
    worktree.mkdir()
    worker_script = tmp_path / "iterative_worker.py"
    worker_script.write_text(
        "import json, pathlib\n"
        "state_path = pathlib.Path('.fake-opencode-sessions.json')\n"
        "state = json.loads(state_path.read_text())\n"
        "version = len(state['runs'])\n"
        "source = pathlib.Path('decomp/src/eboot/func_00001000.c')\n"
        "source.parent.mkdir(parents=True, exist_ok=True)\n"
        "source.write_text(f'int func_00001000(void) {{ return {version}; }}\\n')\n"
        "print(json.dumps({'type':'text','text':json.dumps({'checkpoint':{'next_experiment':'use matcher feedback'}})}))\n",
        encoding="utf-8",
    )
    checkpoint_repo = tmp_path / "checkpoints"
    checkpoint_repo.mkdir()
    score = 0
    def verifier(path: Path, claim: Claim, _checkpoint: dict[str, object]):
        nonlocal score
        score += 1
        source = path / "decomp/src/eboot/func_00001000.c"
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        reports = []
        for _ in (1, 2):
            report = strict_report(claim.address)
            report["status"] = "NONMATCHING"
            report["symbol"] = f"func_{claim.numeric_address:08X}"
            report["verified_decompilation"] = False
            report["provenance"]["source_sha256"] = source_hash
            report["match"].update(
                status="NONMATCHING",
                matching_words=score,
                difference_count=4 - score,
                differences=[{"word_index": item} for item in range(4 - score)],
            )
            reports.append(report)
        return {
            "status": "NONMATCHING",
            "source_sha256": source_hash,
            "matching_words": score,
            "total_words": 4,
            "build_sha256": [report["provenance"]["object_sha256"] for report in reports],
            "reports": reports,
        }

    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path, worker_script),
        worktrees={"luna-01": worktree},
        verifier=verifier,
        timeout_seconds=5,
        checkpoint_repo_root=checkpoint_repo,
        max_consecutive_attempts=3,
    )

    result = runner.run(
        [Worker("luna-01", "openai", "openai/gpt-6-luna")], max_tasks=3
    )

    attempts = store.list_attempts()
    task = store.get_task("0x1000")
    session_state = json.loads(
        (worktree / ".fake-opencode-sessions.json").read_text(encoding="utf-8")
    )
    assert result["attempted"] == 3
    assert [item["attempt_number"] for item in attempts] == [1, 2, 3]
    assert [item["outcome"] for item in attempts] == ["pending", "pending", "pending"]
    assert len({item["session_id"] for item in attempts}) == 1
    assert len(session_state["created"]) == 1
    assert len(session_state["runs"]) == 3
    assert task["status"] == "pending"
    assert task["best_result"]["matching_words"] == 3
    assert task["best_result"]["campaign_origin"]["attempt_number"] == 3


def test_compiler_failure_is_fed_back_and_each_luna_call_is_counted(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000", preferred_provider="openai")])
    worktree = tmp_path / "luna-01"
    worktree.mkdir()
    worker_script = tmp_path / "feedback_worker.py"
    worker_script.write_text(
        "import json, pathlib, sys\n"
        "state_path = pathlib.Path('.fake-opencode-sessions.json')\n"
        "state = json.loads(state_path.read_text())\n"
        "version = len(state['runs'])\n"
        "prompt = sys.argv[-1]\n"
        "state.setdefault('prompts', []).append(prompt)\n"
        "state_path.write_text(json.dumps(state))\n"
        "source = pathlib.Path('decomp/src/eboot/func_00001000.c')\n"
        "source.parent.mkdir(parents=True, exist_ok=True)\n"
        "source.write_text(f'void func_00001000(void) {{ return {version}; }}\\n')\n"
        "print(json.dumps({'type':'text','text':json.dumps({'checkpoint':{'next_experiment':'fix compiler diagnostic'}})}))\n",
        encoding="utf-8",
    )
    calls = 0

    def verifier(path: Path, claim: Claim, _checkpoint: dict[str, object]):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise decomp_campaign_module.MatcherCompilerError(
                "MWCC compilation failed",
                excerpt="error: illegal conversion near local declaration",
            )
        source = path / "decomp/src/eboot/func_00001000.c"
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        reports = []
        for _ in (1, 2):
            report = strict_report(claim.address)
            report["status"] = "NONMATCHING"
            report["symbol"] = f"func_{claim.numeric_address:08X}"
            report["verified_decompilation"] = False
            report["provenance"]["source_sha256"] = source_hash
            report["match"].update(
                status="NONMATCHING",
                matching_words=1,
                difference_count=3,
                differences=[{"word_index": index} for index in range(3)],
            )
            reports.append(report)
        return {
            "status": "NONMATCHING",
            "source_sha256": source_hash,
            "matching_words": 1,
            "total_words": 4,
            "build_sha256": [report["provenance"]["object_sha256"] for report in reports],
            "reports": reports,
        }

    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path, worker_script),
        worktrees={"luna-01": worktree},
        verifier=verifier,
        timeout_seconds=5,
        max_consecutive_attempts=2,
    )

    result = runner.run(
        [Worker("luna-01", "openai", "openai/gpt-6-luna")], max_tasks=2
    )

    attempts = store.list_attempts()
    task = store.get_task("0x1000")
    session_state = json.loads(
        (worktree / ".fake-opencode-sessions.json").read_text(encoding="utf-8")
    )
    assert result["attempted"] == 2
    assert [item["outcome"] for item in attempts] == ["compiler_failed", "pending"]
    assert attempts[0]["failure_kind"] == "agent_error"
    assert len({item["session_id"] for item in attempts}) == 1
    assert len(session_state["created"]) == 1
    assert len(session_state["runs"]) == 2
    assert "illegal conversion" in session_state["prompts"][1]
    assert task["best_result"]["status"] == "NONMATCHING"
    assert task["best_result"]["campaign_origin"]["attempt_number"] == 2


def test_unchanged_source_hash_is_not_compiled_or_matched_again(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000", preferred_provider="openai")])
    worktree = tmp_path / "luna-01"
    worktree.mkdir()
    checkpoint_repo = tmp_path / "checkpoints"
    checkpoint_repo.mkdir()
    worker_script = tmp_path / "unchanged_worker.py"
    worker_script.write_text(
        "import json, pathlib\n"
        "source = pathlib.Path('decomp/src/eboot/func_00001000.c')\n"
        "source.parent.mkdir(parents=True, exist_ok=True)\n"
        "source.write_text('void func_00001000(void) { return 0; }\\n')\n"
        "print(json.dumps({'type':'text','text':json.dumps({'checkpoint':{'next_experiment':'inspect first divergence'}})}))\n",
        encoding="utf-8",
    )
    matcher_calls = 0

    def verifier(path: Path, claim: Claim, _checkpoint: dict[str, object]):
        nonlocal matcher_calls
        matcher_calls += 1
        source_hash = hashlib.sha256(
            (path / "decomp/src/eboot/func_00001000.c").read_bytes()
        ).hexdigest()
        reports = []
        for _ in (1, 2):
            report = strict_report(claim.address)
            report["status"] = "NONMATCHING"
            report["verified_decompilation"] = False
            report["provenance"]["source_sha256"] = source_hash
            report["match"].update(
                status="NONMATCHING",
                matching_words=1,
                difference_count=3,
                differences=[{"word_index": index} for index in range(3)],
            )
            reports.append(report)
        return {
            "status": "NONMATCHING",
            "source_sha256": source_hash,
            "matching_words": 1,
            "total_words": 4,
            "build_sha256": [report["provenance"]["object_sha256"] for report in reports],
            "reports": reports,
        }

    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path, worker_script),
        worktrees={"luna-01": worktree},
        verifier=verifier,
        timeout_seconds=5,
        checkpoint_repo_root=checkpoint_repo,
        max_consecutive_attempts=3,
    )

    result = runner.run(
        [Worker("luna-01", "openai", "openai/gpt-6-luna")], max_tasks=3
    )

    attempts = store.list_attempts()
    task = store.get_task("0x1000")
    assert result["attempted"] == 2
    assert matcher_calls == 1
    assert [attempt["outcome"] for attempt in attempts] == ["pending", "source_unchanged"]
    assert task["status"] == "stalled"
    assert task["checkpoint"]["last_diagnostic"] == {
        "stage": "worker_return",
        "code": "source_unchanged",
    }
    assert task["best_result"]["campaign_origin"]["attempt_number"] == 1


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


def test_cumulative_attempt_ceiling_is_atomic_with_historical_attempts(
    tmp_path: Path,
) -> None:
    database = tmp_path / "campaign.sqlite3"
    store = CampaignStore(database)
    candidates = [candidate(f"0x{0x1000 + index * 0x10:x}") for index in range(12)]
    store.seed(candidates)
    with store._connect() as db:
        for index, item in enumerate(candidates[:4], start=1):
            db.execute(
                "UPDATE candidates SET attempt_count=1 WHERE address=?", (item.address,)
            )
            db.execute(
                "INSERT INTO attempts(address,attempt_number,worker_id,provider,session_id,started_at,ended_at,outcome) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (
                    item.address,
                    1,
                    "historical",
                    "openai",
                    f"ses_historical_{index}",
                    float(index),
                    float(index) + 0.5,
                    "agent_error",
                ),
            )

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
        ("ceiling-openai", "openai", "openai/gpt-6-luna"),
        ("ceiling-deepseek", "opencode", "opencode/deepseek-v4.1-flash-free"),
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
        futures = [pool.submit(runner.run, workers, max_tasks=12) for runner, workers in runners]
        results = [future.result(timeout=20) for future in futures]

    assert sum(result["attempted"] for result in results) == 8
    assert len(store.list_attempts()) == 12
    assert sum(sum(outcomes.values()) for outcomes in store.attempt_summary().values()) == 12
    assert all(task["status"] != "running" for task in store.list_tasks())


def test_repeated_provider_workers_share_provider_capacity_and_run_independently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    candidates = [candidate(f"0x{0x1000 + index * 0x10:x}") for index in range(8)]
    store.seed(candidates)
    worker_specs = [
        *(Worker(f"luna-{index:02d}", "openai", "openai/gpt-6-luna") for index in range(1, 5)),
        *(Worker(f"deepseek-{index:02d}", "opencode", "opencode/deepseek-v4.1-flash-free") for index in range(1, 5)),
    ]
    worktrees = {worker.worker_id: tmp_path / worker.worker_id for worker in worker_specs}
    for worktree in worktrees.values():
        worktree.mkdir()
    runner = CampaignRunner(
        store,
        opencode_command=["unused"],
        worktrees=worktrees,
        verifier=lambda *_args: {},
        provider_parallelism={"openai": 2, "opencode": 2},
    )
    active: dict[str, int] = {"openai": 0, "opencode": 0}
    observed_max: dict[str, int] = {"openai": 0, "opencode": 0}
    first_wave = threading.Barrier(4)
    wave_count = 0
    lock = threading.Lock()

    def simulated_claim(
        worker: Worker,
        claim: Claim,
        _deadline: float | None,
        *,
        max_total_attempts: int | None,
        on_attempt_started,
    ) -> str:
        nonlocal wave_count
        slot = runner.provider_slots[worker.provider]
        with slot:
            started = store.start_attempt(
                claim,
                max_total_attempts=max_total_attempts,
                lease_seconds=runner.lease_seconds,
            )
            if started is None:
                return "budget_exhausted"
            on_attempt_started()
            with lock:
                active[worker.provider] += 1
                observed_max[worker.provider] = max(
                    observed_max[worker.provider], active[worker.provider]
                )
                wave_count += 1
                wait_for_first_wave = wave_count <= 4
            if wait_for_first_wave:
                first_wave.wait(timeout=5)
            report = strict_report(started.address)
            result = {
                "status": "MATCHED",
                "source_sha256": report["provenance"]["source_sha256"],
                "matching_words": 4,
                "total_words": 4,
                "build_sha256": [report["provenance"]["object_sha256"]] * 2,
                "reports": [report, report],
            }
            try:
                return store.complete(
                    started,
                    {},
                    result,
                    max_attempts_without_progress=3,
                    max_attempts_per_candidate=8,
                )
            finally:
                with lock:
                    active[worker.provider] -= 1

    monkeypatch.setattr(runner, "_run_claim", simulated_claim)

    result = runner.run(worker_specs, max_tasks=8)

    assert result["attempted"] == 8
    assert len(store.list_attempts()) == 8
    assert observed_max == {"openai": 2, "opencode": 2}
    assert all(task["status"] == "matched" for task in store.list_tasks())


def test_promotion_runs_without_pausing_other_workers_and_failure_keeps_matched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000"), candidate("0x2000")])
    worker_specs = [
        Worker("luna-01", "openai", "openai/gpt-6-luna"),
        Worker("luna-02", "openai", "openai/gpt-6-luna"),
    ]
    worktrees = {worker.worker_id: tmp_path / worker.worker_id for worker in worker_specs}
    for worktree in worktrees.values():
        worktree.mkdir()
    other_model_completed = threading.Event()
    both_started = threading.Barrier(2)
    runner = CampaignRunner(
        store,
        opencode_command=["unused"],
        worktrees=worktrees,
        verifier=lambda *_args: {},
        provider_parallelism={"openai": 2},
        promotion_callback=lambda address, _deadline: (
            {} if address == "0x1000" and other_model_completed.wait(5)
            else (_ for _ in ()).throw(RuntimeError("integration unavailable"))
        ),
    )

    def simulated_claim(
        _worker: Worker,
        claim: Claim,
        _deadline: float | None,
        *,
        max_total_attempts: int | None,
        on_attempt_started,
    ) -> str:
        started = store.start_attempt(claim, max_total_attempts=max_total_attempts)
        assert started is not None
        on_attempt_started()
        both_started.wait(timeout=5)
        report = strict_report(started.address)
        result = {
            "status": "MATCHED",
            "source_sha256": report["provenance"]["source_sha256"],
            "matching_words": 4,
            "total_words": 4,
            "build_sha256": [report["provenance"]["object_sha256"]] * 2,
            "reports": [report, report],
        }
        status = store.complete(
            started,
            {},
            result,
            max_attempts_without_progress=3,
            max_attempts_per_candidate=8,
        )
        if started.address == "0x2000":
            other_model_completed.set()
        return status

    monkeypatch.setattr(runner, "_run_claim", simulated_claim)

    result = runner.run(worker_specs, max_tasks=2)

    assert result["attempted"] == 2
    assert result["integrations_promoted"] == ["0x1000"]
    assert result["integration_blocked"] == ["0x2000"]
    assert store.get_task("0x1000")["status"] == "matched"
    assert store.get_task("0x1000")["evidence"]["promotion"]["status"] == "promoted"
    assert store.get_task("0x2000")["status"] == "matched"
    assert store.get_task("0x2000")["evidence"]["promotion"] == {
        "status": "blocked",
        "diagnostic": "integration_failed",
    }


def test_model_workers_continue_claiming_while_promotion_queue_is_busy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000"), candidate("0x2000"), candidate("0x3000")])
    workers = [
        Worker("luna-01", "openai", "openai/gpt-6-luna"),
        Worker("luna-02", "openai", "openai/gpt-6-luna"),
    ]
    worktrees = {worker.worker_id: tmp_path / worker.worker_id for worker in workers}
    for worktree in worktrees.values():
        worktree.mkdir()
    third_model_completed = threading.Event()
    promotion_waiting = threading.Event()

    def promote(address: str, _deadline: float | None) -> dict[str, object]:
        if address == "0x1000":
            promotion_waiting.set()
            if not third_model_completed.wait(5):
                raise TimeoutError("model workers stopped while promotion was in progress")
        return {"address": address, "status": "MATCHED"}

    runner = CampaignRunner(
        store,
        opencode_command=["unused"],
        worktrees=worktrees,
        verifier=lambda *_args: {},
        provider_parallelism={"openai": 2},
        promotion_callback=promote,
    )

    def simulated_claim(
        _worker: Worker,
        claim: Claim,
        _deadline: float | None,
        *,
        max_total_attempts: int | None,
        on_attempt_started,
    ) -> str:
        started = store.start_attempt(claim, max_total_attempts=max_total_attempts)
        assert started is not None
        on_attempt_started()
        report = strict_report(started.address)
        status = store.complete(
            started,
            {},
            {
                "status": "MATCHED",
                "source_sha256": report["provenance"]["source_sha256"],
                "matching_words": 4,
                "total_words": 4,
                "build_sha256": [report["provenance"]["object_sha256"]] * 2,
                "reports": [report, report],
            },
            max_attempts_without_progress=3,
            max_attempts_per_candidate=8,
        )
        if started.address == "0x3000":
            third_model_completed.set()
        return status

    monkeypatch.setattr(runner, "_run_claim", simulated_claim)

    result = runner.run(workers, max_tasks=3)

    assert promotion_waiting.is_set()
    assert third_model_completed.is_set()
    assert result["attempted"] == 3
    assert set(result["integrations_promoted"]) == {"0x1000", "0x2000", "0x3000"}


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


def test_campaign_uses_native_opencode_cli_for_api_and_session_calls() -> None:
    config = load_config(
        Path(__file__).resolve().parents[1] / "config" / "decomp_campaign.toml"
    )

    assert config["opencode"]["command"] == ["opencode"]


def test_worker_permission_audit_rejects_global_allow_and_shell_access() -> None:
    agent = {
        "id": "seto-decomp-worker",
        "permissions": [
            {"action": "*", "resource": "*", "effect": "allow"},
            {"action": "*", "resource": "*", "effect": "deny"},
            {"action": "read", "resource": "*", "effect": "allow"},
            {"action": "glob", "resource": "*", "effect": "allow"},
            {"action": "grep", "resource": "*", "effect": "allow"},
            {
                "action": "edit",
                "resource": "decomp/src/eboot/func_*.c",
                "effect": "allow",
            },
            {"action": "edit", "resource": "build/decomp-campaign/*", "effect": "allow"},
            {"action": "execute", "resource": "*", "effect": "allow"},
            {"action": "ai-memory_memory_query", "resource": "*", "effect": "allow"},
            {"action": "ai-memory_memory_read_page", "resource": "*", "effect": "allow"},
            {"action": "external_directory", "resource": "*", "effect": "deny"},
            {"action": "subagent", "resource": "*", "effect": "deny"},
            {"action": "read", "resource": "*.env", "effect": "deny"},
            {"action": "read", "resource": "*.env.*", "effect": "deny"},
        ],
    }
    assert any(
        rule["action"] == "execute" and rule["effect"] == "allow"
        for rule in agent["permissions"]
    )
    # Regression for PR #43: the prior audit treated execute:allow as acceptable.
    assert not worker_agent_policy_is_restricted([agent], "seto-decomp-worker")
    agent["permissions"].append({"action": "shell", "resource": "*", "effect": "allow"})
    assert not worker_agent_policy_is_restricted([agent], "seto-decomp-worker")
    assert not worker_agent_policy_is_restricted([], "missing-agent")


def _restricted_worker_agent(*, query_action: str = "ai-memory_memory_query") -> dict[str, object]:
    return {
        "id": "seto-decomp-worker",
        "permissions": [
            {"action": "*", "resource": "*", "effect": "deny"},
            {"action": "read", "resource": "*", "effect": "allow"},
            {"action": "glob", "resource": "*", "effect": "allow"},
            {"action": "grep", "resource": "*", "effect": "allow"},
            {"action": "edit", "resource": "decomp/src/eboot/func_*.c", "effect": "allow"},
            {"action": "edit", "resource": "build/decomp-campaign/*", "effect": "allow"},
            {"action": query_action, "resource": "*", "effect": "allow"},
            {"action": "ai-memory_memory_read_page", "resource": "*", "effect": "allow"},
            {"action": "execute", "resource": "*", "effect": "deny"},
            {"action": "shell", "resource": "*", "effect": "deny"},
            {"action": "http", "resource": "*", "effect": "deny"},
            {"action": "http_request", "resource": "*", "effect": "deny"},
            {"action": "webfetch", "resource": "*", "effect": "deny"},
            {"action": "websearch", "resource": "*", "effect": "deny"},
            {"action": "browser", "resource": "*", "effect": "deny"},
            {"action": "external_directory", "resource": "*", "effect": "deny"},
            {"action": "subagent", "resource": "*", "effect": "deny"},
            {"action": "read", "resource": "*.env", "effect": "deny"},
            {"action": "read", "resource": "*.env.*", "effect": "deny"},
        ],
    }


def test_worker_permission_audit_uses_real_mcp_ids_and_allows_only_read_tools() -> None:
    agent = _restricted_worker_agent()

    assert worker_agent_policy_is_restricted([agent], "seto-decomp-worker")

    permissions = agent["permissions"]
    assert isinstance(permissions, list)

    def effect(action: str) -> str | None:
        result = None
        for item in permissions:
            if item["action"] in {"*", action}:
                result = item["effect"]
        return result

    assert effect("ai-memory_memory_query") == "allow"
    assert effect("ai-memory_memory_read_page") == "allow"
    assert effect("ai-memory_memory_write_page") == "deny"
    assert effect("ai-memory_memory_message_send") == "deny"
    assert effect("ai-memory_memory_delete_page") == "deny"
    assert effect("execute") == "deny"
    assert effect("shell") == "deny"
    assert effect("http") == "deny"
    assert effect("http_request") == "deny"
    assert effect("webfetch") == "deny"
    assert effect("websearch") == "deny"
    assert effect("browser") == "deny"
    assert effect("external_directory") == "deny"
    assert effect("subagent") == "deny"


def test_worker_permission_audit_rejects_misnamed_tools_and_unsafe_overrides() -> None:
    wrong_name = _restricted_worker_agent(query_action="ai_memory_memory_query")
    assert not worker_agent_policy_is_restricted([wrong_name], "seto-decomp-worker")

    write_enabled = _restricted_worker_agent()
    write_enabled["permissions"].append(
        {"action": "ai-memory_memory_write_page", "resource": "*", "effect": "allow"}
    )
    assert not worker_agent_policy_is_restricted([write_enabled], "seto-decomp-worker")


@pytest.mark.parametrize(
    "override",
    [
        {"action": "execute", "resource": "*", "effect": "allow"},
        {"action": "shell", "resource": "*", "effect": "allow"},
        {"action": "http", "resource": "*", "effect": "allow"},
        {"action": "webfetch", "resource": "*", "effect": "allow"},
        {"action": "websearch", "resource": "*", "effect": "allow"},
        {"action": "browser", "resource": "*", "effect": "allow"},
        {"action": "http_request", "resource": "*", "effect": "allow"},
        {"action": "ai-memory_*", "resource": "*", "effect": "allow"},
        {"action": "*", "resource": "*", "effect": "allow"},
    ],
)
def test_worker_policy_rejects_permissive_execution_and_network_overrides(
    override: dict[str, str],
) -> None:
    agent = _restricted_worker_agent()
    agent["permissions"].append(override)

    assert not worker_agent_policy_is_restricted([agent], "seto-decomp-worker")


def test_effective_permission_preflight_rejects_execute_allow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _restricted_worker_agent()
    agent["permissions"].append(
        {"action": "execute", "resource": "*", "effect": "allow"}
    )

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, json.dumps([agent]), "")

    monkeypatch.setattr(decomp_campaign_module.subprocess, "run", fake_run)

    assert not decomp_campaign_module._effective_worker_policy_ready(
        ["opencode"], tmp_path, "seto-decomp-worker"
    )


def test_ai_memory_connected_is_not_misreported_as_tool_availability() -> None:
    report = decomp_campaign_module._ai_memory_exposure_report(
        "✓ ai-memory  connected\n",
        registered_tool_names=None,
        worker_permissions_ready=True,
    )

    assert report == {
        "connection": "CONNECTED",
        "registered_tools": "UNVERIFIED",
        "worker_permissions": "READY",
        "available_to_agent": "UNVERIFIED",
    }


@pytest.mark.parametrize(
    ("names", "permissions_ready", "registered", "available"),
    [
        ([], True, "BLOCKED", "BLOCKED"),
        (["memory_query", "read_page"], True, "BLOCKED", "BLOCKED"),
        (["memory_query", "memory_read_page"], False, "READY", "BLOCKED"),
        (["memory_query", "memory_read_page"], True, "READY", "UNVERIFIED"),
    ],
)
def test_ai_memory_exposure_checks_catalog_names_and_permissions(
    names: list[str], permissions_ready: bool, registered: str, available: str
) -> None:
    report = decomp_campaign_module._ai_memory_exposure_report(
        "✓ ai-memory  connected\n",
        registered_tool_names=names,
        worker_permissions_ready=permissions_ready,
    )

    assert report["registered_tools"] == registered
    assert report["available_to_agent"] == available


def test_ai_memory_exposure_requires_session_tool_introspection_for_ready() -> None:
    report = decomp_campaign_module._ai_memory_exposure_report(
        "✓ ai-memory  connected\n",
        registered_tool_names=["memory_query", "memory_read_page"],
        worker_permissions_ready=True,
        effective_tool_names=["ai-memory_memory_query", "ai-memory_memory_read_page"],
    )

    assert report["registered_tools"] == "READY"
    assert report["available_to_agent"] == "READY"


def test_ai_memory_exposure_blocks_extra_tools_even_when_read_tools_are_present() -> None:
    report = decomp_campaign_module._ai_memory_exposure_report(
        "✓ ai-memory  connected\n",
        registered_tool_names=["memory_query", "memory_read_page"],
        worker_permissions_ready=True,
        effective_tool_names=[
            "ai-memory_memory_query",
            "ai-memory_memory_read_page",
            "ai-memory_memory_write_page",
        ],
    )

    assert report["registered_tools"] == "READY"
    assert report["available_to_agent"] == "BLOCKED"


def test_full_inconclusive_matcher_report_is_complete_and_retains_its_status() -> None:
    report = strict_report(word_count=3)
    report["function"] = "func_00001000"
    report["status"] = "INCONCLUSIVE"
    report["verified_decompilation"] = False
    report["match"].update(
        status="INCONCLUSIVE",
        total_words=4,
        limitations=["unresolved data identity"],
    )

    decomp_campaign_module._validate_complete_matcher_report(
        report,
        expected_address=0x1000,
        expected_size=16,
        expected_source_sha256="a" * 64,
    )


def test_incomplete_matcher_report_is_rejected_before_score_persistence() -> None:
    report = strict_report(word_count=2)
    report["function"] = "func_00001000"
    report["status"] = "NONMATCHING"
    report["verified_decompilation"] = False
    report["match"].update(
        status="NONMATCHING",
        total_words=2,
        difference_count=0,
        relocation_issues=["size mismatch: candidate is shorter"],
    )

    with pytest.raises(decomp_campaign_module.MatcherIncomplete):
        decomp_campaign_module._validate_complete_matcher_report(
            report,
            expected_address=0x1000,
            expected_size=16,
            expected_source_sha256="a" * 64,
        )


def test_checkpoint_sanitizer_preserves_only_known_diagnostic_codes() -> None:
    safe = decomp_campaign_module._sanitize_checkpoint(
        {
            "last_diagnostic": {"stage": "matcher", "code": "matcher_incomplete"},
            "ignored": "private path",
        },
        trusted_evidence=True,
    )
    unsafe = decomp_campaign_module._sanitize_checkpoint(
        {"last_diagnostic": {"stage": "matcher", "code": "private token"}},
        trusted_evidence=True,
    )

    assert safe == {"last_diagnostic": {"stage": "matcher", "code": "matcher_incomplete"}}
    assert unsafe == {}


def _historical_test_spec(path: str, content: bytes) -> dict[str, object]:
    return {
        "source_path": path,
        "sha256": hashlib.sha256(content).hexdigest(),
        "function": "func_00001000",
        "matching_words": 26,
        "total_words": 28,
        "first_divergence": {
            "address": "0x1004",
            "candidate": "bnel with lhu in the delay slot",
            "original": "bne followed by nop",
        },
    }


def test_historical_hypothesis_is_hash_identity_checked_and_worker_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hypothesis = b"void func_00001000(void) { return; }\n"
    repo = tmp_path / "repo"
    source = campaign_build_path(repo, "seto038/hypothesis.c")
    source.parent.mkdir(parents=True)
    source.write_bytes(hypothesis)
    monkeypatch.setattr(
        decomp_campaign_module,
        "HISTORICAL_HYPOTHESES",
        {"0x1000": _historical_test_spec("seto038/hypothesis.c", hypothesis)},
    )
    claims = [
        replace(
            Claim("0x1000", 112, "0x12345678", 1, "EXACT", worker, "openai", None, 1, 0, {}, {}),
            worker_id=worker,
        )
        for worker in ("openai", "deepseek")
    ]
    for claim in claims:
        (tmp_path / claim.worker_id).mkdir()

    evidence = [
        decomp_campaign_module._copy_known_historical_hypothesis(
            repo, tmp_path / claim.worker_id, claim
        )
        for claim in claims
    ]

    assert [item["status"] for item in evidence] == ["available", "available"]
    assert evidence[0]["sha256"] == hashlib.sha256(hypothesis).hexdigest()
    assert evidence[0]["matching_words"] == 26
    assert evidence[0]["total_words"] == 28
    assert evidence[0]["first_divergence"]["address"] == "0x1004"
    paths = [tmp_path / claim.worker_id / evidence[index]["path"] for index, claim in enumerate(claims)]
    assert paths[0] != paths[1]
    assert all(path.read_bytes() == hypothesis for path in paths)
    assert all("NONMATCHING" in evidence[index]["classification"] for index in range(2))


@pytest.mark.parametrize("failure", ["missing", "hash", "identity", "external", "symlink"])
def test_historical_hypothesis_invalid_provenance_degrades_without_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    content = b"void func_00001000(void) { return; }\n"
    repo = tmp_path / "repo"
    source_path = "seto038/hypothesis.c"
    source_content = b"void func_00002000(void) { return; }\n" if failure == "identity" else content
    expected_hash = hashlib.sha256(source_content).hexdigest()
    source = campaign_build_path(repo, source_path)
    source.parent.mkdir(parents=True)
    expected_identity = "func_00001000"
    if failure != "missing":
        source.write_bytes(source_content)
    if failure == "hash":
        expected_hash = "0" * 64
    if failure == "external":
        source_path = "../outside.c"
    if failure == "symlink":
        redirected = repo / "build" / "redirect"
        redirected.symlink_to(tmp_path, target_is_directory=True)
        source_path = "redirect/hypothesis.c"
        redirected_source = tmp_path / "hypothesis.c"
        redirected_source.write_bytes(content)
    monkeypatch.setattr(
        decomp_campaign_module,
        "HISTORICAL_HYPOTHESES",
        {
            "0x1000": {
                "source_path": source_path,
                "sha256": expected_hash,
                "function": expected_identity,
                "matching_words": 26,
                "total_words": 28,
                "first_divergence": {"address": "0x1004"},
            }
        },
    )
    worktree = tmp_path / "worker"
    claim = Claim("0x1000", 112, "0x12345678", 1, "EXACT", "openai", "openai", None, 1, 0, {}, {})

    evidence = decomp_campaign_module._copy_known_historical_hypothesis(repo, worktree, claim)

    assert evidence["status"] == "unavailable"
    assert evidence["reason"] in {
        "missing",
        "hash_mismatch",
        "identity_mismatch",
        "unsafe_path",
    }
    assert not (worktree / "build" / "decomp-campaign" / "openai" / "1000" / "evidence" / "historical" / "hypothesis.c").exists()


def test_historical_hypothesis_conflict_does_not_overwrite_existing_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"void func_00001000(void) { return; }\n"
    repo = tmp_path / "repo"
    source = campaign_build_path(repo, "seto038/hypothesis.c")
    source.parent.mkdir(parents=True)
    source.write_bytes(content)
    monkeypatch.setattr(
        decomp_campaign_module,
        "HISTORICAL_HYPOTHESES",
        {"0x1000": _historical_test_spec("seto038/hypothesis.c", content)},
    )
    worktree = tmp_path / "worker"
    claim = Claim("0x1000", 112, "0x12345678", 1, "EXACT", "openai", "openai", None, 1, 0, {}, {})
    destination = worktree / "build" / "decomp-campaign" / "openai" / "1000" / "evidence" / "historical" / "hypothesis.c"
    destination.parent.mkdir(parents=True)
    destination.write_text("existing different artifact", encoding="utf-8")
    original = destination.read_bytes()

    evidence = decomp_campaign_module._copy_known_historical_hypothesis(repo, worktree, claim)

    assert evidence["status"] == "unavailable"
    assert evidence["reason"] == "destination_conflict"
    assert destination.read_bytes() == original


def test_historical_hypothesis_removes_a_partial_copy_after_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"void func_00001000(void) { return; }\n"
    repo = tmp_path / "repo"
    source = campaign_build_path(repo, "seto038/hypothesis.c")
    source.parent.mkdir(parents=True)
    source.write_bytes(content)
    monkeypatch.setattr(
        decomp_campaign_module,
        "HISTORICAL_HYPOTHESES",
        {"0x1000": _historical_test_spec("seto038/hypothesis.c", content)},
    )
    worktree = tmp_path / "worker"
    worktree.mkdir()
    claim = Claim("0x1000", 112, "0x12345678", 1, "EXACT", "openai", "openai", None, 1, 0, {}, {})
    destination = (
        worktree
        / "build"
        / "decomp-campaign"
        / "openai"
        / "1000"
        / "evidence"
        / "historical"
        / "hypothesis.c"
    )
    original_open = Path.open

    class FailingWriter:
        def __init__(self, output) -> None:
            self.output = output

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.output.close()

        def fileno(self):
            return self.output.fileno()

        def write(self, data: bytes) -> int:
            self.output.write(data[:4])
            self.output.flush()
            raise OSError("simulated disk-full during copy")

        def flush(self) -> None:
            self.output.flush()

    def failing_open(path: Path, *args, **kwargs):
        output = original_open(path, *args, **kwargs)
        if path == destination and args and args[0] == "xb":
            return FailingWriter(output)
        return output

    monkeypatch.setattr(Path, "open", failing_open)

    evidence = decomp_campaign_module._copy_known_historical_hypothesis(repo, worktree, claim)

    assert evidence == {"status": "unavailable", "reason": "copy_failed"}
    assert not destination.exists()


def test_historical_hypothesis_keeps_better_checkpoint_and_source_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"void func_00001000(void) { return; }\n"
    repo = tmp_path / "repo"
    historical = campaign_build_path(repo, "seto038/hypothesis.c")
    historical.parent.mkdir(parents=True)
    historical.write_bytes(content)
    history_spec = _historical_test_spec("seto038/hypothesis.c", content)
    history_spec["matching_words"] = 3
    history_spec["total_words"] = 4
    monkeypatch.setattr(
        decomp_campaign_module,
        "HISTORICAL_HYPOTHESES",
        {"0x1000": history_spec},
    )
    worktree = tmp_path / "worker"
    worktree.mkdir()
    candidate_source = worktree / "decomp" / "src" / "eboot" / "func_00001000.c"
    candidate_source.parent.mkdir(parents=True)
    candidate_source.write_text("older worker source\n", encoding="utf-8")
    best_source = b"void func_00001000(void) { return 1; }\n"
    best_hash = hashlib.sha256(best_source).hexdigest()
    snapshot_relative = f"decomp-campaign/checkpoints/00001000/{best_hash}.c"
    snapshot = campaign_build_path(repo, snapshot_relative)
    snapshot.parent.mkdir(parents=True)
    snapshot.write_bytes(best_source)

    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000", preferred_provider="openai")])
    claim = store.claim_next("openai", "openai")
    assert claim is not None
    checkpoint = {
        "best_source_sha256": best_hash,
        "best_source_snapshot": snapshot_relative,
        "best_match": {"status": "NONMATCHING", "matching_words": 3, "total_words": 4},
    }
    store.save_checkpoint(claim, checkpoint, trusted_evidence=True)
    claim = replace(claim, checkpoint=checkpoint)
    runner = CampaignRunner(
        store,
        opencode_command=fake_opencode_command(tmp_path),
        worktrees={"openai": worktree},
        checkpoint_repo_root=repo,
    )

    prepared = runner._attach_historical_hypothesis(worktree, claim)
    runner._restore_best_source(worktree, prepared)

    assert prepared.checkpoint["best_source_sha256"] == best_hash
    assert prepared.checkpoint["best_source_snapshot"] == snapshot_relative
    assert prepared.checkpoint["historical_hypothesis"]["classification"] == (
        "NONMATCHING / not certified"
    )
    assert candidate_source.read_bytes() == best_source


def test_restore_candidate_source_prefers_latest_hypothesis_without_overwriting_best(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    worktree = tmp_path / "luna-01"
    worktree.mkdir()
    best_source = b"void func_00001000(void) { return 1; }\n"
    latest_source = b"void func_00001000(void) { return 2; }\n"
    best_hash = hashlib.sha256(best_source).hexdigest()
    latest_hash = hashlib.sha256(latest_source).hexdigest()
    best_relative = f"decomp-campaign/checkpoints/00001000/{best_hash}.c"
    latest_relative = f"decomp-campaign/checkpoints/00001000/{latest_hash}.c"
    for relative, content in (
        (best_relative, best_source),
        (latest_relative, latest_source),
    ):
        snapshot = campaign_build_path(repo, relative)
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(content)
    candidate_source = worktree / "decomp/src/eboot/func_00001000.c"
    candidate_source.parent.mkdir(parents=True)
    candidate_source.write_bytes(b"stale worktree hypothesis\n")
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    runner = CampaignRunner(
        store,
        opencode_command=["unused"],
        worktrees={"luna-01": worktree},
        checkpoint_repo_root=repo,
    )
    claim = Claim(
        "0x1000",
        16,
        "0x12345678",
        10,
        "EXACT",
        "luna-01",
        "openai",
        None,
        3,
        0,
        {
            "best_source_sha256": best_hash,
            "best_source_snapshot": best_relative,
            "source_sha256": latest_hash,
            "latest_source_snapshot": latest_relative,
        },
        {},
    )

    runner._restore_best_source(worktree, claim)

    assert candidate_source.read_bytes() == latest_source
    assert (campaign_build_path(repo, best_relative)).read_bytes() == best_source
    assert (campaign_build_path(repo, latest_relative)).read_bytes() == latest_source


def test_status_report_exposes_only_the_bounded_diagnostic(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000", preferred_provider="openai")])
    claim = store.claim_next("openai", "openai")
    assert claim is not None
    store.fail(
        claim,
        Failure(
            FailureKind.AGENT_ERROR,
            diagnostic_stage="matcher",
            diagnostic_code="matcher_incomplete",
        ),
    )
    config = {
        "execution": {},
        "worktrees": {"root": "build/decomp-campaign/worktrees"},
        "workers": {"openai": {"provider": "openai"}},
    }

    report = decomp_campaign_module._status_report(store, config, tmp_path)

    assert report["blockers"] == [
        {
            "address": "0x1000",
            "status": "blocked",
            "diagnostic": {"stage": "matcher", "code": "matcher_incomplete"},
        }
    ]


def test_status_report_shows_configured_active_and_idle_workers(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed(
        [
            candidate("0x1000"),
            Candidate("0x2000", 0, "0x22222222", 40, "UNVERIFIED", initial_state="needs_boundary"),
        ]
    )
    model_claim = store.claim_next("luna-01", "openai")
    boundary_claim = store.claim_boundary("deepseek-01")
    assert model_claim is not None and boundary_claim is not None
    config = {
        "execution": {},
        "inventory": "config/decomp_campaign_inventory.json",
        "worktrees": {"root": "build/decomp-campaign/worktrees"},
        "workers": {
            "luna-01": {"provider": "openai", "model": "openai/gpt-6-luna", "max_parallel": 4},
            "luna-02": {"provider": "openai", "model": "openai/gpt-6-luna", "max_parallel": 4},
            "deepseek-01": {"provider": "opencode", "model": "opencode/deepseek-v4.1-flash-free", "max_parallel": 4},
        },
    }

    report = decomp_campaign_module._status_report(store, config, tmp_path)

    assert report["worker_pool"]["configured"] == 3
    assert report["worker_pool"]["active"] == 2
    assert report["worker_pool"]["idle"] == 1
    assert report["worker_pool"]["workers"]["luna-01"]["assignments"] == [
        {"address": "0x1000", "status": "running", "stage": "inference"}
    ]
    assert report["worker_pool"]["workers"]["deepseek-01"]["assignments"] == [
        {"address": "0x2000", "status": "boundary_checking", "stage": "ghidra"}
    ]


def test_explicit_precomparison_inconclusive_keeps_object_provenance_without_certifying(
    tmp_path: Path,
) -> None:
    source = tmp_path / "func_00001000.c"
    source.write_text("void func_00001000(void) { return; }\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    object_path = out / "func_00001000.o"
    object_path.write_bytes(b"compiled-object-fixture")
    claim = Claim(
        "0x1000", 16, "0x12345678", 50, "EXACT", "luna-01", "openai", "ses_test", 1, 0, {}, {}
    )
    result = decomp_campaign_module.WorkResult(
        5,
        "",
        "INCONCLUSIVE: symbol 'FUN_00001000' is not present in the candidate",
    )

    report = _explicit_inconclusive_match_report(
        result,
        claim=claim,
        source=source,
        out=out,
        report_relative="decomp-campaign/luna-01/1000/attempt-1/verify-1",
        compiler="mwccpsp.exe",
        flags=["-O4,p", "-sdatathreshold", "0"],
        includes=["decomp/include"],
    )

    assert report is not None
    assert report["status"] == "INCONCLUSIVE"
    assert report["symbol"] is None
    assert report["requested_symbol"] == "func_00001000"
    assert report["provenance"]["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert report["provenance"]["object_sha256"] == hashlib.sha256(object_path.read_bytes()).hexdigest()
    assert report["match"]["comparison_complete"] is False
    assert report["match"]["matching_words"] == -1
    assert not is_strict_match(report, expected_address=0x1000, expected_size=16)
    decomp_campaign_module._validate_complete_matcher_report(
        report,
        expected_address=0x1000,
        expected_size=16,
        expected_source_sha256=report["provenance"]["source_sha256"],
    )


def test_explicit_precomparison_inconclusive_requires_a_compiled_object(
    tmp_path: Path,
) -> None:
    source = tmp_path / "func_00001000.c"
    source.write_text("void func_00001000(void) { return; }\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    claim = Claim(
        "0x1000", 16, "0x12345678", 50, "EXACT", "luna-01", "openai", "ses_test", 1, 0, {}, {}
    )

    report = _explicit_inconclusive_match_report(
        decomp_campaign_module.WorkResult(
            5, "", "INCONCLUSIVE: no function was discovered in '.text'"
        ),
        claim=claim,
        source=source,
        out=out,
        report_relative="decomp-campaign/luna-01/1000/attempt-1/verify-1",
        compiler="mwccpsp.exe",
        flags=["-O4,p", "-sdatathreshold", "0"],
        includes=["decomp/include"],
    )

    assert report is None


def test_matcher_wrapper_persists_explicit_inconclusive_with_source_object_provenance(
    tmp_path: Path,
) -> None:
    source = tmp_path / "func_00001000.c"
    source.write_text("void FUN_00001000(void) { return; }\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    (out / "func_00001000.o").write_bytes(b"compiled object")
    config = tmp_path / "seto.toml"
    config.write_text(
        '[tools.mwccpsp]\npath = "/tools/mwccpsp.exe"\n'
        '[match]\nflags = ["-O4,p", "-sdatathreshold", "0"]\n'
        'includes = ["decomp/include"]\n',
        encoding="utf-8",
    )
    claim = Claim(
        "0x1000", 16, "0x12345678", 50, "EXACT", "luna-01", "openai", "ses_test", 1, 0, {}, {}
    )

    report = decomp_campaign_module._matcher_report_from_process(
        decomp_campaign_module.WorkResult(
            5, "", "INCONCLUSIVE: symbol 'FUN_00001000' is not present in the candidate"
        ),
        claim=claim,
        source=source,
        out=out,
        config=config,
        relative_out="decomp-campaign/luna-01/1000/attempt-1/verify-1",
    )

    assert report["status"] == "INCONCLUSIVE"
    assert report["provenance"]["compiler"] == "/tools/mwccpsp.exe"
    assert report["report_path"] == (
        "build/decomp-campaign/luna-01/1000/attempt-1/verify-1/func_00001000.match.json"
    )
    assert (out / "func_00001000.match.json").is_file()


def test_matcher_wrapper_does_not_replace_malformed_json_with_text_diagnostic(
    tmp_path: Path,
) -> None:
    source = tmp_path / "func_00001000.c"
    source.write_text("void func_00001000(void) { return; }\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    (out / "func_00001000.o").write_bytes(b"compiled object")
    config = tmp_path / "seto.toml"
    config.write_text(
        '[tools.mwccpsp]\npath = "/tools/mwccpsp.exe"\n'
        '[match]\nflags = ["-O4,p"]\nincludes = ["decomp/include"]\n',
        encoding="utf-8",
    )
    claim = Claim(
        "0x1000", 16, "0x12345678", 50, "EXACT", "luna-01", "openai", "ses_test", 1, 0, {}, {}
    )

    with pytest.raises(ValueError, match="JSON"):
        decomp_campaign_module._matcher_report_from_process(
            decomp_campaign_module.WorkResult(
                5, "{malformed", "INCONCLUSIVE: symbol is not present"
            ),
            claim=claim,
            source=source,
            out=out,
            config=config,
            relative_out="decomp-campaign/luna-01/1000/attempt-1/verify-1",
        )

    assert not (out / "func_00001000.match.json").exists()


@pytest.mark.parametrize(
    ("stderr", "error_type"),
    [
        (
            r"error: compilation failed in C:\private\secret.c token sk-sensitive-secret",
            decomp_campaign_module.MatcherCompilerError,
        ),
        (
            "error: candidate section '.text': needs 36 bytes at offset 0 but the section is 20 bytes",
            decomp_campaign_module.MatcherIncomplete,
        ),
    ],
)
def test_matcher_process_failures_keep_compiler_and_incomplete_distinctions(
    stderr: str, error_type: type[Exception]
) -> None:
    with pytest.raises(error_type) as raised:
        _raise_matcher_process_error(
            decomp_campaign_module.WorkResult(1, "", stderr)
        )
    excerpt = raised.value.excerpt
    assert excerpt
    assert len(excerpt) <= 600
    assert "C:\\private" not in excerpt
    assert "sk-sensitive-secret" not in excerpt


def test_mwccincludes_usage_warning_is_not_a_compiler_failure() -> None:
    result = decomp_campaign_module.WorkResult(
        5,
        "",
        "### mwccpsp.exe Usage Warning:\n"
        "# Environment variable 'MWCIncludes' not found\n"
        "INCONCLUSIVE: symbol 'func_00001000' is not present in the candidate",
    )

    _raise_matcher_process_error(result)

    excerpt = decomp_campaign_module._safe_diagnostic_excerpt(
        "### mwccpsp.exe Usage Warning:\n"
        "# Environment variable 'MWCIncludes' not found\n"
        "# Error: illegal conversion in candidate source"
    )
    assert "illegal conversion" in excerpt
    assert "MWCIncludes" not in excerpt


def test_prompt_makes_local_evidence_primary_and_memory_optional() -> None:
    claim = Claim(
        "0x2c28c",
        112,
        "0x7187E0F0",
        85,
        "EXACT",
        "openai",
        "openai",
        "ses-test",
        2,
        0,
        {
            "ghidra_log_path": "build/decomp-campaign/openai/2c28c/evidence/ghidra-attempt-2.log",
            "historical_hypothesis": {
                "status": "available",
                "path": "build/decomp-campaign/openai/2c28c/evidence/historical/hypothesis.c",
                "classification": "NONMATCHING / not certified",
                "matching_words": 26,
                "total_words": 28,
                "first_divergence": {"address": "0x2c2c4"},
            },
            "best_match": {
                "status": "NONMATCHING",
                "matching_words": 26,
                "total_words": 28,
                "difference_indices": [14, 15],
                "first_divergence_address": "0x2c2c4",
                "first_divergence_original": "0x14a30004",
                "first_divergence_candidate": "0x54a30005",
            },
            "last_attempt": {
                "status": "NONMATCHING",
                "matching_words": 26,
                "total_words": 28,
                "producer_worker_id": "openai",
                "producer_attempt_number": 2,
            },
            "last_diagnostic_detail": {
                "stage": "compiler",
                "code": "compiler_failed",
                "excerpt": "illegal conversion in the candidate source",
            },
            "local_experiments": [
                {
                    "origin_kind": "local_experiment",
                    "worker_id": "openai",
                    "status": "MATCHED",
                    "source_path": "build/decomp-campaign/experiments/2c28c/conditional-pointer.c",
                    "source_sha256": "b" * 64,
                    "matching_words": 28,
                    "total_words": 28,
                    "report_paths": ["build/decomp-campaign/experiments/2c28c/verify-1.json"],
                },
                {
                    "origin_kind": "local_experiment",
                    "worker_id": "deepseek",
                    "status": "MATCHED",
                    "source_path": "build/decomp-campaign/experiments/4217c/variant.c",
                    "source_sha256": "c" * 64,
                    "matching_words": 44,
                    "total_words": 44,
                    "report_paths": ["build/decomp-campaign/experiments/4217c/verify.json"],
                },
            ],
            "next_experiment": "inspect delay slot",
        },
        {},
    )

    prompt = decomp_campaign_module._prompt(claim, claim.checkpoint, Path("worker"))

    assert "ghidra-attempt-2.log" in prompt
    assert "SetoAnalyzeEntry" in prompt or "28" in prompt
    assert "build/seto035/export-triage.json" in prompt
    assert "relocation" in prompt.lower() and "call site" in prompt.lower()
    assert "NONMATCHING / not certified" in prompt
    assert "0x2c2c4" in prompt
    assert "26" in prompt and "28" in prompt
    assert "0x14a30004" in prompt and "0x54a30005" in prompt
    assert "last_attempt" in prompt and "producer_attempt_number" in prompt
    assert "illegal conversion" in prompt
    assert "conditional-pointer.c" in prompt
    assert "4217c/variant.c" not in prompt
    assert "func_0002C28C" in prompt
    assert "Ghidra's autogenerated FUN_ label" in prompt
    assert "optional" in prompt.lower()
    assert "if retrieval is unavailable, report that limitation" in prompt
    assert "first use" not in prompt.lower()


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
    local_opencode = repo / ".opencode" / "opencode.json"
    local_opencode.parent.mkdir(parents=True)
    local_opencode.write_text(
        json.dumps({"plugins": ["local-auth-plugin"], "providers": {"openai": {}}}),
        encoding="utf-8",
    )
    local_opencode_hash = hashlib.sha256(local_opencode.read_bytes()).hexdigest()

    worker_names = [
        *(f"luna-{index:02d}" for index in range(1, 5)),
        *(f"deepseek-{index:02d}" for index in range(1, 5)),
    ]
    config = {
        "workers": {name: {} for name in worker_names},
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
    assert set(workers) == set(worker_names)
    assert len({path.resolve() for path in workers.values()}) == 8
    for name, worktree in workers.items():
        assert subprocess.run(
            ["git", "branch", "--show-current"], cwd=worktree, check=True, capture_output=True, text=True
        ).stdout.strip() == f"seto/decomp-campaign/{name}"
        for input_name, relative in inputs.items():
            assert hashlib.sha256((worktree / relative).read_bytes()).hexdigest() == hashes[input_name]
        assert (worktree / "config/wsl/seto.toml").is_file()
        assert hashlib.sha256((worktree / ".opencode/opencode.json").read_bytes()).hexdigest() == local_opencode_hash


def test_unverified_inventory_boundary_runs_without_spending_model_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed(
        [
            Candidate(
                address="0x1000",
                size_bytes=0,
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
        "import json, pathlib, sys\n"
        "source = pathlib.Path('decomp/src/eboot/func_00001000.c')\n"
        "source.parent.mkdir(parents=True, exist_ok=True)\n"
        "source.write_text('void func_00001000(void) { return; }\\n')\n"
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

    def fake_prepare(_worktree: Path, claim: Claim, _deadline: float | None) -> Claim:
        assert claim.boundary_status == "UNVERIFIED"
        store.update_boundary(claim, 16, {"source": "synthetic Ghidra test"})
        return replace(claim, size_bytes=16, boundary_status="EXACT")

    monkeypatch.setattr(runner, "_prepare_claim", fake_prepare)
    result = runner.run([Worker("openai", "openai", "openai/gpt-6-luna")], max_tasks=2)
    task = store.get_task("0x1000")
    assert result["attempted"] == 1
    assert result["boundary_outcomes"] == {"boundary_validated": 1}
    assert len(store.list_attempts()) == 1
    assert task["boundary_status"] == "EXACT"
    assert task["size_bytes"] == 16
    assert task["status"] == "matched"


def test_model_worker_waits_for_parallel_boundary_discovery_and_claims_new_exact_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed(
        [
            candidate("0x1000"),
            Candidate(
                "0x2000", 0, "0x22222222", 20, "UNVERIFIED", initial_state="needs_boundary"
            ),
        ]
    )
    worktree = tmp_path / "luna-01"
    worktree.mkdir()
    runner = CampaignRunner(
        store,
        opencode_command=["unused"],
        worktrees={"luna-01": worktree},
        verifier=lambda *_args: {},
        ghidra_parallelism=1,
    )
    boundary_started = threading.Event()
    release_boundary = threading.Event()
    first_model_finished = threading.Event()

    def fake_prepare(_worktree: Path, claim: Claim, _deadline: float | None) -> Claim:
        boundary_started.set()
        assert release_boundary.wait(timeout=10)
        store.update_boundary(claim, 16, {"source": "parallel Ghidra proof"})
        return replace(claim, size_bytes=16, boundary_status="EXACT")

    def fake_model(
        _worker: Worker,
        claim: Claim,
        _deadline: float | None,
        *,
        max_total_attempts: int | None,
        on_attempt_started,
    ) -> str:
        started = store.start_attempt(claim, max_total_attempts=max_total_attempts)
        assert started is not None
        on_attempt_started()
        report = strict_report(started.address)
        result = {
            "status": "MATCHED",
            "source_sha256": report["provenance"]["source_sha256"],
            "matching_words": 4,
            "total_words": 4,
            "build_sha256": [report["provenance"]["object_sha256"]] * 2,
            "reports": [report, report],
        }
        status = store.complete(
            started,
            {},
            result,
            max_attempts_without_progress=3,
            max_attempts_per_candidate=8,
        )
        if started.address == "0x1000":
            first_model_finished.set()
        return status

    monkeypatch.setattr(runner, "_prepare_claim", fake_prepare)
    monkeypatch.setattr(runner, "_run_claim", fake_model)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            runner.run,
            [Worker("luna-01", "openai", "openai/gpt-6-luna")],
            max_tasks=10,
        )
        assert boundary_started.wait(timeout=5)
        assert first_model_finished.wait(timeout=5)
        assert store.get_task("0x2000")["status"] == "boundary_checking"
        release_boundary.set()
        result = future.result(timeout=15)

    assert result["attempted"] == 2
    assert result["boundary_outcomes"] == {"boundary_validated": 1}
    assert store.get_task("0x2000")["status"] == "matched"
    assert len(store.list_attempts()) == 2


def test_ghidra_boundary_failure_blocks_only_that_candidate_without_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed(
        [
            candidate("0x1000"),
            Candidate(
                "0x2000", 0, "0x22222222", 20, "UNVERIFIED", initial_state="needs_boundary"
            ),
        ]
    )
    worktree = tmp_path / "luna-01"
    worktree.mkdir()
    runner = CampaignRunner(
        store,
        opencode_command=["unused"],
        worktrees={"luna-01": worktree},
        verifier=lambda *_args: {},
    )

    def failed_prepare(_worktree: Path, _claim: Claim, _deadline: float | None) -> Claim:
        raise ValueError("ambiguous Ghidra body")

    def fake_model(
        _worker: Worker,
        claim: Claim,
        _deadline: float | None,
        *,
        max_total_attempts: int | None,
        on_attempt_started,
    ) -> str:
        started = store.start_attempt(claim, max_total_attempts=max_total_attempts)
        assert started is not None
        on_attempt_started()
        report = strict_report(started.address)
        return store.complete(
            started,
            {},
            {
                "status": "MATCHED",
                "source_sha256": report["provenance"]["source_sha256"],
                "matching_words": 4,
                "total_words": 4,
                "build_sha256": [report["provenance"]["object_sha256"]] * 2,
                "reports": [report, report],
            },
            max_attempts_without_progress=3,
            max_attempts_per_candidate=8,
        )

    monkeypatch.setattr(runner, "_prepare_claim", failed_prepare)
    monkeypatch.setattr(runner, "_run_claim", fake_model)

    result = runner.run(
        [Worker("luna-01", "openai", "openai/gpt-6-luna")], max_tasks=10
    )

    assert result["attempted"] == 1
    assert result["boundary_outcomes"] == {"boundary_blocked": 1}
    assert store.get_task("0x1000")["status"] == "matched"
    assert store.get_task("0x2000")["status"] == "blocked"
    assert store.get_task("0x2000")["attempt_count"] == 0
    assert len(store.list_attempts()) == 1


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
    latest_source = (
        worktree / "decomp/src/eboot/func_00001000.c"
    ).read_bytes()
    latest_hash = hashlib.sha256(latest_source).hexdigest()
    assert latest_source != b"version-one"
    latest_snapshot = repo / "build" / checkpoint["latest_source_snapshot"]
    assert checkpoint["source_sha256"] == latest_hash
    assert latest_snapshot.read_bytes() == latest_source

    next_claim = store.claim_next("openai", "openai")
    assert next_claim is not None
    runner._restore_best_source(worktree, next_claim)
    assert (worktree / "decomp/src/eboot/func_00001000.c").read_bytes() == latest_source
    assert snapshot.read_text(encoding="utf-8") == "version-one"


def test_lower_score_from_fallback_worker_keeps_best_report_provenance(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])

    def result(worker: str, attempt: int, score: int, source_hash: str, object_hash: str):
        reports = []
        for verify in (1, 2):
            report_path = (
                f"build/decomp-campaign/{worker}/1000/attempt-{attempt}/verify-{verify}/"
                "func_00001000.match.json"
            )
            difference = {
                "address": 0x1000 + score * 4,
                "word_index": score,
                "candidate": "0x00000000",
                "original": "0x00000001",
                "reason": "word differs",
            }
            reports.append(
                {
                    "status": "NONMATCHING",
                    "verified_decompilation": False,
                    "address": "0x1000",
                    "symbol": "func_00001000",
                    "report_path": report_path,
                    "provenance": {
                        "source_sha256": source_hash,
                        "object_sha256": object_hash,
                    },
                    "match": {
                        "status": "NONMATCHING",
                        "matching_words": score,
                        "total_words": 4,
                        "difference_count": 4 - score,
                        "differences": [difference],
                        "limitations": [],
                        "relocation_issues": [],
                    },
                }
            )
        return {
            "status": "NONMATCHING",
            "source_sha256": source_hash,
            "source_snapshot_path": f"decomp-campaign/checkpoints/00001000/{source_hash}.c",
            "matching_words": score,
            "total_words": 4,
            "build_sha256": [object_hash, object_hash],
            "reports": reports,
        }

    first = store.claim_next("openai", "openai")
    assert first is not None
    first = store.bind_session(first, "ses_test_openai")
    store.complete(
        first,
        {"next_experiment": "check original branch delay slot"},
        result("openai", 1, 3, "a" * 64, "b" * 64),
        max_attempts_without_progress=3,
        max_attempts_per_candidate=8,
    )

    # Simulate an older checkpoint written before matcher divergence details
    # were included; the next claim should enrich it from best_result_json.
    with store._connect() as db:
        checkpoint = json.loads(
            db.execute(
                "SELECT checkpoint_json FROM candidates WHERE address='0x1000'"
            ).fetchone()[0]
        )
        for key in (
            "first_divergence_address",
            "first_divergence_word_index",
            "first_divergence_candidate",
            "first_divergence_original",
            "first_divergence_reason",
        ):
            checkpoint["best_match"].pop(key, None)
        db.execute(
            "UPDATE candidates SET checkpoint_json=? WHERE address='0x1000'",
            (json.dumps(checkpoint),),
        )

    fallback = store.claim_next("deepseek", "opencode")
    assert fallback is not None
    assert fallback.checkpoint["best_match"]["first_divergence_address"] == "0x100c"
    assert fallback.checkpoint["best_match"]["first_divergence_original"] == "0x00000001"
    fallback = store.bind_session(fallback, "ses_test_deepseek")
    store.complete(
        fallback,
        {"next_experiment": "inspect first divergence"},
        result("deepseek", 2, 2, "c" * 64, "d" * 64),
        max_attempts_without_progress=3,
        max_attempts_per_candidate=8,
    )

    task = store.get_task("0x1000")
    assert task["best_result"]["campaign_origin"]["worker_id"] == "openai"
    best_match = task["checkpoint"]["best_match"]
    assert best_match["report_path"] == (
        "build/decomp-campaign/openai/1000/attempt-1/verify-1/func_00001000.match.json"
    )
    assert best_match["producer_worker_id"] == "openai"
    assert best_match["first_divergence_address"] == "0x100c"
    assert best_match["first_divergence_candidate"] == "0x00000000"
    latest = task["checkpoint"]["last_attempt"]
    assert latest["producer_worker_id"] == "deepseek"
    assert latest["matching_words"] == 2
    assert latest["report_path"] == (
        "build/decomp-campaign/deepseek/1000/attempt-2/verify-1/func_00001000.match.json"
    )
    assert set(task["checkpoint"]["evidence_paths"]) >= {
        best_match["report_path"],
        latest["report_path"],
    }


def test_matcher_outputs_are_scoped_to_their_attempt(tmp_path: Path, monkeypatch) -> None:
    worktree = tmp_path / "openai"
    worktree.mkdir()
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    runner = CampaignRunner(
        store,
        opencode_command=["opencode"],
        worktrees={"openai": worktree},
        verifier=lambda *_args: {},
    )
    claim = Claim(
        "0x1000", 16, "0x12345678", 50, "EXACT", "openai", "openai", "ses_test", 3, 0, {}, {}
    )
    report = strict_report("0x1000", word_count=4)
    calls = []

    def fake_run(argv, **_kwargs):
        calls.append(list(argv))
        return decomp_campaign_module.WorkResult(0, json.dumps(report), "")

    monkeypatch.setattr(decomp_campaign_module, "_run_process", fake_run)

    reports = runner._run_matcher_native(
        worktree,
        claim,
        worktree / "source.c",
        worktree / "eboot.elf",
        worktree / "seto.toml",
        worktree / "match_function.py",
    )

    expected = [
        "build/decomp-campaign/openai/1000/attempt-3/verify-1/func_00001000.match.json",
        "build/decomp-campaign/openai/1000/attempt-3/verify-2/func_00001000.match.json",
    ]
    assert [item["report_path"] for item in reports] == expected
    out_arguments = [argv[argv.index("--out") + 1].replace("\\", "/") for argv in calls]
    assert all("/attempt-3/verify-" in value for value in out_arguments)


def test_match_summary_uses_campaign_origin_when_report_paths_are_absent() -> None:
    result = {
        "status": "NONMATCHING",
        "source_sha256": "a" * 64,
        "matching_words": 3,
        "total_words": 4,
        "build_sha256": ["b" * 64, "b" * 64],
        "campaign_origin": {
            "worker_id": "openai",
            "provider": "openai",
            "session_id": "ses_test_best",
            "attempt_number": 3,
        },
        "reports": [
            {
                "address": "0x1000",
                "match": {
                    "status": "NONMATCHING",
                    "matching_words": 3,
                    "total_words": 4,
                    "difference_count": 1,
                    "differences": [],
                    "limitations": [],
                },
            }
        ],
    }

    summary = decomp_campaign_module._match_checkpoint_summary(result)

    assert summary["report_path"] == (
        "build/decomp-campaign/openai/1000/attempt-3/verify-1/func_00001000.match.json"
    )
    assert summary["producer_worker_id"] == "openai"
    assert summary["producer_attempt_number"] == 3


def test_cli_accepts_repeated_productive_candidate_filters() -> None:
    args = decomp_campaign_module.build_parser().parse_args(
        [
            "run",
            "--confirm",
            "--productive",
            "--candidate-address",
            "0x2c28c",
            "--candidate-address",
            "0x4217c",
        ]
    )

    assert args.candidate_address == ["0x2c28c", "0x4217c"]


def test_all_eligible_requires_explicit_productive_scope_and_conflicts_with_address_filter() -> None:
    args = decomp_campaign_module.build_parser().parse_args(
        ["run", "--confirm", "--productive", "--continuous", "--all-eligible"]
    )
    assert args.all_eligible is True
    assert args.candidate_address is None
    assert productive_candidate_selection(
        productive=True,
        all_eligible=True,
        candidate_addresses=None,
        candidates=[candidate("0x1000")],
    ) is None
    with pytest.raises(ValueError, match="mutually exclusive"):
        productive_candidate_selection(
            productive=True,
            all_eligible=True,
            candidate_addresses=["0x1000"],
            candidates=[candidate("0x1000")],
        )
    with pytest.raises(ValueError, match="require --productive"):
        productive_candidate_selection(
            productive=False,
            all_eligible=True,
            candidate_addresses=None,
            candidates=[candidate("0x1000")],
        )


def test_resume_cli_accepts_selective_retry_address() -> None:
    args = decomp_campaign_module.build_parser().parse_args(
        ["resume", "--retry-address", "0x4217c"]
    )

    assert args.retry_address == ["0x4217c"]


def test_productive_candidate_address_filter_is_normalized_and_scoped() -> None:
    candidates = [candidate("0x1000"), candidate("0x2000")]

    assert decomp_campaign_module._normalize_candidate_addresses(
        ["0X1000", "0x2000"], candidates, required=True
    ) == ["0x1000", "0x2000"]
    with pytest.raises(ValueError, match="required"):
        decomp_campaign_module._normalize_candidate_addresses(
            None, candidates, required=True
        )
    with pytest.raises(ValueError, match="invalid"):
        decomp_campaign_module._normalize_candidate_addresses(
            ["0xnot-hex"], candidates, required=True
        )
    with pytest.raises(ValueError, match="inventory"):
        decomp_campaign_module._normalize_candidate_addresses(
            ["0x3000"], candidates, required=True
        )
    with pytest.raises(ValueError, match="duplicate"):
        decomp_campaign_module._normalize_candidate_addresses(
            ["0x1000", "0X1000"], candidates, required=True
        )


@pytest.mark.parametrize(
    ("historical_attempts", "total_ceiling", "expected_new_attempts"),
    [(4, 12, 8), (12, 12, 0), (14, 12, None)],
)
def test_productive_run_max_tasks_is_a_cumulative_sqlite_ceiling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    historical_attempts: int,
    total_ceiling: int,
    expected_new_attempts: int,
) -> None:
    repo = Path(__file__).resolve().parents[1]
    config_path = tmp_path / "local.toml"
    database = tmp_path / "campaign.sqlite3"
    candidates = [candidate("0x1000"), candidate("0x2000")]
    store = CampaignStore(database)
    store.seed(candidates)
    attempts_per_candidate = historical_attempts // len(candidates)
    with store._connect() as db:
        for item in candidates:
            db.execute(
                "UPDATE candidates SET attempt_count=?,status='pending' WHERE address=?",
                (attempts_per_candidate, item.address),
            )
            for attempt_number in range(1, attempts_per_candidate + 1):
                db.execute(
                    "INSERT INTO attempts(address,attempt_number,worker_id,provider,session_id,started_at,ended_at,outcome) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (
                        item.address,
                        attempt_number,
                        "openai",
                        "openai",
                        f"ses_history_{item.address[-1]}_{attempt_number}",
                        float(attempt_number),
                        float(attempt_number) + 0.5,
                        "agent_error",
                    ),
                )

    config = {
        "execution": {
            "enabled": True,
            "provider_access_verified": True,
            "worker_permissions_reviewed": True,
            "pilot_verified": True,
            "productive_expansion_authorized": True,
            "continuous": False,
        },
        "opencode": {"command": ["opencode"]},
        "models": {"allowlist": ["openai/gpt-6-luna", "opencode/deepseek-v4.1-flash-free"]},
        "workers": {
            "openai": {"provider": "openai", "model": "openai/gpt-6-luna", "agent": "seto-decomp-worker"},
            "deepseek": {"provider": "opencode", "model": "opencode/deepseek-v4.1-flash-free", "agent": "seto-decomp-worker"},
        },
        "limits": {
            "max_workers": 2,
            "max_tasks": 12,
            "max_duration_seconds": 5400,
            "agent_timeout_seconds": 900,
            "max_output_bytes": 1048576,
            "max_attempts_without_progress": 3,
            "max_attempts_per_candidate": 8,
            "lease_seconds": 3600,
            "max_retry_after_seconds": 900,
        },
        "pilot": {"max_tasks": 4, "max_duration_seconds": 1800, "candidate_addresses": ["0x1000", "0x2000"]},
        "toolchain": {"wsl_distro": "Ubuntu", "ghidra_local_config": "config/decomp_campaign.local.toml"},
        "inputs": {"eboot_sha256": "a" * 64},
        "worktrees": {"root": "build/decomp-campaign/worktrees"},
    }
    local_ghidra_config = tmp_path / "config" / "decomp_campaign.local.toml"
    local_ghidra_config.parent.mkdir(parents=True)
    local_ghidra_config.write_text("[ghidra]\n", encoding="utf-8")
    monkeypatch.setattr(decomp_campaign_module, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(decomp_campaign_module, "load_config", lambda _path: config)
    monkeypatch.setattr(
        decomp_campaign_module,
        "_config_paths",
        lambda *_args: (tmp_path / "inventory.json", database),
    )
    monkeypatch.setattr(
        decomp_campaign_module,
        "load_inventory",
        lambda _path: (candidates, {"source_commit": "test"}),
    )
    monkeypatch.setattr(
        decomp_campaign_module,
        "_doctor",
        lambda *_args: {
            "opencode": {
                "workers": {"openai": {"ready": True}, "deepseek": {"ready": True}}
            },
            "wsl_python": "Python 3.12",
            "toolchain": {"ghidra": "READY", "mwcc": "READY", "wibo": "READY"},
        },
    )
    monkeypatch.setattr(decomp_campaign_module, "_sanitize_opencode_prefix", lambda command: command)
    monkeypatch.setattr(decomp_campaign_module, "_effective_worker_policy_ready", lambda *_args: True)
    monkeypatch.setattr(
        decomp_campaign_module,
        "verify_campaign_inputs",
        lambda *_args: {name: {"matches": True} for name in ("eboot", "libtutoriallist", "libhtml_view", "triage")},
    )
    worker_roots = {name: tmp_path / name for name in ("openai", "deepseek")}
    for path in worker_roots.values():
        path.mkdir()
    monkeypatch.setattr(
        decomp_campaign_module,
        "prepare_worker_worktrees",
        lambda *_args: worker_roots,
    )
    captured: dict[str, object] = {}

    class FakeRunner:
        def __init__(self, *_args: object, **kwargs: object) -> None:
            captured["candidate_addresses"] = kwargs.get("candidate_addresses")

        def run(self, _workers: object, *, max_tasks: int) -> dict[str, object]:
            captured["max_tasks"] = max_tasks
            return {"attempted": max_tasks, "outcomes": {}}

    monkeypatch.setattr(decomp_campaign_module, "CampaignRunner", FakeRunner)
    monkeypatch.setattr(decomp_campaign_module, "_print_json", lambda _value: None)

    argv = [
        "--config", str(config_path), "run", "--confirm", "--productive",
        "--allow-openai-usage", "--allow-free-model-usage",
        "--candidate-address", "0x1000", "--candidate-address", "0x2000",
        "--max-tasks", str(total_ceiling),
    ]
    exit_code = decomp_campaign_module.main(argv)

    if expected_new_attempts is None:
        assert exit_code == 2
        assert "max_tasks" not in captured
    else:
        assert exit_code == 0
        assert captured.get("candidate_addresses") == ["0x1000", "0x2000"]
    if expected_new_attempts:
        assert captured.get("max_tasks") == total_ceiling
    elif expected_new_attempts == 0:
        assert "max_tasks" not in captured


def test_all_eligible_run_discovers_exports_and_seeds_zero_size_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "config" / "run.toml"
    config_path.parent.mkdir(parents=True)
    database = tmp_path / "campaign.sqlite3"
    inventory_path = tmp_path / "inventory.json"
    certified_addresses = ["0x2c28c", "0x31650"]
    base_candidates = [
        candidate("0x1000"),
        candidate("0x2c28c"),
        Candidate(
            "0x31650", 0, "0x9EA6989A", 48, "UNVERIFIED", initial_state="needs_boundary"
        ),
    ]
    discovered = Candidate(
        "0x2000",
        0,
        "0x22222222",
        21,
        "UNVERIFIED",
        evidence={"source": "verified triage export", "prx_call_sites": []},
        initial_state="needs_boundary",
    )
    config = {
        "execution": {
            "enabled": True,
            "continuous": True,
            "provider_access_verified": True,
            "worker_permissions_reviewed": True,
            "pilot_verified": True,
            "productive_expansion_authorized": True,
        },
        "opencode": {"command": ["opencode"]},
        "models": {"allowlist": ["openai/gpt-6-luna", "opencode/deepseek-v4.1-flash-free"]},
        "workers": {
            "luna-01": {"provider": "openai", "model": "openai/gpt-6-luna", "agent": "seto-decomp-worker", "max_parallel": 4},
            "deepseek-01": {"provider": "opencode", "model": "opencode/deepseek-v4.1-flash-free", "agent": "seto-decomp-worker", "max_parallel": 4},
        },
        "limits": {
            "max_workers": 2,
            "max_tasks": 20,
            "max_duration_seconds": 21600,
            "agent_timeout_seconds": 900,
            "max_output_bytes": 1048576,
            "max_attempts_without_progress": 3,
            "max_attempts_per_candidate": 8,
            "lease_seconds": 3660,
            "max_retry_after_seconds": 900,
            "ghidra_parallelism": 1,
            "matcher_parallelism": 2,
        },
        "pilot": {"max_tasks": 4, "max_duration_seconds": 1800, "candidate_addresses": ["0x1000", "0x2000"]},
        "toolchain": {"wsl_distro": "Ubuntu", "ghidra_local_config": "config/decomp_campaign.local.toml", "mwcc_config": "config/wsl/seto.toml"},
        "inputs": {"eboot_sha256": "a" * 64, "triage_report": "build/seto035/export-triage.json"},
        "worktrees": {"root": "build/decomp-campaign/worktrees", "branch_prefix": "seto/decomp-campaign"},
    }
    (tmp_path / "config" / "decomp_campaign.local.toml").write_text("[ghidra]\n", encoding="utf-8")
    monkeypatch.setattr(decomp_campaign_module, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(decomp_campaign_module, "load_config", lambda _path: config)
    monkeypatch.setattr(
        decomp_campaign_module,
        "_config_paths",
        lambda *_args: (inventory_path, database),
    )
    load_count = 0

    def fake_load_inventory(_path: Path):
        nonlocal load_count
        load_count += 1
        items = base_candidates if load_count == 1 else [*base_candidates, discovered]
        return items, {
            "baseline": {
                "eboot_matched_functions": len(certified_addresses),
                "eboot_matched_addresses": certified_addresses,
            },
            "source_commit": "test",
        }

    monkeypatch.setattr(decomp_campaign_module, "load_inventory", fake_load_inventory)
    monkeypatch.setattr(
        decomp_campaign_module,
        "discover_proven_exports",
        lambda *_args, **_kwargs: [discovered],
    )
    monkeypatch.setattr(
        decomp_campaign_module,
        "append_inventory_candidates",
        lambda _path, items: len(items),
    )
    monkeypatch.setattr(
        decomp_campaign_module,
        "_doctor",
        lambda *_args: {
            "opencode": {
                "workers": {
                    "luna-01": {"ready": True},
                    "deepseek-01": {"ready": True},
                }
            },
            "wsl_python": "Python 3.12",
            "toolchain": {"ghidra": "READY", "mwcc": "READY", "wibo": "READY"},
        },
    )
    monkeypatch.setattr(decomp_campaign_module, "_sanitize_opencode_prefix", lambda command: command)
    monkeypatch.setattr(decomp_campaign_module, "_effective_worker_policy_ready", lambda *_args: True)
    monkeypatch.setattr(
        decomp_campaign_module,
        "verify_campaign_inputs",
        lambda *_args: {name: {"matches": True} for name in ("eboot", "libtutoriallist", "libhtml_view", "triage")},
    )
    worker_roots = {name: tmp_path / name for name in config["workers"]}
    for worktree in worker_roots.values():
        worktree.mkdir()
    monkeypatch.setattr(decomp_campaign_module, "prepare_worker_worktrees", lambda *_args: worker_roots)
    captured: dict[str, object] = {}

    class FakeRunner:
        def __init__(self, *_args: object, **kwargs: object) -> None:
            captured["candidate_addresses"] = kwargs.get("candidate_addresses")
            captured["worker_count"] = len(kwargs["worktrees"])
            captured["provider_parallelism"] = kwargs.get("provider_parallelism")
            captured["excluded_addresses"] = kwargs.get("excluded_addresses")

        def run(self, workers: object, *, max_tasks: int) -> dict[str, object]:
            captured["max_tasks"] = max_tasks
            captured["workers"] = len(workers)  # type: ignore[arg-type]
            return {"attempted": 0, "outcomes": {}, "boundary_outcomes": {}, "stopped": False}

    monkeypatch.setattr(decomp_campaign_module, "CampaignRunner", FakeRunner)
    output: dict[str, object] = {}
    monkeypatch.setattr(decomp_campaign_module, "_print_json", output.update)

    assert decomp_campaign_module.main(
        [
            "--config", str(config_path), "run", "--confirm", "--productive",
            "--continuous", "--all-eligible", "--allow-openai-usage",
            "--allow-free-model-usage", "--max-tasks", "10",
        ]
    ) == 0

    assert captured["candidate_addresses"] is None
    assert captured["worker_count"] == 2
    assert captured["provider_parallelism"] == {"openai": 4, "opencode": 4}
    assert set(captured["excluded_addresses"]) == set(certified_addresses)
    assert captured["workers"] == 2
    assert captured["max_tasks"] == 10
    assert output["new_candidates_discovered"] == 1
    store = CampaignStore(database)
    assert {task["address"] for task in store.list_tasks()} == {"0x1000", "0x2000"}
    assert store.get_task("0x2000")["size_bytes"] == 0
    assert store.list_attempts() == []
    assert store.claim_next(
        "luna-01", "openai", eligible_addresses=certified_addresses
    ) is None
    boundary = store.claim_boundary("ghidra-01")
    assert boundary is not None and boundary.address == "0x2000"


def test_selective_retry_changes_only_requested_block_and_preserves_history(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000"), candidate("0x2000")])
    original = {}
    with store._connect() as db:
        for address, session in (("0x1000", "ses_target"), ("0x2000", "ses_other")):
            checkpoint = {"next_experiment": f"keep {address}", "best_source_sha256": "a" * 64}
            best_result = {"status": "NONMATCHING", "matching_words": 2, "source_sha256": "a" * 64}
            encoded_checkpoint = json.dumps(checkpoint, sort_keys=True)
            encoded_result = json.dumps(best_result, sort_keys=True)
            db.execute(
                "UPDATE candidates SET status='blocked',attempt_count=2,attempts_without_progress=1,"
                "owner=NULL,provider=NULL,lease_until=NULL,session_id=?,checkpoint_json=?,best_result_json=? "
                "WHERE address=?",
                (session, encoded_checkpoint, encoded_result, address),
            )
            original[address] = (encoded_checkpoint, encoded_result, session)
            for attempt in (1, 2):
                db.execute(
                    "INSERT INTO attempts(address,attempt_number,worker_id,provider,session_id,started_at,ended_at,outcome) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (address, attempt, "openai", "openai", session, float(attempt), float(attempt + 1), "agent_error"),
                )

    assert store.retry_blocked_addresses(["0x1000"]) == ["0x1000"]
    target = store.get_task("0x1000")
    untouched = store.get_task("0x2000")
    assert target["status"] == "pending"
    assert target["attempt_count"] == 2
    assert target["session_id"] == original["0x1000"][2]
    assert target["checkpoint"] == json.loads(original["0x1000"][0])
    assert target["best_result"] == json.loads(original["0x1000"][1])
    assert untouched["status"] == "blocked"
    assert untouched["attempt_count"] == 2
    assert untouched["session_id"] == original["0x2000"][2]
    assert len(store.list_attempts()) == 4


def test_selective_retry_rejects_active_lease(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])
    with store._connect() as db:
        db.execute(
            "UPDATE candidates SET status='blocked',owner='openai',lease_until=?,attempt_count=1 WHERE address='0x1000'",
            (time.time() + 300,),
        )

    with pytest.raises(ValueError, match="lease"):
        store.retry_blocked_addresses(["0x1000"])
    assert store.get_task("0x1000")["status"] == "blocked"


def test_reopen_recoverable_candidate_requires_reason_exact_boundary_and_preserves_history(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000"), candidate("0x2000")])
    with store._connect() as db:
        db.execute(
            """UPDATE candidates SET status='stalled',attempt_count=9,
               attempts_without_progress=2,session_id='ses_kept',
               checkpoint_json=?,best_result_json=? WHERE address='0x1000'""",
            (
                json.dumps({"source_sha256": "a" * 64, "next_experiment": "keep"}),
                json.dumps({"status": "NONMATCHING", "matching_words": 3}),
            ),
        )
        db.execute(
            "UPDATE candidates SET status='blocked',boundary_status='UNVERIFIED',size_bytes=0 "
            "WHERE address='0x2000'"
        )
        for attempt in range(1, 10):
            db.execute(
                """INSERT INTO attempts(address,attempt_number,worker_id,provider,session_id,
                   started_at,ended_at,outcome) VALUES('0x1000',?,'old','openai','ses_kept',?,?,?)""",
                (attempt, float(attempt), float(attempt) + 0.5, "pending"),
            )

    reason = "EXACT source/object from luna-01; current matcher can reproduce full comparison"
    reopened = store.reopen_recoverable_candidates(
        {"0x1000": reason},
        max_attempts_per_candidate=12,
        campaign_id="SETO-DECOMP-046",
    )

    task = store.get_task("0x1000")
    assert reopened == ["0x1000"]
    assert task["status"] == "pending"
    assert task["attempt_count"] == 9
    assert task["attempts_without_progress"] == 2
    assert task["session_id"] == "ses_kept"
    assert task["checkpoint"]["source_sha256"] == "a" * 64
    assert task["checkpoint"]["recovery_reason"] == f"SETO-DECOMP-046: {reason}"
    assert len(store.list_attempts()) == 9
    assert store.reopen_recoverable_candidates(
        {"0x1000": reason},
        max_attempts_per_candidate=12,
        campaign_id="SETO-DECOMP-046",
    ) == []

    with pytest.raises(ValueError, match="EXACT boundary"):
        store.reopen_recoverable_candidates(
            {"0x2000": "boundary evidence invalid"},
            max_attempts_per_candidate=12,
            campaign_id="SETO-DECOMP-046",
        )
    with pytest.raises(ValueError, match="requires a concrete reason"):
        store.reopen_recoverable_candidates(
            {"0x2000": "   "},
            max_attempts_per_candidate=12,
            campaign_id="SETO-DECOMP-046",
        )
    with pytest.raises(ValueError, match="does not exceed"):
        with store._connect() as db:
            db.execute("UPDATE candidates SET status='stalled' WHERE address='0x1000'")
        store.reopen_recoverable_candidates(
            {"0x1000": "limit too low"},
            max_attempts_per_candidate=9,
            campaign_id="SETO-DECOMP-046",
        )


def test_resume_main_retries_only_the_requested_blocked_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "campaign.sqlite3"
    candidates = [candidate("0x1000"), candidate("0x2000")]
    store = CampaignStore(database)
    store.seed(candidates)
    snapshots = {}
    with store._connect() as db:
        for address, session in (("0x1000", "ses_target"), ("0x2000", "ses_other")):
            checkpoint = json.dumps({"next_experiment": f"keep {address}"}, sort_keys=True)
            best = json.dumps({"status": "NONMATCHING", "matching_words": 2}, sort_keys=True)
            db.execute(
                "UPDATE candidates SET status='blocked',attempt_count=1,owner=NULL,provider=NULL,"
                "lease_until=NULL,session_id=?,checkpoint_json=?,best_result_json=? WHERE address=?",
                (session, checkpoint, best, address),
            )
            snapshots[address] = (checkpoint, best, session)
            db.execute(
                "INSERT INTO attempts(address,attempt_number,worker_id,provider,session_id,started_at,ended_at,outcome) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (address, 1, "openai", "openai", session, 1.0, 2.0, "agent_error"),
            )
    config = {}
    monkeypatch.setattr(decomp_campaign_module, "load_config", lambda _path: config)
    monkeypatch.setattr(
        decomp_campaign_module,
        "_config_paths",
        lambda *_args: (tmp_path / "inventory.json", database),
    )
    monkeypatch.setattr(
        decomp_campaign_module,
        "load_inventory",
        lambda _path: (candidates, {}),
    )
    output = {}
    monkeypatch.setattr(decomp_campaign_module, "_print_json", output.update)

    assert decomp_campaign_module.main(
        ["--config", str(tmp_path / "local.toml"), "resume", "--retry-address", "0x1000"]
    ) == 0

    assert output["retried_addresses"] == ["0x1000"]
    retried = store.get_task("0x1000")
    untouched = store.get_task("0x2000")
    assert retried["status"] == "pending"
    assert untouched["status"] == "blocked"
    assert len(store.list_attempts()) == 2
    for address, task in (("0x1000", retried), ("0x2000", untouched)):
        assert task["attempt_count"] == 1
        assert task["session_id"] == snapshots[address][2]
        assert json.dumps(task["checkpoint"], sort_keys=True) == snapshots[address][0]
        assert json.dumps(task["best_result"], sort_keys=True) == snapshots[address][1]


def test_resume_retry_modes_never_reenable_certified_baseline_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "campaign.sqlite3"
    candidates = [candidate("0x2c28c"), candidate("0x1000")]
    store = CampaignStore(database)
    store.seed(candidates)
    snapshots = {}
    with store._connect() as db:
        for address, session in (("0x2c28c", "ses_certified"), ("0x1000", "ses_other")):
            checkpoint = json.dumps({"next_experiment": f"retain {address}"}, sort_keys=True)
            best = json.dumps({"status": "NONMATCHING", "matching_words": 2}, sort_keys=True)
            db.execute(
                "UPDATE candidates SET status='blocked',attempt_count=2,session_id=?,"
                "checkpoint_json=?,best_result_json=? WHERE address=?",
                (session, checkpoint, best, address),
            )
            snapshots[address] = (checkpoint, best, session)
            for attempt in (1, 2):
                db.execute(
                    """INSERT INTO attempts(address,attempt_number,worker_id,provider,session_id,
                       started_at,ended_at,outcome) VALUES(?,?,?,?,?,?,?,?)""",
                    (address, attempt, "luna-01", "openai", session, float(attempt), float(attempt + 1), "agent_error"),
                )
    inventory = {
        "baseline": {
            "eboot_matched_functions": 1,
            "eboot_matched_addresses": ["0x2C28C"],
        }
    }
    monkeypatch.setattr(decomp_campaign_module, "load_config", lambda _path: {})
    monkeypatch.setattr(
        decomp_campaign_module,
        "_config_paths",
        lambda *_args: (tmp_path / "inventory.json", database),
    )
    monkeypatch.setattr(
        decomp_campaign_module,
        "load_inventory",
        lambda _path: (candidates, inventory),
    )

    assert decomp_campaign_module.main(
        ["--config", str(tmp_path / "local.toml"), "resume", "--retry-address", "0x2c28c"]
    ) == 2
    certified_after_selective = store.get_task("0x2c28c")
    other_after_selective = store.get_task("0x1000")
    assert certified_after_selective["status"] == "blocked"
    assert other_after_selective["status"] == "blocked"
    assert len(store.list_attempts()) == 4

    assert decomp_campaign_module.main(
        ["--config", str(tmp_path / "local.toml"), "resume", "--retry-blocked"]
    ) == 0

    certified = store.get_task("0x2c28c")
    retried_other = store.get_task("0x1000")
    assert certified["status"] == "blocked"
    assert retried_other["status"] == "pending"
    for address, task in (("0x2c28c", certified), ("0x1000", retried_other)):
        assert task["attempt_count"] == 2
        assert task["session_id"] == snapshots[address][2]
        assert json.dumps(task["checkpoint"], sort_keys=True) == snapshots[address][0]
        assert json.dumps(task["best_result"], sort_keys=True) == snapshots[address][1]
    assert len(store.list_attempts()) == 4


def test_local_match_experiment_is_checkpointed_without_changing_campaign_best(
    tmp_path: Path,
) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])
    worktree = tmp_path / "openai"
    worktree.mkdir()
    source_relative = "decomp-campaign/experiments/1000/conditional/func_00001000.c"
    source = campaign_build_path(worktree, source_relative)
    source.parent.mkdir(parents=True)
    source.write_text("int func_00001000(void) { return 1; }\n", encoding="utf-8")
    source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    report_paths = [
        f"decomp-campaign/experiments/1000/conditional/verify-{number}/full-match.json"
        for number in (1, 2)
    ]
    for report_path in report_paths:
        report_file = campaign_build_path(worktree, report_path)
        report_file.parent.mkdir(parents=True)
        report = strict_report("0x1000", word_count=4)
        report["function"] = "func_00001000"
        report["provenance"]["source_sha256"] = source_sha
        report_file.write_text(json.dumps(report), encoding="utf-8")

    summary = store.record_local_match_experiment(
        "0x1000",
        worker_id="openai",
        worktree=worktree,
        source_relative=source_relative,
        report_relatives=report_paths,
    )

    task = store.get_task("0x1000")
    assert summary["status"] == "MATCHED"
    assert summary["origin_kind"] == "local_experiment"
    assert summary["source_sha256"] == source_sha
    assert task["status"] == "pending"
    assert task["attempt_count"] == 0
    assert task["best_result"] == {}
    assert task["checkpoint"]["local_experiments"] == [summary]


def test_discover_local_recovery_prefers_best_hash_and_keeps_symbol_mismatch_for_recheck(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    (repo / "build").mkdir(parents=True)
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])
    best_source = b"void func_00001000(void) { return 1; }\n"
    other_source = b"void func_00001000(void) { return 2; }\n"
    mismatch_source = b"void FUN_00001000(void) { return 3; }\n"
    best_hash = hashlib.sha256(best_source).hexdigest()
    other_hash = hashlib.sha256(other_source).hexdigest()
    snapshot_relative = f"decomp-campaign/checkpoints/00001000/{best_hash}.c"
    snapshot = campaign_build_path(repo, snapshot_relative)
    snapshot.parent.mkdir(parents=True)
    snapshot.write_bytes(best_source)
    worker = tmp_path / "luna-01"
    source = worker / "decomp/src/eboot/func_00001000.c"
    source.parent.mkdir(parents=True)
    source.write_bytes(other_source)
    mismatch_worker = tmp_path / "luna-02"
    mismatch_path = mismatch_worker / "decomp/src/eboot/func_00001000.c"
    mismatch_path.parent.mkdir(parents=True)
    mismatch_path.write_bytes(mismatch_source)
    report_base = worker / "build/decomp-campaign/luna-01/1000/attempt-1/verify-1"
    report_base.mkdir(parents=True)
    report = strict_report()
    report["function"] = "func_00001000"
    report["status"] = "NONMATCHING"
    report["verified_decompilation"] = False
    report["provenance"]["source_sha256"] = other_hash
    report["match"].update(
        status="NONMATCHING",
        matching_words=3,
        difference_count=1,
        differences=[{"word_index": 3}],
    )
    (report_base / "func_00001000.match.json").write_text(
        json.dumps(report), encoding="utf-8"
    )
    with store._connect() as db:
        db.execute(
            """UPDATE candidates SET checkpoint_json=?,best_result_json=?
               WHERE address='0x1000'""",
            (
                json.dumps(
                    {
                        "best_source_sha256": best_hash,
                        "best_source_snapshot": snapshot_relative,
                    }
                ),
                json.dumps({"status": "NONMATCHING", "source_sha256": best_hash}),
            ),
        )

    variants = decomp_campaign_module.discover_local_recovery_sources(
        store.get_task("0x1000"),
        repo,
        {"luna-01": worker, "luna-02": mismatch_worker},
        max_variants=3,
    )

    mismatch_hash = hashlib.sha256(mismatch_source).hexdigest()
    assert {item["source_sha256"] for item in variants} == {
        best_hash,
        other_hash,
        mismatch_hash,
    }
    assert variants[0]["source_sha256"] == best_hash
    assert variants[1]["source_sha256"] == other_hash
    assert variants[1]["matching_words"] == 3
    assert variants[2]["source_sha256"] == mismatch_hash
    assert variants[2]["has_exact_symbol"] is False


def test_local_recovery_compares_once_and_reopens_only_with_verified_reason(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    (repo / "private/decrypted").mkdir(parents=True)
    (repo / "config/wsl").mkdir(parents=True)
    (repo / "scripts").mkdir()
    (repo / "build").mkdir()
    (repo / "private/decrypted/ULUS10136_EBOOT.elf").write_bytes(b"eboot")
    (repo / "config/wsl/seto.toml").write_text("local config", encoding="utf-8")
    (repo / "scripts/match_function.py").write_text("matcher", encoding="utf-8")
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])
    source_root = tmp_path / "archive/luna-01"
    source = source_root / "decomp/src/eboot/func_00001000.c"
    source.parent.mkdir(parents=True)
    source.write_text("void func_00001000(void) { return 0; }\n", encoding="utf-8")
    ghidra_relative = (
        "decomp-campaign/luna-01/1000/evidence/"
        "ghidra-run-0123456789abcdef0123456789abcdef.log"
    )
    ghidra_path = campaign_build_path(source_root, ghidra_relative)
    ghidra_path.parent.mkdir(parents=True)
    ghidra_path.write_text(ghidra_log(), encoding="utf-8")
    ghidra_hash = hashlib.sha256(ghidra_path.read_bytes()).hexdigest()
    with store._connect() as db:
        db.execute(
            """UPDATE candidates SET status='blocked',attempt_count=1,checkpoint_json=?
               WHERE address='0x1000'""",
            (json.dumps({"ghidra_log_path": ghidra_relative, "ghidra_log_sha256": ghidra_hash}),),
        )
        db.execute(
            """INSERT INTO attempts(address,attempt_number,worker_id,provider,session_id,
               started_at,ended_at,outcome) VALUES('0x1000',1,'luna-01','openai','ses_old',1,2,'blocked')"""
        )
    runner = CampaignRunner(
        store,
        opencode_command=["unused"],
        worktrees={},
        checkpoint_repo_root=repo,
    )
    matcher_calls = []

    def fake_matcher(
        worktree: Path,
        claim: Claim,
        candidate_source: Path,
        _eboot: Path,
        _config: Path,
        _matcher: Path,
        *,
        verification_numbers: tuple[int, ...],
    ):
        matcher_calls.extend(verification_numbers)
        source_hash = hashlib.sha256(candidate_source.read_bytes()).hexdigest()
        reports = []
        for number in verification_numbers:
            relative_out = (
                f"decomp-campaign/experiments/1000/attempt-{claim.attempt_number}/verify-{number}"
            )
            out = campaign_build_path(worktree, relative_out)
            out.mkdir(parents=True, exist_ok=True)
            report = strict_report()
            report["function"] = "func_00001000"
            report["status"] = "NONMATCHING"
            report["verified_decompilation"] = False
            report["provenance"]["source_sha256"] = source_hash
            report["match"].update(
                status="NONMATCHING",
                matching_words=2,
                difference_count=2,
                differences=[
                    {
                        "word_index": 2,
                        "address": "0x1008",
                        "candidate": "0x00000000",
                        "original": "0x00000001",
                    },
                    {"word_index": 3},
                ],
            )
            report_relative = (
                f"build/{relative_out}/func_00001000.match.json"
            )
            report["report_path"] = report_relative
            (out / "func_00001000.match.json").write_text(
                json.dumps(report), encoding="utf-8"
            )
            reports.append(report)
        return reports

    runner._run_matcher_native = fake_matcher  # type: ignore[method-assign]
    runner._run_matcher_wsl = fake_matcher  # type: ignore[method-assign]

    result = decomp_campaign_module.recover_local_artifacts(
        runner,
        repo,
        {"luna-01": source_root},
        excluded_addresses={"0x4217c"},
        max_attempts_per_candidate=12,
        campaign_id="SETO-DECOMP-046",
    )

    task = store.get_task("0x1000")
    assert matcher_calls == [1]
    assert result["comparisons_complete"] == 1
    assert result["reopened"] == ["0x1000"]
    assert task["status"] == "pending"
    assert task["attempt_count"] == 1
    assert len(store.list_attempts()) == 1
    recovery = task["checkpoint"]["local_recoveries"][0]
    assert recovery["status"] == "NONMATCHING"
    assert recovery["matching_words"] == 2
    assert recovery["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert task["checkpoint"]["recovery_reason"].startswith("SETO-DECOMP-046: local matcher")

    new_worktree = tmp_path / "new-luna-01"
    new_worktree.mkdir()
    assert decomp_campaign_module.provision_local_recovery_evidence(
        store,
        repo,
        {"luna-01": new_worktree},
        source_worktrees={"luna-01": source_root},
    ) == 1
    assert campaign_build_path(new_worktree, ghidra_relative).is_file()
    ghidra_claim = Claim(
        "0x1000",
        16,
        "0x12345678",
        50,
        "EXACT",
        "luna-01",
        "openai",
        "ses_luna",
        2,
        1,
        store.get_task("0x1000")["checkpoint"],
        {},
    )
    assert decomp_campaign_module.validated_cached_ghidra_boundary(
        new_worktree, ghidra_claim
    )["size_bytes"] == 16
    prompt_claim = Claim(
        "0x1000",
        16,
        "0x12345678",
        50,
        "EXACT",
        "luna-01",
        "openai",
        "ses_luna",
        2,
        1,
        task["checkpoint"],
        {},
    )
    prompt = decomp_campaign_module._prompt(prompt_claim, task["checkpoint"], new_worktree)
    assert "local_recoveries" in prompt
    assert recovery["report_path"] in prompt
    assert (new_worktree / recovery["source_path"]).is_file()
    assert (new_worktree / recovery["report_path"]).is_file()

    second_result = decomp_campaign_module.recover_local_artifacts(
        runner,
        repo,
        {"luna-01": source_root},
        excluded_addresses={"0x4217c"},
        max_attempts_per_candidate=12,
        campaign_id="SETO-DECOMP-046",
    )
    assert second_result["sources_selected"] == 1
    assert matcher_calls == [1]


def test_local_match_experiment_rejects_report_with_wrong_source_hash(tmp_path: Path) -> None:
    store = CampaignStore(tmp_path / "campaign.sqlite3")
    store.seed([candidate("0x1000")])
    worktree = tmp_path / "openai"
    worktree.mkdir()
    source_relative = "decomp-campaign/experiments/1000/conditional/func_00001000.c"
    source = campaign_build_path(worktree, source_relative)
    source.parent.mkdir(parents=True)
    source.write_text("int func_00001000(void) { return 1; }\n", encoding="utf-8")
    report_paths = []
    for number in (1, 2):
        relative = f"decomp-campaign/experiments/1000/conditional/verify-{number}/full-match.json"
        report_file = campaign_build_path(worktree, relative)
        report_file.parent.mkdir(parents=True)
        report = strict_report("0x1000", word_count=4)
        report["function"] = "func_00001000"
        report_file.write_text(json.dumps(report), encoding="utf-8")
        report_paths.append(relative)

    with pytest.raises(ValueError, match="source/object provenance"):
        store.record_local_match_experiment(
            "0x1000",
            worker_id="openai",
            worktree=worktree,
            source_relative=source_relative,
            report_relatives=report_paths,
        )
    assert store.get_task("0x1000")["checkpoint"].get("local_experiments") is None
    assert store.list_attempts() == []


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
        "import json, pathlib, sys, time\n"
        "args = sys.argv[1:]\n"
        "model = args[args.index('--model') + 1]\n"
        "time.sleep(0.08)\n"
        "if model.startswith('opencode/'):\n"
        " sys.stderr.write('insufficient_quota token=sk-supersecret')\n"
        " raise SystemExit(1)\n"
        "title = args[args.index('--title') + 1].split()\n"
        "address = int(title[2], 0)\n"
        "source = pathlib.Path('decomp/src/eboot') / f'func_{address:08X}.c'\n"
        "source.parent.mkdir(parents=True, exist_ok=True)\n"
        "source.write_text(f'void func_{address:08X}(void) {{ return; }}\\n')\n"
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
    assert len({item["session_id"] for item in first_claims}) == 2
    fallback = [item for item in attempts if item["address"] == "0x1000"]
    assert [item["provider"] for item in fallback] == ["opencode", "openai"]
    assert store.provider_status("opencode") == "suspended_quota"

    # Raw provider output is never persisted to the local event/attempt ledger.
    persisted = b"".join(p.read_bytes() for p in tmp_path.glob("campaign.sqlite3*"))
    assert b"sk-supersecret" not in persisted
