"""Additive module/address queue for internal functions, without export NIDs."""

from __future__ import annotations

import json
import hashlib
import os
import sqlite3
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from decomp_campaign import (
    CampaignRunner,
    CampaignStore,
    InternalClaim,
    Worker,
    _assert_git_identity_unchanged,
    _assert_worker_changes_scoped,
    _extract_checkpoint,
    _file_manifest,
    _safe_worktree_path,
    _worktree_status_snapshot,
    campaign_build_path,
)
from internal_functions import (
    InternalFunction,
    build_internal_certificate,
    load_internal_catalog,
    write_internal_certificate,
)


class InternalCampaignStore:
    """Transactional access to the internal tables in the existing campaign DB."""

    def __init__(self, campaign_store: CampaignStore) -> None:
        self.campaign_store = campaign_store

    def seed(self, functions: Iterable[InternalFunction]) -> int:
        inserted = 0
        now = time.time()
        with self.campaign_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for function in functions:
                if (
                    function.boundary_status != "UNVERIFIED"
                    or function.kind != "code"
                    or function.section != ".text"
                ):
                    continue
                db.execute(
                    """INSERT OR IGNORE INTO internal_candidates
                    (module,address,section,kind,size_bytes,boundary_status,status,
                     evidence_json,updated_at)
                    VALUES (?,?,?, ?,0,'UNVERIFIED','needs_boundary',?,?)""",
                    (
                        function.module,
                        f"0x{function.address:x}",
                        function.section,
                        function.kind,
                        json.dumps({"discovery_evidence": function.evidence_path}, sort_keys=True),
                        now,
                    ),
                )
                inserted += int(db.execute("SELECT changes()").fetchone()[0])
            db.commit()
        return inserted

    @staticmethod
    def _claim(row: sqlite3.Row, worker_id: str, provider: str, *, model_provider: str | None = None) -> InternalClaim:
        return InternalClaim(
            module=str(row["module"]),
            address=str(row["address"]),
            size_bytes=int(row["size_bytes"]),
            section=str(row["section"]),
            kind=str(row["kind"]),
            priority=0,
            boundary_status=str(row["boundary_status"]),
            worker_id=worker_id,
            provider=provider,
            session_id=row["session_id"],
            attempt_number=int(row["attempt_count"]),
            lease_until=float(row["lease_until"] or 0),
            checkpoint=json.loads(row["checkpoint_json"]),
            evidence=json.loads(row["evidence_json"]),
            model_provider=model_provider,
        )

    def claim_boundary(self, worker_id: str, *, lease_seconds: float, now: float | None = None) -> InternalClaim | None:
        now = time.time() if now is None else now
        with self.campaign_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT * FROM internal_candidates
                WHERE status='needs_boundary' OR
                  (status='boundary_checking' AND lease_until<?)
                ORDER BY module,address LIMIT 1""",
                (now,),
            ).fetchone()
            if row is None:
                db.commit()
                return None
            lease_until = now + max(1.0, lease_seconds)
            db.execute(
                """UPDATE internal_candidates SET status='boundary_checking',owner=?,
                   provider='ghidra',lease_until=?,boundary_attempts=boundary_attempts+1,
                   updated_at=? WHERE module=? AND address=?""",
                (worker_id, lease_until, now, row["module"], row["address"]),
            )
            claimed = dict(row)
            claimed.update(status="boundary_checking", owner=worker_id, provider="ghidra", lease_until=lease_until)
            db.commit()
        return self._claim(claimed, worker_id, "ghidra")  # type: ignore[arg-type]

    def finish_boundary(self, claim: InternalClaim) -> None:
        with self.campaign_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self.campaign_store._require_internal_owner(db, claim)
            checkpoint = json.loads(row["checkpoint_json"])
            if (
                row["boundary_status"] != "EXACT"
                or int(row["size_bytes"]) <= 0
                or checkpoint.get("boundary_status") != "EXACT"
                or not isinstance(checkpoint.get("ghidra_log_sha256"), str)
            ):
                raise ValueError("internal task boundary lacks independent EXACT evidence")
            db.execute(
                """UPDATE internal_candidates SET status='pending',owner=NULL,provider=NULL,
                   lease_until=NULL,updated_at=? WHERE module=? AND address=?""",
                (time.time(), claim.module, claim.address),
            )
            db.commit()

    def fail_boundary(self, claim: InternalClaim, *, retry_limit: int = 3) -> None:
        with self.campaign_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self.campaign_store._require_internal_owner(db, claim)
            checkpoint = json.loads(row["checkpoint_json"])
            checkpoint["last_boundary_failure"] = "boundary_not_exact_or_analysis_failed"
            status = "needs_boundary" if int(row["boundary_attempts"]) < retry_limit else "blocked"
            db.execute(
                """UPDATE internal_candidates SET status=?,owner=NULL,provider=NULL,
                   lease_until=NULL,checkpoint_json=?,updated_at=? WHERE module=? AND address=?""",
                (status, json.dumps(checkpoint, sort_keys=True), time.time(), claim.module, claim.address),
            )
            db.commit()

    def claim_next(
        self,
        worker_id: str,
        provider: str,
        *,
        model_provider: str | None,
        lease_seconds: float,
        max_total_attempts: int,
        max_attempts_per_candidate: int,
        now: float | None = None,
    ) -> InternalClaim | None:
        now = time.time() if now is None else now
        with self.campaign_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            total = self.campaign_store._total_attempt_count(db)
            if total >= max_total_attempts:
                db.commit()
                return None
            db.execute(
                "INSERT OR IGNORE INTO providers(provider,status,updated_at) "
                "VALUES (?,'active',?)",
                (provider, now),
            )
            provider_row = db.execute(
                "SELECT status,resume_at FROM providers WHERE provider=?", (provider,)
            ).fetchone()
            if provider_row["status"] in {"suspended_quota", "blocked_auth", "blocked"}:
                db.commit()
                return None
            if provider_row["status"] in {"rate_limited", "network_backoff"}:
                if provider_row["resume_at"] is None or provider_row["resume_at"] > now:
                    db.commit()
                    return None
                db.execute(
                    "UPDATE providers SET status='active',resume_at=NULL,reason=NULL,updated_at=? "
                    "WHERE provider=?",
                    (now, provider),
                )
            db.execute(
                """UPDATE internal_candidates SET status='stalled',owner=NULL,provider=NULL,
                   lease_until=NULL,updated_at=? WHERE status='pending' AND attempt_count>=?""",
                (now, max_attempts_per_candidate),
            )
            row = db.execute(
                """SELECT * FROM internal_candidates WHERE status='pending'
                AND boundary_status='EXACT' AND section='.text' AND kind='code'
                AND available_at<=? AND attempt_count<? ORDER BY attempt_count,module,address LIMIT 1""",
                (now, max_attempts_per_candidate),
            ).fetchone()
            if row is None:
                db.commit()
                return None
            lease_until = now + max(1.0, lease_seconds)
            db.execute(
                """UPDATE internal_candidates SET status='preparing',owner=?,provider=?,
                   lease_until=?,updated_at=? WHERE module=? AND address=?""",
                (worker_id, provider, lease_until, now, row["module"], row["address"]),
            )
            claimed = dict(row)
            claimed.update(status="preparing", owner=worker_id, provider=provider, lease_until=lease_until)
            db.commit()
        return self._claim(claimed, worker_id, provider, model_provider=model_provider)  # type: ignore[arg-type]

    def start_attempt(
        self,
        claim: InternalClaim,
        *,
        max_total_attempts: int,
        lease_seconds: float,
        now: float | None = None,
    ) -> InternalClaim | None:
        now = time.time() if now is None else now
        with self.campaign_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self.campaign_store._require_internal_owner(db, claim)
            if row["status"] != "preparing" or row["boundary_status"] != "EXACT":
                raise RuntimeError("only a prepared EXACT internal task can start an attempt")
            stop_row = db.execute(
                "SELECT value FROM metadata WHERE key='stop_requested'"
            ).fetchone()
            provider_row = db.execute(
                "SELECT status FROM providers WHERE provider=?", (claim.provider,)
            ).fetchone()
            if stop_row is not None and stop_row["value"] == "1":
                db.commit()
                return None
            if provider_row is None or provider_row["status"] != "active":
                db.commit()
                return None
            if self.campaign_store._total_attempt_count(db) >= max_total_attempts:
                db.execute(
                    "UPDATE internal_candidates SET status='pending',owner=NULL,provider=NULL,"
                    "lease_until=NULL,updated_at=? WHERE module=? AND address=?",
                    (now, claim.module, claim.address),
                )
                db.commit()
                return None
            attempt_number = int(row["attempt_count"]) + 1
            session_id = row["session_id"] or "pending_" + claim.module + "_" + claim.address
            lease_until = now + max(1.0, lease_seconds)
            db.execute(
                """INSERT INTO internal_attempts
                (module,address,attempt_number,worker_id,provider,session_id,started_at)
                VALUES (?,?,?,?,?,?,?)""",
                (claim.module, claim.address, attempt_number, claim.worker_id, claim.provider, session_id, now),
            )
            db.execute(
                """UPDATE internal_candidates SET status='running',attempt_count=?,session_id=?,
                   lease_until=?,updated_at=? WHERE module=? AND address=?""",
                (attempt_number, session_id, lease_until, now, claim.module, claim.address),
            )
            db.commit()
        return replace(claim, session_id=session_id, attempt_number=attempt_number, lease_until=lease_until)

    def finish_attempt(self, claim: InternalClaim, status: str, result: Mapping[str, Any], *, max_attempts: int) -> str:
        if status not in {"MATCHED", "NONMATCHING", "INCONCLUSIVE", "BLOCKED", "FAILED", "INTERRUPTED"}:
            raise ValueError("invalid internal task result")
        if status == "MATCHED" and result.get("certified") is not True:
            raise ValueError("internal MATCHED task requires an orchestrator-validated certificate")
        safe_result = {
            key: result[key]
            for key in (
                "source_sha256",
                "matching_words",
                "total_words",
                "build_sha256",
                "certificate_path",
                "certificate_sha256",
                "certified",
                "diagnostic",
                "returncode",
            )
            if key in result
        }
        with self.campaign_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self.campaign_store._require_internal_owner(db, claim)
            if row["status"] != "running":
                raise RuntimeError("internal attempt is not running")
            if status in {"FAILED", "INTERRUPTED"}:
                task_status = "pending" if int(row["attempt_count"]) < max_attempts else "stalled"
            else:
                task_status = status.casefold()
            db.execute(
                """UPDATE internal_candidates SET status=?,owner=NULL,provider=NULL,lease_until=NULL,
                   result_json=?,updated_at=? WHERE module=? AND address=?""",
                (task_status, json.dumps(safe_result, sort_keys=True), time.time(), claim.module, claim.address),
            )
            db.execute(
                """UPDATE internal_attempts SET ended_at=?,outcome=?
                   WHERE module=? AND address=? AND attempt_number=?""",
                (time.time(), status.casefold(), claim.module, claim.address, claim.attempt_number),
            )
            db.commit()
        return task_status

    def recover_expired(self, *, now: float | None = None, max_attempts: int = 8) -> int:
        now = time.time() if now is None else now
        with self.campaign_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT module,address,status,attempt_count FROM internal_candidates "
                "WHERE lease_until IS NOT NULL AND lease_until<?",
                (now,),
            ).fetchall()
            recovered = 0
            for row in rows:
                if row["status"] == "boundary_checking":
                    status = "needs_boundary"
                elif row["status"] in {"preparing", "running"}:
                    status = "pending" if int(row["attempt_count"]) < max_attempts else "stalled"
                    if row["status"] == "running":
                        db.execute(
                            """UPDATE internal_attempts SET ended_at=?,outcome='lease_expired'
                            WHERE module=? AND address=? AND attempt_number=? AND ended_at IS NULL""",
                            (now, row["module"], row["address"], row["attempt_count"]),
                        )
                else:
                    continue
                db.execute(
                    """UPDATE internal_candidates SET status=?,owner=NULL,provider=NULL,
                       lease_until=NULL,updated_at=? WHERE module=? AND address=?""",
                    (status, now, row["module"], row["address"]),
                )
                recovered += 1
            db.commit()
        return recovered

    def pending_count(self) -> int:
        with self.campaign_store._connect() as db:
            return int(db.execute(
                "SELECT COUNT(*) FROM internal_candidates WHERE status IN "
                "('needs_boundary','pending','boundary_checking','preparing','running')"
            ).fetchone()[0])


class InternalCampaignRunner:
    """Sequential adapter that requires exact boundary, worker, matcher and certifier stages."""

    def __init__(
        self,
        store: InternalCampaignStore,
        *,
        boundary: Callable[[InternalClaim, float], InternalClaim],
        worker: Callable[[InternalClaim, Callable[[InternalClaim | None], InternalClaim], float], Mapping[str, Any]],
        matcher: Callable[[InternalClaim, Mapping[str, Any], float], Mapping[str, Any]],
        certifier: Callable[[InternalClaim, Mapping[str, Any]], Mapping[str, Any]],
        lease_seconds: float = 1800,
        max_attempts_per_candidate: int = 8,
    ) -> None:
        self.store = store
        self.boundary = boundary
        self.worker = worker
        self.matcher = matcher
        self.certifier = certifier
        self.lease_seconds = lease_seconds
        self.max_attempts_per_candidate = max_attempts_per_candidate

    def run_segment(
        self,
        workers: Iterable[tuple[str, str, str | None]],
        *,
        max_total_attempts: int,
        deadline: float,
    ) -> dict[str, Any]:
        worker_rows = tuple(workers)
        if not worker_rows:
            return {
                "attempted": 0,
                "outcomes": {},
                "boundary_outcomes": {},
                "stages": {},
                "external_work_remains": bool(self.store.pending_count()),
            }
        attempted = 0
        outcomes: list[str] = []
        boundary_outcomes: list[str] = []
        stages = {
            "worker_attempts_started": 0,
            "matcher_runs": 0,
            "strict_matches": 0,
            "certification_attempts": 0,
            "certifications": 0,
            "certification_blocked": 0,
        }
        index = 0
        while time.monotonic() < deadline and not self.store.campaign_store.stop_requested():
            worker_id, provider, model_provider = worker_rows[index % len(worker_rows)]
            index += 1
            boundary_claim = self.store.claim_boundary(
                worker_id, lease_seconds=self.lease_seconds
            )
            if boundary_claim is not None:
                try:
                    exact = self.boundary(boundary_claim, deadline)
                    if (
                        exact.boundary_status != "EXACT"
                        or exact.size_bytes <= 0
                        or exact.size_bytes % 4
                        or exact.section != ".text"
                        or exact.kind != "code"
                    ):
                        raise ValueError("internal candidate did not receive an EXACT .text boundary")
                    self.store.finish_boundary(exact)
                    boundary_outcomes.append("exact")
                except Exception:
                    self.store.fail_boundary(boundary_claim)
                    boundary_outcomes.append("blocked")
                continue

            claim = self.store.claim_next(
                worker_id,
                provider,
                model_provider=model_provider,
                lease_seconds=self.lease_seconds,
                max_total_attempts=max_total_attempts,
                max_attempts_per_candidate=self.max_attempts_per_candidate,
            )
            if claim is None:
                break
            promotion_started = False
            try:
                started: list[InternalClaim] = []

                def begin_attempt(current_claim: InternalClaim | None = None) -> InternalClaim:
                    if started:
                        return started[0]
                    if (
                        self.store.campaign_store.stop_requested()
                        or time.monotonic() >= deadline
                    ):
                        raise RuntimeError("internal inference cancelled before its attempt began")
                    updated = self.store.start_attempt(
                        current_claim or claim,
                        max_total_attempts=max_total_attempts,
                        lease_seconds=self.lease_seconds,
                    )
                    if updated is None:
                        raise RuntimeError("shared attempt budget exhausted before inference")
                    started.append(updated)
                    stages["worker_attempts_started"] += 1
                    return updated

                worker_result = self.worker(claim, begin_attempt, deadline)
                if not started:
                    raise RuntimeError("worker returned without starting a counted inference attempt")
                claim = started[0]
                if isinstance(worker_result.get("checkpoint"), dict):
                    claim = replace(
                        claim,
                        checkpoint={**claim.checkpoint, **worker_result["checkpoint"]},
                    )
                if worker_result.get("status") != "SOURCE_READY":
                    failure_status = (
                        "INTERRUPTED"
                        if worker_result.get("status") == "INTERRUPTED"
                        else "FAILED"
                    )
                    final = self.store.finish_attempt(
                        claim,
                        failure_status,
                        worker_result,
                        max_attempts=self.max_attempts_per_candidate,
                    )
                    outcomes.append(final)
                    attempted += 1
                    continue
                match = self.matcher(claim, worker_result, deadline)
                stages["matcher_runs"] += 1
                match_status = match.get("status")
                if match_status != "MATCHED":
                    final = self.store.finish_attempt(
                        claim,
                        str(match_status) if match_status in {"NONMATCHING", "INCONCLUSIVE"} else "FAILED",
                        match,
                        max_attempts=self.max_attempts_per_candidate,
                    )
                    outcomes.append(final)
                    attempted += 1
                    continue
                promotion_started = True
                stages["strict_matches"] += 1
                stages["certification_attempts"] += 1
                certificate = self.certifier(claim, match)
                if certificate.get("certified") is not True:
                    raise ValueError("certifier did not approve the two-build internal match")
                stages["certifications"] += 1
                final = self.store.finish_attempt(
                    claim,
                    "MATCHED",
                    {**dict(match), **dict(certificate), "certified": True},
                    max_attempts=self.max_attempts_per_candidate,
                )
                outcomes.append(final)
                attempted += 1
            except Exception as exc:
                if started:
                    try:
                        if promotion_started:
                            stages["certification_blocked"] += 1
                        final = self.store.finish_attempt(
                            started[0],
                            "BLOCKED" if promotion_started else "FAILED",
                            {"diagnostic": type(exc).__name__},
                            max_attempts=self.max_attempts_per_candidate,
                        )
                        outcomes.append(final)
                        attempted += 1
                    except RuntimeError:
                        pass
                else:
                    # Preparation failed before a provider attempt: release without quota use.
                    with self.store.campaign_store._connect() as db:
                        db.execute("BEGIN IMMEDIATE")
                        try:
                            self.store.campaign_store._require_internal_owner(db, claim)
                            db.execute(
                                "UPDATE internal_candidates SET status='pending',owner=NULL,provider=NULL,"
                                "lease_until=NULL,updated_at=? WHERE module=? AND address=?",
                                (time.time(), claim.module, claim.address),
                            )
                            db.commit()
                        except RuntimeError:
                            db.rollback()
                    break
        return {
            "attempted": attempted,
            "outcomes": {kind: outcomes.count(kind) for kind in sorted(set(outcomes))},
            "boundary_outcomes": {
                kind: boundary_outcomes.count(kind) for kind in sorted(set(boundary_outcomes))
            },
            "stages": stages,
            "external_work_remains": bool(self.store.pending_count()),
        }


def make_production_internal_runner(
    campaign_runner: CampaignRunner,
    campaign_store: CampaignStore,
    workers: Mapping[str, Worker],
    *,
    repo_root: Path,
    catalog_path: Path,
    lease_seconds: float,
    max_attempts_per_candidate: int,
) -> InternalCampaignRunner:
    """Bind the durable internal queue to the existing Ghidra/worker/matcher services."""
    internal_store = InternalCampaignStore(campaign_store)
    repo_root = repo_root.resolve(strict=True)
    if catalog_path.is_symlink():
        raise ValueError("internal catalog path must not be a symlink")
    catalog_path = catalog_path.resolve(strict=True)

    def run_boundary(claim: InternalClaim, deadline: float) -> InternalClaim:
        worktree = campaign_runner.worktrees.get(claim.worker_id)
        if worktree is None or worktree.is_symlink() or not worktree.is_dir():
            raise ValueError("internal Ghidra worktree is missing or unsafe")
        return campaign_runner._prepare_claim(worktree, claim, deadline)  # type: ignore[arg-type,return-value]

    def run_worker(
        claim: InternalClaim,
        begin_attempt: Callable[[InternalClaim | None], InternalClaim],
        deadline: float,
    ) -> Mapping[str, Any]:
        worker = workers.get(claim.worker_id)
        worktree = campaign_runner.worktrees.get(claim.worker_id)
        if worker is None or worktree is None or worktree.is_symlink() or not worktree.is_dir():
            raise ValueError("internal worker or its isolated worktree is unavailable")
        if worker.agent != "seto-decomp-worker":
            raise ValueError("internal tasks require the restricted decomp worker agent")
        if not campaign_runner._provider_gate_open(worker):
            raise ValueError("configured provider gate is closed for this internal worker")
        source_relative = f"decomp/src/eboot/func_{claim.numeric_address:08X}.c"
        source = _safe_worktree_path(worktree, Path(source_relative))
        if source.is_symlink():
            raise ValueError("internal candidate source is a symlink")
        source.parent.mkdir(parents=True, exist_ok=True)
        if not source.exists():
            with source.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write("/* Internal EBOOT candidate; reconstruct from verified evidence. */\n")
        if not source.is_file():
            raise ValueError("internal candidate source is not a regular file")
        checkpoint = claim.checkpoint
        log_path = checkpoint.get("ghidra_log_path")
        log_hash = checkpoint.get("ghidra_log_sha256")
        if not isinstance(log_path, str) or not isinstance(log_hash, str):
            raise ValueError("internal worker requires hash-bound EXACT Ghidra evidence")
        log_file = campaign_build_path(worktree, log_path)
        if log_file.is_symlink() or not log_file.is_file() or hashlib.sha256(log_file.read_bytes()).hexdigest() != log_hash:
            raise ValueError("internal worker Ghidra evidence is missing or changed")
        prompt = (
            "Reconstruct exactly one internal EBOOT function.\n"
            f"Module: {claim.module}; address: {claim.address}; original section: {claim.section}; "
            f"exact size: {claim.size_bytes} bytes ({claim.size_bytes // 4} words).\n"
            f"Only source file: {source_relative}.\n"
            f"Verified boundary evidence: build/{log_path} sha256={log_hash}.\n"
            "Use the disassembly, decompilation, relocation and reference evidence in that log. "
            "Do not invent an NID, export identity, data identity, or unresolved relocation. "
            "Do not modify Git, configuration, other source files, credentials, or unrelated artifacts. "
            "Do not claim a match or certification; the orchestrator runs MWCC and the matcher twice. "
            "If evidence is insufficient, preserve the best hypothesis and return a concise checkpoint."
        )
        if len(prompt.encode("utf-8")) > 32_000:
            raise ValueError("internal reconstruction prompt exceeds its fixed bound")
        provider_slot = campaign_runner.provider_slots.get(worker.execution_scope)
        acquired = False
        try:
            if provider_slot is not None:
                if not campaign_runner._acquire_resource_slot(provider_slot, deadline):
                    return {"status": "INTERRUPTED"}
                acquired = True
                if campaign_store.provider_status(worker.execution_scope) != "active":
                    raise ValueError("provider was paused before internal inference")
            remote_target = None
            if worker.transport == "ssh":
                remote_target = campaign_runner._prepare_remote_claim(
                    worker, claim, worktree, deadline
                )  # type: ignore[arg-type]
            claim = campaign_runner._ensure_session(
                claim,
                worktree,
                deadline,
                agent=worker.agent,
                model=worker.model,
                worker=worker,
            )  # type: ignore[assignment]
            protected_before = _file_manifest(worktree) if campaign_runner.auto_preflight else {}
            changes_before = _worktree_status_snapshot(worktree) if campaign_runner.auto_preflight else {}
            git_head = _git_output_internal(worktree, "rev-parse", "HEAD") if campaign_runner.auto_preflight else ""
            git_branch = _git_output_internal(worktree, "branch", "--show-current") if campaign_runner.auto_preflight else ""
            started_claim = begin_attempt(claim)
            argv = campaign_runner._argv(worker, started_claim, prompt) if worker.transport == "local" else []  # type: ignore[arg-type]
            campaign_store.record_event(
                "internal_inference_started",
                address=claim.address,
                worker_id=worker.worker_id,
                provider=worker.execution_scope,
                session_id=claim.session_id,
            )
            if worker.transport == "ssh":
                assert remote_target is not None
                remote_result = campaign_runner.ssh_executor.run(
                    remote_target,
                    address=claim.address,
                    attempt_number=started_claim.attempt_number,
                    model=worker.model,
                    agent=worker.agent,
                    session_id=str(claim.session_id),
                    prompt=prompt,
                    timeout=campaign_runner.timeout_seconds,
                    cwd=worktree,
                    stop_requested=campaign_store.stop_requested,
                    deadline=deadline,
                )
                campaign_runner._collect_remote_source(
                    worker, claim, worktree, remote_result, deadline
                )  # type: ignore[arg-type]
                from decomp_campaign import WorkResult

                process = WorkResult(
                    returncode=int(remote_result["returncode"]),
                    stdout=str(remote_result.get("stdout", "")),
                    stderr=str(remote_result.get("stderr", "")),
                    timed_out=bool(remote_result.get("timed_out", False)),
                )
            else:
                from decomp_campaign import _run_process

                process = _run_process(
                    argv,
                    cwd=worktree,
                    timeout=campaign_runner.timeout_seconds,
                    output_limit=campaign_runner.output_limit,
                    stop_requested=campaign_store.stop_requested,
                    deadline=deadline,
                )
            campaign_store.record_event(
                "internal_inference_finished",
                address=claim.address,
                worker_id=worker.worker_id,
                provider=worker.execution_scope,
                session_id=claim.session_id,
            )
            if campaign_runner.auto_preflight:
                if protected_before != _file_manifest(worktree):
                    raise ValueError("internal worker changed protected inputs")
                _assert_worker_changes_scoped(
                    changes_before, _worktree_status_snapshot(worktree), started_claim  # type: ignore[arg-type]
                )
                _assert_git_identity_unchanged(
                    worktree, original_head=git_head, original_branch=git_branch
                )
            if process.interrupted or campaign_store.stop_requested():
                return {"status": "INTERRUPTED"}
            if process.returncode != 0 or process.timed_out:
                return {"status": "FAILED", "returncode": process.returncode}
            if source.is_symlink() or not source.is_file():
                raise ValueError("internal worker did not leave a regular source file")
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            if not re_full_sha256(source_hash):
                raise ValueError("internal worker source hash is malformed")
            extracted = _extract_checkpoint(process.stdout)
            worker_checkpoint = {
                key: extracted[key]
                for key in ("next_experiment", "limitations")
                if key in extracted
            }
            snapshot_relative = (
                f"decomp-campaign/checkpoints/{claim.numeric_address:08x}/{source_hash}.c"
            )
            snapshot = campaign_build_path(repo_root, snapshot_relative)
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            if snapshot.exists() or snapshot.is_symlink():
                if snapshot.is_symlink() or not snapshot.is_file() or hashlib.sha256(snapshot.read_bytes()).hexdigest() != source_hash:
                    raise ValueError("internal hypothesis checkpoint conflicts with existing content")
            else:
                temporary = snapshot.with_name(snapshot.name + ".tmp")
                if temporary.exists() or temporary.is_symlink():
                    raise ValueError("internal hypothesis checkpoint temporary already exists")
                temporary.write_bytes(source.read_bytes())
                if hashlib.sha256(temporary.read_bytes()).hexdigest() != source_hash:
                    temporary.unlink(missing_ok=True)
                    raise ValueError("internal hypothesis checkpoint failed its source hash")
                os.replace(temporary, snapshot)
            worker_checkpoint.update(
                {
                    "source_path": source_relative,
                    "source_sha256": source_hash,
                    "latest_source_snapshot": snapshot_relative,
                }
            )
            campaign_store.save_checkpoint(
                started_claim, worker_checkpoint, trusted_evidence=True  # type: ignore[arg-type]
            )
            return {"status": "SOURCE_READY", "source_sha256": source_hash, "checkpoint": worker_checkpoint}
        finally:
            if acquired and provider_slot is not None:
                provider_slot.release()

    def run_matcher(
        claim: InternalClaim, _worker_result: Mapping[str, Any], deadline: float
    ) -> Mapping[str, Any]:
        worktree = campaign_runner.worktrees[claim.worker_id]
        return campaign_runner._run_limited_operation(
            campaign_runner.matcher_slots,
            "matcher",
            claim=claim,  # type: ignore[arg-type]
            deadline=deadline,
            operation=lambda: campaign_runner._verify_internal_with_matcher_twice(
                worktree, claim, deadline
            ),
        )

    def certify(claim: InternalClaim, match: Mapping[str, Any]) -> Mapping[str, Any]:
        if match.get("status") != "MATCHED" or not isinstance(match.get("reports"), list):
            raise ValueError("only two strict MATCHED internal reports can be certified")
        worktree = campaign_runner.worktrees[claim.worker_id]
        source_relative = f"decomp/src/eboot/func_{claim.numeric_address:08X}.c"
        worker_source = _safe_worktree_path(worktree, Path(source_relative))
        if worker_source.is_symlink() or not worker_source.is_file():
            raise ValueError("matched internal source is missing or unsafe")
        source_hash = hashlib.sha256(worker_source.read_bytes()).hexdigest()
        if match.get("source_sha256") != source_hash:
            raise ValueError("matched source changed before certificate integration")
        main_source = _safe_worktree_path(repo_root, Path(source_relative))
        if main_source.exists() or main_source.is_symlink():
            if main_source.is_symlink() or not main_source.is_file() or hashlib.sha256(main_source.read_bytes()).hexdigest() != source_hash:
                raise ValueError("refusing to overwrite a conflicting source in the primary checkout")
        else:
            main_source.parent.mkdir(parents=True, exist_ok=True)
            temporary_source = main_source.with_name(main_source.name + ".internal.tmp")
            if temporary_source.exists() or temporary_source.is_symlink():
                raise ValueError("internal source integration temporary already exists")
            temporary_source.write_bytes(worker_source.read_bytes())
            if hashlib.sha256(temporary_source.read_bytes()).hexdigest() != source_hash:
                temporary_source.unlink(missing_ok=True)
                raise ValueError("internal source copy failed its hash check")
            os.replace(temporary_source, main_source)

        audit_root = campaign_build_path(
            repo_root,
            f"seto049/internal-audit/eboot/{claim.numeric_address:08x}/{source_hash}",
        )
        reports: list[Path] = []
        for number, report in enumerate(match["reports"], 1):
            if not isinstance(report, dict) or not isinstance(report.get("report_path"), str):
                raise ValueError("internal matcher report path is incomplete")
            report_relative = Path(report["report_path"])
            source_report = _safe_worktree_path(worktree, report_relative)
            if source_report.is_symlink() or not source_report.is_file():
                raise ValueError("internal matcher full report is missing or unsafe")
            audit_report = audit_root / f"verify-{number}.json"
            audit_report.parent.mkdir(parents=True, exist_ok=True)
            report_bytes = source_report.read_bytes()
            if audit_report.exists() or audit_report.is_symlink():
                if audit_report.is_symlink() or not audit_report.is_file() or audit_report.read_bytes() != report_bytes:
                    raise ValueError("internal matcher audit report destination conflicts")
            else:
                with audit_report.open("xb") as stream:
                    stream.write(report_bytes)
            reports.append(audit_report)

        certificate, _ = build_internal_certificate(
            module=claim.module,
            address=claim.numeric_address,
            size_bytes=claim.size_bytes,
            source_path=main_source,
            report_paths=reports,
            repo_root=repo_root,
        )
        for report in certificate["reports"]:
            provenance = report.get("provenance", {})
            compiler = provenance.get("compiler")
            if isinstance(compiler, str):
                provenance["compiler"] = Path(compiler.replace("\\", "/")).name
            loaders = provenance.get("loader")
            if isinstance(loaders, list):
                provenance["loader"] = [Path(str(value).replace("\\", "/")).name for value in loaders]
        certificate["boundary"] = {
            "status": "EXACT",
            "module": claim.module,
            "address": claim.address,
            "size_bytes": claim.size_bytes,
            "section": claim.section,
            "ghidra_log_sha256": claim.checkpoint.get("ghidra_log_sha256"),
        }
        certificate_relative = Path("decomp/evidence/internal") / f"eboot-{claim.numeric_address:08x}.json"
        certificate_path = repo_root / certificate_relative
        certificate_hash = write_internal_certificate(
            certificate_relative, certificate, repo_root=repo_root
        )

        catalog_bytes = catalog_path.read_bytes()
        catalog_document = json.loads(catalog_bytes)
        current_functions = load_internal_catalog(catalog_path)
        if any(
            item.module.casefold() == claim.module.casefold()
            and item.address == claim.numeric_address
            for item in current_functions
        ):
            raise ValueError("internal catalog identity appeared before atomic promotion")
        builds = list(match.get("build_sha256", []))
        entry = {
            "module": claim.module,
            "address": claim.address,
            "size_bytes": claim.size_bytes,
            "instruction_count": claim.size_bytes // 4,
            "boundary_status": "EXACT",
            "section": claim.section,
            "kind": "code",
            "evidence_path": f"{certificate_path.relative_to(repo_root).as_posix()}#matcher-and-boundary",
            "source_path": source_relative,
            "source_sha256": source_hash,
            "result": {
                "status": "MATCHED",
                "matching_words": claim.size_bytes // 4,
                "total_words": claim.size_bytes // 4,
                "object_sha256s": builds,
                "resolved_calls": list(match["reports"][0]["match"].get("resolved_calls", [])),
                "data_reference_count": len(match["reports"][0]["match"].get("resolved_data", [])),
                "certificate_path": certificate_path.relative_to(repo_root).as_posix(),
                "certificate_sha256": certificate_hash,
            },
        }
        catalog_document["functions"].append(entry)
        catalog_document["functions"].sort(
            key=lambda item: (item["module"].casefold(), int(item["address"], 0))
        )
        if hashlib.sha256(catalog_path.read_bytes()).digest() != hashlib.sha256(catalog_bytes).digest():
            raise ValueError("internal catalog changed concurrently; certificate was not promoted")
        temporary_catalog = catalog_path.with_name(catalog_path.name + ".internal.tmp")
        if temporary_catalog.exists() or temporary_catalog.is_symlink():
            raise ValueError("internal catalog promotion temporary already exists")
        with temporary_catalog.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(catalog_document, stream, indent=2)
            stream.write("\n")
        os.replace(temporary_catalog, catalog_path)
        return {
            "certified": True,
            "certificate_path": certificate_path.relative_to(repo_root).as_posix(),
            "certificate_sha256": certificate_hash,
        }

    return InternalCampaignRunner(
        internal_store,
        boundary=run_boundary,
        worker=run_worker,
        matcher=run_matcher,
        certifier=certify,
        lease_seconds=lease_seconds,
        max_attempts_per_candidate=max_attempts_per_candidate,
    )


def _git_output_internal(worktree: Path, *args: str) -> str:
    import subprocess

    result = subprocess.run(
        ["git", *args], cwd=worktree, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def re_full_sha256(value: str) -> bool:
    import re

    return re.fullmatch(r"[0-9a-f]{64}", value) is not None
