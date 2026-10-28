"""Additive module/address queue for internal functions, without export NIDs."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
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
    internal_reference_evidence_is_resolved,
    load_internal_catalog,
    validate_internal_catalog_evidence,
    write_internal_certificate,
)


class InternalWorkerUnavailable(RuntimeError):
    """A worker/provider/session failure that may be avoided with another worker."""


class InternalTaskBlocked(RuntimeError):
    """Verified task evidence or its assigned source is unsafe/inconsistent."""


class InternalAttemptCeiling(RuntimeError):
    """The bounded inference retry count for one internal function is exhausted."""


class InternalCampaignBudgetExhausted(RuntimeError):
    """The global attempt ceiling/stop condition closed before inference began."""


def _atomic_create_file(path: Path, payload: bytes, *, label: str) -> None:
    """Create one file atomically without replacing an existing destination."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"{label} destination already exists")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if hashlib.sha256(temporary.read_bytes()).digest() != hashlib.sha256(payload).digest():
            raise OSError(f"{label} temporary failed its digest")
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


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
                if (
                    isinstance(function.priority, bool)
                    or not isinstance(function.priority, int)
                    or not 0 <= function.priority <= 1_000_000
                ):
                    raise ValueError("internal discovery priority is outside its bounded range")
                db.execute(
                    """INSERT OR IGNORE INTO internal_candidates
                    (module,address,section,kind,priority,size_bytes,boundary_status,status,
                     evidence_json,updated_at)
                    VALUES (?,?,?,?,?,0,'UNVERIFIED','needs_boundary',?,?)""",
                    (
                        function.module,
                        f"0x{function.address:x}",
                        function.section,
                        function.kind,
                        function.priority,
                        json.dumps({"discovery_evidence": function.evidence_path}, sort_keys=True),
                        now,
                    ),
                )
                did_insert = int(db.execute("SELECT changes()").fetchone()[0])
                inserted += did_insert
                if not did_insert:
                    existing = db.execute(
                        "SELECT priority,status,attempt_count,owner FROM internal_candidates "
                        "WHERE module=? AND address=?",
                        (function.module, f"0x{function.address:x}"),
                    ).fetchone()
                    if (
                        existing is not None
                        and int(existing["attempt_count"]) == 0
                        and existing["owner"] is None
                        and existing["status"] in {"needs_boundary", "pending"}
                        and function.priority > int(existing["priority"])
                    ):
                        db.execute(
                            "UPDATE internal_candidates SET priority=?,updated_at=? "
                            "WHERE module=? AND address=?",
                            (function.priority, now, function.module, f"0x{function.address:x}"),
                        )
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
            priority=int(row["priority"]),
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
                ORDER BY priority DESC,module,address LIMIT 1""",
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
            db.execute(
                "INSERT OR IGNORE INTO providers(provider,status,updated_at) "
                "VALUES (?,'active',?)",
                (provider, now),
            )
            db.execute(
                """UPDATE internal_candidates SET status='stalled',owner=NULL,provider=NULL,
                   lease_until=NULL,updated_at=? WHERE status='pending' AND attempt_count>=?""",
                (now, max_attempts_per_candidate),
            )
            rows = db.execute(
                """SELECT * FROM internal_candidates WHERE status IN
                ('pending','source_pending','promotion_pending')
                AND boundary_status='EXACT' AND section='.text' AND kind='code'
                AND available_at<=? AND
                  (status IN ('source_pending','promotion_pending') OR attempt_count<?)
                ORDER BY CASE WHEN status='promotion_pending' THEN 0
                              WHEN status='source_pending' THEN 1 ELSE 2 END,
                         priority DESC,attempt_count ASC,module,address""",
                (now, max_attempts_per_candidate),
            ).fetchall()
            row = None
            for candidate in rows:
                checkpoint = json.loads(candidate["checkpoint_json"])
                worker_backoff = checkpoint.get("worker_retry_after", {})
                retry_after = (
                    worker_backoff.get(worker_id, 0)
                    if isinstance(worker_backoff, dict)
                    else 0
                )
                if isinstance(retry_after, (int, float)) and not isinstance(retry_after, bool) and retry_after > now:
                    continue
                row = candidate
                break
            if row is None:
                db.commit()
                return None
            if total >= max_total_attempts and row["status"] == "pending":
                db.commit()
                return None
            lease_until = now + max(1.0, lease_seconds)
            db.execute(
                """UPDATE internal_candidates SET status='preparing',owner=?,provider=?,
                   lease_until=?,updated_at=? WHERE module=? AND address=?""",
                (worker_id, provider, lease_until, now, row["module"], row["address"]),
            )
            recovery_state = str(row["status"]) if row["status"] != "pending" else None
            claimed = dict(row)
            claimed.update(
                status="preparing",
                owner=worker_id,
                provider=provider,
                lease_until=lease_until,
                recovery_state=recovery_state,
            )
            db.commit()
        claim = self._claim(claimed, worker_id, provider, model_provider=model_provider)  # type: ignore[arg-type]
        if recovery_state:
            recovered_checkpoint = {
                **claim.checkpoint,
                "recovery_state": recovery_state,
            }
            if total >= max_total_attempts or claim.attempt_number >= max_attempts_per_candidate:
                recovered_checkpoint["inference_allowed"] = False
            claim = replace(
                claim,
                checkpoint=recovered_checkpoint,
            )
        return claim

    def release_preparation(
        self,
        claim: InternalClaim,
        *,
        diagnostic_code: str,
        worker_backoff_seconds: float = 30.0,
    ) -> None:
        if not diagnostic_code or len(diagnostic_code) > 80:
            diagnostic_code = "worker_unavailable"
        now = time.time()
        with self.campaign_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self.campaign_store._require_internal_owner(db, claim)
            checkpoint = json.loads(row["checkpoint_json"])
            backoff = checkpoint.get("worker_retry_after", {})
            if not isinstance(backoff, dict):
                backoff = {}
            backoff = {
                str(worker): float(until)
                for worker, until in backoff.items()
                if isinstance(worker, str)
                and isinstance(until, (int, float))
                and not isinstance(until, bool)
                and float(until) > now
            }
            backoff[claim.worker_id] = now + min(300.0, max(1.0, worker_backoff_seconds))
            checkpoint["worker_retry_after"] = dict(sorted(backoff.items())[-32:])
            checkpoint["last_diagnostic"] = {
                "stage": "context",
                "code": "context_unavailable",
            }
            checkpoint["internal_worker_failure"] = {
                "worker_id": claim.worker_id,
                "code": diagnostic_code,
            }
            db.execute(
                """UPDATE internal_candidates SET status='pending',owner=NULL,provider=NULL,
                   lease_until=NULL,checkpoint_json=?,updated_at=? WHERE module=? AND address=?""",
                (
                    json.dumps(checkpoint, sort_keys=True),
                    now,
                    claim.module,
                    claim.address,
                ),
            )
            db.commit()

    def start_attempt(
        self,
        claim: InternalClaim,
        *,
        max_total_attempts: int,
        max_attempts_per_candidate: int,
        lease_seconds: float,
        now: float | None = None,
    ) -> InternalClaim | None:
        now = time.time() if now is None else now
        with self.campaign_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self.campaign_store._require_internal_owner(db, claim)
            if row["status"] != "preparing" or row["boundary_status"] != "EXACT":
                raise RuntimeError("only a prepared EXACT internal task can start an attempt")
            if int(row["attempt_count"]) >= max_attempts_per_candidate:
                db.commit()
                return None
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
            checkpoint = json.loads(row["checkpoint_json"])
            checkpoint["last_worker_id"] = claim.worker_id
            db.execute(
                """INSERT INTO internal_attempts
                (module,address,attempt_number,worker_id,provider,session_id,started_at)
                VALUES (?,?,?,?,?,?,?)""",
                (claim.module, claim.address, attempt_number, claim.worker_id, claim.provider, session_id, now),
            )
            db.execute(
                """UPDATE internal_candidates SET status='running',attempt_count=?,session_id=?,
                   lease_until=?,checkpoint_json=?,updated_at=? WHERE module=? AND address=?""",
                (
                    attempt_number,
                    session_id,
                    lease_until,
                    json.dumps(checkpoint, sort_keys=True),
                    now,
                    claim.module,
                    claim.address,
                ),
            )
            db.commit()
        return replace(
            claim,
            session_id=session_id,
            attempt_number=attempt_number,
            lease_until=lease_until,
            checkpoint=checkpoint,
        )

    def finish_prepared_result(
        self,
        claim: InternalClaim,
        status: str,
        result: Mapping[str, Any],
        *,
        max_attempts: int,
        local_match_source_sha256: str | None = None,
    ) -> str:
        if status not in {"MATCHED", "NONMATCHING", "INCONCLUSIVE", "FAILED", "BLOCKED"}:
            raise ValueError("invalid result for a recovery-only internal task")
        if status == "MATCHED" and result.get("certified") is not True:
            raise ValueError("recovered MATCHED task requires a validated certificate")
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
            )
            if key in result
        }
        with self.campaign_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self.campaign_store._require_internal_owner(db, claim)
            if row["status"] != "preparing":
                raise RuntimeError("recovery result requires an active preparation lease")
            checkpoint = json.loads(row["checkpoint_json"])
            if local_match_source_sha256 is not None:
                checkpoint["last_local_match_source_sha256"] = local_match_source_sha256
            if status == "MATCHED":
                task_status = "matched"
            elif status == "BLOCKED":
                task_status = "blocked"
            else:
                task_status = (
                    "pending"
                    if int(row["attempt_count"]) < max_attempts
                    else "stalled"
                )
            db.execute(
                """UPDATE internal_candidates SET status=?,owner=NULL,provider=NULL,lease_until=NULL,
                   checkpoint_json=?,result_json=?,updated_at=? WHERE module=? AND address=?""",
                (
                    task_status,
                    json.dumps(checkpoint, sort_keys=True),
                    json.dumps(safe_result, sort_keys=True),
                    time.time(),
                    claim.module,
                    claim.address,
                ),
            )
            db.commit()
        return task_status

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

    def finish_recovered_promotion(
        self, claim: InternalClaim, result: Mapping[str, Any]
    ) -> None:
        """Reconcile an already-promoted MATCHED catalog row without another attempt."""
        if result.get("certified") is not True:
            raise ValueError("promotion recovery requires an audited certificate")
        safe_result = {
            key: result[key]
            for key in (
                "source_sha256",
                "build_sha256",
                "certificate_path",
                "certificate_sha256",
                "certified",
            )
            if key in result
        }
        with self.campaign_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self.campaign_store._require_internal_owner(db, claim)
            if row["status"] != "preparing" or row["boundary_status"] != "EXACT":
                raise RuntimeError("only a prepared EXACT task can reconcile a promotion")
            db.execute(
                """UPDATE internal_candidates SET status='matched',owner=NULL,provider=NULL,
                   lease_until=NULL,result_json=?,updated_at=? WHERE module=? AND address=?""",
                (
                    json.dumps(safe_result, sort_keys=True),
                    time.time(),
                    claim.module,
                    claim.address,
                ),
            )
            self.campaign_store._event(
                db,
                "internal_promotion_reconciled",
                address=claim.address,
                worker_id=claim.worker_id,
                provider=claim.provider,
                session_id=claim.session_id,
            )
            db.commit()

    def block_prepared(self, claim: InternalClaim, diagnostic: str) -> None:
        with self.campaign_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self.campaign_store._require_internal_owner(db, claim)
            if row["status"] != "preparing":
                raise RuntimeError("only a prepared internal task can be blocked")
            db.execute(
                """UPDATE internal_candidates SET status='blocked',owner=NULL,provider=NULL,
                   lease_until=NULL,result_json=?,updated_at=? WHERE module=? AND address=?""",
                (
                    json.dumps({"diagnostic": diagnostic[:120]}, sort_keys=True),
                    time.time(),
                    claim.module,
                    claim.address,
                ),
            )
            db.commit()

    def queue_promotion_recovery(
        self,
        claim: InternalClaim,
        *,
        source_sha256: str | None = None,
        build_sha256: Any = None,
    ) -> None:
        self.campaign_store.save_checkpoint(
            claim, {"promotion_pending": True}, trusted_evidence=True
        )
        with self.campaign_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self.campaign_store._require_internal_owner(db, claim)
            if row["status"] not in {"preparing", "running"}:
                raise RuntimeError("promotion recovery requires an active internal lease")
            db.execute(
                """UPDATE internal_candidates SET status='promotion_pending',owner=NULL,
                   provider=NULL,lease_until=NULL,result_json=?,updated_at=?
                   WHERE module=? AND address=?""",
                (
                    json.dumps(
                        {
                            "source_sha256": source_sha256,
                            "build_sha256": build_sha256,
                            "promotion_pending": True,
                        },
                        sort_keys=True,
                    ),
                    time.time(),
                    claim.module,
                    claim.address,
                ),
            )
            if claim.attempt_number > 0:
                db.execute(
                    """UPDATE internal_attempts SET ended_at=?,outcome='promotion_pending'
                    WHERE module=? AND address=? AND attempt_number=? AND ended_at IS NULL""",
                    (time.time(), claim.module, claim.address, claim.attempt_number),
                )
            db.commit()

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
                state = str(row["status"])
                if state in {"promotion_pending", "source_pending"}:
                    status = state
                elif state == "boundary_checking":
                    status = "needs_boundary"
                elif state in {"preparing", "running"}:
                    checkpoint_row = db.execute(
                        "SELECT checkpoint_json FROM internal_candidates WHERE module=? AND address=?",
                        (row["module"], row["address"]),
                    ).fetchone()
                    checkpoint = json.loads(checkpoint_row["checkpoint_json"])
                    if checkpoint.get("promotion_pending") is True:
                        status = "promotion_pending"
                    elif state == "running" and int(row["attempt_count"]) > 0:
                        status = "source_pending"
                    elif (
                        isinstance(checkpoint.get("source_sha256"), str)
                        and isinstance(checkpoint.get("latest_source_snapshot"), str)
                    ):
                        status = "source_pending"
                    else:
                        status = "pending" if int(row["attempt_count"]) < max_attempts else "stalled"
                    if state == "running":
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
                "('needs_boundary','pending','boundary_checking','preparing','running',"
                "'source_pending','promotion_pending')"
            ).fetchone()[0])

    def exact_pending_count(self) -> int:
        with self.campaign_store._connect() as db:
            return int(
                db.execute(
                    """SELECT COUNT(*) FROM internal_candidates
                    WHERE status='pending' AND boundary_status='EXACT'
                    AND section='.text' AND kind='code'"""
                ).fetchone()[0]
            )

    def recovery_count(self) -> int:
        with self.campaign_store._connect() as db:
            return int(
                db.execute(
                    "SELECT COUNT(*) FROM internal_candidates "
                    "WHERE status IN ('source_pending','promotion_pending')"
                ).fetchone()[0]
            )


class InternalCampaignRunner:
    """Run exact internal tasks sequentially or across isolated ready workers."""

    def __init__(
        self,
        store: InternalCampaignStore,
        *,
        boundary: Callable[[InternalClaim, float], InternalClaim],
        worker: Callable[[InternalClaim, Callable[[InternalClaim | None], InternalClaim], float], Mapping[str, Any]],
        matcher: Callable[[InternalClaim, Mapping[str, Any], float], Mapping[str, Any]],
        certifier: Callable[[InternalClaim, Mapping[str, Any]], Mapping[str, Any]],
        journal_promotion: Callable[[InternalClaim, Mapping[str, Any]], Mapping[str, Any]] | None = None,
        recover_promotion: Callable[[InternalClaim], Mapping[str, Any] | None] | None = None,
        lease_seconds: float = 1800,
        max_attempts_per_candidate: int = 8,
    ) -> None:
        self.store = store
        self.boundary = boundary
        self.worker = worker
        self.matcher = matcher
        self.certifier = certifier
        self.journal_promotion = journal_promotion
        self.recover_promotion = recover_promotion
        self.lease_seconds = lease_seconds
        self.max_attempts_per_candidate = max_attempts_per_candidate
        self._inference_state_lock = threading.Lock()
        self._active_inferences = 0
        self._peak_inferences = 0

    def _inference_started(self) -> None:
        with self._inference_state_lock:
            self._active_inferences += 1
            self._peak_inferences = max(self._peak_inferences, self._active_inferences)

    def _inference_finished(self) -> None:
        with self._inference_state_lock:
            self._active_inferences = max(0, self._active_inferences - 1)

    def _peak_inference_count(self) -> int:
        with self._inference_state_lock:
            return self._peak_inferences

    def run_segment(
        self,
        workers: Iterable[tuple[str, str, str | None]],
        *,
        max_total_attempts: int,
        deadline: float,
        max_attempts_this_segment: int | None = None,
        max_boundary_tasks_this_segment: int | None = None,
        boundary_only: bool = False,
        _skip_boundary_work: bool = False,
    ) -> dict[str, Any]:
        if max_attempts_this_segment is not None and max_attempts_this_segment <= 0:
            raise ValueError("internal segment attempt limit must be positive")
        if max_boundary_tasks_this_segment is not None and max_boundary_tasks_this_segment <= 0:
            raise ValueError("internal segment boundary limit must be positive")
        worker_rows = tuple(workers)
        if not worker_rows:
            return {
                "attempted": 0,
                "outcomes": {},
                "boundary_outcomes": {},
                "stages": {},
                "external_work_remains": bool(self.store.pending_count()),
            }
        attempts_remaining = max(
            0,
            max_total_attempts - self.store.campaign_store.total_attempt_count(),
        )
        segment_limit = (
            len(worker_rows)
            if max_attempts_this_segment is None
            else max_attempts_this_segment
        )
        concurrent_slots = min(
            len(worker_rows),
            segment_limit,
            attempts_remaining,
            self.store.exact_pending_count(),
        )
        if len(worker_rows) > 1 and concurrent_slots > 1 and not boundary_only:
            worker_results: list[dict[str, Any]] = []
            selected_workers = worker_rows[:concurrent_slots]
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=concurrent_slots,
                thread_name_prefix="seto-internal-worker",
            ) as pool:
                pending = {
                    pool.submit(
                        self.run_segment,
                        (worker,),
                        max_total_attempts=max_total_attempts,
                        deadline=deadline,
                        max_attempts_this_segment=1,
                        max_boundary_tasks_this_segment=1,
                        _skip_boundary_work=True,
                    ): worker[0]
                    for worker in selected_workers
                }
                for future in concurrent.futures.as_completed(pending):
                    worker_id = pending[future]
                    try:
                        result = dict(future.result())
                        result["worker_id"] = worker_id
                    except Exception as exc:
                        result = {
                            "worker_id": worker_id,
                            "attempted": 0,
                            "outcomes": {"worker_error": 1},
                            "boundary_outcomes": {},
                            "stages": {},
                            "error": type(exc).__name__,
                        }
                    worker_results.append(result)

            outcomes: dict[str, int] = {}
            boundary_outcomes: dict[str, int] = {}
            stages: dict[str, int] = {}
            attempted = 0
            for result in worker_results:
                attempted += int(result.get("attempted", 0))
                for name, count in result.get("outcomes", {}).items():
                    outcomes[name] = outcomes.get(name, 0) + int(count)
                for name, count in result.get("boundary_outcomes", {}).items():
                    boundary_outcomes[name] = boundary_outcomes.get(name, 0) + int(count)
                for name, count in result.get("stages", {}).items():
                    stages[name] = stages.get(name, 0) + int(count)
            return {
                "attempted": attempted,
                "outcomes": outcomes,
                "boundary_outcomes": boundary_outcomes,
                "stages": stages,
                "worker_segments": worker_results,
                "workers_dispatched": len(worker_results),
                "peak_inference_workers": self._peak_inference_count(),
                "external_work_remains": bool(self.store.pending_count()),
            }
        attempted = 0
        outcomes: list[str] = []
        boundary_outcomes: list[str] = []
        boundary_tasks = 0
        stages = {
            "worker_attempts_started": 0,
            "matcher_runs": 0,
            "strict_matches": 0,
            "certification_attempts": 0,
            "certifications": 0,
            "certification_blocked": 0,
            "promotions_reconciled": 0,
            "promotion_recovery_blocked": 0,
        }
        index = 0
        failed_workers: set[str] = set()
        while time.monotonic() < deadline and not self.store.campaign_store.stop_requested():
            if (
                boundary_only
                and max_boundary_tasks_this_segment is not None
                and boundary_tasks >= max_boundary_tasks_this_segment
            ):
                break
            budget_full = self.store.campaign_store.total_attempt_count() >= max_total_attempts
            if budget_full and self.store.recovery_count() == 0:
                break
            if (
                max_attempts_this_segment is not None
                and attempted >= max_attempts_this_segment
            ):
                break
            available_workers = [row for row in worker_rows if row[0] not in failed_workers]
            if not available_workers:
                break
            worker_id, provider, model_provider = available_workers[index % len(available_workers)]
            index += 1
            boundary_claim = None
            if not _skip_boundary_work and not budget_full and (
                max_boundary_tasks_this_segment is None
                or boundary_tasks < max_boundary_tasks_this_segment
            ):
                boundary_claim = self.store.claim_boundary(
                    worker_id, lease_seconds=self.lease_seconds
                )
            if boundary_claim is not None:
                boundary_tasks += 1
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
                except Exception as exc:
                    self.store.fail_boundary(boundary_claim)
                    boundary_outcomes.append("blocked")
                    if isinstance(exc, InternalWorkerUnavailable):
                        failed_workers.add(worker_id)
                continue

            if boundary_only:
                break

            claim = self.store.claim_next(
                worker_id,
                provider,
                model_provider=model_provider,
                lease_seconds=self.lease_seconds,
                max_total_attempts=max_total_attempts,
                max_attempts_per_candidate=self.max_attempts_per_candidate,
            )
            if claim is None:
                failed_workers.add(worker_id)
                continue
            if self.recover_promotion is not None:
                try:
                    recovered = self.recover_promotion(claim)
                except Exception as exc:
                    self.store.block_prepared(claim, type(exc).__name__)
                    outcomes.append("blocked")
                    stages["promotion_recovery_blocked"] += 1
                    continue
                if recovered is not None:
                    try:
                        if recovered.get("certified") is not True:
                            raise ValueError("recovered promotion is not certified")
                        self.store.finish_recovered_promotion(claim, recovered)
                        outcomes.append("matched_recovered")
                        stages["promotions_reconciled"] += 1
                        continue
                    except Exception as exc:
                        self.store.block_prepared(claim, type(exc).__name__)
                        outcomes.append("blocked")
                        stages["promotion_recovery_blocked"] += 1
                        continue
            promotion_started = False
            local_source_to_skip: str | None = None
            worker_completed = False
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
                        max_attempts_per_candidate=self.max_attempts_per_candidate,
                        lease_seconds=self.lease_seconds,
                    )
                    if updated is None:
                        if (current_claim or claim).attempt_number >= self.max_attempts_per_candidate:
                            raise InternalAttemptCeiling("internal candidate attempt ceiling reached")
                        if (
                            self.store.campaign_store.stop_requested()
                            or time.monotonic() >= deadline
                            or self.store.campaign_store.total_attempt_count() >= max_total_attempts
                        ):
                            raise InternalCampaignBudgetExhausted("shared campaign budget ended before inference")
                        raise RuntimeError("shared attempt budget exhausted before inference")
                    started.append(updated)
                    stages["worker_attempts_started"] += 1
                    self._inference_started()
                    return updated

                try:
                    worker_result = self.worker(claim, begin_attempt, deadline)
                finally:
                    if started:
                        self._inference_finished()
                worker_completed = True
                if not started and worker_result.get("status") == "INTERRUPTED":
                    self.store.release_preparation(
                        claim, diagnostic_code="campaign_interrupted", worker_backoff_seconds=1
                    )
                    break
                if not started and worker_result.get("status") != "SOURCE_READY":
                    raise InternalWorkerUnavailable("worker returned before producing a recoverable source")
                claim = started[0] if started else claim
                if isinstance(worker_result.get("checkpoint"), dict):
                    claim = replace(
                        claim,
                        checkpoint={**claim.checkpoint, **worker_result["checkpoint"]},
                    )
                    self.store.campaign_store.save_checkpoint(
                        claim,
                        worker_result["checkpoint"],
                        trusted_evidence=True,
                    )
                if worker_result.get("status") != "SOURCE_READY":
                    if worker_result.get("status") == "INTERRUPTED":
                        if started:
                            final = self.store.finish_attempt(
                                claim,
                                "INTERRUPTED",
                                worker_result,
                                max_attempts=self.max_attempts_per_candidate,
                            )
                            outcomes.append(final)
                            attempted += 1
                        else:
                            self.store.release_preparation(
                                claim,
                                diagnostic_code="campaign_interrupted",
                                worker_backoff_seconds=1,
                            )
                        break
                    failed_workers.add(worker_id)
                    raise InternalWorkerUnavailable("worker did not return a source for matching")
                if not started:
                    candidate_source_hash = worker_result.get("source_sha256")
                    if isinstance(candidate_source_hash, str) and re_full_sha256(candidate_source_hash):
                        local_source_to_skip = candidate_source_hash
                match = self.matcher(claim, worker_result, deadline)
                stages["matcher_runs"] += 1
                local_match_hash = match.get("source_sha256")
                if not started and isinstance(local_match_hash, str):
                    self.store.campaign_store.save_checkpoint(
                        claim,
                        {"last_local_match_source_sha256": local_match_hash},
                        trusted_evidence=True,
                    )
                match_status = match.get("status")
                if match_status != "MATCHED":
                    status = (
                        str(match_status)
                        if match_status in {"NONMATCHING", "INCONCLUSIVE"}
                        else "FAILED"
                    )
                    final = (
                        self.store.finish_attempt(
                            claim,
                            status,
                            match,
                            max_attempts=self.max_attempts_per_candidate,
                        )
                        if started
                        else self.store.finish_prepared_result(
                            claim,
                            status,
                            match,
                            max_attempts=self.max_attempts_per_candidate,
                            local_match_source_sha256=(
                                local_match_hash if isinstance(local_match_hash, str) else None
                            ),
                        )
                    )
                    outcomes.append(final)
                    attempted += int(bool(started))
                    continue
                stages["strict_matches"] += 1
                stages["certification_attempts"] += 1
                journal = (
                    dict(self.journal_promotion(claim, match))
                    if self.journal_promotion is not None
                    else {"promotion_pending": True}
                )
                if journal.get("promotion_pending") is not True:
                    raise ValueError("promotion journal must be durable before filesystem integration")
                self.store.campaign_store.save_checkpoint(
                    claim, journal, trusted_evidence=True
                )
                claim = replace(claim, checkpoint={**claim.checkpoint, **journal})
                promotion_started = True
                certificate = self.certifier(claim, match)
                if certificate.get("certified") is not True:
                    raise ValueError("certifier did not approve the two-build internal match")
                stages["certifications"] += 1
                certified_result = {**dict(match), **dict(certificate), "certified": True}
                final = (
                    self.store.finish_attempt(
                        claim,
                        "MATCHED",
                        certified_result,
                        max_attempts=self.max_attempts_per_candidate,
                    )
                    if started
                    else self.store.finish_prepared_result(
                        claim,
                        "MATCHED",
                        certified_result,
                        max_attempts=self.max_attempts_per_candidate,
                    )
                )
                outcomes.append(final)
                attempted += int(bool(started))
            except Exception as exc:
                if promotion_started:
                    try:
                        self.store.queue_promotion_recovery(
                            claim,
                            source_sha256=(
                                match.get("source_sha256") if "match" in locals() else None
                            ),
                            build_sha256=(
                                match.get("build_sha256") if "match" in locals() else None
                            ),
                        )
                        stages["certification_blocked"] += 1
                        outcomes.append("promotion_pending")
                        attempted += int(bool(started))
                    except RuntimeError:
                        pass
                    continue
                if started:
                    try:
                        if (
                            self.store.campaign_store.stop_requested()
                            or time.monotonic() >= deadline
                        ):
                            final = self.store.finish_attempt(
                                started[0],
                                "INTERRUPTED",
                                {"diagnostic": "campaign_interrupted"},
                                max_attempts=self.max_attempts_per_candidate,
                            )
                            outcomes.append(final)
                            attempted += 1
                            break
                        final = self.store.finish_attempt(
                            started[0],
                            "FAILED",
                            {"diagnostic": type(exc).__name__},
                            max_attempts=self.max_attempts_per_candidate,
                        )
                        outcomes.append(final)
                        attempted += 1
                        if not worker_completed:
                            failed_workers.add(worker_id)
                    except RuntimeError:
                        pass
                else:
                    if isinstance(exc, InternalAttemptCeiling):
                        final = self.store.finish_prepared_result(
                            claim,
                            "FAILED",
                            {"diagnostic": "attempt_ceiling"},
                            max_attempts=self.max_attempts_per_candidate,
                        )
                        outcomes.append(final)
                        continue
                    if isinstance(exc, InternalCampaignBudgetExhausted):
                        try:
                            self.store.release_preparation(
                                claim,
                                diagnostic_code="campaign_interrupted",
                                worker_backoff_seconds=1,
                            )
                        except RuntimeError:
                            pass
                        break
                    if (
                        self.store.campaign_store.stop_requested()
                        or time.monotonic() >= deadline
                        or self.store.campaign_store.total_attempt_count() >= max_total_attempts
                    ):
                        try:
                            self.store.release_preparation(
                                claim, diagnostic_code="campaign_interrupted", worker_backoff_seconds=1
                            )
                        except RuntimeError:
                            pass
                        break
                    if isinstance(exc, InternalTaskBlocked):
                        self.store.block_prepared(claim, type(exc).__name__)
                        outcomes.append("blocked")
                        continue
                    if local_source_to_skip is not None:
                        self.store.campaign_store.save_checkpoint(
                            claim,
                            {"last_local_match_source_sha256": local_source_to_skip},
                            trusted_evidence=True,
                        )
                        claim = replace(
                            claim,
                            checkpoint={
                                **claim.checkpoint,
                                "last_local_match_source_sha256": local_source_to_skip,
                            },
                        )
                    self.store.release_preparation(
                        claim,
                        diagnostic_code=(
                            "provider_or_session_unavailable"
                            if isinstance(exc, InternalWorkerUnavailable)
                            else type(exc).__name__
                        ),
                    )
                    failed_workers.add(worker_id)
        return {
            "attempted": attempted,
            "outcomes": {kind: outcomes.count(kind) for kind in sorted(set(outcomes))},
            "boundary_outcomes": {
                kind: boundary_outcomes.count(kind) for kind in sorted(set(boundary_outcomes))
            },
            "stages": stages,
            "workers_dispatched": 1,
            "peak_inference_workers": self._peak_inference_count(),
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

    def catalog_entry_for(claim: InternalClaim, source_hash: str, builds: list[str], certificate_hash: str) -> dict[str, Any]:
        certificate_relative = (
            Path("decomp/evidence/internal")
            / f"eboot-{claim.numeric_address:08x}.json"
        )
        certificate_path = repo_root / certificate_relative
        return {
            "module": claim.module,
            "address": claim.address,
            "size_bytes": claim.size_bytes,
            "instruction_count": claim.size_bytes // 4,
            "boundary_status": "EXACT",
            "section": claim.section,
            "kind": claim.kind,
            "evidence_path": f"{certificate_relative.as_posix()}#matcher-and-boundary",
            "source_path": f"decomp/src/eboot/func_{claim.numeric_address:08X}.c",
            "source_sha256": source_hash,
            "result": {
                "status": "MATCHED",
                "matching_words": claim.size_bytes // 4,
                "total_words": claim.size_bytes // 4,
                "object_sha256s": builds,
                "resolved_calls": [],
                "data_reference_count": 0,
                "certificate_path": certificate_relative.as_posix(),
                "certificate_sha256": certificate_hash,
            },
        }

    def audit_standalone_entry(entry: dict[str, Any]) -> None:
        recovery_catalog = campaign_build_path(
            repo_root,
            f"seto049/internal-recovery/{uuid.uuid4().hex}.json",
        )
        recovery_catalog.parent.mkdir(parents=True, exist_ok=True)
        try:
            with recovery_catalog.open("x", encoding="utf-8", newline="\n") as stream:
                json.dump({"schema_version": 2, "functions": [entry]}, stream, indent=2)
                stream.write("\n")
            problems = validate_internal_catalog_evidence(
                recovery_catalog,
                repo_root=repo_root,
                mode="full",
                require_tracked_sources=False,
                check_export_overlaps=(repo_root / "config/decomp_campaign_inventory.json").is_file(),
            )
            if problems:
                raise ValueError("stored internal certificate failed the full evidence audit")
        finally:
            recovery_catalog.unlink(missing_ok=True)

    def same_promotion(existing: Any, expected: dict[str, Any]) -> bool:
        if not isinstance(existing, dict):
            return False
        fields = (
            "module",
            "address",
            "size_bytes",
            "instruction_count",
            "boundary_status",
            "section",
            "kind",
            "evidence_path",
            "source_path",
            "source_sha256",
        )
        if any(existing.get(key) != expected.get(key) for key in fields):
            return False
        old_result, new_result = existing.get("result"), expected.get("result")
        if not isinstance(old_result, dict) or not isinstance(new_result, dict):
            return False
        result_fields = (
            "status",
            "matching_words",
            "total_words",
            "object_sha256s",
            "resolved_calls",
            "data_reference_count",
            "certificate_path",
            "certificate_sha256",
        )
        return all(old_result.get(key) == new_result.get(key) for key in result_fields)

    catalog_write_lock = threading.RLock()

    def persist_catalog_entry_unlocked(entry: dict[str, Any]) -> None:
        current_bytes = catalog_path.read_bytes()
        document = json.loads(current_bytes)
        if not isinstance(document, dict) or not isinstance(document.get("functions"), list):
            raise ValueError("internal catalog schema is malformed during promotion")
        existing = [
            item
            for item in document["functions"]
            if isinstance(item, dict)
            and str(item.get("module", "")).casefold() == str(entry["module"]).casefold()
            and item.get("address") == entry["address"]
        ]
        if existing:
            if len(existing) != 1 or not same_promotion(existing[0], entry):
                raise ValueError("existing internal catalog entry conflicts with promotion")
            problems = validate_internal_catalog_evidence(
                catalog_path,
                repo_root=repo_root,
                mode="full",
                require_tracked_sources=False,
                check_export_overlaps=(repo_root / "config/decomp_campaign_inventory.json").is_file(),
            )
            if problems:
                raise ValueError("existing internal catalog entry failed full evidence audit")
            return
        document["functions"].append(entry)
        document["functions"].sort(
            key=lambda item: (item["module"].casefold(), int(item["address"], 0))
        )
        # Validate the new schema and intervals before the atomic replace.
        validation_catalog = campaign_build_path(
            repo_root, f"seto049/internal-recovery/catalog-{uuid.uuid4().hex}.json"
        )
        validation_catalog.parent.mkdir(parents=True, exist_ok=True)
        try:
            with validation_catalog.open("x", encoding="utf-8", newline="\n") as stream:
                json.dump(document, stream, indent=2)
                stream.write("\n")
            load_internal_catalog(validation_catalog)
            metadata_problems = validate_internal_catalog_evidence(
                validation_catalog,
                repo_root=repo_root,
                mode="metadata-only",
                require_tracked_sources=False,
                check_export_overlaps=(repo_root / "config/decomp_campaign_inventory.json").is_file(),
            )
            if metadata_problems:
                raise ValueError("internal catalog promotion failed metadata/overlap checks")
        finally:
            validation_catalog.unlink(missing_ok=True)
        temporary = catalog_path.with_name(f"{catalog_path.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as stream:
                json.dump(document, stream, indent=2)
                stream.write("\n")
            if catalog_path.read_bytes() != current_bytes:
                raise ValueError("internal catalog changed concurrently; promotion was not applied")
            os.replace(temporary, catalog_path)
        finally:
            temporary.unlink(missing_ok=True)

    def persist_catalog_entry(entry: dict[str, Any]) -> None:
        # Concurrent certified workers may append different addresses. Keep the
        # read/validate/atomic-replace transaction indivisible to avoid lost updates.
        with catalog_write_lock:
            persist_catalog_entry_unlocked(entry)

    def recover_promotion_journal(
        claim: InternalClaim,
    ) -> tuple[dict[str, Any] | None, list[dict[str, Any]], InternalClaim]:
        journal = claim.checkpoint.get("promotion_recovery")
        report_specs = journal.get("report_files") if isinstance(journal, dict) else None
        if not isinstance(report_specs, list):
            source_hash_hint = claim.checkpoint.get("source_sha256")
            attempt_number = max(1, claim.attempt_number)
            journal_base = campaign_build_path(
                repo_root,
                f"seto049/internal-audit/eboot/{claim.numeric_address:08x}",
            )
            roots = []
            if journal_base.is_dir() and not journal_base.is_symlink():
                for report_path in journal_base.glob(
                    f"*/attempt-{attempt_number}/journal-*/verify-1.json"
                ):
                    if report_path.is_symlink():
                        continue
                    root = report_path.parent
                    second = root / "verify-2.json"
                    if second.is_file() and not second.is_symlink():
                        roots.append(root)
            complete = []
            for root in roots:
                specs = []
                source_hashes = set()
                build_hashes = []
                reports = []
                try:
                    for number in (1, 2):
                        path = root / f"verify-{number}.json"
                        relative = path.relative_to(repo_root).as_posix()
                        safe_path = campaign_build_path(repo_root, relative.removeprefix("build/"))
                        if safe_path.is_symlink() or not safe_path.is_file() or safe_path.stat().st_size > 2_000_000:
                            raise ValueError("journal report path is missing/unsafe")
                        raw = safe_path.read_bytes()
                        report = json.loads(raw)
                        provenance = report.get("provenance", {})
                        source_hash = provenance.get("source_sha256")
                        object_hash = provenance.get("object_sha256")
                        if (
                            not is_strict_match(report, expected_address=claim.numeric_address, expected_size=claim.size_bytes)
                            or report.get("section") != claim.section
                            or provenance.get("source") != f"decomp/src/eboot/func_{claim.numeric_address:08X}.c"
                            or not isinstance(source_hash, str)
                            or not re_full_sha256(source_hash)
                            or not isinstance(object_hash, str)
                            or not re_full_sha256(object_hash)
                            or not internal_reference_evidence_is_resolved(report)
                        ):
                            raise ValueError("journal report fails its full identity/match gates")
                        source_hashes.add(source_hash)
                        build_hashes.append(object_hash)
                        reports.append(report)
                        specs.append({"path": relative, "sha256": hashlib.sha256(raw).hexdigest()})
                    if len(source_hashes) != 1 or build_hashes[0] != build_hashes[1]:
                        raise ValueError("journal reports disagree on source or deterministic object")
                    source_hash = next(iter(source_hashes))
                    if isinstance(source_hash_hint, str) and source_hash_hint != source_hash:
                        continue
                    complete.append(
                        (
                            {
                                "version": 1,
                                "module": claim.module,
                                "address": claim.address,
                                "size_bytes": claim.size_bytes,
                                "section": claim.section,
                                "source_path": f"decomp/src/eboot/func_{claim.numeric_address:08X}.c",
                                "source_sha256": source_hash,
                                "build_sha256": build_hashes,
                                "worker_id": str(claim.checkpoint.get("last_worker_id", claim.worker_id)),
                                "attempt_number": attempt_number,
                                "report_files": specs,
                            },
                            reports,
                        )
                    )
                except (OSError, ValueError, TypeError, json.JSONDecodeError):
                    continue
            if len(complete) > 1:
                raise ValueError("multiple conflicting promotion journals exist for this attempt")
            if complete:
                journal, reports = complete[0]
                journal["promotion_pending"] = True
                campaign_store.save_checkpoint(claim, journal, trusted_evidence=True)
                claim = replace(claim, checkpoint={**claim.checkpoint, **journal})
                return journal, reports, claim
            if claim.checkpoint.get("promotion_pending") is True:
                raise ValueError("promotion is pending but its durable matcher journal is missing")
            return None, [], claim

        reports = []
        for spec in report_specs:
            if not isinstance(spec, dict):
                raise ValueError("promotion journal report record is malformed")
            relative = spec.get("path")
            digest = spec.get("sha256")
            if not isinstance(relative, str) or not isinstance(digest, str) or not re_full_sha256(digest):
                raise ValueError("promotion journal report path/hash is malformed")
            if not relative.startswith("build/"):
                raise ValueError("promotion journal report path must be build-relative")
            path = campaign_build_path(repo_root, relative.removeprefix("build/"))
            raw = path.read_bytes()
            if path.is_symlink() or hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError("promotion journal report is absent, unsafe, or changed")
            reports.append(json.loads(raw))
        return journal, reports, claim

    def recover_catalog_promotion(claim: InternalClaim) -> Mapping[str, Any] | None:
        document = json.loads(catalog_path.read_text(encoding="utf-8"))
        entries = document.get("functions", [])
        matches = [
            entry
            for entry in entries
            if isinstance(entry, dict)
            and str(entry.get("module", "")).casefold() == claim.module.casefold()
            and entry.get("address") == claim.address
        ]
        if not matches:
            certificate_relative = (
                Path("decomp/evidence/internal")
                / f"eboot-{claim.numeric_address:08x}.json"
            )
            certificate_path = repo_root / certificate_relative
            if not certificate_path.exists() and not certificate_path.is_symlink():
                journal, reports, claim = recover_promotion_journal(claim)
                if journal is None:
                    return None
                recovered_match = {
                    "status": "MATCHED",
                    "source_sha256": journal["source_sha256"],
                    "matching_words": claim.size_bytes // 4,
                    "total_words": claim.size_bytes // 4,
                    "build_sha256": journal["build_sha256"],
                    "reports": reports,
                }
                return certify(claim, recovered_match)
            if certificate_path.is_symlink() or not certificate_path.is_file():
                raise ValueError("orphan internal certificate path is unsafe")
            try:
                certificate = json.loads(certificate_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError("orphan internal certificate is unreadable") from exc
            source_relative = f"decomp/src/eboot/func_{claim.numeric_address:08X}.c"
            if (
                certificate.get("schema_version") != 1
                or certificate.get("module") != claim.module
                or certificate.get("address") != claim.address
                or certificate.get("size_bytes") != claim.size_bytes
                or certificate.get("section") != claim.section
                or certificate.get("source_path") != source_relative
            ):
                raise ValueError("orphan certificate identity conflicts with its internal task")
            source_hash = certificate.get("source_sha256")
            builds = certificate.get("build_sha256")
            if not isinstance(source_hash, str) or not isinstance(builds, list):
                raise ValueError("orphan internal certificate is missing source/build hashes")
            journal = claim.checkpoint.get("promotion_recovery")
            source_hint = (
                journal.get("source_sha256")
                if isinstance(journal, dict)
                else claim.checkpoint.get("source_sha256")
            )
            if isinstance(source_hint, str) and source_hint != source_hash:
                raise ValueError("orphan certificate source conflicts with the task checkpoint")
            if isinstance(journal, dict) and journal.get("build_sha256") != builds:
                raise ValueError("orphan certificate disagrees with the persisted promotion journal")
            certificate_hash = hashlib.sha256(certificate_path.read_bytes()).hexdigest()
            entry = catalog_entry_for(claim, source_hash, builds, certificate_hash)
            entry["result"]["resolved_calls"] = list(
                certificate["reports"][0]["match"].get("resolved_calls", [])
            )
            entry["result"]["data_reference_count"] = len(
                certificate["reports"][0]["match"].get("resolved_data", [])
            )
            audit_standalone_entry(entry)
            persist_catalog_entry(entry)
            return {
                "certified": True,
                "source_sha256": source_hash,
                "build_sha256": builds,
                "certificate_path": certificate_relative.as_posix(),
                "certificate_sha256": certificate_hash,
            }
        if len(matches) != 1:
            raise ValueError("internal catalog contains duplicate promotion identities")
        entry = matches[0]
        result = entry.get("result")
        expected_source = f"decomp/src/eboot/func_{claim.numeric_address:08X}.c"
        if (
            entry.get("boundary_status") != "EXACT"
            or entry.get("size_bytes") != claim.size_bytes
            or entry.get("section") != claim.section
            or entry.get("kind") != claim.kind
            or entry.get("source_path") != expected_source
            or not isinstance(result, dict)
            or result.get("status") != "MATCHED"
        ):
            raise ValueError("existing catalog identity conflicts with the leased internal task")
        promotion_journal = claim.checkpoint.get("promotion_recovery")
        source_hint = (
            promotion_journal.get("source_sha256")
            if isinstance(promotion_journal, dict)
            else claim.checkpoint.get("source_sha256")
        )
        if isinstance(source_hint, str) and entry.get("source_sha256") != source_hint:
            raise ValueError("existing catalog source conflicts with the internal recovery checkpoint")
        if isinstance(promotion_journal, dict) and (
            result.get("object_sha256s") != promotion_journal.get("build_sha256")
        ):
            raise ValueError("existing catalog object hashes conflict with the promotion journal")
        problems = validate_internal_catalog_evidence(
            catalog_path,
            repo_root=repo_root,
            mode="full",
            require_tracked_sources=False,
            check_export_overlaps=(repo_root / "config/decomp_campaign_inventory.json").is_file(),
        )
        if problems:
            raise ValueError("existing catalog promotion failed full evidence audit")
        journal = claim.checkpoint.get("promotion_recovery")
        if isinstance(journal, dict) and (
            journal.get("source_sha256") != entry.get("source_sha256")
            or journal.get("build_sha256") != result.get("object_sha256s")
        ):
            raise ValueError("catalog promotion differs from the persisted source/build journal")
        return {
            "certified": True,
            "source_sha256": entry["source_sha256"],
            "build_sha256": result["object_sha256s"],
            "certificate_path": result["certificate_path"],
            "certificate_sha256": result["certificate_sha256"],
        }

    def run_boundary(claim: InternalClaim, deadline: float) -> InternalClaim:
        worktree = campaign_runner.worktrees.get(claim.worker_id)
        if worktree is None or worktree.is_symlink() or not worktree.is_dir():
            raise InternalWorkerUnavailable("internal Ghidra worktree is missing or unsafe")
        try:
            return campaign_runner._prepare_claim(worktree, claim, deadline)  # type: ignore[arg-type,return-value]
        except CampaignInterrupted:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            message = str(exc).casefold()
            if any(
                marker in message
                for marker in (
                    "ghidra home",
                    "ghidra launcher",
                    "ghidra headless",
                    "ghidra completed without",
                    "ghidra analysis omitted",
                    "machine-local",
                    "private eboot",
                    "eboot hash differs",
                    "configured windows jdk",
                )
            ):
                raise InternalWorkerUnavailable("Ghidra worktree/toolchain is unavailable") from exc
            raise

    source_stub = b"/* Internal EBOOT candidate; reconstruct from verified evidence. */\n"

    def preserve_source_checkpoint(
        claim: InternalClaim, source: Path, source_relative: str
    ) -> dict[str, str]:
        if source.is_symlink() or not source.is_file() or source.stat().st_size > 1_000_000:
            raise InternalTaskBlocked("internal source is missing, unsafe, or too large")
        source_bytes = source.read_bytes()
        source_hash = hashlib.sha256(source_bytes).hexdigest()
        snapshot_relative = f"decomp-campaign/checkpoints/{claim.numeric_address:08x}/{source_hash}.c"
        snapshot = campaign_build_path(repo_root, snapshot_relative)
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        if snapshot.exists() or snapshot.is_symlink():
            if snapshot.is_symlink() or not snapshot.is_file() or hashlib.sha256(snapshot.read_bytes()).hexdigest() != source_hash:
                raise InternalTaskBlocked("internal source checkpoint conflicts with existing content")
        else:
            try:
                _atomic_create_file(snapshot, source_bytes, label="internal source checkpoint")
            except FileExistsError:
                if snapshot.is_symlink() or not snapshot.is_file() or hashlib.sha256(snapshot.read_bytes()).hexdigest() != source_hash:
                    raise InternalTaskBlocked("internal source checkpoint conflicts with concurrent content")
        return {
            "source_path": source_relative,
            "source_sha256": source_hash,
            "latest_source_snapshot": snapshot_relative,
        }

    def run_worker(
        claim: InternalClaim,
        begin_attempt: Callable[[InternalClaim | None], InternalClaim],
        deadline: float,
    ) -> Mapping[str, Any]:
        worker = workers.get(claim.worker_id)
        worktree = campaign_runner.worktrees.get(claim.worker_id)
        if worker is None or worktree is None or worktree.is_symlink() or not worktree.is_dir():
            raise InternalWorkerUnavailable("internal worker or its isolated worktree is unavailable")
        source_relative = f"decomp/src/eboot/func_{claim.numeric_address:08X}.c"
        source = _safe_worktree_path(worktree, Path(source_relative))
        if source.is_symlink():
            raise InternalTaskBlocked("internal candidate source is a symlink")
        source.parent.mkdir(parents=True, exist_ok=True)
        checkpoint = claim.checkpoint
        log_path = checkpoint.get("ghidra_log_path")
        log_hash = checkpoint.get("ghidra_log_sha256")
        if not isinstance(log_path, str) or not isinstance(log_hash, str):
            raise InternalTaskBlocked("internal worker requires hash-bound EXACT Ghidra evidence")
        log_file = campaign_build_path(worktree, log_path)
        if log_file.is_symlink() or not log_file.is_file() or hashlib.sha256(log_file.read_bytes()).hexdigest() != log_hash:
            parts = log_path.replace("\\", "/").split("/")
            if len(parts) < 5 or parts[0] != "decomp-campaign":
                raise InternalTaskBlocked("internal Ghidra checkpoint path is not canonical")
            copied = campaign_runner._copy_cached_ghidra_evidence(
                worktree,
                claim,  # type: ignore[arg-type]
                source_worker=parts[1],
                source_relative=log_path,
                source_sha256=log_hash,
            )
            if copied is None:
                raise InternalTaskBlocked("internal worker Ghidra evidence is missing or changed")
            claim = replace(claim, checkpoint=dict(claim.checkpoint))
            checkpoint = claim.checkpoint
            log_path = checkpoint["ghidra_log_path"]
            log_file = campaign_build_path(worktree, log_path)

        if source.exists() and not source.is_file():
            raise InternalTaskBlocked("internal candidate source is not a regular file")
        source_bytes = source.read_bytes() if source.is_file() else b""
        source_is_stub = source_bytes == source_stub
        origin_worker = checkpoint.get("last_worker_id")
        if (not source.exists() or source_is_stub) and isinstance(origin_worker, str):
            origin_worktree = campaign_runner.worktrees.get(origin_worker)
            if origin_worktree is not None and not origin_worktree.is_symlink() and origin_worktree.is_dir():
                origin_source = _safe_worktree_path(origin_worktree, Path(source_relative))
                if origin_source.is_symlink():
                    raise InternalTaskBlocked("prior worker source checkpoint is a symlink")
                if origin_source.is_file():
                    origin_bytes = origin_source.read_bytes()
                    if origin_bytes != source_stub:
                        if source.exists():
                            if source.read_bytes() != source_stub:
                                raise InternalTaskBlocked("refusing to replace a conflicting current source")
                            temporary_source = source.with_name(
                                f".{source.name}.{uuid.uuid4().hex}.tmp"
                            )
                            _atomic_create_file(temporary_source, origin_bytes, label="origin source recovery")
                            os.replace(temporary_source, source)
                        else:
                            _atomic_create_file(source, origin_bytes, label="origin source recovery")
                        source_bytes = origin_bytes
                        source_is_stub = False
        if (not source.exists() or source_is_stub):
            snapshot_relative = checkpoint.get("latest_source_snapshot")
            source_hash = checkpoint.get("source_sha256")
            expected_snapshot = (
                f"decomp-campaign/checkpoints/{claim.numeric_address:08x}/{source_hash}.c"
                if isinstance(source_hash, str) and re_full_sha256(source_hash)
                else None
            )
            if snapshot_relative is not None and snapshot_relative != expected_snapshot:
                raise InternalTaskBlocked("internal source checkpoint path is not canonical")
            if expected_snapshot is not None:
                snapshot = campaign_build_path(repo_root, expected_snapshot)
                if snapshot.is_symlink() or not snapshot.is_file() or hashlib.sha256(snapshot.read_bytes()).hexdigest() != source_hash:
                    raise InternalTaskBlocked("internal source checkpoint is absent or has a hash mismatch")
                if source.exists():
                    if source.read_bytes() != source_stub:
                        raise InternalTaskBlocked("refusing to replace a conflicting source with its checkpoint")
                    temporary_source = source.with_name(f".{source.name}.{uuid.uuid4().hex}.tmp")
                    _atomic_create_file(
                        temporary_source,
                        snapshot.read_bytes(),
                        label="checkpoint source recovery",
                    )
                    if source.read_bytes() != source_stub:
                        temporary_source.unlink(missing_ok=True)
                        raise InternalTaskBlocked("candidate source changed during checkpoint recovery")
                    os.replace(temporary_source, source)
                else:
                    _atomic_create_file(source, snapshot.read_bytes(), label="checkpoint source recovery")
                source_bytes = snapshot.read_bytes()
                source_is_stub = source_bytes == source_stub

        existing_source = source.is_file() and not source_is_stub
        if existing_source:
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            if checkpoint.get("last_local_match_source_sha256") != source_hash:
                recovered_checkpoint = preserve_source_checkpoint(claim, source, source_relative)
                return {
                    "status": "SOURCE_READY",
                    "source_sha256": source_hash,
                    "checkpoint": recovered_checkpoint,
                    "local_recovery": True,
                }

        if checkpoint.get("inference_allowed") is False:
            raise InternalAttemptCeiling("no reusable source remains at the shared attempt ceiling")
        if worker.agent != "seto-decomp-worker":
            raise InternalWorkerUnavailable("internal tasks require the restricted decomp worker agent")
        if not campaign_runner._provider_gate_open(worker):
            raise InternalWorkerUnavailable("configured provider gate is closed for this internal worker")
        if campaign_store.provider_status(worker.execution_scope) != "active":
            raise InternalWorkerUnavailable("provider status is paused for this internal worker")
        if not source.exists():
            with source.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(source_stub.decode("ascii"))
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
            "If evidence is insufficient, preserve the best hypothesis. Finish with exactly one JSON "
            'object shaped like {"checkpoint": {"next_experiment": "...", "limitations": "..."}} '
            "and no other final text."
        )
        if len(prompt.encode("utf-8")) > 32_000:
            raise InternalTaskBlocked("internal reconstruction prompt exceeds its fixed bound")
        provider_slot = campaign_runner.provider_slots.get(worker.execution_scope)
        acquired = False
        try:
            if provider_slot is not None:
                if not campaign_runner._acquire_resource_slot(provider_slot, deadline):
                    return {"status": "INTERRUPTED"}
                acquired = True
                if campaign_store.provider_status(worker.execution_scope) != "active":
                    raise InternalWorkerUnavailable("provider was paused before internal inference")
            remote_target = None
            if worker.transport == "ssh":
                try:
                    remote_target = campaign_runner._prepare_remote_claim(
                        worker, claim, worktree, deadline
                    )  # type: ignore[arg-type]
                except Exception as exc:
                    if isinstance(exc, CampaignInterrupted):
                        raise
                    raise InternalWorkerUnavailable("remote worker context/session staging failed") from exc
            try:
                claim = campaign_runner._ensure_session(
                    claim,
                    worktree,
                    deadline,
                    agent=worker.agent,
                    model=worker.model,
                    worker=worker,
                )  # type: ignore[assignment]
            except Exception as exc:
                if isinstance(exc, CampaignInterrupted):
                    raise
                raise InternalWorkerUnavailable("OpenCode session is unavailable for this worker") from exc
            protected_before = _file_manifest(worktree) if campaign_runner.auto_preflight else {}
            changes_before = _worktree_status_snapshot(worktree) if campaign_runner.auto_preflight else {}
            git_head = _git_output_internal(worktree, "rev-parse", "HEAD") if campaign_runner.auto_preflight else ""
            git_branch = _git_output_internal(worktree, "branch", "--show-current") if campaign_runner.auto_preflight else ""
            argv = campaign_runner._argv(worker, claim, prompt) if worker.transport == "local" else []  # type: ignore[arg-type]
            started_claim = begin_attempt(claim)
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
            if (
                process.interrupted
                or campaign_store.stop_requested()
                or (process.timed_out and time.monotonic() >= deadline)
            ):
                return {"status": "INTERRUPTED"}
            if process.returncode != 0 or process.timed_out:
                return {"status": "FAILED", "returncode": process.returncode}
            if source.is_symlink() or not source.is_file():
                raise InternalTaskBlocked("internal worker did not leave a regular source file")
            try:
                extracted = _extract_checkpoint(process.stdout)
            except ValueError:
                # A worker can leave a usable source without the optional final JSON
                # checkpoint (the real failure at 0x39f04 was prose-only output).
                # Keep the strict requirement only when no reconstruction happened.
                if source.read_bytes() == source_stub:
                    raise InternalWorkerUnavailable(
                        "worker returned without reconstructing its source"
                    ) from None
                extracted = {}
            worker_checkpoint = {
                key: extracted[key]
                for key in ("next_experiment", "limitations")
                if key in extracted
            }
            worker_checkpoint.update(preserve_source_checkpoint(claim, source, source_relative))
            source_hash = worker_checkpoint["source_sha256"]
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
        match_claim = replace(
            claim,
            checkpoint={**claim.checkpoint, "matcher_run_id": uuid.uuid4().hex},
        )
        return campaign_runner._run_limited_operation(
            campaign_runner.matcher_slots,
            "matcher",
            claim=match_claim,  # type: ignore[arg-type]
            deadline=deadline,
            operation=lambda: campaign_runner._verify_internal_with_matcher_twice(
                worktree, match_claim, deadline
            ),
        )

    def journal_promotion(
        claim: InternalClaim, match: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if match.get("status") != "MATCHED" or not isinstance(match.get("reports"), list) or len(match["reports"]) != 2:
            raise InternalTaskBlocked("strict two-report match is required before promotion journaling")
        source_hash = match.get("source_sha256")
        builds = match.get("build_sha256")
        if (
            not isinstance(source_hash, str)
            or not re_full_sha256(source_hash)
            or not isinstance(builds, list)
            or len(builds) != 2
            or builds[0] != builds[1]
            or any(not isinstance(value, str) or not re_full_sha256(value) for value in builds)
        ):
            raise InternalTaskBlocked("strict match is missing deterministic source/object hashes")
        from decomp_campaign import is_strict_match

        worktree = campaign_runner.worktrees[claim.worker_id]
        attempt_number = max(1, claim.attempt_number)
        journal_id = _promotion_journal_id(claim, source_hash, attempt_number)
        audit_relative_root = (
            f"seto049/internal-audit/eboot/{claim.numeric_address:08x}/"
            f"{source_hash}/attempt-{attempt_number}/journal-{journal_id}"
        )
        audit_root = campaign_build_path(repo_root, audit_relative_root)
        report_files = []
        for index, report in enumerate(match["reports"], 1):
            if not isinstance(report, dict) or not isinstance(report.get("report_path"), str):
                raise InternalTaskBlocked("matcher report path is missing from promotion journal")
            report_path = _safe_worktree_path(worktree, Path(report["report_path"]))
            if report_path.is_symlink() or not report_path.is_file() or report_path.stat().st_size > 2_000_000:
                raise InternalTaskBlocked("full matcher report is missing, unsafe, or too large")
            try:
                payload = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise InternalTaskBlocked("full matcher report is not valid JSON") from exc
            provenance = payload.get("provenance", {})
            if (
                not is_strict_match(payload, expected_address=claim.numeric_address, expected_size=claim.size_bytes)
                or payload.get("section") != claim.section
                or provenance.get("source_sha256") != source_hash
                or provenance.get("object_sha256") != builds[index - 1]
                or not internal_reference_evidence_is_resolved(payload)
            ):
                raise InternalTaskBlocked("full matcher report identity differs from its promotion result")
            destination = audit_root / f"verify-{index}.json"
            destination.parent.mkdir(parents=True, exist_ok=True)
            raw = report_path.read_bytes()
            if destination.is_symlink():
                raise InternalTaskBlocked("promotion report destination is a symlink")
            if destination.exists():
                try:
                    previous = json.loads(destination.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise InternalTaskBlocked("existing promotion report is unreadable") from exc
                previous_provenance = previous.get("provenance", {})
                if (
                    not is_strict_match(
                        previous,
                        expected_address=claim.numeric_address,
                        expected_size=claim.size_bytes,
                    )
                    or previous_provenance.get("source_sha256") != source_hash
                    or previous_provenance.get("object_sha256") != builds[index - 1]
                    or not internal_reference_evidence_is_resolved(previous)
                ):
                    raise InternalTaskBlocked("existing promotion report conflicts with the current source/build")
                raw = destination.read_bytes()
            else:
                try:
                    _atomic_create_file(destination, raw, label="promotion report")
                except FileExistsError:
                    if destination.is_symlink() or not destination.is_file() or destination.read_bytes() != raw:
                        raise InternalTaskBlocked("promotion report destination changed concurrently")
                    raw = destination.read_bytes()
            report_files.append(
                {
                    "path": destination.relative_to(repo_root).as_posix(),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        return {
            "promotion_pending": True,
            "promotion_recovery": {
                "version": 1,
                "module": claim.module,
                "address": claim.address,
                "size_bytes": claim.size_bytes,
                "section": claim.section,
                "source_path": f"decomp/src/eboot/func_{claim.numeric_address:08X}.c",
                "source_sha256": source_hash,
                "build_sha256": list(builds),
                "worker_id": claim.worker_id,
                "attempt_number": attempt_number,
                "report_files": report_files,
            },
        }

    def certify(claim: InternalClaim, match: Mapping[str, Any]) -> Mapping[str, Any]:
        if match.get("status") != "MATCHED" or not isinstance(match.get("reports"), list):
            raise ValueError("only two strict MATCHED internal reports can be certified")
        source_relative = f"decomp/src/eboot/func_{claim.numeric_address:08X}.c"
        source_hash = match.get("source_sha256")
        if not isinstance(source_hash, str) or not re_full_sha256(source_hash):
            raise ValueError("matched internal result has no valid source digest")
        main_source = _safe_worktree_path(repo_root, Path(source_relative))
        source_bytes: bytes | None = None
        if main_source.exists() or main_source.is_symlink():
            if main_source.is_symlink() or not main_source.is_file():
                raise ValueError("primary internal source path is unsafe")
            source_bytes = main_source.read_bytes()
            if hashlib.sha256(source_bytes).hexdigest() != source_hash:
                raise ValueError("refusing to overwrite a conflicting source in the primary checkout")
        if source_bytes is None:
            snapshot_relative = claim.checkpoint.get("latest_source_snapshot")
            snapshot_hash = claim.checkpoint.get("source_sha256")
            expected_snapshot = f"decomp-campaign/checkpoints/{claim.numeric_address:08x}/{source_hash}.c"
            if snapshot_relative == expected_snapshot and snapshot_hash == source_hash:
                snapshot = campaign_build_path(repo_root, expected_snapshot)
                if snapshot.is_symlink() or not snapshot.is_file():
                    raise ValueError("internal source checkpoint is missing or unsafe")
                source_bytes = snapshot.read_bytes()
            else:
                worker_root = campaign_runner.worktrees.get(claim.worker_id)
                if worker_root is None or worker_root.is_symlink() or not worker_root.is_dir():
                    raise ValueError("internal source is unavailable in primary and worker checkpoints")
                worker_source = _safe_worktree_path(worker_root, Path(source_relative))
                if worker_source.is_symlink() or not worker_source.is_file():
                    raise ValueError("matched internal source is missing or unsafe")
                source_bytes = worker_source.read_bytes()
            if hashlib.sha256(source_bytes).hexdigest() != source_hash:
                raise ValueError("internal source checkpoint digest differs from the MATCHED result")
            try:
                _atomic_create_file(main_source, source_bytes, label="internal source integration")
            except FileExistsError:
                if main_source.is_symlink() or not main_source.is_file() or hashlib.sha256(main_source.read_bytes()).hexdigest() != source_hash:
                    raise ValueError("primary internal source appeared with conflicting content")

        if hashlib.sha256(main_source.read_bytes()).hexdigest() != source_hash:
            raise ValueError("matched source changed before certificate integration")

        certificate_relative = Path("decomp/evidence/internal") / f"eboot-{claim.numeric_address:08x}.json"
        certificate_path = repo_root / certificate_relative
        existing_certificate_hash: str | None = None
        if certificate_path.exists() or certificate_path.is_symlink():
            if certificate_path.is_symlink() or not certificate_path.is_file():
                raise ValueError("refusing to reuse an unsafe existing internal certificate")
            try:
                existing_document = json.loads(certificate_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError("existing internal certificate is unreadable") from exc
            expected_builds = list(match.get("build_sha256", []))
            boundary = existing_document.get("boundary")
            if (
                existing_document.get("schema_version") != 1
                or existing_document.get("module") != claim.module
                or existing_document.get("address") != claim.address
                or existing_document.get("size_bytes") != claim.size_bytes
                or existing_document.get("section") != claim.section
                or existing_document.get("source_path") != source_relative
                or existing_document.get("source_sha256") != source_hash
                or existing_document.get("build_sha256") != expected_builds
                or not isinstance(boundary, dict)
                or boundary.get("status") != "EXACT"
                or boundary.get("module") != claim.module
                or boundary.get("address") != claim.address
                or boundary.get("size_bytes") != claim.size_bytes
                or boundary.get("section") != claim.section
            ):
                raise ValueError("existing internal certificate conflicts with the current source/build")
            existing_certificate_hash = hashlib.sha256(certificate_path.read_bytes()).hexdigest()
            recovery_entry = {
                "module": claim.module,
                "address": claim.address,
                "size_bytes": claim.size_bytes,
                "instruction_count": claim.size_bytes // 4,
                "boundary_status": "EXACT",
                "section": claim.section,
                "kind": claim.kind,
                "evidence_path": f"{certificate_relative.as_posix()}#recovery-audit",
                "source_path": source_relative,
                "source_sha256": source_hash,
                "result": {
                    "status": "MATCHED",
                    "matching_words": claim.size_bytes // 4,
                    "total_words": claim.size_bytes // 4,
                    "object_sha256s": expected_builds,
                    "certificate_path": certificate_relative.as_posix(),
                    "certificate_sha256": existing_certificate_hash,
                },
            }
            recovery_catalog = campaign_build_path(
                repo_root,
                f"seto049/internal-recovery/{claim.numeric_address:08x}-{uuid.uuid4().hex}.json",
            )
            recovery_catalog.parent.mkdir(parents=True, exist_ok=True)
            try:
                with recovery_catalog.open("x", encoding="utf-8", newline="\n") as stream:
                    json.dump({"schema_version": 2, "functions": [recovery_entry]}, stream, indent=2)
                    stream.write("\n")
                problems = validate_internal_catalog_evidence(
                    recovery_catalog,
                    repo_root=repo_root,
                    mode="full",
                    require_tracked_sources=False,
                    check_export_overlaps=(repo_root / "config/decomp_campaign_inventory.json").is_file(),
                )
                if problems:
                    raise ValueError("existing internal certificate failed full recovery audit")
            finally:
                recovery_catalog.unlink(missing_ok=True)

        promotion_journal = claim.checkpoint.get("promotion_recovery")
        if not isinstance(promotion_journal, dict):
            raise ValueError("internal promotion is missing its durable report journal")
        if (
            promotion_journal.get("source_sha256") != source_hash
            or promotion_journal.get("build_sha256") != list(match.get("build_sha256", []))
        ):
            raise ValueError("internal promotion journal differs from the strict MATCHED result")
        if existing_certificate_hash is not None:
            certificate_hash = existing_certificate_hash
        else:
            reports: list[Path] = []
            journal_reports = promotion_journal.get("report_files")
            if not isinstance(journal_reports, list) or len(journal_reports) != 2:
                raise ValueError("internal promotion journal has incomplete matcher report references")
            for report_file in journal_reports:
                if not isinstance(report_file, dict):
                    raise ValueError("internal promotion journal report metadata is invalid")
                relative = report_file.get("path")
                digest = report_file.get("sha256")
                if not isinstance(relative, str) or not isinstance(digest, str):
                    raise ValueError("internal promotion journal report path/hash is incomplete")
                if not relative.startswith("build/"):
                    raise ValueError("internal promotion journal report path is not build-relative")
                audit_report = campaign_build_path(repo_root, relative.removeprefix("build/"))
                if (
                    audit_report.is_symlink()
                    or not audit_report.is_file()
                    or hashlib.sha256(audit_report.read_bytes()).hexdigest() != digest
                ):
                    raise ValueError("journaled full matcher report is missing or changed")
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
            certificate_hash = write_internal_certificate(
                certificate_relative, certificate, repo_root=repo_root
            )

        builds = list(match.get("build_sha256", []))
        entry = catalog_entry_for(claim, source_hash, builds, certificate_hash)
        entry["result"]["resolved_calls"] = list(
            match["reports"][0]["match"].get("resolved_calls", [])
        )
        entry["result"]["data_reference_count"] = len(
            match["reports"][0]["match"].get("resolved_data", [])
        )
        persist_catalog_entry(entry)
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
        journal_promotion=journal_promotion,
        recover_promotion=recover_catalog_promotion,
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


def _promotion_journal_id(
    claim: InternalClaim, source_sha256: str, attempt_number: int
) -> str:
    identity = f"{claim.module.casefold()}:{claim.numeric_address:x}:{attempt_number}:{source_sha256}"
    return hashlib.sha256(identity.encode("ascii")).hexdigest()[:32]
