#!/usr/bin/env python3
"""Local, resumable OpenCode orchestration for strictly verified EBOOT work.

The scheduler stores only candidate metadata and local checkpoints in SQLite.
It never writes AIMemory pages, changes the production matcher, or treats an
agent's claim of MATCHED as evidence.  Certification is performed by two fresh
invocations of scripts/match_function.py against the private EBOOT.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import email.utils
import fnmatch
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import tomllib
import uuid
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Collection, Iterable, Mapping, Sequence
from urllib.parse import urlsplit


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = REPO_ROOT / "config" / "decomp_campaign.toml"
SECRET_ENV_PARTS = ("API_KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH")
TOKEN_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
)
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
CHATGPT_OAUTH_METHODS = frozenset(
    {"chatgpt-token-sharing", "chatgpt-browser", "chatgpt-headless"}
)
OPENAI_PROVIDER_PACKAGE = "@opencode/ai/providers/openai"
OPENAI_DEFAULT_BASE_URL = "https://api.openai.com/v1"
AI_MEMORY_SERVER = "ai-memory"
AI_MEMORY_READ_TOOLS = frozenset({"memory_query", "memory_read_page"})
AI_MEMORY_READ_ACTIONS = frozenset(
    f"{AI_MEMORY_SERVER}_{tool}" for tool in AI_MEMORY_READ_TOOLS
)
DIAGNOSTIC_CODES = {
    "ghidra_evidence_invalid": "ghidra",
    "context_unavailable": "context",
    "checkpoint_invalid": "worker_return",
    "candidate_source_missing": "worker_return",
    "source_unchanged": "worker_return",
    "matcher_incomplete": "matcher",
    "compiler_failed": "compiler",
    "protected_input_changed": "integrity",
    "internal_error": "internal",
}
HISTORICAL_HYPOTHESES: dict[str, dict[str, Any]] = {
    "0x2c28c": {
        "source_path": "seto038/func_0002C28C-hypothesis-v1.c",
        "sha256": "1deb1fc3490cb64505db44bd02eb3b5c2493c820bea78f48ab52b6a99f645000",
        "function": "func_0002C28C",
        "matching_words": 26,
        "total_words": 28,
        "first_divergence": {
            "address": "0x2C2C4",
            "candidate": "bnel with lhu in the delay slot",
            "original": "bne followed by nop",
        },
    }
}


class FailureKind(StrEnum):
    QUOTA_EXHAUSTED = "quota_exhausted"
    RATE_LIMIT = "rate_limit"
    AUTH = "auth"
    NETWORK = "network"
    TIMEOUT = "timeout"
    AGENT_ERROR = "agent_error"
    INTERRUPTED = "interrupted"


@dataclass(frozen=True)
class Failure:
    kind: FailureKind
    retry_after_seconds: float | None = None
    diagnostic_stage: str | None = None
    diagnostic_code: str | None = None


@dataclass(frozen=True)
class Candidate:
    address: str
    size_bytes: int
    nid: str
    priority: int
    boundary_status: str
    preferred_provider: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    initial_state: str | None = None

    def __post_init__(self) -> None:
        try:
            address = int(self.address, 0)
            nid = int(self.nid, 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("candidate address and NID must be hexadecimal integers") from exc
        if address < 0 or nid < 0 or nid > 0xFFFFFFFF:
            raise ValueError("candidate address/NID is outside its valid range")
        if self.boundary_status not in {"EXACT", "UNVERIFIED"}:
            raise ValueError("boundary_status must be EXACT or UNVERIFIED")
        if self.boundary_status == "EXACT" and (
            self.size_bytes <= 0 or self.size_bytes % 4
        ):
            raise ValueError("EXACT candidate size must be a positive multiple of four bytes")
        if self.boundary_status == "UNVERIFIED" and (
            self.size_bytes < 0 or self.size_bytes % 4
        ):
            raise ValueError("UNVERIFIED candidate size must be zero or a multiple of four bytes")

    @property
    def numeric_address(self) -> int:
        return int(self.address, 0)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Candidate:
        return cls(
            address=str(value["address"]),
            size_bytes=int(value["size_bytes"]),
            nid=str(value["nid"]),
            priority=int(value.get("priority", 0)),
            boundary_status=str(value.get("boundary_status", "UNVERIFIED")),
            preferred_provider=value.get("preferred_provider"),
            evidence=dict(value.get("evidence", {})),
            initial_state=value.get("initial_state"),
        )


@dataclass(frozen=True)
class Worker:
    worker_id: str
    provider: str
    model: str
    agent: str = "seto-decomp-worker"


@dataclass(frozen=True)
class Claim:
    address: str
    size_bytes: int
    nid: str
    priority: int
    boundary_status: str
    worker_id: str
    provider: str
    session_id: str | None
    attempt_number: int
    lease_until: float
    checkpoint: dict[str, Any]
    evidence: dict[str, Any]

    @property
    def numeric_address(self) -> int:
        return int(self.address, 0)


@dataclass(frozen=True)
class WorkResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    interrupted: bool = False


class CampaignInterrupted(Exception):
    """Internal signal used to release a task after an operator stop request."""


class MatcherIncomplete(ValueError):
    """Matcher output did not cover the complete required function interval."""

    def __init__(self, message: str, *, excerpt: str = "") -> None:
        super().__init__(message)
        self.excerpt = _safe_diagnostic_excerpt(excerpt) if excerpt else ""


class MatcherCompilerError(ValueError):
    """MWCC did not produce a usable candidate object for the requested function."""

    def __init__(self, message: str, *, excerpt: str = "") -> None:
        super().__init__(message)
        self.excerpt = _safe_diagnostic_excerpt(excerpt) if excerpt else ""


def _normalize_eboot_address(value: str, *, label: str = "EBOOT address") -> str:
    if not isinstance(value, str) or not re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        raise ValueError(f"{label} must be a hexadecimal address")
    numeric = int(value, 16)
    if not 0 <= numeric <= 0xFFFFFFFF:
        raise ValueError(f"{label} is outside the 32-bit EBOOT address space")
    return f"0x{numeric:x}"


def validate_model_id(model: str, allowed_models: Iterable[str]) -> str:
    """Require an exact, configured model identifier; aliases are not accepted."""
    allowed = set(allowed_models)
    if model not in allowed:
        raise ValueError(f"model {model!r} is not explicitly allowlisted")
    if "#" in model or any(ch.isspace() for ch in model):
        raise ValueError("model variants and whitespace are not permitted")
    return model


def _retry_after(text: str) -> float | None:
    match = re.search(
        r"(?i)retry[- ]after\s*[:=]\s*([0-9]+(?:\.[0-9]+)?)\s*(s|sec(?:onds?)?)?",
        text,
    )
    if match:
        return float(match.group(1))
    match = re.search(r"(?i)retry after\s+([0-9]+(?:\.[0-9]+)?)\s*(s|sec(?:onds?)?)?", text)
    if match:
        return float(match.group(1))
    match = re.search(r"(?i)retry[- ]after\s*:\s*(.+?)(?:\r?\n|$)", text)
    if match:
        try:
            when = email.utils.parsedate_to_datetime(match.group(1))
            if when.tzinfo is None:
                when = when.replace(tzinfo=dt.timezone.utc)
            return max(0.0, (when - dt.datetime.now(dt.timezone.utc)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return None
    return None


def classify_failure(
    returncode: int | None,
    stdout: str,
    stderr: str,
    *,
    timed_out: bool = False,
) -> Failure:
    """Classify explicit provider signals without treating unknown errors as quota."""
    if timed_out:
        return Failure(FailureKind.TIMEOUT)
    text = f"{stdout}\n{stderr}".lower()
    if re.search(
        r"insufficient[_ -]quota|quota[_ -]exhausted|quota exceeded|"
        r"usage limit (?:has been )?reached|credits? (?:are )?exhausted|"
        r"billing hard limit|monthly limit reached|daily quota exhausted",
        text,
    ):
        return Failure(FailureKind.QUOTA_EXHAUSTED)
    if re.search(r"rate limit|too many requests|http\s*429|status\s*429", text):
        return Failure(FailureKind.RATE_LIMIT, _retry_after(f"{stdout}\n{stderr}"))
    if re.search(
        r"unauthorized|invalid api key|authentication failed|http\s*401|http\s*403|"
        r"status(?: code)?\s*[:=]?\s*401|status(?: code)?\s*[:=]?\s*403|forbidden",
        text,
    ):
        return Failure(FailureKind.AUTH)
    if re.search(r"request timed? out|operation timed? out|deadline exceeded", text):
        return Failure(FailureKind.TIMEOUT)
    if re.search(
        r"connection (?:reset|refused|aborted)|name or service not known|"
        r"temporary failure in name resolution|network is unreachable|"
        r"service unavailable|http\s*50[0234]|status\s*50[0234]|tls handshake",
        text,
    ):
        return Failure(FailureKind.NETWORK)
    if returncode is None or returncode != 0:
        return Failure(FailureKind.AGENT_ERROR)
    return Failure(FailureKind.AGENT_ERROR)


def _safe_text(value: Any, limit: int = 4000) -> str:
    text = str(value)
    for pattern in TOKEN_PATTERNS:
        text = pattern.sub(lambda m: (m.group(1) if m.lastindex else "") + "[REDACTED]", text)
    return text[:limit]


def _safe_diagnostic_excerpt(value: Any, *, limit: int = 600) -> str:
    """Keep only a short compiler/matcher diagnostic, stripping paths and secrets."""
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", str(value))
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    relevant = [
        line
        for line in lines
        if not re.search(r"(?i)MWCIncludes.{0,40}not found|usage warning", line)
        if re.search(
            r"(?i)error|failed|undefined|not found|not present|needs? \d+|"
            r"too (?:small|short)|symbol|candidate section|expected",
            line,
        )
    ]
    if not relevant:
        relevant = lines[:1]
    sanitized = []
    for line in relevant[:4]:
        line = re.sub(
            r"(?i)(?:\b[a-z]:[\\/][^\s:]+|\\\\[^\\\s]+\\[^\s]+|"
            r"/mnt/[a-z]/[^\s]+|/home/[^\s]+|/tmp/[^\s]+|/var/tmp/[^\s]+)",
            "[PATH]",
            line,
        )
        sanitized.append(_safe_text(line, 240))
    return " | ".join(sanitized)[:limit]


def _sanitize_match_checkpoint(value: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    text_fields = {
        "status",
        "source_sha256",
        "object_sha256",
        "report_path",
        "producer_worker_id",
        "producer_provider",
        "producer_session_id",
        "origin_kind",
        "worker_id",
        "source_path",
        "first_divergence_address",
        "first_divergence_candidate",
        "first_divergence_original",
        "first_divergence_reason",
        "recovery_reason",
    }
    integer_fields = {
        "matching_words",
        "total_words",
        "difference_count",
        "producer_attempt_number",
        "first_divergence_word_index",
    }
    for key, item in value.items():
        if key in text_fields and isinstance(item, str):
            if key in {"source_sha256", "object_sha256"} and item and not HEX_SHA256.fullmatch(item):
                continue
            if key in {"report_path", "source_path"}:
                normalized = item.replace("\\", "/")
                if not normalized.startswith("build/decomp-campaign/") or ".." in Path(normalized).parts:
                    continue
            if key == "worker_id" and not re.fullmatch(r"[a-z0-9-]+", item):
                continue
            summary[key] = _safe_text(item, 500)
        elif key in integer_fields and isinstance(item, int) and not isinstance(item, bool):
            summary[key] = item
        elif key == "difference_indices" and isinstance(item, list):
            summary[key] = [
                item_value
                for item_value in item[:100]
                if isinstance(item_value, int) and not isinstance(item_value, bool)
            ]
        elif key == "object_sha256s" and isinstance(item, list):
            summary[key] = [
                item_value
                for item_value in item[:2]
                if isinstance(item_value, str) and HEX_SHA256.fullmatch(item_value)
            ]
        elif key in {"report_paths", "limitations"} and isinstance(item, list):
            values = []
            for item_value in item[:10]:
                if not isinstance(item_value, str):
                    continue
                normalized = item_value.replace("\\", "/")
                if key == "report_paths" and (
                    not normalized.startswith("build/decomp-campaign/")
                    or ".." in Path(normalized).parts
                ):
                    continue
                values.append(_safe_text(item_value, 500 if key == "report_paths" else 1000))
            summary[key] = values
    return summary


def _match_checkpoint_summary(
    result: dict[str, Any], *, fallback_report_path: str | None = None
) -> dict[str, Any]:
    reports = result.get("reports")
    reports = reports if isinstance(reports, list) else []
    first_report = next((item for item in reports if isinstance(item, dict)), {})
    match = first_report.get("match")
    match = match if isinstance(match, dict) else {}
    differences = match.get("differences")
    differences = differences if isinstance(differences, list) else []
    indices = [
        item.get("word_index", item.get("index"))
        for item in differences
        if isinstance(item, dict)
        and isinstance(item.get("word_index", item.get("index")), int)
        and not isinstance(item.get("word_index", item.get("index")), bool)
    ][:100]
    difference = differences[0] if differences and isinstance(differences[0], dict) else {}
    difference_address = difference.get("address")
    if isinstance(difference_address, int) and not isinstance(difference_address, bool):
        difference_address = f"0x{difference_address:x}"
    origin = result.get("campaign_origin")
    origin = origin if isinstance(origin, dict) else {}
    builds = result.get("build_sha256")
    builds = builds if isinstance(builds, list) else []
    report_paths = [
        item["report_path"]
        for item in reports
        if isinstance(item, dict) and isinstance(item.get("report_path"), str)
    ][:2]
    if not report_paths:
        if fallback_report_path:
            report_paths = [fallback_report_path]
        else:
            try:
                origin_worker = str(origin["worker_id"])
                origin_attempt = int(origin["attempt_number"])
                origin_address = int(str(first_report.get("address", result.get("address"))), 0)
            except (KeyError, TypeError, ValueError):
                origin_worker = ""
                origin_attempt = 0
                origin_address = -1
            if re.fullmatch(r"[a-z0-9-]+", origin_worker) and origin_attempt > 0 and origin_address >= 0:
                report_paths = [
                    f"build/decomp-campaign/{origin_worker}/{origin_address:x}/"
                    f"attempt-{origin_attempt}/verify-{verify}/func_{origin_address:08X}.match.json"
                    for verify in (1, 2)
                ]
    summary: dict[str, Any] = {
        "status": result.get("status", first_report.get("status", "NONMATCHING")),
        "matching_words": result.get("matching_words", match.get("matching_words", -1)),
        "total_words": result.get("total_words", match.get("total_words", -1)),
        "difference_count": match.get(
            "difference_count", len(differences) if isinstance(differences, list) else 0
        ),
        "difference_indices": indices,
        "source_sha256": result.get("source_sha256", ""),
        "object_sha256": builds[0] if builds else first_report.get("provenance", {}).get("object_sha256", ""),
        "object_sha256s": builds,
        "report_path": report_paths[0] if report_paths else fallback_report_path or "",
        "report_paths": report_paths,
        "producer_worker_id": origin.get("worker_id", ""),
        "producer_provider": origin.get("provider", ""),
        "producer_session_id": origin.get("session_id", ""),
        "producer_attempt_number": origin.get("attempt_number", -1),
        "limitations": match.get("limitations", []),
    }
    if difference:
        summary.update(
            {
                "first_divergence_address": difference_address,
                "first_divergence_word_index": difference.get(
                    "word_index", difference.get("index", -1)
                ),
                "first_divergence_candidate": difference.get("candidate", ""),
                "first_divergence_original": difference.get("original", ""),
                "first_divergence_reason": difference.get("reason", ""),
            }
        )
    return _sanitize_match_checkpoint(summary)


def _matcher_failure_is_incomplete(exc: Exception) -> bool:
    """Recognize bounded-output failures without retaining the exception text."""
    if isinstance(exc, MatcherIncomplete):
        return True
    return bool(
        re.search(
            r"(?is)(?:\.text|object|candidate).{0,100}"
            r"(?:\b\d+\s+bytes?\b|too small|too short|incomplete|truncated)|"
            r"(?:too few|incomplete|truncated).{0,80}(?:bytes?|object|text)",
            str(exc),
        )
    )


def _sanitize_checkpoint(
    checkpoint: dict[str, Any], *, trusted_evidence: bool = False
) -> dict[str, Any]:
    """Persist bounded checkpoint metadata, separating agent claims from evidence."""
    allowed = {"next_experiment", "limitations"}
    if trusted_evidence:
        allowed |= {
            "source_path",
            "source_sha256",
            "best_source_sha256",
            "best_source_snapshot",
            "latest_source_snapshot",
            "ghidra_log_path",
            "ghidra_log_sha256",
            "boundary_status",
            "best_match",
            "last_attempt",
            "local_experiments",
            "local_recoveries",
            "evidence_paths",
            "historical_hypothesis",
            "last_diagnostic",
            "last_diagnostic_detail",
            "recovery_reason",
        }
    result: dict[str, Any] = {}
    for key in allowed:
        if key not in checkpoint:
            continue
        value = checkpoint[key]
        if key in {"source_path", "ghidra_log_path", "boundary_status", "next_experiment"}:
            result[key] = _safe_text(value, 4000)
        elif key in {
            "source_sha256",
            "best_source_sha256",
            "ghidra_log_sha256",
        }:
            if HEX_SHA256.fullmatch(str(value)):
                result[key] = str(value)
        elif key in {"best_source_snapshot", "latest_source_snapshot"}:
            if isinstance(value, str) and re.fullmatch(
                r"decomp-campaign/checkpoints/[0-9a-f]{8}/[0-9a-f]{64}\.c",
                value.replace("\\", "/"),
            ):
                result[key] = value
        elif key == "limitations" and isinstance(value, list):
            result[key] = [_safe_text(item, 1000) for item in value[:40]]
        elif key == "evidence_paths" and isinstance(value, list):
            result[key] = [_safe_text(item, 500) for item in value[:40]]
        elif key in {"best_match", "last_attempt"} and isinstance(value, dict):
            result[key] = _sanitize_match_checkpoint(value)
        elif key == "last_diagnostic_detail" and isinstance(value, dict):
            code = value.get("code")
            stage = value.get("stage")
            excerpt = value.get("excerpt")
            if (
                isinstance(code, str)
                and DIAGNOSTIC_CODES.get(code) == stage
                and isinstance(excerpt, str)
            ):
                result[key] = {
                    "stage": stage,
                    "code": code,
                    "excerpt": _safe_diagnostic_excerpt(excerpt),
                }
        elif key == "recovery_reason":
            result[key] = _safe_text(value, 600)
        elif key == "local_experiments" and isinstance(value, list):
            experiments = []
            for item in value[:8]:
                if not isinstance(item, dict) or item.get("origin_kind") != "local_experiment":
                    continue
                summary = _sanitize_match_checkpoint(item)
                if (
                    summary.get("status") == "MATCHED"
                    and summary.get("worker_id")
                    and summary.get("source_path")
                    and summary.get("source_sha256")
                    and len(summary.get("report_paths", [])) == 2
                    and len(summary.get("object_sha256s", [])) == 2
                ):
                    experiments.append(summary)
            result[key] = experiments
        elif key == "local_recoveries" and isinstance(value, list):
            recoveries = []
            for item in value[-16:]:
                if not isinstance(item, dict) or item.get("origin_kind") != "local_recovery":
                    continue
                summary = _sanitize_match_checkpoint(item)
                if (
                    summary.get("status") in {"NONMATCHING", "INCONCLUSIVE"}
                    and summary.get("source_sha256")
                    and summary.get("source_path")
                    and summary.get("report_path")
                ):
                    recoveries.append(summary)
            result[key] = recoveries
        elif key == "historical_hypothesis" and isinstance(value, dict):
            status = value.get("status")
            if status == "available":
                path = value.get("path")
                digest = value.get("sha256")
                first_divergence = value.get("first_divergence")
                if (
                    isinstance(path, str)
                    and path.replace("\\", "/").startswith("build/decomp-campaign/")
                    and ".." not in Path(path.replace("\\", "/")).parts
                    and isinstance(digest, str)
                    and HEX_SHA256.fullmatch(digest)
                    and isinstance(first_divergence, dict)
                ):
                    matching_words = value.get("matching_words")
                    total_words = value.get("total_words")
                    if (
                        isinstance(matching_words, bool)
                        or not isinstance(matching_words, int)
                        or isinstance(total_words, bool)
                        or not isinstance(total_words, int)
                        or not 0 <= matching_words <= total_words <= 512
                    ):
                        continue
                    result[key] = {
                        "status": "available",
                        "path": path.replace("\\", "/"),
                        "sha256": digest,
                        "classification": "NONMATCHING / not certified",
                        "matching_words": matching_words,
                        "total_words": total_words,
                        "first_divergence": {
                            field: _safe_text(first_divergence[field], 200)
                            for field in ("address", "candidate", "original")
                            if isinstance(first_divergence.get(field), str)
                        },
                    }
            elif status == "unavailable" and value.get("reason") in {
                "missing",
                "hash_mismatch",
                "identity_mismatch",
                "unsafe_path",
                "destination_conflict",
                "copy_failed",
            }:
                result[key] = {"status": "unavailable", "reason": value["reason"]}
        elif key == "last_diagnostic" and isinstance(value, dict):
            stage = value.get("stage")
            code = value.get("code")
            if (
                isinstance(stage, str)
                and isinstance(code, str)
                and code in DIAGNOSTIC_CODES
                and DIAGNOSTIC_CODES[code] == stage
            ):
                result[key] = {"stage": stage, "code": code}
    return result


def _json_dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def is_strict_match(
    report: dict[str, Any], *, expected_address: int, expected_size: int
) -> bool:
    """Validate one production matcher report; a model assertion is insufficient."""
    try:
        match = report["match"]
        provenance = report["provenance"]
        if not isinstance(match, dict) or not isinstance(provenance, dict):
            return False
        expected_words = expected_size // 4
        return bool(
            report.get("status") == "MATCHED"
            and report.get("verified_decompilation") is True
            and report.get("evidence") == "compiled-object"
            and int(str(report.get("address")), 0) == expected_address
            and report.get("symbol") == f"func_{expected_address:08X}"
            and HEX_SHA256.fullmatch(str(provenance.get("source_sha256", "")))
            and HEX_SHA256.fullmatch(str(provenance.get("object_sha256", "")))
            and Path(str(provenance.get("compiler", ""))).name.lower() == "mwccpsp.exe"
            and list(provenance.get("flags", [])) == ["-O4,p", "-sdatathreshold", "0"]
            and match.get("status") == "MATCHED"
            and int(match.get("matching_words", -1)) == expected_words
            and int(match.get("total_words", -1)) == expected_words
            and int(match.get("difference_count", -1)) == 0
            and match.get("differences") == []
            and match.get("limitations") == []
            and match.get("relocation_issues") == []
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def is_deterministic_match(
    result: dict[str, Any], *, expected_address: int, expected_size: int
) -> bool:
    """Require two full matcher reports and identical independent object hashes."""
    reports = result.get("reports")
    builds = result.get("build_sha256")
    if not isinstance(reports, list) or len(reports) != 2:
        return False
    if not isinstance(builds, list) or len(builds) != 2 or builds[0] != builds[1]:
        return False
    if not all(HEX_SHA256.fullmatch(str(value)) for value in builds):
        return False
    if not all(
        is_strict_match(report, expected_address=expected_address, expected_size=expected_size)
        for report in reports
        if isinstance(report, dict)
    ):
        return False
    if any(not isinstance(report, dict) for report in reports):
        return False
    source_hashes = {report.get("provenance", {}).get("source_sha256") for report in reports}
    object_hashes = [report.get("provenance", {}).get("object_sha256") for report in reports]
    return (
        len(source_hashes) == 1
        and object_hashes == builds
        and result.get("status") == "MATCHED"
        and result.get("source_sha256") in source_hashes
    )


def campaign_build_path(repo_root: Path, relative: str | Path) -> Path:
    """Return a build path while rejecting traversal and symlinks at every level."""
    root = repo_root / "build"
    if root.is_symlink():
        raise ValueError(f"build root is a symlink: {root}")
    rel = Path(relative)
    if rel.is_absolute() or any(part in {"..", ""} for part in rel.parts):
        raise ValueError("build path escapes the allowed build tree")
    target = root / rel
    cursor = root
    for part in rel.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError(f"symlink is not allowed in campaign build path: {cursor}")
    resolved_root = root.resolve(strict=False)
    resolved_target = target.resolve(strict=False)
    try:
        resolved_target.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError("build path escapes the allowed build tree") from exc
    return target


def validated_cached_ghidra_boundary(
    worktree: Path, claim: Claim
) -> dict[str, Any] | None:
    """Reuse only a hash-checked exact Ghidra log bound to this worker and address."""
    log_relative = claim.checkpoint.get("ghidra_log_path")
    log_digest = claim.checkpoint.get("ghidra_log_sha256")
    if log_relative is None and log_digest is None:
        return None
    if (
        claim.boundary_status != "EXACT"
        or not isinstance(log_relative, str)
        or not isinstance(log_digest, str)
        or not HEX_SHA256.fullmatch(log_digest)
    ):
        raise ValueError("cached Ghidra checkpoint is incomplete or not bound to an exact boundary")
    address = claim.address.removeprefix("0x").lower()
    expected_root = f"decomp-campaign/{claim.worker_id}/{address}/evidence/"
    normalized = log_relative.replace("\\", "/")
    filename = normalized.removeprefix(expected_root)
    if not normalized.startswith(expected_root) or not re.fullmatch(
        r"ghidra-(?:attempt-[1-9][0-9]*|run-[0-9a-f]{32}|cache-[0-9a-f]{64})\.log",
        filename,
    ):
        raise ValueError("cached Ghidra checkpoint path is outside this worker/address evidence")
    log_path = campaign_build_path(worktree, normalized)
    if log_path.is_symlink() or not log_path.is_file() or log_path.stat().st_size > 2_000_000:
        raise ValueError("cached Ghidra evidence is missing, unsafe, or too large")
    content = log_path.read_bytes()
    if hashlib.sha256(content).hexdigest() != log_digest:
        raise ValueError("cached Ghidra evidence hash does not match its checkpoint")
    boundary = validate_ghidra_log(content.decode("utf-8", errors="replace"), claim.numeric_address)
    if boundary["size_bytes"] != claim.size_bytes:
        raise ValueError("cached Ghidra boundary conflicts with the exact candidate size")
    return boundary


def _ghidra_log_has_reconstruction_details(text: str) -> bool:
    """Require disassembly and decompiler output before reusing Ghidra evidence."""
    raw_instruction_markers = re.findall(r"(?m)^[ \t]*SETO_INSN=", text)
    detailed_instruction_rows = re.findall(
        r"(?m)^[ \t]*SETO_INSN=0x[0-9a-fA-F]+[ \t]+SIZE=\d+[ \t]+\S[^\r\n]*\r?$",
        text,
    )
    begin_markers = list(re.finditer(r"(?m)^\s*SETO_DECOMP_C_BEGIN\s*$", text))
    end_markers = list(re.finditer(r"(?m)^\s*SETO_DECOMP_C_END\s*$", text))
    return (
        bool(raw_instruction_markers)
        and len(raw_instruction_markers) == len(detailed_instruction_rows)
        and len(begin_markers) == 1
        and len(end_markers) == 1
        and begin_markers[0].end() < end_markers[0].start()
        and bool(text[begin_markers[0].end() : end_markers[0].start()].strip())
    )


class CampaignStore:
    """Small SQLite queue with atomic claims, leases, checkpoints, and event history."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS candidates (
                    address TEXT PRIMARY KEY,
                    size_bytes INTEGER NOT NULL,
                    nid TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    boundary_status TEXT NOT NULL,
                    status TEXT NOT NULL,
                    owner TEXT,
                    provider TEXT,
                    last_provider TEXT,
                    session_id TEXT,
                    lease_until REAL,
                    available_at REAL NOT NULL DEFAULT 0,
                    preferred_provider TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    attempts_without_progress INTEGER NOT NULL DEFAULT 0,
                    checkpoint_json TEXT NOT NULL DEFAULT '{}',
                    best_result_json TEXT NOT NULL DEFAULT '{}',
                    evidence_json TEXT NOT NULL DEFAULT '{}',
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS providers (
                    provider TEXT PRIMARY KEY,
                    status TEXT NOT NULL DEFAULT 'active',
                    resume_at REAL,
                    reason TEXT,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT NOT NULL REFERENCES candidates(address),
                    attempt_number INTEGER NOT NULL,
                    worker_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    ended_at REAL,
                    outcome TEXT NOT NULL DEFAULT 'running',
                    failure_kind TEXT,
                    retry_after REAL,
                    UNIQUE(address, attempt_number)
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at REAL NOT NULL,
                    kind TEXT NOT NULL,
                    address TEXT,
                    worker_id TEXT,
                    provider TEXT,
                    session_id TEXT
                );
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                INSERT OR IGNORE INTO metadata(key, value) VALUES ('stop_requested', '0');
                """
            )

    def seed(
        self,
        candidates: Iterable[Candidate],
        *,
        excluded_addresses: Collection[str] = (),
    ) -> int:
        excluded: set[str] = set()
        for value in excluded_addresses:
            excluded.add(
                _normalize_eboot_address(value, label="excluded certified address")
            )
        inserted = 0
        now = time.time()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for candidate in candidates:
                if f"0x{candidate.numeric_address:x}" in excluded:
                    continue
                state = candidate.initial_state or (
                    "pending" if candidate.boundary_status == "EXACT" else "needs_boundary"
                )
                db.execute(
                    """INSERT OR IGNORE INTO candidates
                    (address,size_bytes,nid,priority,boundary_status,status,preferred_provider,
                     evidence_json,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        candidate.address.lower(),
                        candidate.size_bytes,
                        candidate.nid.upper(),
                        candidate.priority,
                        candidate.boundary_status,
                        state,
                        candidate.preferred_provider,
                        _json_dump(candidate.evidence),
                        now,
                    ),
                )
                inserted += db.execute("SELECT changes()").fetchone()[0]
                if candidate.boundary_status == "UNVERIFIED":
                    db.execute(
                        """UPDATE candidates SET size_bytes=0,evidence_json=?,updated_at=?
                           WHERE address=? AND boundary_status='UNVERIFIED'
                             AND status='needs_boundary' AND attempt_count=0 AND owner IS NULL""",
                        (_json_dump(candidate.evidence), now, candidate.address.lower()),
                    )
            db.commit()
        return inserted

    def _event(
        self,
        db: sqlite3.Connection,
        kind: str,
        *,
        address: str | None = None,
        worker_id: str | None = None,
        provider: str | None = None,
        session_id: str | None = None,
    ) -> None:
        db.execute(
            "INSERT INTO events(created_at,kind,address,worker_id,provider,session_id) "
            "VALUES (?,?,?,?,?,?)",
            (time.time(), kind, address, worker_id, provider, session_id),
        )

    def record_event(
        self,
        kind: str,
        *,
        address: str | None = None,
        worker_id: str | None = None,
        provider: str | None = None,
        session_id: str | None = None,
    ) -> None:
        if not re.fullmatch(r"[a-z0-9_]{1,48}", kind):
            raise ValueError("campaign event kind is invalid")
        with self._connect() as db:
            self._event(
                db,
                kind,
                address=address,
                worker_id=worker_id,
                provider=provider,
                session_id=session_id,
            )

    def claim_next(
        self,
        worker_id: str,
        provider: str,
        *,
        lease_seconds: float = 1800,
        max_attempts_per_candidate: int = 8,
        max_total_attempts: int | None = None,
        eligible_addresses: Sequence[str] | None = None,
        excluded_addresses: Collection[str] = (),
        reserve_only: bool = False,
        now: float | None = None,
    ) -> Claim | None:
        now = time.time() if now is None else now
        normalized_excluded = sorted(
            {
                _normalize_eboot_address(value, label="excluded certified address")
                for value in excluded_addresses
            }
        )
        excluded_clause = (
            " AND address NOT IN (" + ",".join("?" for _ in normalized_excluded) + ")"
            if normalized_excluded
            else ""
        )
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if max_total_attempts is not None:
                total_attempts = int(db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0])
                if total_attempts >= max_total_attempts:
                    db.commit()
                    return None
            db.execute(
                "INSERT OR IGNORE INTO providers(provider,status,updated_at) VALUES (?,'active',?)",
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
                    "UPDATE providers SET status='active',resume_at=NULL,reason=NULL,updated_at=? WHERE provider=?",
                    (now, provider),
                )
            db.execute(
                """UPDATE candidates SET status='stalled',updated_at=?
                   WHERE status='pending' AND boundary_status='EXACT' AND attempt_count>=?"""
                + excluded_clause,
                (now, max_attempts_per_candidate, *normalized_excluded),
            )
            address_clause = ""
            parameters: list[Any] = [now, max_attempts_per_candidate, provider]
            if eligible_addresses is not None:
                normalized_addresses = sorted({item.lower() for item in eligible_addresses})
                if not normalized_addresses:
                    db.commit()
                    return None
                address_clause = " AND address IN (" + ",".join("?" for _ in normalized_addresses) + ")"
                parameters.extend(normalized_addresses)
            address_clause += excluded_clause
            parameters.extend(normalized_excluded)
            row = db.execute(
                """SELECT * FROM candidates
                WHERE status='pending' AND boundary_status='EXACT' AND available_at<=?
                  AND attempt_count<?
                  AND (preferred_provider IS NULL OR preferred_provider=?)"""
                + address_clause
                + " ORDER BY CASE WHEN attempt_count=0 THEN 0 ELSE 1 END, "
                "attempt_count ASC,priority DESC,address ASC LIMIT 1",
                parameters,
            ).fetchone()
            if row is None:
                db.commit()
                return None
            session_id = (
                row["session_id"]
                if reserve_only or row["last_provider"] == provider
                else None
            )
            attempt_number = int(row["attempt_count"]) + (0 if reserve_only else 1)
            lease_until = now + max(1.0, lease_seconds)
            db.execute(
                """UPDATE candidates SET status=?,owner=?,provider=?,
                    last_provider=CASE WHEN ? THEN last_provider ELSE ? END,
                    session_id=?,lease_until=?,
                    attempt_count=?,updated_at=? WHERE address=?""",
                (
                    "preparing" if reserve_only else "running",
                    worker_id,
                    provider,
                    int(reserve_only),
                    provider,
                    session_id,
                    lease_until,
                    attempt_number,
                    now,
                    row["address"],
                ),
            )
            if not reserve_only:
                attempt_session_id = session_id or "pending_" + uuid.uuid4().hex
                db.execute(
                    """INSERT INTO attempts(address,attempt_number,worker_id,provider,session_id,started_at)
                       VALUES (?,?,?,?,?,?)""",
                    (row["address"], attempt_number, worker_id, provider, attempt_session_id, now),
                )
            self._event(
                db,
                "preparation_reserved" if reserve_only else "claimed",
                address=row["address"],
                worker_id=worker_id,
                provider=provider,
                session_id=session_id,
            )
            checkpoint = json.loads(row["checkpoint_json"])
            best_result = json.loads(row["best_result_json"])
            if isinstance(best_result, dict) and best_result:
                saved_best = checkpoint.get("best_match")
                builds = best_result.get("build_sha256")
                fallback_path = None
                if (
                    isinstance(saved_best, dict)
                    and saved_best.get("source_sha256") == best_result.get("source_sha256")
                    and isinstance(builds, list)
                    and builds
                    and saved_best.get("object_sha256") == builds[0]
                    and isinstance(saved_best.get("report_path"), str)
                ):
                    fallback_path = saved_best["report_path"]
                checkpoint["best_match"] = _match_checkpoint_summary(
                    best_result, fallback_report_path=fallback_path
                )
            claim = Claim(
                address=row["address"],
                size_bytes=int(row["size_bytes"]),
                nid=row["nid"],
                priority=int(row["priority"]),
                boundary_status=row["boundary_status"],
                worker_id=worker_id,
                provider=provider,
                session_id=session_id,
                attempt_number=attempt_number,
                lease_until=lease_until,
                checkpoint=checkpoint,
                evidence=json.loads(row["evidence_json"]),
            )
            db.commit()
            return claim

    def start_attempt(
        self,
        claim: Claim,
        *,
        max_total_attempts: int | None = None,
        lease_seconds: float = 1800,
        now: float | None = None,
    ) -> Claim | None:
        """Atomically count an inference attempt only after local preparation succeeds."""
        now = time.time() if now is None else now
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._require_owner(db, claim)
            if row["status"] == "running":
                existing = db.execute(
                    """SELECT 1 FROM attempts WHERE address=? AND attempt_number=?
                       AND worker_id=? AND provider=?""",
                    (claim.address, claim.attempt_number, claim.worker_id, claim.provider),
                ).fetchone()
                if existing is not None:
                    db.commit()
                    return claim
            if row["status"] != "preparing" or row["boundary_status"] != "EXACT":
                raise RuntimeError("only a prepared EXACT reservation can start inference")
            provider_row = db.execute(
                "SELECT status,resume_at FROM providers WHERE provider=?",
                (claim.provider,),
            ).fetchone()
            provider_status = "active" if provider_row is None else str(provider_row["status"])
            paused = provider_status in {"suspended_quota", "blocked_auth", "blocked"} or (
                provider_status in {"rate_limited", "network_backoff"}
                and (
                    provider_row["resume_at"] is None
                    or float(provider_row["resume_at"]) > now
                )
            )
            if paused:
                db.execute(
                    """UPDATE candidates SET status='pending',owner=NULL,provider=NULL,
                       lease_until=NULL,updated_at=? WHERE address=?""",
                    (now, claim.address),
                )
                self._event(
                    db,
                    "provider_paused_before_attempt",
                    address=claim.address,
                    worker_id=claim.worker_id,
                    provider=claim.provider,
                )
                db.commit()
                return None
            if provider_status in {"rate_limited", "network_backoff"}:
                db.execute(
                    "UPDATE providers SET status='active',resume_at=NULL,reason=NULL,updated_at=? WHERE provider=?",
                    (now, claim.provider),
                )
            if max_total_attempts is not None:
                total_attempts = int(db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0])
                if total_attempts >= max_total_attempts:
                    db.execute(
                        """UPDATE candidates SET status='pending',owner=NULL,provider=NULL,
                           lease_until=NULL,updated_at=? WHERE address=?""",
                        (now, claim.address),
                    )
                    self._event(
                        db,
                        "attempt_ceiling_reached",
                        address=claim.address,
                        worker_id=claim.worker_id,
                        provider=claim.provider,
                    )
                    db.commit()
                    return None
            attempt_number = int(row["attempt_count"]) + 1
            session_id = (
                row["session_id"]
                if row["last_provider"] == claim.provider
                else None
            )
            attempt_session_id = session_id or "pending_" + uuid.uuid4().hex
            lease_until = now + max(1.0, lease_seconds)
            db.execute(
                """UPDATE candidates SET status='running',last_provider=?,session_id=?,
                   lease_until=?,attempt_count=?,updated_at=? WHERE address=?""",
                (claim.provider, session_id, lease_until, attempt_number, now, claim.address),
            )
            db.execute(
                """INSERT INTO attempts(address,attempt_number,worker_id,provider,session_id,started_at)
                   VALUES (?,?,?,?,?,?)""",
                (
                    claim.address,
                    attempt_number,
                    claim.worker_id,
                    claim.provider,
                    attempt_session_id,
                    now,
                ),
            )
            self._event(
                db,
                "claimed",
                address=claim.address,
                worker_id=claim.worker_id,
                provider=claim.provider,
                session_id=session_id,
            )
            db.commit()
        return replace(
            claim,
            attempt_number=attempt_number,
            session_id=session_id,
            lease_until=lease_until,
        )

    def release_preparation(
        self,
        claim: Claim,
        *,
        diagnostic_code: str | None = None,
        failure: Failure | None = None,
        max_retry_after: float = 900,
    ) -> None:
        """Release an EXACT model reservation without recording an inference attempt."""
        if diagnostic_code is not None and failure is not None:
            raise ValueError("preparation release cannot have both a diagnostic and provider failure")
        now = time.time()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._require_owner(db, claim)
            if row["status"] != "preparing":
                raise RuntimeError("only a model preparation reservation can be released")
            checkpoint = json.loads(row["checkpoint_json"])
            event_kind = "preparation_interrupted"
            status = "pending"
            preferred_provider: str | None = row["preferred_provider"]
            available_at = now
            last_provider = row["last_provider"]
            if diagnostic_code is not None:
                stage = DIAGNOSTIC_CODES.get(diagnostic_code)
                if stage not in {"ghidra", "context", "integrity"}:
                    raise ValueError("unsupported preparation diagnostic")
                checkpoint["last_diagnostic"] = {
                    "stage": stage,
                    "code": diagnostic_code,
                }
                event_kind = diagnostic_code
                status = "blocked"
            elif failure is not None:
                if failure.kind not in {
                    FailureKind.QUOTA_EXHAUSTED,
                    FailureKind.RATE_LIMIT,
                    FailureKind.NETWORK,
                    FailureKind.TIMEOUT,
                    FailureKind.INTERRUPTED,
                }:
                    raise ValueError("unsupported provider failure during preparation")
                delay = failure.retry_after_seconds
                if failure.kind is FailureKind.RATE_LIMIT:
                    delay = max(delay or 0.0, 1.0)
                elif failure.kind in {FailureKind.NETWORK, FailureKind.TIMEOUT}:
                    delay = min(max_retry_after, max(delay or 2.0, 1.0))
                provider_status = "active"
                resume_at = None
                preferred_provider = claim.provider
                if failure.kind is FailureKind.QUOTA_EXHAUSTED:
                    provider_status = "suspended_quota"
                    preferred_provider = None
                elif failure.kind is FailureKind.RATE_LIMIT:
                    provider_status = "rate_limited"
                    available_at = now + float(delay or 0.0)
                    resume_at = available_at
                elif failure.kind in {FailureKind.NETWORK, FailureKind.TIMEOUT}:
                    provider_status = "network_backoff"
                    available_at = now + float(delay or 0.0)
                    resume_at = available_at
                elif failure.kind is FailureKind.INTERRUPTED:
                    event_kind = "preparation_interrupted"
                else:
                    raise AssertionError("unreachable provider failure classification")
                last_provider = claim.provider
                db.execute(
                    """INSERT INTO providers(provider,status,resume_at,reason,updated_at)
                       VALUES (?,?,?,?,?) ON CONFLICT(provider) DO UPDATE SET
                       status=excluded.status,resume_at=excluded.resume_at,reason=excluded.reason,
                       updated_at=excluded.updated_at""",
                    (
                        claim.provider,
                        provider_status,
                        resume_at,
                        failure.kind.value,
                        now,
                    ),
                )
                event_kind = failure.kind.value
            db.execute(
                """UPDATE candidates SET status=?,owner=NULL,provider=NULL,lease_until=NULL,
                   preferred_provider=?,available_at=?,last_provider=?,session_id=?,
                   checkpoint_json=?,updated_at=? WHERE address=?""",
                (
                    status,
                    preferred_provider,
                    available_at,
                    last_provider,
                    claim.session_id,
                    _json_dump(checkpoint),
                    now,
                    claim.address,
                ),
            )
            self._event(
                db,
                event_kind,
                address=claim.address,
                worker_id=claim.worker_id,
                provider=claim.provider,
            )
            db.commit()

    def claim_boundary(
        self,
        worker_id: str,
        *,
        lease_seconds: float = 1800,
        excluded_addresses: Collection[str] = (),
        now: float | None = None,
    ) -> Claim | None:
        """Lease one UNVERIFIED boundary for Ghidra without creating a model attempt."""
        now = time.time() if now is None else now
        normalized_excluded = sorted(
            {
                _normalize_eboot_address(value, label="excluded certified address")
                for value in excluded_addresses
            }
        )
        address_clause = (
            " AND address NOT IN (" + ",".join("?" for _ in normalized_excluded) + ")"
            if normalized_excluded
            else ""
        )
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT * FROM candidates
                   WHERE status='needs_boundary' AND boundary_status='UNVERIFIED' AND available_at<=?
                   """ + address_clause + " ORDER BY priority DESC,address ASC LIMIT 1",
                (now, *normalized_excluded),
            ).fetchone()
            if row is None:
                db.commit()
                return None
            lease_until = now + max(1.0, lease_seconds)
            db.execute(
                """UPDATE candidates SET status='boundary_checking',owner=?,provider='ghidra',
                   lease_until=?,updated_at=? WHERE address=? AND status='needs_boundary'""",
                (worker_id, lease_until, now, row["address"]),
            )
            self._event(
                db,
                "boundary_claimed",
                address=row["address"],
                worker_id=worker_id,
                provider="ghidra",
            )
            claim = Claim(
                address=row["address"],
                size_bytes=int(row["size_bytes"]),
                nid=row["nid"],
                priority=int(row["priority"]),
                boundary_status=row["boundary_status"],
                worker_id=worker_id,
                provider="ghidra",
                session_id=row["session_id"],
                attempt_number=int(row["attempt_count"]),
                lease_until=lease_until,
                checkpoint=json.loads(row["checkpoint_json"]),
                evidence=json.loads(row["evidence_json"]),
            )
            db.commit()
            return claim

    def finish_boundary(self, claim: Claim) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._require_owner(db, claim)
            if row["status"] != "boundary_checking" or row["boundary_status"] != "EXACT":
                raise RuntimeError("only a Ghidra-validated boundary claim can be completed")
            db.execute(
                """UPDATE candidates SET status='pending',owner=NULL,provider=NULL,
                   lease_until=NULL,updated_at=? WHERE address=?""",
                (time.time(), claim.address),
            )
            self._event(
                db,
                "boundary_claim_finished",
                address=claim.address,
                worker_id=claim.worker_id,
                provider="ghidra",
            )
            db.commit()

    def fail_boundary(
        self,
        claim: Claim,
        diagnostic_code: str | None = None,
        *,
        interrupted: bool = False,
    ) -> None:
        if not interrupted and DIAGNOSTIC_CODES.get(str(diagnostic_code)) != "ghidra":
            raise ValueError("unsupported Ghidra boundary diagnostic")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._require_owner(db, claim)
            if row["status"] != "boundary_checking":
                raise RuntimeError("only an active boundary claim can be failed")
            checkpoint = json.loads(row["checkpoint_json"])
            if interrupted:
                status = "needs_boundary"
                event_kind = "boundary_interrupted"
            else:
                status = "blocked"
                event_kind = str(diagnostic_code)
                checkpoint["last_diagnostic"] = {
                    "stage": "ghidra",
                    "code": diagnostic_code,
                }
            db.execute(
                """UPDATE candidates SET status=?,owner=NULL,provider=NULL,lease_until=NULL,
                   checkpoint_json=?,updated_at=? WHERE address=?""",
                (status, _json_dump(checkpoint), time.time(), claim.address),
            )
            self._event(
                db,
                event_kind,
                address=claim.address,
                worker_id=claim.worker_id,
                provider="ghidra",
            )
            db.commit()

    def bind_session(self, claim: Claim, session_id: str) -> Claim:
        """Persist an OpenCode-issued session ID on the owned attempt and task."""
        if not session_id:
            raise ValueError("OpenCode session ID cannot be empty")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._require_owner(db, claim)
            now = time.time()
            db.execute(
                "UPDATE candidates SET session_id=?,last_provider=?,updated_at=? WHERE address=?",
                (session_id, claim.provider, now, claim.address),
            )
            if row["status"] == "running":
                db.execute(
                    "UPDATE attempts SET session_id=? WHERE address=? AND attempt_number=?",
                    (session_id, claim.address, claim.attempt_number),
                )
            self._event(
                db,
                "session_bound",
                address=claim.address,
                worker_id=claim.worker_id,
                provider=claim.provider,
                session_id=session_id,
            )
            db.commit()
        return replace(claim, session_id=session_id)

    def _require_owner(self, db: sqlite3.Connection, claim: Claim) -> sqlite3.Row:
        row = db.execute("SELECT * FROM candidates WHERE address=?", (claim.address,)).fetchone()
        if (
            row is None
            or row["status"] not in {"running", "preparing", "boundary_checking"}
            or row["owner"] != claim.worker_id
            or row["provider"] != claim.provider
            or row["session_id"] != claim.session_id
            or int(row["attempt_count"]) != claim.attempt_number
        ):
            raise RuntimeError("task lease is no longer owned by this worker")
        return row

    def save_checkpoint(
        self,
        claim: Claim,
        checkpoint: dict[str, Any],
        *,
        trusted_evidence: bool = False,
    ) -> None:
        update = _sanitize_checkpoint(checkpoint, trusted_evidence=trusted_evidence)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._require_owner(db, claim)
            checkpoint = json.loads(row["checkpoint_json"])
            checkpoint.update(update)
            encoded = _json_dump(checkpoint)
            if len(encoded) > 128_000:
                raise ValueError("checkpoint metadata exceeds 128 KiB")
            db.execute(
                "UPDATE candidates SET checkpoint_json=?,updated_at=? WHERE address=?",
                (encoded, time.time(), claim.address),
            )
            self._event(
                db,
                "checkpoint_saved",
                address=claim.address,
                worker_id=claim.worker_id,
                provider=claim.provider,
                session_id=claim.session_id,
            )
            db.commit()

    def update_boundary(self, claim: Claim, size_bytes: int, evidence: dict[str, Any]) -> None:
        if size_bytes <= 0 or size_bytes % 4:
            raise ValueError("Ghidra boundary size must be a positive multiple of four bytes")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._require_owner(db, claim)
            if row["status"] not in {"running", "preparing", "boundary_checking"}:
                raise RuntimeError("boundary update requires an active campaign lease")
            start = claim.numeric_address
            end = start + size_bytes
            exact_rows = db.execute(
                "SELECT address,size_bytes FROM candidates WHERE boundary_status='EXACT' AND address<>?",
                (claim.address,),
            ).fetchall()
            for exact in exact_rows:
                exact_start = int(exact["address"], 0)
                exact_end = exact_start + int(exact["size_bytes"])
                if start < exact_end and exact_start < end:
                    raise ValueError(
                        f"Ghidra boundary {claim.address} overlaps EXACT candidate {exact['address']}"
                    )
            old = db.execute(
                "SELECT evidence_json FROM candidates WHERE address=?", (claim.address,)
            ).fetchone()
            merged = json.loads(old["evidence_json"])
            merged["ghidra_validation"] = evidence
            db.execute(
                """UPDATE candidates SET size_bytes=?,boundary_status='EXACT',evidence_json=?,updated_at=?
                   WHERE address=?""",
                (size_bytes, _json_dump(merged), time.time(), claim.address),
            )
            self._event(
                db,
                "boundary_validated",
                address=claim.address,
                worker_id=claim.worker_id,
                provider=claim.provider,
                session_id=claim.session_id,
            )
            db.commit()

    def complete(
        self,
        claim: Claim,
        checkpoint: dict[str, Any],
        verification: dict[str, Any],
        *,
        max_attempts_without_progress: int,
        max_attempts_per_candidate: int,
        continue_refinement: bool = False,
        refinement_progress: bool = False,
        max_total_attempts: int | None = None,
        lease_seconds: float = 1800,
    ) -> str | Claim:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._require_owner(db, claim)
            if row["status"] != "running":
                raise RuntimeError("only a started model attempt can be completed")
            size = int(row["size_bytes"])
            previous = json.loads(row["best_result_json"])
            previous_checkpoint = json.loads(row["checkpoint_json"])
            score = int(verification.get("matching_words", -1))
            previous_score = int(previous.get("matching_words", -1))
            attempt_certified = is_deterministic_match(
                verification,
                expected_address=claim.numeric_address,
                expected_size=size,
            )
            previous_certified = is_deterministic_match(
                previous,
                expected_address=claim.numeric_address,
                expected_size=size,
            )
            improved = (
                attempt_certified and not previous_certified
            ) or (
                attempt_certified == previous_certified and score > previous_score
            )
            attempt_result = dict(verification)
            attempt_result["campaign_origin"] = {
                "attempt_number": claim.attempt_number,
                "worker_id": claim.worker_id,
                "provider": claim.provider,
                "session_id": claim.session_id,
            }
            best = attempt_result if improved or not previous else previous
            boundary_only = verification.get("status") == "BOUNDARY_VALIDATED"
            checkpoint = _sanitize_checkpoint(checkpoint, trusted_evidence=True)
            if not boundary_only:
                checkpoint.pop("last_diagnostic_detail", None)
                source_sha256 = verification.get("source_sha256")
                if isinstance(source_sha256, str) and HEX_SHA256.fullmatch(source_sha256):
                    source_path = f"decomp/src/eboot/func_{claim.numeric_address:08X}.c"
                    checkpoint["source_path"] = source_path
                    checkpoint["source_sha256"] = source_sha256
                    if improved or not previous:
                        snapshot = verification.get("source_snapshot_path")
                        if isinstance(snapshot, str):
                            checkpoint["best_source_sha256"] = source_sha256
                            checkpoint["best_source_snapshot"] = snapshot
                    else:
                        for key in ("best_source_sha256", "best_source_snapshot"):
                            if key in previous_checkpoint:
                                checkpoint[key] = previous_checkpoint[key]
                if isinstance(best, dict):
                    previous_match = previous_checkpoint.get("best_match")
                    previous_builds = previous.get("build_sha256", [])
                    previous_report_path = None
                    if (
                        isinstance(previous_match, dict)
                        and previous_match.get("source_sha256") == best.get("source_sha256")
                        and isinstance(previous_builds, list)
                        and previous_builds
                        and previous_match.get("object_sha256") == previous_builds[0]
                        and isinstance(previous_match.get("report_path"), str)
                    ):
                        previous_report_path = previous_match["report_path"]
                    checkpoint["best_match"] = _match_checkpoint_summary(
                        best, fallback_report_path=previous_report_path
                    )
                    checkpoint["last_attempt"] = _match_checkpoint_summary(attempt_result)
                    evidence_paths = []
                    if isinstance(checkpoint.get("ghidra_log_path"), str):
                        evidence_paths.insert(0, f"build/{checkpoint['ghidra_log_path']}")
                    for summary in (checkpoint["best_match"], checkpoint["last_attempt"]):
                        if not isinstance(summary, dict):
                            continue
                        paths = summary.get("report_paths", [])
                        if isinstance(paths, list):
                            evidence_paths.extend(path for path in paths if isinstance(path, str))
                    checkpoint["evidence_paths"] = list(dict.fromkeys(evidence_paths))[:40]
            encoded_checkpoint = _json_dump(checkpoint)
            if len(encoded_checkpoint) > 128_000:
                raise ValueError("checkpoint metadata exceeds 128 KiB")
            if boundary_only:
                status = "pending"
            elif attempt_certified:
                status = "matched"
            elif int(row["attempt_count"]) >= max_attempts_per_candidate:
                status = "stalled"
            elif not improved and int(row["attempts_without_progress"]) + 1 >= max_attempts_without_progress:
                status = "stalled"
            else:
                status = "pending"
            if boundary_only:
                no_progress = int(row["attempts_without_progress"])
            else:
                no_progress = 0 if improved else int(row["attempts_without_progress"]) + 1
            now = time.time()
            total_attempts = int(db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0])
            stop_row = db.execute(
                "SELECT value FROM metadata WHERE key='stop_requested'"
            ).fetchone()
            should_continue = bool(
                continue_refinement
                and not boundary_only
                and not attempt_certified
                and (improved or refinement_progress)
                and status == "pending"
                and (max_total_attempts is None or total_attempts < max_total_attempts)
                and not (stop_row and stop_row[0] == "1")
            )
            lease_until = now + max(1.0, lease_seconds) if should_continue else None
            if should_continue:
                db.execute(
                    """UPDATE candidates SET status='preparing',lease_until=?,checkpoint_json=?,
                       best_result_json=?,attempts_without_progress=?,updated_at=? WHERE address=?""",
                    (
                        lease_until,
                        encoded_checkpoint,
                        _json_dump(best),
                        no_progress,
                        now,
                        claim.address,
                    ),
                )
            else:
                db.execute(
                    """UPDATE candidates SET status=?,owner=NULL,provider=NULL,lease_until=NULL,
                        preferred_provider=CASE WHEN ?='pending' THEN NULL ELSE preferred_provider END,
                        checkpoint_json=?,best_result_json=?,attempts_without_progress=?,updated_at=?
                        WHERE address=?""",
                    (
                        status,
                        status,
                        encoded_checkpoint,
                        _json_dump(best),
                        no_progress,
                        now,
                        claim.address,
                    ),
                )
            db.execute(
                "UPDATE attempts SET ended_at=?,outcome=? WHERE address=? AND attempt_number=?",
                (now, status, claim.address, claim.attempt_number),
            )
            self._event(
                db,
                status,
                address=claim.address,
                worker_id=claim.worker_id,
                provider=claim.provider,
                session_id=claim.session_id,
            )
            if should_continue:
                self._event(
                    db,
                    "refinement_reserved",
                    address=claim.address,
                    worker_id=claim.worker_id,
                    provider=claim.provider,
                    session_id=claim.session_id,
                )
            db.commit()
        if should_continue:
            return replace(claim, checkpoint=checkpoint, lease_until=float(lease_until))
        return status

    def start_continued_attempt(
        self,
        claim: Claim,
        *,
        max_total_attempts: int,
        max_attempts_per_candidate: int,
        lease_seconds: float,
        now: float | None = None,
    ) -> Claim | None:
        """Atomically begin the next Luna call while retaining this worker's lease/session."""
        now = time.time() if now is None else now
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._require_owner(db, claim)
            if row["status"] != "preparing" or row["boundary_status"] != "EXACT":
                raise RuntimeError("continued inference requires an owned EXACT refinement reservation")
            prior_attempt = db.execute(
                """SELECT ended_at,outcome FROM attempts WHERE address=? AND attempt_number=?
                   AND worker_id=? AND provider=?""",
                (claim.address, claim.attempt_number, claim.worker_id, claim.provider),
            ).fetchone()
            if prior_attempt is None or prior_attempt["ended_at"] is None:
                raise RuntimeError("the previous inference attempt must be finalized before refinement")
            provider_row = db.execute(
                "SELECT status,resume_at FROM providers WHERE provider=?", (claim.provider,)
            ).fetchone()
            provider_status = "active" if provider_row is None else str(provider_row["status"])
            paused = provider_status in {"suspended_quota", "blocked_auth", "blocked"} or (
                provider_status in {"rate_limited", "network_backoff"}
                and (
                    provider_row["resume_at"] is None
                    or float(provider_row["resume_at"]) > now
                )
            )
            total_attempts = int(db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0])
            stopped = db.execute(
                "SELECT value FROM metadata WHERE key='stop_requested'"
            ).fetchone()
            budget_exhausted = total_attempts >= max_total_attempts
            candidate_limit = int(row["attempt_count"]) >= max_attempts_per_candidate
            if paused or budget_exhausted or candidate_limit or (stopped and stopped[0] == "1"):
                status = "stalled" if candidate_limit else "pending"
                db.execute(
                    """UPDATE candidates SET status=?,owner=NULL,provider=NULL,lease_until=NULL,
                       updated_at=? WHERE address=?""",
                    (status, now, claim.address),
                )
                event = (
                    "refinement_stalled"
                    if candidate_limit
                    else "refinement_released"
                )
                self._event(
                    db,
                    event,
                    address=claim.address,
                    worker_id=claim.worker_id,
                    provider=claim.provider,
                    session_id=claim.session_id,
                )
                db.commit()
                return None
            if provider_status in {"rate_limited", "network_backoff"}:
                db.execute(
                    "UPDATE providers SET status='active',resume_at=NULL,reason=NULL,updated_at=? WHERE provider=?",
                    (now, claim.provider),
                )
            attempt_number = int(row["attempt_count"]) + 1
            lease_until = now + max(1.0, lease_seconds)
            attempt_session_id = claim.session_id or "pending_" + uuid.uuid4().hex
            db.execute(
                """UPDATE candidates SET status='running',last_provider=?,lease_until=?,
                   attempt_count=?,updated_at=? WHERE address=?""",
                (claim.provider, lease_until, attempt_number, now, claim.address),
            )
            db.execute(
                """INSERT INTO attempts(address,attempt_number,worker_id,provider,session_id,started_at)
                   VALUES(?,?,?,?,?,?)""",
                (
                    claim.address,
                    attempt_number,
                    claim.worker_id,
                    claim.provider,
                    attempt_session_id,
                    now,
                ),
            )
            self._event(
                db,
                "refinement_attempt_started",
                address=claim.address,
                worker_id=claim.worker_id,
                provider=claim.provider,
                session_id=claim.session_id,
            )
            db.commit()
        return replace(
            claim,
            attempt_number=attempt_number,
            lease_until=lease_until,
        )

    def complete_diagnostic(
        self,
        claim: Claim,
        *,
        diagnostic_stage: str,
        diagnostic_code: str,
        excerpt: str,
        max_attempts_without_progress: int,
        max_attempts_per_candidate: int,
        continue_refinement: bool,
        max_total_attempts: int | None,
        lease_seconds: float,
    ) -> str | Claim:
        """Finish a recoverable local compiler/matcher error without changing best evidence."""
        if (
            diagnostic_code not in {"compiler_failed", "matcher_incomplete"}
            or DIAGNOSTIC_CODES.get(diagnostic_code) != diagnostic_stage
        ):
            raise ValueError("recoverable diagnostic code/stage is unsupported")
        now = time.time()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._require_owner(db, claim)
            if row["status"] != "running":
                raise RuntimeError("only a started model attempt can record a recoverable diagnostic")
            checkpoint = json.loads(row["checkpoint_json"])
            checkpoint["last_diagnostic"] = {
                "stage": diagnostic_stage,
                "code": diagnostic_code,
            }
            sanitized_detail = _sanitize_checkpoint(
                {
                    "last_diagnostic_detail": {
                        "stage": diagnostic_stage,
                        "code": diagnostic_code,
                        "excerpt": excerpt,
                    }
                },
                trusted_evidence=True,
            ).get("last_diagnostic_detail")
            if sanitized_detail:
                checkpoint["last_diagnostic_detail"] = sanitized_detail
            no_progress = int(row["attempts_without_progress"]) + 1
            attempts = int(row["attempt_count"])
            current_status = (
                "stalled"
                if attempts >= max_attempts_per_candidate
                or no_progress >= max_attempts_without_progress
                else "pending"
            )
            total_attempts = int(db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0])
            stopped = db.execute(
                "SELECT value FROM metadata WHERE key='stop_requested'"
            ).fetchone()
            should_continue = bool(
                continue_refinement
                and current_status == "pending"
                and (max_total_attempts is None or total_attempts < max_total_attempts)
                and not (stopped and stopped[0] == "1")
            )
            lease_until = now + max(1.0, lease_seconds) if should_continue else None
            encoded_checkpoint = _json_dump(
                _sanitize_checkpoint(checkpoint, trusted_evidence=True)
            )
            if len(encoded_checkpoint) > 128_000:
                raise ValueError("checkpoint metadata exceeds 128 KiB")
            if should_continue:
                db.execute(
                    """UPDATE candidates SET status='preparing',lease_until=?,checkpoint_json=?,
                       attempts_without_progress=?,updated_at=? WHERE address=?""",
                    (
                        lease_until,
                        encoded_checkpoint,
                        no_progress,
                        now,
                        claim.address,
                    ),
                )
            else:
                db.execute(
                    """UPDATE candidates SET status=?,owner=NULL,provider=NULL,lease_until=NULL,
                       checkpoint_json=?,attempts_without_progress=?,updated_at=? WHERE address=?""",
                    (current_status, encoded_checkpoint, no_progress, now, claim.address),
                )
            db.execute(
                """UPDATE attempts SET ended_at=?,outcome=?,failure_kind=?
                   WHERE address=? AND attempt_number=?""",
                (now, diagnostic_code, "agent_error", claim.address, claim.attempt_number),
            )
            self._event(
                db,
                diagnostic_code,
                address=claim.address,
                worker_id=claim.worker_id,
                provider=claim.provider,
                session_id=claim.session_id,
            )
            if should_continue:
                self._event(
                    db,
                    "refinement_reserved",
                    address=claim.address,
                    worker_id=claim.worker_id,
                    provider=claim.provider,
                    session_id=claim.session_id,
                )
            db.commit()
        if should_continue:
            return replace(
                claim,
                checkpoint=checkpoint,
                lease_until=float(lease_until),
            )
        return current_status

    def complete_unchanged_source(self, claim: Claim) -> str:
        """Close a paid inference without recompiling a source hash already tested."""
        now = time.time()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._require_owner(db, claim)
            if row["status"] != "running":
                raise RuntimeError("only a started model attempt can be closed as unchanged")
            checkpoint = json.loads(row["checkpoint_json"])
            checkpoint["last_diagnostic"] = {
                "stage": "worker_return",
                "code": "source_unchanged",
            }
            encoded = _json_dump(_sanitize_checkpoint(checkpoint, trusted_evidence=True))
            if len(encoded) > 128_000:
                raise ValueError("checkpoint metadata exceeds 128 KiB")
            no_progress = int(row["attempts_without_progress"]) + 1
            db.execute(
                """UPDATE candidates SET status='stalled',owner=NULL,provider=NULL,
                   lease_until=NULL,checkpoint_json=?,attempts_without_progress=?,updated_at=?
                   WHERE address=?""",
                (encoded, no_progress, now, claim.address),
            )
            db.execute(
                """UPDATE attempts SET ended_at=?,outcome='source_unchanged'
                   WHERE address=? AND attempt_number=?""",
                (now, claim.address, claim.attempt_number),
            )
            self._event(
                db,
                "source_unchanged",
                address=claim.address,
                worker_id=claim.worker_id,
                provider=claim.provider,
                session_id=claim.session_id,
            )
            db.commit()
        return "stalled"

    def fail(
        self,
        claim: Claim,
        failure: Failure,
        *,
        max_retry_after: float = 900,
        max_attempts_per_candidate: int = 8,
    ) -> None:
        now = time.time()
        delay = failure.retry_after_seconds
        if failure.kind is FailureKind.RATE_LIMIT:
            delay = max(delay or 0, 1.0)
        elif failure.kind in {FailureKind.NETWORK, FailureKind.TIMEOUT}:
            delay = min(max_retry_after, max(delay or 2.0, 1.0))
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            candidate_row = self._require_owner(db, claim)
            if candidate_row["status"] != "running":
                raise RuntimeError("only a started model attempt can be failed")
            diagnostic = None
            if (
                isinstance(failure.diagnostic_code, str)
                and failure.diagnostic_code in DIAGNOSTIC_CODES
                and DIAGNOSTIC_CODES[failure.diagnostic_code]
                == failure.diagnostic_stage
            ):
                diagnostic = {
                    "stage": failure.diagnostic_stage,
                    "code": failure.diagnostic_code,
                }
            diagnostic_code = diagnostic["code"] if diagnostic is not None else None
            checkpoint = json.loads(candidate_row["checkpoint_json"])
            if diagnostic is not None:
                checkpoint["last_diagnostic"] = diagnostic
            checkpoint_json = _json_dump(checkpoint)
            provider_status = "blocked"
            task_status = "blocked"
            preferred_provider: str | None = claim.provider
            available_at = now
            if failure.kind is FailureKind.QUOTA_EXHAUSTED:
                provider_status = "suspended_quota"
                task_status = "pending"
                preferred_provider = None
            elif failure.kind is FailureKind.RATE_LIMIT:
                provider_status = "rate_limited"
                task_status = "pending"
                available_at = now + float(delay or 0)
            elif failure.kind in {FailureKind.NETWORK, FailureKind.TIMEOUT}:
                provider_status = "network_backoff"
                task_status = "pending"
                available_at = now + float(delay or 0)
            elif failure.kind is FailureKind.AGENT_ERROR:
                # Unknown errors pause this task, but are not mislabeled as quota and
                # do not authorize moving it to the other provider.
                provider_status = "active"
                task_status = "blocked"
            elif failure.kind is FailureKind.INTERRUPTED:
                provider_status = "active"
                task_status = "pending"
            if int(candidate_row["attempt_count"]) >= max_attempts_per_candidate:
                task_status = "stalled"
                preferred_provider = claim.provider
            if failure.kind is FailureKind.QUOTA_EXHAUSTED:
                resume_at = None
            elif provider_status in {"rate_limited", "network_backoff"}:
                resume_at = available_at
            else:
                resume_at = None
            reason = failure.kind.value
            db.execute(
                """INSERT INTO providers(provider,status,resume_at,reason,updated_at)
                   VALUES (?,?,?,?,?) ON CONFLICT(provider) DO UPDATE SET
                   status=excluded.status,resume_at=excluded.resume_at,reason=excluded.reason,
                   updated_at=excluded.updated_at""",
                (claim.provider, provider_status, resume_at, reason, now),
            )
            db.execute(
                """UPDATE candidates SET status=?,owner=NULL,provider=NULL,lease_until=NULL,
                   preferred_provider=?,available_at=?,last_provider=?,session_id=?,checkpoint_json=?,updated_at=?
                   WHERE address=?""",
                (
                    task_status,
                    preferred_provider,
                    available_at,
                    claim.provider,
                    claim.session_id,
                    checkpoint_json,
                    now,
                    claim.address,
                ),
            )
            db.execute(
                """UPDATE attempts SET ended_at=?,outcome=?,failure_kind=?,retry_after=?
                   WHERE address=? AND attempt_number=?""",
                (
                    now,
                    diagnostic_code or failure.kind.value,
                    failure.kind.value,
                    delay,
                    claim.address,
                    claim.attempt_number,
                ),
            )
            self._event(
                db,
                diagnostic_code or failure.kind.value,
                address=claim.address,
                worker_id=claim.worker_id,
                provider=claim.provider,
                session_id=claim.session_id,
            )
            db.commit()

    def recover_expired(self, *, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT address,owner,provider,session_id,attempt_count FROM candidates "
                "WHERE status='running' AND lease_until<=?",
                (now,),
            ).fetchall()
            for row in rows:
                db.execute(
                    """UPDATE candidates SET status='pending',owner=NULL,provider=NULL,
                       lease_until=NULL,updated_at=? WHERE address=?""",
                    (now, row["address"]),
                )
                db.execute(
                    """UPDATE attempts SET ended_at=?,outcome='interrupted',failure_kind='interrupted'
                       WHERE address=? AND attempt_number=? AND outcome='running'""",
                    (now, row["address"], row["attempt_count"]),
                )
                self._event(
                    db,
                    "interrupted_recovered",
                    address=row["address"],
                    worker_id=row["owner"],
                    provider=row["provider"],
                    session_id=row["session_id"],
                )
            preparation_rows = db.execute(
                "SELECT address,owner,provider,boundary_status FROM candidates "
                "WHERE status IN ('preparing','boundary_checking') AND lease_until<=?",
                (now,),
            ).fetchall()
            for row in preparation_rows:
                restored_status = (
                    "pending" if row["boundary_status"] == "EXACT" else "needs_boundary"
                )
                db.execute(
                    """UPDATE candidates SET status=?,owner=NULL,provider=NULL,lease_until=NULL,
                       updated_at=? WHERE address=?""",
                    (restored_status, now, row["address"]),
                )
                self._event(
                    db,
                    "preparation_recovered",
                    address=row["address"],
                    worker_id=row["owner"],
                    provider=row["provider"],
                )
            db.commit()
            return len(rows) + len(preparation_rows)

    def request_stop(self) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO metadata(key,value) VALUES('stop_requested','1') "
                "ON CONFLICT(key) DO UPDATE SET value='1'"
            )

    def stop_requested(self) -> bool:
        with self._connect() as db:
            row = db.execute("SELECT value FROM metadata WHERE key='stop_requested'").fetchone()
            return bool(row and row[0] == "1")

    def resume(self, *, reset_providers: bool = True) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "UPDATE metadata SET value='0' WHERE key='stop_requested'"
            )
            if reset_providers:
                db.execute(
                    "UPDATE providers SET status='active',resume_at=NULL,reason=NULL,updated_at=?",
                    (time.time(),),
                )
            db.commit()

    def retry_blocked_addresses(
        self,
        addresses: Sequence[str],
        *,
        excluded_addresses: Collection[str] = (),
    ) -> list[str]:
        """Unblock only named, lease-free blocked tasks without rewriting history."""
        excluded = {
            _normalize_eboot_address(value, label="excluded certified address")
            for value in excluded_addresses
        }
        normalized: list[str] = []
        for value in addresses:
            try:
                numeric = int(str(value).strip(), 0)
            except ValueError as exc:
                raise ValueError(f"invalid retry address: {value}") from exc
            if not 0 <= numeric <= 0xFFFFFFFF:
                raise ValueError(f"invalid retry address: {value}")
            address = f"0x{numeric:x}"
            if address in excluded:
                raise ValueError(f"certified baseline address cannot be retried: {address}")
            if address in normalized:
                raise ValueError(f"duplicate retry address: {address}")
            normalized.append(address)
        if not normalized:
            raise ValueError("selective retry requires at least one address")

        now = time.time()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for address in normalized:
                row = db.execute(
                    "SELECT status,owner,lease_until FROM candidates WHERE address=?",
                    (address,),
                ).fetchone()
                if row is None or row["status"] != "blocked":
                    raise ValueError(f"retry address is not a blocked candidate: {address}")
                if row["owner"] is not None or (
                    row["lease_until"] is not None and float(row["lease_until"]) > now
                ):
                    raise ValueError(f"retry address still has an active lease: {address}")
            for address in normalized:
                changed = db.execute(
                    "UPDATE candidates SET status='pending',updated_at=? "
                    "WHERE address=? AND status='blocked' AND owner IS NULL",
                    (now, address),
                ).rowcount
                if changed != 1:
                    raise ValueError(f"retry address changed while validating its lease: {address}")
            db.commit()
        return normalized

    def reopen_recoverable_candidates(
        self,
        reasons: Mapping[str, str],
        *,
        excluded_addresses: Collection[str] = (),
        max_attempts_per_candidate: int,
        campaign_id: str,
    ) -> list[str]:
        """Reopen named EXACT blocked/stalled candidates with an auditable reason."""
        if (
            isinstance(max_attempts_per_candidate, bool)
            or max_attempts_per_candidate <= 0
        ):
            raise ValueError("recovery attempt limit must be positive")
        if not re.fullmatch(r"SETO-DECOMP-[0-9]{3}", campaign_id):
            raise ValueError("recovery campaign id is invalid")
        excluded = {
            _normalize_eboot_address(value, label="excluded certified address")
            for value in excluded_addresses
        }
        normalized: dict[str, str] = {}
        for value, reason in reasons.items():
            address = _normalize_eboot_address(value, label="recovery address")
            if address in excluded:
                raise ValueError(f"certified baseline address cannot be reopened: {address}")
            if address in normalized:
                raise ValueError(f"duplicate recovery address: {address}")
            clean_reason = _safe_text(reason, 600).strip()
            if not clean_reason:
                raise ValueError(f"reopening {address} requires a concrete reason")
            normalized[address] = clean_reason
        if not normalized:
            raise ValueError("selective recovery requires at least one justified candidate")

        now = time.time()
        reopened: list[str] = []
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            rows: dict[str, sqlite3.Row] = {}
            for address, reason in normalized.items():
                row = db.execute(
                    """SELECT status,boundary_status,size_bytes,owner,lease_until,
                       attempt_count,checkpoint_json,best_result_json FROM candidates
                       WHERE address=?""",
                    (address,),
                ).fetchone()
                if row is None:
                    raise ValueError(f"recovery address is not in the SQLite inventory: {address}")
                if row["status"] == "pending":
                    # Already eligible: a repeated recovery command is a no-op.
                    continue
                if row["status"] not in {"blocked", "stalled"}:
                    raise ValueError(
                        f"recovery address must be blocked or stalled: {address}"
                    )
                if row["boundary_status"] != "EXACT" or int(row["size_bytes"]) <= 0:
                    raise ValueError(f"recovery address lacks an EXACT boundary: {address}")
                if int(row["size_bytes"]) % 4:
                    raise ValueError(f"recovery address has a non-word boundary: {address}")
                if row["owner"] is not None or (
                    row["lease_until"] is not None and float(row["lease_until"]) > now
                ):
                    raise ValueError(f"recovery address still has an active lease: {address}")
                best = json.loads(row["best_result_json"])
                if best.get("status") == "MATCHED":
                    raise ValueError(f"MATCHED candidate cannot be reopened: {address}")
                if int(row["attempt_count"]) >= max_attempts_per_candidate:
                    raise ValueError(
                        f"recovery attempt limit {max_attempts_per_candidate} does not exceed "
                        f"the preserved history for {address} ({row['attempt_count']})"
                    )
                rows[address] = row

            for address, reason in normalized.items():
                if address not in rows:
                    continue
                row = rows[address]
                checkpoint = json.loads(row["checkpoint_json"])
                checkpoint["recovery_reason"] = f"{campaign_id}: {reason}"
                encoded = _json_dump(_sanitize_checkpoint(checkpoint, trusted_evidence=True))
                if len(encoded) > 128_000:
                    raise ValueError("recovery checkpoint exceeds 128 KiB")
                changed = db.execute(
                    """UPDATE candidates SET status='pending',owner=NULL,provider=NULL,
                       lease_until=NULL,preferred_provider=NULL,available_at=?,checkpoint_json=?,
                       updated_at=? WHERE address=? AND status IN ('blocked','stalled')
                       AND owner IS NULL""",
                    (now, encoded, now, address),
                ).rowcount
                if changed != 1:
                    raise ValueError(f"recovery address changed while validating its lease: {address}")
                self._event(db, "candidate_reopened", address=address)
                reopened.append(address)
            db.commit()
        return reopened

    def record_local_match_experiment(
        self,
        address: str,
        *,
        worker_id: str,
        worktree: Path,
        source_relative: str,
        report_relatives: Sequence[str],
    ) -> dict[str, Any]:
        """Attach a deterministic local matcher result without changing campaign attempts or best."""
        try:
            numeric_address = int(address, 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("local experiment address must be hexadecimal") from exc
        address = f"0x{numeric_address:x}"
        if not re.fullmatch(r"[a-z0-9-]+", worker_id):
            raise ValueError("local experiment worker id is invalid")
        experiment_prefix = f"decomp-campaign/experiments/{address.removeprefix('0x')}/"
        source_relative = source_relative.replace("\\", "/")
        if not source_relative.startswith(experiment_prefix):
            raise ValueError("local experiment source must remain in its build experiment directory")
        if len(report_relatives) != 2:
            raise ValueError("a local matched experiment requires two independent matcher reports")
        normalized_reports = [item.replace("\\", "/") for item in report_relatives]
        if any(not item.startswith(experiment_prefix) for item in normalized_reports):
            raise ValueError("local experiment reports must remain beside their build experiment")

        task = self.get_task(address)
        if task["boundary_status"] != "EXACT":
            raise ValueError("local matcher experiments require an exact campaign boundary")
        source = campaign_build_path(worktree, source_relative)
        if source.is_symlink() or not source.is_file() or source.stat().st_size > 1_000_000:
            raise ValueError("local experiment source is missing, unsafe, or too large")
        source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
        reports = []
        for relative in normalized_reports:
            report_path = campaign_build_path(worktree, relative)
            if report_path.is_symlink() or not report_path.is_file() or report_path.stat().st_size > 2_000_000:
                raise ValueError("local experiment matcher report is missing, unsafe, or too large")
            report = json.loads(report_path.read_text(encoding="utf-8"))
            _validate_complete_matcher_report(
                report,
                expected_address=numeric_address,
                expected_size=int(task["size_bytes"]),
                expected_source_sha256=source_sha256,
            )
            if not is_strict_match(
                report,
                expected_address=numeric_address,
                expected_size=int(task["size_bytes"]),
            ):
                raise ValueError("local experiment must be a complete MATCHED result")
            reports.append(report)
        object_hashes = [report["provenance"]["object_sha256"] for report in reports]
        if object_hashes[0] != object_hashes[1]:
            raise ValueError("local matched experiment is not deterministic across both builds")

        report_paths = [f"build/{item}" for item in normalized_reports]
        summary = _sanitize_match_checkpoint(
            {
                "origin_kind": "local_experiment",
                "worker_id": worker_id,
                "source_path": f"build/{source_relative}",
                "source_sha256": source_sha256,
                "status": "MATCHED",
                "matching_words": reports[0]["match"]["matching_words"],
                "total_words": reports[0]["match"]["total_words"],
                "difference_count": 0,
                "difference_indices": [],
                "object_sha256": object_hashes[0],
                "object_sha256s": object_hashes,
                "report_path": report_paths[0],
                "report_paths": report_paths,
                "producer_worker_id": worker_id,
                "producer_provider": "local-mwcc-matcher",
                "producer_session_id": "",
                "producer_attempt_number": 0,
            }
        )

        now = time.time()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT status,boundary_status,owner,lease_until,checkpoint_json FROM candidates WHERE address=?",
                (address,),
            ).fetchone()
            if row is None or row["boundary_status"] != "EXACT":
                raise ValueError("local experiment candidate is missing or no longer EXACT")
            if row["status"] == "running" or row["owner"] is not None or (
                row["lease_until"] is not None and float(row["lease_until"]) > now
            ):
                raise ValueError("cannot record a local experiment while the candidate has an active lease")
            checkpoint = json.loads(row["checkpoint_json"])
            experiments = checkpoint.get("local_experiments", [])
            experiments = experiments if isinstance(experiments, list) else []
            for existing in experiments:
                if isinstance(existing, dict) and existing.get("source_sha256") == source_sha256:
                    if existing == summary:
                        db.commit()
                        return summary
                    raise ValueError("a different local experiment record already uses this source hash")
            if len(experiments) >= 8:
                raise ValueError("local experiment checkpoint is full")
            checkpoint["local_experiments"] = [*experiments, summary]
            encoded = _json_dump(_sanitize_checkpoint(checkpoint, trusted_evidence=True))
            if len(encoded) > 128_000:
                raise ValueError("checkpoint metadata exceeds 128 KiB")
            db.execute(
                "UPDATE candidates SET checkpoint_json=?,updated_at=? WHERE address=?",
                (encoded, now, address),
            )
            self._event(db, "local_experiment_recorded", address=address, worker_id=worker_id)
            db.commit()
        return summary

    def record_local_recovery_result(
        self,
        address: str,
        *,
        worktree: Path,
        source_relative: str,
        report_relative: str,
        recovery_reason: str,
    ) -> dict[str, Any]:
        """Record one full local NONMATCHING/INCONCLUSIVE comparison, never as best or attempt."""
        numeric_address = int(_normalize_eboot_address(address), 16)
        address = f"0x{numeric_address:x}"
        prefix = f"decomp-campaign/experiments/{numeric_address:x}/"
        source_relative = source_relative.replace("\\", "/")
        report_relative = report_relative.replace("\\", "/")
        if not source_relative.startswith(prefix) or not report_relative.startswith(prefix):
            raise ValueError("local recovery evidence must remain in its address experiment directory")
        reason = _safe_text(recovery_reason, 600).strip()
        if not reason:
            raise ValueError("local recovery evidence requires a concrete reason")
        task = self.get_task(address)
        if task["status"] == "matched" or task["boundary_status"] != "EXACT":
            raise ValueError("local recovery requires an uncertified candidate with an EXACT boundary")
        source = campaign_build_path(worktree, source_relative)
        report_path = campaign_build_path(worktree, report_relative)
        if (
            source.is_symlink()
            or not source.is_file()
            or source.stat().st_size > 1_000_000
            or report_path.is_symlink()
            or not report_path.is_file()
            or report_path.stat().st_size > 2_000_000
        ):
            raise ValueError("local recovery source/report is missing, unsafe, or too large")
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        report = json.loads(report_path.read_text(encoding="utf-8"))
        _validate_complete_matcher_report(
            report,
            expected_address=numeric_address,
            expected_size=int(task["size_bytes"]),
            expected_source_sha256=source_hash,
        )
        if report.get("status") not in {"NONMATCHING", "INCONCLUSIVE"}:
            raise ValueError("one local full comparison can record only NONMATCHING or INCONCLUSIVE")
        evidence_path = f"build/{report_relative}"
        result = {
            "status": report["status"],
            "source_sha256": source_hash,
            "matching_words": report["match"].get("matching_words", -1),
            "total_words": report["match"].get("total_words", int(task["size_bytes"]) // 4),
            "build_sha256": [report["provenance"]["object_sha256"]],
            "reports": [{**report, "report_path": evidence_path}],
            "campaign_origin": {
                "worker_id": "experiments",
                "provider": "local-mwcc-matcher",
                "session_id": "",
                "attempt_number": 0,
            },
        }
        summary = _match_checkpoint_summary(result, fallback_report_path=evidence_path)
        summary.update(
            {
                "origin_kind": "local_recovery",
                "worker_id": "experiments",
                "source_path": f"build/{source_relative}",
                "recovery_reason": reason,
            }
        )
        summary = _sanitize_match_checkpoint(summary)

        now = time.time()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT status,boundary_status,owner,lease_until,checkpoint_json
                   FROM candidates WHERE address=?""",
                (address,),
            ).fetchone()
            if row is None or row["boundary_status"] != "EXACT" or row["status"] == "matched":
                raise ValueError("candidate changed or was certified during local recovery")
            if row["owner"] is not None or (
                row["lease_until"] is not None and float(row["lease_until"]) > now
            ):
                raise ValueError("cannot record local recovery while the candidate has an active lease")
            checkpoint = json.loads(row["checkpoint_json"])
            recoveries = checkpoint.get("local_recoveries", [])
            recoveries = recoveries if isinstance(recoveries, list) else []
            for existing in recoveries:
                if (
                    isinstance(existing, dict)
                    and existing.get("source_sha256") == source_hash
                    and existing.get("report_path") == evidence_path
                ):
                    db.commit()
                    return _sanitize_match_checkpoint(existing)
            if len(recoveries) >= 16:
                raise ValueError("local recovery checkpoint is full")
            checkpoint["local_recoveries"] = [*recoveries, summary]
            checkpoint.pop("last_diagnostic_detail", None)
            encoded = _json_dump(_sanitize_checkpoint(checkpoint, trusted_evidence=True))
            if len(encoded) > 128_000:
                raise ValueError("local recovery checkpoint exceeds 128 KiB")
            db.execute(
                "UPDATE candidates SET checkpoint_json=?,updated_at=? WHERE address=?",
                (encoded, now, address),
            )
            self._event(db, "local_recovery_recorded", address=address, worker_id="experiments")
            db.commit()
        return summary

    def record_latest_recovered_source(
        self,
        address: str,
        *,
        repo_root: Path,
        source_relative: str,
    ) -> dict[str, str]:
        """Preserve a recovered hypothesis before matching, without changing best evidence."""
        numeric_address = int(_normalize_eboot_address(address), 16)
        address = f"0x{numeric_address:x}"
        prefix = f"decomp-campaign/experiments/{numeric_address:x}/"
        source_relative = source_relative.replace("\\", "/")
        if not source_relative.startswith(prefix):
            raise ValueError("recovered source must remain in its address experiment directory")
        source = campaign_build_path(repo_root, source_relative)
        if source.is_symlink() or not source.is_file() or source.stat().st_size > 1_000_000:
            raise ValueError("recovered source is missing, unsafe, or too large")
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        address_hex = f"{numeric_address:08x}"
        snapshot_relative = f"decomp-campaign/checkpoints/{address_hex}/{source_hash}.c"
        snapshot = campaign_build_path(repo_root, snapshot_relative)
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        if snapshot.is_symlink():
            raise ValueError("recovered source checkpoint path is a symlink")
        if snapshot.exists():
            if not snapshot.is_file() or hashlib.sha256(snapshot.read_bytes()).hexdigest() != source_hash:
                raise ValueError("content-addressed recovered source checkpoint is corrupt")
        else:
            temporary = snapshot.with_name(snapshot.name + ".recover.tmp")
            if temporary.exists() or temporary.is_symlink():
                raise ValueError("refusing to overwrite a recovered source checkpoint temporary")
            shutil.copyfile(source, temporary)
            if hashlib.sha256(temporary.read_bytes()).hexdigest() != source_hash:
                temporary.unlink(missing_ok=True)
                raise ValueError("recovered source checkpoint failed its hash check")
            os.replace(temporary, snapshot)

        now = time.time()
        checkpoint_update = {
            "source_path": f"decomp/src/eboot/func_{numeric_address:08X}.c",
            "source_sha256": source_hash,
            "latest_source_snapshot": snapshot_relative,
        }
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT status,boundary_status,owner,lease_until,checkpoint_json
                   FROM candidates WHERE address=?""",
                (address,),
            ).fetchone()
            if row is None or row["boundary_status"] != "EXACT" or row["status"] == "matched":
                raise ValueError("recovered-source candidate changed or was certified")
            if row["owner"] is not None or (
                row["lease_until"] is not None and float(row["lease_until"]) > now
            ):
                raise ValueError("cannot attach a recovered source during an active lease")
            checkpoint = json.loads(row["checkpoint_json"])
            if (
                checkpoint.get("source_sha256") == source_hash
                and checkpoint.get("latest_source_snapshot") == snapshot_relative
            ):
                db.commit()
                return checkpoint_update
            checkpoint.update(checkpoint_update)
            encoded = _json_dump(_sanitize_checkpoint(checkpoint, trusted_evidence=True))
            if len(encoded) > 128_000:
                raise ValueError("recovered source checkpoint exceeds 128 KiB")
            db.execute(
                "UPDATE candidates SET checkpoint_json=?,updated_at=? WHERE address=?",
                (encoded, now, address),
            )
            self._event(db, "local_source_recovered", address=address, worker_id="experiments")
            db.commit()
        return checkpoint_update

    def record_local_recovery_diagnostic(
        self,
        address: str,
        *,
        diagnostic_stage: str,
        diagnostic_code: str,
        excerpt: str,
    ) -> dict[str, str]:
        """Attach a sanitized local tool diagnostic without modifying attempt history."""
        normalized = _normalize_eboot_address(address)
        if DIAGNOSTIC_CODES.get(diagnostic_code) != diagnostic_stage:
            raise ValueError("local recovery diagnostic code/stage is invalid")
        detail = _sanitize_checkpoint(
            {
                "last_diagnostic_detail": {
                    "stage": diagnostic_stage,
                    "code": diagnostic_code,
                    "excerpt": excerpt,
                }
            },
            trusted_evidence=True,
        ).get("last_diagnostic_detail")
        if not isinstance(detail, dict):
            raise ValueError("local recovery diagnostic could not be safely summarized")
        now = time.time()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT status,boundary_status,owner,lease_until,checkpoint_json
                   FROM candidates WHERE address=?""",
                (normalized,),
            ).fetchone()
            if row is None or row["boundary_status"] != "EXACT" or row["status"] == "matched":
                raise ValueError("local recovery diagnostic target is not an uncertified EXACT candidate")
            if row["owner"] is not None or (
                row["lease_until"] is not None and float(row["lease_until"]) > now
            ):
                raise ValueError("cannot attach a local diagnostic during an active lease")
            checkpoint = json.loads(row["checkpoint_json"])
            checkpoint["last_diagnostic"] = {
                "stage": diagnostic_stage,
                "code": diagnostic_code,
            }
            checkpoint["last_diagnostic_detail"] = detail
            encoded = _json_dump(_sanitize_checkpoint(checkpoint, trusted_evidence=True))
            if len(encoded) > 128_000:
                raise ValueError("local recovery diagnostic checkpoint exceeds 128 KiB")
            db.execute(
                "UPDATE candidates SET checkpoint_json=?,updated_at=? WHERE address=?",
                (encoded, now, normalized),
            )
            self._event(db, "local_recovery_diagnostic", address=normalized, worker_id="experiments")
            db.commit()
        return detail

    def attach_local_ghidra_cache(
        self,
        address: str,
        *,
        worker_id: str,
        worktree: Path,
        log_relative: str,
        log_sha256: str,
    ) -> bool:
        """Attach a copied, hash-validated exact Ghidra log without changing attempt history."""
        normalized = _normalize_eboot_address(address)
        if not re.fullmatch(r"[a-z0-9-]+", worker_id):
            raise ValueError("cached Ghidra worker id is invalid")
        relative = log_relative.replace("\\", "/")
        expected_prefix = f"decomp-campaign/{worker_id}/{normalized.removeprefix('0x')}/evidence/"
        if not relative.startswith(expected_prefix) or ".." in Path(relative).parts:
            raise ValueError("copied Ghidra log is outside its worker/address evidence")
        if not HEX_SHA256.fullmatch(log_sha256):
            raise ValueError("copied Ghidra log hash is invalid")
        task = self.get_task(normalized)
        if task["status"] == "matched" or task["boundary_status"] != "EXACT":
            raise ValueError("cached Ghidra evidence requires an uncertified EXACT candidate")
        claim = Claim(
            normalized,
            int(task["size_bytes"]),
            task["nid"],
            int(task["priority"]),
            "EXACT",
            worker_id,
            "local-ghidra",
            None,
            int(task["attempt_count"]),
            0,
            {
                "ghidra_log_path": relative,
                "ghidra_log_sha256": log_sha256,
            },
            {},
        )
        validated_cached_ghidra_boundary(worktree, claim)
        now = time.time()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT status,boundary_status,owner,lease_until,checkpoint_json
                   FROM candidates WHERE address=?""",
                (normalized,),
            ).fetchone()
            if row is None or row["boundary_status"] != "EXACT" or row["status"] == "matched":
                raise ValueError("candidate changed or was certified while attaching Ghidra evidence")
            if row["owner"] is not None or (
                row["lease_until"] is not None and float(row["lease_until"]) > now
            ):
                raise ValueError("cannot attach Ghidra evidence during an active lease")
            checkpoint = json.loads(row["checkpoint_json"])
            if (
                checkpoint.get("ghidra_log_path") == relative
                and checkpoint.get("ghidra_log_sha256") == log_sha256
            ):
                db.commit()
                return False
            checkpoint.update(
                {
                    "ghidra_log_path": relative,
                    "ghidra_log_sha256": log_sha256,
                    "boundary_status": "EXACT",
                }
            )
            evidence_paths = checkpoint.get("evidence_paths", [])
            if not isinstance(evidence_paths, list):
                evidence_paths = []
            checkpoint["evidence_paths"] = list(
                dict.fromkeys([*evidence_paths, f"build/{relative}"])
            )[:40]
            encoded = _json_dump(_sanitize_checkpoint(checkpoint, trusted_evidence=True))
            if len(encoded) > 128_000:
                raise ValueError("Ghidra evidence checkpoint exceeds 128 KiB")
            db.execute(
                "UPDATE candidates SET checkpoint_json=?,updated_at=? WHERE address=?",
                (encoded, now, normalized),
            )
            self._event(db, "local_ghidra_evidence_attached", address=normalized, worker_id=worker_id)
            db.commit()
        return True

    def get_task(self, address: str) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute("SELECT * FROM candidates WHERE address=?", (address.lower(),)).fetchone()
        if row is None:
            raise KeyError(address)
        result = dict(row)
        for source, target in (
            ("checkpoint_json", "checkpoint"),
            ("best_result_json", "best_result"),
            ("evidence_json", "evidence"),
        ):
            result[target] = json.loads(result.pop(source))
        return result

    def list_tasks(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            addresses = [row[0] for row in db.execute("SELECT address FROM candidates ORDER BY priority DESC,address")]
        return [self.get_task(address) for address in addresses]

    def list_attempts(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM attempts ORDER BY id").fetchall()
            return [dict(row) for row in rows]

    def list_recent_events(self, *, limit: int = 40) -> list[dict[str, Any]]:
        limit = min(100, max(1, int(limit)))
        with self._connect() as db:
            rows = db.execute(
                "SELECT created_at,kind,address,worker_id,provider,session_id "
                "FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def attempt_summary(self) -> dict[str, dict[str, int]]:
        summary: dict[str, dict[str, int]] = {}
        with self._connect() as db:
            rows = db.execute(
                "SELECT provider,outcome,COUNT(*) AS count FROM attempts GROUP BY provider,outcome"
            ).fetchall()
        for row in rows:
            provider = str(row["provider"])
            outcome = str(row["outcome"])
            summary.setdefault(provider, {})[outcome] = int(row["count"])
        return summary

    def integrity_check(self) -> str:
        with self._connect() as db:
            return str(db.execute("PRAGMA integrity_check").fetchone()[0])

    def provider_status(self, provider: str) -> str:
        with self._connect() as db:
            row = db.execute("SELECT status FROM providers WHERE provider=?", (provider,)).fetchone()
            return "active" if row is None else str(row[0])

    def record_integration_result(
        self,
        address: str,
        status: str,
        *,
        diagnostic_code: str | None = None,
    ) -> None:
        if status not in {"promoted", "blocked"}:
            raise ValueError("integration status must be promoted or blocked")
        if status == "blocked" and diagnostic_code != "integration_failed":
            raise ValueError("blocked integration requires a stable integration diagnostic")
        normalized = f"0x{int(address, 0):x}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT status,evidence_json,best_result_json FROM candidates WHERE address=?",
                (normalized,),
            ).fetchone()
            if row is None or row["status"] != "matched":
                raise ValueError("only a campaign-certified MATCHED source can record integration")
            evidence = json.loads(row["evidence_json"])
            evidence["promotion"] = {
                "status": status,
                **({"diagnostic": diagnostic_code} if diagnostic_code else {}),
            }
            db.execute(
                "UPDATE candidates SET evidence_json=?,updated_at=? WHERE address=?",
                (_json_dump(evidence), time.time(), normalized),
            )
            best_result = json.loads(row["best_result_json"])
            origin = best_result.get("campaign_origin", {}) if isinstance(best_result, dict) else {}
            self._event(
                db,
                "integration_" + status,
                address=normalized,
                worker_id=origin.get("worker_id") if isinstance(origin, dict) else None,
                provider=origin.get("provider") if isinstance(origin, dict) else None,
                session_id=origin.get("session_id") if isinstance(origin, dict) else None,
            )
            db.commit()

    def provider_resume_at(self, provider: str) -> float | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT status,resume_at FROM providers WHERE provider=?", (provider,)
            ).fetchone()
        if row is None or row["status"] not in {"rate_limited", "network_backoff"}:
            return None
        return None if row["resume_at"] is None else float(row["resume_at"])

    def total_attempt_count(self) -> int:
        with self._connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0])

    def next_eligible_time(
        self,
        provider: str,
        *,
        max_attempts_per_candidate: int,
        eligible_addresses: Sequence[str] | None = None,
        excluded_addresses: Collection[str] = (),
    ) -> float | None:
        now = time.time()
        normalized_excluded = sorted(
            {
                _normalize_eboot_address(value, label="excluded certified address")
                for value in excluded_addresses
            }
        )
        with self._connect() as db:
            state = db.execute(
                "SELECT status,resume_at FROM providers WHERE provider=?", (provider,)
            ).fetchone()
            provider_status = "active" if state is None else str(state["status"])
            if provider_status in {"suspended_quota", "blocked_auth", "blocked"}:
                return None
            address_clause = ""
            parameters: list[Any] = [max_attempts_per_candidate, provider]
            if eligible_addresses is not None:
                normalized = sorted({str(item).lower() for item in eligible_addresses})
                if not normalized:
                    return None
                address_clause = " AND address IN (" + ",".join("?" for _ in normalized) + ")"
                parameters.extend(normalized)
            if normalized_excluded:
                address_clause += " AND address NOT IN (" + ",".join(
                    "?" for _ in normalized_excluded
                ) + ")"
                parameters.extend(normalized_excluded)
            row = db.execute(
                """SELECT MIN(available_at) FROM candidates
                   WHERE status='pending' AND boundary_status='EXACT' AND attempt_count<?
                     AND (preferred_provider IS NULL OR preferred_provider=?)"""
                + address_clause,
                parameters,
            ).fetchone()
            if row is None or row[0] is None:
                return None
            available_at = float(row[0])
            resume_at = None
            if provider_status in {"rate_limited", "network_backoff"}:
                resume_at = None if state is None or state["resume_at"] is None else float(state["resume_at"])
                if resume_at is None:
                    return None
            return max(available_at, resume_at or now)

def _safe_child_environment() -> dict[str, str]:
    env = os.environ.copy()
    for key in list(env):
        if any(part in key.upper() for part in SECRET_ENV_PARTS):
            env.pop(key, None)
    return env


def _drain_bounded(stream: Any, output: bytearray, limit: int) -> None:
    while True:
        chunk = stream.read(8192)
        if not chunk:
            return
        remaining = limit - len(output)
        if remaining > 0:
            output.extend(chunk[:remaining])


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
        except OSError:
            pass
    if os.name == "nt":
        taskkill = shutil.which("taskkill.exe")
        if taskkill:
            try:
                subprocess.run(
                    [taskkill, "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                pass


def _run_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    output_limit: int,
    stop_requested: Callable[[], bool],
    deadline: float | None = None,
) -> WorkResult:
    if not argv or not cwd.is_dir():
        raise ValueError("process command and worktree directory are required")
    process = subprocess.Popen(
        list(argv),
        cwd=cwd,
        env=_safe_child_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    assert process.stdout is not None and process.stderr is not None
    readers = [
        threading.Thread(target=_drain_bounded, args=(process.stdout, stdout_buffer, output_limit), daemon=True),
        threading.Thread(target=_drain_bounded, args=(process.stderr, stderr_buffer, output_limit), daemon=True),
    ]
    for thread in readers:
        thread.start()
    started = time.monotonic()
    timed_out = interrupted = False
    while process.poll() is None:
        if stop_requested():
            interrupted = True
            _terminate_process(process)
            break
        if time.monotonic() - started >= timeout or (deadline is not None and time.monotonic() >= deadline):
            timed_out = True
            _terminate_process(process)
            break
        time.sleep(0.1)
    try:
        process.wait(timeout=4)
    except subprocess.TimeoutExpired:
        _terminate_process(process)
    for thread in readers:
        thread.join(timeout=4)
    return WorkResult(
        returncode=process.returncode if process.returncode is not None else -1,
        stdout=stdout_buffer.decode("utf-8", errors="replace"),
        stderr=stderr_buffer.decode("utf-8", errors="replace"),
        timed_out=timed_out,
        interrupted=interrupted,
    )


def _extract_checkpoint(output: str) -> dict[str, Any]:
    texts: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("type") in {"text", "text_delta"} and isinstance(value.get("text"), str):
                texts.append(value["text"])
            if isinstance(value.get("checkpoint"), dict):
                texts.append(json.dumps({"checkpoint": value["checkpoint"]}))
            for item in value.values():
                if isinstance(item, (dict, list)):
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    try:
        walk(json.loads(output))
    except json.JSONDecodeError:
        for line in output.splitlines():
            try:
                walk(json.loads(line))
            except json.JSONDecodeError:
                continue
    for text in reversed(texts):
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r"\{\s*\"checkpoint\"\s*:", text)
            if not match:
                continue
            try:
                value, _ = json.JSONDecoder().raw_decode(text, match.start())
            except json.JSONDecodeError:
                continue
        if isinstance(value, dict) and isinstance(value.get("checkpoint"), dict):
            checkpoint = dict(value["checkpoint"])
            if "next_experiment" not in checkpoint:
                checkpoint["next_experiment"] = "Review saved source and verified matcher report."
            return checkpoint
    raise ValueError("OpenCode did not return the required JSON checkpoint")


def _prompt(claim: Claim, checkpoint: dict[str, Any], worktree: Path) -> str:
    compact_checkpoint = {
        key: checkpoint[key]
        for key in (
            "next_experiment",
            "source_sha256",
            "best_source_sha256",
            "best_source_snapshot",
            "best_match",
            "last_attempt",
            "last_diagnostic_detail",
            "local_experiments",
            "local_recoveries",
            "ghidra_log_path",
            "historical_hypothesis",
        )
        if key in checkpoint
    }
    local_experiments = compact_checkpoint.get("local_experiments")
    if isinstance(local_experiments, list):
        compact_checkpoint["local_experiments"] = [
            item
            for item in local_experiments
            if isinstance(item, dict)
            and item.get("worker_id") == claim.worker_id
            and item.get("status") == "MATCHED"
        ]
    local_recoveries = compact_checkpoint.get("local_recoveries")
    if isinstance(local_recoveries, list):
        available_recoveries = []
        for item in local_recoveries[-4:]:
            if (
                not isinstance(item, dict)
                or item.get("origin_kind") != "local_recovery"
                or not isinstance(item.get("source_path"), str)
                or not isinstance(item.get("report_path"), str)
                or not item["source_path"].startswith("build/decomp-campaign/experiments/")
                or not item["report_path"].startswith("build/decomp-campaign/experiments/")
            ):
                continue
            try:
                source = campaign_build_path(
                    worktree, item["source_path"].removeprefix("build/")
                )
                report = campaign_build_path(
                    worktree, item["report_path"].removeprefix("build/")
                )
                if (
                    source.is_symlink()
                    or not source.is_file()
                    or report.is_symlink()
                    or not report.is_file()
                    or hashlib.sha256(source.read_bytes()).hexdigest()
                    != item.get("source_sha256")
                ):
                    continue
                _validate_complete_matcher_report(
                    json.loads(report.read_text(encoding="utf-8")),
                    expected_address=claim.numeric_address,
                    expected_size=claim.size_bytes,
                    expected_source_sha256=str(item["source_sha256"]),
                )
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
            available_recoveries.append(item)
        compact_checkpoint["local_recoveries"] = available_recoveries
    return (
        "Reconstruct only this EBOOT function in the isolated worker worktree. Treat local "
        "MIPS instructions and full-object matcher results as primary evidence; Ghidra's C "
        "decompilation is an initial hypothesis, not proof of equivalence. First read the "
        "complete Ghidra log at the checkpoint path: it contains the verified boundary, "
        "instruction disassembly, and decompiled C. Then inspect "
        "build/seto035/export-triage.json for the export/NID, proven call sites, relocations, "
         "and references; follow only evidence paths actually present in the supplied task "
         "evidence. Review the current candidate source and the best prior checkpoint/source "
         "hash before changing anything. `best_match` is the strongest verified result; "
          "`last_attempt` is the latest result and may be worse. Read their exact matcher report "
          "paths and preserve a stronger hypothesis while recording the first causal divergence. "
          "A bounded `last_diagnostic_detail` is a sanitized local MWCC/matcher excerpt; use it "
          "to make a specific correction, not as evidence of equivalence. "
          "`local_recoveries` are independently validated local source/report pairs copied into "
          "this worktree; read the cited report and source, preserve any stronger hypothesis, "
          "and do not treat one NONMATCHING/INCONCLUSIVE comparison as certification. "
         "Local matcher experiments are separate worktree evidence, not the campaign best: read "
         "only listed source/report paths, keep them unchanged, and let the orchestrator verify "
         "any source you adopt. "
         "A supplied historical hypothesis is explicitly NONMATCHING "
         "and not certified; use it as a lead only and never promote it automatically.\n\n"
         f"The required externally visible C/linker symbol is exactly "
         f"func_{claim.numeric_address:08X}. Do not copy Ghidra's autogenerated FUN_ label, "
         "change capitalization, or rely on automatic candidate-symbol fallback.\n\n"
         "AIMemory retrieval via memory_query/memory_read_page is optional supporting context. "
        "Use it only if those read-only tools are actually available; if retrieval is unavailable, "
        "report that limitation and continue from sufficient local evidence. It is not a "
        "prerequisite. Never write, annotate, or send anything to AIMemory. Do not invoke shell "
        "commands, subagents, Git mutations, or paths outside this worktree. Edit only the "
        "assigned C source and put auxiliary evidence below this worker's build directory. "
        "Do not modify the matcher, certified sources, tests, or documentation. The orchestrator "
        "independently compiles and compares the complete function with the production matcher "
        "and MWCC PSP 3.0.1, requiring two deterministic full builds for certification; never "
        "claim MATCHED from partial words or an incomplete object. Do not invent semantics when "
        "the evidence is insufficient.\n\n"
        "Return one JSON object with a top-level checkpoint containing next_experiment, "
        "limitations, and evidence_paths. Include source_path and source_sha256 only when a "
        "candidate source was actually produced. Do not include credentials, full prompts, "
        "stdout dumps, private input contents, or media contents.\n\n"
        f"Address: {claim.address}; size currently listed: {claim.size_bytes} bytes; "
        f"NID: {claim.nid}; boundary: {claim.boundary_status}; priority: {claim.priority}.\n"
        f"Worktree: {worktree}\n"
        f"Task evidence/build root: build/decomp-campaign/{claim.worker_id}/"
        f"{claim.address.removeprefix('0x')} (paths in JSON must be repo-relative).\n"
        f"Candidate source path: decomp/src/eboot/func_{claim.numeric_address:08X}.c.\n"
        f"Local export/reference evidence: {json.dumps(claim.evidence, sort_keys=True)}\n"
        f"Previous local checkpoint: {json.dumps(compact_checkpoint, sort_keys=True)}\n"
        f"Session: {claim.session_id}. If local evidence is insufficient, state exactly what is "
        "missing and propose a bounded next experiment instead of guessing."
    )


class CampaignRunner:
    """Run independent OpenCode subprocesses against separate worktrees."""

    def __init__(
        self,
        store: CampaignStore,
        *,
        opencode_command: Sequence[str],
        worktrees: dict[str, Path],
        verifier: Callable[[Path, Claim, dict[str, Any]], dict[str, Any]] | None = None,
        timeout_seconds: float = 900,
        output_limit: int = 1_048_576,
        max_attempts_without_progress: int = 3,
        max_attempts_per_candidate: int = 8,
        max_consecutive_attempts: int = 3,
        max_duration_seconds: float | None = None,
        lease_seconds: float = 3660,
        ghidra_home: str | None = None,
        ghidra_windows_home: str | None = None,
        wsl_distro: str = "Ubuntu",
        expected_eboot_sha256: str | None = None,
        checkpoint_repo_root: Path | None = None,
        max_retry_after_seconds: float = 900,
        candidate_addresses: Iterable[str] | None = None,
        excluded_addresses: Iterable[str] = (),
        provider_parallelism: dict[str, int] | None = None,
        ghidra_parallelism: int = 1,
        matcher_parallelism: int = 1,
        promotion_callback: Callable[[str, float | None], dict[str, Any]] | None = None,
        known_exact_ranges: Sequence[dict[str, Any]] = (),
    ):
        self.store = store
        self.command = list(opencode_command)
        self.worktrees = {key: Path(value) for key, value in worktrees.items()}
        self.verifier = verifier or self._verify_with_matcher_twice
        self.auto_preflight = verifier is None
        self.timeout_seconds = timeout_seconds
        self.output_limit = output_limit
        self.max_attempts_without_progress = max_attempts_without_progress
        self.max_attempts_per_candidate = max_attempts_per_candidate
        self.max_consecutive_attempts = max(1, int(max_consecutive_attempts))
        self.max_duration_seconds = max_duration_seconds
        self.lease_seconds = max(60.0, lease_seconds)
        self.ghidra_home = ghidra_home
        self.ghidra_windows_home = ghidra_windows_home
        self.wsl_distro = wsl_distro
        self.expected_eboot_sha256 = expected_eboot_sha256
        self.max_retry_after_seconds = max(1.0, max_retry_after_seconds)
        self.provider_parallelism = dict(provider_parallelism or {})
        self.provider_slots: dict[str, threading.BoundedSemaphore] = {}
        self.ghidra_parallelism = max(1, int(ghidra_parallelism))
        self.matcher_parallelism = max(1, int(matcher_parallelism))
        self.ghidra_slots = threading.BoundedSemaphore(self.ghidra_parallelism)
        self.matcher_slots = threading.BoundedSemaphore(self.matcher_parallelism)
        self.promotion_callback = promotion_callback
        self.promotion_lock = threading.Lock()
        self.known_exact_ranges: list[tuple[int, int]] = []
        for item in known_exact_ranges:
            try:
                start = int(str(item["address"]), 0)
                size = int(item["size_bytes"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("known exact boundary metadata is malformed") from exc
            if size <= 0 or size % 4:
                raise ValueError("known exact boundary sizes must be positive word multiples")
            self.known_exact_ranges.append((start, size))
        self.candidate_addresses = (
            None
            if candidate_addresses is None
            else {f"0x{int(address, 0):x}" for address in candidate_addresses}
        )
        self.excluded_addresses = frozenset(
            _normalize_eboot_address(address, label="excluded certified address")
            for address in excluded_addresses
        )
        self.checkpoint_repo_root = (
            Path(checkpoint_repo_root).resolve(strict=True)
            if checkpoint_repo_root is not None
            else None
        )

    def _command(self) -> list[str]:
        command = list(self.command)
        if os.name == "nt":
            script_index = next(
                (index for index, item in enumerate(command) if item.lower().endswith(".ps1")),
                None,
            )
            wrapper_index = script_index
            if wrapper_index is None and command and command[0].lower().endswith((".cmd", ".bat")):
                wrapper_index = 0
            if wrapper_index is not None:
                wrapper = Path(command[wrapper_index])
                executable = (
                    wrapper.parent
                    / "node_modules"
                    / "@opencode"
                    / "cli"
                    / "bin"
                    / "opencode.exe"
                )
                if executable.is_file():
                    return [str(executable), *command[wrapper_index + 1 :]]
            if script_index == 0:
                powershell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
                if powershell is None:
                    raise FileNotFoundError("PowerShell is needed to invoke the installed OpenCode shim")
                return [powershell, "-NoProfile", "-File", command[0], *command[1:]]
        return command

    def _api_request(
        self, worktree: Path, args: Sequence[str], deadline: float | None
    ) -> WorkResult:
        result = _run_process(
            [*self._command(), "api", *args],
            cwd=worktree,
            timeout=min(30.0, self.timeout_seconds),
            output_limit=self.output_limit,
            stop_requested=self.store.stop_requested,
            deadline=deadline,
        )
        if result.interrupted:
            raise CampaignInterrupted
        if result.timed_out:
            raise ValueError("OpenCode session API timed out")
        return result

    @staticmethod
    def _session_data(result: WorkResult) -> dict[str, Any]:
        try:
            payload = json.loads(result.stdout)
            data = payload["data"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ValueError("OpenCode session API returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise ValueError("OpenCode session API returned invalid session data")
        return data

    @staticmethod
    def _session_id(value: Any) -> str:
        if not isinstance(value, str) or not re.fullmatch(r"ses_[A-Za-z0-9_-]+", value):
            raise ValueError("OpenCode did not return a valid session ID")
        return value

    @staticmethod
    def _same_location(data: dict[str, Any], worktree: Path) -> bool:
        location = data.get("location")
        directory = location.get("directory") if isinstance(location, dict) else None
        if not isinstance(directory, str):
            return False
        try:
            return os.path.normcase(str(Path(directory).resolve())) == os.path.normcase(
                str(worktree.resolve())
            )
        except OSError:
            return False

    @staticmethod
    def _session_model_matches(data: dict[str, Any], model: str) -> bool:
        provider_id, separator, model_id = model.partition("/")
        stored = data.get("model")
        return bool(
            separator
            and provider_id
            and model_id
            and isinstance(stored, dict)
            and stored.get("providerID") == provider_id
            and stored.get("id") == model_id
            and stored.get("variant", "default") in (None, "default")
        )

    def _create_session(
        self,
        claim: Claim,
        worktree: Path,
        deadline: float | None,
        *,
        agent: str = "seto-decomp-worker",
        model: str | None = None,
    ) -> str:
        payload: dict[str, Any] = {
            "title": f"Seto EBOOT {claim.address} {claim.worker_id}",
            "location": {"directory": str(worktree.resolve())},
            "agent": agent,
        }
        if model is not None:
            provider_id, separator, model_id = model.partition("/")
            if not separator or not provider_id or not model_id:
                raise ValueError("worker model must use provider/model form")
            payload["model"] = {"providerID": provider_id, "id": model_id}
        result = self._api_request(
            worktree,
            [
                "post",
                "/api/session",
                "--data",
                json.dumps(payload, separators=(",", ":")),
            ],
            deadline,
        )
        if result.returncode != 0:
            raise ValueError("OpenCode could not create a session")
        data = self._session_data(result)
        session_id = self._session_id(data.get("id"))
        if not self._same_location(data, worktree):
            raise ValueError("OpenCode created a session outside the worker worktree")
        return session_id

    def _ensure_session(
        self,
        claim: Claim,
        worktree: Path,
        deadline: float | None,
        *,
        agent: str = "seto-decomp-worker",
        model: str | None = None,
    ) -> Claim:
        """Reuse an existing provider session, or create/bind one via the V2 API."""
        session_id = claim.session_id
        if session_id and re.fullmatch(r"ses_[A-Za-z0-9_-]+", session_id):
            result = self._api_request(
                worktree, ["get", f"/api/session/{session_id}"], deadline
            )
            if result.returncode == 0:
                data = self._session_data(result)
                if (
                    self._session_id(data.get("id")) == session_id
                    and self._same_location(data, worktree)
                    and data.get("agent") == agent
                    and (model is None or self._session_model_matches(data, model))
                ):
                    return claim
            elif not (
                "SessionNotFoundError" in result.stdout
                and "404" in result.stderr
            ):
                raise ValueError("OpenCode could not validate the saved session")

        session_id = self._create_session(
            claim, worktree, deadline, agent=agent, model=model
        )
        return self.store.bind_session(claim, session_id)

    def _argv(self, worker: Worker, claim: Claim, prompt: str) -> list[str]:
        if claim.session_id is None:
            raise ValueError("OpenCode session must be created before running a prompt")
        return [
            *self._command(),
            "run",
            "--model",
            worker.model,
            "--agent",
            worker.agent,
            "--format",
            "json",
            "--session",
            claim.session_id,
            "--title",
            f"Seto EBOOT {claim.address} {worker.worker_id}",
            prompt,
        ]

    def _restore_best_source(self, worktree: Path, claim: Claim) -> None:
        if self.checkpoint_repo_root is None:
            return
        address = f"{claim.numeric_address:08X}"
        for hash_key, snapshot_key, label in (
            ("source_sha256", "latest_source_snapshot", "latest hypothesis"),
            ("best_source_sha256", "best_source_snapshot", "best verified source"),
        ):
            source_hash = claim.checkpoint.get(hash_key)
            snapshot_relative = claim.checkpoint.get(snapshot_key)
            if source_hash is None and snapshot_relative is None:
                continue
            if snapshot_key == "latest_source_snapshot" and snapshot_relative is None:
                continue
            if not isinstance(source_hash, str) or not HEX_SHA256.fullmatch(source_hash):
                raise ValueError(f"{label} checkpoint has no valid source SHA-256")
            expected_relative = (
                f"decomp-campaign/checkpoints/{address.lower()}/{source_hash}.c"
            )
            if snapshot_relative != expected_relative:
                raise ValueError(f"{label} checkpoint path does not match its address/hash")
            snapshot = campaign_build_path(self.checkpoint_repo_root, expected_relative)
            if snapshot.is_symlink() or not snapshot.is_file():
                raise ValueError(f"{label} checkpoint snapshot is missing or unsafe")
            if hashlib.sha256(snapshot.read_bytes()).hexdigest() != source_hash:
                raise ValueError(f"{label} checkpoint hash does not match its contents")
            source_relative = Path("decomp/src/eboot") / f"func_{address}.c"
            source = _safe_worktree_path(worktree, source_relative)
            source.parent.mkdir(parents=True, exist_ok=True)
            if source.is_file() and not source.is_symlink():
                if hashlib.sha256(source.read_bytes()).hexdigest() == source_hash:
                    return
            elif source.is_symlink():
                raise ValueError("candidate source path is a symlink")
            temporary = source.with_name(
                source.name + f".restore-{label.replace(' ', '-')}-{claim.attempt_number}.tmp"
            )
            if temporary.exists() or temporary.is_symlink():
                raise ValueError(f"refusing to overwrite an existing {label} restore temporary")
            shutil.copyfile(snapshot, temporary)
            if hashlib.sha256(temporary.read_bytes()).hexdigest() != source_hash:
                temporary.unlink(missing_ok=True)
                raise ValueError(f"restored {label} copy failed its hash check")
            os.replace(temporary, source)
            return

    def _snapshot_candidate_source(
        self,
        worktree: Path,
        claim: Claim,
        verification: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        if self.checkpoint_repo_root is None:
            return {}
        address = f"{claim.numeric_address:08X}"
        source = _safe_worktree_path(
            worktree, Path("decomp/src/eboot") / f"func_{address}.c"
        )
        if source.is_symlink() or not source.is_file():
            raise ValueError("candidate source for hypothesis snapshot is missing or unsafe")
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        if verification is not None and source_hash != verification.get("source_sha256"):
            raise ValueError("matcher source hash does not match the current candidate file")
        relative = f"decomp-campaign/checkpoints/{address.lower()}/{source_hash}.c"
        destination = campaign_build_path(self.checkpoint_repo_root, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_symlink():
            raise ValueError("best-source checkpoint destination is a symlink")
        if destination.exists():
            if not destination.is_file() or hashlib.sha256(destination.read_bytes()).hexdigest() != source_hash:
                raise ValueError("existing content-addressed source checkpoint is corrupt")
        else:
            temporary = destination.with_name(destination.name + ".tmp")
            if temporary.exists() or temporary.is_symlink():
                raise ValueError("refusing to overwrite a source-checkpoint temporary")
            shutil.copyfile(source, temporary)
            if hashlib.sha256(temporary.read_bytes()).hexdigest() != source_hash:
                temporary.unlink(missing_ok=True)
                raise ValueError("source checkpoint copy failed its hash check")
            os.replace(temporary, destination)
        if verification is not None:
            verification["source_snapshot_path"] = relative
        return {
            "source_path": f"decomp/src/eboot/func_{address}.c",
            "source_sha256": source_hash,
            "latest_source_snapshot": relative,
        }

    def _attach_historical_hypothesis(self, worktree: Path, claim: Claim) -> Claim:
        evidence = _copy_known_historical_hypothesis(
            self.checkpoint_repo_root or REPO_ROOT, worktree, claim
        )
        if evidence is None:
            return claim
        checkpoint = dict(claim.checkpoint)
        checkpoint["historical_hypothesis"] = evidence
        self.store.save_checkpoint(claim, checkpoint, trusted_evidence=True)
        return replace(claim, checkpoint=checkpoint)

    def _validate_boundary_nonoverlap(
        self, address: str, size_bytes: int
    ) -> None:
        start = int(address, 0)
        end = start + size_bytes
        ranges = list(self.known_exact_ranges)
        ranges.extend(
            (int(task["address"], 0), int(task["size_bytes"]))
            for task in self.store.list_tasks()
            if task["boundary_status"] == "EXACT" and task["address"] != address.lower()
        )
        for other_start, other_size in ranges:
            if other_start == start:
                continue
            other_end = other_start + other_size
            if start < other_end and other_start < end:
                raise ValueError(
                    f"Ghidra boundary {address} overlaps an existing EXACT function interval"
                )

    def _acquire_resource_slot(
        self, semaphore: threading.BoundedSemaphore, deadline: float | None
    ) -> bool:
        while not self.store.stop_requested():
            if deadline is not None and time.monotonic() >= deadline:
                return False
            if semaphore.acquire(timeout=0.25):
                return True
        return False

    def _run_limited_operation(
        self,
        semaphore: threading.BoundedSemaphore,
        resource: str,
        *,
        claim: Claim,
        operation: Callable[[], Any],
        deadline: float | None,
    ) -> Any:
        """Measure one Ghidra/matcher operation while its capacity slot is owned."""
        if resource not in {"ghidra", "matcher"}:
            raise ValueError("unsupported measured campaign resource")
        if not self._acquire_resource_slot(semaphore, deadline):
            raise CampaignInterrupted
        event_started = False
        try:
            self.store.record_event(
                f"{resource}_started",
                address=claim.address,
                worker_id=claim.worker_id,
                provider=claim.provider,
                session_id=claim.session_id,
            )
            event_started = True
            return operation()
        finally:
            try:
                if event_started:
                    self.store.record_event(
                        f"{resource}_finished",
                        address=claim.address,
                        worker_id=claim.worker_id,
                        provider=claim.provider,
                        session_id=claim.session_id,
                    )
            finally:
                semaphore.release()

    def _copy_cached_ghidra_evidence(
        self,
        worktree: Path,
        claim: Claim,
        *,
        source_worker: str,
        source_relative: str,
        source_sha256: str,
    ) -> dict[str, Any] | None:
        source_root = self.worktrees.get(source_worker)
        address = claim.address.removeprefix("0x")
        source_relative = source_relative.replace("\\", "/")
        expected_prefix = f"decomp-campaign/{source_worker}/{address}/evidence/"
        filename = source_relative.removeprefix(expected_prefix)
        if (
            source_root is None
            or not source_relative.startswith(expected_prefix)
            or not re.fullmatch(r"ghidra-(?:attempt-[1-9][0-9]*|run-[0-9a-f]{32})\.log", filename)
            or not HEX_SHA256.fullmatch(source_sha256)
        ):
            return None
        try:
            source = campaign_build_path(source_root, source_relative)
            if source.is_symlink() or not source.is_file() or source.stat().st_size > 2_000_000:
                return None
            source_content = source.read_bytes()
            if hashlib.sha256(source_content).hexdigest() != source_sha256:
                return None
            log_text = source_content.decode("utf-8", errors="replace")
            boundary = validate_ghidra_log(log_text, claim.numeric_address)
            if (
                boundary["size_bytes"] != claim.size_bytes
                or not _ghidra_log_has_reconstruction_details(log_text)
            ):
                return None
            local_relative = (
                f"decomp-campaign/{claim.worker_id}/{address}/evidence/"
                f"ghidra-cache-{source_sha256}.log"
            )
            target = campaign_build_path(worktree, local_relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                if (
                    target.is_symlink()
                    or not target.is_file()
                    or hashlib.sha256(target.read_bytes()).hexdigest() != source_sha256
                ):
                    return None
            else:
                temporary = target.with_name(target.name + ".tmp")
                if temporary.exists() or temporary.is_symlink():
                    return None
                temporary.write_bytes(source_content)
                if hashlib.sha256(temporary.read_bytes()).hexdigest() != source_sha256:
                    temporary.unlink(missing_ok=True)
                    return None
                os.replace(temporary, target)
            checkpoint = dict(claim.checkpoint)
            checkpoint.update(
                {
                    "ghidra_log_path": local_relative,
                    "ghidra_log_sha256": source_sha256,
                    "boundary_status": "EXACT",
                }
            )
            self.store.save_checkpoint(claim, checkpoint, trusted_evidence=True)
            claim.checkpoint.update(checkpoint)
            return boundary
        except (OSError, ValueError):
            return None

    def _prepare_claim(self, worktree: Path, claim: Claim, deadline: float | None) -> Claim:
        """Recheck export provenance and exact Ghidra body before any model call."""
        eboot = worktree / "private" / "decrypted" / "ULUS10136_EBOOT.elf"
        triage = worktree / "build" / "seto035" / "export-triage.json"
        if any(path.is_symlink() or not path.is_file() for path in (eboot, triage)):
            raise ValueError("private EBOOT or real export/import triage is missing/unsafe")
        if self.expected_eboot_sha256:
            observed = hashlib.sha256(eboot.read_bytes()).hexdigest()
            if observed != self.expected_eboot_sha256.lower():
                raise ValueError("local EBOOT hash differs from the certified baseline")
        validate_export_evidence(triage, claim.address, claim.nid)
        try:
            cached_boundary = validated_cached_ghidra_boundary(worktree, claim)
        except ValueError:
            # An invalid local cache is never trusted; try a hash-bound copy from
            # the worktree that originally ran Ghidra, then fall back to a fresh proof.
            cached_boundary = None
        if cached_boundary is None:
            log_relative = claim.checkpoint.get("ghidra_log_path")
            log_digest = claim.checkpoint.get("ghidra_log_sha256")
            if isinstance(log_relative, str) and isinstance(log_digest, str):
                parts = log_relative.replace("\\", "/").split("/")
                if len(parts) >= 5 and parts[0] == "decomp-campaign":
                    cached_boundary = self._copy_cached_ghidra_evidence(
                        worktree,
                        claim,
                        source_worker=parts[1],
                        source_relative=log_relative,
                        source_sha256=log_digest,
                    )
        if cached_boundary is None:
            prior_validation = claim.evidence.get("ghidra_validation")
            if isinstance(prior_validation, dict):
                source_worker = prior_validation.get("worker_id")
                source_relative = prior_validation.get("log_path")
                source_hash = prior_validation.get("log_sha256")
                if (
                    isinstance(source_worker, str)
                    and isinstance(source_relative, str)
                    and isinstance(source_hash, str)
                ):
                    cached_boundary = self._copy_cached_ghidra_evidence(
                        worktree,
                        claim,
                        source_worker=source_worker,
                        source_relative=source_relative,
                        source_sha256=source_hash,
                    )
        if cached_boundary is not None:
            self._validate_boundary_nonoverlap(
                claim.address, int(cached_boundary["size_bytes"])
            )
            cached_path = campaign_build_path(
                worktree, str(claim.checkpoint["ghidra_log_path"])
            )
            cached_text = cached_path.read_text(encoding="utf-8", errors="replace")
            if _ghidra_log_has_reconstruction_details(cached_text):
                return self._attach_historical_hypothesis(
                    worktree, replace(claim, checkpoint=dict(claim.checkpoint))
                )
        if os.name == "nt":
            if not self.ghidra_windows_home:
                raise ValueError("machine-local Windows Ghidra home is not configured")
        elif not self.ghidra_home or not self.ghidra_home.startswith("/"):
            raise ValueError("machine-local WSL/Linux Ghidra home is not configured")

        address = claim.address.removeprefix("0x")
        analysis_id = uuid.uuid4().hex
        project_relative = (
            f"decomp-campaign/{claim.worker_id}/{address}/ghidra-projects/"
            f"run-{analysis_id}"
        )
        log_relative = (
            f"decomp-campaign/{claim.worker_id}/{address}/evidence/"
            f"ghidra-run-{analysis_id}.log"
        )
        project_dir = campaign_build_path(worktree, project_relative)
        log_path = campaign_build_path(worktree, log_relative)
        if project_dir.exists() or project_dir.is_symlink() or log_path.exists() or log_path.is_symlink():
            raise ValueError("refusing to overwrite existing Ghidra project/evidence")
        project_dir.mkdir(parents=True, exist_ok=False)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        project_name = f"seto_eboot_{address}_run_{analysis_id}"
        script_dir = worktree / "scripts" / "ghidra"
        if os.name == "nt":
            ghidra_bat = Path(self.ghidra_windows_home) / "support" / "analyzeHeadless.bat"
            powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
            wrapper = worktree / "scripts" / "run_ghidra_headless.ps1"
            if powershell is None or ghidra_bat.is_symlink() or not ghidra_bat.is_file() or not wrapper.is_file():
                raise ValueError("Windows Ghidra headless launcher or safe wrapper is missing")
            argv = [
                powershell,
                "-NoProfile",
                "-File",
                str(wrapper),
                str(ghidra_bat),
                str(project_dir),
                project_name,
                "-import",
                str(eboot),
                "-scriptPath",
                str(script_dir),
                "-postScript",
                "SetoAnalyzeEntry.java",
                claim.address,
            ]
        else:
            argv = [
                    f"{self.ghidra_home.rstrip('/')}/support/analyzeHeadless",
                str(project_dir),
                project_name,
                "-import",
                str(eboot),
                "-scriptPath",
                str(script_dir),
                "-postScript",
                "SetoAnalyzeEntry.java",
                claim.address,
            ]
        process = self._run_limited_operation(
            self.ghidra_slots,
            "ghidra",
            claim=replace(claim, provider="ghidra"),
            deadline=deadline,
            operation=lambda: _run_process(
                argv,
                cwd=worktree,
                timeout=900,
                output_limit=8_000_000,
                stop_requested=self.store.stop_requested,
                deadline=deadline,
            ),
        )
        if process.interrupted:
            raise CampaignInterrupted
        if process.timed_out or process.returncode != 0:
            raise ValueError("Ghidra headless boundary analysis failed")
        # Persist only the helper's bounded markers. Ghidra's surrounding process
        # output may contain private paths or diagnostics unrelated to evidence.
        marker_lines = []
        collecting_decompilation = False
        for line in (process.stdout + "\n" + process.stderr).splitlines():
            if collecting_decompilation:
                end_marker = re.search(r"SETO_DECOMP_C_END(?:\s|$)", line)
                if end_marker:
                    marker_lines.append("SETO_DECOMP_C_END")
                    collecting_decompilation = False
                else:
                    marker_lines.append(
                        re.sub(r"[ \t]+\(GhidraScript\)[ \t]*$", "", line).rstrip()
                    )
                continue
            marker = re.search(
                r"SETO_[A-Z0-9_]+(?==|[ \t]+\(GhidraScript\)|$)", line
            )
            if not marker:
                continue
            marker_line = line[marker.start() :].split(" (GhidraScript)", 1)[0].strip()
            marker_lines.append(marker_line)
            if marker_line == "SETO_DECOMP_C_BEGIN":
                collecting_decompilation = True
        if not marker_lines:
            raise ValueError(
                "Ghidra completed without boundary markers "
                f"(captured {len(process.stdout)} stdout / {len(process.stderr)} stderr bytes)"
            )
        log_path.write_text(
            "\n".join(marker_lines) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        log_text = log_path.read_text(encoding="utf-8")
        boundary = validate_ghidra_log(log_text, claim.numeric_address)
        if not _ghidra_log_has_reconstruction_details(log_text):
            raise ValueError("Ghidra analysis omitted the instruction listing or decompilation")
        self._validate_boundary_nonoverlap(
            claim.address, int(boundary["size_bytes"])
        )
        if claim.boundary_status == "EXACT" and boundary["size_bytes"] != claim.size_bytes:
            raise ValueError("fresh Ghidra analysis conflicts with the inventory's exact size")
        log_sha256 = hashlib.sha256(log_path.read_bytes()).hexdigest()
        if claim.boundary_status == "UNVERIFIED":
            boundary_evidence = {
                **boundary,
                "worker_id": claim.worker_id,
                "log_path": log_relative,
                "log_sha256": log_sha256,
            }
            self.store.update_boundary(
                claim, int(boundary["size_bytes"]), boundary_evidence
            )
        checkpoint = dict(claim.checkpoint)
        checkpoint.update(
            {
                "ghidra_log_path": log_relative,
                "ghidra_log_sha256": log_sha256,
                "boundary_status": "EXACT",
            }
        )
        self.store.save_checkpoint(claim, checkpoint, trusted_evidence=True)
        prepared = replace(
            claim,
            size_bytes=int(boundary["size_bytes"]),
            boundary_status="EXACT",
            checkpoint=checkpoint,
        )
        return self._attach_historical_hypothesis(worktree, prepared)

    def _verify_with_matcher_twice(
        self,
        worktree: Path,
        claim: Claim,
        checkpoint: dict[str, Any],
        deadline: float | None = None,
    ) -> dict[str, Any]:
        log_value = checkpoint.get("ghidra_log_path")
        if not isinstance(log_value, str):
            raise ValueError("checkpoint must reference a local Ghidra evidence log")
        log_path = campaign_build_path(worktree, log_value)
        worker_root = campaign_build_path(
            worktree, f"decomp-campaign/{claim.worker_id}/{claim.address.removeprefix('0x')}"
        )
        if not log_path.resolve(strict=True).is_relative_to(worker_root.resolve(strict=False)):
            raise ValueError("Ghidra log must remain in this worker's function build directory")
        if log_path.is_symlink() or not log_path.is_file() or log_path.stat().st_size > 2_000_000:
            raise ValueError("Ghidra evidence log is absent, unsafe, or too large")
        log_content = log_path.read_bytes()
        if hashlib.sha256(log_content).hexdigest() != checkpoint.get("ghidra_log_sha256"):
            raise ValueError("Ghidra evidence changed after the orchestrator checkpointed its hash")
        boundary = validate_ghidra_log(log_content.decode("utf-8", errors="replace"), claim.numeric_address)
        triage_path = worktree / "build" / "seto035" / "export-triage.json"
        if triage_path.is_symlink() or not triage_path.is_file():
            raise ValueError("local real-triage report is missing in the worker worktree")
        validate_export_evidence(triage_path, claim.address, claim.nid)
        if claim.boundary_status == "UNVERIFIED":
            self.store.update_boundary(claim, int(boundary["size_bytes"]), boundary)
            return {
                "status": "BOUNDARY_VALIDATED",
                "matching_words": -1,
                "total_words": int(boundary["size_bytes"]) // 4,
                "ghidra_boundary": boundary,
            }
        if boundary["size_bytes"] != claim.size_bytes:
            raise ValueError("Ghidra boundary conflicts with the inventory's exact size")

        source_relative = f"decomp/src/eboot/func_{claim.numeric_address:08X}.c"
        source = worktree / source_relative
        if source.is_symlink() or not source.is_file():
            raise ValueError("required candidate source is missing or is a symlink")
        source = source.resolve(strict=True)
        source.relative_to(worktree.resolve(strict=True))
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()

        eboot = worktree / "private" / "decrypted" / "ULUS10136_EBOOT.elf"
        config = worktree / "config" / "wsl" / "seto.toml"
        matcher = worktree / "scripts" / "match_function.py"
        if any(path.is_symlink() or not path.is_file() for path in (eboot, config, matcher)):
            raise ValueError("EBOOT, local MWCC config, or production matcher is missing/unsafe")
        if os.name == "nt":
            reports = self._run_matcher_wsl(
                worktree, claim, source, eboot, config, matcher, deadline=deadline
            )
        else:
            reports = self._run_matcher_native(
                worktree, claim, source, eboot, config, matcher, deadline=deadline
            )
        if len(reports) != 2:
            raise MatcherIncomplete("matcher did not produce two complete verification reports")
        objects = [
            str(provenance.get("object_sha256", ""))
            if isinstance(provenance := report.get("provenance"), dict)
            else ""
            for report in reports
        ]
        for report in reports:
            _validate_complete_matcher_report(
                report,
                expected_address=claim.numeric_address,
                expected_size=claim.size_bytes,
                expected_source_sha256=source_hash,
            )
        matching = max(
            (int(report.get("match", {}).get("matching_words", -1)) for report in reports),
            default=-1,
        )
        all_matched = all(
            is_strict_match(
                report,
                expected_address=claim.numeric_address,
                expected_size=claim.size_bytes,
            )
            for report in reports
        )
        if all_matched and objects[0] == objects[1]:
            result_status = "MATCHED"
        elif any(report["status"] == "INCONCLUSIVE" for report in reports) or (
            all(report["status"] == "MATCHED" for report in reports)
            and objects[0] != objects[1]
        ):
            result_status = "INCONCLUSIVE"
        else:
            result_status = "NONMATCHING"
        result: dict[str, Any] = {
            "status": result_status,
            "source_sha256": source_hash,
            "matching_words": matching,
            "total_words": claim.size_bytes // 4,
            "build_sha256": objects,
            "reports": reports,
            "ghidra_log_sha256": hashlib.sha256(log_path.read_bytes()).hexdigest(),
            "ghidra_boundary": boundary,
        }
        return result

    def _run_matcher_native(
        self,
        worktree: Path,
        claim: Claim,
        source: Path,
        eboot: Path,
        config: Path,
        matcher: Path,
        *,
        deadline: float | None = None,
        verification_numbers: Sequence[int] = (1, 2),
    ) -> list[dict[str, Any]]:
        reports: list[dict[str, Any]] = []
        if not verification_numbers or any(number not in {1, 2} for number in verification_numbers):
            raise ValueError("matcher verification numbers must be selected from 1 and 2")
        for number in verification_numbers:
            relative_out = (
                f"decomp-campaign/{claim.worker_id}/{claim.address.removeprefix('0x')}"
                f"/attempt-{claim.attempt_number}/verify-{number}"
            )
            out = campaign_build_path(
                worktree, relative_out
            )
            out.mkdir(parents=True, exist_ok=True)
            result = _run_process(
                [
                    sys.executable,
                    str(matcher),
                    "--config",
                    str(config),
                    "--prx",
                    str(eboot),
                    "--function",
                    claim.address,
                    "--size",
                    str(claim.size_bytes),
                    "--source",
                    str(source),
                    "--out",
                    str(out),
                    "--json",
                ],
                cwd=worktree,
                timeout=420,
                output_limit=self.output_limit,
                stop_requested=self.store.stop_requested,
                deadline=deadline,
            )
            if result.interrupted:
                raise CampaignInterrupted
            if result.timed_out:
                if deadline is not None and time.monotonic() >= deadline:
                    raise CampaignInterrupted
                raise ValueError("production matcher build/compare timed out")
            report = _matcher_report_from_process(
                result,
                claim=claim,
                source=source,
                out=out,
                config=config,
                relative_out=relative_out,
            )
            report["report_path"] = (
                f"build/{relative_out}/func_{claim.numeric_address:08X}.match.json"
            )
            _persist_full_matcher_report(
                out, f"func_{claim.numeric_address:08X}", report
            )
            reports.append(report)
        return reports

    def _run_matcher_wsl(
        self,
        worktree: Path,
        claim: Claim,
        source: Path,
        eboot: Path,
        config: Path,
        matcher: Path,
        *,
        deadline: float | None = None,
        verification_numbers: Sequence[int] = (1, 2),
    ) -> list[dict[str, Any]]:
        distro = os.environ.get("SETO_WSL_DISTRO", self.wsl_distro)
        worktree_wsl = _wsl_path(worktree, distro)
        reports: list[dict[str, Any]] = []
        if not verification_numbers or any(number not in {1, 2} for number in verification_numbers):
            raise ValueError("matcher verification numbers must be selected from 1 and 2")
        for number in verification_numbers:
            relative_out = (
                f"decomp-campaign/{claim.worker_id}/{claim.address.removeprefix('0x')}"
                f"/attempt-{claim.attempt_number}/verify-{number}"
            )
            out = campaign_build_path(worktree, relative_out)
            out.mkdir(parents=True, exist_ok=True)
            out_wsl = _wsl_path(out, distro)
            argv = [
                "wsl.exe",
                "-d",
                distro,
                "--cd",
                worktree_wsl,
                "--exec",
                "env",
                f"PYTHONPATH={_wsl_path(worktree / 'src', distro)}",
                "python3",
                _wsl_path(matcher, distro),
                "--config",
                _wsl_path(config, distro),
                "--prx",
                _wsl_path(eboot, distro),
                "--function",
                claim.address,
                "--size",
                str(claim.size_bytes),
                "--source",
                _wsl_path(source, distro),
                "--out",
                out_wsl,
                "--json",
            ]
            result = _run_process(
                argv,
                cwd=worktree,
                timeout=420,
                output_limit=self.output_limit,
                stop_requested=self.store.stop_requested,
                deadline=deadline,
            )
            if result.interrupted:
                raise CampaignInterrupted
            if result.timed_out:
                if deadline is not None and time.monotonic() >= deadline:
                    raise CampaignInterrupted
                raise ValueError("production matcher build/compare timed out")
            report = _matcher_report_from_process(
                result,
                claim=claim,
                source=source,
                out=out,
                config=config,
                relative_out=relative_out,
            )
            report["report_path"] = (
                f"build/{relative_out}/func_{claim.numeric_address:08X}.match.json"
            )
            _persist_full_matcher_report(
                out, f"func_{claim.numeric_address:08X}", report
            )
            reports.append(report)
        return reports

    def _run_claim(
        self,
        worker: Worker,
        claim: Claim,
        deadline: float | None,
        *,
        max_total_attempts: int | None = None,
        on_attempt_started: Callable[[], None] | None = None,
        refinement_attempt_index: int = 1,
        continuation: bool = False,
    ) -> str:
        worktree = self.worktrees[worker.worker_id]
        if worktree.is_symlink() or not worktree.is_dir():
            self.store.release_preparation(
                claim, diagnostic_code="context_unavailable"
            )
            return "blocked"

        phase = "ghidra"
        attempt_started = False
        provider_slot: threading.BoundedSemaphore | None = None
        provider_slot_acquired = False
        try:
            if self.auto_preflight and not continuation:
                claim = self._prepare_claim(worktree, claim, deadline)

            provider_slot = self.provider_slots.get(worker.provider)
            if provider_slot is not None:
                if not self._acquire_resource_slot(provider_slot, deadline):
                    provider_slot = None
                    self.store.release_preparation(claim)
                    return "interrupted"
                provider_slot_acquired = True
                if self.store.provider_status(worker.provider) != "active":
                    self.store.release_preparation(claim)
                    return "provider_paused"

            phase = "context"
            claim = self._ensure_session(
                claim, worktree, deadline, agent=worker.agent, model=worker.model
            )
            phase = "checkpoint"
            self._restore_best_source(worktree, claim)
            phase = "integrity"
            protected_before = _file_manifest(worktree) if self.auto_preflight else {}
            changes_before = _worktree_status_snapshot(worktree) if self.auto_preflight else {}
            git_head_before = _git_output(worktree, "rev-parse", "HEAD") if self.auto_preflight else ""
            git_branch_before = _git_output(worktree, "branch", "--show-current") if self.auto_preflight else ""
            validate_model_id(worker.model, {"openai/gpt-6-luna", "opencode/deepseek-v4.1-flash-free"})
            prompt = _prompt(claim, claim.checkpoint, worktree)
            argv = self._argv(worker, claim, prompt)
            if self.store.stop_requested() or (
                deadline is not None and time.monotonic() >= deadline
            ):
                self.store.release_preparation(claim)
                return "interrupted"
            if continuation:
                if max_total_attempts is None:
                    raise ValueError("continued inference requires the cumulative attempt ceiling")
                started_claim = self.store.start_continued_attempt(
                    claim,
                    max_total_attempts=max_total_attempts,
                    max_attempts_per_candidate=self.max_attempts_per_candidate,
                    lease_seconds=self.lease_seconds,
                )
            else:
                started_claim = self.store.start_attempt(
                    claim,
                    max_total_attempts=max_total_attempts,
                    lease_seconds=self.lease_seconds,
                )
            if started_claim is None:
                return "continuation_released" if continuation else "budget_exhausted"
            claim = started_claim
            attempt_started = True
            if on_attempt_started is not None:
                on_attempt_started()
            phase = "context"
            self.store.record_event(
                "inference_started",
                address=claim.address,
                worker_id=worker.worker_id,
                provider=worker.provider,
                session_id=claim.session_id,
            )
            try:
                process = _run_process(
                    argv,
                    cwd=worktree,
                    timeout=self.timeout_seconds,
                    output_limit=self.output_limit,
                    stop_requested=self.store.stop_requested,
                    deadline=deadline,
                )
            finally:
                self.store.record_event(
                    "inference_finished",
                    address=claim.address,
                    worker_id=worker.worker_id,
                    provider=worker.provider,
                    session_id=claim.session_id,
                )
        except CampaignInterrupted:
            if attempt_started:
                self._fail(claim, Failure(FailureKind.INTERRUPTED))
            else:
                self.store.release_preparation(claim)
            return "interrupted"
        except Exception as exc:
            if phase == "context":
                provider_failure = classify_failure(1, "", str(exc))
                if provider_failure.kind is not FailureKind.AGENT_ERROR:
                    try:
                        if attempt_started:
                            self._fail(claim, provider_failure)
                        else:
                            self.store.release_preparation(
                                claim,
                                failure=provider_failure,
                                max_retry_after=self.max_retry_after_seconds,
                            )
                    except RuntimeError:
                        pass
                    return "failed"
            code_by_phase = {
                "ghidra": "ghidra_evidence_invalid",
                "context": "context_unavailable",
                "checkpoint": "checkpoint_invalid",
                "integrity": "protected_input_changed",
            }
            if not attempt_started:
                code = code_by_phase.get(phase)
                try:
                    self.store.release_preparation(claim, diagnostic_code=code)
                except RuntimeError:
                    pass
                return "blocked"
            stage = DIAGNOSTIC_CODES.get(code_by_phase.get(phase, "internal_error"), "internal")
            code = code_by_phase.get(phase, "internal_error")
            try:
                self._fail(
                    claim,
                    Failure(
                        FailureKind.AGENT_ERROR,
                        diagnostic_stage=stage,
                        diagnostic_code=code,
                    ),
                )
            except RuntimeError:
                pass
            return "blocked"
        finally:
            if provider_slot is not None and provider_slot_acquired:
                provider_slot.release()
                provider_slot_acquired = False

        try:
            phase = "integrity"
            protected_after = _file_manifest(worktree) if self.auto_preflight else {}
            if protected_before != protected_after:
                self._fail(
                    claim,
                    Failure(
                        FailureKind.AGENT_ERROR,
                        diagnostic_stage="integrity",
                        diagnostic_code="protected_input_changed",
                    ),
                )
                return "blocked"
            if self.auto_preflight:
                _assert_worker_changes_scoped(
                    changes_before,
                    _worktree_status_snapshot(worktree),
                    claim,
                )
                _assert_git_identity_unchanged(
                    worktree,
                    original_head=git_head_before,
                    original_branch=git_branch_before,
                )
            if process.interrupted:
                self._fail(claim, Failure(FailureKind.INTERRUPTED))
                return "interrupted"
            if process.returncode != 0 or process.timed_out:
                failure = classify_failure(
                    process.returncode,
                    process.stdout,
                    process.stderr,
                    timed_out=process.timed_out,
                )
                if failure.kind is FailureKind.AGENT_ERROR:
                    failure = replace(
                        failure,
                        diagnostic_stage="context",
                        diagnostic_code="context_unavailable",
                    )
                self._fail(claim, failure)
                return "failed"
            phase = "worker_return"
            agent_checkpoint = _extract_checkpoint(process.stdout)
            checkpoint = {
                key: agent_checkpoint[key]
                for key in ("next_experiment", "limitations")
                if key in agent_checkpoint
            }
            for key in ("ghidra_log_path", "ghidra_log_sha256", "boundary_status"):
                if key in claim.checkpoint:
                    checkpoint[key] = claim.checkpoint[key]
            if "historical_hypothesis" in claim.checkpoint:
                checkpoint["historical_hypothesis"] = claim.checkpoint[
                    "historical_hypothesis"
                ]
            for key in (
                "source_path",
                "source_sha256",
                "latest_source_snapshot",
                "best_source_sha256",
                "best_source_snapshot",
                "best_match",
                "last_attempt",
                "local_experiments",
            ):
                if key in claim.checkpoint:
                    checkpoint[key] = claim.checkpoint[key]
            phase = "checkpoint"
            self.store.save_checkpoint(claim, checkpoint, trusted_evidence=True)
            source_relative = Path("decomp/src/eboot") / f"func_{claim.numeric_address:08X}.c"
            try:
                source = _safe_worktree_path(worktree, source_relative)
            except (OSError, ValueError):
                self._fail(
                    claim,
                    Failure(
                        FailureKind.AGENT_ERROR,
                        diagnostic_stage="integrity",
                        diagnostic_code="protected_input_changed",
                    ),
                )
                return "blocked"
            if source.is_symlink():
                self._fail(
                    claim,
                    Failure(
                        FailureKind.AGENT_ERROR,
                        diagnostic_stage="integrity",
                        diagnostic_code="protected_input_changed",
                    ),
                )
                return "blocked"
            if not source.is_file():
                self._fail(
                    claim,
                    Failure(
                        FailureKind.AGENT_ERROR,
                        diagnostic_stage="worker_return",
                        diagnostic_code="candidate_source_missing",
                    ),
                )
                return "blocked"
            previous_source_hash = claim.checkpoint.get("source_sha256")
            phase = "checkpoint"
            latest_source = self._snapshot_candidate_source(worktree, claim)
            source_changed = bool(
                latest_source
                and latest_source.get("source_sha256") != previous_source_hash
            )
            if latest_source:
                checkpoint.update(latest_source)
                self.store.save_checkpoint(claim, checkpoint, trusted_evidence=True)
                claim = replace(claim, checkpoint=checkpoint)
                if not source_changed:
                    return self.store.complete_unchanged_source(claim)
            phase = "matcher"
            try:
                if self.auto_preflight:
                    verification = self._run_limited_operation(
                        self.matcher_slots,
                        "matcher",
                        claim=claim,
                        deadline=deadline,
                        operation=lambda: self._verify_with_matcher_twice(
                            worktree, claim, checkpoint, deadline
                        ),
                    )
                else:
                    verification = self._run_limited_operation(
                        self.matcher_slots,
                        "matcher",
                        claim=claim,
                        deadline=deadline,
                        operation=lambda: self.verifier(worktree, claim, checkpoint),
                    )
            except CampaignInterrupted:
                raise
            except Exception as exc:
                if isinstance(exc, MatcherCompilerError):
                    stage, code = "compiler", "compiler_failed"
                elif _matcher_failure_is_incomplete(exc):
                    stage, code = "matcher", "matcher_incomplete"
                else:
                    stage, code = "internal", "internal_error"
                excerpt = getattr(exc, "excerpt", "") or _safe_diagnostic_excerpt(exc)
                if excerpt:
                    checkpoint = dict(claim.checkpoint)
                    checkpoint["last_diagnostic_detail"] = {
                        "stage": stage,
                        "code": code,
                        "excerpt": excerpt,
                    }
                    self.store.save_checkpoint(claim, checkpoint, trusted_evidence=True)
                    claim = replace(claim, checkpoint=checkpoint)
                if code in {"compiler_failed", "matcher_incomplete"}:
                    refinement = self.store.complete_diagnostic(
                        claim,
                        diagnostic_stage=stage,
                        diagnostic_code=code,
                        excerpt=excerpt,
                        max_attempts_without_progress=self.max_attempts_without_progress,
                        max_attempts_per_candidate=self.max_attempts_per_candidate,
                        continue_refinement=(
                            source_changed
                            and max_total_attempts is not None
                            and refinement_attempt_index < self.max_consecutive_attempts
                        ),
                        max_total_attempts=max_total_attempts,
                        lease_seconds=self.lease_seconds,
                    )
                    if isinstance(refinement, Claim):
                        return self._run_claim(
                            worker,
                            refinement,
                            deadline,
                            max_total_attempts=max_total_attempts,
                            on_attempt_started=on_attempt_started,
                            refinement_attempt_index=refinement_attempt_index + 1,
                            continuation=True,
                        )
                    return refinement
                self._fail(
                    claim,
                    Failure(
                        FailureKind.AGENT_ERROR,
                        diagnostic_stage=stage,
                        diagnostic_code=code,
                    ),
                )
                return "blocked"
            phase = "checkpoint"
            if latest_source:
                if verification.get("source_sha256") != latest_source["source_sha256"]:
                    raise ValueError("matcher source hash does not match the pre-verification snapshot")
                verification["source_snapshot_path"] = latest_source[
                    "latest_source_snapshot"
                ]
            previous_best = checkpoint.get("best_match", {})
            previous_best_status = (
                previous_best.get("status") if isinstance(previous_best, dict) else None
            )
            diagnostic_progress = bool(
                verification.get("status") == "INCONCLUSIVE"
                and previous_best_status != "INCONCLUSIVE"
                and any(
                    isinstance(report, dict)
                    and isinstance(report.get("match"), dict)
                    and report["match"].get("comparison_complete") is False
                    for report in verification.get("reports", [])
                )
            )
            completion = self.store.complete(
                claim,
                checkpoint,
                verification,
                max_attempts_without_progress=self.max_attempts_without_progress,
                max_attempts_per_candidate=self.max_attempts_per_candidate,
                continue_refinement=(
                    source_changed
                    and max_total_attempts is not None
                    and refinement_attempt_index < self.max_consecutive_attempts
                ),
                refinement_progress=diagnostic_progress,
                max_total_attempts=max_total_attempts,
                lease_seconds=self.lease_seconds,
            )
            if isinstance(completion, Claim):
                return self._run_claim(
                    worker,
                    completion,
                    deadline,
                    max_total_attempts=max_total_attempts,
                    on_attempt_started=on_attempt_started,
                    refinement_attempt_index=refinement_attempt_index + 1,
                    continuation=True,
                )
            return completion
        except CampaignInterrupted:
            self._fail(claim, Failure(FailureKind.INTERRUPTED))
            return "interrupted"
        except Exception as exc:
            if phase == "context":
                provider_failure = classify_failure(1, "", str(exc))
                if provider_failure.kind is not FailureKind.AGENT_ERROR:
                    try:
                        if attempt_started:
                            self._fail(claim, provider_failure)
                        else:
                            self.store.release_preparation(
                                claim,
                                failure=provider_failure,
                                max_retry_after=self.max_retry_after_seconds,
                            )
                    except RuntimeError:
                        pass
                    return "failed"
            code_by_phase = {
                "ghidra": ("ghidra", "ghidra_evidence_invalid"),
                "context": ("context", "context_unavailable"),
                "worker_return": ("worker_return", "checkpoint_invalid"),
                "checkpoint": ("worker_return", "checkpoint_invalid"),
                "integrity": ("integrity", "protected_input_changed"),
                "matcher": ("internal", "internal_error"),
            }
            stage, code = code_by_phase.get(phase, ("internal", "internal_error"))
            try:
                self._fail(
                    claim,
                    Failure(
                        FailureKind.AGENT_ERROR,
                        diagnostic_stage=stage,
                        diagnostic_code=code,
                    ),
                )
            except RuntimeError:
                pass
            return "blocked"

    def _run_boundary_claim(
        self, worker_id: str, claim: Claim, deadline: float | None
    ) -> str:
        worktree = self.worktrees[worker_id]
        try:
            if worktree.is_symlink() or not worktree.is_dir():
                raise ValueError("Ghidra boundary worker worktree is missing or unsafe")
            prepared = self._prepare_claim(worktree, claim, deadline)
            if prepared.boundary_status != "EXACT":
                raise ValueError("Ghidra did not return an exact body boundary")
            self.store.finish_boundary(claim)
            return "boundary_validated"
        except CampaignInterrupted:
            try:
                self.store.fail_boundary(claim, interrupted=True)
            except RuntimeError:
                pass
            return "interrupted"
        except Exception:
            try:
                self.store.fail_boundary(claim, "ghidra_evidence_invalid")
            except RuntimeError:
                pass
            return "boundary_blocked"

    def _fail(self, claim: Claim, failure: Failure) -> None:
        self.store.fail(
            claim,
            failure,
            max_retry_after=self.max_retry_after_seconds,
            max_attempts_per_candidate=self.max_attempts_per_candidate,
        )

    def run(self, workers: Sequence[Worker], *, max_tasks: int) -> dict[str, Any]:
        if max_tasks <= 0:
            raise ValueError("max_tasks must be positive")
        if len({worker.worker_id for worker in workers}) != len(workers):
            raise ValueError("worker identifiers must be unique")
        if not workers:
            raise ValueError("at least one READY model worker is required")
        workers_by_provider: dict[str, int] = {}
        for worker in workers:
            validate_model_id(worker.model, {"openai/gpt-6-luna", "opencode/deepseek-v4.1-flash-free"})
            if worker.worker_id not in self.worktrees:
                raise ValueError(f"missing isolated worktree for {worker.worker_id}")
            workers_by_provider[worker.provider] = workers_by_provider.get(worker.provider, 0) + 1
        self.provider_slots = {
            provider: threading.BoundedSemaphore(
                max(1, int(self.provider_parallelism.get(provider, count)))
            )
            for provider, count in workers_by_provider.items()
        }
        self.store.recover_expired()
        if self.store.stop_requested():
            return {"attempted": 0, "outcomes": {}, "stopped": True}
        deadline = (
            None
            if self.max_duration_seconds is None
            else time.monotonic() + self.max_duration_seconds
        )
        outcomes: list[str] = []
        condition = threading.Condition()
        boundary_claim_lock = threading.Lock()
        attempts_started = 0
        attempts_claiming = 0
        attempts_preparing = 0
        attempts_active = 0
        completion_generation = 0
        boundary_active = 0
        boundary_threads_remaining = 1
        boundary_outcomes: list[str] = []
        promotions: list[str] = []
        promotion_failures: list[str] = []
        promotion_results_lock = threading.Lock()
        started_at = time.monotonic()

        def stop_or_expired() -> bool:
            return self.store.stop_requested() or (
                deadline is not None and time.monotonic() >= deadline
            )

        def integrate_source(address: str) -> None:
            try:
                origin = self.store.get_task(address)["best_result"].get(
                    "campaign_origin", {}
                )
                self.store.record_event(
                    "promotion_started",
                    address=address,
                    worker_id=origin.get("worker_id") if isinstance(origin, dict) else None,
                    provider=origin.get("provider") if isinstance(origin, dict) else None,
                    session_id=origin.get("session_id") if isinstance(origin, dict) else None,
                )
                with self.promotion_lock:
                    self.promotion_callback(address, deadline)  # type: ignore[misc]
                    self.store.record_integration_result(address, "promoted")
                with promotion_results_lock:
                    promotions.append(address)
            except Exception:
                try:
                    self.store.record_integration_result(
                        address, "blocked", diagnostic_code="integration_failed"
                    )
                except (KeyError, RuntimeError, sqlite3.Error):
                    pass
                with promotion_results_lock:
                    promotion_failures.append(address)

        def boundary_coordinator() -> None:
            nonlocal boundary_active, boundary_threads_remaining, completion_generation
            available_workers = [
                worker.worker_id
                for worker in workers[: min(self.ghidra_parallelism, len(workers))]
            ]
            pending: dict[concurrent.futures.Future[str], str] = {}
            boundary_slots = max(1, len(available_workers))
            try:
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=boundary_slots, thread_name_prefix="seto-ghidra"
                ) as pool:
                    while not stop_or_expired():
                        while available_workers and not stop_or_expired():
                            worker_id = available_workers[-1]
                            with boundary_claim_lock:
                                claim = self.store.claim_boundary(
                                    worker_id,
                                    lease_seconds=self.lease_seconds,
                                    excluded_addresses=self.excluded_addresses,
                                )
                            if claim is None:
                                break
                            available_workers.pop()
                            with condition:
                                boundary_active += 1
                                completion_generation += 1
                                condition.notify_all()
                            pending[pool.submit(
                                self._run_boundary_claim, worker_id, claim, deadline
                            )] = worker_id

                        if not pending:
                            break
                        done, _ = concurrent.futures.wait(
                            pending,
                            timeout=0.5,
                            return_when=concurrent.futures.FIRST_COMPLETED,
                        )
                        for future in done:
                            worker_id = pending.pop(future)
                            try:
                                boundary_outcomes.append(future.result())
                            except Exception:
                                boundary_outcomes.append("boundary_blocked")
                            available_workers.append(worker_id)
                            with condition:
                                boundary_active -= 1
                                completion_generation += 1
                                condition.notify_all()
            finally:
                with condition:
                    boundary_threads_remaining = 0
                    completion_generation += 1
                    condition.notify_all()

        def model_worker_loop(worker: Worker) -> None:
            nonlocal attempts_started, attempts_claiming, attempts_preparing
            nonlocal attempts_active, completion_generation
            while True:
                with condition:
                    while True:
                        if stop_or_expired() or self.store.total_attempt_count() >= max_tasks:
                            return
                        if attempts_started + attempts_claiming + attempts_preparing < max_tasks:
                            attempts_claiming += 1
                            break
                        condition.wait(timeout=0.5)

                try:
                    claim = self.store.claim_next(
                        worker.worker_id,
                        worker.provider,
                        lease_seconds=self.lease_seconds,
                        max_attempts_per_candidate=self.max_attempts_per_candidate,
                        max_total_attempts=max_tasks,
                        eligible_addresses=self.candidate_addresses,
                        excluded_addresses=self.excluded_addresses,
                        reserve_only=True,
                    )
                except BaseException:
                    with condition:
                        attempts_claiming -= 1
                        condition.notify_all()
                    raise

                with condition:
                    attempts_claiming -= 1
                    if claim is not None:
                        attempts_preparing += 1
                        attempts_active += 1
                        completion_generation += 1
                        condition.notify_all()
                    else:
                        condition.notify_all()

                if claim is None:
                    next_eligible = self.store.next_eligible_time(
                        worker.provider,
                        max_attempts_per_candidate=self.max_attempts_per_candidate,
                        eligible_addresses=(
                            None
                            if self.candidate_addresses is None
                            else sorted(self.candidate_addresses)
                        ),
                        excluded_addresses=self.excluded_addresses,
                    )
                    with condition:
                        has_campaign_work = bool(
                            attempts_active
                            or attempts_claiming
                            or attempts_preparing
                            or boundary_threads_remaining
                        )
                        if has_campaign_work:
                            condition.wait(timeout=1.0)
                            continue
                        if self.store.total_attempt_count() >= max_tasks:
                            return
                        if next_eligible is None:
                            return
                        delay = max(0.0, next_eligible - time.time())
                        if deadline is not None:
                            delay = min(delay, max(0.0, deadline - time.monotonic()))
                        if delay <= 0:
                            continue
                        # Backoff waits are event-driven and bounded so stop/deadline
                        # changes are noticed without busy-waiting.
                        condition.wait(timeout=min(delay, 30.0))
                    continue

                attempt_started = False

                def mark_attempt_started() -> None:
                    nonlocal attempts_started, attempts_preparing, completion_generation
                    nonlocal attempt_started
                    with condition:
                        if not attempt_started:
                            attempt_started = True
                            attempts_preparing -= 1
                        attempts_started += 1
                        completion_generation += 1
                        condition.notify_all()

                try:
                    outcome = self._run_claim(
                        worker,
                        claim,
                        deadline,
                        max_total_attempts=max_tasks,
                        on_attempt_started=mark_attempt_started,
                    )
                finally:
                    with condition:
                        if not attempt_started:
                            attempts_preparing -= 1
                        attempts_active -= 1
                        completion_generation += 1
                        condition.notify_all()
                with condition:
                    outcomes.append(outcome)
                    condition.notify_all()

                if outcome == "matched" and self.promotion_callback is not None:
                    # Queue integration so this worker and its peers can claim
                    # more EBOOT work while one certified source is revalidated.
                    promotion_pool.submit(integrate_source, claim.address)

        promotion_pool = (
            concurrent.futures.ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="seto-promotion"
            )
            if self.promotion_callback is not None
            else None
        )
        boundary_thread = threading.Thread(
            target=boundary_coordinator,
            name="seto-boundary-coordinator",
            daemon=True,
        )
        boundary_started = False
        try:
            boundary_thread.start()
            boundary_started = True
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(workers), thread_name_prefix="seto-model"
            ) as pool:
                futures = [
                    pool.submit(model_worker_loop, worker) for worker in workers
                ]
                for future in futures:
                    future.result()
            boundary_thread.join()
        except KeyboardInterrupt:
            self.store.request_stop()
            raise
        except BaseException:
            self.store.request_stop()
            raise
        finally:
            if boundary_started:
                boundary_thread.join()
            if promotion_pool is not None:
                promotion_pool.shutdown(wait=True)
        return {
            "attempted": attempts_started,
            "outcomes": {kind: outcomes.count(kind) for kind in sorted(set(outcomes))},
            "boundary_outcomes": {
                kind: boundary_outcomes.count(kind)
                for kind in sorted(set(boundary_outcomes))
            },
            "integrations_promoted": promotions,
            "integration_blocked": promotion_failures,
            "duration_seconds": round(time.monotonic() - started_at, 3),
            "stopped": self.store.stop_requested(),
        }


def _existing_local_recovery_reports(
    repo_root: Path,
    address: str,
    *,
    expected_size: int,
    expected_source_sha256: str,
) -> list[dict[str, Any]]:
    numeric = int(address, 0)
    address_root = campaign_build_path(
        repo_root, f"decomp-campaign/experiments/{numeric:x}"
    )
    if address_root.is_symlink() or not address_root.is_dir():
        return []
    results = []
    stem = f"func_{numeric:08X}"
    for report_path in address_root.glob(f"attempt-*/verify-*/{stem}.match.json"):
        if report_path.is_symlink() or not report_path.is_file() or report_path.stat().st_size > 2_000_000:
            continue
        cursor = report_path.parent
        safe = True
        while cursor != address_root:
            if cursor.is_symlink():
                safe = False
                break
            cursor = cursor.parent
        if not safe:
            continue
        try:
            match = re.fullmatch(r"attempt-(\d+)", report_path.parent.parent.name)
            verify = re.fullmatch(r"verify-(1|2)", report_path.parent.name)
            if match is None or verify is None:
                continue
            report = json.loads(report_path.read_text(encoding="utf-8"))
            _validate_complete_matcher_report(
                report,
                expected_address=numeric,
                expected_size=expected_size,
                expected_source_sha256=expected_source_sha256,
            )
            provenance = report.get("provenance", {})
            if (
                report.get("evidence") != "compiled-object"
                or Path(str(provenance.get("compiler", ""))).name.lower() != "mwccpsp.exe"
                or provenance.get("flags") != ["-O4,p", "-sdatathreshold", "0"]
            ):
                continue
            report_relative = report_path.relative_to(repo_root / "build").as_posix()
            report["report_path"] = f"build/{report_relative}"
            results.append(
                {
                    "attempt_number": int(match.group(1)),
                    "verification_number": int(verify.group(1)),
                    "report_relative": report_relative,
                    "report": report,
                }
            )
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            continue
    return sorted(
        results,
        key=lambda item: (item["attempt_number"], item["verification_number"]),
        reverse=True,
    )


def _has_local_report_for_source(
    repo_root: Path, address: str, source_sha256: str
) -> bool:
    numeric = int(address, 0)
    address_root = campaign_build_path(
        repo_root, f"decomp-campaign/experiments/{numeric:x}"
    )
    if address_root.is_symlink() or not address_root.is_dir():
        return False
    stem = f"func_{numeric:08X}"
    for path in address_root.glob(f"attempt-*/verify-*/{stem}.match.json"):
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
                continue
            report = json.loads(path.read_text(encoding="utf-8"))
            provenance = report.get("provenance", {})
            if isinstance(provenance, dict) and provenance.get("source_sha256") == source_sha256:
                return True
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            continue
    return False


def recover_local_artifacts(
    runner: CampaignRunner,
    repo_root: Path,
    source_worktrees: Mapping[str, Path],
    *,
    excluded_addresses: Collection[str],
    max_attempts_per_candidate: int,
    campaign_id: str,
    max_variants_per_candidate: int = 2,
) -> dict[str, Any]:
    """Recompile only validated recovered sources; local work never consumes attempts."""
    repo_root = repo_root.resolve(strict=True)
    excluded = {
        _normalize_eboot_address(value, label="excluded certified address")
        for value in excluded_addresses
    }
    for required in (
        repo_root / "private" / "decrypted" / "ULUS10136_EBOOT.elf",
        repo_root / "config" / "wsl" / "seto.toml",
        repo_root / "scripts" / "match_function.py",
    ):
        if required.is_symlink() or not required.is_file():
            raise ValueError("local recovery requires the verified EBOOT, MWCC config and matcher")

    summary: dict[str, Any] = {
        "candidates_scanned": 0,
        "exact_candidates": 0,
        "sources_selected": 0,
        "comparisons_complete": 0,
        "inconclusive": 0,
        "compiler_failures": 0,
        "matcher_failures": 0,
        "local_matches": 0,
        "reopened": [],
        "items": [],
    }
    reopen_reasons: dict[str, str] = {}
    for task in runner.store.list_tasks():
        address = task["address"]
        if address in excluded or task["status"] == "matched":
            continue
        summary["candidates_scanned"] += 1
        if task["boundary_status"] != "EXACT" or int(task["size_bytes"]) <= 0:
            continue
        summary["exact_candidates"] += 1
        variants = discover_local_recovery_sources(
            task,
            repo_root,
            source_worktrees,
            max_variants=max_variants_per_candidate,
        )
        if not variants:
            summary["items"].append(
                {"address": address, "status": "no_recoverable_source"}
            )
            continue

        item_result: dict[str, Any] = {
            "address": address,
            "historical_attempts": task["attempt_count"],
            "sources": [],
        }
        for variant in variants:
            source_hash = variant["source_sha256"]
            numeric = int(address, 0)
            address_hex = f"{numeric:08X}"
            experiment_prefix = f"decomp-campaign/experiments/{numeric:x}"
            source_directory = campaign_build_path(
                repo_root, f"{experiment_prefix}/{source_hash}"
            )
            source_directory.mkdir(parents=True, exist_ok=True)
            experiment_source = source_directory / f"func_{address_hex}.c"
            if experiment_source.is_symlink():
                item_result["sources"].append(
                    {"source_sha256": source_hash, "status": "unsafe_experiment_source"}
                )
                continue
            if experiment_source.exists():
                if (
                    not experiment_source.is_file()
                    or hashlib.sha256(experiment_source.read_bytes()).hexdigest() != source_hash
                ):
                    item_result["sources"].append(
                        {"source_sha256": source_hash, "status": "experiment_source_conflict"}
                    )
                    continue
            else:
                temporary = experiment_source.with_name(experiment_source.name + ".recover.tmp")
                if temporary.exists() or temporary.is_symlink():
                    item_result["sources"].append(
                        {"source_sha256": source_hash, "status": "experiment_source_conflict"}
                    )
                    continue
                shutil.copyfile(variant["source_path"], temporary)
                if hashlib.sha256(temporary.read_bytes()).hexdigest() != source_hash:
                    temporary.unlink(missing_ok=True)
                    item_result["sources"].append(
                        {"source_sha256": source_hash, "status": "source_copy_hash_mismatch"}
                    )
                    continue
                os.replace(temporary, experiment_source)

            source_relative = experiment_source.relative_to(repo_root / "build").as_posix()
            runner.store.record_latest_recovered_source(
                address,
                repo_root=repo_root,
                source_relative=source_relative,
            )

            address_root = campaign_build_path(repo_root, experiment_prefix)
            previous_attempts = [
                int(match.group(1))
                for path in address_root.glob("attempt-*")
                if not path.is_symlink()
                and path.is_dir()
                and (match := re.fullmatch(r"attempt-(\d+)", path.name))
            ]
            attempt_number = max(previous_attempts, default=0) + 1
            claim = Claim(
                address=address,
                size_bytes=int(task["size_bytes"]),
                nid=task["nid"],
                priority=int(task["priority"]),
                boundary_status="EXACT",
                worker_id="experiments",
                provider="local-mwcc-matcher",
                session_id=None,
                attempt_number=attempt_number,
                lease_until=0.0,
                checkpoint={},
                evidence={},
            )
            matcher = repo_root / "scripts" / "match_function.py"
            eboot = repo_root / "private" / "decrypted" / "ULUS10136_EBOOT.elf"
            config = repo_root / "config" / "wsl" / "seto.toml"

            def run_verification(number: int) -> list[dict[str, Any]]:
                if os.name == "nt":
                    operation = lambda: runner._run_matcher_wsl(
                        repo_root,
                        claim,
                        experiment_source,
                        eboot,
                        config,
                        matcher,
                        verification_numbers=(number,),
                    )
                else:
                    operation = lambda: runner._run_matcher_native(
                        repo_root,
                        claim,
                        experiment_source,
                        eboot,
                        config,
                        matcher,
                        verification_numbers=(number,),
                    )
                return runner._run_limited_operation(
                    runner.matcher_slots,
                    "matcher",
                    claim=claim,
                    deadline=None,
                    operation=operation,
                )

            local_item: dict[str, Any] = {
                "source_sha256": source_hash,
                "origins": variant["origins"][:8],
                "historical_matching_words": variant["matching_words"],
                "historical_reports": variant["report_paths"][:4],
                "source_path": f"build/{source_relative}",
            }
            existing_reports = _existing_local_recovery_reports(
                repo_root,
                address,
                expected_size=int(task["size_bytes"]),
                expected_source_sha256=source_hash,
            )
            latest_report_attempt = max(
                (entry["attempt_number"] for entry in existing_reports), default=None
            )
            latest_reports = {
                entry["verification_number"]: entry
                for entry in existing_reports
                if entry["attempt_number"] == latest_report_attempt
            }
            existing_first = latest_reports.get(1)
            if (
                existing_first is not None
                and existing_first["report"].get("status") in {"NONMATCHING", "INCONCLUSIVE"}
            ):
                report = existing_first["report"]
                report_relative = existing_first["report_relative"]
                recovery_reason = _local_recovery_reason(report, source_hash)
                recorded = runner.store.record_local_recovery_result(
                    address,
                    worktree=repo_root,
                    source_relative=source_relative,
                    report_relative=report_relative,
                    recovery_reason=recovery_reason,
                )
                local_item.update(
                    {
                        "status": report["status"],
                        "matching_words": recorded.get("matching_words"),
                        "total_words": recorded.get("total_words"),
                        "difference_count": recorded.get("difference_count"),
                        "report_path": recorded.get("report_path"),
                        "recovery_reason": recovery_reason,
                        "reused_existing_report": True,
                    }
                )
                summary["comparisons_complete"] += int(
                    report["status"] == "NONMATCHING"
                    or report.get("match", {}).get("comparison_complete") is True
                )
                summary["inconclusive"] += int(report["status"] == "INCONCLUSIVE")
                if task["status"] in {"blocked", "stalled"} and int(
                    task["attempt_count"]
                ) < max_attempts_per_candidate:
                    reopen_reasons[address] = recovery_reason
                item_result["sources"].append(local_item)
                summary["sources_selected"] += 1
                continue
            latest_task = runner.store.get_task(address)
            latest_checkpoint = latest_task["checkpoint"]
            previous_diagnostic = latest_checkpoint.get("last_diagnostic_detail")
            if (
                latest_checkpoint.get("source_sha256") == source_hash
                and not _has_local_report_for_source(repo_root, address, source_hash)
                and isinstance(previous_diagnostic, dict)
                and previous_diagnostic.get("code")
                in {"compiler_failed", "matcher_incomplete"}
            ):
                code = str(previous_diagnostic["code"])
                excerpt = str(previous_diagnostic.get("excerpt", ""))
                local_item.update(
                    {
                        "status": code,
                        "diagnostic": excerpt,
                        "diagnostic_code": code,
                        "reused_existing_diagnostic": True,
                    }
                )
                summary["compiler_failures"] += int(code == "compiler_failed")
                summary["matcher_failures"] += int(code == "matcher_incomplete")
                if task["status"] in {"blocked", "stalled"} and int(
                    task["attempt_count"]
                ) < max_attempts_per_candidate:
                    reopen_reasons[address] = (
                        f"local {code} remains for unchanged validated source sha256={source_hash}: "
                        f"{excerpt}"
                    )
                item_result["sources"].append(local_item)
                summary["sources_selected"] += 1
                continue
            try:
                reports = (
                    [existing_first["report"]]
                    if existing_first is not None
                    and existing_first["report"].get("status") == "MATCHED"
                    else run_verification(1)
                )
                if len(reports) != 1:
                    raise MatcherIncomplete("local recovery did not produce exactly one matcher report")
                _validate_complete_matcher_report(
                    reports[0],
                    expected_address=numeric,
                    expected_size=int(task["size_bytes"]),
                    expected_source_sha256=source_hash,
                )
                if reports[0]["status"] == "MATCHED":
                    if not is_strict_match(
                        reports[0],
                        expected_address=numeric,
                        expected_size=int(task["size_bytes"]),
                    ):
                        raise MatcherIncomplete("local MATCHED report failed strict validation")
                    existing_second = latest_reports.get(2)
                    reports.extend(
                        [existing_second["report"]]
                        if existing_second is not None
                        else run_verification(2)
                    )
                    if len(reports) != 2:
                        raise MatcherIncomplete("local MATCHED revalidation did not produce two reports")
                    for report in reports:
                        _validate_complete_matcher_report(
                            report,
                            expected_address=numeric,
                            expected_size=int(task["size_bytes"]),
                            expected_source_sha256=source_hash,
                        )
                    result = {
                        "status": "MATCHED",
                        "source_sha256": source_hash,
                        "matching_words": int(task["size_bytes"]) // 4,
                        "total_words": int(task["size_bytes"]) // 4,
                        "build_sha256": [
                            report["provenance"]["object_sha256"] for report in reports
                        ],
                        "reports": reports,
                    }
                    if is_deterministic_match(
                        result, expected_address=numeric, expected_size=int(task["size_bytes"])
                    ):
                        rels = [report["report_path"].removeprefix("build/") for report in reports]
                        experiment = runner.store.record_local_match_experiment(
                            address,
                            worker_id="experiments",
                            worktree=repo_root,
                            source_relative=source_relative,
                            report_relatives=rels,
                        )
                        local_item.update(
                            {
                                "status": "MATCHED_LOCAL_EXPERIMENT",
                                "object_sha256s": result["build_sha256"],
                                "report_paths": experiment["report_paths"],
                            }
                        )
                        summary["local_matches"] += 1
                    else:
                        local_item.update(
                            {
                                "status": "INCONCLUSIVE_NONDETERMINISTIC_MATCH",
                                "object_sha256s": result["build_sha256"],
                                "report_paths": [report["report_path"] for report in reports],
                            }
                        )
                        summary["inconclusive"] += 1
                        if task["status"] in {"blocked", "stalled"} and int(
                            task["attempt_count"]
                        ) < max_attempts_per_candidate:
                            reopen_reasons[address] = (
                                f"local MWCC matcher returned one strict MATCHED build but "
                                f"independent object hashes differed for source sha256={source_hash}; "
                                "retry refinement with the full local reports"
                            )
                else:
                    report = reports[0]
                    report_relative = report["report_path"].removeprefix("build/")
                    recovery_reason = _local_recovery_reason(report, source_hash)
                    recorded = runner.store.record_local_recovery_result(
                        address,
                        worktree=repo_root,
                        source_relative=source_relative,
                        report_relative=report_relative,
                        recovery_reason=recovery_reason,
                    )
                    local_item.update(
                        {
                            "status": report["status"],
                            "matching_words": recorded.get("matching_words"),
                            "total_words": recorded.get("total_words"),
                            "difference_count": recorded.get("difference_count"),
                            "report_path": recorded.get("report_path"),
                            "recovery_reason": recovery_reason,
                        }
                    )
                    summary["comparisons_complete"] += int(
                        report["status"] == "NONMATCHING"
                        or report.get("match", {}).get("comparison_complete") is True
                    )
                    summary["inconclusive"] += int(report["status"] == "INCONCLUSIVE")
                    if task["status"] in {"blocked", "stalled"} and int(
                        task["attempt_count"]
                    ) < max_attempts_per_candidate:
                        reopen_reasons[address] = recovery_reason
            except MatcherCompilerError as exc:
                excerpt = exc.excerpt or _safe_diagnostic_excerpt(exc)
                local_item.update(
                    {
                        "status": "compiler_failed",
                        "diagnostic": excerpt,
                        "diagnostic_code": "compiler_failed",
                    }
                )
                summary["compiler_failures"] += 1
                runner.store.record_local_recovery_diagnostic(
                    address,
                    diagnostic_stage="compiler",
                    diagnostic_code="compiler_failed",
                    excerpt=excerpt,
                )
                environment_failure = bool(
                    re.search(
                        r"(?i)(?:blocked:\s*mwccpsp is required|"
                        r"mwccpsp(?:\.exe)?[^\r\n]{0,60}\b(?:is )?not found\b|"
                        r"no usable win32 loader)",
                        excerpt,
                    )
                )
                if (
                    not environment_failure
                    and task["status"] in {"blocked", "stalled"}
                    and int(task["attempt_count"]) < max_attempts_per_candidate
                ):
                    reopen_reasons[address] = (
                        f"local MWCC failed on validated source sha256={source_hash}: {excerpt}"
                    )
            except (MatcherIncomplete, ValueError, OSError, sqlite3.Error) as exc:
                excerpt = getattr(exc, "excerpt", "") or _safe_diagnostic_excerpt(exc)
                if isinstance(exc, MatcherIncomplete) or _matcher_failure_is_incomplete(exc):
                    diagnostic_stage, diagnostic_code = "matcher", "matcher_incomplete"
                else:
                    diagnostic_stage, diagnostic_code = "internal", "internal_error"
                local_item.update(
                    {
                        "status": diagnostic_code,
                        "diagnostic": excerpt,
                        "diagnostic_code": diagnostic_code,
                    }
                )
                summary["matcher_failures"] += 1
                runner.store.record_local_recovery_diagnostic(
                    address,
                    diagnostic_stage=diagnostic_stage,
                    diagnostic_code=diagnostic_code,
                    excerpt=excerpt,
                )
                if (
                    diagnostic_code == "matcher_incomplete"
                ) and task["status"] in {"blocked", "stalled"} and int(
                    task["attempt_count"]
                ) < max_attempts_per_candidate:
                    reopen_reasons[address] = (
                        f"local matcher could not complete the exact comparison for validated "
                        f"source sha256={source_hash}: {excerpt}"
                    )
            item_result["sources"].append(local_item)
            summary["sources_selected"] += 1
        summary["items"].append(item_result)

    if reopen_reasons:
        summary["reopened"] = runner.store.reopen_recoverable_candidates(
            reopen_reasons,
            excluded_addresses=excluded,
            max_attempts_per_candidate=max_attempts_per_candidate,
            campaign_id=campaign_id,
        )
    return summary


def _local_recovery_reason(report: dict[str, Any], source_sha256: str) -> str:
    status = str(report.get("status", "INCONCLUSIVE"))
    match = report.get("match", {})
    match = match if isinstance(match, dict) else {}
    score = match.get("matching_words", -1)
    total = match.get("total_words", -1)
    differences = match.get("differences", [])
    difference = differences[0] if isinstance(differences, list) and differences else {}
    if isinstance(difference, dict):
        divergence = ", first divergence " + str(
            difference.get("address", difference.get("word_index", "unknown"))
        )
    else:
        divergence = ""
    limitations = match.get("limitations", [])
    detail = "; ".join(str(item) for item in limitations[:3]) if isinstance(limitations, list) else ""
    if detail:
        detail = ", matcher limitation: " + _safe_text(detail, 240)
    return _safe_text(
        f"local matcher recovered source sha256={source_sha256}: {status} {score}/{total}"
        f"{divergence}{detail}; see the linked local recovery report",
        600,
    )


def _parse_match_report(returncode: int, stdout: str) -> dict[str, Any]:
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("production matcher did not return JSON") from exc
    if not isinstance(report, dict) or returncode not in {0, 3, 5}:
        raise ValueError("production matcher returned an invalid exit code or report")
    expected_codes = {"MATCHED": 0, "NONMATCHING": 3, "INCONCLUSIVE": 5}
    if expected_codes.get(report.get("status")) != returncode:
        raise ValueError("production matcher status and exit code disagree")
    return report


def _raise_matcher_process_error(result: WorkResult) -> None:
    text = (result.stdout + "\n" + result.stderr).lower()
    if re.search(
        r"(?is)(?:error:\s*compilation failed|compiler produced no object|"
        r"blocked:\s*mwccpsp is required|"
        r"mwccpsp(?:\.exe)?[^\r\n]{0,60}\b(?:is )?not found\b)",
        text,
    ):
        raise MatcherCompilerError(
            "MWCC did not produce a usable candidate object",
            excerpt=_safe_diagnostic_excerpt(result.stderr or result.stdout),
        )
    if re.search(
        r"(?is)(?:candidate(?: section)?[^\r\n]{0,160}(?:needs\s+\d+\s+bytes|"
        r"only\s+\d+\s+bytes|too small|too short|incomplete)|"
        r"needs\s+\d+\s+bytes[^\r\n]{0,120}section is)",
        text,
    ):
        raise MatcherIncomplete(
            "candidate object does not cover the complete function interval",
            excerpt=_safe_diagnostic_excerpt(result.stderr or result.stdout),
        )


def _explicit_inconclusive_match_report(
    result: WorkResult,
    *,
    claim: Claim,
    source: Path,
    out: Path,
    report_relative: str,
    compiler: str,
    flags: Sequence[str],
    includes: Sequence[str],
) -> dict[str, Any] | None:
    """Persist explicit comparator INCONCLUSIVE output without claiming a full comparison."""
    if result.returncode != 5 or out.is_symlink() or not out.is_dir():
        return None
    text = result.stdout + "\n" + result.stderr
    reasons = re.findall(r"(?im)^\s*INCONCLUSIVE:\s*(.+?)\s*$", text)
    if len(reasons) != 1 or source.is_symlink() or not source.is_file():
        return None
    relative = Path(report_relative)
    if relative.is_absolute() or ".." in relative.parts:
        return None
    object_path = out / f"{source.stem}.o"
    report_path = out / f"{source.stem}.match.json"
    if (
        object_path.is_symlink()
        or not object_path.is_file()
        or object_path.stat().st_size <= 0
        or object_path.stat().st_size > 16_000_000
        or report_path.exists()
        or report_path.is_symlink()
    ):
        return None
    expected_symbol = f"func_{claim.numeric_address:08X}"
    reason_class = (
        "candidate_symbol_unresolved"
        if "symbol" in reasons[0].lower()
        else "comparison_insufficient"
    )
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    object_hash = hashlib.sha256(object_path.read_bytes()).hexdigest()
    report: dict[str, Any] = {
        "address": claim.address,
        "function": expected_symbol,
        "symbol": None,
        "requested_symbol": expected_symbol,
        "section": ".text",
        "status": "INCONCLUSIVE",
        "evidence": "compiled-object",
        "equivalence": "candidate identity or comparison evidence is insufficient",
        "verified_decompilation": False,
        "exit_code": 5,
        "report_path": f"build/{relative.as_posix()}/{source.stem}.match.json",
        "provenance": {
            "compiler": compiler,
            "flags": list(flags),
            "includes": list(includes),
            "source": str(source),
            "source_sha256": source_hash,
            "object": str(object_path),
            "object_sha256": object_hash,
        },
        "match": {
            "status": "INCONCLUSIVE",
            "evidence": "binary-range",
            "equivalence": "candidate identity or comparison evidence is insufficient",
            "address": claim.numeric_address,
            "name": expected_symbol,
            "matching_words": -1,
            "total_words": claim.size_bytes // 4,
            "difference_count": 0,
            "differences": [],
            "limitations": [
                f"explicit matcher INCONCLUSIVE before a full word comparison: {reason_class}"
            ],
            "relocation_issues": [],
            "comparison_complete": False,
        },
    }
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return report


def _matcher_report_from_process(
    result: WorkResult,
    *,
    claim: Claim,
    source: Path,
    out: Path,
    config: Path,
    relative_out: str,
) -> dict[str, Any]:
    _raise_matcher_process_error(result)
    try:
        return _parse_match_report(result.returncode, result.stdout)
    except ValueError:
        if result.stdout.strip():
            raise
        try:
            settings = tomllib.loads(config.read_text(encoding="utf-8-sig"))
            compiler = str(settings["tools"]["mwccpsp"]["path"])
            flags = [str(item) for item in settings["match"]["flags"]]
            includes = [str(item) for item in settings["match"]["includes"]]
        except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
            raise ValueError("matcher local compiler provenance is unavailable") from exc
        report = _explicit_inconclusive_match_report(
            result,
            claim=claim,
            source=source,
            out=out,
            report_relative=relative_out,
            compiler=compiler,
            flags=flags,
            includes=includes,
        )
        if report is None:
            raise
        return report


def _persist_full_matcher_report(
    out: Path, source_stem: str, report: dict[str, Any]
) -> Path:
    """Keep the full comparison payload beside match_function's provenance summary."""
    if not re.fullmatch(r"func_[0-9A-Fa-f]{8}", source_stem):
        raise ValueError("matcher report source stem is not an EBOOT function symbol")
    path = out / f"{source_stem}.match.json"
    if path.is_symlink():
        raise ValueError("matcher report path is a symlink")
    if path.exists():
        if not path.is_file() or path.stat().st_size > 2_000_000:
            raise ValueError("existing matcher report is unsafe or too large")
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("existing matcher report is not valid JSON") from exc
        old_provenance = previous.get("provenance", {})
        new_provenance = report.get("provenance", {})
        if (
            previous.get("status") != report.get("status")
            or not isinstance(old_provenance, dict)
            or not isinstance(new_provenance, dict)
            or old_provenance.get("source_sha256") != new_provenance.get("source_sha256")
            or old_provenance.get("object_sha256") != new_provenance.get("object_sha256")
        ):
            raise ValueError("existing matcher report does not match the current compiler result")
    temporary = path.with_name(path.name + ".full-report.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("refusing to overwrite a matcher report temporary")
    try:
        temporary.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        if temporary.stat().st_size > 2_000_000:
            raise ValueError("full matcher report exceeds 2 MiB")
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return path


def _validate_complete_matcher_report(
    report: dict[str, Any],
    *,
    expected_address: int,
    expected_size: int,
    expected_source_sha256: str,
) -> None:
    """Reject malformed or partial comparisons without rejecting full INCONCLUSIVE results."""
    expected_words = expected_size // 4
    match = report.get("match")
    status = report.get("status")
    expected_function = f"func_{expected_address:08X}"
    precomparison_inconclusive = (
        status == "INCONCLUSIVE" and match.get("comparison_complete") is False
        if isinstance(match, dict)
        else False
    )
    if (
        expected_size <= 0
        or expected_size % 4
        or not isinstance(status, str)
        or status not in {"MATCHED", "NONMATCHING", "INCONCLUSIVE"}
        or not isinstance(match, dict)
        or match.get("status") != status
        or report.get("function") != expected_function
        or (
            report.get("symbol") != expected_function
            and not (
                precomparison_inconclusive
                and report.get("symbol") is None
                and report.get("requested_symbol") == expected_function
            )
        )
    ):
        raise MatcherIncomplete("matcher report is malformed or identifies another function")
    provenance = report.get("provenance")
    if (
        not isinstance(provenance, dict)
        or provenance.get("source_sha256") != expected_source_sha256
        or not isinstance(provenance.get("object_sha256"), str)
        or not HEX_SHA256.fullmatch(provenance["object_sha256"])
    ):
        raise MatcherIncomplete("matcher report is missing source/object provenance")
    try:
        report_address = int(str(report.get("address")), 0)
    except (TypeError, ValueError):
        raise MatcherIncomplete("matcher report is missing the expected function address") from None
    if report_address != expected_address:
        raise MatcherIncomplete("matcher report identifies another function address")

    if precomparison_inconclusive:
        if (
            report.get("evidence") != "compiled-object"
            or report.get("verified_decompilation") is not False
            or not isinstance(match.get("matching_words"), int)
            or match.get("matching_words") != -1
            or match.get("total_words") != expected_words
            or match.get("difference_count") != 0
            or match.get("differences") != []
            or not isinstance(match.get("limitations"), list)
            or not match["limitations"]
            or match.get("relocation_issues") != []
        ):
            raise MatcherIncomplete("precomparison INCONCLUSIVE matcher evidence is malformed")
        return

    matching_words = match.get("matching_words")
    total_words = match.get("total_words")
    difference_count = match.get("difference_count")
    if (
        isinstance(matching_words, bool)
        or not isinstance(matching_words, int)
        or isinstance(total_words, bool)
        or not isinstance(total_words, int)
        or isinstance(difference_count, bool)
        or not isinstance(difference_count, int)
        or total_words != expected_words
        or not 0 <= matching_words <= total_words
        or not 0 <= difference_count <= total_words
        or matching_words + difference_count > total_words
    ):
        raise MatcherIncomplete("matcher report does not cover the complete function interval")
    for key in ("differences", "limitations", "relocation_issues"):
        if not isinstance(match.get(key), list):
            raise MatcherIncomplete("matcher report omitted comparison evidence")
    relocation_issues = match["relocation_issues"]
    if any(not isinstance(issue, str) for issue in relocation_issues):
        raise MatcherIncomplete("matcher report contains malformed relocation evidence")
    if any(issue.startswith("size mismatch:") for issue in relocation_issues):
        raise MatcherIncomplete("matcher report identifies an incomplete object interval")


def _wsl_path(path: Path, distro: str) -> str:
    result = subprocess.run(
        ["wsl.exe", "-d", distro, "--exec", "wslpath", "-a", str(path.resolve())],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise OSError("WSL path conversion failed")
    value = result.stdout.strip()
    if not value.startswith("/"):
        raise OSError("WSL returned a non-absolute path")
    return value


def validate_ghidra_log(text: str, address: int) -> dict[str, Any]:
    """Validate the complete, contiguous instruction listing emitted by Ghidra."""
    try:
        marker_names = (
            "SETO_LANGUAGE",
            "SETO_FUNCTION_START",
            "SETO_FUNCTION_END",
            "SETO_FUNCTION_BODY_START",
            "SETO_FUNCTION_BODY_END",
            "SETO_FUNCTION_BODY_ADDRESSES",
            "SETO_FUNCTION_BODY_RANGES",
            "SETO_ADDRESSABLE_UNIT_SIZE",
            "SETO_BOUNDARY_STATUS",
            "SETO_DECOMP_STATUS",
            "SETO_INSTRUCTION_COUNT",
        )
        markers: dict[str, str] = {}
        for name in marker_names:
            matches = re.findall(rf"(?m)^\s*{re.escape(name)}=([^\s]+)\s*$", text)
            if len(matches) != 1:
                raise ValueError("missing or duplicate marker")
            markers[name] = matches[0]
        start = int(markers["SETO_FUNCTION_BODY_START"], 16)
        end = int(markers["SETO_FUNCTION_BODY_END"], 16)
        function_end = int(markers["SETO_FUNCTION_END"], 16)
        requested_start = int(markers["SETO_FUNCTION_START"], 0)
        addresses = int(markers["SETO_FUNCTION_BODY_ADDRESSES"])
        ranges = int(markers["SETO_FUNCTION_BODY_RANGES"])
        unit = int(markers["SETO_ADDRESSABLE_UNIT_SIZE"])
        instruction_count = int(markers["SETO_INSTRUCTION_COUNT"])
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Ghidra evidence does not prove one exact Allegrex function boundary"
        ) from exc

    raw_instruction_markers = re.findall(r"(?m)^[ \t]*SETO_INSN=", text)
    instruction_rows = re.findall(
        r"(?m)^[ \t]*SETO_INSN=(0x[0-9a-fA-F]+)[ \t]+SIZE=(\d+)(?:[ \t]+\S[^\r\n]*)?[ \t]*\r?$",
        text,
    )
    try:
        instructions = [(int(item, 16), int(size)) for item, size in instruction_rows]
    except ValueError as exc:
        raise ValueError(
            "Ghidra evidence does not prove one exact Allegrex function boundary"
        ) from exc
    size = end - start
    if (
        markers["SETO_LANGUAGE"] != "Allegrex:LE:32:default"
        or markers["SETO_BOUNDARY_STATUS"] != "EXACT"
        or markers["SETO_DECOMP_STATUS"] != "OK"
        or start != address
        or requested_start != address
        or function_end != end
        or start % 4
        or size <= 0
        or size % 4
        or addresses != size
        or ranges != 1
        or unit != 1
        or len(raw_instruction_markers) != len(instruction_rows)
        or len(instructions) != instruction_count
        or instruction_count != size // 4
        or any(
            instruction_address != start + index * 4 or instruction_size != 4
            for index, (instruction_address, instruction_size) in enumerate(instructions)
        )
    ):
        raise ValueError("Ghidra evidence does not prove one exact Allegrex function boundary")
    return {
        "language": "Allegrex:LE:32:default",
        "start": f"0x{start:x}",
        "end": f"0x{end:x}",
        "size_bytes": size,
        "instruction_count": instruction_count,
    }


def validate_export_evidence(path: Path, address: str, nid: str) -> None:
    """Require a unique, relocated export with a real importing PRX call site."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("real export/import triage report cannot be read") from exc
    rows = [
        item
        for item in payload.get("exports", [])
        if item.get("address", "").lower() == address.lower()
        and item.get("nid", "").upper() == nid.upper()
        and item.get("library") == "libehsys"
    ]
    if len(rows) != 1:
        raise ValueError("candidate does not have one unique libehsys export/NID")
    row = rows[0]
    relocation = row.get("pointer_relocation", {})
    if (
        relocation.get("type") != "R_MIPS_32"
        or relocation.get("addend_valid") is not True
        or int(relocation.get("addend", -1)) != int(address, 0)
        or relocation.get("application_valid") is not True
    ):
        raise ValueError("candidate export pointer relocation is not proven")
    calls = [
        site
        for importer in row.get("importers", [])
        for site in importer.get("call_sites", [])
    ]
    limitations = [
        limitation
        for importer in row.get("importers", [])
        for limitation in importer.get("table_limitations", [])
    ]
    if not calls or limitations:
        raise ValueError("candidate lacks real importing call sites or has table limitations")


def _promotion_context(
    store: CampaignStore,
    repo_root: Path,
    config: dict[str, Any],
    address: str,
) -> dict[str, Any]:
    """Validate every persisted input before fresh integration builds are run."""
    try:
        numeric_address = int(address, 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("promotion address must be hexadecimal") from exc
    if not 0 <= numeric_address <= 0xFFFFFFFF:
        raise ValueError("promotion address is outside the 32-bit EBOOT address space")
    task_address = f"0x{numeric_address:x}"
    task = store.get_task(task_address)
    if task["status"] != "matched" or task["boundary_status"] != "EXACT":
        raise ValueError("only an EXACT, campaign-certified MATCHED function can be promoted")
    size_bytes = int(task["size_bytes"])
    source_hash = task["checkpoint"].get("best_source_sha256")
    snapshot_relative = task["checkpoint"].get("best_source_snapshot")
    result = task["best_result"]
    if not isinstance(result, dict):
        raise ValueError("campaign has no structured best result")
    if not isinstance(source_hash, str) or not HEX_SHA256.fullmatch(source_hash):
        raise ValueError("campaign checkpoint has no valid best-source SHA-256")
    expected_snapshot = f"decomp-campaign/checkpoints/{numeric_address:08x}/{source_hash}.c"
    if snapshot_relative != expected_snapshot or result.get("source_snapshot_path") != expected_snapshot:
        raise ValueError("best-source checkpoint path does not match its address/hash")
    source = campaign_build_path(repo_root, expected_snapshot)
    if source.is_symlink() or not source.is_file():
        raise ValueError("best-source checkpoint is missing or unsafe")
    if hashlib.sha256(source.read_bytes()).hexdigest() != source_hash:
        raise ValueError("best-source checkpoint hash does not match its contents")
    if not is_deterministic_match(
        result,
        expected_address=numeric_address,
        expected_size=size_bytes,
    ):
        raise ValueError("stored best result is not a complete deterministic MATCHED result")
    if any(
        report.get("provenance", {}).get("source_sha256") != source_hash
        for report in result["reports"]
    ):
        raise ValueError("stored matcher reports do not certify the checkpoint source hash")

    origin = result.get("campaign_origin")
    if not isinstance(origin, dict):
        raise ValueError("best result is missing campaign worker/session provenance")
    worker_id = origin.get("worker_id")
    worker_config = config.get("workers", {}).get(worker_id)
    session_id = origin.get("session_id")
    if (
        not isinstance(worker_id, str)
        or not isinstance(worker_config, dict)
        or origin.get("provider") != worker_config.get("provider")
        or not isinstance(session_id, str)
        or not re.fullmatch(r"ses_[A-Za-z0-9_-]+", session_id)
        or not isinstance(origin.get("attempt_number"), int)
        or origin["attempt_number"] <= 0
    ):
        raise ValueError("campaign worker/session provenance is invalid")

    worker_root_rel = Path(config["worktrees"]["root"]).relative_to("build") / worker_id
    worker_root = campaign_build_path(repo_root, worker_root_rel)
    if worker_root.is_symlink() or not worker_root.is_dir():
        raise ValueError("origin worker worktree is missing or unsafe")
    evidence_claim = Claim(
        address=task_address,
        size_bytes=size_bytes,
        nid=task["nid"],
        priority=int(task["priority"]),
        boundary_status=task["boundary_status"],
        worker_id=worker_id,
        provider=str(origin["provider"]),
        session_id=session_id,
        attempt_number=int(origin.get("attempt_number", 0)),
        lease_until=0,
        checkpoint=task["checkpoint"],
        evidence=task["evidence"],
    )
    boundary = validated_cached_ghidra_boundary(worker_root, evidence_claim)
    if boundary is None or result.get("ghidra_boundary") != boundary:
        raise ValueError("best result lacks matching hash-checked exact Ghidra evidence")
    if result.get("ghidra_log_sha256") != task["checkpoint"].get("ghidra_log_sha256"):
        raise ValueError("Ghidra report hash differs from the campaign checkpoint")

    eboot = repo_root / config["inputs"]["eboot"]
    triage = repo_root / config["inputs"]["triage_report"]
    if any(path.is_symlink() or not path.is_file() for path in (eboot, triage)):
        raise ValueError("private EBOOT or export/import triage is missing or unsafe")
    if hashlib.sha256(eboot.read_bytes()).hexdigest() != config["inputs"]["eboot_sha256"].lower():
        raise ValueError("private EBOOT hash differs from the campaign baseline")
    validate_export_evidence(triage, task_address, task["nid"])

    destination = _safe_worktree_path(
        repo_root, Path("decomp/src/eboot") / f"func_{numeric_address:08X}.c"
    )
    if destination.is_symlink():
        raise ValueError("certified source destination is a symlink")
    if destination.exists():
        if not destination.is_file():
            raise ValueError("certified source destination is not a regular file")
        existing_hash = hashlib.sha256(destination.read_bytes()).hexdigest()
        if existing_hash != source_hash:
            raise ValueError("promotion conflicts with an existing certified source")
    return {
        "address": task_address,
        "numeric_address": numeric_address,
        "size_bytes": size_bytes,
        "nid": task["nid"],
        "source_hash": source_hash,
        "source": source,
        "destination": destination,
        "origin": origin,
        "result": result,
        "boundary": boundary,
        "worker_root": worker_root,
    }


def _append_promotion_documentation(
    repo_root: Path,
    record: dict[str, Any],
    *,
    campaign_id: str = "SETO-DECOMP-045",
) -> None:
    path = repo_root / "docs" / "decomp-progress.md"
    if path.is_symlink() or not path.is_file():
        raise ValueError("decompilation progress documentation is missing or unsafe")
    existing = path.read_text(encoding="utf-8")
    if not re.fullmatch(r"SETO-DECOMP-[0-9]{3}", campaign_id):
        raise ValueError("campaign documentation identifier is invalid")
    heading = f"## {campaign_id} — Promoções certificadas"
    address = record["address"]
    source_hash = record["source_sha256"]
    session_id = record["session_id"]
    object_hashes = ", ".join(record["object_sha256"])
    entry = (
        f"- `{address}` — {record['size_bytes'] // 4} instruções, source SHA-256 "
        f"`{source_hash}`; origem `{record['worker_id']}` / sessão `{session_id}`; "
        f"dois builds MWCC certificados: `{object_hashes}`.\n"
    )
    if heading in existing:
        section_start = existing.index(heading)
        section_end = existing.find("\n## ", section_start + len(heading))
        section = existing[section_start:] if section_end < 0 else existing[section_start:section_end]
        previous = [line for line in section.splitlines() if line.startswith(f"- `{address}` ")]
        if previous:
            if len(previous) == 1 and source_hash in previous[0] and session_id in previous[0]:
                return
            raise ValueError("progress documentation already records a conflicting promotion")
        section_suffix = existing[section_end:] if section_end >= 0 else ""
        updated = existing[:section_start] + section.rstrip() + "\n" + entry + section_suffix
    else:
        updated = existing.rstrip() + "\n\n" + heading + "\n\n" + entry
    temporary = path.with_name(path.name + ".promotion.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("refusing to overwrite a progress-documentation temporary")
    try:
        temporary.write_text(updated, encoding="utf-8", newline="\n")
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def promote_campaign_source(
    store: CampaignStore,
    config: dict[str, Any],
    repo_root: Path,
    address: str,
    *,
    deadline: float | None = None,
) -> dict[str, Any]:
    """Revalidate a stored candidate with two new MWCC builds, then integrate it."""
    repo_root = repo_root.resolve(strict=True)
    context = _promotion_context(store, repo_root, config, address)
    if store.stop_requested() or (
        deadline is not None and time.monotonic() >= deadline
    ):
        raise ValueError("campaign stop is active; clear it before source integration")
    source = context["source"]
    destination = context["destination"]
    source_hash = context["source_hash"]
    numeric_address = context["numeric_address"]
    eboot = repo_root / config["inputs"]["eboot"]
    mwcc_config = repo_root / config["toolchain"]["mwcc_config"]
    matcher = repo_root / "scripts" / "match_function.py"
    if any(path.is_symlink() or not path.is_file() for path in (mwcc_config, matcher)):
        raise ValueError("local MWCC configuration or production matcher is missing or unsafe")
    origin = context["origin"]
    claim = Claim(
        address=context["address"],
        size_bytes=context["size_bytes"],
        nid=context["nid"],
        priority=0,
        boundary_status="EXACT",
        worker_id="integration",
        provider=str(origin["provider"]),
        session_id=str(origin["session_id"]),
        attempt_number=int(origin["attempt_number"]),
        lease_until=0,
        checkpoint={},
        evidence={},
    )
    verifier = CampaignRunner(
        store,
        opencode_command=["opencode"],
        worktrees={"integration": repo_root},
        output_limit=int(config["limits"]["max_output_bytes"]),
        wsl_distro=config["toolchain"]["wsl_distro"],
    )
    if os.name == "nt":
        reports = verifier._run_matcher_wsl(
            repo_root, claim, source, eboot, mwcc_config, matcher, deadline=deadline
        )
    else:
        reports = verifier._run_matcher_native(
            repo_root, claim, source, eboot, mwcc_config, matcher, deadline=deadline
        )
    objects = [str(report.get("provenance", {}).get("object_sha256", "")) for report in reports]
    if not all(
        is_strict_match(
            report,
            expected_address=numeric_address,
            expected_size=context["size_bytes"],
        )
        and report.get("provenance", {}).get("source_sha256") == source_hash
        for report in reports
    ) or len(objects) != 2 or objects[0] != objects[1]:
        raise ValueError("fresh promotion builds did not produce two deterministic full MATCHED reports")

    already_present = destination.is_file()
    if not already_present:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            raise ValueError("promotion destination appeared during integration")
        try:
            with destination.open("xb") as output, source.open("rb") as input_stream:
                shutil.copyfileobj(input_stream, output)
            if destination.is_symlink() or hashlib.sha256(destination.read_bytes()).hexdigest() != source_hash:
                raise ValueError("promoted source failed its post-copy hash check")
        except BaseException:
            if destination.is_file() and not destination.is_symlink():
                destination.unlink()
            raise

    record = {
        "address": context["address"],
        "size_bytes": context["size_bytes"],
        "source_sha256": source_hash,
        "object_sha256": objects,
        "worker_id": origin["worker_id"],
        "session_id": origin["session_id"],
        "already_present": already_present,
        "status": "MATCHED",
    }
    campaign_id = config.get("campaign", {}).get("id", "SETO-DECOMP-045")
    _append_promotion_documentation(repo_root, record, campaign_id=campaign_id)
    return record


def normalize_certified_addresses(baseline: Any) -> frozenset[str]:
    """Normalize and validate the inventory's certified EBOOT address set.

    Inventories predating the address list remain compatible and contribute an
    empty exclusion set; no MATCHED records are synthesized in campaign SQLite.
    """
    if baseline is None:
        return frozenset()
    if not isinstance(baseline, dict):
        raise ValueError("inventory baseline must be an object")
    if "eboot_matched_addresses" not in baseline:
        return frozenset()
    addresses = baseline["eboot_matched_addresses"]
    if not isinstance(addresses, list):
        raise ValueError("baseline matched addresses must be a list")
    normalized = [
        _normalize_eboot_address(value, label="baseline matched address")
        for value in addresses
    ]
    if len(normalized) != len(set(normalized)):
        raise ValueError("baseline contains duplicate matched addresses")
    function_count = baseline.get("eboot_matched_functions")
    if (
        isinstance(function_count, bool)
        or not isinstance(function_count, int)
        or function_count != len(normalized)
    ):
        raise ValueError("baseline matched-address count disagrees with its function total")
    return frozenset(normalized)


def load_inventory(path: Path) -> tuple[list[Candidate], dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1 or not isinstance(payload.get("candidates"), list):
        raise ValueError("unsupported campaign inventory schema")
    candidates = [Candidate.from_dict(item) for item in payload["candidates"]]
    addresses = [candidate.address.lower() for candidate in candidates]
    if len(addresses) != len(set(addresses)):
        raise ValueError("campaign inventory contains duplicate addresses")
    nids = [candidate.nid.upper() for candidate in candidates]
    if len(nids) != len(set(nids)):
        raise ValueError("campaign inventory contains duplicate EBOOT export NIDs")
    baseline = payload.get("baseline", {})
    normalized_baseline = normalize_certified_addresses(baseline)
    if isinstance(baseline, dict) and "eboot_matched_addresses" in baseline:
        ranges = baseline.get("eboot_matched_ranges")
        if ranges is not None:
            if not isinstance(ranges, list):
                raise ValueError("baseline matched ranges must be a list")
            parsed_ranges = []
            for item in ranges:
                if not isinstance(item, dict):
                    raise ValueError("baseline matched range is malformed")
                try:
                    start = int(str(item["address"]), 0)
                    size = int(item["size_bytes"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise ValueError("baseline matched range is malformed") from exc
                if size <= 0 or size % 4:
                    raise ValueError("baseline matched range size must be a positive word multiple")
                parsed_ranges.append((start, start + size))
            if len(parsed_ranges) != len(normalized_baseline):
                raise ValueError("baseline matched ranges disagree with the matched-address list")
            if sorted(start for start, _end in parsed_ranges) != sorted(
                int(item, 0) for item in normalized_baseline
            ):
                raise ValueError("baseline matched ranges do not match certified addresses")
            for index, (start, end) in enumerate(sorted(parsed_ranges)):
                if any(start < prior_end and prior_start < end for prior_start, prior_end in sorted(parsed_ranges)[:index]):
                    raise ValueError("baseline contains overlapping certified function ranges")
    return candidates, payload


def discover_proven_exports(
    triage_path: Path,
    existing_candidates: Sequence[Candidate],
    *,
    matched_addresses: Iterable[str],
) -> list[Candidate]:
    """Find only unique libehsys exports with verified relocation and PRX call sites."""
    if triage_path.is_symlink() or not triage_path.is_file() or triage_path.stat().st_size > 32_000_000:
        raise ValueError("export triage report is missing, unsafe, or too large")
    try:
        payload = json.loads(triage_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("export triage report is malformed") from exc
    exports = payload.get("exports") if isinstance(payload, dict) else None
    if not isinstance(exports, list):
        raise ValueError("export triage report omitted its exports list")
    libehsys = [
        row
        for row in exports
        if isinstance(row, dict) and row.get("library") == "libehsys"
    ]
    address_counts: dict[int, int] = {}
    nid_counts: dict[str, int] = {}
    parsed_rows: list[tuple[dict[str, Any], int, str]] = []
    for row in libehsys:
        try:
            address_value = row.get("address")
            address = int(str(address_value), 0)
            nid = int(str(row.get("nid")), 0)
        except (TypeError, ValueError):
            continue
        if not 0 <= address <= 0xFFFFFFFF or not 0 <= nid <= 0xFFFFFFFF:
            continue
        nid_text = f"0x{nid:08X}"
        parsed_rows.append((row, address, nid_text))
        address_counts[address] = address_counts.get(address, 0) + 1
        nid_counts[nid_text] = nid_counts.get(nid_text, 0) + 1

    existing_addresses = {item.numeric_address for item in existing_candidates}
    existing_nids = {item.nid.upper() for item in existing_candidates}
    certified = {int(str(item), 0) for item in matched_addresses}
    triage_hash = hashlib.sha256(triage_path.read_bytes()).hexdigest()
    discovered: list[Candidate] = []
    for row, address, nid in parsed_rows:
        if (
            address in existing_addresses
            or address in certified
            or address_counts.get(address) != 1
            or nid_counts.get(nid) != 1
            or nid in existing_nids
        ):
            continue
        relocation = row.get("pointer_relocation")
        if not isinstance(relocation, dict):
            continue
        try:
            addend_value = relocation.get("addend")
            addend = int(addend_value, 0) if isinstance(addend_value, str) else int(addend_value)
        except (TypeError, ValueError):
            continue
        if (
            relocation.get("type") != "R_MIPS_32"
            or relocation.get("addend_valid") is not True
            or relocation.get("application_valid") is not True
            or addend != address
        ):
            continue
        importers = row.get("importers")
        if not isinstance(importers, list):
            continue
        call_sites: list[dict[str, Any]] = []
        limited = False
        for importer in importers:
            if not isinstance(importer, dict):
                continue
            limitations = importer.get("table_limitations", [])
            if not isinstance(limitations, list) or limitations:
                limited = True
                break
            module = importer.get("module")
            sites = importer.get("call_sites")
            if not isinstance(module, str) or not isinstance(sites, list):
                continue
            values = []
            for site in sites[:128]:
                if isinstance(site, dict):
                    site = site.get("address")
                if isinstance(site, str) and re.fullmatch(r"0x[0-9a-fA-F]+", site):
                    values.append(site.lower())
            if values:
                call_sites.append({"module": _safe_text(module, 100), "sites": values})
        if limited or not call_sites:
            continue
        call_count = sum(len(item["sites"]) for item in call_sites)
        evidence = {
            "source": "build/seto035/export-triage.json verified incremental discovery",
            "triage_sha256": triage_hash,
            "library": "libehsys",
            "export_entry": row.get("entry_index"),
            "export_slot": row.get("slot_index"),
            "pointer_site": _safe_text(row.get("pointer_site", ""), 100),
            "pointer_relocation": {
                "type": "R_MIPS_32",
                "addend": f"0x{addend:08x}",
                "application_valid": True,
            },
            "prx_call_sites": call_sites,
            "size_basis": "UNVERIFIED; no size assigned until a complete Ghidra boundary is proved",
        }
        discovered.append(
            Candidate(
                address=f"0x{address:x}",
                size_bytes=0,
                nid=nid,
                priority=20 + min(call_count, 60),
                boundary_status="UNVERIFIED",
                evidence=evidence,
                initial_state="needs_boundary",
            )
        )
        existing_addresses.add(address)
        existing_nids.add(nid)
    return discovered


def append_inventory_candidates(path: Path, candidates: Sequence[Candidate]) -> int:
    """Append new zero-size UNVERIFIED exports atomically and idempotently."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("campaign inventory is missing or unsafe")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1 or not isinstance(payload.get("candidates"), list):
        raise ValueError("unsupported campaign inventory schema")
    address_nids = {
        int(str(item.get("address")), 0): str(item.get("nid", "")).upper()
        for item in payload["candidates"]
        if isinstance(item, dict) and item.get("address") is not None
    }
    nids = {
        str(item.get("nid", "")).upper()
        for item in payload["candidates"]
        if isinstance(item, dict)
    }
    inserted = 0
    for candidate in candidates:
        if candidate.boundary_status != "UNVERIFIED" or candidate.size_bytes != 0:
            raise ValueError("incremental discovery may append only zero-size UNVERIFIED candidates")
        if candidate.numeric_address in address_nids:
            if address_nids[candidate.numeric_address] != candidate.nid.upper():
                raise ValueError("incremental discovery conflicts with an inventoried address/NID")
            continue
        if candidate.nid.upper() in nids:
            raise ValueError("incremental discovery would duplicate an export NID")
        payload["candidates"].append(
            {
                "address": f"0x{candidate.numeric_address:x}",
                "size_bytes": 0,
                "nid": candidate.nid.upper(),
                "priority": candidate.priority,
                "boundary_status": "UNVERIFIED",
                "initial_state": "needs_boundary",
                "evidence": candidate.evidence,
            }
        )
        address_nids[candidate.numeric_address] = candidate.nid.upper()
        nids.add(candidate.nid.upper())
        inserted += 1
    if not inserted:
        return 0
    temporary = path.with_name(path.name + ".discovery.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("refusing to overwrite an inventory discovery temporary")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return inserted


def record_inventory_promotion(path: Path, store: CampaignStore, address: str) -> bool:
    """Increment the checked EBOOT baseline only after independent promotion succeeds."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("campaign inventory is missing or unsafe")
    task = store.get_task(address)
    if task["status"] != "matched" or task["boundary_status"] != "EXACT":
        raise ValueError("only an EXACT SQLite-certified MATCHED function can update the baseline")
    numeric = int(task["address"], 0)
    normalized = f"0x{numeric:x}"
    payload = json.loads(path.read_text(encoding="utf-8"))
    baseline = payload.get("baseline")
    if not isinstance(baseline, dict) or not isinstance(
        baseline.get("eboot_matched_addresses"), list
    ) or not isinstance(baseline.get("eboot_matched_ranges"), list):
        raise ValueError("campaign inventory lacks its certified EBOOT address/range baseline")
    addresses = [f"0x{int(str(item), 0):x}" for item in baseline["eboot_matched_addresses"]]
    if normalized in addresses:
        return False
    addresses.append(normalized)
    addresses.sort(key=lambda item: int(item, 0))
    ranges = baseline["eboot_matched_ranges"]
    if any(
        isinstance(item, dict)
        and int(str(item.get("address", "-1")), 0) == numeric
        for item in ranges
    ):
        raise ValueError("inventory range baseline already contains an unlisted address")
    ranges.append({"address": normalized, "size_bytes": int(task["size_bytes"])})
    ranges.sort(key=lambda item: int(str(item["address"]), 0))
    baseline["eboot_matched_addresses"] = addresses
    baseline["eboot_matched_functions"] = len(addresses)
    baseline["eboot_matched_instructions"] = int(
        baseline["eboot_matched_instructions"]
    ) + int(task["size_bytes"]) // 4
    temporary = path.with_name(path.name + ".promotion.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("refusing to overwrite a campaign-baseline temporary")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return True


def load_config(path: Path = DEFAULT_CONFIG) -> dict[str, Any]:
    with path.open("rb") as stream:
        value = tomllib.load(stream)
    if value.get("schema_version") != 1:
        raise ValueError("unsupported campaign configuration schema")
    models = value.get("models", {}).get("allowlist", [])
    if not isinstance(models, list) or not models:
        raise ValueError("model allowlist must be a non-empty list")
    if len(models) != len(set(models)):
        raise ValueError("model allowlist contains duplicates")
    campaign = value.get("campaign", {})
    if campaign:
        campaign_id = campaign.get("id") if isinstance(campaign, dict) else None
        if not isinstance(campaign_id, str) or not re.fullmatch(
            r"SETO-DECOMP-[0-9]{3}", campaign_id
        ):
            raise ValueError("campaign id must use the SETO-DECOMP-NNN form")
    limits = value.get("limits", {})

    def positive_integer(mapping: dict[str, Any], key: str, *, required: bool = True) -> None:
        if key not in mapping and not required:
            return
        item = mapping.get(key)
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise ValueError(f"campaign {key} must be a positive integer")

    def positive_number(mapping: dict[str, Any], key: str, *, required: bool = True) -> None:
        if key not in mapping and not required:
            return
        item = mapping.get(key)
        if (
            isinstance(item, bool)
            or not isinstance(item, (int, float))
            or not math.isfinite(float(item))
            or item <= 0
        ):
            raise ValueError(f"campaign {key} must be a positive number")

    for key in (
        "max_workers",
        "max_tasks",
        "max_attempts_per_candidate",
        "max_attempts_without_progress",
        "max_output_bytes",
    ):
        positive_integer(limits, key)
    for key in ("ghidra_parallelism", "matcher_parallelism"):
        positive_integer(limits, key, required=False)
    for key in (
        "max_duration_seconds",
        "lease_seconds",
        "agent_timeout_seconds",
        "max_retry_after_seconds",
    ):
        positive_number(limits, key)
    refinement = value.get("refinement", {})
    if not isinstance(refinement, dict):
        raise ValueError("campaign refinement config must be an object")
    positive_integer(refinement, "max_consecutive_attempts", required=False)
    recovery = value.get("recovery", {})
    if not isinstance(recovery, dict):
        raise ValueError("campaign recovery config must be an object")
    positive_integer(recovery, "max_variants_per_candidate", required=False)
    positive_integer(recovery, "prompt_evidence_per_candidate", required=False)
    source_roots = recovery.get("source_roots", [])
    if not isinstance(source_roots, list) or any(
        not isinstance(root, str)
        or Path(root).is_absolute()
        or ".." in Path(root).parts
        or not Path(root).parts
        or Path(root).parts[0] != "build"
        for root in source_roots
    ):
        raise ValueError("campaign recovery source roots must remain under build/")
    pilot = value.get("pilot", {})
    if not 1 <= int(pilot.get("max_tasks", 0)) <= 4:
        raise ValueError("pilot max_tasks must stay within four attempts")
    if not 1 <= int(pilot.get("max_duration_seconds", 0)) <= 1800:
        raise ValueError("pilot duration must stay within 30 minutes")
    try:
        pilot_addresses = [f"0x{int(item, 0):x}" for item in pilot["candidate_addresses"]]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("pilot candidate addresses must be hexadecimal") from exc
    if set(pilot_addresses) != {"0x2c28c", "0x4217c"} or len(pilot_addresses) != 2:
        raise ValueError("pilot must remain scoped to 0x2C28C and 0x4217C")
    workers = value.get("workers", {})
    if not isinstance(workers, dict) or not workers:
        raise ValueError("campaign requires at least one configured worker")
    for worker_id, worker in workers.items():
        if not re.fullmatch(r"[a-z0-9-]+", worker_id):
            raise ValueError("worker identifiers may contain only lowercase letters, digits, and hyphens")
        if not re.fullmatch(r"[a-z0-9-]+", str(worker.get("agent", ""))):
            raise ValueError(f"worker {worker_id} must name a valid restricted agent")
        positive_integer(worker, "max_parallel", required=False)
        if worker.get("usage_mode", "unknown") not in {
            "unknown",
            "subscription_included",
            "free",
        }:
            raise ValueError(f"worker {worker_id} has an unsupported usage_mode")
    return value


def _unwrap_api_data(value: Any) -> Any:
    return value.get("data", value) if isinstance(value, dict) else value


def _provider_auth_metadata(payload: Any, provider: str) -> dict[str, Any]:
    """Summarize auth-list metadata without exposing credential labels or values."""
    entries = _unwrap_api_data(payload)
    if not isinstance(entries, list):
        return {"auth": "not-listed", "method": None, "single_credential": False}
    matches = [
        entry
        for entry in entries
        if isinstance(entry, dict) and entry.get("id") == provider
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("connections"), list):
        return {"auth": "not-listed", "method": None, "single_credential": False}
    connections = matches[0]["connections"]
    if len(connections) != 1 or not isinstance(connections[0], dict):
        return {"auth": "ambiguous", "method": None, "single_credential": False}
    connection = connections[0]
    if connection.get("type") == "environment":
        return {"auth": "environment", "method": connection.get("method"), "single_credential": False}
    if connection.get("type") != "credential":
        return {"auth": "not-listed", "method": None, "single_credential": False}
    return {
        "auth": "stored",
        "method": connection.get("method"),
        "single_credential": True,
    }


def _chatgpt_oauth_method_available(payload: Any, method_id: Any) -> bool:
    """Require an operator-confirmed method that this OpenCode build advertises as OAuth."""
    if method_id not in CHATGPT_OAUTH_METHODS:
        return False
    integration = _unwrap_api_data(payload)
    if not isinstance(integration, dict) or integration.get("id") != "openai":
        return False
    methods = integration.get("methods")
    return isinstance(methods, list) and any(
        isinstance(method, dict)
        and method.get("id") == method_id
        and method.get("type") == "oauth"
        for method in methods
    )


def _openai_base_url_is_default(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        route = urlsplit(value)
        default = urlsplit(OPENAI_DEFAULT_BASE_URL)
    except ValueError:
        return False
    return bool(
        route.scheme == "https"
        and route.hostname == default.hostname
        and route.port is None
        and route.path.rstrip("/") == default.path
        and not route.query
        and not route.fragment
        and not route.username
        and not route.password
    )


def _openai_route_is_subscription_compatible(
    payload: Any, model_metadata: Any = None
) -> bool:
    """Reject API-key overrides and custom gateways; accept only native OpenAI defaults."""
    provider = _unwrap_api_data(payload)
    if not isinstance(provider, dict) or provider.get("id") != "openai":
        return False
    settings = provider.get("settings")
    if (
        provider.get("package") != OPENAI_PROVIDER_PACKAGE
        or not isinstance(settings, dict)
        or not _openai_base_url_is_default(settings.get("baseURL"))
        or settings.get("apiKey")
        or provider.get("headers")
        or provider.get("body")
    ):
        return False
    model = _unwrap_api_data(model_metadata)
    if model is None:
        return True
    if not isinstance(model, dict) or model.get("providerID") != "openai":
        return False
    model_settings = model.get("settings")
    if not isinstance(model_settings, dict):
        return False
    if (
        model.get("package") not in {None, OPENAI_PROVIDER_PACKAGE}
        or ("baseURL" in model_settings and not _openai_base_url_is_default(model_settings["baseURL"]))
        or model_settings.get("apiKey")
        or model.get("headers")
        or model.get("body")
    ):
        return False
    return True


def worker_readiness(
    worker: dict[str, Any], observed: dict[str, Any], allowed_models: Iterable[str]
) -> dict[str, Any]:
    """Require catalog, verified billing/auth, and restricted tools."""
    blockers: list[str] = []
    model = worker.get("model")
    provider = worker.get("provider")
    if model not in set(allowed_models):
        blockers.append("model_not_allowlisted")
    if observed.get("catalog") != "available":
        blockers.append("model_not_in_catalog")
    public_free_auth = (
        provider == "opencode"
        and model == "opencode/deepseek-v4.1-flash-free"
        and observed.get("auth") == "public"
        and observed.get("public_model_metadata") is True
    )
    if observed.get("auth") != "stored" and not public_free_auth:
        blockers.append("provider_auth_not_listed")
    if worker.get("access_verified") is not True:
        blockers.append("provider_access_unverified")
    usage_mode = worker.get("usage_mode")
    if usage_mode == "unknown":
        blockers.append("usage_mode_unverified")
    if provider == "openai":
        if usage_mode != "subscription_included":
            blockers.append("additional_cost_not_excluded")
        if observed.get("chatgpt_oauth_verified") is not True:
            blockers.append("chatgpt_subscription_auth_unverified")
        if observed.get("provider_route_compatible") is not True:
            blockers.append("provider_route_not_subscription_compatible")
        if observed.get("model_status") != "active":
            blockers.append("model_not_active")
        if observed.get("model_enabled") is not True:
            blockers.append("model_disabled_or_unverified")
    elif provider == "opencode":
        if (
            usage_mode != "free"
            or model != "opencode/deepseek-v4.1-flash-free"
            or worker.get("free_model_only") is not True
        ):
            blockers.append("exact_free_usage_not_verified")
        if model == "opencode/deepseek-v4.1-flash-free" and observed.get(
            "public_model_metadata"
        ) is not True:
            blockers.append("public_auth_metadata_unverified")
        if observed.get("model_status") != "active":
            blockers.append("model_not_active")
        if observed.get("model_enabled") is not True:
            blockers.append("model_disabled_or_unverified")
        if observed.get("model_cost_zero") is not True:
            blockers.append("model_cost_not_zero_or_unverified")
    else:
        blockers.append("provider_not_supported")
    if observed.get("agent_policy") is not True:
        blockers.append("worker_permissions_not_restricted")
    return {"ready": not blockers, "blockers": blockers}


def select_ready_workers(
    workers: dict[str, dict[str, Any]],
    states: dict[str, dict[str, Any]],
    *,
    max_workers: int,
) -> list[str]:
    """Select only preflight-READY providers, preserving configured order."""
    if max_workers <= 0:
        raise ValueError("max_workers must be positive")
    return [
        worker_id
        for worker_id in workers
        if states.get(worker_id, {}).get("ready") is True
    ][:max_workers]


def _normalize_candidate_addresses(
    values: Sequence[str] | None,
    candidates: Sequence[Candidate],
    *,
    required: bool,
) -> list[str] | None:
    if values is None:
        if required:
            raise ValueError("at least one --candidate-address is required for productive execution")
        return None
    if not values:
        raise ValueError("candidate-address filter cannot be empty")
    inventory_addresses = {candidate.address.lower() for candidate in candidates}
    normalized: list[str] = []
    for value in values:
        try:
            numeric = int(str(value).strip(), 0)
        except ValueError as exc:
            raise ValueError(f"invalid candidate address: {value}") from exc
        if not 0 <= numeric <= 0xFFFFFFFF:
            raise ValueError(f"invalid candidate address: {value}")
        address = f"0x{numeric:x}"
        if address not in inventory_addresses:
            raise ValueError(f"candidate address is outside the inventory: {address}")
        if address in normalized:
            raise ValueError(f"duplicate candidate address: {address}")
        normalized.append(address)
    return normalized


def productive_candidate_selection(
    *,
    productive: bool,
    all_eligible: bool,
    candidate_addresses: Sequence[str] | None,
    candidates: Sequence[Candidate],
) -> list[str] | None:
    if not productive:
        if all_eligible or candidate_addresses is not None:
            raise ValueError("productive candidate selectors require --productive")
        return None
    if all_eligible:
        if candidate_addresses is not None:
            raise ValueError("--all-eligible and --candidate-address are mutually exclusive")
        return None
    return _normalize_candidate_addresses(candidate_addresses, candidates, required=True)


def discover_local_recovery_sources(
    task: dict[str, Any],
    repo_root: Path,
    source_worktrees: Mapping[str, Path],
    *,
    max_variants: int = 2,
) -> list[dict[str, Any]]:
    """Select content-validated source variants from this inventory and known worktrees."""
    if isinstance(max_variants, bool) or max_variants <= 0:
        raise ValueError("local recovery variant limit must be positive")
    numeric = int(task["address"], 0)
    address_hex = f"{numeric:08X}"
    if task.get("boundary_status") != "EXACT" or int(task.get("size_bytes", 0)) <= 0:
        return []
    checkpoint = task.get("checkpoint", {})
    checkpoint = checkpoint if isinstance(checkpoint, dict) else {}
    best = task.get("best_result", {})
    best = best if isinstance(best, dict) else {}
    best_match = checkpoint.get("best_match", {})
    best_match = best_match if isinstance(best_match, dict) else {}
    best_hashes = {
        value
        for value in (
            checkpoint.get("best_source_sha256"),
            best_match.get("source_sha256"),
            best.get("source_sha256"),
        )
        if isinstance(value, str) and HEX_SHA256.fullmatch(value)
    }
    latest_hash = checkpoint.get("source_sha256")
    expected_name = f"func_{address_hex}.c"
    variants: dict[str, dict[str, Any]] = {}

    def add_source(
        path: Path,
        *,
        worker_id: str,
        origin: str,
        expected_sha256: str | None = None,
    ) -> None:
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_000_000:
                return
            content = path.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            if expected_sha256 is not None and digest != expected_sha256:
                return
            expected_symbol = f"func_{address_hex}".encode("ascii")
            has_exact_symbol = bool(
                re.search(rb"\b" + re.escape(expected_symbol) + rb"\s*\(", content)
            )
            item = variants.setdefault(
                digest,
                {
                    "source_sha256": digest,
                    "source_path": path,
                    "worker_id": worker_id,
                    "origins": [],
                    "matching_words": -1,
                    "report_paths": [],
                    "has_exact_symbol": has_exact_symbol,
                },
            )
            item["has_exact_symbol"] = item["has_exact_symbol"] or has_exact_symbol
            item["origins"].append(origin)
        except OSError:
            return

    snapshot_hash = checkpoint.get("best_source_sha256")
    snapshot_relative = checkpoint.get("best_source_snapshot")
    if isinstance(snapshot_hash, str) and HEX_SHA256.fullmatch(snapshot_hash):
        expected_snapshot = (
            f"decomp-campaign/checkpoints/{address_hex.lower()}/{snapshot_hash}.c"
        )
        if snapshot_relative == expected_snapshot:
            add_source(
                campaign_build_path(repo_root, expected_snapshot),
                worker_id="checkpoint",
                origin="best_source_snapshot",
                expected_sha256=snapshot_hash,
            )

    for worker_id, worktree_value in source_worktrees.items():
        if not re.fullmatch(r"[a-z0-9-]+", worker_id):
            continue
        worktree = Path(worktree_value)
        if worktree.is_symlink() or not worktree.is_dir():
            continue
        source = worktree / "decomp" / "src" / "eboot" / expected_name
        try:
            source.resolve(strict=True).relative_to(worktree.resolve(strict=True))
        except (OSError, ValueError):
            continue
        add_source(source, worker_id=worker_id, origin=f"worktree:{worker_id}")

    if not variants:
        return []

    # Reuse only old reports whose address, boundary, symbol, source hash and object
    # provenance validate against one of the exact C snapshots found above.
    for worker_id, worktree_value in source_worktrees.items():
        worktree = Path(worktree_value)
        base = worktree / "build" / "decomp-campaign" / worker_id / f"{numeric:x}"
        if base.is_symlink() or not base.is_dir():
            continue
        for report_path in base.glob(
            f"attempt-*/verify-*/{expected_name.removesuffix('.c')}.match.json"
        ):
            try:
                if report_path.is_symlink() or not report_path.is_file() or report_path.stat().st_size > 2_000_000:
                    continue
                report = json.loads(report_path.read_text(encoding="utf-8"))
                provenance = report.get("provenance", {})
                source_hash = provenance.get("source_sha256")
                if source_hash not in variants:
                    continue
                _validate_complete_matcher_report(
                    report,
                    expected_address=numeric,
                    expected_size=int(task["size_bytes"]),
                    expected_source_sha256=source_hash,
                )
                if (
                    report.get("evidence") != "compiled-object"
                    or Path(str(provenance.get("compiler", ""))).name.lower() != "mwccpsp.exe"
                    or provenance.get("flags") != ["-O4,p", "-sdatathreshold", "0"]
                ):
                    continue
                match = report.get("match", {})
                score = match.get("matching_words", -1)
                if isinstance(score, int) and not isinstance(score, bool):
                    variant = variants[source_hash]
                    variant["matching_words"] = max(variant["matching_words"], score)
                    variant["report_paths"].append(
                        f"build/decomp-campaign/{worker_id}/{numeric:x}/"
                        f"{report_path.relative_to(base).as_posix()}"
                    )
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue

    ordered = sorted(
        variants.values(),
        key=lambda item: (
            item["source_sha256"] in best_hashes,
            item["matching_words"],
            item["source_sha256"] == latest_hash,
            item["has_exact_symbol"],
            item["worker_id"] == "checkpoint",
            item["source_sha256"],
        ),
        reverse=True,
    )
    return ordered[:max_variants]


def worker_agent_policy_is_restricted(
    agents: list[dict[str, Any]], agent_id: str
) -> bool:
    """Require local-only worker access and exact read-only AIMemory tool grants."""
    matches = [agent for agent in agents if agent.get("id") == agent_id]
    if len(matches) != 1 or not isinstance(matches[0].get("permissions"), list):
        return False
    rules = matches[0]["permissions"]
    deny_indices = [
        index
        for index, rule in enumerate(rules)
        if isinstance(rule, dict)
        and rule.get("action") == "*"
        and rule.get("resource") == "*"
        and rule.get("effect") == "deny"
    ]
    if not deny_indices:
        return False
    denied_actions = {
        (action, "*", "deny")
        for action in (
            "execute",
            "shell",
            "http",
            "http_request",
            "webfetch",
            "websearch",
            "browser",
            "external_directory",
            "subagent",
        )
    }
    allowed_overrides = {
        ("*", "*", "deny"),
        ("read", "*", "allow"),
        ("glob", "*", "allow"),
        ("grep", "*", "allow"),
        ("edit", "decomp/src/eboot/func_*.c", "allow"),
        ("edit", "build/decomp-campaign/*", "allow"),
        ("ai-memory_memory_query", "*", "allow"),
        ("ai-memory_memory_read_page", "*", "allow"),
        ("read", "*.env", "deny"),
        ("read", "*.env.*", "deny"),
    } | denied_actions
    for rule in rules[deny_indices[-1] :]:
        if not isinstance(rule, dict) or (
            rule.get("action"), rule.get("resource"), rule.get("effect")
        ) not in allowed_overrides:
            return False

    def effect(action: str, resource: str) -> str | None:
        result = None
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            action_pattern = str(rule.get("action", "")).casefold()
            resource_pattern = str(rule.get("resource", "")).replace("\\", "/").casefold()
            if fnmatch.fnmatchcase(action.casefold(), action_pattern) and fnmatch.fnmatchcase(
                resource.replace("\\", "/").casefold(), resource_pattern
            ):
                result = rule.get("effect")
        return result

    return (
        effect("other", "other") == "deny"
        and effect("shell", "*") == "deny"
        and effect("external_directory", "*") == "deny"
        and effect("edit", "*") == "deny"
        and effect("edit", "decomp/src/eboot/func_00002C28C.c") == "allow"
        and effect("edit", "build/decomp-campaign/openai/2c28c/result.json") == "allow"
        and effect("execute", "*") == "deny"
        and effect("http", "*") == "deny"
        and effect("http_request", "*") == "deny"
        and effect("webfetch", "*") == "deny"
        and effect("websearch", "*") == "deny"
        and effect("browser", "*") == "deny"
        and effect("subagent", "*") == "deny"
        and effect("ai-memory_memory_query", "*") == "allow"
        and effect("ai-memory_memory_read_page", "*") == "allow"
        and effect("ai-memory_memory_write_page", "*") == "deny"
        and effect("ai-memory_memory_message_send", "*") == "deny"
        and effect("ai-memory_memory_delete_page", "*") == "deny"
        and effect("ai-memory_memory_message_pop", "*") == "deny"
        and effect("read", "private/credentials.env") == "deny"
        and effect("read", "private/credentials.env.local") == "deny"
    )


def _effective_worker_policy_ready(command: list[str], cwd: Path, agent_id: str) -> bool:
    result = subprocess.run(
        [*command, "debug", "agents"],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        return False
    try:
        agents = json.loads(result.stdout)
    except json.JSONDecodeError:
        return False
    return isinstance(agents, list) and worker_agent_policy_is_restricted(agents, agent_id)


def _git_output(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError("Git worktree operation failed")
    return result.stdout.strip()


def _safe_worktree_path(worktree: Path, relative: str | Path) -> Path:
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("worker path escapes the worktree")
    target = worktree / relative
    cursor = worktree
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError(f"worker path contains a symlink: {cursor}")
    try:
        target.resolve(strict=False).relative_to(worktree.resolve(strict=True))
    except ValueError as exc:
        raise ValueError("worker path escapes the worktree") from exc
    return target


def _copy_known_historical_hypothesis(
    repo_root: Path, worktree: Path, claim: Claim
) -> dict[str, Any] | None:
    """Copy only a specifically catalogued, hash- and identity-checked hypothesis."""
    spec = HISTORICAL_HYPOTHESES.get(claim.address.lower())
    if spec is None:
        return None

    def unavailable(reason: str) -> dict[str, Any]:
        return {"status": "unavailable", "reason": reason}

    try:
        source_relative = spec["source_path"]
        expected_hash = spec["sha256"]
        expected_function = f"func_{claim.numeric_address:08X}"
        if (
            not isinstance(source_relative, str)
            or not isinstance(expected_hash, str)
            or not HEX_SHA256.fullmatch(expected_hash)
            or spec.get("function") != expected_function
            or int(spec["total_words"]) != claim.size_bytes // 4
        ):
            return unavailable("unsafe_path")
        source = campaign_build_path(repo_root, source_relative)
    except (KeyError, TypeError, ValueError, OSError):
        return unavailable("unsafe_path")

    if source.is_symlink():
        return unavailable("unsafe_path")
    if not source.is_file():
        return unavailable("missing")
    try:
        content = source.read_bytes()
    except OSError:
        return unavailable("missing")
    digest = hashlib.sha256(content).hexdigest()
    if digest != expected_hash.lower():
        return unavailable("hash_mismatch")
    text = content.decode("utf-8", errors="replace")
    if not re.search(rf"(?m)^\s*void\s+{re.escape(expected_function)}\s*\(", text):
        return unavailable("identity_mismatch")

    matching_words = spec.get("matching_words")
    total_words = spec.get("total_words")
    divergence = spec.get("first_divergence")
    if (
        isinstance(matching_words, bool)
        or not isinstance(matching_words, int)
        or isinstance(total_words, bool)
        or not isinstance(total_words, int)
        or not 0 <= matching_words <= total_words <= 512
        or not isinstance(divergence, dict)
        or not isinstance(divergence.get("address"), str)
    ):
        return unavailable("identity_mismatch")
    worker_id = claim.worker_id
    if not re.fullmatch(r"[a-z0-9-]+", worker_id) or not worktree.is_dir():
        return unavailable("unsafe_path")

    address = claim.address.removeprefix("0x").lower()
    relative_destination = Path(
        "build",
        "decomp-campaign",
        worker_id,
        address,
        "evidence",
        "historical",
        Path(source_relative).name,
    )
    destination: Path | None = None
    created_identity: tuple[int, int] | None = None

    def remove_incomplete_copy() -> None:
        if destination is None or created_identity is None or destination.is_symlink():
            return
        try:
            info = destination.stat()
            if (info.st_dev, info.st_ino) == created_identity:
                destination.unlink(missing_ok=True)
        except OSError:
            return

    try:
        destination = _safe_worktree_path(worktree, relative_destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Recheck every parent after creating directories, then use exclusive
        # creation so a concurrent worker/artifact can never be overwritten.
        destination = _safe_worktree_path(worktree, relative_destination)
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_file():
                return unavailable("unsafe_path")
            if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
                return unavailable("destination_conflict")
        else:
            try:
                with destination.open("xb") as output:
                    info = os.fstat(output.fileno())
                    created_identity = (info.st_dev, info.st_ino)
                    if output.write(content) != len(content):
                        raise OSError("historical hypothesis copy was incomplete")
                    output.flush()
            except FileExistsError:
                if (
                    destination.is_symlink()
                    or not destination.is_file()
                    or hashlib.sha256(destination.read_bytes()).hexdigest() != digest
                ):
                    return unavailable("destination_conflict")
            except OSError:
                remove_incomplete_copy()
                return unavailable("copy_failed")
            try:
                copied_hash = hashlib.sha256(destination.read_bytes()).hexdigest()
            except OSError:
                remove_incomplete_copy()
                return unavailable("copy_failed")
            if copied_hash != digest:
                remove_incomplete_copy()
                return unavailable("copy_failed")
    except (OSError, ValueError):
        remove_incomplete_copy()
        return unavailable("unsafe_path")

    return {
        "status": "available",
        "path": relative_destination.as_posix(),
        "sha256": digest,
        "classification": "NONMATCHING / not certified",
        "matching_words": matching_words,
        "total_words": total_words,
        "first_divergence": {
            key: value
            for key, value in divergence.items()
            if key in {"address", "candidate", "original"} and isinstance(value, str)
        },
    }


def _file_manifest(worktree: Path) -> dict[str, str]:
    """Hash every file the worker must treat as read-only, including ignored media."""
    candidates = [
        *sorted((worktree / "src" / "seto").rglob("*.py")),
        *(
            worktree / relative
            for relative in (
                "scripts/match_function.py",
                "scripts/ghidra/SetoAnalyzeEntry.java",
                "scripts/run_ghidra_headless.ps1",
                "config/decomp_campaign.toml",
                "config/decomp_campaign_inventory.json",
                "config/decomp_campaign.local.toml",
                "config/wsl/seto.toml",
                "private/decrypted/ULUS10136_EBOOT.elf",
                "private/original/PSP_GAME/USRDIR/gmodule/libtutoriallist.prx",
                "private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx",
                "build/seto035/export-triage.json",
            )
        ),
    ]
    manifest: dict[str, str] = {}
    for path in candidates:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"protected worker input is missing or unsafe: {path.name}")
        relative = path.relative_to(worktree).as_posix()
        manifest[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return manifest


def _worktree_status_snapshot(worktree: Path) -> dict[str, tuple[str, str]]:
    result = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=worktree,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError("could not audit worker worktree changes")
    snapshot: dict[str, tuple[str, str]] = {}
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        if len(record) < 4:
            raise ValueError("Git returned malformed worktree status")
        status = record[:2].decode("ascii", errors="replace")
        relative = record[3:].decode("utf-8", errors="surrogateescape").replace("\\", "/")
        if "R" in status or "C" in status:
            raise ValueError("worker worktree rename/copy operations are not allowed")
        path = _safe_worktree_path(worktree, relative)
        if path.is_symlink():
            digest = "SYMLINK"
        elif path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            digest = "MISSING"
        snapshot[relative.casefold()] = (status, digest)
    return snapshot


def _assert_worker_changes_scoped(
    before: dict[str, tuple[str, str]],
    after: dict[str, tuple[str, str]],
    claim: Claim,
) -> None:
    address = f"{claim.numeric_address:08X}".casefold()
    allowed_source = f"decomp/src/eboot/func_{address}.c".casefold()
    allowed_build = (
        f"build/decomp-campaign/{claim.worker_id}/{claim.address.removeprefix('0x')}/".casefold()
    )
    for relative in set(before) | set(after):
        if before.get(relative) == after.get(relative):
            continue
        if relative == allowed_source:
            if relative in after and after[relative][1] in {"SYMLINK", "MISSING"}:
                raise ValueError("candidate source was replaced with an unsafe file")
            continue
        if relative.startswith(allowed_build):
            continue
        raise ValueError("worker changed files outside its candidate source/build directory")


def _assert_git_identity_unchanged(
    worktree: Path,
    *,
    original_head: str,
    original_branch: str,
) -> None:
    if (
        _git_output(worktree, "rev-parse", "HEAD") != original_head
        or _git_output(worktree, "branch", "--show-current") != original_branch
    ):
        raise ValueError("worker committed changes or switched its isolated branch")


def _copy_local_file(source: Path, destination: Path, *, expected_sha256: str | None = None) -> str:
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"required local input is missing or unsafe: {source.name}")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    if expected_sha256 and source_hash != expected_sha256.lower():
        raise ValueError(f"local input hash does not match the configured baseline: {source.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise ValueError(f"worker input target is a symlink: {destination}")
    if destination.exists():
        if not destination.is_file() or hashlib.sha256(destination.read_bytes()).hexdigest() != source_hash:
            raise ValueError(f"refusing to overwrite a different worker-local input: {destination.name}")
    else:
        shutil.copyfile(source, destination)
    return source_hash


def provision_local_opencode_config(
    repo_root: Path, worktrees: Mapping[str, Path]
) -> int:
    """Copy the verified local OpenCode project config into isolated worker roots."""
    source = repo_root / ".opencode" / "opencode.json"
    if not source.exists() and not source.is_symlink():
        return 0
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 1_000_000:
        raise ValueError("local OpenCode project config is missing, unsafe, or too large")
    copied = 0
    for worktree in worktrees.values():
        if worktree.is_symlink() or not worktree.is_dir():
            raise ValueError("worker worktree is missing or unsafe while provisioning OpenCode config")
        destination = _safe_worktree_path(worktree, Path(".opencode") / "opencode.json")
        _copy_local_file(source, destination)
        copied += 1
    return copied


def provision_local_recovery_evidence(
    store: CampaignStore,
    repo_root: Path,
    worktrees: Mapping[str, Path],
    *,
    per_candidate_limit: int = 4,
    source_worktrees: Mapping[str, Path] | None = None,
) -> int:
    """Copy only hash-checked local recovery and exact Ghidra evidence into new workers."""
    if isinstance(per_candidate_limit, bool) or per_candidate_limit <= 0:
        raise ValueError("local recovery evidence limit must be positive")
    copied = 0
    if worktrees and source_worktrees:
        target_worker, target_worktree = sorted(worktrees.items())[0]
        for task in store.list_tasks():
            if task["status"] == "matched" or task["boundary_status"] != "EXACT":
                continue
            checkpoint = task["checkpoint"]
            log_relative = checkpoint.get("ghidra_log_path")
            log_sha256 = checkpoint.get("ghidra_log_sha256")
            if not isinstance(log_relative, str) or not isinstance(log_sha256, str):
                continue
            parts = log_relative.replace("\\", "/").split("/")
            if len(parts) < 5 or parts[0] != "decomp-campaign":
                continue
            source_worker = parts[1]
            source_worktree = source_worktrees.get(source_worker)
            if source_worktree is None or source_worktree.is_symlink() or not source_worktree.is_dir():
                continue
            source_claim = Claim(
                task["address"],
                int(task["size_bytes"]),
                task["nid"],
                int(task["priority"]),
                "EXACT",
                source_worker,
                "local-ghidra",
                None,
                int(task["attempt_count"]),
                0.0,
                checkpoint,
                {},
            )
            try:
                validated_cached_ghidra_boundary(source_worktree, source_claim)
            except (OSError, ValueError):
                continue
            source_log = campaign_build_path(source_worktree, log_relative)
            address = task["address"].removeprefix("0x")
            target_relative = (
                f"decomp-campaign/{target_worker}/{address}/evidence/{Path(log_relative).name}"
            )
            target_log = campaign_build_path(target_worktree, target_relative)
            _copy_local_file(source_log, target_log, expected_sha256=log_sha256)
            if store.attach_local_ghidra_cache(
                task["address"],
                worker_id=target_worker,
                worktree=target_worktree,
                log_relative=target_relative,
                log_sha256=log_sha256,
            ):
                copied += 1
    for task in store.list_tasks():
        if task["status"] == "matched" or task["boundary_status"] != "EXACT":
            continue
        numeric = int(task["address"], 0)
        prefix = f"build/decomp-campaign/experiments/{numeric:x}/"
        recoveries = task["checkpoint"].get("local_recoveries", [])
        if not isinstance(recoveries, list):
            continue
        selected = [
            item
            for item in recoveries[-per_candidate_limit:]
            if isinstance(item, dict)
            and item.get("origin_kind") == "local_recovery"
            and item.get("status") in {"NONMATCHING", "INCONCLUSIVE"}
            and item.get("source_sha256")
            and isinstance(item.get("source_path"), str)
            and item["source_path"].startswith(prefix)
            and isinstance(item.get("report_path"), str)
            and item["report_path"].startswith(prefix)
        ]
        for item in selected:
            source_relative = item["source_path"].removeprefix("build/")
            report_relative = item["report_path"].removeprefix("build/")
            source = campaign_build_path(repo_root, source_relative)
            report_path = campaign_build_path(repo_root, report_relative)
            if (
                source.is_symlink()
                or not source.is_file()
                or report_path.is_symlink()
                or not report_path.is_file()
            ):
                continue
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            if source_hash != item["source_sha256"]:
                continue
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
                _validate_complete_matcher_report(
                    report,
                    expected_address=numeric,
                    expected_size=int(task["size_bytes"]),
                    expected_source_sha256=source_hash,
                )
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
            if report.get("status") != item.get("status"):
                continue
            for worktree in worktrees.values():
                if worktree.is_symlink() or not worktree.is_dir():
                    raise ValueError("worker worktree is missing or unsafe while provisioning recovery evidence")
                source_target = campaign_build_path(worktree, source_relative)
                report_target = campaign_build_path(worktree, report_relative)
                _copy_local_file(source, source_target, expected_sha256=source_hash)
                _copy_local_file(report_path, report_target)
                copied += 1
    return copied


def prepare_worker_worktrees(
    repo_root: Path,
    config: dict[str, Any],
) -> dict[str, Path]:
    """Create/reuse one Git worktree per worker and provision local ignored inputs."""
    repo_root = repo_root.resolve(strict=True)
    current_remote = _git_output(repo_root, "remote", "get-url", "origin")
    root_relative = Path(config["worktrees"]["root"])
    if root_relative.is_absolute() or ".." in root_relative.parts:
        raise ValueError("worktree root must be a relative build path")
    if root_relative.parts[0] != "build":
        raise ValueError("worktrees must be isolated under the ignored build/ tree")
    root = campaign_build_path(repo_root, Path(*root_relative.parts[1:]))
    root.mkdir(parents=True, exist_ok=True)
    prefix = str(config["worktrees"]["branch_prefix"]).strip("/")
    worktrees: dict[str, Path] = {}
    registered = _git_output(repo_root, "worktree", "list", "--porcelain")
    inputs = config["inputs"]
    input_specs = (
        ("eboot", "eboot_sha256"),
        ("libtutoriallist", "libtutoriallist_sha256"),
        ("libhtml_view", "libhtml_view_sha256"),
        ("triage_report", "triage_report_sha256"),
        (config["toolchain"]["mwcc_config"], None),
        (config["toolchain"]["ghidra_local_config"], None),
    )
    for worker_id in config["workers"]:
        if not re.fullmatch(r"[a-z0-9-]+", worker_id):
            raise ValueError("worker identifiers may contain only lowercase letters, digits, and hyphens")
        relative = root_relative / worker_id
        target = campaign_build_path(repo_root, relative.relative_to("build"))
        branch = f"{prefix}/{worker_id}"
        target_text = str(target.resolve(strict=False))
        if target.is_symlink():
            raise ValueError(f"worker worktree may not be a symlink: {target}")
        registered_paths = [
            os.path.normcase(os.path.normpath(line.removeprefix("worktree ").strip()))
            for line in registered.splitlines()
            if line.startswith("worktree ")
        ]
        already_registered = os.path.normcase(os.path.normpath(target_text)) in registered_paths
        if already_registered:
            actual_root = _git_output(target, "rev-parse", "--show-toplevel")
            actual_branch = _git_output(target, "branch", "--show-current")
            if Path(actual_root).resolve() != target.resolve() or actual_branch != branch:
                raise ValueError("existing worker path is registered to a different worktree/branch")
        elif target.exists():
            raise ValueError("refusing to reuse an unregistered non-empty worker directory")
        else:
            branch_exists = subprocess.run(
                ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
                cwd=repo_root,
                check=False,
            ).returncode == 0
            target.parent.mkdir(parents=True, exist_ok=True)
            if branch_exists:
                _git_output(repo_root, "worktree", "add", str(target), branch)
            else:
                _git_output(repo_root, "worktree", "add", "-b", branch, str(target), "HEAD")
        remote = _git_output(target, "remote", "get-url", "origin")
        if remote != current_remote:
            raise ValueError("worker worktree does not resolve to the same AIMemory project remote")
        worktrees[worker_id] = target

    def provision_inputs(item: tuple[str, Path]) -> None:
        _worker_id, target = item
        for input_key, hash_key in input_specs:
            source_relative = input_key if input_key not in inputs else inputs[input_key]
            source = repo_root / source_relative
            destination = _safe_worktree_path(target, source_relative)
            expected_hash = inputs.get(hash_key) if hash_key else None
            _copy_local_file(source, destination, expected_sha256=expected_hash)

    if worktrees:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(len(worktrees), os.cpu_count() or 1),
            thread_name_prefix="seto-worker-inputs",
        ) as pool:
            futures = [pool.submit(provision_inputs, item) for item in worktrees.items()]
            for future in futures:
                future.result()
        provision_local_opencode_config(repo_root, worktrees)
    return worktrees


def _config_paths(config: dict[str, Any], config_path: Path) -> tuple[Path, Path]:
    base = config_path.resolve().parent.parent
    inventory = (base / config["inventory"]).resolve()
    database_relative = Path(config["database"])
    if database_relative.is_absolute() or ".." in database_relative.parts:
        raise ValueError("database path must remain inside build/")
    database = campaign_build_path(base, database_relative.relative_to("build"))
    return inventory, database


def _sanitize_opencode_prefix(command: list[str]) -> list[str]:
    if not command:
        raise ValueError("OpenCode command cannot be empty")
    if len(command) == 1 and os.name == "nt" and command[0].lower() == "opencode":
        resolved = next(
            (shutil.which(name) for name in ("opencode.exe", "opencode.cmd", "opencode.bat") if shutil.which(name)),
            None,
        )
        if resolved is None:
            powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
            if powershell:
                found = subprocess.run(
                    [
                        powershell,
                        "-NoProfile",
                        "-Command",
                        "(Get-Command opencode -ErrorAction Stop).Source",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                candidate = found.stdout.strip()
                if found.returncode == 0 and candidate.lower().endswith(".ps1"):
                    return [powershell, "-NoProfile", "-File", candidate]
                if found.returncode == 0 and candidate:
                    return [candidate]
        if resolved:
            return [resolved]
    return command


def _opencode_preflight(config: dict[str, Any], cwd: Path) -> dict[str, Any]:
    command = _sanitize_opencode_prefix(list(config["opencode"].get("command", ["opencode"])))
    catalog = subprocess.run(
        [*command, "models"], cwd=cwd, capture_output=True, text=True, timeout=120, check=False
    )
    auth = subprocess.run(
        [*command, "auth", "list", "--format", "json"],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    model_metadata_result = subprocess.run(
        [*command, "api", "get", "/api/model"],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    provider_result = subprocess.run(
        [*command, "api", "get", "/api/provider/openai"],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    integration_result = subprocess.run(
        [*command, "api", "get", "/api/integration/openai"],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    agents_result = subprocess.run(
        [*command, "debug", "agents"],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    listed_models = set(catalog.stdout.splitlines()) if catalog.returncode == 0 else set()
    try:
        auth_payload = json.loads(auth.stdout) if auth.returncode == 0 else None
    except json.JSONDecodeError:
        auth_payload = None
    try:
        model_payload = (
            json.loads(model_metadata_result.stdout)
            if model_metadata_result.returncode == 0
            else {}
        )
    except json.JSONDecodeError:
        model_payload = {}
    raw_model_data = model_payload.get("data") if isinstance(model_payload, dict) else None
    model_data = raw_model_data if isinstance(raw_model_data, list) else []
    model_records = [item for item in model_data if isinstance(item, dict)]
    try:
        provider_payload = json.loads(provider_result.stdout) if provider_result.returncode == 0 else None
    except json.JSONDecodeError:
        provider_payload = None
    try:
        integration_payload = (
            json.loads(integration_result.stdout) if integration_result.returncode == 0 else None
        )
    except json.JSONDecodeError:
        integration_payload = None

    def cost_is_zero(cost: Any) -> bool:
        if not isinstance(cost, list) or not cost:
            return False
        for tier in cost:
            if not isinstance(tier, dict) or set(tier) != {"input", "output", "cache"}:
                return False
            cache = tier.get("cache")
            if not isinstance(cache, dict) or set(cache) != {"read", "write"}:
                return False
            values = [tier["input"], tier["output"], cache["read"], cache["write"]]
            if any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or value != 0
                for value in values
            ):
                return False
        return True

    try:
        configured_agents = json.loads(agents_result.stdout) if agents_result.returncode == 0 else []
    except json.JSONDecodeError:
        configured_agents = []
    worker_states = {}
    for worker_name, item in config.get("workers", {}).items():
        model = validate_model_id(item["model"], config["models"]["allowlist"])
        model_present = model in listed_models
        provider_id = str(item["provider"])
        auth_metadata = _provider_auth_metadata(auth_payload, provider_id)
        model_id = model.partition("/")[2]
        metadata_matches = [
            record
            for record in model_records
            if record.get("providerID") == provider_id
            and record.get("id") == model_id
        ]
        metadata = metadata_matches[0] if len(metadata_matches) == 1 else {}
        settings = metadata.get("settings")
        public_key_metadata = (
            len(metadata_matches) == 1
            and isinstance(settings, dict)
            and settings.get("apiKey") == "public"
        )
        provider_route_compatible = (
            _openai_route_is_subscription_compatible(provider_payload, metadata)
            if provider_id == "openai"
            else None
        )
        operator_confirmed_method = item.get("auth_method_confirmed")
        chatgpt_oauth_verified = (
            provider_id == "openai"
            and auth_metadata.get("auth") == "stored"
            and auth_metadata.get("single_credential") is True
            and auth_metadata.get("method") == "oauth"
            and provider_route_compatible is True
            and _chatgpt_oauth_method_available(
                integration_payload, operator_confirmed_method
            )
        )
        observation = {
            "model": model,
            "catalog": "available" if model_present else "missing",
            "auth": (
                auth_metadata["auth"]
                if auth_metadata["auth"] != "not-listed"
                else "public"
                if public_key_metadata
                else "not-listed"
            ),
            "auth_method": (
                operator_confirmed_method
                if chatgpt_oauth_verified
                else auth_metadata.get("method")
            ),
            "chatgpt_oauth_verified": chatgpt_oauth_verified,
            "provider_route_compatible": (
                provider_route_compatible
            ),
            "public_model_metadata": public_key_metadata,
            "model_status": metadata.get("status"),
            "model_enabled": metadata.get("enabled"),
            "model_cost_zero": cost_is_zero(metadata.get("cost")),
            "usage_mode": item.get("usage_mode", "unknown"),
            "access_verified": item.get("access_verified") is True,
            "agent_policy": worker_agent_policy_is_restricted(
                configured_agents if isinstance(configured_agents, list) else [],
                str(item.get("agent", "")),
            ),
        }
        readiness = worker_readiness(item, observation, config["models"]["allowlist"])
        worker_states[worker_name] = {**observation, **readiness, "execution": "unverified"}
    return {
        "catalog_exit_code": catalog.returncode,
        "auth_exit_code": auth.returncode,
        "model_metadata_exit_code": model_metadata_result.returncode,
        "provider_metadata_exit_code": provider_result.returncode,
        "integration_metadata_exit_code": integration_result.returncode,
        "worker_agent_configured": agents_result.returncode == 0,
        "workers": worker_states,
    }


def _ai_memory_exposure_report(
    mcp_output: str,
    *,
    registered_tool_names: Iterable[str] | None,
    worker_permissions_ready: bool | None,
    effective_tool_names: Iterable[str] | None = None,
) -> dict[str, str]:
    """Separate MCP connection/catalog/policy checks from session-level exposure."""
    connected = bool(
        re.search(r"(?im)^\s*✓\s+ai-memory\s+connected\s*$", mcp_output)
    )
    expected_names = AI_MEMORY_READ_ACTIONS
    if registered_tool_names is None:
        registered = "UNVERIFIED"
        registered_ids: set[str] = set()
    else:
        registered_ids = set()
        for name in registered_tool_names:
            normalized = str(name).strip()
            if normalized in AI_MEMORY_READ_TOOLS:
                registered_ids.add(f"{AI_MEMORY_SERVER}_{normalized}")
            else:
                registered_ids.add(normalized)
        registered = "READY" if expected_names <= registered_ids else "BLOCKED"
    if worker_permissions_ready is None:
        permissions = "UNVERIFIED"
    else:
        permissions = "READY" if worker_permissions_ready else "BLOCKED"

    if not connected or registered == "BLOCKED" or permissions == "BLOCKED":
        available = "BLOCKED"
    elif effective_tool_names is None:
        # OpenCode 2.1.4 reports the MCP server connection and effective agent
        # policy, but cannot inspect the tool catalog attached to a live session.
        available = "UNVERIFIED"
    else:
        effective_ids = {str(name).strip() for name in effective_tool_names}
        available = "READY" if effective_ids == expected_names else "BLOCKED"
    return {
        "connection": "CONNECTED" if connected else "DISCONNECTED",
        "registered_tools": registered,
        "worker_permissions": permissions,
        "available_to_agent": available,
    }


def verify_campaign_inputs(
    config: dict[str, Any], repo_root: Path
) -> dict[str, dict[str, Any]]:
    inputs = config.get("inputs", {})
    result: dict[str, dict[str, Any]] = {}
    for name, path_key, hash_key in (
        ("eboot", "eboot", "eboot_sha256"),
        ("libtutoriallist", "libtutoriallist", "libtutoriallist_sha256"),
        ("libhtml_view", "libhtml_view", "libhtml_view_sha256"),
        ("triage", "triage_report", "triage_report_sha256"),
    ):
        relative = Path(str(inputs.get(path_key, "")))
        expected = inputs.get(hash_key)
        safe = bool(
            relative.parts
            and not relative.is_absolute()
            and ".." not in relative.parts
            and isinstance(expected, str)
            and HEX_SHA256.fullmatch(expected.lower())
        )
        path = repo_root / relative if safe else repo_root / "__invalid_campaign_input__"
        regular = safe and not path.is_symlink() and path.is_file()
        observed = hashlib.sha256(path.read_bytes()).hexdigest() if regular else None
        result[name] = {
            "present": regular,
            "matches": regular and observed == str(expected).lower(),
            "sha256": observed,
        }
    return result


def _doctor(config: dict[str, Any], config_path: Path) -> dict[str, Any]:
    command = _sanitize_opencode_prefix(list(config["opencode"].get("command", ["opencode"])))
    repo_root = config_path.resolve().parent.parent
    version = subprocess.run(
        [*command, "--version"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    model_check = _opencode_preflight(config, repo_root)
    mcp = subprocess.run(
        [*command, "mcp", "list"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    ai_memory = shutil.which("ai-memory")
    memory_version = None
    if ai_memory:
        result = subprocess.run(
            [ai_memory, "--version"], capture_output=True, text=True, timeout=30, check=False
        )
        if result.returncode == 0:
            memory_version = result.stdout.strip().splitlines()[0]
    wsl = shutil.which("wsl.exe") or shutil.which("wsl")
    wsl_result: str | None = None
    toolchain: dict[str, str] = {"mwcc": "BLOCKED", "wibo": "BLOCKED", "ghidra": "BLOCKED"}
    if wsl:
        result = subprocess.run(
            [wsl, "-d", config.get("toolchain", {}).get("wsl_distro", "Ubuntu"), "--exec", "python3", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode == 0:
            wsl_result = result.stdout.strip()
        local_toolchain = repo_root / config["toolchain"]["mwcc_config"]
        if local_toolchain.is_file() and not local_toolchain.is_symlink():
            try:
                local_settings = tomllib.loads(local_toolchain.read_text(encoding="utf-8-sig"))
                mwcc = local_settings["tools"]["mwccpsp"]["path"]
                wibo_path = local_settings["tools"]["wibo"]["path"]
                checks = {
                    "mwcc": [wsl, "-d", config["toolchain"]["wsl_distro"], "--exec", "test", "-f", mwcc],
                    "wibo": [wsl, "-d", config["toolchain"]["wsl_distro"], "--exec", "test", "-x", wibo_path],
                }
                for name, argv in checks.items():
                    checked = subprocess.run(argv, capture_output=True, timeout=30, check=False)
                    toolchain[name] = "READY" if checked.returncode == 0 else "BLOCKED"
                java_check = subprocess.run(
                    [wsl, "-d", config["toolchain"]["wsl_distro"], "--exec", "test", "-x", "/usr/bin/java"],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                ghidra_config = repo_root / config["toolchain"]["ghidra_local_config"]
                if ghidra_config.is_file() and not ghidra_config.is_symlink():
                    ghidra_settings = tomllib.loads(ghidra_config.read_text(encoding="utf-8"))
                    ghidra_home = ghidra_settings.get("ghidra", {}).get("home")
                    if java_check.returncode == 0 and isinstance(ghidra_home, str) and ghidra_home.startswith("/"):
                        headless = f"{ghidra_home.rstrip('/')}/support/analyzeHeadless"
                        checked = subprocess.run(
                            [wsl, "-d", config["toolchain"]["wsl_distro"], "--exec", "test", "-x", headless],
                            capture_output=True,
                            timeout=30,
                            check=False,
                        )
                        toolchain["ghidra"] = "READY" if checked.returncode == 0 else "BLOCKED"
                    if toolchain["ghidra"] != "READY":
                        windows_home = ghidra_settings.get("ghidra", {}).get("windows_home")
                        powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
                        wrapper = repo_root / "scripts" / "run_ghidra_headless.ps1"
                        if isinstance(windows_home, str) and powershell and wrapper.is_file():
                            launcher = Path(windows_home) / "support" / "analyzeHeadless.bat"
                            if launcher.is_file() and not launcher.is_symlink():
                                checked = subprocess.run(
                                    [powershell, "-NoProfile", "-File", str(wrapper), str(launcher), "--help"],
                                    capture_output=True,
                                    text=True,
                                    timeout=120,
                                    check=False,
                                )
                                output = checked.stdout + checked.stderr
                                if "Headless Analyzer Usage" in output and "could not be found" not in output:
                                    toolchain["ghidra"] = "READY"
            except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError):
                pass
    mcp_connected = mcp.returncode == 0 and bool(
        re.search(r"(?im)^\s*✓\s+ai-memory\s+connected\s*$", mcp.stdout)
    )
    worker_permissions_ready = bool(model_check.get("workers")) and all(
        state.get("agent_policy") is True
        for state in model_check.get("workers", {}).values()
    )
    ai_memory_exposure = _ai_memory_exposure_report(
        mcp.stdout if mcp.returncode == 0 else "",
        registered_tool_names=None,
        worker_permissions_ready=worker_permissions_ready,
    )
    return {
        "opencode_version": version.stdout.strip() if version.returncode == 0 else "BLOCKED",
        "opencode": model_check,
        "mcp_connected": mcp_connected,
        "ai_memory_exposure": ai_memory_exposure,
        "ai_memory_version": memory_version,
        "wsl_python": wsl_result,
        "toolchain": toolchain,
        "input_hashes": verify_campaign_inputs(config, repo_root),
        "execution": "NOT STARTED: doctor is read-only; run requires explicit --confirm and the READY worker's usage flag",
    }


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def _status_report(
    store: CampaignStore,
    config: dict[str, Any],
    repo_root: Path,
) -> dict[str, Any]:
    tasks = store.list_tasks()
    counts: dict[str, int] = {}
    for task in tasks:
        counts[task["status"]] = counts.get(task["status"], 0) + 1
    matched = [task for task in tasks if task["status"] == "matched"]
    worktree_root_rel = Path(config["worktrees"]["root"]).relative_to("build")
    worktree_root = campaign_build_path(repo_root, worktree_root_rel)
    reconstructed: list[str] = []
    for task in tasks:
        checkpoint = task["checkpoint"]
        digest = checkpoint.get("best_source_sha256")
        if not isinstance(digest, str) or not HEX_SHA256.fullmatch(digest):
            continue
        address = f"{int(task['address'], 0):08X}"
        source_relative = Path("decomp/src/eboot") / f"func_{address}.c"
        found = False
        for worker_id in config["workers"]:
            worktree = worktree_root / worker_id
            if worktree.is_symlink() or not worktree.is_dir():
                continue
            try:
                source = _safe_worktree_path(worktree, source_relative)
                if source.is_file() and not source.is_symlink() and hashlib.sha256(source.read_bytes()).hexdigest() == digest:
                    found = True
                    break
            except (OSError, ValueError):
                continue
        snapshot_rel = checkpoint.get("best_source_snapshot")
        if not found and isinstance(snapshot_rel, str):
            try:
                snapshot = campaign_build_path(repo_root, snapshot_rel)
                found = (
                    not snapshot.is_symlink()
                    and snapshot.is_file()
                    and hashlib.sha256(snapshot.read_bytes()).hexdigest() == digest
                )
            except (OSError, ValueError):
                found = False
        if found:
            reconstructed.append(task["address"])
    attempts = store.attempt_summary()
    provider_attempts = {
        provider: sum(outcomes.values()) for provider, outcomes in attempts.items()
    }
    completed_attempts = [
        attempt
        for attempt in store.list_attempts()
        if isinstance(attempt.get("ended_at"), (int, float))
        and isinstance(attempt.get("started_at"), (int, float))
    ]
    attempt_duration_by_provider: dict[str, dict[str, float]] = {}
    for attempt in completed_attempts:
        provider = str(attempt["provider"])
        totals = attempt_duration_by_provider.setdefault(
            provider, {"completed": 0.0, "seconds": 0.0}
        )
        totals["completed"] += 1
        totals["seconds"] += max(0.0, float(attempt["ended_at"]) - float(attempt["started_at"]))
    for totals in attempt_duration_by_provider.values():
        if totals["completed"]:
            totals["seconds"] = round(totals["seconds"], 3)
    blockers = []
    for task in tasks:
        promotion = task["evidence"].get("promotion")
        integration_blocked = (
            task["status"] == "matched"
            and isinstance(promotion, dict)
            and promotion.get("status") == "blocked"
        )
        if task["status"] not in {"needs_boundary", "blocked", "stalled"} and not integration_blocked:
            continue
        item = {"address": task["address"], "status": task["status"]}
        if integration_blocked:
            item["integration"] = "blocked"
            item["diagnostic"] = {"stage": "integration", "code": "integration_failed"}
        diagnostic = task["checkpoint"].get("last_diagnostic")
        if not integration_blocked and (
            isinstance(diagnostic, dict)
            and isinstance(diagnostic.get("code"), str)
            and diagnostic.get("code") in DIAGNOSTIC_CODES
            and diagnostic.get("stage") == DIAGNOSTIC_CODES[diagnostic["code"]]
        ):
            item["diagnostic"] = {
                "stage": diagnostic["stage"],
                "code": diagnostic["code"],
            }
        blockers.append(item)
    assignments: dict[str, list[dict[str, str]]] = {
        worker_id: [] for worker_id in config.get("workers", {})
    }
    for task in tasks:
        owner = task.get("owner")
        if owner in assignments:
            assignments[owner].append(
                {
                    "address": task["address"],
                    "status": task["status"],
                    "stage": "ghidra" if task["status"] == "boundary_checking" else "inference",
                }
            )
    worker_pool = {
        "configured": len(assignments),
        "active": sum(bool(items) for items in assignments.values()),
        "idle": sum(not items for items in assignments.values()),
        "workers": {
            worker_id: {
                "provider": worker.get("provider"),
                "model": worker.get("model"),
                "max_parallel": worker.get("max_parallel", 1),
                "state": "active" if assignments[worker_id] else "idle",
                "assignments": assignments[worker_id],
            }
            for worker_id, worker in config.get("workers", {}).items()
        },
    }
    inventory_baseline = {}
    inventory_path = repo_root / config.get("inventory", "")
    if inventory_path.is_file() and not inventory_path.is_symlink():
        try:
            inventory_baseline = json.loads(inventory_path.read_text(encoding="utf-8")).get(
                "baseline", {}
            )
        except (OSError, json.JSONDecodeError):
            inventory_baseline = {}
    certified_addresses = normalize_certified_addresses(inventory_baseline)
    return {
        "execution_enabled": bool(config.get("execution", {}).get("enabled", False)),
        "provider_access_verified": bool(
            config.get("execution", {}).get("provider_access_verified", False)
        ),
        "worker_permissions_reviewed": bool(
            config.get("execution", {}).get("worker_permissions_reviewed", False)
        ),
        "counts": counts,
        "worker_pool": worker_pool,
        "baseline": inventory_baseline,
        "attempts_cumulative": store.total_attempt_count(),
        "eligible_exact_pending": sum(
            task["status"] == "pending"
            and task["boundary_status"] == "EXACT"
            and task["address"] not in certified_addresses
            for task in tasks
        ),
        "boundaries_pending": sum(
            task["status"] == "needs_boundary"
            and task["address"] not in certified_addresses
            for task in tasks
        ),
        "certified_baseline_addresses_excluded": len(certified_addresses),
        "matched_functions": len(matched),
        "matched_instructions": sum(int(task["size_bytes"]) // 4 for task in matched),
        "reconstructed_c_functions": len(reconstructed),
        "reconstructed_c_addresses": reconstructed,
        "blockers": blockers,
        "providers": {
            provider: store.provider_status(provider)
            for provider in sorted(
                {worker["provider"] for worker in config.get("workers", {}).values()}
            )
        },
        "observed_consumption": {
            "model_process_attempts_by_provider": provider_attempts,
            "completed_attempt_duration_by_provider": attempt_duration_by_provider,
            "token_and_cost_totals": "not reported by the current OpenCode JSON integration",
        },
        "recent_events": store.list_recent_events(),
        "stopped": store.stop_requested(),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("doctor", help="read-only environment/model/auth/MCP diagnostics")
    subparsers.add_parser("init", help="seed the local SQLite queue from the reviewed inventory")
    subparsers.add_parser("plan", help="show queued candidates and explicit execution readiness")
    subparsers.add_parser("status", help="show queue/provider/checkpoint status")
    subparsers.add_parser(
        "recover-local",
        help="validate archived EBOOT sources and run local MWCC/matcher without Luna attempts",
    )
    promote = subparsers.add_parser(
        "promote", help="recertify one campaign MATCHED source and integrate it safely"
    )
    promote.add_argument("--address", required=True, help="hex EBOOT function address")
    resume = subparsers.add_parser("resume", help="recover expired leases and clear a clean stop")
    resume.add_argument("--recover-expired", action="store_true")
    resume.add_argument("--retry-blocked", action="store_true", help="explicitly retry blocked tasks after fixing their cause")
    resume.add_argument(
        "--retry-address",
        action="append",
        default=None,
        help="explicitly retry only this blocked inventory address; repeatable",
    )
    resume.add_argument(
        "--reopen-candidate",
        action="append",
        default=None,
        metavar="ADDRESS=REASON",
        help="selectively reopen one EXACT blocked/stalled candidate with concrete evidence",
    )
    stop = subparsers.add_parser("stop", help="request safe shutdown of running workers")
    run = subparsers.add_parser("run", help="execute only after a separate explicit authorization")
    run.add_argument("--confirm", action="store_true", help="confirm this model execution campaign")
    run.add_argument("--continuous", action="store_true", help="drain the bounded queue until idle or configured limits")
    run.add_argument("--productive", action="store_true", help="expand beyond the pilot after verified authorization")
    run.add_argument("--allow-openai-usage", action="store_true", help="confirm use of the configured OpenAI account")
    run.add_argument("--allow-free-model-usage", action="store_true", help="confirm requests to the exact allowlisted free model")
    run.add_argument(
        "--all-eligible",
        action="store_true",
        help="explicitly select every non-MATCHED, non-blocked candidate with an exact boundary",
    )
    run.add_argument(
        "--candidate-address",
        action="append",
        default=None,
        help="restrict productive execution to explicit inventory addresses; repeatable",
    )
    run.add_argument("--max-tasks", type=int, default=None, help="cumulative SQLite attempt ceiling")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config_path = args.config.resolve()
    try:
        config = load_config(config_path)
        inventory_path, database_path = _config_paths(config, config_path)
        candidates, inventory = load_inventory(inventory_path)
        certified_addresses = normalize_certified_addresses(
            inventory.get("baseline", {})
        )
        if args.command == "doctor":
            _print_json(_doctor(config, config_path))
            return 0
        store = CampaignStore(database_path)
        if args.command == "init":
            inserted = store.seed(
                candidates, excluded_addresses=certified_addresses
            )
            _print_json({"seeded": inserted, "inventory_candidates": len(candidates), "database": str(database_path)})
            return 0
        if args.command == "plan":
            certified_candidate_addresses = {
                candidate.address.lower()
                for candidate in candidates
                if f"0x{candidate.numeric_address:x}" in certified_addresses
            }
            _print_json(
                {
                    "campaign_enabled": bool(config.get("execution", {}).get("enabled", False)),
                    "provider_access_verified": bool(
                        config.get("execution", {}).get("provider_access_verified", False)
                    ),
                    "worker_permissions_reviewed": bool(
                        config.get("execution", {}).get("worker_permissions_reviewed", False)
                    ),
                    "models": {name: value["model"] for name, value in config["workers"].items()},
                    "inventory_candidates": len(candidates),
                    "pending_with_exact_boundary": sum(
                        c.boundary_status == "EXACT"
                        and c.address.lower() not in certified_candidate_addresses
                        for c in candidates
                    ),
                    "awaiting_ghidra_boundary": sum(
                        c.boundary_status != "EXACT"
                        and c.address.lower() not in certified_candidate_addresses
                        for c in candidates
                    ),
                    "certified_baseline_excluded": len(certified_addresses),
                    "source_commit": inventory.get("source_commit"),
                    "instruction": "No model process is started by plan/doctor/status.",
                }
            )
            return 0
        if args.command == "status":
            _print_json(_status_report(store, config, REPO_ROOT))
            return 0
        if args.command == "recover-local":
            if store.integrity_check() != "ok":
                raise ValueError("campaign SQLite integrity check failed before local recovery")
            preflight = _doctor(config, config_path)
            if preflight.get("wsl_python") is None or any(
                value != "READY" for value in preflight.get("toolchain", {}).values()
            ):
                raise ValueError("local recovery requires READY WSL2, Ghidra, MWCC and wibo")
            input_hashes = preflight.get("input_hashes", {})
            if not isinstance(input_hashes, dict) or not all(
                item.get("matches") is True for item in input_hashes.values()
            ):
                raise ValueError("local recovery EBOOT/PRX/triage hashes are not verified")
            recovery_config = config.get("recovery", {})
            roots = recovery_config.get("source_roots", ["build/decomp-campaign/worktrees"])
            if not isinstance(roots, list) or not roots:
                raise ValueError("local recovery requires at least one known worktree source root")
            source_worktrees: dict[str, Path] = {}
            known_workers = [
                *(f"luna-{index:02d}" for index in range(1, 9)),
                *(f"deepseek-{index:02d}" for index in range(1, 5)),
            ]
            for relative_root in roots:
                root_path = Path(str(relative_root))
                if (
                    root_path.is_absolute()
                    or ".." in root_path.parts
                    or not root_path.parts
                    or root_path.parts[0] != "build"
                ):
                    raise ValueError("local recovery source roots must remain under build/")
                source_root = REPO_ROOT / root_path
                if source_root.is_symlink() or not source_root.is_dir():
                    continue
                for worker_id in known_workers:
                    worker_path = source_root / worker_id
                    if worker_path.is_dir() and not worker_path.is_symlink():
                        source_worktrees[worker_id] = worker_path
            if not source_worktrees:
                raise ValueError("no existing known campaign worktrees contain recovery evidence")
            if store.stop_requested():
                store.resume(reset_providers=False)
            limits = config["limits"]
            recovery_runner = CampaignRunner(
                store,
                opencode_command=list(config["opencode"].get("command", ["opencode"])),
                worktrees={},
                timeout_seconds=float(limits["agent_timeout_seconds"]),
                output_limit=int(limits["max_output_bytes"]),
                max_attempts_without_progress=int(limits["max_attempts_without_progress"]),
                max_attempts_per_candidate=int(limits["max_attempts_per_candidate"]),
                max_consecutive_attempts=int(
                    config.get("refinement", {}).get("max_consecutive_attempts", 3)
                ),
                lease_seconds=float(limits["lease_seconds"]),
                wsl_distro=config.get("toolchain", {}).get("wsl_distro", "Ubuntu"),
                checkpoint_repo_root=REPO_ROOT,
                matcher_parallelism=int(limits.get("matcher_parallelism", 1)),
            )
            attempts_before = store.total_attempt_count()
            recovery_result = recover_local_artifacts(
                recovery_runner,
                REPO_ROOT,
                source_worktrees,
                excluded_addresses=certified_addresses | {"0x4217c"},
                max_attempts_per_candidate=int(limits["max_attempts_per_candidate"]),
                campaign_id=str(config.get("campaign", {}).get("id", "")),
                max_variants_per_candidate=int(
                    recovery_config.get("max_variants_per_candidate", 2)
                ),
            )
            attempts_after = store.total_attempt_count()
            if attempts_after != attempts_before:
                raise RuntimeError("local recovery unexpectedly changed the inference attempt count")
            _print_json(
                {
                    "integrity": store.integrity_check(),
                    "attempts_before": attempts_before,
                    "attempts_after": attempts_after,
                    "source_worktrees": sorted(source_worktrees),
                    **recovery_result,
                }
            )
            return 0
        if args.command == "promote":
            report = promote_campaign_source(store, config, REPO_ROOT, args.address)
            record_inventory_promotion(inventory_path, store, args.address)
            store.record_integration_result(args.address, "promoted")
            _print_json(report)
            return 0
        if args.command == "stop":
            store.request_stop()
            _print_json({"stop_requested": True})
            return 0
        if args.command == "resume":
            if args.retry_blocked and (args.retry_address is not None or args.reopen_candidate):
                raise ValueError("choose either --retry-blocked or a selective recovery option")
            if args.retry_address is not None and args.reopen_candidate:
                raise ValueError("choose either legacy blocked retry or justified candidate recovery")
            if (args.retry_address is not None or args.reopen_candidate) and args.recover_expired:
                raise ValueError("run --recover-expired separately before selective recovery")
            retried_addresses: list[str] = []
            reopened_addresses: list[str] = []
            if args.reopen_candidate:
                reasons: dict[str, str] = {}
                for item in args.reopen_candidate:
                    address, separator, reason = item.partition("=")
                    if not separator or not address.strip() or not reason.strip():
                        raise ValueError("--reopen-candidate must be ADDRESS=REASON")
                    normalized = _normalize_candidate_addresses(
                        [address.strip()], candidates, required=True
                    ) or []
                    if normalized[0] in reasons:
                        raise ValueError(f"duplicate recovery address: {normalized[0]}")
                    reasons[normalized[0]] = reason.strip()
                reopened_addresses = store.reopen_recoverable_candidates(
                    reasons,
                    excluded_addresses=certified_addresses,
                    max_attempts_per_candidate=int(
                        config["limits"]["max_attempts_per_candidate"]
                    ),
                    campaign_id=str(config.get("campaign", {}).get("id", "")),
                )
                store.resume(reset_providers=False)
                recovered = 0
            elif args.retry_address is not None:
                retried_addresses = _normalize_candidate_addresses(
                    args.retry_address, candidates, required=True
                ) or []
                retried_addresses = store.retry_blocked_addresses(
                    retried_addresses,
                    excluded_addresses=certified_addresses,
                )
                recovered = 0
            else:
                recovered = store.recover_expired() if args.recover_expired else 0
                store.resume()
            if args.retry_blocked:
                with store._connect() as db:
                    if certified_addresses:
                        placeholders = ",".join("?" for _ in certified_addresses)
                        db.execute(
                            "UPDATE candidates SET status='pending',updated_at=? "
                            f"WHERE status='blocked' AND address NOT IN ({placeholders})",
                            (time.time(), *sorted(certified_addresses)),
                        )
                    else:
                        db.execute(
                            "UPDATE candidates SET status='pending',updated_at=? WHERE status='blocked'",
                            (time.time(),),
                        )
            if args.retry_address is not None:
                store.resume()
            _print_json(
                {
                    "resumed": True,
                    "expired_leases_recovered": recovered,
                    "retried_addresses": retried_addresses,
                    "reopened_addresses": reopened_addresses,
                }
            )
            return 0
        if args.command == "run":
            if not args.confirm:
                raise ValueError("run requires --confirm; preparation commands never start model sessions")
            productive_candidate_addresses = productive_candidate_selection(
                productive=args.productive,
                all_eligible=args.all_eligible,
                candidate_addresses=args.candidate_address,
                candidates=candidates,
            )
            if productive_candidate_addresses is not None and any(
                address in certified_addresses
                for address in productive_candidate_addresses
            ):
                raise ValueError("certified baseline addresses cannot be selected for productive retry")
            if args.continuous and not config.get("execution", {}).get("continuous", False):
                raise ValueError("continuous mode is disabled in config")
            if args.continuous and not args.productive:
                raise ValueError("--continuous is reserved for the separately authorized productive campaign")
            if args.productive and not (
                config.get("execution", {}).get("pilot_verified", False)
                and config.get("execution", {}).get("productive_expansion_authorized", False)
            ):
                raise ValueError("productive expansion requires a reviewed valid pilot and separate authorization")
            if not config.get("execution", {}).get("enabled", False):
                raise ValueError("campaign execution is disabled in config; separate authorization is required")
            if not config.get("execution", {}).get("provider_access_verified", False):
                raise ValueError(
                    "provider execution/access is unverified; keep the campaign blocked until a later, "
                    "explicitly authorized readiness check"
                )
            if not config.get("execution", {}).get("worker_permissions_reviewed", False):
                raise ValueError(
                    "worker tool permissions have not been reviewed for unattended execution"
                )
            preflight = _doctor(config, config_path)
            ready_names = select_ready_workers(
                config["workers"],
                preflight["opencode"]["workers"],
                max_workers=int(config["limits"]["max_workers"]),
            )
            if not ready_names:
                details = "; ".join(
                    f"{name}: {','.join(state.get('blockers', [])) or 'not READY'}"
                    for name, state in preflight["opencode"]["workers"].items()
                )
                raise ValueError("no provider passed the READY preflight (" + details + ")")
            ready_providers = {
                config["workers"][worker_id]["provider"] for worker_id in ready_names
            }
            if "openai" in ready_providers and not args.allow_openai_usage:
                raise ValueError("run requires --allow-openai-usage for the READY OpenAI worker")
            if "opencode" in ready_providers and not args.allow_free_model_usage:
                raise ValueError("run requires --allow-free-model-usage for the READY exact Free worker")
            if preflight.get("wsl_python") is None or any(
                state != "READY" for state in preflight.get("toolchain", {}).values()
            ):
                raise ValueError("WSL2, Ghidra, MWCC, or wibo preflight is BLOCKED")
            input_hashes = preflight.get("input_hashes")
            if not isinstance(input_hashes, dict):
                input_hashes = verify_campaign_inputs(config, REPO_ROOT)
            if not input_hashes or not all(
                item.get("matches") is True for item in input_hashes.values()
            ):
                raise ValueError("one or more EBOOT/PRX/triage input hashes are not verified")
            discovered_count = 0
            if args.productive:
                if store.integrity_check() != "ok":
                    raise ValueError("campaign SQLite integrity check failed")
                if args.all_eligible:
                    matched_addresses = list(certified_addresses)
                    matched_addresses.extend(
                        task["address"]
                        for task in store.list_tasks()
                        if task["status"] == "matched"
                    )
                    discovered = discover_proven_exports(
                        REPO_ROOT / config["inputs"]["triage_report"],
                        candidates,
                        matched_addresses=matched_addresses,
                    )
                    discovered_count = append_inventory_candidates(
                        inventory_path, discovered
                    )
                    candidates, inventory = load_inventory(inventory_path)
                    certified_addresses = normalize_certified_addresses(
                        inventory.get("baseline", {})
                    )
            store.seed(candidates, excluded_addresses=certified_addresses)
            active_config = dict(config)
            active_config["workers"] = {
                worker_id: config["workers"][worker_id] for worker_id in ready_names
            }
            worktrees = prepare_worker_worktrees(
                REPO_ROOT,
                active_config,
            )
            recovery_source_worktrees: dict[str, Path] = {}
            recovery_source_roots = config.get("recovery", {}).get(
                "source_roots", ["build/decomp-campaign/worktrees"]
            )
            known_recovery_workers = [
                *(f"luna-{index:02d}" for index in range(1, 9)),
                *(f"deepseek-{index:02d}" for index in range(1, 5)),
            ]
            for relative_root in recovery_source_roots:
                source_root = REPO_ROOT / str(relative_root)
                if source_root.is_symlink() or not source_root.is_dir():
                    continue
                for worker_id in known_recovery_workers:
                    source_worktree = source_root / worker_id
                    if source_worktree.is_dir() and not source_worktree.is_symlink():
                        recovery_source_worktrees[worker_id] = source_worktree
            recovery_evidence_copied = provision_local_recovery_evidence(
                store,
                REPO_ROOT,
                worktrees,
                per_candidate_limit=int(
                    config.get("recovery", {}).get("prompt_evidence_per_candidate", 4)
                ),
                source_worktrees=recovery_source_worktrees,
            )
            command = _sanitize_opencode_prefix(list(config["opencode"].get("command", ["opencode"])))
            # OpenCode's effective config loader shares local user state; inspect
            # each isolated worktree in sequence to avoid concurrent debug-server
            # startup races while still verifying every worker's actual policy.
            policy_blocked = [
                worker_id
                for worker_id, worker_config in active_config["workers"].items()
                if not _effective_worker_policy_ready(
                    command, worktrees[worker_id], worker_config["agent"]
                )
            ]
            if policy_blocked:
                raise ValueError(
                    "restricted campaign agent policy is not present in worker worktree(s): "
                    + ", ".join(policy_blocked)
                )
            workers = [
                Worker(
                    worker_id,
                    value["provider"],
                    validate_model_id(value["model"], config["models"]["allowlist"]),
                    value["agent"],
                )
                for worker_id, value in active_config["workers"].items()
            ]
            limits = config["limits"]
            if args.productive:
                candidate_addresses = productive_candidate_addresses
                phase_max_tasks = int(limits["max_tasks"])
                phase_duration = float(limits["max_duration_seconds"])
            else:
                pilot = config["pilot"]
                candidate_addresses = [str(item).lower() for item in pilot["candidate_addresses"]]
                phase_max_tasks = min(
                    int(pilot["max_tasks"]),
                    max(1, len(workers)) * 2,
                )
                phase_duration = float(pilot["max_duration_seconds"])
            local_ghidra = tomllib.loads(
                (REPO_ROOT / config["toolchain"]["ghidra_local_config"]).read_text(encoding="utf-8")
            )["ghidra"]
            provider_parallelism: dict[str, int] = {}
            for worker_id in ready_names:
                worker_config = config["workers"][worker_id]
                provider = str(worker_config["provider"])
                capacity = int(worker_config.get("max_parallel", 1))
                provider_parallelism[provider] = min(
                    provider_parallelism.get(provider, capacity), capacity
                )

            def integrate_source(
                address: str, deadline: float | None
            ) -> dict[str, Any]:
                task = store.get_task(address)
                origin = task["best_result"].get("campaign_origin", {})
                promotion_claim = Claim(
                    address=address,
                    size_bytes=task["size_bytes"],
                    nid=task["nid"],
                    priority=task["priority"],
                    boundary_status="EXACT",
                    worker_id=(
                        origin.get("worker_id")
                        if isinstance(origin, dict)
                        else "promotion"
                    ),
                    provider="local-promotion",
                    session_id=(
                        origin.get("session_id") if isinstance(origin, dict) else None
                    ),
                    attempt_number=task["attempt_count"],
                    lease_until=0.0,
                    checkpoint={},
                    evidence={},
                )
                return runner._run_limited_operation(
                    runner.matcher_slots,
                    "matcher",
                    claim=promotion_claim,
                    deadline=deadline,
                    operation=lambda: _integrate_promoted_source(
                        store,
                        active_config,
                        REPO_ROOT,
                        inventory_path,
                        address,
                        deadline,
                    ),
                )

            def _integrate_promoted_source(
                campaign_store: CampaignStore,
                campaign_config: dict[str, Any],
                repository_root: Path,
                campaign_inventory_path: Path,
                promotion_address: str,
                promotion_deadline: float | None,
            ) -> dict[str, Any]:
                record = promote_campaign_source(
                    campaign_store,
                    campaign_config,
                    repository_root,
                    promotion_address,
                    deadline=promotion_deadline,
                )
                record_inventory_promotion(
                    campaign_inventory_path, campaign_store, promotion_address
                )
                return record

            legacy_worktrees = {}
            configured_root = REPO_ROOT / config["worktrees"]["root"]
            for legacy_id in ("openai", "deepseek"):
                legacy = configured_root / legacy_id
                if legacy.is_dir() and not legacy.is_symlink():
                    legacy_worktrees[legacy_id] = legacy
            evidence_worktrees = {**legacy_worktrees, **worktrees}
            runner = CampaignRunner(
                store,
                opencode_command=command,
                worktrees=evidence_worktrees,
                timeout_seconds=float(limits["agent_timeout_seconds"]),
                output_limit=int(limits["max_output_bytes"]),
                max_attempts_without_progress=int(limits["max_attempts_without_progress"]),
                max_attempts_per_candidate=int(limits["max_attempts_per_candidate"]),
                max_consecutive_attempts=int(
                    config.get("refinement", {}).get("max_consecutive_attempts", 3)
                ),
                max_duration_seconds=phase_duration,
                lease_seconds=float(limits["lease_seconds"]),
                ghidra_home=local_ghidra.get("home"),
                ghidra_windows_home=local_ghidra.get("windows_home"),
                wsl_distro=config["toolchain"]["wsl_distro"],
                expected_eboot_sha256=config["inputs"]["eboot_sha256"],
                checkpoint_repo_root=REPO_ROOT,
                max_retry_after_seconds=float(limits["max_retry_after_seconds"]),
                candidate_addresses=candidate_addresses,
                excluded_addresses=certified_addresses,
                provider_parallelism=provider_parallelism,
                ghidra_parallelism=int(limits.get("ghidra_parallelism", 1)),
                matcher_parallelism=int(limits.get("matcher_parallelism", 1)),
                promotion_callback=integrate_source,
                known_exact_ranges=inventory.get("baseline", {}).get(
                    "eboot_matched_ranges", []
                ),
            )
            if args.max_tasks is None:
                max_tasks = phase_max_tasks
            else:
                max_tasks = args.max_tasks
            if max_tasks > int(limits["max_tasks"]):
                raise ValueError("--max-tasks cannot exceed the configured campaign limit")
            if max_tasks > phase_max_tasks:
                raise ValueError("--max-tasks cannot exceed the active pilot/productive phase limit")
            if max_tasks <= 0:
                raise ValueError("--max-tasks must be positive")
            attempts_used = store.total_attempt_count()
            if attempts_used > max_tasks:
                raise ValueError(
                    f"cumulative attempt ceiling {max_tasks} is below the SQLite total {attempts_used}"
                )
            remaining_attempts = max_tasks - attempts_used
            if remaining_attempts:
                # `CampaignRunner` passes this value to SQLite's atomic
                # max_total_attempts guard, so it must remain the cumulative
                # ceiling (not the remaining per-process budget).
                outcome = runner.run(workers, max_tasks=max_tasks)
            else:
                outcome = {
                    "attempted": 0,
                    "outcomes": {},
                    "stopped": store.stop_requested(),
                }
            outcome["attempts_existing"] = attempts_used
            outcome["attempts_cumulative"] = store.total_attempt_count()
            outcome["attempt_budget_new"] = max(0, max_tasks - attempts_used)
            outcome["new_candidates_discovered"] = discovered_count
            outcome["local_recovery_evidence_copied"] = recovery_evidence_copied
            _print_json(outcome)
            return 0
        return 2
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        print(f"decomp_campaign: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
