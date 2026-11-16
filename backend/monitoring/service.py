"""
MonitoringService — turns login + face verification into a *running*
continuous-monitoring session, and turns every subsequent heartbeat
into a re-evaluation of derived security telemetry against
configurable thresholds.

Flow this implements (see docs/architecture-design-document.md and
the Phase 3 brief):

    LOGIN -> FACE VERIFIED -> MONITORING SESSION STARTED
    heartbeat, heartbeat, heartbeat, ... (lightweight polling)
    on repeated face failure / device revoke / session revoke /
    session re-authorization / risk escalation / lifecycle change:
        -> WARNING -> REAUTH_REQUIRED -> REVOKED

Authentication is explicitly NOT treated as permanent authorization
here: this service is the thing that keeps re-checking, for the
lifetime of the session, whether the facts that justified granting
access are still true.

Deliberately reused rather than reinvented:
    - `authorization.devices.DeviceRepository` / `.sessions.SessionRepository`
      — the SAME device/session state `AuthorizationService` checks
      before every encrypt/decrypt. When this service escalates to
      REVOKED it calls `session_repository.revoke(...)`, which means
      `AuthorizationService.authorize(...)` (and therefore every
      future encrypt/decrypt) rejects with `SessionInvalidError`
      automatically — "block future crypto" falls out of the existing
      architecture rather than needing a second enforcement path.
    - `policy.risk.RiskEngine` — the same weighted risk engine used
      by the decrypt route, fed with `face_confidence` from the
      latest heartbeat.
    - `audit.service.AuditLogService` — status *transitions* (not
      every heartbeat) are written to the same tamper-evident,
      hash-chained audit log used everywhere else.

Expression telemetry (if supplied) is carried through as supporting,
informational-only data: see `expression_hint` on `MonitoringSnapshot`.
It never changes `status`, is never treated as proof of anything, and
is never folded into any cryptographic material.
"""
from __future__ import annotations

import hmac
import logging
import os
import secrets
import threading
import time

import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Protocol, Sequence

from audit.events import AuditEvent
from audit.service import AuditLogService
from authorization.devices import DeviceRepository
from authorization.sessions import SessionRepository
from policy.risk import RiskEngine, RiskFactors, RiskLevel

from .state import (
    DEFAULT_THRESHOLDS,
    IDENTITY_MATCH_THRESHOLD,
    IdentityCheckState,
    MonitoringSnapshot,
    MonitoringStatus,
    MonitoringThresholds,
    SecurityPostureState,
    compute_monitoring_state_hash,
    derive_identity_state,
    derive_security_posture,
)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


log = logging.getLogger("cipherq.monitoring")


def _env_float(name: str, default: float) -> float:
    try:
        return max(0.0, float(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


# Audit-chain verification reads and HMAC-checks EVERY audit entry. It used to run on
# every heartbeat, every read-only refresh and every admin snapshot, so monitoring cost
# grew linearly with the (ever-growing) audit log. `audit_chain_intact` is an
# informational, system-level signal (it never changes session status -- see
# `derive_security_posture`), so a short process-wide cache is safe: a tampered chain is
# still reported, at most this many seconds late. 0 restores verify-on-every-evaluation.
AUDIT_VERIFY_TTL_SECONDS = _env_float("MONITORING_AUDIT_VERIFY_TTL_SECONDS", 30.0)
_AUDIT_VERIFY_RETRY_SECONDS = 5.0


class _AuditIntegrityCache:
    """Process-wide, single-flight cache of the audit-chain verification result."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[int, tuple[bool, float]] = {}

    @staticmethod
    def _key(audit: AuditLogService) -> int:
        repo = getattr(audit, "_repository", None)
        return id(getattr(repo, "_db", repo))

    def is_valid(self, audit: AuditLogService) -> bool:
        ttl = AUDIT_VERIFY_TTL_SECONDS
        key = self._key(audit)
        with self._lock:
            cached = self._entries.get(key)
            now = time.monotonic()
            if ttl > 0 and cached is not None and now - cached[1] < ttl:
                return cached[0]
            try:
                valid = bool(audit.verify_integrity().valid)
            except Exception:  # noqa: BLE001 -- a transient audit-read failure is not evidence of tampering
                log.warning("audit integrity verification could not run; keeping last known result", exc_info=True)
                last = cached[0] if cached is not None else True
                # retry soon, but never hammer the audit collection while it is unavailable
                self._entries[key] = (last, now - max(0.0, ttl - _AUDIT_VERIFY_RETRY_SECONDS))
                return last
            self._entries[key] = (valid, time.monotonic())
            return valid

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()


_audit_integrity_cache = _AuditIntegrityCache()


class LifecycleLookup(Protocol):
    """Minimal read-only interface onto intent lifecycle state, so this
    module doesn't need to depend on the whole `IntentRepository`."""

    def current_lifecycle_state(self, intent_id: int) -> str | None: ...


@dataclass
class MonitoringSessionRecord:
    """Persisted monitoring-session state."""

    monitoring_session_id: str
    user_id: int
    device_id: str
    session_id: str
    intent_id: int | None
    status: MonitoringStatus
    consecutive_face_failures: int
    thresholds: MonitoringThresholds
    started_at: datetime
    updated_at: datetime
    stopped: bool = False
    # PHASE 4 — behavioral/continuous-risk counters, and idempotency
    # guards so escalation events (revoke, audit-tamper alert) are
    # each only ever acted on / logged once per session, never
    # re-triggered every subsequent heartbeat.
    repeated_denied_requests: int = 0
    device_revoked_by_monitoring: bool = False
    audit_tamper_alerted: bool = False
    # The authorization session's `version` (see authorization.sessions
    # .SessionState) at the moment THIS record most recently transitioned
    # into REVOKED. `_evaluate` uses this to tell a still-currently-revoked
    # session apart from one that has since been explicitly restored via
    # `SessionRepository.reauthorize` (which always bumps `version`) —
    # without it, a monitoring record that once crossed into REVOKED would
    # latch there forever, even after the underlying session/device were
    # legitimately restored, because nothing would ever tell THIS record
    # the world moved on. `None` means "never revoked".
    revoked_at_session_version: int | None = None
    # Latest REAL client-side monitoring evidence. Admin/read-only
    # views must consume this evidence; they must never fabricate a
    # face-present/liveness/confidence result by re-running evaluation
    # without a camera frame.
    last_face_present: bool = False
    last_face_match_confidence: float | None = None
    last_liveness: bool = False
    last_camera_available: bool = False
    last_identity_state: IdentityCheckState = IdentityCheckState.NO_FACE
    last_expression_hint: str | None = None
    last_reason_code: str | None = None
    last_reason: str | None = None
    # Monotonic server-side revision for the live monitoring snapshot.
    # Heartbeats advance it; read-only refreshes reuse it. This lets clients
    # reject stale GET responses that arrive after a newer heartbeat.
    snapshot_revision: int = 0
    # Compact session-level aggregates. These replace per-heartbeat
    # monitoring_events writes while retaining the useful information needed
    # for a final session summary.
    check_count: int = 0
    last_risk_level: RiskLevel = RiskLevel.LOW
    last_risk_score: float = 0.0
    successful_face_verifications: int = 0
    face_liveness_failures: int = 0
    warning_occurrences: int = 0
    recovery_count: int = 0
    camera_interruptions: int = 0
    highest_security_state: str = "SECURE"
    last_security_state: str = "SECURE"
    final_security_state: str | None = None
    overall_security_outcome: str | None = None
    ended_at: datetime | None = None
    duration_seconds: float | None = None
    # Heartbeat integrity (hardening): the server issues a fresh nonce with every heartbeat response;
    # the next heartbeat must echo it (replay / out-of-order protection), and a gap longer than the
    # configured maximum latches REAUTH_REQUIRED (fail closed) until a fresh step-up acknowledges it.
    heartbeat_nonce: str | None = None
    last_heartbeat_ts: datetime | None = None
    reauth_latched: bool = False


@dataclass(frozen=True)
class MonitoringEvent:
    """One row in the monitoring event log — "monitoring events
    recorded" per the Phase 3 test requirements."""

    monitoring_session_id: str
    event_type: str  # lifecycle, risk, policy, or security-posture transition
    snapshot: MonitoringSnapshot


class MonitoringRepository(Protocol):
    def create(
        self, user_id: int, device_id: str, session_id: str, intent_id: int | None,
        thresholds: MonitoringThresholds, now: datetime,
    ) -> MonitoringSessionRecord: ...

    def get(self, monitoring_session_id: str) -> MonitoringSessionRecord | None: ...

    def update(self, record: MonitoringSessionRecord) -> MonitoringSessionRecord: ...

    def append_event(self, event: MonitoringEvent) -> None: ...

    def list_events(self, monitoring_session_id: str) -> Sequence[MonitoringEvent]: ...
    def list_all(self) -> Sequence[MonitoringSessionRecord]: ...
    def list_active(self) -> Sequence[MonitoringSessionRecord]: ...
    def get_by_session(self, session_id: str) -> MonitoringSessionRecord | None: ...


class InMemoryMonitoringRepository:
    """Reference/test implementation only — not for production use."""

    def __init__(self) -> None:
        self._sessions: dict[str, MonitoringSessionRecord] = {}
        self._events: dict[str, list[MonitoringEvent]] = {}

    def create(self, user_id, device_id, session_id, intent_id, thresholds, now):
        monitoring_session_id = uuid.uuid4().hex
        record = MonitoringSessionRecord(
            monitoring_session_id=monitoring_session_id,
            user_id=user_id,
            device_id=device_id,
            session_id=session_id,
            intent_id=intent_id,
            status=MonitoringStatus.ACTIVE,
            consecutive_face_failures=0,
            thresholds=thresholds,
            started_at=now,
            updated_at=now,
        )
        self._sessions[monitoring_session_id] = record
        self._events[monitoring_session_id] = []
        return record

    def get(self, monitoring_session_id: str) -> MonitoringSessionRecord | None:
        return self._sessions.get(monitoring_session_id)

    def update(self, record: MonitoringSessionRecord) -> MonitoringSessionRecord:
        self._sessions[record.monitoring_session_id] = record
        return record

    def append_event(self, event: MonitoringEvent) -> None:
        events = self._events.setdefault(event.monitoring_session_id, [])
        events.append(event)
        del events[:-MAX_MONITORING_EVENTS_PER_SESSION]

    def list_events(self, monitoring_session_id: str) -> Sequence[MonitoringEvent]:
        return tuple(self._events.get(monitoring_session_id, ()))

    def list_all(self) -> Sequence[MonitoringSessionRecord]:
        return tuple(self._sessions.values())

    def list_active(self) -> Sequence[MonitoringSessionRecord]:
        return tuple(r for r in self._sessions.values() if not r.stopped)

    def get_by_session(self, session_id: str) -> MonitoringSessionRecord | None:
        matches = [r for r in self._sessions.values() if r.session_id == session_id and not r.stopped]
        return max(matches, key=lambda r: _aware(r.updated_at)) if matches else None


_STATUS_TRANSITION_EVENT = {
    MonitoringStatus.WARNING: AuditEvent.MONITORING_WARNING,
    MonitoringStatus.REAUTH_REQUIRED: AuditEvent.MONITORING_REAUTH_REQUIRED,
    MonitoringStatus.REVOKED: AuditEvent.MONITORING_REVOKED,
}
MAX_MONITORING_EVENTS_PER_SESSION = 500


def _security_state_summary(snapshot: MonitoringSnapshot) -> str:
    return {
        SecurityPostureState.NORMAL: "SECURE",
        SecurityPostureState.WARNING: "SECURITY_WARNING",
        SecurityPostureState.COMPROMISED: "COMPROMISED",
        SecurityPostureState.REVOKED: "REVOKED",
    }[snapshot.security_state]


class HeartbeatNonceError(Exception):
    """Heartbeat did not echo the server's current nonce (replayed, duplicated or out of order)."""


class MonitoringSessionNotFoundError(Exception):
    def __init__(self, monitoring_session_id: str) -> None:
        self.monitoring_session_id = monitoring_session_id
        super().__init__(f"no monitoring session '{monitoring_session_id}'")


class MonitoringService:
    def __init__(
        self,
        repository: MonitoringRepository,
        device_repository: DeviceRepository,
        session_repository: SessionRepository,
        risk_engine: RiskEngine | None = None,
        audit_service: AuditLogService | None = None,
        lifecycle_lookup: LifecycleLookup | None = None,
        thresholds: MonitoringThresholds = DEFAULT_THRESHOLDS,
        max_heartbeat_gap_seconds: int = 45,
    ) -> None:
        self._max_gap = max_heartbeat_gap_seconds
        self._repository = repository
        self._devices = device_repository
        self._sessions = session_repository
        self._risk_engine = risk_engine or RiskEngine()
        self._audit = audit_service
        self._lifecycle_lookup = lifecycle_lookup
        self._default_thresholds = thresholds

    _LOCKS: dict = {}
    _LOCKS_GUARD = threading.Lock()

    @classmethod
    def _lock_for(cls, key: str) -> threading.RLock:
        with cls._LOCKS_GUARD:
            lk = cls._LOCKS.get(key)
            if lk is None:
                lk = cls._LOCKS[key] = threading.RLock()
            return lk

    @classmethod
    def session_lock(cls, authorization_session_id: str) -> threading.RLock:
        """Serialises monitoring START/retire for one authorization session, so two
        concurrent start requests (double click, two tabs, retry after a timeout) can
        never both observe 'no active record' and create two live monitoring sessions."""
        return cls._lock_for("authsession:" + authorization_session_id)

    @staticmethod
    def reset_integrity_cache() -> None:
        _audit_integrity_cache.reset()

    def get_record(self, monitoring_session_id: str) -> MonitoringSessionRecord | None:
        return self._repository.get(monitoring_session_id)

    def get_owner(self, monitoring_session_id: str) -> int | None:
        """Cheap, side-effect-free ownership lookup for routers to use
        before performing a mutating or informational operation (e.g.
        `/stop`, `/events`) — deliberately separate from `refresh()`,
        which re-evaluates risk/decay state and is not meant to be
        called just to check who owns a session."""
        record = self._repository.get(monitoring_session_id)
        return record.user_id if record is not None else None

    def get_by_session(self, session_id: str) -> MonitoringSessionRecord | None:
        return self._repository.get_by_session(session_id)

    def get_latest_evidence(self, monitoring_session_id: str) -> dict:
        """Return the last real client-reported monitoring evidence.

        Read-only: this never runs face detection/liveness and never
        fabricates a new biometric result.
        """
        record = self._repository.get(monitoring_session_id)
        if record is None:
            raise MonitoringSessionNotFoundError(monitoring_session_id)
        return {
            "face_present": record.last_face_present,
            "face_match_confidence": record.last_face_match_confidence,
            "liveness": record.last_liveness,
            "camera_available": record.last_camera_available,
            "identity_state": record.last_identity_state.value,
            "reason_code": record.last_reason_code,
            "reason": record.last_reason,
            "snapshot_revision": record.snapshot_revision,
            "updated_at": record.updated_at,
        }

    def list_current_snapshots(self) -> Sequence[MonitoringSnapshot]:
        """Return authoritative snapshots for admin/read-only views.

        IMPORTANT: this path never invents biometric evidence. It reuses
        the latest real heartbeat evidence persisted on the monitoring
        session and only re-evaluates server-owned authorization/risk
        facts that may have changed since that heartbeat.
        """
        snapshots = []
        for record in self._repository.list_active():
            try:
                snapshots.append(self.refresh(record.monitoring_session_id))
            except MonitoringSessionNotFoundError:
                continue
        return tuple(snapshots)

    def list_session_summaries(self, *, limit: int = 100, active_only: bool = False) -> list[dict]:
        """Admin/read-only session-level summaries (active AND finished sessions).

        Built purely from what monitoring persisted -- the compact per-session aggregates and the
        last real heartbeat evidence. Nothing is re-evaluated, no biometric result is invented and
        nothing is written."""
        records = self._repository.list_active() if active_only else self._repository.list_all()
        records = sorted(records, key=lambda r: _aware(r.updated_at), reverse=True)[: max(1, limit)]
        now = datetime.now(timezone.utc)
        rows: list[dict] = []
        for r in records:
            if r.stopped:
                connection = "ended"
            elif r.last_heartbeat_ts is not None and (now - _aware(r.last_heartbeat_ts)).total_seconds() > self._max_gap:
                connection = "lapsed"
            else:
                connection = "live"
            ended = _aware(r.ended_at) if r.ended_at else None
            rows.append({
                "monitoring_session_id": r.monitoring_session_id,
                "user_id": r.user_id,
                "device_id": r.device_id,
                "session_id": r.session_id,
                "status": r.status.value,
                "connection": connection,
                "started_at": _aware(r.started_at),
                "updated_at": _aware(r.updated_at),
                "ended_at": ended,
                "duration_seconds": r.duration_seconds if r.stopped else max(0.0, (now - _aware(r.started_at)).total_seconds()),
                "check_count": r.check_count,
                "successful_face_verifications": r.successful_face_verifications,
                "face_liveness_failures": r.face_liveness_failures,
                "warning_occurrences": r.warning_occurrences,
                "recovery_count": r.recovery_count,
                "camera_interruptions": r.camera_interruptions,
                "highest_security_state": r.highest_security_state,
                "last_security_state": r.last_security_state,
                "final_security_state": r.final_security_state,
                "overall_security_outcome": r.overall_security_outcome,
                "last_risk_level": r.last_risk_level.value,
                "last_risk_score": r.last_risk_score,
                "last_identity_state": r.last_identity_state.value,
                "last_reason_code": r.last_reason_code,
                "last_reason": r.last_reason,
                "consecutive_face_failures": r.consecutive_face_failures,
                "reauth_latched": r.reauth_latched,
                "last_heartbeat_ts": _aware(r.last_heartbeat_ts) if r.last_heartbeat_ts else None,
            })
        return rows


    # ------------------------------------------------------------------
    # LOGIN -> FACE VERIFIED -> MONITORING SESSION STARTED
    # ------------------------------------------------------------------
    def start(
        self,
        user_id: int,
        device_id: str,
        session_id: str,
        face_confidence: float,
        intent_id: int | None = None,
        now: datetime | None = None,
    ) -> MonitoringSnapshot:
        """Begin a continuous-monitoring session. Callers must have
        already obtained a successful face verification — this method
        does not itself verify identity (that stays in
        `authentication.face_auth`); it only starts *watching*."""
        now = now or datetime.now(timezone.utc)
        record = self._repository.create(
            user_id, device_id, session_id, intent_id, self._default_thresholds, now
        )
        record.heartbeat_nonce = secrets.token_hex(16)
        record.last_heartbeat_ts = now
        snapshot = self._evaluate(
            record,
            face_present=True,
            face_confidence=face_confidence,
            liveness=True,
            expression_hint=None,
            failure_this_tick=False,
            now=now,
            camera_available=True,
            persist_record=False,
        )
        self._persist_latest_evidence(record, snapshot, count_check=True)
        self._repository.append_event(
            MonitoringEvent(record.monitoring_session_id, "started", snapshot)
        )
        if self._audit is not None:
            self._audit.record(
                AuditEvent.MONITORING_STARTED,
                "success",
                user_id=user_id,
                session_id=session_id,
                device_id=device_id,
                timestamp=now,
            )
        return snapshot

    # ------------------------------------------------------------------
    # Heartbeat: re-evaluate derived security telemetry
    # ------------------------------------------------------------------
    def heartbeat(
        self,
        monitoring_session_id: str,
        face_present: bool,
        face_confidence: float | None,
        liveness: bool,
        expression_hint: str | None = None,
        camera_available: bool = True,
        now: datetime | None = None,
        prev_nonce: str | None = None,
    ) -> MonitoringSnapshot:
        """``face_confidence`` MUST be computed by the server from a verified descriptor comparison;
        ``None`` (no server-verified evidence) counts as a FAILED tick -- it never counts as a pass.
        ``face_present`` / ``liveness`` / ``camera_available`` are client claims: they can only make a
        tick fail, never make it succeed."""
        with self._lock_for(monitoring_session_id):
            record = self._repository.get(monitoring_session_id)
            if record is None or record.stopped:
                raise MonitoringSessionNotFoundError(monitoring_session_id)
            now = now or datetime.now(timezone.utc)
            if not (record.heartbeat_nonce and prev_nonce is not None
                    and hmac.compare_digest(record.heartbeat_nonce, prev_nonce)):
                raise HeartbeatNonceError(monitoring_session_id)
            last = _aware(record.last_heartbeat_ts) if record.last_heartbeat_ts else None
            heartbeat_lapsed = False
            # A lapse already latched (and audited) by a read-only refresh must not be audited a
            # second time when this heartbeat is the one that finally records the status change.
            latched_before = record.reauth_latched
            if last is not None and (now - last).total_seconds() > self._max_gap and not record.reauth_latched:
                record.reauth_latched = True
                heartbeat_lapsed = True
                if self._audit is not None:
                    self._audit.record(AuditEvent.MONITORING_REAUTH_REQUIRED, "reauth_required",
                                       user_id=record.user_id, session_id=record.session_id,
                                       device_id=record.device_id, reason="heartbeat gap exceeded; fail closed")
            record.heartbeat_nonce = secrets.token_hex(16)
            record.last_heartbeat_ts = now
            previous_status = record.status
            previous_risk_level = record.last_risk_level
            previous_identity_state = record.last_identity_state
            face_ok = (
                camera_available
                and face_present
                and liveness
                and face_confidence is not None
                and face_confidence >= IDENTITY_MATCH_THRESHOLD
            )
            snapshot = self._evaluate(
                record,
                face_present=face_present,
                face_confidence=face_confidence,
                liveness=liveness,
                expression_hint=expression_hint,
                failure_this_tick=not face_ok,
                camera_available=camera_available,
                now=now,
                persist_record=False,
            )
            self._persist_latest_evidence(record, snapshot, count_check=True)
            self._record_meaningful_event(
                record,
                snapshot,
                previous_status=previous_status,
                previous_risk_level=previous_risk_level,
                previous_identity_state=previous_identity_state,
            )
            already_audited_lapse = (
                latched_before and snapshot.status is MonitoringStatus.REAUTH_REQUIRED
                and previous_status is not MonitoringStatus.REAUTH_REQUIRED
                and record.consecutive_face_failures < record.thresholds.reauth_required_after
            )
            if snapshot.status is not previous_status and not heartbeat_lapsed and not already_audited_lapse:
                self._maybe_audit_transition(record, snapshot, now)
            return snapshot

    def acknowledge_stepup(self, session_id: str, now: datetime | None = None) -> bool:
        """A fresh, server-verified step-up clears the REAUTH latch (never a REVOKED state)."""
        record = self.get_by_session(session_id)
        if record is None:
            return False
        with self._lock_for(record.monitoring_session_id):
            record = self._repository.get(record.monitoring_session_id)
            if record is None or record.stopped or record.status is MonitoringStatus.REVOKED:
                return False
            now = now or datetime.now(timezone.utc)
            record.reauth_latched = False
            record.consecutive_face_failures = 0
            record.heartbeat_nonce = secrets.token_hex(16)
            record.last_heartbeat_ts = now
            self._repository.update(record)
            return True

    # ------------------------------------------------------------------
    # Read-only refresh: re-derive status from CURRENT device/session/
    # risk state without a new face reading (e.g. for a plain GET, or
    # for detecting an admin-side revoke between heartbeats).
    # ------------------------------------------------------------------
    def refresh(self, monitoring_session_id: str, now: datetime | None = None) -> MonitoringSnapshot:
        # Serialised with heartbeat/stop for this session: a refresh may latch a heartbeat lapse and
        # persist the record, and must never write back a copy that a concurrent heartbeat has
        # already superseded (that would roll back the nonce / counters).
        with self._lock_for(monitoring_session_id):
            record = self._repository.get(monitoring_session_id)
            if record is None:
                raise MonitoringSessionNotFoundError(monitoring_session_id)
            now = now or datetime.now(timezone.utc)
            return self._evaluate(
                record,
                face_present=record.last_face_present,
                face_confidence=record.last_face_match_confidence,
                liveness=record.last_liveness,
                expression_hint=record.last_expression_hint,
                failure_this_tick=False,
                persist_failure_counter=False,
                camera_available=record.last_camera_available,
                now=now,
            )

    def stop(self, monitoring_session_id: str, now: datetime | None = None) -> None:
        with self._lock_for(monitoring_session_id):
            record = self._repository.get(monitoring_session_id)
            if record is None:
                raise MonitoringSessionNotFoundError(monitoring_session_id)
            if record.stopped:
                return
            now = now or datetime.now(timezone.utc)
            # Capture the final authoritative state before marking the session
            # stopped. No synthetic biometric check is added to the summary.
            snapshot = self._evaluate(
                record,
                face_present=record.last_face_present,
                face_confidence=record.last_face_match_confidence,
                liveness=record.last_liveness,
                expression_hint=record.last_expression_hint,
                failure_this_tick=False,
                persist_failure_counter=False,
                camera_available=record.last_camera_available,
                now=now,
            )
            record.stopped = True
            record.ended_at = now
            record.final_security_state = _security_state_summary(snapshot)
            record.overall_security_outcome = (
                "COMPROMISED"
                if snapshot.security_state in (SecurityPostureState.COMPROMISED, SecurityPostureState.REVOKED)
                else "SECURE" if snapshot.security_state is SecurityPostureState.NORMAL
                else "SECURITY_WARNING"
            )
            record.duration_seconds = max(0.0, (now - _aware(record.started_at)).total_seconds())
            record.updated_at = now
            self._repository.update(record)
            self._repository.append_event(MonitoringEvent(monitoring_session_id, "stopped", snapshot))
            if self._audit is not None:
                self._audit.record(
                    AuditEvent.MONITORING_TERMINATED,
                    "success",
                    user_id=record.user_id,
                    session_id=record.session_id,
                    device_id=record.device_id,
                    timestamp=now,
                )

    def list_events(self, monitoring_session_id: str) -> Sequence[MonitoringEvent]:
        return self._repository.list_events(monitoring_session_id)

    # ------------------------------------------------------------------
    # PHASE 4: let other subsystems (policy/decrypt/encrypt routers)
    # report a denied request against this monitoring session, so
    # "repeated denied requests" becomes a real, accumulating risk
    # signal rather than something only this module can see.
    # ------------------------------------------------------------------
    def report_denied_request(
        self, monitoring_session_id: str, now: datetime | None = None
    ) -> MonitoringSnapshot:
        with self._lock_for(monitoring_session_id):
            return self._report_denied_request_locked(monitoring_session_id, now)

    def _report_denied_request_locked(
        self, monitoring_session_id: str, now: datetime | None = None
    ) -> MonitoringSnapshot:
        record = self._repository.get(monitoring_session_id)
        if record is None:
            raise MonitoringSessionNotFoundError(monitoring_session_id)
        now = now or datetime.now(timezone.utc)
        record.repeated_denied_requests += 1
        previous_status = record.status
        previous_risk_level = record.last_risk_level
        previous_identity_state = record.last_identity_state
        snapshot = self._evaluate(
            record, face_present=True, face_confidence=None, liveness=True,
            expression_hint=None, failure_this_tick=False, now=now,
            persist_record=False,
        )
        self._persist_latest_evidence(record, snapshot)
        self._repository.append_event(
            MonitoringEvent(monitoring_session_id, "denied_request", snapshot)
        )
        self._record_meaningful_event(
            record,
            snapshot,
            previous_status=previous_status,
            previous_risk_level=previous_risk_level,
            previous_identity_state=previous_identity_state,
        )
        if snapshot.status is not previous_status:
            self._maybe_audit_transition(record, snapshot, now)
        return snapshot

    def _persist_latest_evidence(
        self,
        record: MonitoringSessionRecord,
        snapshot: MonitoringSnapshot,
        *,
        count_check: bool = False,
    ) -> None:
        """Persist latest real telemetry plus compact session aggregates."""
        previous_security_state = record.last_security_state
        current_security_state = _security_state_summary(snapshot)

        if count_check:
            record.check_count += 1
            if (
                snapshot.identity_state is IdentityCheckState.IDENTITY_CONFIRMED
                and snapshot.liveness
                and snapshot.face_present
                and (
                    snapshot.face_match_confidence is None
                    or snapshot.face_match_confidence >= IDENTITY_MATCH_THRESHOLD
                )
            ):
                record.successful_face_verifications += 1
            else:
                record.face_liveness_failures += 1

            if snapshot.identity_state is IdentityCheckState.CAMERA_UNAVAILABLE:
                record.camera_interruptions += 1

            if current_security_state == "SECURITY_WARNING" and previous_security_state != "SECURITY_WARNING":
                record.warning_occurrences += 1
            if current_security_state == "SECURE" and previous_security_state != "SECURE":
                record.recovery_count += 1

            rank = {"SECURE": 0, "SECURITY_WARNING": 1, "COMPROMISED": 2, "REVOKED": 3}
            if rank.get(current_security_state, 0) > rank.get(record.highest_security_state, 0):
                record.highest_security_state = current_security_state

            record.last_security_state = current_security_state

        record.last_face_present = snapshot.face_present
        record.last_face_match_confidence = snapshot.face_match_confidence
        record.last_liveness = snapshot.liveness
        # Camera availability is represented by identity_state and the
        # actual tick input; preserve it explicitly for future refreshes.
        record.last_camera_available = snapshot.identity_state is not IdentityCheckState.CAMERA_UNAVAILABLE
        record.last_identity_state = snapshot.identity_state
        record.last_expression_hint = snapshot.expression_hint
        record.last_risk_level = snapshot.current_risk
        record.last_risk_score = snapshot.risk_score
        record.last_reason_code = snapshot.reason_code
        record.last_reason = snapshot.reason
        record.updated_at = max(_aware(record.updated_at), _aware(snapshot.timestamp))
        self._repository.update(record)

    def _record_meaningful_event(
        self,
        record: MonitoringSessionRecord,
        snapshot: MonitoringSnapshot,
        *,
        previous_status: MonitoringStatus,
        previous_risk_level: RiskLevel,
        previous_identity_state: IdentityCheckState,
    ) -> None:
        if snapshot.status is not previous_status:
            event_type = (
                "recovered"
                if snapshot.status is MonitoringStatus.ACTIVE
                and previous_status is not MonitoringStatus.ACTIVE
                else snapshot.status.value
            )
        elif snapshot.current_risk is not previous_risk_level:
            event_type = "risk_changed"
        elif (
            snapshot.identity_state is not previous_identity_state
            and snapshot.identity_state is not IdentityCheckState.IDENTITY_CONFIRMED
        ):
            event_type = "suspicious_behavior"
        else:
            return

        self._repository.append_event(
            MonitoringEvent(record.monitoring_session_id, event_type, snapshot)
        )

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------
    def _evaluate(
        self,
        record: MonitoringSessionRecord,
        *,
        face_present: bool,
        face_confidence: float | None,
        liveness: bool,
        expression_hint: str | None,
        failure_this_tick: bool,
        now: datetime,
        persist_failure_counter: bool = True,
        camera_available: bool = True,
        persist_record: bool = True,
    ) -> MonitoringSnapshot:
        thresholds = record.thresholds
        warnings: list[str] = []

        # -- Continuous authorization: device / session / re-auth --
        device_status = self._devices.get_status(record.device_id)
        session_state = self._sessions.get(record.session_id)

        device_revoked = device_status.revoked
        session_revoked = session_state.revoked if session_state is not None else False
        session_expired = (
            session_state is not None and now > session_state.expires_at
        )
        session_version = session_state.version if session_state is not None else 1

        # -- Heartbeat lapse: no heartbeat for longer than the maximum gap => latch REAUTH_REQUIRED
        # (fail closed).  Read-only refreshes also detect it.
        if (not record.stopped and record.last_heartbeat_ts is not None and not record.reauth_latched
                and (now - _aware(record.last_heartbeat_ts)).total_seconds() > self._max_gap):
            record.reauth_latched = True
            if persist_record:
                self._repository.update(record)
            if self._audit is not None:
                self._audit.record(AuditEvent.MONITORING_REAUTH_REQUIRED, "reauth_required",
                                   user_id=record.user_id, session_id=record.session_id,
                                   device_id=record.device_id, reason="heartbeat lapsed; fail closed")

        # A fresh re-authorization (session.refresh -> version bump)
        # clears any accumulated face-failure streak: it is exactly
        # the "reauthenticate" step-up this module would otherwise be
        # demanding on its own.
        if persist_failure_counter:
            failures = record.consecutive_face_failures + 1 if failure_this_tick else 0
        else:
            # Read-only refresh (GET / stop): don't perturb the
            # accumulated streak, just re-derive status from it plus
            # whatever changed externally (device/session repos).
            failures = record.consecutive_face_failures

        # -- Lifecycle (optional — only if this monitoring session is
        # scoped to a specific intent) --
        current_lifecycle = None
        if record.intent_id is not None and self._lifecycle_lookup is not None:
            current_lifecycle = self._lifecycle_lookup.current_lifecycle_state(record.intent_id)

        # -- Risk (reuses the existing weighted risk engine). Folds in
        # the "repeated denied requests" counter other routers report
        # via `report_denied_request`, and treats an already-revoked
        # device/session as an outright critical signal. --
        # Full risk is still reported to the UI, but face-monitoring
        # failures/confidence must NOT independently bypass the explicit
        # 3/3/6/8 monitoring state machine. Otherwise 5 failed frames
        # can reach CRITICAL and revoke before the required 6/8
        # re-auth/revoke thresholds. A second score containing only
        # non-face authorization/risk signals controls independent
        # high/critical escalation.
        risk = self._risk_engine.assess(
            RiskFactors(
                face_confidence=face_confidence,
                device_mismatch=device_revoked,
                session_expired=session_expired,
                repeated_face_failures=failures,
                repeated_denied_requests=record.repeated_denied_requests,
                revoked_device_or_session=device_revoked or session_revoked,
            )
        )
        independent_risk = self._risk_engine.assess(
            RiskFactors(
                device_mismatch=device_revoked,
                session_expired=session_expired,
                repeated_denied_requests=record.repeated_denied_requests,
                revoked_device_or_session=device_revoked or session_revoked,
            )
        )

        # -- Determine status. PHASE 4 mapping:
        #      LOW      -> NORMAL   (MonitoringStatus.ACTIVE)
        #      MEDIUM   -> WARNING
        #      HIGH     -> REAUTHENTICATION / RESTRICTED
        #      CRITICAL -> REVOCATION / CRYPTO BLOCK
        #    Explicit device/session facts (already revoked/expired)
        #    always win outright, ahead of the risk score. --
        #
        # `already_revoked` must NOT latch forever: a monitoring record
        # that crossed into REVOKED stays authoritative only until the
        # underlying authorization session is explicitly restored (an
        # admin-approved + face-reverified `reauthenticate`, which always
        # bumps `session_state.version` — see authorization/sessions.py).
        # Once a newer session version is observed, the OLD revocation no
        # longer describes reality, so this record is allowed to be
        # re-derived from current facts instead of being stuck reporting
        # REVOKED/COMPROMISED against a session that is actually valid
        # again with a healthy face check and a risk score of 0.
        already_revoked = (
            record.status is MonitoringStatus.REVOKED
            and (
                record.revoked_at_session_version is None
                or session_version <= record.revoked_at_session_version
            )
        )
        if device_revoked or session_revoked or session_expired or already_revoked:
            status = MonitoringStatus.REVOKED
            if device_revoked:
                warnings.append("device revoked")
            if session_revoked:
                warnings.append("session revoked")
            if session_expired:
                warnings.append("session expired")
        elif failures >= thresholds.invalidate_after:
            status = MonitoringStatus.REVOKED
            warnings.append(
                f"{failures} consecutive face-verification failures — authorization invalidated"
            )
        elif independent_risk.level is RiskLevel.CRITICAL:
            status = MonitoringStatus.REVOKED
            warnings.append(f"critical authorization risk score ({independent_risk.score}) — authorization revoked")
        elif failures >= thresholds.reauth_required_after:
            status = MonitoringStatus.REAUTH_REQUIRED
            warnings.append(f"{failures} consecutive face-verification failures — reauthentication required")
        elif independent_risk.level is RiskLevel.HIGH:
            status = MonitoringStatus.REAUTH_REQUIRED
            warnings.append(f"elevated authorization risk score ({independent_risk.score}) — reauthentication required")
        elif failures >= thresholds.risk_increase_after:
            status = MonitoringStatus.WARNING
            warnings.append(f"{failures} consecutive face-verification failures — risk increased")
        elif failures >= thresholds.warning_after:
            status = MonitoringStatus.WARNING
            warnings.append(
                f"face verification failed for {failures} consecutive monitoring cycles — monitoring closely"
            )
        elif independent_risk.level is RiskLevel.MEDIUM:
            status = MonitoringStatus.WARNING
            warnings.append(f"elevated authorization risk score ({independent_risk.score})")
        elif not persist_failure_counter and record.last_identity_state is not IdentityCheckState.IDENTITY_CONFIRMED:
            # A legacy/migrated record may have no stored biometric
            # evidence yet. Never turn missing evidence into SECURE.
            status = MonitoringStatus.WARNING
            warnings.append("Latest live identity evidence is not confirmed; waiting for the next real monitoring heartbeat.")
        else:
            status = MonitoringStatus.ACTIVE

        if record.reauth_latched and status in (MonitoringStatus.ACTIVE, MonitoringStatus.WARNING):
            status = MonitoringStatus.REAUTH_REQUIRED
            warnings.append("re-authentication required (monitoring lapsed or step-up pending)")
        elif status is MonitoringStatus.REAUTH_REQUIRED and not record.reauth_latched and persist_failure_counter:
            record.reauth_latched = True          # entering REAUTH_REQUIRED latches until a fresh step-up

        # -- Enact revocation. Only act (and only audit) the FIRST time
        # a session crosses into REVOKED — everything after that is
        # already revoked and re-acting/re-logging on every subsequent
        # heartbeat would be exactly the "unbounded audit logging"
        # PHASE 4 says to avoid. --
        newly_revoked = status is MonitoringStatus.REVOKED and not already_revoked
        # Plain session EXPIRY is routine, not a security violation: authorization is already
        # blocked by the expiry itself (monitoring reports REVOKED/session_expired and crypto is
        # gated), and the user simply re-authenticates with their face. Marking the stored session
        # `revoked` as well would wrongly force a non-admin through the admin-approval path
        # reserved for real revocations. Anything else (device/session revoked, face failures,
        # critical risk) is still enforced exactly as before.
        expiry_only = (
            session_expired and not device_revoked and not session_revoked
            and failures < thresholds.invalidate_after
            and independent_risk.level is not RiskLevel.CRITICAL
        )
        if newly_revoked and persist_failure_counter:
            if not session_revoked and not expiry_only:
                try:
                    self._sessions.revoke(record.session_id)
                    if self._audit is not None:
                        self._audit.record(
                            AuditEvent.SESSION_REVOKED,
                            "revoked",
                            user_id=record.user_id,
                            session_id=record.session_id,
                            device_id=record.device_id,
                            risk=risk.level.value,
                            reason="; ".join(warnings) or None,
                            timestamp=now,
                        )
                except KeyError:
                    pass
            # Device revocation is deliberately narrower than session
            # revocation. Repeated face failures must be recoverable by
            # explicit re-authentication on the same trusted device; they
            # must not permanently poison that device. A device-level
            # revoke is still appropriate for an independent, repeated
            # denied-request risk signal because that represents a
            # separate authorization-abuse pattern rather than a user
            # temporarily leaving the camera frame.
            device_revocation_eligible = (
                risk.level is RiskLevel.CRITICAL
                and record.repeated_denied_requests > 0
                and not device_revoked
                and not record.device_revoked_by_monitoring
            )
            if device_revocation_eligible:
                self._devices.revoke(record.device_id)
                record.device_revoked_by_monitoring = True
                if self._audit is not None:
                    self._audit.record(
                        AuditEvent.DEVICE_REVOKED,
                        "revoked",
                        user_id=record.user_id,
                        session_id=record.session_id,
                        device_id=record.device_id,
                        risk=risk.level.value,
                        reason="; ".join(warnings) or None,
                        timestamp=now,
                    )

        # -- Audit-chain integrity is a READ-ONLY system-level measurement.
        # Never append a tamper alert to the chain being verified: doing so
        # would contaminate the evidence chain and make the failure persist
        # forever. The UI/API exposes the exact failed measurement instead. --
        audit_compromised = False
        if self._audit is not None:
            audit_compromised = not _audit_integrity_cache.is_valid(self._audit)
            # Keep the in-memory flag for compatibility/telemetry, but do not
            # write an audit event into the broken chain.
            if audit_compromised and persist_failure_counter:
                record.audit_tamper_alerted = True

        # Audit-chain integrity is a separate system control. It is surfaced
        # to administrators, but it must never turn a healthy live session
        # into Qira/session COMPROMISED. Session posture is derived only from
        # the current authorization/monitoring state.
        security_state = derive_security_posture(status)

        # Explicit per-tick identity result — computed from the SAME
        # facts (face_present/face_confidence/liveness/camera_available)
        # that decided `failure_this_tick` above, never re-derived from
        # `status` (which is coarser and also reflects device/session/
        # risk facts unrelated to this one identity check).
        identity_state = derive_identity_state(
            face_present=face_present,
            face_match_confidence=face_confidence,
            liveness=liveness,
            camera_available=camera_available,
        )
        if identity_state is IdentityCheckState.IDENTITY_MISMATCH:
            warnings.append("detected face does not match enrolled identity")
        elif identity_state is IdentityCheckState.CAMERA_UNAVAILABLE:
            warnings.append("camera unavailable — identity could not be checked")

        authorization_valid = status not in (MonitoringStatus.REVOKED,)
        current_authorization_state = "valid" if authorization_valid else "invalid"

        # One machine-readable + human-readable reason for the authoritative
        # status. This is what every UI surface should display; do not
        # replace a real reason with the generic text "session revoked".
        if device_revoked:
            reason_code, reason = "device_revoked", "Device was revoked by an administrator or authorization policy."
        elif session_revoked:
            reason_code, reason = "session_revoked", "Session was revoked by an administrator or authorization policy."
        elif session_expired:
            reason_code, reason = "session_expired", "Session expired and authorization is no longer valid."
        elif failures >= thresholds.invalidate_after:
            reason_code, reason = "repeated_face_failures", f"{failures} consecutive identity verification failures."
        elif independent_risk.level is RiskLevel.CRITICAL:
            reason_code, reason = "critical_risk", f"Critical authorization risk score ({independent_risk.score}) triggered revocation."
        elif failures >= thresholds.reauth_required_after:
            reason_code, reason = "reauth_required", f"{failures} consecutive identity verification failures."
        elif independent_risk.level is RiskLevel.HIGH:
            reason_code, reason = "elevated_risk", f"Elevated authorization risk score ({independent_risk.score}) requires re-authentication."
        elif identity_state is IdentityCheckState.IDENTITY_MISMATCH:
            reason_code, reason = "identity_mismatch", "Detected face does not match the enrolled account identity."
        elif identity_state is IdentityCheckState.NO_FACE:
            reason_code, reason = "no_face", "No face was detected in the current monitoring frame."
        elif identity_state is IdentityCheckState.LIVENESS_UNCERTAIN:
            reason_code, reason = "liveness_uncertain", "Face detected, but liveness could not be confidently established."
        elif identity_state is IdentityCheckState.CAMERA_UNAVAILABLE:
            reason_code, reason = "camera_unavailable", "Camera is unavailable, so identity could not be verified."
        elif independent_risk.level is RiskLevel.MEDIUM:
            reason_code, reason = "elevated_risk", f"Elevated authorization risk score ({independent_risk.score})."
        else:
            reason_code, reason = "identity_confirmed", "Face descriptor matched server-side (descriptor similarity only; liveness is NOT established), device/session authorization valid, and monitoring connection healthy."

        state_hash = compute_monitoring_state_hash(
            monitoring_session_id=record.monitoring_session_id,
            current_user=record.user_id,
            current_device=record.device_id,
            current_session=record.session_id,
            status=status,
            current_lifecycle=current_lifecycle,
            current_risk=risk.level,
            current_authorization_state=current_authorization_state,
            session_version=session_version,
        )

        if persist_failure_counter:
            record.consecutive_face_failures = failures
            record.status = status
            record.updated_at = now
            record.snapshot_revision += 1
            if status is MonitoringStatus.REVOKED:
                # Keep tracking the session version this revocation is
                # tied to, so a LATER `reauthorize()` (which bumps the
                # version) can be detected and unlatch `already_revoked`
                # above. Re-stamping it on every still-revoked tick is
                # harmless — it only ever moves forward with the current
                # (unchanged, while still revoked) session version.
                record.revoked_at_session_version = session_version
            else:
                # Healed (or never revoked): nothing stale left to track.
                record.revoked_at_session_version = None
            if persist_record:
                self._repository.update(record)

        return MonitoringSnapshot(
            monitoring_session_id=record.monitoring_session_id,
            current_user=record.user_id,
            current_device=record.device_id,
            current_session=record.session_id,
            status=status,
            face_present=face_present,
            face_match_confidence=face_confidence,
            liveness=liveness,
            current_intent=record.intent_id,
            current_lifecycle=current_lifecycle,
            current_risk=risk.level,
            risk_score=risk.score,
            current_authorization_state=current_authorization_state,
            authorization_state_hash=state_hash,
            consecutive_face_failures=failures,
            warnings=tuple(warnings),
            expression_hint=expression_hint,
            timestamp=now,
            security_state=security_state,
            identity_state=identity_state,
            reason_code=reason_code,
            reason=reason,
            audit_chain_intact=not audit_compromised,
            snapshot_revision=record.snapshot_revision,
        )

    def _maybe_audit_transition(
        self, record: MonitoringSessionRecord, snapshot: MonitoringSnapshot, now: datetime
    ) -> None:
        if self._audit is None:
            return
        event_name = _STATUS_TRANSITION_EVENT.get(snapshot.status)
        if event_name is None:
            return
        self._audit.record(
            event_name,
            snapshot.status.value,
            user_id=record.user_id,
            session_id=record.session_id,
            device_id=record.device_id,
            risk=snapshot.current_risk.value,
            reason="; ".join(snapshot.warnings) or None,
            timestamp=now,
        )
