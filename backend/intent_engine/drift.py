"""Deterministic purpose-drift and scope rules.

``evaluate(facts)`` is a pure function: same facts -> same reasons.  It never consults a
model, a risk score or free text.  Each reason is machine-readable and has a *severity*:

* ``VIOLATION``  -- a definite policy violation.  Any violation => ``DENY``.
* ``REQUIRES``   -- a missing precondition that a legitimate actor can satisfy
                    (``APPROVAL`` or ``STEP_UP``); never a denial by itself.
* ``SIGNAL``     -- contextual information (e.g. elevated risk).  Signals are *reported*; the
                    separate risk gate decides whether a signal escalates to a step-up/denial.

Unusual behaviour is not classified as malicious: only definite mismatches against the approved
intent and authoritative state are violations.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .schema import Classification, IntentStatus


class Severity(str, Enum):
    VIOLATION = "VIOLATION"
    REQUIRES = "REQUIRES"
    SIGNAL = "SIGNAL"


@dataclass(frozen=True)
class Reason:
    code: str
    severity: Severity
    detail: str = ""
    requires: str | None = None            # "APPROVAL" | "STEP_UP" for REQUIRES

    def as_dict(self) -> dict:
        return {"code": self.code, "severity": self.severity.value, "detail": self.detail,
                "requires": self.requires}


@dataclass
class Facts:
    # ---- what is being attempted (from the request / actual operation)
    actor_user_id: int
    operation: str
    resource: str
    purpose_code: str
    session_id: str
    device_id: str
    requested_version: int | None
    requested_bytes: int | None
    key_session_id: str | None
    record: dict | None                     # decrypt: metadata of the record (resource, classification, size, owner)
    now_ts: int
    # ---- authoritative state
    intent_found: bool = True
    intent_integrity_ok: bool = True
    intent_owner_id: int | None = None
    intent_status: str = IntentStatus.APPROVED.value
    intent_version: int | None = None
    intent_body_hash: str | None = None
    intent_uses: int = 0
    body: dict = field(default_factory=dict)
    approvals_valid: int = 0
    rejected_by_approver: bool = False
    user_enabled: bool = True
    session_exists: bool = True
    session_owner_id: int | None = None
    session_device_id: str | None = None
    session_valid: bool = True
    session_reason: str | None = None
    device_revoked: bool = False
    device_owner_id: int | None = None
    monitoring_state: str | None = "active"     # active|warning|reauth_required|revoked|None(not established)|ERROR
    evidence_ok: bool = True
    evidence_detail: str = ""
    evidence_codes: tuple[str, ...] = ()
    key_status: str | None = "ACTIVE"
    key_owner_ok: bool = True
    recipient_enabled: bool = True
    recipient_user_id: int | None = None
    legacy_policy_failures: tuple[str, ...] = ()
    stepup_fresh: bool = False
    risk_action: str | None = None              # "decrypt"(proceed)|"require_face_verification"|"reject"|"revoke"|None
    risk_level: str | None = None
    admin_self_approval: bool = False


def _classification_rank(v: str) -> int:
    return Classification(v).rank


def evaluate(f: Facts) -> list[Reason]:
    R: list[Reason] = []
    V = lambda code, detail="": R.append(Reason(code, Severity.VIOLATION, detail))  # noqa: E731

    if not f.intent_found:
        V("INTENT_NOT_FOUND")
        return R
    if not f.intent_integrity_ok:
        V("INTENT_RECORD_TAMPERED", "stored intent version failed integrity verification")
        return R
    b = f.body

    # --- identity / ownership
    if not f.user_enabled:
        V("ACCOUNT_DISABLED")
    delegated_recipient = f.recipient_user_id == f.actor_user_id
    if f.intent_owner_id != f.actor_user_id and not delegated_recipient:
        V("USER_MISMATCH", "authorization belongs to another user")
    if f.operation == "share":
        if f.recipient_user_id is None:
            V("RECIPIENT_REQUIRED")
        elif not f.recipient_enabled:
            V("RECIPIENT_NOT_ELIGIBLE")

    # --- intent state
    if f.requested_version is not None and f.requested_version != f.intent_version:
        V("INTENT_VERSION_STALE", f"requested v{f.requested_version}, current v{f.intent_version}")
    st = f.intent_status
    if st in (IntentStatus.REVOKED.value, IntentStatus.REJECTED.value):
        V("INTENT_" + st, f"intent is {st.lower()}")
    elif st == IntentStatus.EXPIRED.value:
        V("INTENT_EXPIRED")
    elif st == IntentStatus.EXHAUSTED.value:
        V("INTENT_EXHAUSTED")
    elif st != IntentStatus.APPROVED.value:
        R.append(Reason("INTENT_NOT_APPROVED", Severity.REQUIRES, f"intent is {st.lower()}", "APPROVAL"))

    # --- validity window
    from security.canonical import iso_utc  # noqa: F401  (documented dependency)
    vf, vu = _ts(b.get("valid_from")), _ts(b.get("valid_until"))
    if vf is not None and f.now_ts < vf:
        V("INTENT_NOT_YET_VALID")
    if vu is not None and f.now_ts > vu:
        V("INTENT_EXPIRED", "validity window has passed")
    ds = b.get("data_scope", {})
    if f.intent_uses >= int(ds.get("max_uses", 1)) and st == IntentStatus.APPROVED.value:
        V("INTENT_EXHAUSTED", "maximum number of uses reached")

    # --- approvals
    need = int(b.get("required_approvals", 0))
    if f.rejected_by_approver:
        V("APPROVAL_REJECTED")
    elif f.approvals_valid < need and st == IntentStatus.APPROVED.value:
        # an APPROVED head with fewer valid approvals than required means approvals were invalidated
        V("APPROVAL_REVOKED_OR_INSUFFICIENT", f"{f.approvals_valid}/{need} valid approvals")

    # --- purpose / resource / operation / scope drift
    if f.purpose_code != b.get("purpose_code"):
        V("PURPOSE_DRIFT", "requested purpose differs from the approved purpose")
    if f.resource != b.get("resource"):
        V("RESOURCE_DRIFT", "requested resource differs from the approved resource")
    if f.operation not in b.get("operations", []):
        V("OPERATION_DRIFT", f"operation '{f.operation}' is not in the approved operations")
    if f.requested_bytes is not None and f.requested_bytes > int(ds.get("max_bytes", 0)):
        V("SCOPE_EXCEEDED", "requested data volume exceeds the approved scope")
    if f.record is not None:
        expires_ts = f.record.get("expires_ts")
        if not isinstance(expires_ts, int) or expires_ts <= f.now_ts:
            V("RECORD_EXPIRED")
        shared_to_actor = (
            f.operation == "decrypt"
            and f.record.get("recipient_user_id") == f.actor_user_id
            and f.record.get("share_status") == "APPROVED"
            and delegated_recipient
            and f.recipient_enabled
        )
        if f.record.get("owner_user_id") != f.actor_user_id and not shared_to_actor:
            V("RECORD_NOT_OWNED", "record belongs to another user")
        if f.record.get("intent_id") != b.get("intent_id"):
            V("INTENT_DRIFT", "record is bound to another intent")
        if f.record.get("intent_version") != f.intent_version:
            V("INTENT_VERSION_STALE", "record is bound to another intent version")
        if f.record.get("intent_body_hash") != f.intent_body_hash:
            V("INTENT_INTEGRITY_FAILED", "record is bound to another intent body")
        if f.operation == "share" and f.record.get("owner_user_id") != f.actor_user_id:
            V("RECORD_NOT_OWNED", "only the record owner may create a share")
        if f.operation == "decrypt" and f.record.get("share_status") not in (None, "APPROVED"):
            V("SHARE_NOT_AVAILABLE", "share is not approved")
        if f.record.get("resource") != b.get("resource"):
            V("RESOURCE_DRIFT", "record resource differs from the approved resource")
        try:
            if _classification_rank(f.record.get("classification", "RESTRICTED")) > _classification_rank(
                    ds.get("classification", "PUBLIC")):
                V("SCOPE_EXCEEDED", "record classification exceeds the approved scope")
        except ValueError:
            V("SCOPE_EXCEEDED", "record classification unrecognised")
        if int(f.record.get("size", 0)) > int(ds.get("max_bytes", 0)):
            V("SCOPE_EXCEEDED", "record size exceeds the approved scope")

    # --- session / device binding
    # An owner's decrypt operation may be resumed from another device/login session.
    # This is NOT a bypass: the record must be owned by the actor and the current
    # session/device are still independently checked below (ownership, revocation,
    # session validity, session-device match, monitoring and step-up authorization).
    # Encryption and sharing remain bound to the original intent session/device.
    owner_resumed_decrypt = (
        f.operation == "decrypt" and f.record is not None
        and f.record.get("owner_user_id") == f.actor_user_id
        and f.intent_owner_id == f.actor_user_id
    )
    if f.session_id != b.get("session_id") and not (delegated_recipient or owner_resumed_decrypt):
        V("SESSION_MISMATCH", "request session differs from the intent's bound session")
    if f.device_id != b.get("device_id") and not (delegated_recipient or owner_resumed_decrypt):
        V("DEVICE_MISMATCH", "request device differs from the intent's bound device")
    if not f.session_exists:
        V("SESSION_UNKNOWN")
    else:
        if f.session_owner_id != f.actor_user_id:
            V("SESSION_NOT_OWNED")
        if f.session_device_id != f.device_id:
            V("SESSION_DEVICE_MISMATCH")
        if not f.session_valid:
            V("SESSION_INVALID", f.session_reason or "")
    if f.device_revoked:
        V("DEVICE_REVOKED")
    if f.device_owner_id is not None and f.device_owner_id != f.actor_user_id:
        V("DEVICE_NOT_OWNED")

    # --- evidence (authoritative records)
    if not f.evidence_ok:
        codes = f.evidence_codes
        if "CASE_CLOSED" in codes:
            V("CASE_CLOSED", "supporting business case is closed")
        elif "USER_NOT_ASSIGNED" in codes:
            V("USER_REMOVED_FROM_CASE", "requester is no longer assigned to the supporting case")
        elif "RESOURCE_NOT_IN_CASE_SCOPE" in codes or "CLASSIFICATION_ABOVE_CASE_CAP" in codes:
            V("CASE_SCOPE_MISMATCH", f.evidence_detail)
        else:
            V("EVIDENCE_INSUFFICIENT", f.evidence_detail)

    # --- key session
    if f.key_session_id is None:
        V("KEY_SESSION_REQUIRED")
    elif f.key_status is None or not f.key_owner_ok:
        V("KEY_SESSION_NOT_FOUND")
    else:
        allowed = ("ACTIVE",) if f.operation == "encrypt" else ("ACTIVE", "ROTATED")
        if f.key_status not in allowed:
            V("KEY_SESSION_" + f.key_status, "key session cannot be used for this operation")

    # --- legacy persisted policies (allowed ops/devices/resources/roles)
    for msg in f.legacy_policy_failures:
        V("POLICY_RULE_FAILED", msg)

    # --- monitoring (mandatory; fail closed)
    ms = f.monitoring_state
    if ms is None:
        V("MONITORING_NOT_ESTABLISHED", "continuous monitoring is not active for this session")
    elif ms == "ERROR":
        V("MONITORING_UNAVAILABLE", "monitoring state could not be determined (fail closed)")
    elif ms == "revoked":
        V("MONITORING_REVOKED", "monitoring revoked this session")
    elif ms == "reauth_required":
        R.append(Reason("MONITORING_REAUTH_REQUIRED", Severity.REQUIRES, "fresh re-authentication required", "STEP_UP"))
    elif ms == "warning":
        R.append(Reason("MONITORING_WARNING", Severity.SIGNAL, "monitoring is in WARNING"))

    # --- approvals still missing (not yet approved)
    if st == IntentStatus.PENDING_APPROVAL.value:
        pass  # already reported as INTENT_NOT_APPROVED (REQUIRES APPROVAL)

    # --- step-up policy
    cls = ds.get("classification", "PUBLIC")
    needs_stepup = _classification_rank(cls) >= Classification.RESTRICTED.rank
    if needs_stepup and not f.stepup_fresh:
        R.append(Reason("STEP_UP_REQUIRED", Severity.REQUIRES, "fresh identity step-up is required for this classification", "STEP_UP"))

    # --- risk gate (signal-driven; can only add caution)
    if f.risk_level:
        R.append(Reason("RISK_" + f.risk_level.upper(), Severity.SIGNAL, "contextual risk signal"))
    if f.risk_action in ("reject", "revoke"):
        V("RISK_GATE_DENIED", "contextual risk exceeds the permitted threshold")
    elif f.risk_action == "require_face_verification" and not f.stepup_fresh:
        R.append(Reason("RISK_STEP_UP", Severity.REQUIRES, "elevated contextual risk requires step-up", "STEP_UP"))

    return R


def _ts(v):
    if v is None:
        return None
    import calendar
    import time
    return calendar.timegm(time.strptime(v, "%Y-%m-%dT%H:%M:%SZ"))


def outcome(reasons: list[Reason]) -> str:
    if any(r.severity is Severity.VIOLATION for r in reasons):
        return "DENY"
    reqs = {r.requires for r in reasons if r.severity is Severity.REQUIRES}
    if "APPROVAL" in reqs:
        return "REQUIRE_APPROVAL"
    if "STEP_UP" in reqs:
        return "REQUIRE_STEP_UP"
    return "PERMIT"
