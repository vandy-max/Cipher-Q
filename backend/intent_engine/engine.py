"""Intent Integrity & Purpose Drift Engine -- orchestration.

Flow:  create intent (v1) -> validate (evidence + scope) -> approvals -> APPROVED
       -> decide(operation request)  = deterministic rules -> signed decision (+ crypto context on PERMIT)
       -> open_context(actual operation) = re-evaluate everything against CURRENT state, release the
          quantum-key material only if the cryptographic context still matches, single use.

Authorization-state binding: the qkey handed to a context is wrapped under
    HKDF(CTX_WRAP sub-key, salt=context_id, info=H(current authorization state))
and the state hash is *recomputed from authoritative records* every time the context is opened.  If
the intent, approvals, decision status, session, device, monitoring, evidence, policy or key session
changed in a relevant way the recomputed hash differs, the AEAD unwrap fails, and the operation
cannot proceed -- regardless of any client-supplied value.
"""
from __future__ import annotations

import time
import uuid
import base64
import binascii
from dataclasses import dataclass, field
from typing import Any, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from audit.events import AuditEvent
from intent.schema import CID
from keymgmt.key_sessions import KeySessionService, KeyUnavailableError
from policy.config import policy_context_overrides
from policy.engine import PolicyEngine
from policy.rules import PolicyContext, default_rules
from security import integrity
from security.canonical import canonical_bytes, digest, frame, iso_utc
from security.keyring import CTX_WRAP, Keyring

from . import drift
from .drift import Facts, Reason, Severity
from .evidence import (
    EvidenceValidator,
    evidence_supports,
)
from .schema import (EVIDENCE_REQUIRED_FROM, REQUIRED_APPROVALS, TERMINAL, Classification, IntentRequest,
                     IntentStatus, body_from_request)
from .store import EngineStore, now_ts

CODE_POLICY_VERSION = "cipherq-policy-2026.10.1"


class EngineError(Exception):
    def __init__(self, code: str, status: int = 400, detail: str = "") -> None:
        self.code, self.status = code, status
        super().__init__(detail or code)


@dataclass(frozen=True)
class Actor:
    user_id: int
    username: str
    role: str


@dataclass
class OperationRequest:
    intent_id: int
    operation: str
    resource: str
    purpose_code: str
    session_id: str
    device_id: str
    intent_version: int | None = None
    key_session_id: str | None = None        # encrypt only; decrypt derives it from the record
    requested_bytes: int | None = None
    record: dict | None = None               # decrypt/share: server-loaded record metadata
    recipient_user_id: int | None = None


@dataclass
class Deps:
    db: Any
    keyring: Keyring
    settings: Any
    users: Any
    sessions: Any
    devices: Any
    monitoring_state: Callable[[str, int], str | None]
    evidence: Any
    keys: KeySessionService
    stepup: Any
    risk: Callable[[Actor, CID], tuple[str | None, str | None]]
    policy_rows: Callable[[], list]
    audit: Any


@dataclass
class DecisionOutcome:
    decision: dict
    outcome: str
    reasons: list[Reason]
    context_id: str | None = None
    findings: list[dict] = field(default_factory=list)


@dataclass
class OpenedContext:
    qkey: bytes = field(repr=False)
    decision: dict
    context: dict
    body: dict
    head: dict


def _hkdf_ctx_key(kr: Keyring, kid: int, ctx_id: str, state_hash: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=ctx_id.encode(),
                info=frame(b"CIPHERQ|CTX|v1", state_hash.encode())).derive(kr.subkey(CTX_WRAP, kid))


class IntentEngine:
    def __init__(self, deps: Deps) -> None:
        self.d = deps
        self.store = EngineStore(deps.db, deps.keyring)
        self.validator = EvidenceValidator(deps.evidence)
        self._legacy = PolicyEngine([r for r in default_rules() if r.name in
                                     ("allowed_operation", "allowed_device", "resource_matching", "role_matching")])

    # ============================================================ helpers
    def policy_version(self) -> str:
        rows = sorted(({"rule_type": r.rule_type, "active": bool(r.active),
                        "config": _plain(r.config_json)} for r in self.d.policy_rows()),
                      key=lambda x: (x["rule_type"], str(x["config"])))
        return f"{CODE_POLICY_VERSION}+{digest('CIPHERQ|POLICY-SET|v1', rows)[:12]}"

    def _audit(self, action: str, result: str, actor: Actor | None = None, **kw) -> None:
        self.d.audit.record(action, result, user_id=actor.user_id if actor else kw.pop("user_id", None), **kw)

    def _user(self, user_id: int):
        return self.d.users.get_by_id(user_id)

    def _validate_recipient(self, actor: Actor, req: IntentRequest) -> None:
        recipient_id = getattr(req, "recipient_user_id", None)
        if recipient_id is None:
            return
        recipient = self._user(recipient_id)
        if recipient is None or recipient.disabled:
            raise EngineError("RECIPIENT_NOT_FOUND", 400)

    # ============================================================ intents
    def create_intent(self, actor: Actor, req: IntentRequest) -> dict:
        self._validate_recipient(actor, req)
        user = self._user(actor.user_id)
        if user is None or user.disabled:
            raise EngineError("ACCOUNT_DISABLED", 403)
        required = REQUIRED_APPROVALS[req.data_scope.classification]

        def body_fn(intent_id: int) -> dict:
            b = body_from_request(req, intent_id=intent_id, version=1, owner_user_id=actor.user_id,
                                  sender=actor.username, required_approvals=required)
            b["_reason"] = req.reason
            return b

        head, ver = self.store.create_intent(actor.user_id, body_fn)
        self._audit(AuditEvent.INTENT_CREATED, "success", actor, intent_hash=ver["body_hash"],
                    resource=req.resource, session_id=req.session_id, device_id=req.device_id,
                    reason=f"intent={head['_id']} v1 classification={req.data_scope.classification.value}")
        return self.view(actor, head["_id"])

    def new_version(self, actor: Actor, intent_id: int, req: IntentRequest) -> dict:
        self._validate_recipient(actor, req)
        head = self._owned_head(actor, intent_id)
        cur = head["current_version"]
        required = REQUIRED_APPROVALS[req.data_scope.classification]
        body = body_from_request(req, intent_id=intent_id, version=cur + 1, owner_user_id=head["owner_user_id"],
                                 sender=actor.username, required_approvals=required)
        ver = self.store.add_version(intent_id, cur, body, actor.user_id, req.reason)
        if ver is None:
            raise EngineError("CONCURRENT_MODIFICATION", 409)
        # An approved intent is NEVER edited in place: the old version's decisions and contexts die now.
        self.store.revoke_decisions_where(intent_id=intent_id)
        self.store.invalidate_contexts_where(intent_id=intent_id)
        self._audit(AuditEvent.INTENT_VERSION_CREATED, "success", actor, intent_hash=ver["body_hash"],
                    reason=f"intent={intent_id} v{cur + 1}; prior decisions revoked; re-approval required")
        return self.view(actor, intent_id)

    def _owned_head(self, actor: Actor, intent_id: int) -> dict:
        head = self.store.get_head(intent_id)
        if head is None or head["owner_user_id"] != actor.user_id:
            raise EngineError("INTENT_NOT_FOUND", 404)
        return head

    def _readable_head(self, actor: Actor, intent_id: int) -> dict:
        head = self.store.get_head(intent_id)
        if head is None or (head["owner_user_id"] != actor.user_id and actor.role != "ADMIN"):
            raise EngineError("INTENT_NOT_FOUND", 404)
        return head

    def _effective_status(self, head: dict, body: dict) -> str:
        st = head["status"]
        if st in (IntentStatus.APPROVED.value, IntentStatus.PENDING_APPROVAL.value, IntentStatus.DRAFT.value):
            if now_ts() > _ts(body["valid_until"]):
                self.store.set_status(head["_id"], {st}, IntentStatus.EXPIRED)
                return IntentStatus.EXPIRED.value
        return st

    def view(self, actor: Actor, intent_id: int) -> dict:
        head = self._readable_head(actor, intent_id)
        ver = self.store.get_version(intent_id, head["current_version"], verify=False)
        authentic = integrity.verify(self.d.keyring, "intent-version", ver)
        body = ver["body"]
        # Attachment bytes stay inside the encrypted intent version. Never serialize
        # them through list/detail/approval responses.
        public_body = dict(body)
        attachment = public_body.get("attachment")
        if attachment:
            public_body["attachment"] = {"filename": attachment["filename"],
                                         "content_type": attachment["content_type"],
                                         "size": len(base64.b64decode(attachment["content_base64"]))}
        approvals = self._approval_summary(intent_id, head["current_version"])
        return {"intent_id": intent_id, "version": head["current_version"],
                "status": self._effective_status(head, body), "uses": head["uses"],
                "integrity_ok": authentic, "body": public_body, "body_hash": ver["body_hash"],
                "approvals": approvals, "required_approvals": body["required_approvals"],
                "owner_user_id": head["owner_user_id"]}

    def download_attachment(self, actor: Actor, intent_id: int, session_id: str, device_id: str,
                            key_session_id: str) -> tuple[dict, bytes]:
        """Release an attachment only from the current, live, fully approved intent."""
        head = self.store.get_head(intent_id)
        if head is None:
            raise EngineError("INTENT_NOT_FOUND", 404)
        ver = self.store.get_version(intent_id, head["current_version"])
        if ver is None or not integrity.verify(self.d.keyring, "intent-version", ver):
            raise EngineError("INTENT_INTEGRITY_FAILED", 403)
        body = ver["body"]
        if actor.user_id not in {head["owner_user_id"], body.get("recipient_user_id")}:
            raise EngineError("INTENT_NOT_FOUND", 404)
        status = self._effective_status(head, body)
        if status != IntentStatus.APPROVED.value:
            raise EngineError("INTENT_NOT_APPROVED", 403)
        valid_count, rejected = self._valid_approvals(intent_id, head["current_version"], head["owner_user_id"])
        if rejected or valid_count < body["required_approvals"]:
            raise EngineError("APPROVALS_INSUFFICIENT", 403)
        attachment = body.get("attachment")
        if not attachment:
            raise EngineError("ATTACHMENT_NOT_FOUND", 404)
        try:
            content = base64.b64decode(attachment["content_base64"], validate=True)
        except (ValueError, binascii.Error, KeyError, TypeError):
            raise EngineError("ATTACHMENT_CORRUPT", 422) from None
        if not content or len(content) > int(body["data_scope"]["max_bytes"]):
            raise EngineError("ATTACHMENT_CORRUPT", 422)
        # The sender is retrieving their own approved CID attachment as the
        # plaintext source for the subsequent encryption/share operation.
        # Authorize this as ENCRYPT (not DECRYPT): an intent may explicitly
        # permit encrypt/share without granting standalone decrypt permission.
        # All normal owner, intent, evidence, session/device, monitoring,
        # key-session, validity and scope checks still run.
        req = OperationRequest(intent_id=intent_id, operation="encrypt", resource=body["resource"],
                               purpose_code=body["purpose_code"], session_id=session_id,
                               device_id=device_id, intent_version=head["current_version"],
                               key_session_id=key_session_id, requested_bytes=len(content))
        facts, _state, _head, _ver = self.gather(actor.user_id, req)
        denied = [reason for reason in drift.evaluate(facts)
                  if reason.severity in (Severity.VIOLATION, Severity.REQUIRES)]
        if denied:
            # Return the actual failed precondition so the client can guide the
            # user (e.g. monitoring re-authentication) instead of a generic denial.
            first = denied[0]
            raise EngineError(first.code, 403, first.detail)
        if self.store.consume_use(intent_id, head["current_version"], int(body["data_scope"]["max_uses"])) is None:
            raise EngineError("INTENT_EXHAUSTED", 409)
        self._audit(AuditEvent.INTENT_ATTACHMENT_DOWNLOADED, "success", actor,
                    intent_hash=ver["body_hash"], resource=body["resource"],
                    reason=f"intent={intent_id} v{head['current_version']}")
        return {"filename": attachment["filename"], "content_type": attachment["content_type"]}, content

    def list_intents(self, actor: Actor) -> list[dict]:
        heads = self.store.list_heads(None if actor.role == "ADMIN" else actor.user_id)
        return [self.view(actor, h["_id"]) for h in heads]

    # ---- approvals
    def _approval_summary(self, intent_id: int, version: int) -> list[dict]:
        last: dict[int, dict] = {}
        for a in self.store.approvals_for(intent_id, version):
            last[a["approver_id"]] = a
        return [{"approver_id": a["approver_id"], "verdict": a["verdict"], "at": a["created_ts"]}
                for a in last.values()]

    def _validate_evidence(self, body: dict, version: dict, user_id: int, actor: Actor) -> dict:
        cls = Classification(body["data_scope"]["classification"])
        findings = self.validator.validate(body["evidence_refs"], user_id=user_id, resource=body["resource"],
                                           classification=cls, business_reference=body["business_reference"])
        ok, why = evidence_supports(findings, cls, EVIDENCE_REQUIRED_FROM, body["business_reference"])
        codes = {finding.code for finding in findings}
        if ok:
            outcome = ("VERIFIED" if any(f.ok and f.trust.value == "VERIFIED_FACT" for f in findings)
                       else "NOT_REQUIRED")
        elif "EVIDENCE_PROVIDER_UNAVAILABLE" in codes:
            outcome = "EVIDENCE_PROVIDER_UNAVAILABLE"
        elif "CASE_NOT_FOUND" in codes:
            outcome = "CASE_NOT_FOUND"
        else:
            outcome = "EVIDENCE_INVALID"
        finding_data = [finding.as_dict() for finding in findings]
        evidence_source = self.d.evidence.name
        self.store.record_evidence_validation(
            intent_id=body["intent_id"], version=body["version"], body_hash=version["body_hash"],
            outcome=outcome, evidence_source=evidence_source, findings=finding_data, validated_by=actor.user_id)
        self._audit(AuditEvent.EVIDENCE_VALIDATED, "success" if ok else "rejected", actor,
                    intent_hash=version["body_hash"], resource=body["resource"],
                    reason=f"intent={body['intent_id']} v{body['version']} {outcome}: {why}")
        return {"evidence_ok": ok, "outcome": outcome, "evidence_source": evidence_source,
                "evidence_summary": why, "findings": finding_data}

    def _invalidate_version_approvals(self, actor: Actor, intent_id: int, version: int,
                                      body_hash: str, reason: str) -> None:
        latest: dict[int, dict] = {}
        for approval in self.store.approvals_for(intent_id, version):
            latest[approval["approver_id"]] = approval
        invalidated = []
        for approver_id, approval in latest.items():
            if approval["verdict"] != "APPROVE":
                continue
            approver = self._user(approver_id)
            role = approver.role if approver else approval["approver_role"]
            self.store.add_approval(intent_id, version, approver_id, role, "WITHDRAW",
                                    "evidence validation no longer supports approval", self.policy_version())
            invalidated.append(approver_id)
        if invalidated:
            self._audit(AuditEvent.INTENT_APPROVAL_WITHDRAWN, "success", actor, intent_hash=body_hash,
                        reason=f"intent={intent_id} v{version} prior approvals invalidated: {reason}")

    def _valid_approvals(self, intent_id: int, version: int, owner_id: int) -> tuple[int, bool]:
        """(count of distinct current APPROVE verdicts from eligible approvers, any REJECT standing)"""
        last: dict[int, dict] = {}
        for a in self.store.approvals_for(intent_id, version):
            last[a["approver_id"]] = a
        n, rejected = 0, False
        for uid, a in last.items():
            approver = self._user(uid)
            if approver is None or approver.disabled or approver.role != "ADMIN":
                continue                               # demoted/disabled approvers no longer count
            if uid == owner_id and not self.d.settings.admin_self_approval:
                continue
            if a["verdict"] == "APPROVE":
                n += 1
            elif a["verdict"] == "REJECT":
                rejected = True
        return n, rejected

    def validate(self, actor: Actor, intent_id: int) -> dict:
        """Evidence + scope validation report. Moves DRAFT -> PENDING_APPROVAL (or APPROVED when policy
        requires no human approval).  A valid-looking report is NOT an authorization."""
        head = self._owned_head(actor, intent_id)
        ver = self.store.get_version(intent_id, head["current_version"])
        body = ver["body"]
        evidence = self._validate_evidence(body, ver, head["owner_user_id"], actor)
        status = self._effective_status(head, body)
        if evidence["evidence_ok"] and status == IntentStatus.DRAFT.value:
            if body["required_approvals"] == 0:
                self.store.add_approval(intent_id, head["current_version"], 0, "POLICY", "APPROVE",
                                        "policy: no human approval required for this classification",
                                        self.policy_version())
                self.store.set_status(intent_id, {IntentStatus.DRAFT.value}, IntentStatus.APPROVED)
            else:
                self.store.set_status(intent_id, {IntentStatus.DRAFT.value}, IntentStatus.PENDING_APPROVAL)
        elif not evidence["evidence_ok"] and status in {
            IntentStatus.PENDING_APPROVAL.value, IntentStatus.APPROVED.value
        }:
            self.store.set_status(intent_id, {status}, IntentStatus.DRAFT)
            self._invalidate_version_approvals(actor, intent_id, head["current_version"], ver["body_hash"],
                                                evidence["evidence_summary"])
            if status == IntentStatus.APPROVED.value:
                self.store.revoke_decisions_where(intent_id=intent_id)
                self.store.invalidate_contexts_where(intent_id=intent_id)
        v = self.view(actor, intent_id)
        return {**evidence, "intent": v,
                "note": "Validation reports on evidence; it does not authorise any operation."}

    def approve(self, actor: Actor, intent_id: int, version: int, verdict: str, comment: str) -> dict:
        if actor.role != "ADMIN":
            raise EngineError("FORBIDDEN", 403)
        head = self.store.get_head(intent_id)
        if head is None:
            raise EngineError("INTENT_NOT_FOUND", 404)
        if head["owner_user_id"] == actor.user_id and not self.d.settings.admin_self_approval:
            raise EngineError("SELF_APPROVAL_FORBIDDEN", 403, "requesters cannot approve their own intent")
        if version != head["current_version"]:
            raise EngineError("INTENT_VERSION_STALE", 409)
        if head["status"] != IntentStatus.PENDING_APPROVAL.value:
            raise EngineError("INTENT_NOT_PENDING", 409, f"intent is {head['status']}")
        ver = self.store.get_version(intent_id, version)
        body = ver["body"]
        if now_ts() > _ts(body["valid_until"]):
            self.store.set_status(intent_id, {head["status"]}, IntentStatus.EXPIRED)
            raise EngineError("INTENT_EXPIRED", 409)
        evidence = self._validate_evidence(body, ver, head["owner_user_id"], actor)
        if not evidence["evidence_ok"]:
            self.store.set_status(intent_id, {IntentStatus.PENDING_APPROVAL.value}, IntentStatus.DRAFT)
            self._invalidate_version_approvals(actor, intent_id, version, ver["body_hash"],
                                                evidence["evidence_summary"])
            if evidence["outcome"] == "EVIDENCE_PROVIDER_UNAVAILABLE":
                raise EngineError("EVIDENCE_PROVIDER_UNAVAILABLE", 503)
            raise EngineError("EVIDENCE_INVALID", 409, evidence["evidence_summary"])
        self.store.add_approval(intent_id, version, actor.user_id, actor.role, verdict, comment[:200],
                                self.policy_version())
        self._audit(AuditEvent.INTENT_APPROVAL_RECORDED, "success", actor, intent_hash=ver["body_hash"],
                    reason=f"intent={intent_id} v{version} verdict={verdict}")
        n, rejected = self._valid_approvals(intent_id, version, head["owner_user_id"])
        if rejected:
            self.store.set_status(intent_id, {IntentStatus.PENDING_APPROVAL.value}, IntentStatus.REJECTED)
            self._audit(AuditEvent.INTENT_REJECTED, "success", actor, intent_hash=ver["body_hash"])
        elif n >= body["required_approvals"]:
            self.store.set_status(intent_id, {IntentStatus.PENDING_APPROVAL.value}, IntentStatus.APPROVED)
            self._audit(AuditEvent.INTENT_APPROVED, "success", actor, intent_hash=ver["body_hash"],
                        reason=f"intent={intent_id} v{version} approvals={n}/{body['required_approvals']}")
        return self.view(actor, intent_id)

    def withdraw_approval(self, actor: Actor, intent_id: int, reason: str) -> dict:
        """An administrator withdraws their earlier approval: the intent drops back to PENDING and all
        decisions/contexts issued under it are revoked."""
        if actor.role != "ADMIN":
            raise EngineError("FORBIDDEN", 403)
        head = self.store.get_head(intent_id)
        if head is None:
            raise EngineError("INTENT_NOT_FOUND", 404)
        self.store.add_approval(intent_id, head["current_version"], actor.user_id, actor.role, "WITHDRAW",
                                reason[:200], self.policy_version())
        n, _ = self._valid_approvals(intent_id, head["current_version"], head["owner_user_id"])
        ver = self.store.get_version(intent_id, head["current_version"])
        if n < ver["body"]["required_approvals"] and head["status"] == IntentStatus.APPROVED.value:
            self.store.set_status(intent_id, {IntentStatus.APPROVED.value}, IntentStatus.PENDING_APPROVAL)
            self.store.revoke_decisions_where(intent_id=intent_id)
            self.store.invalidate_contexts_where(intent_id=intent_id)
        self._audit(AuditEvent.INTENT_APPROVAL_WITHDRAWN, "success", actor, intent_hash=ver["body_hash"],
                    reason=f"intent={intent_id} approvals now {n}")
        return self.view(actor, intent_id)

    def revoke_intent(self, actor: Actor, intent_id: int, reason: str) -> dict:
        head = self.store.get_head(intent_id)
        if head is None or (head["owner_user_id"] != actor.user_id and actor.role != "ADMIN"):
            raise EngineError("INTENT_NOT_FOUND", 404)
        self.store.set_status(intent_id, {s.value for s in IntentStatus if s not in TERMINAL}, IntentStatus.REVOKED)
        nd = self.store.revoke_decisions_where(intent_id=intent_id)
        nc = self.store.invalidate_contexts_where(intent_id=intent_id)
        self._audit(AuditEvent.INTENT_REVOKED, "success", actor,
                    reason=f"intent={intent_id} decisions_revoked={nd} contexts_invalidated={nc}: {reason[:120]}")
        return self.view(actor, intent_id)

    # ============================================================ facts + state
    def _legacy_policy(self, actor_role: str, cid: CID, now) -> tuple[str, ...]:
        overrides = policy_context_overrides(self.d.policy_rows())
        ctx = PolicyContext(now=now, requesting_user_role=actor_role, **overrides)
        dec = self._legacy.evaluate(cid, ctx)
        return tuple(f"{o.rule_name}: {o.reason}" for o in dec.failures)

    def gather(self, actor_id: int, req: OperationRequest, *, decision: dict | None = None,
               include_risk: bool = True) -> tuple[Facts, dict, dict | None, dict | None]:
        """Facts for the rule engine + the canonical state dict (hashed into the context key)."""
        now = now_ts()
        from datetime import datetime, timezone
        user = self._user(actor_id)
        head = self.store.get_head(req.intent_id)
        f = Facts(actor_user_id=actor_id, operation=req.operation, resource=req.resource,
                  purpose_code=req.purpose_code, session_id=req.session_id, device_id=req.device_id,
                  requested_version=req.intent_version, requested_bytes=req.requested_bytes,
                  key_session_id=req.key_session_id, record=req.record, now_ts=now,
                  admin_self_approval=self.d.settings.admin_self_approval)
        state: dict[str, Any] = {"v": 2}
        if req.record is not None:
            state["record"] = dict(req.record)
        f.user_enabled = bool(user and not user.disabled)
        state["user"] = {"id": actor_id, "enabled": f.user_enabled, "role": user.role if user else None}
        if head is None:
            f.intent_found = False
            return f, state, None, None
        ver = self.store.get_version(req.intent_id, head["current_version"], verify=False)
        f.intent_integrity_ok = integrity.verify(self.d.keyring, "intent-version", ver)
        body = ver["body"]
        f.body, f.intent_owner_id = body, head["owner_user_id"]
        f.intent_version, f.intent_uses = head["current_version"], head["uses"]
        f.intent_body_hash = ver["body_hash"]
        f.intent_status = self._effective_status(head, body)
        n_app, rejected = self._valid_approvals(req.intent_id, head["current_version"], head["owner_user_id"])
        f.approvals_valid, f.rejected_by_approver = n_app, rejected
        state["intent"] = {"id": req.intent_id, "version": head["current_version"], "status": f.intent_status,
                           "approvals": n_app, "body_hash": ver["body_hash"], "integrity": f.intent_integrity_ok}
        recipient_id = (req.recipient_user_id if req.recipient_user_id is not None
                        else (req.record or {}).get("recipient_user_id", body.get("recipient_user_id")))
        if req.operation == "share" or recipient_id is not None:
            recipient = self._user(recipient_id) if recipient_id is not None else None
            f.recipient_enabled = bool(recipient and not recipient.disabled)
            f.recipient_user_id = recipient_id
            state["recipient"] = {"id": recipient_id, "enabled": f.recipient_enabled}
        # session / device
        sess = self.d.sessions.get(req.session_id)
        f.session_exists = sess is not None
        sv = {"id": req.session_id, "exists": sess is not None}
        if sess is not None:
            from authorization.sessions import is_session_valid
            valid, reason = is_session_valid(sess, datetime.now(timezone.utc))
            f.session_owner_id, f.session_device_id = sess.user_id, sess.device_id
            f.session_valid, f.session_reason = valid, reason
            sv.update({"version": sess.version, "valid": valid, "owner": sess.user_id, "device": sess.device_id})
        state["session"] = sv
        dev_rev = self.d.devices.get_status(req.device_id).revoked
        f.device_revoked = dev_rev
        f.device_owner_id = self.d.devices.get_owner(req.device_id)
        state["device"] = {"id": req.device_id, "revoked": dev_rev, "owner": f.device_owner_id}
        # monitoring
        try:
            ms = self.d.monitoring_state(req.session_id, actor_id)
        except Exception:  # noqa: BLE001 -- fail closed
            ms = "ERROR"
        f.monitoring_state = ms
        state["monitoring"] = {None: "none", "active": "permit", "warning": "permit", "reauth_required": "reauth",
                               "revoked": "block", "ERROR": "error"}.get(ms, "error")
        # Evidence is evaluated for the sender when the share is created. Once an
        # approved share has been delivered, the recipient's right to decrypt is
        # represented by that recipient-bound share record and its validity window.
        # Requiring the recipient to be assigned to the sender's supporting case
        # would incorrectly deny legitimate cross-user sharing (USER_REMOVED_FROM_CASE).
        # This exception is deliberately narrow: it applies only to an authenticated
        # recipient decrypting an APPROVED share owned by the intent owner. All other
        # intent integrity/status, expiry, RBAC, session/device, monitoring, risk,
        # key ownership, face step-up and cryptographic checks remain in force.
        delegated_share_decrypt = (
            req.operation == "decrypt"
            and req.record is not None
            and req.record.get("share_status") == "APPROVED"
            and req.record.get("recipient_user_id") == actor_id
            and req.record.get("owner_user_id") == head["owner_user_id"]
            and req.record.get("intent_id") == req.intent_id
        )
        if delegated_share_decrypt:
            f.evidence_ok, f.evidence_detail = True, "approved recipient-bound share"
            f.evidence_codes = ()
            state["evidence"] = {"mode": "approved_share_delegation",
                                 "share_id": req.record.get("record_id"),
                                 "recipient_user_id": actor_id}
        else:
            cls = Classification(body["data_scope"]["classification"])
            findings = self.validator.validate(body["evidence_refs"], user_id=actor_id, resource=body["resource"],
                                               classification=cls, business_reference=body["business_reference"])
            ok, why = evidence_supports(findings, cls, EVIDENCE_REQUIRED_FROM, body["business_reference"])
            f.evidence_ok, f.evidence_detail = ok, why
            f.evidence_codes = tuple(sorted({x.code for x in findings if not x.ok}))
            state["evidence"] = [[x.ref, x.case_status, x.case_revision, x.ok, x.code] for x in findings]
        # key session
        ks_id = req.key_session_id
        if ks_id:
            ks = self.d.keys.get(ks_id, actor_id)
            f.key_owner_ok = ks is not None
            f.key_status = ks.status if ks else None
            state["key"] = {"id": ks_id, "status": f.key_status}
        # legacy persisted policy rules + policy version
        pv = self.policy_version()
        state["policy"] = pv
        try:
            cid = _adapter_cid(f.body, req, user.username if user else "unknown", now)
            f.legacy_policy_failures = self._legacy_policy(user.role if user else "", cid, datetime.now(timezone.utc))
            state["policy_failures"] = list(f.legacy_policy_failures)
            if include_risk:
                actor = Actor(actor_id, user.username if user else "", user.role if user else "")
                try:
                    f.risk_action, f.risk_level = self.d.risk(actor, cid)
                except Exception:  # noqa: BLE001 -- unavailable risk layer -> add caution, never leniency
                    f.risk_action, f.risk_level = "require_face_verification", "unknown"
        except Exception:  # noqa: BLE001
            f.legacy_policy_failures = ("policy evaluation failed",)
        f.stepup_fresh = self.d.stepup.has_fresh_grant(actor_id, req.session_id)
        if decision is not None:
            st = self.store.decision_status(decision["_id"]) or {}
            state["decision"] = {"id": decision["_id"], "status": st.get("status"), "revision": st.get("revision")}
        return f, state, head, ver

    @staticmethod
    def state_hash(state: dict) -> str:
        return digest("CIPHERQ|AUTHZ-STATE|v2", state)

    # ============================================================ decisions
    def decide(self, actor: Actor, req: OperationRequest) -> DecisionOutcome:
        f, _state, head, ver = self.gather(actor.user_id, req)
        reasons = drift.evaluate(f)
        outcome = drift.outcome(reasons)
        findings = []
        now = now_ts()
        body_hash = ver["body_hash"] if ver else ""
        ds = f.body.get("data_scope", {}) if f.body else {}
        rec = self.store.save_decision({
            "_id": "dec_" + uuid.uuid4().hex, "schema": 1, "outcome": outcome,
            "reasons": [r.as_dict() for r in reasons], "user_id": actor.user_id, "role": actor.role,
            "session_id": req.session_id, "device_id": req.device_id, "intent_id": req.intent_id,
            "intent_version": f.intent_version or 0, "intent_body_hash": body_hash,
            "resource": req.resource, "operation": req.operation, "purpose_code": req.purpose_code,
            "data_scope": {"classification": ds.get("classification", ""), "max_bytes": ds.get("max_bytes", 0)},
            "requested_bytes": req.requested_bytes if req.requested_bytes is not None else -1,
            "record_id": (req.record or {}).get("record_id"), "key_session_id": req.key_session_id,
            "policy_version": self.policy_version(), "issued_ts": now,
            "expires_ts": now + self.d.settings.decision_ttl_seconds, "nonce": uuid.uuid4().hex,
        })
        drift_codes = [r.code for r in reasons if r.severity is Severity.VIOLATION
                       and r.code.endswith(("DRIFT", "SCOPE_EXCEEDED", "MISMATCH", "NOT_OWNED"))]
        self._audit(AuditEvent.AUTHZ_DECISION, "success" if outcome == "PERMIT" else "rejected", actor,
                    intent_hash=body_hash, device_id=req.device_id, session_id=req.session_id,
                    resource=req.resource, operation=req.operation,
                    reason=f"decision={rec['_id']} outcome={outcome} codes={[r.code for r in reasons]}"[:480])
        if drift_codes:
            self._audit(AuditEvent.PURPOSE_DRIFT_DETECTED, "rejected", actor, intent_hash=body_hash,
                        device_id=req.device_id, session_id=req.session_id, resource=req.resource,
                        operation=req.operation, reason=f"decision={rec['_id']} {drift_codes}"[:480])
        out = DecisionOutcome(decision=rec, outcome=outcome, reasons=reasons, findings=findings)
        if outcome == "PERMIT":
            out.context_id = self._issue_context(actor, req, rec)
        return out

    def _issue_context(self, actor: Actor, req: OperationRequest, decision: dict) -> str:
        if not self.store.claim_context_slot(decision["_id"], 1):
            raise EngineError("CONTEXT_ALREADY_ISSUED", 409)
        # re-gather *after* the decision exists so the decision status/revision enters the state
        f, state, head, ver = self.gather(actor.user_id, req, decision=decision, include_risk=False)
        qkey = self.d.keys.unwrap(req.key_session_id or "", actor.user_id, for_encrypt=req.operation == "encrypt")
        ctx_id = "ctx_" + uuid.uuid4().hex
        h = self.state_hash(state)
        kid = self.d.keyring.active_id
        nonce = uuid.uuid4().bytes[:12]
        aad = self._ctx_aad(ctx_id, decision["_id"], actor.user_id, req.intent_id, decision["intent_version"],
                            req.key_session_id or "", req.operation, (req.record or {}).get("record_id") or "")
        wrapped = AESGCM(_hkdf_ctx_key(self.d.keyring, kid, ctx_id, h)).encrypt(nonce, qkey, aad)
        now = now_ts()
        self.store.save_context({
            "_id": ctx_id, "decision_id": decision["_id"], "user_id": actor.user_id, "session_id": req.session_id,
            "device_id": req.device_id, "intent_id": req.intent_id, "intent_version": decision["intent_version"],
            "resource": req.resource, "operation": req.operation, "purpose_code": req.purpose_code,
            "key_session_id": req.key_session_id, "record_id": (req.record or {}).get("record_id"),
            "created_ts": now, "expires_ts": min(now + self.d.settings.context_ttl_seconds, decision["expires_ts"]),
            "used": False, "kid": kid, "nonce": nonce, "wrapped_qkey": wrapped})
        self._audit(AuditEvent.CONTEXT_ISSUED, "success", actor, device_id=req.device_id, session_id=req.session_id,
                    resource=req.resource, operation=req.operation, reason=f"context={ctx_id} decision={decision['_id']}")
        return ctx_id

    @staticmethod
    def _ctx_aad(ctx_id, decision_id, user_id, intent_id, version, ks_id, operation, record_id) -> bytes:
        return frame(b"CIPHERQ|CTX-QKEY|v1", ctx_id.encode(), decision_id.encode(), str(user_id).encode(),
                     str(intent_id).encode(), str(version).encode(), ks_id.encode(), operation.encode(),
                     str(record_id).encode())

    def revoke_decision(self, actor: Actor, decision_id: str, reason: str) -> bool:
        d = self.store.get_decision(decision_id)
        if d is None or (d["user_id"] != actor.user_id and actor.role != "ADMIN"):
            raise EngineError("DECISION_NOT_FOUND", 404)
        ok = self.store.revoke_decision(decision_id, reason)
        self.store.invalidate_contexts_where(decision_id=decision_id)
        self._audit(AuditEvent.AUTHZ_DECISION_REVOKED, "success", actor, reason=f"decision={decision_id}: {reason[:120]}")
        return ok

    # ============================================================ context use
    def open_context(self, actor: Actor, ctx_id: str, actual: OperationRequest) -> OpenedContext:
        """Called by the protected operation with what is ACTUALLY about to happen."""
        def reject(code: str, status: int = 403, detail: str = "", drift_event: bool = False):
            self._audit(AuditEvent.CONTEXT_REJECTED, "rejected", actor, device_id=actual.device_id,
                        session_id=actual.session_id, resource=actual.resource, operation=actual.operation,
                        reason=f"context={ctx_id} {code} {detail}"[:480])
            if drift_event:
                self._audit(AuditEvent.PURPOSE_DRIFT_DETECTED, "rejected", actor, device_id=actual.device_id,
                            session_id=actual.session_id, resource=actual.resource, operation=actual.operation,
                            reason=f"context={ctx_id} {code}")
            raise EngineError(code, status, detail)

        ctx = self.store.get_context(ctx_id)
        if ctx is None or ctx["user_id"] != actor.user_id:
            reject("CONTEXT_INVALID", 403)               # same answer for "not yours" and "unknown"
        if ctx["used"]:
            if ctx.get("invalidated"):
                reject("CONTEXT_INVALIDATED", 403, "authorization changed after this context was issued")
            reject("CONTEXT_ALREADY_USED", 409)          # replay
        if ctx["expires_ts"] < now_ts():
            reject("CONTEXT_EXPIRED", 403)
        decision = self.store.get_decision(ctx["decision_id"])
        if decision is None or not self.store.decision_authentic(decision):
            reject("DECISION_INTEGRITY_FAILED", 403)
        st = self.store.decision_status(decision["_id"]) or {}
        if st.get("status") != "ACTIVE":
            reject("DECISION_REVOKED", 403)
        if decision["expires_ts"] < now_ts():
            reject("DECISION_EXPIRED", 403)
        # the actual operation must be exactly what was authorised
        bound = {"intent_id": ctx["intent_id"], "operation": ctx["operation"], "resource": ctx["resource"],
                 "purpose_code": ctx["purpose_code"], "session_id": ctx["session_id"], "device_id": ctx["device_id"]}
        got = {"intent_id": actual.intent_id, "operation": actual.operation, "resource": actual.resource,
               "purpose_code": actual.purpose_code, "session_id": actual.session_id, "device_id": actual.device_id}
        diff = sorted(k for k in bound if bound[k] != got[k])
        if diff:
            reject("CONTEXT_BINDING_MISMATCH", 403, ",".join(diff), drift_event=True)
        if (ctx.get("record_id") or None) != ((actual.record or {}).get("record_id") or None):
            reject("CONTEXT_BINDING_MISMATCH", 403, "record_id", drift_event=True)
        if (ctx.get("key_session_id") or None) != (actual.key_session_id or None):
            reject("CONTEXT_BINDING_MISMATCH", 403, "key_session_id", drift_event=True)
        actual.intent_version = ctx["intent_version"]
        # full re-evaluation against CURRENT authoritative state
        f, state, head, ver = self.gather(actor.user_id, actual, decision=decision, include_risk=True)
        reasons = drift.evaluate(f)
        bad = [r for r in reasons if r.severity in (Severity.VIOLATION, Severity.REQUIRES)]
        if bad:
            self.store.invalidate_contexts_where(_id=ctx_id)
            reject("AUTHORIZATION_CHANGED", 403, ",".join(r.code for r in bad),
                   drift_event=any(r.code.endswith(("DRIFT", "SCOPE_EXCEEDED")) for r in bad))
        # cryptographic enforcement: the key is only releasable under the CURRENT state hash
        h = self.state_hash(state)
        aad = self._ctx_aad(ctx_id, decision["_id"], actor.user_id, ctx["intent_id"], ctx["intent_version"],
                            ctx.get("key_session_id") or "", ctx["operation"], ctx.get("record_id") or "")
        try:
            qkey = AESGCM(_hkdf_ctx_key(self.d.keyring, int(ctx["kid"]), ctx_id, h)).decrypt(
                bytes(ctx["nonce"]), bytes(ctx["wrapped_qkey"]), aad)
        except InvalidTag:
            self.store.invalidate_contexts_where(_id=ctx_id)
            reject("CONTEXT_STALE", 403, "authorization state changed since the context was issued")
        # single use: exactly one caller wins
        if not self.store.consume_context(ctx_id):
            reject("CONTEXT_ALREADY_USED", 409)
        used = self.store.consume_use(ctx["intent_id"], ctx["intent_version"], int(f.body["data_scope"]["max_uses"]))
        if used is None:
            reject("INTENT_EXHAUSTED", 409)
        return OpenedContext(qkey=qkey, decision=decision, context=ctx, body=f.body, head=head)


def _ts(v: str) -> int:
    import calendar
    return calendar.timegm(time.strptime(v, "%Y-%m-%dT%H:%M:%SZ"))


def _plain(v):
    if isinstance(v, dict):
        return {str(k): _plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set, frozenset)):
        return sorted((_plain(x) for x in v), key=str)
    if isinstance(v, float):
        return str(v)
    return v


def _adapter_cid(body: dict, req: OperationRequest, username: str, now: int) -> CID:
    from datetime import datetime, timezone
    # Secure Share reuses a record already created under the approved encryption scope.
    # Keep legacy policy allow-lists compatible by evaluating the operation as encrypt;
    # the dedicated intent-integrity rules still validate the share recipient and state.
    legacy_operation = "encrypt" if req.operation == "share" else req.operation
    return CID(sender=username, receiver=username, purpose=body["purpose_code"], resource=req.resource,
               operation=legacy_operation, device_id=req.device_id, session_id=req.session_id,
               valid_from=datetime.fromtimestamp(_ts(body["valid_from"]), timezone.utc),
               valid_until=datetime.fromtimestamp(_ts(body["valid_until"]), timezone.utc),
               classification=body["data_scope"]["classification"].lower())
