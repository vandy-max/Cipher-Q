"""Evidence validation.

Trust classes (never conflated):

* ``USER_DECLARED``     -- the requester's own statement (purpose text, a case id they typed).
                           Never sufficient on its own for classified data.
* ``VERIFIED_FACT``     -- confirmed by an authoritative record in an evidence provider.
* ``SYSTEM_GENERATED``  -- derived by this backend from its own state (session, device, monitoring).
* ``MISSING``           -- the reference does not resolve to any authoritative record.
* ``STALE``             -- the authoritative record exists but has not been refreshed within the window.

The only provider shipped is :class:`LocalEvidenceProvider`: a documented, *local*,
administrator-maintained table of case records (collection ``evidence_cases``).  It is a
stand-in for a real case-management system and makes no claim to be an external bank or
regulator integration.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Protocol

from pymongo.errors import PyMongoError

from .schema import Classification, EvidenceRef

EVIDENCE_COLLECTION = "evidence_cases"
EVIDENCE_MAX_AGE = timedelta(days=30)
CLASSIFICATIONS = frozenset({"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"})
CASE_STATUSES = frozenset({"OPEN", "CLOSED"})
DEVELOPMENT_FIXTURE_MARKER = "cipherq-development-case-v1"


class EvidenceProviderUnavailable(RuntimeError):
    """The authoritative case source could not be queried."""


class InvalidEvidenceRecord(ValueError):
    """The authoritative source returned a malformed case record."""


class Trust(str, Enum):
    USER_DECLARED = "USER_DECLARED"
    VERIFIED_FACT = "VERIFIED_FACT"
    SYSTEM_GENERATED = "SYSTEM_GENERATED"
    MISSING = "MISSING"
    STALE = "STALE"


@dataclass(frozen=True)
class CaseRecord:
    ref: str
    status: str                         # OPEN | CLOSED
    title: str
    classification_cap: str
    allowed_resources: tuple[str, ...]
    assigned_user_ids: tuple[int, ...]
    updated_at: datetime
    revision: int


class EvidenceProvider(Protocol):
    name: str

    def get_case(self, ref: str) -> CaseRecord | None: ...


class LocalEvidenceProvider:
    name = "local-case-table"

    def __init__(self, db) -> None:
        self._col = db[EVIDENCE_COLLECTION]

    @staticmethod
    def _parse_case(d: dict) -> CaseRecord:
        if d is None:
            raise InvalidEvidenceRecord("case record is missing")
        status = d.get("status")
        title = d.get("title")
        classification_cap = d.get("classification_cap")
        allowed_resources = d.get("allowed_resources")
        assigned_user_ids = d.get("assigned_user_ids")
        ts = d.get("updated_at")
        revision = d.get("revision")
        if (
            not isinstance(status, str)
            or status not in CASE_STATUSES
            or not isinstance(title, str)
            or len(title.strip()) < 3
            or not isinstance(classification_cap, str)
            or classification_cap not in CLASSIFICATIONS
            or not isinstance(allowed_resources, list)
            or any(not isinstance(resource, str) for resource in allowed_resources)
            or not isinstance(assigned_user_ids, list)
            or any(type(user_id) is not int or user_id < 1 for user_id in assigned_user_ids)
            or not isinstance(ts, datetime)
            or type(revision) is not int
            or revision < 1
        ):
            raise InvalidEvidenceRecord("case record is missing required trusted fields")
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return CaseRecord(ref=d["_id"], status=status, title=title, classification_cap=classification_cap,
                          allowed_resources=tuple(allowed_resources), assigned_user_ids=tuple(assigned_user_ids),
                          updated_at=ts, revision=revision)

    def get_case(self, ref: str) -> CaseRecord | None:
        try:
            d = self._col.find_one({"_id": ref})
        except PyMongoError as exc:
            raise EvidenceProviderUnavailable("case evidence provider is unavailable") from exc
        return None if d is None else self._parse_case(d)

    def list_cases(self, *, limit: int = 50, offset: int = 0) -> list[CaseRecord]:
        """Return a bounded administrator view of recently updated local cases."""
        try:
            docs = self._col.find({}).sort("updated_at", -1).skip(offset).limit(limit + 1)
            return [self._parse_case(doc) for doc in docs]
        except PyMongoError as exc:
            raise EvidenceProviderUnavailable("case evidence provider is unavailable") from exc

    # administrative maintenance ---------------------------------------------------
    def upsert_case(self, ref: str, *, title: str, classification_cap: str, allowed_resources: list[str],
                    assigned_user_ids: list[int], status: str = "OPEN",
                    fixture_marker: str | None = None) -> CaseRecord:
        now = datetime.now(timezone.utc)
        cur = self._col.find_one({"_id": ref})
        rev = int(cur["revision"]) + 1 if cur else 1
        doc = {"_id": ref, "status": status, "title": title, "classification_cap": classification_cap,
               "allowed_resources": sorted(set(allowed_resources)),
               "assigned_user_ids": sorted(set(int(u) for u in assigned_user_ids)),
               "updated_at": now, "revision": rev}
        if fixture_marker is not None:
            doc["fixture_marker"] = fixture_marker
        if cur:
            self._col.replace_one({"_id": ref}, doc)
        else:
            self._col.insert_one(doc)
        return self.get_case(ref)  # type: ignore[return-value]

    def create_case(self, ref: str, *, title: str, classification_cap: str, allowed_resources: list[str],
                    assigned_user_ids: list[int], fixture_marker: str | None = None) -> CaseRecord:
        """Insert a new case without ever replacing an existing authoritative record."""
        doc = {"_id": ref, "status": "OPEN", "title": title, "classification_cap": classification_cap,
               "allowed_resources": sorted(set(allowed_resources)),
               "assigned_user_ids": sorted(set(assigned_user_ids)),
               "updated_at": datetime.now(timezone.utc), "revision": 1}
        if fixture_marker is not None:
            doc["fixture_marker"] = fixture_marker
        self._col.insert_one(doc)
        return self.get_case(ref)  # type: ignore[return-value]


@dataclass(frozen=True)
class EvidenceFinding:
    ref: str
    kind: str
    trust: Trust
    ok: bool                      # does this evidence support the requested access for THIS user/resource/classification?
    code: str                     # machine-readable
    detail: str
    case_status: str | None = None
    case_revision: int | None = None

    def as_dict(self) -> dict:
        return {"ref": self.ref, "kind": self.kind, "trust": self.trust.value, "ok": self.ok,
                "code": self.code, "detail": self.detail, "case_status": self.case_status,
                "case_revision": self.case_revision}


class EvidenceValidator:
    def __init__(self, provider: EvidenceProvider, now_fn=lambda: datetime.now(timezone.utc)) -> None:
        self._provider = provider
        self._now = now_fn

    def validate(self, refs: list[EvidenceRef] | list[dict], *, user_id: int, resource: str,
                 classification: Classification, business_reference: str) -> list[EvidenceFinding]:
        findings: list[EvidenceFinding] = []
        norm = [(r.kind.value, r.ref) if isinstance(r, EvidenceRef) else (r["kind"], r["ref"]) for r in refs]
        if (("CASE", business_reference)) not in norm:
            # The business reference the requester typed must itself be backed by evidence.
            findings.append(EvidenceFinding(business_reference, "CASE", Trust.USER_DECLARED, False,
                                            "REFERENCE_NOT_EVIDENCED",
                                            "business_reference is only declared by the user; no evidence ref supports it"))
        for kind, ref in norm:
            findings.append(self._check_case(ref, kind, user_id, resource, classification, business_reference))
        return findings

    def _check_case(self, ref, kind, user_id, resource, classification, business_reference) -> EvidenceFinding:
        try:
            case = self._provider.get_case(ref)
        except (EvidenceProviderUnavailable, PyMongoError):
            return EvidenceFinding(ref, kind, Trust.MISSING, False, "EVIDENCE_PROVIDER_UNAVAILABLE",
                                   "the authoritative case evidence source is unavailable")
        except InvalidEvidenceRecord:
            return EvidenceFinding(ref, kind, Trust.MISSING, False, "EVIDENCE_INVALID",
                                   "the authoritative case record is missing required trusted fields")
        if case is None:
            return EvidenceFinding(ref, kind, Trust.MISSING, False, "CASE_NOT_FOUND",
                                   "no authoritative record for this reference")
        base = dict(ref=ref, kind=kind, case_status=case.status, case_revision=case.revision)
        if case.status != "OPEN":
            return EvidenceFinding(trust=Trust.VERIFIED_FACT, ok=False, code="CASE_CLOSED",
                                   detail="the supporting case is not open", **base)
        if self._now() - case.updated_at > EVIDENCE_MAX_AGE:
            return EvidenceFinding(trust=Trust.STALE, ok=False, code="CASE_STALE",
                                   detail="the case record has not been refreshed recently", **base)
        if user_id not in case.assigned_user_ids:
            return EvidenceFinding(trust=Trust.VERIFIED_FACT, ok=False, code="USER_NOT_ASSIGNED",
                                   detail="the requester is not assigned to this case", **base)
        if resource not in case.allowed_resources:
            return EvidenceFinding(trust=Trust.VERIFIED_FACT, ok=False, code="RESOURCE_NOT_IN_CASE_SCOPE",
                                   detail="the resource is outside the case's authorised scope", **base)
        if Classification(case.classification_cap).rank < classification.rank:
            return EvidenceFinding(trust=Trust.VERIFIED_FACT, ok=False, code="CLASSIFICATION_ABOVE_CASE_CAP",
                                   detail="requested classification exceeds the case's cap", **base)
        if ref != business_reference:
            return EvidenceFinding(trust=Trust.VERIFIED_FACT, ok=True, code="SUPPORTING_CASE_OK",
                                   detail="supporting case verified (different from the declared business reference)", **base)
        return EvidenceFinding(trust=Trust.VERIFIED_FACT, ok=True, code="CASE_VERIFIED",
                               detail="case exists, is open, requester is assigned, resource in scope", **base)


def evidence_supports(findings: list[EvidenceFinding], classification: Classification,
                      required_from: Classification, business_reference: str) -> tuple[bool, str]:
    """Does the evidence set satisfy the policy for this classification?"""
    if classification.rank < required_from.rank:
        return True, "evidence not required for this classification"
    if not any(f.ok and f.trust is Trust.VERIFIED_FACT and f.ref == business_reference for f in findings):
        codes = sorted({f.code for f in findings}) or ["NO_EVIDENCE"]
        return False, "no verified evidence supports this access: " + ",".join(codes)
    # every supplied reference must be sound: a closed/unassigned case cannot be ignored
    bad = [f for f in findings if not f.ok and f.trust is not Trust.USER_DECLARED]
    if bad:
        return False, "evidence problem: " + ",".join(sorted({f.code for f in bad}))
    return True, "verified evidence present"
