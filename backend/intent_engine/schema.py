"""Strict intent schema (v2).

Everything the client may state is an enum, a bounded string or a bounded
number; everything the server decides (owner, sender, required approvals,
policy version, status) is NOT accepted from the client.
"""
from __future__ import annotations

import re
import base64
import binascii
import zipfile
import io
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = 2

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{5,127}$")          # session / device identifiers
RESOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9:/._-]{2,127}$")
REF_RE = re.compile(r"^[A-Z]{2,8}-[0-9]{3,10}$")                     # business reference / case id
MAX_VALIDITY = timedelta(hours=24)
MAX_BYTES_CEILING = 12_582_912  # supports an 8 MiB attachment plus nested base64/JSON envelope overhead


class Operation(str, Enum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    SHARE = "share"


class Purpose(str, Enum):
    CASE_INVESTIGATION = "CASE_INVESTIGATION"
    AUDIT_REVIEW = "AUDIT_REVIEW"
    REGULATORY_REPORTING = "REGULATORY_REPORTING"
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"
    CUSTOMER_SERVICE = "CUSTOMER_SERVICE"


class Classification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"

    @property
    def rank(self) -> int:
        return ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED").index(self.value)


class EvidenceKind(str, Enum):
    CASE = "CASE"


class IntentStatus(str, Enum):
    DRAFT = "DRAFT"                    # created, not validated
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    EXHAUSTED = "EXHAUSTED"            # max_uses consumed


TERMINAL = frozenset({IntentStatus.REJECTED, IntentStatus.REVOKED, IntentStatus.EXPIRED, IntentStatus.EXHAUSTED})

# Server-side policy: approvals required per classification (client cannot set it).
REQUIRED_APPROVALS = {
    Classification.PUBLIC: 0,
    Classification.INTERNAL: 1,
    Classification.CONFIDENTIAL: 1,
    Classification.RESTRICTED: 2,
}
# Verified (authoritative) case evidence is mandatory from this classification upward.
EVIDENCE_REQUIRED_FROM = Classification.INTERNAL
# Fresh step-up (face-descriptor challenge) is mandatory from this classification upward.
STEP_UP_REQUIRED_FROM = Classification.RESTRICTED


class EvidenceRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: EvidenceKind
    ref: Annotated[str, Field(pattern=REF_RE.pattern, max_length=32)]


class DataScope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    classification: Classification
    max_bytes: Annotated[int, Field(ge=1, le=MAX_BYTES_CEILING)]
    max_uses: Annotated[int, Field(ge=1, le=100)] = 1


class IntentAttachment(BaseModel):
    """Small, optional evidence attachment stored inside the encrypted, integrity-sealed intent version."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    filename: Annotated[str, Field(min_length=1, max_length=160)]
    content_type: Annotated[str, Field(min_length=1, max_length=100)]
    content_base64: Annotated[str, Field(min_length=1, max_length=1_398_104)]

    @field_validator("filename")
    @classmethod
    def _safe_filename(cls, value: str) -> str:
        value = value.strip()
        if (not value or value in {".", ".."} or "/" in value or "\\" in value
                or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            raise ValueError("invalid attachment filename")
        return value

    @field_validator("content_type")
    @classmethod
    def _safe_content_type(cls, value: str) -> str:
        if value not in {
            "application/pdf", "image/jpeg", "image/png", "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.ms-excel",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        }:
            raise ValueError("unsupported attachment type")
        return value

    @field_validator("content_base64")
    @classmethod
    def _valid_content(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("attachment is not valid base64") from exc
        if not raw or len(raw) > 1024 * 1024:
            raise ValueError("attachment must be 1 byte to 1 MB")
        return value

    @model_validator(mode="after")
    def _content_matches_name_and_type(self) -> "IntentAttachment":
        raw = base64.b64decode(self.content_base64, validate=True)
        ext = self.filename.rsplit(".", 1)[-1].lower() if "." in self.filename else ""
        def office_zip_has(required: set[str]) -> bool:
            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    names = set(archive.namelist())
                    return required.issubset(names)
            except (OSError, zipfile.BadZipFile):
                return False

        ole = raw.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
        word_stream = b"WordDocument" in raw or "WordDocument".encode("utf-16le") in raw
        excel_stream = any(token in raw for token in (
            b"Workbook", b"Book", "Workbook".encode("utf-16le"), "Book".encode("utf-16le")
        ))
        expected = {
            "pdf": ("application/pdf", raw.startswith(b"%PDF-")),
            "jpg": ("image/jpeg", raw.startswith(b"\xff\xd8\xff")),
            "jpeg": ("image/jpeg", raw.startswith(b"\xff\xd8\xff")),
            "png": ("image/png", raw.startswith(b"\x89PNG\r\n\x1a\n")),
            "doc": ("application/msword", ole and word_stream),
            "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                     office_zip_has({"[Content_Types].xml", "word/document.xml"})),
            "xls": ("application/vnd.ms-excel", ole and excel_stream),
            "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                     office_zip_has({"[Content_Types].xml", "xl/workbook.xml"})),
        }
        valid = expected.get(ext)
        if valid is None or self.content_type != valid[0] or not valid[1]:
            raise ValueError("attachment filename, content type, and file signature must agree")
        return self


def _valid_utf8_text(raw: bytes) -> bool:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return all(char in "\t\n\r" or (char.isprintable() and ord(char) != 127) for char in text)


def _docx_zip(raw: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names = set(archive.namelist())
            return "[Content_Types].xml" in names and "word/document.xml" in names
    except (OSError, zipfile.BadZipFile):
        return False



class IntentRequest(BaseModel):
    """What a client may submit to create an intent or a new version."""

    model_config = ConfigDict(extra="forbid")

    purpose_code: Purpose
    purpose_statement: Annotated[str, Field(min_length=10, max_length=500)]
    business_reference: Annotated[str, Field(pattern=REF_RE.pattern, max_length=32)]
    resource: Annotated[str, Field(pattern=RESOURCE_RE.pattern, max_length=128)]
    recipient_user_id: Annotated[int, Field(gt=0)] | None = None
    operations: Annotated[list[Operation], Field(min_length=1, max_length=3)]
    data_scope: DataScope
    session_id: Annotated[str, Field(pattern=ID_RE.pattern, max_length=128)]
    device_id: Annotated[str, Field(pattern=ID_RE.pattern, max_length=128)]
    valid_from: datetime
    valid_until: datetime
    evidence_refs: Annotated[list[EvidenceRef], Field(max_length=5)] = Field(default_factory=list)
    attachment: Optional[IntentAttachment] = None
    reason: Annotated[str, Field(min_length=3, max_length=200)] = "initial creation"

    @field_validator("valid_from", "valid_until")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_validator("purpose_statement")
    @classmethod
    def _printable(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 10 or any(ord(char) < 32 for char in value):
            raise ValueError(
                "purpose_statement must be 10-500 printable characters"
            )
        return value

    @model_validator(mode="after")
    def _semantics(self) -> "IntentRequest":
        if len(set(self.operations)) != len(self.operations):
            raise ValueError("operations must be unique")
        if Operation.SHARE in self.operations and Operation.ENCRYPT not in self.operations:
            raise ValueError("share operation requires encrypt permission")

        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")

        if self.valid_until - self.valid_from > MAX_VALIDITY:
            raise ValueError("validity window may not exceed 24 hours")

        if len({(item.kind, item.ref) for item in self.evidence_refs}) != len(
            self.evidence_refs
        ):
            raise ValueError("duplicate evidence references")

        if self.attachment:
            size = len(base64.b64decode(self.attachment.content_base64, validate=True))
            if size > self.data_scope.max_bytes:
                raise ValueError("attachment exceeds the declared data scope")

        return self



def body_from_request(req: IntentRequest, *, intent_id: int, version: int, owner_user_id: int,
                      sender: str, required_approvals: int) -> dict:
    """Canonicalisable (typed, float-free) version body. Server-set fields are explicit."""
    from security.canonical import iso_utc
    return {
        "schema_version": SCHEMA_VERSION,
        "intent_id": intent_id,
        "version": version,
        "owner_user_id": owner_user_id,
        "sender": sender,
        "purpose_code": req.purpose_code.value,
        "purpose_statement": req.purpose_statement,
        "business_reference": req.business_reference,
        "resource": req.resource,
        "recipient_user_id": req.recipient_user_id,
        "operations": sorted(o.value for o in req.operations),
        "data_scope": {"classification": req.data_scope.classification.value,
                       "max_bytes": req.data_scope.max_bytes, "max_uses": req.data_scope.max_uses},
        "session_id": req.session_id,
        "device_id": req.device_id,
        "valid_from": iso_utc(req.valid_from),
        "valid_until": iso_utc(req.valid_until),
        "evidence_refs": sorted([{"kind": e.kind.value, "ref": e.ref} for e in req.evidence_refs],
                                key=lambda e: (e["kind"], e["ref"])),
        "attachment": req.attachment.model_dump() if req.attachment else None,
        "required_approvals": required_approvals,
    }
