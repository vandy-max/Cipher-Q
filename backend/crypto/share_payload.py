"""Server-side validation of Secure Sharing payloads (text message or attachment envelope).

The sharing UI wraps what the sender wants to deliver in a ``CIPHERQ_SHARE_V1`` JSON envelope. That envelope is
what gets encrypted (so subject, description, filename and content are all confidential). Before encryption the
server re-validates it and rebuilds it from sanitised fields: a client can never persist an unvalidated filename,
a client-asserted MIME type, a lying size/digest or a file whose content does not match its declared type.
The ordinary text-encryption payload is unchanged. The ordinary file-encryption workflow uses a separate
``CIPHERQ_ATTACHMENT_V1`` envelope which is validated by the same file-content rules.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import io
import zipfile
import re
import unicodedata

FORMAT = "CIPHERQ_SHARE_V1"
MAX_SUBJECT = 120
MAX_DESCRIPTION = 500
MAX_TEXT_CHARS = 200_000
MAX_FILENAME = 120
MAX_FILE_BYTES = 1024 * 1024

# Exactly the formats approved for CipherQ Secure Share.
ALLOWED_TYPES = {
    "pdf": "application/pdf",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xls": "application/vnd.ms-excel",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
}
_CTRL = re.compile(r"[\x00-\x1f\x7f​-‏‪-‮⁦-⁩]")


class SharePayloadError(ValueError):
    """Raised with a client-safe message; never includes payload content."""


def is_share_payload(pt: bytes) -> bool:
    head = pt[:200].lstrip()
    return head.startswith(b"{") and FORMAT.encode() in pt[:400]


def sanitize_filename(name: object) -> str:
    if not isinstance(name, str):
        raise SharePayloadError("filename is required")
    name = unicodedata.normalize("NFKC", name).replace("\\", "/").split("/")[-1]
    name = _CTRL.sub("", name).strip().strip(".")
    if not name or "." not in name:
        raise SharePayloadError("filename must have a supported extension")
    stem, _, ext = name.rpartition(".")
    stem = re.sub(r"[^\w .()\-\[\]]", "_", stem, flags=re.UNICODE).strip(" .") or "file"
    ext = ext.lower()
    if ext not in ALLOWED_TYPES:
        raise SharePayloadError("file type is not supported for sharing")
    if len(stem) + len(ext) + 1 > MAX_FILENAME:
        stem = stem[: MAX_FILENAME - len(ext) - 1]
    return f"{stem}.{ext}"


def _content_matches(ext: str, data: bytes) -> bool:
    if ext == "pdf":
        return data.startswith(b"%PDF-")
    if ext in {"doc", "xls"}:
        if not data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return False
        if ext == "doc":
            return b"WordDocument" in data or "WordDocument".encode("utf-16le") in data
        return any(token in data for token in (
            b"Workbook", b"Book", "Workbook".encode("utf-16le"), "Book".encode("utf-16le")
        ))
    if ext in {"docx", "xlsx"}:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = set(archive.namelist())
                required = {"[Content_Types].xml", "word/document.xml"} if ext == "docx" else {
                    "[Content_Types].xml", "xl/workbook.xml"
                }
                return required.issubset(names)
        except (OSError, zipfile.BadZipFile):
            return False
    if ext == "png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in {"jpg", "jpeg"}:
        return data.startswith(b"\xff\xd8\xff")
    return False


def _validate_file(filename: object, data: bytes, mime: object) -> tuple[str, str, str]:
    safe_name = sanitize_filename(filename)
    ext = safe_name.rsplit(".", 1)[1]
    expected_mime = ALLOWED_TYPES[ext]
    if mime != expected_mime or not data or len(data) > MAX_FILE_BYTES:
        raise SharePayloadError("attachment must be a supported file no larger than 1 MB")
    if not _content_matches(ext, data):
        raise SharePayloadError("file content does not match its extension")
    return safe_name, expected_mime, hashlib.sha256(data).hexdigest()


def is_attachment_payload(pt: bytes) -> bool:
    head = pt[:200].lstrip()
    return head.startswith(b"{") and b"CIPHERQ_ATTACHMENT_V1" in pt[:400]


def validate_attachment_payload(pt: bytes) -> bytes:
    """Validate the actual file envelope before the record-encryption path seals it."""
    try:
        doc = json.loads(pt.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SharePayloadError("attachment payload is not valid") from exc
    if not isinstance(doc, dict) or doc.get("format") != "CIPHERQ_ATTACHMENT_V1":
        raise SharePayloadError("attachment payload is not valid")
    try:
        data = base64.b64decode(doc.get("data_base64") or "", validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise SharePayloadError("file content is not valid base64") from exc
    filename, mime, digest = _validate_file(doc.get("filename"), data, doc.get("mime_type"))
    if doc.get("original_size") != len(data) or doc.get("sha256") not in (None, digest):
        raise SharePayloadError("file size or integrity check failed")
    rebuilt = {"format": "CIPHERQ_ATTACHMENT_V1", "filename": filename, "mime_type": mime,
               "original_size": len(data), "sha256": digest,
               "data_base64": base64.b64encode(data).decode("ascii")}
    return json.dumps(rebuilt, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _clean_text(value: object, limit: int, field: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise SharePayloadError(f"{field} must be text")
    if len(value) > limit:
        raise SharePayloadError(f"{field} is too long")
    return value


def validate_and_rebuild(pt: bytes) -> bytes:
    """Validate a CIPHERQ_SHARE_V1 envelope and return the canonical, sanitised envelope bytes."""
    try:
        doc = json.loads(pt.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SharePayloadError("share payload is not valid") from exc
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise SharePayloadError("share payload is not valid")
    kind = doc.get("kind")
    out: dict = {"format": FORMAT, "kind": kind,
                 "subject": _clean_text(doc.get("subject"), MAX_SUBJECT, "subject").strip(),
                 "description": _clean_text(doc.get("description"), MAX_DESCRIPTION, "description").strip()}
    if kind == "text":
        text = _clean_text(doc.get("text"), MAX_TEXT_CHARS, "message")
        if not text.strip():
            raise SharePayloadError("message is empty")
        out["text"] = text
    elif kind == "file":
        filename = sanitize_filename(doc.get("filename"))
        try:
            data = base64.b64decode(doc.get("data_base64") or "", validate=True)
        except (binascii.Error, ValueError, TypeError) as exc:
            raise SharePayloadError("file content is not valid base64") from exc
        filename, mime, digest = _validate_file(
            filename, data, doc.get("mime_type") or ALLOWED_TYPES.get(filename.rsplit(".", 1)[1].lower(), "")
        )
        if doc.get("sha256") not in (None, digest) or doc.get("size") not in (None, len(data)):
            raise SharePayloadError("file integrity check failed")
        out.update({"filename": filename, "mime_type": mime, "size": len(data), "sha256": digest,
                    "data_base64": base64.b64encode(data).decode()})
        if doc.get("text") is not None:
            out["text"] = _clean_text(doc.get("text"), MAX_TEXT_CHARS, "message")
    else:
        raise SharePayloadError("kind must be text or file")
    return json.dumps(out, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
