"""Regression coverage for the supported 1 MiB file attachment formats."""
import base64
import io
import json
import zipfile

import pytest

from crypto import share_payload
from intent_engine.schema import IntentAttachment


OLE_HEADER = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
OLE_DOC = OLE_HEADER + "WordDocument".encode("utf-16le")
OLE_XLS = OLE_HEADER + "Workbook".encode("utf-16le")
PDF = b"%PDF-1.7\nCipherQ test file"
JPEG = b"\xff\xd8\xff\xe0" + b"jpeg-data"
PNG = b"\x89PNG\r\n\x1a\n" + b"png-data"


def office_zip(name: str) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr(name, "<document/>")
    return stream.getvalue()


@pytest.mark.parametrize(
    "filename,mime,data",
    [
        ("sample.pdf", "application/pdf", PDF),
        ("sample.jpg", "image/jpeg", JPEG),
        ("sample.jpeg", "image/jpeg", JPEG),
        ("sample.png", "image/png", PNG),
        ("sample.doc", "application/msword", OLE_DOC),
        ("sample.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
         office_zip("word/document.xml")),
        ("sample.xls", "application/vnd.ms-excel", OLE_XLS),
        ("sample.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
         office_zip("xl/workbook.xml")),
    ],
)
def test_intent_attachment_accepts_all_eight_formats(filename, mime, data):
    item = IntentAttachment.model_validate({
        "filename": filename, "content_type": mime,
        "content_base64": base64.b64encode(data).decode("ascii"),
    })
    assert item.filename == filename


def test_intent_attachment_rejects_unsupported_extension_and_content_mismatch():
    with pytest.raises(ValueError):
        IntentAttachment.model_validate({
            "filename": "notes.txt", "content_type": "text/plain",
            "content_base64": base64.b64encode(b"plain text").decode("ascii"),
        })
    with pytest.raises(ValueError):
        IntentAttachment.model_validate({
            "filename": "fake.pdf", "content_type": "application/pdf",
            "content_base64": base64.b64encode(b"not a pdf").decode("ascii"),
        })


def test_intent_attachment_rejects_more_than_one_mib():
    data = b"%PDF-" + b"x" * (1024 * 1024)
    with pytest.raises(ValueError):
        IntentAttachment.model_validate({
            "filename": "too-large.pdf", "content_type": "application/pdf",
            "content_base64": base64.b64encode(data).decode("ascii"),
        })


def test_actual_encryption_attachment_envelope_is_canonicalized_and_integrity_bound():
    data = PDF
    payload = {
        "format": "CIPHERQ_ATTACHMENT_V1", "filename": "proof.pdf",
        "mime_type": "application/pdf", "original_size": len(data),
        "data_base64": base64.b64encode(data).decode("ascii"),
    }
    rebuilt = json.loads(share_payload.validate_attachment_payload(json.dumps(payload).encode("utf-8")))
    assert rebuilt["sha256"]
    assert base64.b64decode(rebuilt["data_base64"]) == data
    assert rebuilt["original_size"] == len(data)


def test_actual_encryption_attachment_rejects_mime_mismatch_and_oversize():
    bad_mime = {
        "format": "CIPHERQ_ATTACHMENT_V1", "filename": "proof.pdf",
        "mime_type": "image/png", "original_size": len(PDF),
        "data_base64": base64.b64encode(PDF).decode("ascii"),
    }
    with pytest.raises(share_payload.SharePayloadError):
        share_payload.validate_attachment_payload(json.dumps(bad_mime).encode("utf-8"))

    too_big = b"%PDF-" + b"x" * (1024 * 1024)
    oversized = {
        "format": "CIPHERQ_ATTACHMENT_V1", "filename": "large.pdf",
        "mime_type": "application/pdf", "original_size": len(too_big),
        "data_base64": base64.b64encode(too_big).decode("ascii"),
    }
    with pytest.raises(share_payload.SharePayloadError):
        share_payload.validate_attachment_payload(json.dumps(oversized).encode("utf-8"))


def test_secure_share_file_envelope_accepts_xls_and_checks_digest():
    payload = {
        "format": "CIPHERQ_SHARE_V1", "kind": "file", "subject": "Workbook", "description": "",
        "filename": "sample.xls", "mime_type": "application/vnd.ms-excel",
        "size": len(OLE_XLS), "sha256": __import__("hashlib").sha256(OLE_XLS).hexdigest(),
        "data_base64": base64.b64encode(OLE_XLS).decode("ascii"),
    }
    rebuilt = json.loads(share_payload.validate_and_rebuild(json.dumps(payload).encode("utf-8")))
    assert rebuilt["filename"] == "sample.xls"
    assert base64.b64decode(rebuilt["data_base64"]) == OLE_XLS
