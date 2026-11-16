"""
Strict canonical encoding used for every value that enters a key derivation,
an AEAD associated-data string, a MAC or a signature.

Why not "just json.dumps"?  Ambiguity.  The v17 code joined fields with ``|``
(so ``device_id="a|b"`` could shift bytes between fields) and relied on
``json.dumps`` of arbitrary Python objects (floats, datetimes, NaN, key order,
non-NFC unicode).  This module:

* accepts ONLY ``dict[str, ...]``, ``list``, ``str``, ``int``, ``bool``, ``None``;
  floats / NaN / bytes / datetimes raise ``CanonicalizationError`` (callers
  convert timestamps with :func:`iso_utc` and floats to integers first);
* NFC-normalises every string and rejects lone surrogates;
* emits sorted keys, no whitespace, ASCII-only JSON (RFC 8785-compatible for
  this restricted type set);
* offers :func:`frame` -- unambiguous length-prefixed concatenation for HKDF
  ``info`` / AAD composition, so a separator inside a value cannot shift
  boundaries.
"""
from __future__ import annotations

import hashlib
import json
import struct
import unicodedata
from datetime import datetime, timezone
from typing import Any

MAX_DEPTH = 8


class CanonicalizationError(ValueError):
    pass


def iso_utc(value: datetime) -> str:
    """UTC, whole seconds, ``Z`` suffix. Naive datetimes are treated as UTC."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _norm(value: Any, depth: int) -> Any:
    if depth > MAX_DEPTH:
        raise CanonicalizationError("structure too deep")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CanonicalizationError("string is not valid unicode") from exc
        return unicodedata.normalize("NFC", value)
    if isinstance(value, (list, tuple)):
        return [_norm(v, depth + 1) for v in value]
    if isinstance(value, (set, frozenset)):
        raise CanonicalizationError("sets are not canonicalizable; sort into a list first")
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalizationError("object keys must be strings")
            nk = unicodedata.normalize("NFC", k)
            if nk in out:
                raise CanonicalizationError("duplicate key after normalisation")
            out[nk] = _norm(v, depth + 1)
        return out
    raise CanonicalizationError(f"type {type(value).__name__} is not canonicalizable")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(_norm(value, 0), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def digest(tag: str, value: Any) -> str:
    """Domain-separated SHA-256 hex of the canonical encoding."""
    return hashlib.sha256(frame(tag.encode("utf-8"), canonical_bytes(value))).hexdigest()


def frame(*parts: bytes) -> bytes:
    """Length-prefixed concatenation: ``len(4, big-endian) || part`` for each part."""
    out = bytearray()
    for p in parts:
        if not isinstance(p, (bytes, bytearray)):
            raise CanonicalizationError("frame() takes bytes")
        out += struct.pack(">I", len(p)) + bytes(p)
    return bytes(out)
