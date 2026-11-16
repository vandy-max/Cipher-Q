from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Protocol, Sequence

from security.keyring import Keyring

from .hash_chain import (GENESIS_HASH, AuditEntry, ChainVerificationResult, build_entry, head_mac,
                         verify_chain)

log = logging.getLogger("cipherq.audit")
_append_lock = threading.Lock()


class AuditSinkError(RuntimeError):
    pass


class AuditLogRepository(Protocol):
    def last_entry(self) -> AuditEntry | None: ...
    def insert(self, entry: AuditEntry) -> bool: ...          # False on duplicate seq
    def all_entries(self) -> Sequence[AuditEntry]: ...
    def get_head(self) -> dict | None: ...
    def set_head(self, head: dict) -> None: ...


class InMemoryAuditLogRepository:
    """Reference/test implementation only."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._head: dict | None = None

    def last_entry(self):
        return self._entries[-1] if self._entries else None

    def insert(self, entry: AuditEntry) -> bool:
        if any(e.seq == entry.seq for e in self._entries):
            return False
        self._entries.append(entry)
        return True

    def all_entries(self):
        return tuple(self._entries)

    def get_head(self):
        return self._head

    def set_head(self, head: dict) -> None:
        if self._head is None or head["seq"] > self._head["seq"]:
            self._head = head


class FileSink:
    """Append-only JSON-lines secondary sink (a second copy of ``seq`` + ``mac``, no payload).

    Opened O_APPEND with mode 0600.  This only helps if the file lives somewhere a database/API
    attacker cannot rewrite (separate host, WORM storage, log shipper).  On the same disk it is
    one more thing to delete."""

    def __init__(self, path: str) -> None:
        self.path = path

    def append(self, seq: int, mac: str, ts: str) -> None:
        line = json.dumps({"seq": seq, "mac": mac, "ts": ts}, separators=(",", ":")) + "\n"
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line.encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    def tail(self) -> dict | None:
        try:
            with open(self.path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - 4096))
                lines = [x for x in fh.read().decode("utf-8", "replace").splitlines() if x.strip()]
            return json.loads(lines[-1]) if lines else None
        except FileNotFoundError:
            return None
        except (ValueError, OSError):
            return {"seq": 10**12, "mac": "corrupt"}     # unreadable sink => verification fails closed


class AuditLogService:
    def __init__(self, repository: AuditLogRepository, keyring: Keyring | None = None,
                 sink: FileSink | None = None, sink_fail_closed: bool = False) -> None:
        if keyring is None:
            from security.keyring import get_keyring
            keyring = get_keyring()
        self._repository, self._kr, self._sink, self._sink_fail_closed = repository, keyring, sink, sink_fail_closed

    def record(self, action: str, result: str, user_id: int | None = None, intent_hash: str | None = None,
               timestamp: datetime | None = None, session_id: str | None = None, device_id: str | None = None,
               resource: str | None = None, operation: str | None = None, risk: str | None = None,
               reason: str | None = None) -> AuditEntry:
        # The caller-supplied timestamp is deliberately ignored: audit time is server time.
        entry = None
        with _append_lock:                                    # serialises writers inside this process
            for _ in range(64):                               # unique seq makes cross-process races retry
                ts = datetime.now(timezone.utc)
                ts = ts.replace(microsecond=(ts.microsecond // 1000) * 1000)
                last = self._repository.last_entry()
                if last is not None and ts < last.timestamp:
                    ts = last.timestamp                       # keep timestamps monotonic across clock steps
                seq = (last.seq + 1) if last else 1
                prev = last.current_log_hash if last else GENESIS_HASH
                cand = build_entry(self._kr, seq, prev, ts, user_id, action, intent_hash, result, session_id,
                                   device_id, resource, operation, risk, reason)
                if self._repository.insert(cand):
                    entry = cand
                    break
            if entry is None:
                raise RuntimeError("audit append failed after retries")
            self._repository.set_head({"seq": entry.seq, "mac": entry.current_log_hash, "kid": entry.kid,
                                       "head_mac": head_mac(self._kr, entry.kid, entry.seq, entry.current_log_hash)})
            if self._sink is not None:
                try:
                    self._sink.append(entry.seq, entry.current_log_hash, entry.timestamp.isoformat())
                except OSError as exc:
                    log.error("audit secondary sink write failed: %s", exc)
                    if self._sink_fail_closed:
                        raise AuditSinkError("audit secondary sink unavailable") from exc
        return entry

    def verify_integrity(self) -> ChainVerificationResult:
        return verify_chain(self._kr, self._repository.all_entries(), self._repository.get_head(),
                            self._sink.tail() if self._sink else None, sink_configured=self._sink is not None)

    def list_entries(self) -> Sequence[AuditEntry]:
        return self._repository.all_entries()
