"""Append-only hash-chained and optionally HMAC-authenticated audit events.

The reference implementation is thread-safe inside one broker process and
refuses to append to a chain that no longer verifies. A production deployment
should additionally enforce a single writer with a platform-native service or
cross-process lock and anchor audit heads outside the broker host.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
from pathlib import Path
from typing import Any, Protocol

from .errors import IntegrityError
from .util import canonical_json, utc_epoch


class Signer(Protocol):
    def sign(self, payload: Any) -> str: ...
    def verify(self, payload: Any, signature: str) -> None: ...


def _open_regular_no_follow(path: Path, flags: int, mode: int = 0o600) -> int:
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, mode)
    except OSError as exc:
        raise IntegrityError(f"cannot safely open audit log {path}: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise IntegrityError(f"audit log must be a regular file: {path}")
        return fd
    except Exception:
        os.close(fd)
        raise


class AuditLog:
    ZERO_HASH = "0" * 64

    def __init__(self, path: Path, *, signer: Signer | None = None) -> None:
        self.path = path
        self.signer = signer
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            parent_info = os.lstat(self.path.parent)
        except OSError as exc:
            raise IntegrityError(f"cannot inspect audit directory: {exc}") from exc
        if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
            raise IntegrityError("audit directory must be a real directory")
        if os.path.lexists(self.path):
            try:
                info = os.lstat(self.path)
            except OSError as exc:
                raise IntegrityError(f"cannot inspect audit log: {exc}") from exc
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise IntegrityError(f"audit log must be a regular file: {self.path}")
        self._lock = threading.RLock()
        # Never start a broker on top of a pre-existing corrupt chain.
        self.verify()

    def append(self, event_type: str, payload: dict[str, Any]) -> str:
        if not isinstance(event_type, str) or not event_type.strip():
            raise IntegrityError("audit event type must be a non-empty string")
        with self._lock:
            _, previous = self._verify_unlocked()
            body = {
                "timestamp": utc_epoch(),
                "event_type": event_type,
                "payload": payload,
                "previous_hash": previous,
            }
            event_hash = hashlib.sha256(
                previous.encode("ascii") + canonical_json(body)
            ).hexdigest()
            row = {**body, "event_hash": event_hash}
            if self.signer is not None:
                row["event_signature"] = self.signer.sign(
                    {"kind": "audit_event", "body": body, "event_hash": event_hash}
                )
            fd = _open_regular_no_follow(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            with os.fdopen(fd, "ab") as handle:
                handle.write(canonical_json(row))
                handle.write(b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            return event_hash

    def verify(self) -> int:
        with self._lock:
            count, _ = self._verify_unlocked()
            return count

    def _verify_unlocked(self) -> tuple[int, str]:
        previous = self.ZERO_HASH
        count = 0
        if not os.path.lexists(self.path):
            return count, previous
        fd = _open_regular_no_follow(self.path, os.O_RDONLY)
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise IntegrityError(
                        f"audit line {line_number} is invalid JSON: {exc}"
                    ) from exc
                if not isinstance(parsed, dict):
                    raise IntegrityError(
                        f"audit line {line_number} must contain a JSON object"
                    )
                row = dict(parsed)
                claimed_signature = row.pop("event_signature", None)
                claimed_hash = str(row.pop("event_hash", ""))
                if row.get("previous_hash") != previous:
                    raise IntegrityError(
                        f"audit chain predecessor mismatch at line {line_number}"
                    )
                expected_hash = hashlib.sha256(
                    previous.encode("ascii") + canonical_json(row)
                ).hexdigest()
                if claimed_hash != expected_hash:
                    raise IntegrityError(f"audit hash mismatch at line {line_number}")
                if self.signer is not None:
                    if not claimed_signature:
                        raise IntegrityError(
                            f"audit signature missing at line {line_number}"
                        )
                    self.signer.verify(
                        {
                            "kind": "audit_event",
                            "body": row,
                            "event_hash": claimed_hash,
                        },
                        str(claimed_signature),
                    )
                previous = claimed_hash
                count += 1
        return count, previous
