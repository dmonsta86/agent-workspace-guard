"""HMAC signing for plans, transactions, approvals, and commit records."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import stat
from pathlib import Path
from typing import Any

from .errors import IntegrityError
from .util import canonical_json


class StateSigner:
    def __init__(self, key_path: Path) -> None:
        self.key_path = key_path
        self.key = self._load_or_create_key(key_path)

    @staticmethod
    def _load_or_create_key(path: Path) -> bytes:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            try:
                info = os.lstat(path)
            except OSError as exc:
                raise IntegrityError(f"cannot inspect broker signing key: {path}: {exc}") from exc
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise IntegrityError(f"broker signing key must be a regular file: {path}")
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                read_fd = os.open(path, flags)
            except OSError as exc:
                raise IntegrityError(f"cannot safely open broker signing key: {path}: {exc}") from exc
            with os.fdopen(read_fd, "rb") as handle:
                key = handle.read(33)
            if len(key) != 32:
                raise IntegrityError(f"invalid broker signing key length: {path}")
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return key
        key = os.urandom(32)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(key)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            raise
        return key

    def sign(self, payload: Any) -> str:
        raw = hmac.new(self.key, canonical_json(payload), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    def verify(self, payload: Any, signature: str) -> None:
        expected = self.sign(payload)
        if not hmac.compare_digest(expected, signature):
            raise IntegrityError("signed broker state failed integrity verification")
