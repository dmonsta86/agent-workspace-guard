"""Small, security-sensitive utility functions.

The reference implementation keeps these helpers deliberately boring and
stdlib-only. Production integrations should replace path-based mutation with
platform-native handle-relative APIs while preserving the same invariants.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
import time
from pathlib import Path, PureWindowsPath
from typing import Any

from .errors import GuardError, UnsafePath


_OBJECT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}_[A-Za-z0-9_-]{16,128}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def utc_epoch() -> int:
    return int(time.time())


def random_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(18)}"


def validate_object_id(value: str, *, expected_prefix: str) -> str:
    """Validate an opaque broker identifier before using it in a state path."""
    if not isinstance(value, str) or not _OBJECT_ID_RE.fullmatch(value):
        raise UnsafePath(f"invalid broker object identifier: {value!r}")
    if not value.startswith(f"{expected_prefix}_"):
        raise UnsafePath(
            f"broker object identifier has the wrong type; expected {expected_prefix}_..."
        )
    return value


def validate_text_field(value: str, *, name: str, max_length: int) -> str:
    """Validate a human-readable identifier before signing or auditing it."""
    if not isinstance(value, str):
        raise GuardError(f"{name} must be a string")
    normalized = value.strip()
    if not normalized:
        raise GuardError(f"{name} must be non-empty")
    if len(normalized) > max_length:
        raise GuardError(f"{name} exceeds the {max_length}-character limit")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise GuardError(f"{name} may not contain control characters")
    return normalized


def validate_ttl(value: int, *, name: str, maximum: int) -> int:
    """Return a bounded positive TTL, rejecting booleans and oversized leases."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise GuardError(f"{name} must be an integer number of seconds")
    if value < 1 or value > maximum:
        raise GuardError(f"{name} must be between 1 and {maximum} seconds")
    return value


def validate_sha256(value: str, *, name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise GuardError(f"{name} must be a lowercase SHA-256 digest")
    return value


def canonical_json(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def digest_json(data: Any) -> str:
    return hashlib.sha256(canonical_json(data)).hexdigest()


def atomic_write_json(path: Path, data: Any, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical_json(data))
            handle.write(b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        fsync_directory(path.parent)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise GuardError(f"state file does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GuardError(f"state file is not valid JSON: {path}: {exc}") from exc


def ensure_absolute_directory(
    path: str | os.PathLike[str],
    *,
    name: str,
    create: bool = False,
) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = candidate.absolute()
    if create:
        candidate.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        info = os.lstat(candidate)
    except FileNotFoundError as exc:
        raise GuardError(f"{name} does not exist: {candidate}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise UnsafePath(f"{name} may not be a symlink: {candidate}")
    if not stat.S_ISDIR(info.st_mode):
        raise GuardError(f"{name} is not a directory: {candidate}")
    return candidate.resolve(strict=True)


def ensure_private_directory(path: Path, *, parent: Path) -> Path:
    """Create or validate one broker-owned directory without accepting symlinks."""
    path.mkdir(parents=False, exist_ok=True, mode=0o700)
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise UnsafePath(f"cannot inspect broker directory {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise UnsafePath(f"broker state entry must be a real directory: {path}")
    resolved = path.resolve(strict=True)
    if resolved.parent != parent.resolve(strict=True):
        raise UnsafePath(f"broker directory is outside its state namespace: {path}")
    try:
        os.chmod(resolved, 0o700)
    except OSError:
        pass
    return resolved


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def assert_disjoint(left: Path, right: Path, *, left_name: str, right_name: str) -> None:
    if left == right or is_relative_to(left, right) or is_relative_to(right, left):
        raise UnsafePath(
            f"{left_name} and {right_name} must be disjoint: {left} <-> {right}"
        )


def validate_relative_path(value: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise UnsafePath("path must be a non-empty relative string without NUL bytes")
    if value.startswith(("/", "\\", "//")):
        raise UnsafePath(f"absolute or UNC paths are forbidden: {value}")
    windows = PureWindowsPath(value)
    if windows.is_absolute() or windows.drive:
        raise UnsafePath(f"Windows drive-qualified paths are forbidden: {value}")
    candidate = Path(value)
    if candidate.is_absolute():
        raise UnsafePath(f"absolute paths are forbidden: {value}")
    if any(part in ("", ".", "..") for part in candidate.parts):
        raise UnsafePath(f"non-normalized path is forbidden: {value}")
    return candidate


def safe_join(root: Path, relative: str) -> Path:
    candidate = root.joinpath(validate_relative_path(relative))
    # Do not resolve here: resolving would follow attacker-controlled symlinks.
    if candidate == root or not is_relative_to(candidate, root):
        raise UnsafePath(f"path escapes root: {relative}")
    return candidate


def same_filesystem(left: Path, right: Path) -> bool:
    return os.stat(left).st_dev == os.stat(right).st_dev


def fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def copy_entry(source: Path, destination: Path) -> None:
    """Copy one file-system entry without following symlinks."""
    info = os.lstat(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if stat.S_ISLNK(info.st_mode):
        os.symlink(os.readlink(source), destination)
        return
    if stat.S_ISREG(info.st_mode):
        shutil.copy2(source, destination, follow_symlinks=False)
        return
    if stat.S_ISDIR(info.st_mode):
        shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copy2)
        return
    raise GuardError(f"special files are not supported by the reference broker: {source}")


def remove_state_tree(path: Path, state_root: Path) -> None:
    """Delete only a broker-owned directory strictly below the state root."""
    root = state_root.resolve(strict=True)
    candidate = path.resolve(strict=True)
    if candidate == root or not is_relative_to(candidate, root):
        raise UnsafePath(f"refusing to delete outside broker state: {candidate}")
    shutil.rmtree(candidate)


def reject_dangerous_workspace_root(path: Path) -> None:
    home = Path.home().resolve(strict=False)
    anchor = Path(path.anchor).resolve(strict=False)
    if path == anchor:
        raise UnsafePath(f"filesystem roots cannot be used as workspaces: {path}")
    if path == home or is_relative_to(home, path):
        raise UnsafePath(
            "the user home directory or one of its ancestors cannot be used as a "
            "workspace/state root; choose a dedicated project or broker-state directory"
        )
