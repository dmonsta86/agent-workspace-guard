"""Filesystem manifests, semantic diffs, and commit operation roots."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Iterable

from .errors import GuardError, IntegrityError, UnsafePath
from .models import Change, ChangeKind, EntryKind, ManifestEntry, TreeManifest
from .util import canonical_json, validate_relative_path, validate_sha256


DEFAULT_MAX_ENTRIES = 200_000
DEFAULT_MAX_BYTES = 20 * 1024 * 1024 * 1024


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb", buffering=1024 * 1024) as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _entry_kind(mode: int) -> EntryKind:
    if stat.S_ISREG(mode):
        return EntryKind.FILE
    if stat.S_ISDIR(mode):
        return EntryKind.DIRECTORY
    if stat.S_ISLNK(mode):
        return EntryKind.SYMLINK
    return EntryKind.SPECIAL


def scan_tree(
    root: str | os.PathLike[str],
    *,
    excluded_top_level: Iterable[str] = (),
    max_entries: int = DEFAULT_MAX_ENTRIES,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> TreeManifest:
    candidate = Path(root)
    try:
        root_info = os.lstat(candidate)
    except FileNotFoundError as exc:
        raise GuardError(f"manifest root does not exist: {candidate}") from exc
    if stat.S_ISLNK(root_info.st_mode):
        raise UnsafePath(f"manifest root may not be a symlink: {candidate}")
    root_path = candidate.resolve(strict=True)
    if not root_path.is_dir():
        raise GuardError(f"manifest root is not a directory: {root_path}")

    excluded = set(excluded_top_level)
    root_device = root_info.st_dev
    entries: dict[str, ManifestEntry] = {}
    total_files = 0
    total_bytes = 0

    def walk(directory: Path, relative_directory: Path) -> None:
        nonlocal total_files, total_bytes
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise GuardError(f"cannot scan {directory}: {exc}") from exc

        for child in children:
            if not relative_directory.parts and child.name in excluded:
                continue
            relative = relative_directory / child.name
            relative_text = relative.as_posix()
            validate_relative_path(relative_text)
            try:
                info = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise GuardError(f"cannot stat {child.path}: {exc}") from exc

            kind = _entry_kind(info.st_mode)
            entry_device = info.st_dev if info.st_dev != 0 else os.stat(child.path, follow_symlinks=False).st_dev
            if kind is not EntryKind.SYMLINK and entry_device != root_device:
                raise GuardError(
                    f"workspace crosses a filesystem or mount boundary at {relative_text}; fail closed"
                )
            mode = stat.S_IMODE(info.st_mode)
            size = int(info.st_size) if kind is EntryKind.FILE else 0
            link_target: str | None = None

            if kind is EntryKind.FILE:
                total_files += 1
                total_bytes += size
                digest = _hash_file(Path(child.path))
            elif kind is EntryKind.SYMLINK:
                try:
                    link_target = os.readlink(child.path)
                except OSError as exc:
                    raise GuardError(f"cannot read symlink {child.path}: {exc}") from exc
                digest = hashlib.sha256(
                    link_target.encode("utf-8", "surrogateescape")
                ).hexdigest()
            elif kind is EntryKind.DIRECTORY:
                digest = ""
            else:
                digest = hashlib.sha256(
                    f"special:{info.st_mode}:{getattr(info, 'st_rdev', 0)}".encode("ascii")
                ).hexdigest()

            entries[relative_text] = ManifestEntry(
                path=relative_text,
                kind=kind,
                mode=mode,
                size=size,
                digest=digest,
                link_target=link_target,
            )

            if len(entries) > max_entries:
                raise GuardError(
                    f"workspace exceeds manifest entry limit ({max_entries:,}); fail closed"
                )
            if total_bytes > max_bytes:
                raise GuardError(
                    f"workspace exceeds manifest byte limit ({max_bytes:,}); fail closed"
                )

            if kind is EntryKind.DIRECTORY:
                walk(Path(child.path), relative)

    walk(root_path, Path())
    digest_payload = [entries[key].to_dict() for key in sorted(entries)]
    tree_digest = hashlib.sha256(canonical_json(digest_payload)).hexdigest()
    return TreeManifest(
        root=str(root_path),
        entries=entries,
        digest=tree_digest,
        total_files=total_files,
        total_bytes=total_bytes,
    )


def verify_manifest(manifest: TreeManifest, *, expected_root: Path | None = None) -> None:
    """Recompute all self-authenticating manifest fields and fail closed.

    Baseline manifests are stored separately from signed transaction receipts.
    Checking only the serialized ``digest`` field would allow an attacker who
    can alter state but not the HMAC key to edit the entry list while retaining
    the old digest string. The broker therefore validates keys, paths, counts,
    bytes, entry identity, and the digest before using a stored manifest.
    """

    if expected_root is not None:
        actual_root = Path(manifest.root).resolve(strict=False)
        if actual_root != expected_root.resolve(strict=False):
            raise IntegrityError(
                f"manifest root does not match the signed workspace: {actual_root}"
            )

    total_files = 0
    total_bytes = 0
    for key, entry in manifest.entries.items():
        validate_relative_path(key)
        if entry.path != key:
            raise IntegrityError(f"manifest entry key/path mismatch: {key!r}")
        if entry.size < 0 or entry.mode < 0:
            raise IntegrityError(f"manifest entry has invalid metadata: {key}")
        if entry.kind is EntryKind.FILE:
            total_files += 1
            total_bytes += entry.size
        elif entry.size != 0:
            raise IntegrityError(f"non-file manifest entry has a non-zero size: {key}")
        if entry.kind is EntryKind.SYMLINK:
            if entry.link_target is None:
                raise IntegrityError(f"symlink manifest entry has no target: {key}")
        elif entry.link_target is not None:
            raise IntegrityError(f"non-symlink manifest entry has a link target: {key}")
        try:
            if entry.kind is EntryKind.DIRECTORY:
                if entry.digest != "":
                    raise IntegrityError(
                        f"directory manifest entry has a content digest: {key}"
                    )
            else:
                validate_sha256(entry.digest, name=f"digest for {key}")
        except GuardError as exc:
            raise IntegrityError(str(exc)) from exc

    if total_files != manifest.total_files or total_bytes != manifest.total_bytes:
        raise IntegrityError("manifest file or byte totals do not match its entries")
    digest_payload = [manifest.entries[key].to_dict() for key in sorted(manifest.entries)]
    expected_digest = hashlib.sha256(canonical_json(digest_payload)).hexdigest()
    if expected_digest != manifest.digest:
        raise IntegrityError("manifest digest does not match its entries")


def diff_manifests(before: TreeManifest, after: TreeManifest) -> list[Change]:
    changes: list[Change] = []
    all_paths = sorted(set(before.entries) | set(after.entries))
    for path in all_paths:
        old = before.entries.get(path)
        new = after.entries.get(path)
        if old is None and new is not None:
            changes.append(Change(path=path, kind=ChangeKind.ADD, before=None, after=new))
            continue
        if old is not None and new is None:
            changes.append(Change(path=path, kind=ChangeKind.DELETE, before=old, after=None))
            continue
        assert old is not None and new is not None
        if old.kind is not new.kind:
            changes.append(Change(path=path, kind=ChangeKind.TYPE_CHANGE, before=old, after=new))
            continue
        if _entry_changed(old, new):
            changes.append(Change(path=path, kind=ChangeKind.MODIFY, before=old, after=new))
    return changes


def _entry_changed(before: ManifestEntry, after: ManifestEntry) -> bool:
    if before.kind is EntryKind.DIRECTORY:
        return before.mode != after.mode
    return (
        before.mode != after.mode
        or before.size != after.size
        or before.digest != after.digest
        or before.link_target != after.link_target
    )


def operation_roots(changes: Iterable[Change]) -> list[Change]:
    """Collapse descendant changes when an ancestor operation replaces a whole tree."""
    selected: list[Change] = []
    selected_parts: list[tuple[str, ...]] = []
    for change in sorted(changes, key=lambda item: (len(Path(item.path).parts), item.path)):
        parts = Path(change.path).parts
        if any(parts[: len(parent)] == parent for parent in selected_parts):
            continue
        selected.append(change)
        before_is_directory = bool(change.before and change.before.kind is EntryKind.DIRECTORY)
        after_is_directory = bool(change.after and change.after.kind is EntryKind.DIRECTORY)
        if before_is_directory or after_is_directory:
            selected_parts.append(parts)
    return selected
