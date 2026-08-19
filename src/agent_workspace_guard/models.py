"""Serializable domain models for Agent Workspace Guard."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class TransactionState(str, Enum):
    OPEN = "open"
    PLANNED = "planned"
    COMMITTED = "committed"
    DISCARDED = "discarded"


class PlanState(str, Enum):
    PENDING = "pending"
    COMMITTED = "committed"
    INVALIDATED = "invalidated"


class ChangeKind(str, Enum):
    ADD = "add"
    MODIFY = "modify"
    DELETE = "delete"
    TYPE_CHANGE = "type_change"


class EntryKind(str, Enum):
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    SPECIAL = "special"


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    kind: EntryKind
    mode: int
    size: int
    digest: str
    link_target: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["kind"] = self.kind.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ManifestEntry":
        return cls(
            path=str(data["path"]),
            kind=EntryKind(data["kind"]),
            mode=int(data["mode"]),
            size=int(data["size"]),
            digest=str(data["digest"]),
            link_target=data.get("link_target"),
        )


@dataclass(frozen=True)
class TreeManifest:
    root: str
    entries: dict[str, ManifestEntry]
    digest: str
    total_files: int
    total_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "entries": {key: value.to_dict() for key, value in self.entries.items()},
            "digest": self.digest,
            "total_files": self.total_files,
            "total_bytes": self.total_bytes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TreeManifest":
        return cls(
            root=str(data["root"]),
            entries={
                str(key): ManifestEntry.from_dict(value)
                for key, value in dict(data["entries"]).items()
            },
            digest=str(data["digest"]),
            total_files=int(data["total_files"]),
            total_bytes=int(data["total_bytes"]),
        )


@dataclass(frozen=True)
class Change:
    path: str
    kind: ChangeKind
    before: ManifestEntry | None
    after: ManifestEntry | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind.value,
            "before": self.before.to_dict() if self.before else None,
            "after": self.after.to_dict() if self.after else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Change":
        return cls(
            path=str(data["path"]),
            kind=ChangeKind(data["kind"]),
            before=ManifestEntry.from_dict(data["before"]) if data.get("before") else None,
            after=ManifestEntry.from_dict(data["after"]) if data.get("after") else None,
        )


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        return cls(
            code=str(data["code"]),
            severity=str(data["severity"]),
            message=str(data["message"]),
            path=data.get("path"),
        )


@dataclass(frozen=True)
class Transaction:
    transaction_id: str
    task_id: str
    workspace_root: str
    transaction_root: str
    worktree_root: str
    home_root: str
    temp_root: str
    baseline_path: str
    baseline_digest: str
    created_at: int
    workspace_device: int
    state: TransactionState = TransactionState.OPEN
    signature: str = ""

    def core_dict(self) -> dict[str, Any]:
        return {
            "transaction_id": self.transaction_id,
            "task_id": self.task_id,
            "workspace_root": self.workspace_root,
            "transaction_root": self.transaction_root,
            "worktree_root": self.worktree_root,
            "home_root": self.home_root,
            "temp_root": self.temp_root,
            "baseline_path": self.baseline_path,
            "baseline_digest": self.baseline_digest,
            "created_at": self.created_at,
            "workspace_device": self.workspace_device,
        }

    def signing_dict(self) -> dict[str, Any]:
        return {**self.core_dict(), "state": self.state.value}

    def to_dict(self) -> dict[str, Any]:
        data = self.core_dict()
        data.update({"state": self.state.value, "signature": self.signature})
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Transaction":
        return cls(
            transaction_id=str(data["transaction_id"]),
            task_id=str(data["task_id"]),
            workspace_root=str(data["workspace_root"]),
            transaction_root=str(data["transaction_root"]),
            worktree_root=str(data["worktree_root"]),
            home_root=str(data["home_root"]),
            temp_root=str(data["temp_root"]),
            baseline_path=str(data["baseline_path"]),
            baseline_digest=str(data["baseline_digest"]),
            created_at=int(data["created_at"]),
            workspace_device=int(data["workspace_device"]),
            state=TransactionState(data["state"]),
            signature=str(data["signature"]),
        )


@dataclass(frozen=True)
class CommitPlan:
    protocol_version: int
    plan_id: str
    transaction_id: str
    task_id: str
    workspace_root: str
    baseline_digest: str
    staged_digest: str
    policy_digest: str
    changes: list[Change]
    findings: list[Finding]
    decision: Decision
    fingerprint: str
    created_at: int
    expires_at: int
    signature: str
    state: PlanState = PlanState.PENDING
    summary: dict[str, int] = field(default_factory=dict)

    def core_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "plan_id": self.plan_id,
            "transaction_id": self.transaction_id,
            "task_id": self.task_id,
            "workspace_root": self.workspace_root,
            "baseline_digest": self.baseline_digest,
            "staged_digest": self.staged_digest,
            "policy_digest": self.policy_digest,
            "changes": [change.to_dict() for change in self.changes],
            "findings": [finding.to_dict() for finding in self.findings],
            "decision": self.decision.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "summary": dict(self.summary),
        }

    def signing_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "state": self.state.value,
            "core": self.core_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.core_dict()
        data.update(
            {
                "fingerprint": self.fingerprint,
                "signature": self.signature,
                "state": self.state.value,
            }
        )
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CommitPlan":
        return cls(
            protocol_version=int(data["protocol_version"]),
            plan_id=str(data["plan_id"]),
            transaction_id=str(data["transaction_id"]),
            task_id=str(data["task_id"]),
            workspace_root=str(data["workspace_root"]),
            baseline_digest=str(data["baseline_digest"]),
            staged_digest=str(data["staged_digest"]),
            policy_digest=str(data["policy_digest"]),
            changes=[Change.from_dict(item) for item in data["changes"]],
            findings=[Finding.from_dict(item) for item in data["findings"]],
            decision=Decision(data["decision"]),
            fingerprint=str(data["fingerprint"]),
            created_at=int(data["created_at"]),
            expires_at=int(data["expires_at"]),
            signature=str(data["signature"]),
            state=PlanState(data["state"]),
            summary={str(k): int(v) for k, v in dict(data.get("summary", {})).items()},
        )


@dataclass(frozen=True)
class ApprovalToken:
    token_id: str
    plan_id: str
    plan_fingerprint: str
    actor: str
    created_at: int
    expires_at: int
    signature: str

    def core_dict(self) -> dict[str, Any]:
        return {
            "token_id": self.token_id,
            "plan_id": self.plan_id,
            "plan_fingerprint": self.plan_fingerprint,
            "actor": self.actor,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.core_dict(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ApprovalToken":
        return cls(
            token_id=str(data["token_id"]),
            plan_id=str(data["plan_id"]),
            plan_fingerprint=str(data["plan_fingerprint"]),
            actor=str(data["actor"]),
            created_at=int(data["created_at"]),
            expires_at=int(data["expires_at"]),
            signature=str(data["signature"]),
        )


@dataclass
class CommitOperation:
    path: str
    change_kind: ChangeKind
    before_kind: EntryKind | None
    after_kind: EntryKind | None
    backup_path: str | None = None
    installed: bool = False
    backup_moved: bool = False
    phase: str = "pending"

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "change_kind": self.change_kind.value,
            "before_kind": self.before_kind.value if self.before_kind else None,
            "after_kind": self.after_kind.value if self.after_kind else None,
            "backup_path": self.backup_path,
            "installed": self.installed,
            "backup_moved": self.backup_moved,
            "phase": self.phase,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CommitOperation":
        return cls(
            path=str(data["path"]),
            change_kind=ChangeKind(data["change_kind"]),
            before_kind=EntryKind(data["before_kind"]) if data.get("before_kind") else None,
            after_kind=EntryKind(data["after_kind"]) if data.get("after_kind") else None,
            backup_path=data.get("backup_path"),
            installed=bool(data.get("installed", False)),
            backup_moved=bool(data.get("backup_moved", False)),
            phase=str(data.get("phase", "pending")),
        )


@dataclass
class CommitRecord:
    commit_id: str
    plan_id: str
    transaction_id: str
    workspace_root: str
    quarantine_root: str
    apply_root: str
    operations: list[CommitOperation]
    before_digest: str
    after_digest: str
    created_at: int
    status: str
    signature: str = ""

    def core_dict(self) -> dict[str, Any]:
        return {
            "commit_id": self.commit_id,
            "plan_id": self.plan_id,
            "transaction_id": self.transaction_id,
            "workspace_root": self.workspace_root,
            "quarantine_root": self.quarantine_root,
            "apply_root": self.apply_root,
            "operations": [operation.to_dict() for operation in self.operations],
            "before_digest": self.before_digest,
            "after_digest": self.after_digest,
            "created_at": self.created_at,
            "status": self.status,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.core_dict(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CommitRecord":
        return cls(
            commit_id=str(data["commit_id"]),
            plan_id=str(data["plan_id"]),
            transaction_id=str(data["transaction_id"]),
            workspace_root=str(data["workspace_root"]),
            quarantine_root=str(data["quarantine_root"]),
            apply_root=str(data["apply_root"]),
            operations=[CommitOperation.from_dict(item) for item in data["operations"]],
            before_digest=str(data["before_digest"]),
            after_digest=str(data["after_digest"]),
            created_at=int(data["created_at"]),
            status=str(data["status"]),
            signature=str(data.get("signature", "")),
        )


@dataclass(frozen=True)
class CommandInspection:
    decision: Decision
    findings: list[Finding]
    shell: str
    command_sha256: str
    command_length: int
    boundary_note: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "findings": [finding.to_dict() for finding in self.findings],
            "shell": self.shell,
            "command_sha256": self.command_sha256,
            "command_length": self.command_length,
            "boundary_note": self.boundary_note,
        }
