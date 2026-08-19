"""Transactional workspace and commit broker.

The agent operates on a disposable copy. The real workspace is mutated only by
this broker after it verifies an immutable plan. Existing targets are moved to
same-filesystem quarantine before replacement, making commits reversible.
"""

from __future__ import annotations

import os
import shutil
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Iterator

from .audit import AuditLog
from .crypto import StateSigner
from .errors import ApprovalError, GuardError, IntegrityError, PolicyDenied, StalePlan
from .manifest import diff_manifests, operation_roots, scan_tree, verify_manifest
from .models import (
    ApprovalToken,
    CommitOperation,
    CommitPlan,
    CommitRecord,
    CommandInspection,
    Decision,
    PlanState,
    Transaction,
    TransactionState,
    TreeManifest,
)
from .policy import GuardPolicy
from .shell_gate import inspect_shell_command
from .util import (
    assert_disjoint,
    atomic_write_json,
    copy_entry,
    digest_json,
    ensure_absolute_directory,
    ensure_private_directory,
    fsync_directory,
    random_id,
    read_json,
    reject_dangerous_workspace_root,
    remove_state_tree,
    safe_join,
    same_filesystem,
    utc_epoch,
    validate_object_id,
    validate_relative_path,
    validate_sha256,
    validate_text_field,
    validate_ttl,
)


DEFAULT_EXCLUDED_TOP_LEVEL = (".git", ".agent-workspace-guard")
MAX_PLAN_TTL_SECONDS = 3600
MAX_APPROVAL_TTL_SECONDS = 900
MAX_TASK_ID_LENGTH = 256
MAX_ACTOR_LENGTH = 256
PROTOCOL_VERSION = 1


class WorkspaceGuard:
    """Reference implementation of the Agent Workspace Guard protocol."""

    def __init__(
        self,
        state_root: str | os.PathLike[str],
        *,
        policy: GuardPolicy | None = None,
        excluded_top_level: tuple[str, ...] = DEFAULT_EXCLUDED_TOP_LEVEL,
    ) -> None:
        self.state_root = ensure_absolute_directory(
            state_root, name="state root", create=True
        )
        try:
            os.chmod(self.state_root, 0o700)
        except OSError:
            pass
        reject_dangerous_workspace_root(self.state_root)
        self.policy = policy or GuardPolicy(protected_top_level=excluded_top_level)
        self.excluded_top_level = tuple(excluded_top_level)
        for directory in (
            "transactions",
            "plans",
            "approvals",
            "commits",
            "quarantine",
            "apply",
            "locks",
        ):
            ensure_private_directory(
                self.state_root / directory, parent=self.state_root
            )
        self.signer = StateSigner(self.state_root / "secret.key")
        self.audit = AuditLog(self.state_root / "audit.jsonl", signer=self.signer)

    # ------------------------------------------------------------------
    # Transaction lifecycle
    # ------------------------------------------------------------------
    def begin(self, workspace_root: str | os.PathLike[str], *, task_id: str) -> Transaction:
        task_id = validate_text_field(
            task_id, name="task id", max_length=MAX_TASK_ID_LENGTH
        )
        workspace = ensure_absolute_directory(workspace_root, name="workspace root")
        reject_dangerous_workspace_root(workspace)
        assert_disjoint(
            workspace,
            self.state_root,
            left_name="workspace root",
            right_name="state root",
        )
        if not same_filesystem(workspace, self.state_root):
            raise GuardError(
                "state root must be on the same filesystem as the workspace so quarantine moves are atomic"
            )

        baseline_before = self._scan(workspace)
        transaction_id = random_id("tx")
        transaction_root = self.state_root / "transactions" / transaction_id
        worktree_root = transaction_root / "worktree"
        home_root = transaction_root / "home"
        temp_root = transaction_root / "tmp"
        baseline_path = transaction_root / "baseline.json"

        transaction_root.mkdir(mode=0o700)
        try:
            shutil.copytree(
                workspace,
                worktree_root,
                symlinks=True,
                copy_function=shutil.copy2,
                ignore=shutil.ignore_patterns(*self.excluded_top_level),
            )
            home_root.mkdir(mode=0o700)
            temp_root.mkdir(mode=0o700)
            for relative in (
                ".codex",
                ".config",
                ".cache",
                ".local/share",
                ".local/state",
                "AppData/Roaming",
                "AppData/Local",
            ):
                (home_root / relative).mkdir(parents=True, mode=0o700)
            (temp_root / "runtime").mkdir(mode=0o700)

            # Detect changes during the copy and verify the staged semantic tree.
            baseline_after = self._scan(workspace)
            staged = self._scan(worktree_root)
            if baseline_after.digest != baseline_before.digest:
                raise StalePlan("the workspace changed while the transaction was being created")
            if staged.digest != baseline_before.digest:
                raise IntegrityError(
                    "the disposable worktree does not match the source workspace after copying"
                )

            atomic_write_json(baseline_path, baseline_before.to_dict())
            unsigned = Transaction(
                transaction_id=transaction_id,
                task_id=task_id,
                workspace_root=str(workspace),
                transaction_root=str(transaction_root),
                worktree_root=str(worktree_root),
                home_root=str(home_root),
                temp_root=str(temp_root),
                baseline_path=str(baseline_path),
                baseline_digest=baseline_before.digest,
                created_at=utc_epoch(),
                workspace_device=os.stat(workspace).st_dev,
            )
            transaction = replace(
                unsigned,
                signature=self.signer.sign(
                    {"kind": "transaction", "record": unsigned.signing_dict()}
                ),
            )
            self._save_transaction(transaction)
            receipt_core = {
                "transaction_id": transaction_id,
                "task_id": task_id,
                "worktree_root": str(worktree_root),
                "home_root": str(home_root),
                "temp_root": str(temp_root),
                "baseline_digest": baseline_before.digest,
                "issued_at": transaction.created_at,
                "issued_by": "agent-workspace-guard",
            }
            atomic_write_json(
                transaction_root / "capability-receipt.json",
                {
                    **receipt_core,
                    "signature": self.signer.sign(
                        {"kind": "capability_receipt", "core": receipt_core}
                    ),
                },
            )
        except Exception:
            if transaction_root.exists():
                remove_state_tree(transaction_root, self.state_root)
            raise

        self.audit.append(
            "transaction_started",
            {
                "transaction_id": transaction_id,
                "task_id": task_id,
                "workspace_root": str(workspace),
                "baseline_digest": baseline_before.digest,
            },
        )
        return transaction

    def environment(self, transaction_id: str) -> dict[str, str]:
        transaction = self.load_transaction(transaction_id)
        if transaction.state not in (TransactionState.OPEN, TransactionState.PLANNED):
            raise GuardError(f"transaction is not executable: {transaction.state.value}")
        return {
            "AWG_TRANSACTION_ID": transaction.transaction_id,
            "AWG_WORKTREE": transaction.worktree_root,
            "HOME": transaction.home_root,
            "USERPROFILE": transaction.home_root,
            "TMPDIR": transaction.temp_root,
            "TMP": transaction.temp_root,
            "TEMP": transaction.temp_root,
            "CODEX_HOME": str(Path(transaction.home_root) / ".codex"),
            "XDG_CONFIG_HOME": str(Path(transaction.home_root) / ".config"),
            "XDG_CACHE_HOME": str(Path(transaction.home_root) / ".cache"),
            "XDG_DATA_HOME": str(Path(transaction.home_root) / ".local" / "share"),
            "XDG_STATE_HOME": str(Path(transaction.home_root) / ".local" / "state"),
            "XDG_RUNTIME_DIR": str(Path(transaction.temp_root) / "runtime"),
            "APPDATA": str(Path(transaction.home_root) / "AppData" / "Roaming"),
            "LOCALAPPDATA": str(Path(transaction.home_root) / "AppData" / "Local"),
        }

    def discard(self, transaction_id: str) -> None:
        transaction = self.load_transaction(transaction_id)
        if transaction.state is TransactionState.COMMITTED:
            raise GuardError("committed transactions are retained for audit and restore")
        updated = replace(transaction, state=TransactionState.DISCARDED)
        self._save_transaction(updated)
        transaction_root = Path(transaction.transaction_root)
        self.audit.append(
            "transaction_discarded",
            {"transaction_id": transaction_id, "task_id": transaction.task_id},
        )
        remove_state_tree(transaction_root, self.state_root)

    # ------------------------------------------------------------------
    # Plan / approval
    # ------------------------------------------------------------------
    def plan(self, transaction_id: str, *, ttl_seconds: int = 1800) -> CommitPlan:
        ttl_seconds = validate_ttl(
            ttl_seconds, name="plan TTL", maximum=MAX_PLAN_TTL_SECONDS
        )
        transaction = self.load_transaction(transaction_id)
        if transaction.state not in (TransactionState.OPEN, TransactionState.PLANNED):
            raise GuardError(f"cannot plan transaction in state {transaction.state.value}")
        baseline = self._load_baseline(transaction)
        current_real = self._scan(Path(transaction.workspace_root))
        if current_real.digest != baseline.digest:
            raise StalePlan(
                "the real workspace changed after the transaction began; rebase into a new transaction"
            )
        staged = self._scan(Path(transaction.worktree_root))
        changes = diff_manifests(baseline, staged)
        decision, findings, summary = self.policy.evaluate(baseline, staged, changes)
        created_at = utc_epoch()
        unsigned = CommitPlan(
            protocol_version=PROTOCOL_VERSION,
            plan_id=random_id("plan"),
            transaction_id=transaction.transaction_id,
            task_id=transaction.task_id,
            workspace_root=transaction.workspace_root,
            baseline_digest=baseline.digest,
            staged_digest=staged.digest,
            policy_digest=self.policy.fingerprint(),
            changes=changes,
            findings=findings,
            decision=decision,
            fingerprint="",
            created_at=created_at,
            expires_at=created_at + ttl_seconds,
            signature="",
            summary=summary,
        )
        fingerprint = digest_json(unsigned.core_dict())
        plan_with_fingerprint = replace(unsigned, fingerprint=fingerprint)
        signature = self.signer.sign(
            {"kind": "commit_plan", "record": plan_with_fingerprint.signing_dict()}
        )
        plan = replace(plan_with_fingerprint, signature=signature)
        self._save_plan(plan)
        self._save_transaction(replace(transaction, state=TransactionState.PLANNED))
        self.audit.append(
            "plan_created",
            {
                "plan_id": plan.plan_id,
                "transaction_id": transaction.transaction_id,
                "decision": plan.decision.value,
                "fingerprint": plan.fingerprint,
                "summary": plan.summary,
            },
        )
        return plan

    def approve(
        self,
        plan_id: str,
        *,
        actor: str,
        ttl_seconds: int = 900,
    ) -> ApprovalToken:
        try:
            actor = validate_text_field(
                actor, name="approval actor", max_length=MAX_ACTOR_LENGTH
            )
            ttl_seconds = validate_ttl(
                ttl_seconds,
                name="approval TTL",
                maximum=MAX_APPROVAL_TTL_SECONDS,
            )
        except GuardError as exc:
            raise ApprovalError(str(exc)) from exc
        plan = self.load_plan(plan_id)
        self._assert_plan_pending_and_fresh(plan)
        if plan.decision is Decision.DENY:
            raise PolicyDenied("hard-denied plans cannot be approved")
        created_at = utc_epoch()
        unsigned = ApprovalToken(
            token_id=random_id("approval"),
            plan_id=plan.plan_id,
            plan_fingerprint=plan.fingerprint,
            actor=actor,
            created_at=created_at,
            expires_at=min(plan.expires_at, created_at + ttl_seconds),
            signature="",
        )
        token = replace(
            unsigned,
            signature=self.signer.sign(
                {"kind": "approval", "core": unsigned.core_dict()}
            ),
        )
        atomic_write_json(self._approval_path(token.token_id), token.to_dict())
        self.audit.append(
            "plan_approved",
            {
                "token_id": token.token_id,
                "plan_id": plan.plan_id,
                "plan_fingerprint": plan.fingerprint,
                "actor": token.actor,
            },
        )
        return token

    # ------------------------------------------------------------------
    # Commit / restore
    # ------------------------------------------------------------------
    def commit(
        self,
        plan_id: str,
        *,
        approval_token: str | ApprovalToken | None = None,
    ) -> CommitRecord:
        plan = self.load_plan(plan_id)
        self._assert_plan_pending_and_fresh(plan)
        if plan.decision is Decision.DENY:
            raise PolicyDenied("the plan is hard-denied by policy")
        if plan.decision is Decision.REQUIRE_APPROVAL:
            token = self._resolve_approval(approval_token)
            self._verify_approval(token, plan)

        transaction = self.load_transaction(plan.transaction_id)
        if transaction.state is not TransactionState.PLANNED:
            raise GuardError(
                f"transaction is not commit-capable: {transaction.state.value}"
            )
        if (
            plan.task_id != transaction.task_id
            or plan.workspace_root != transaction.workspace_root
            or plan.baseline_digest != transaction.baseline_digest
        ):
            raise IntegrityError("commit plan does not match its signed transaction")
        baseline = self._load_baseline(transaction)
        workspace = Path(transaction.workspace_root)
        worktree = Path(transaction.worktree_root)

        with self._workspace_lock(workspace):
            current_real = self._scan(workspace)
            current_staged = self._scan(worktree)
            if current_real.digest != plan.baseline_digest:
                raise StalePlan("real workspace no longer matches the approved baseline")
            if current_staged.digest != plan.staged_digest:
                raise StalePlan("disposable worktree no longer matches the approved plan")
            if plan.policy_digest != self.policy.fingerprint():
                raise StalePlan("broker policy changed after the plan was created")

            # Re-evaluate the exact result under the bound current policy rather
            # than trusting a serialized decision in isolation.
            current_changes = diff_manifests(baseline, current_staged)
            current_decision, current_findings, current_summary = self.policy.evaluate(
                baseline, current_staged, current_changes
            )
            if (
                [item.to_dict() for item in current_changes]
                != [item.to_dict() for item in plan.changes]
                or current_decision is not plan.decision
                or [item.to_dict() for item in current_findings]
                != [item.to_dict() for item in plan.findings]
                or current_summary != plan.summary
            ):
                raise IntegrityError(
                    "commit plan does not match deterministic policy re-evaluation"
                )
            if os.stat(workspace).st_dev != transaction.workspace_device:
                raise StalePlan("workspace filesystem identity changed")
            if not same_filesystem(workspace, self.state_root):
                raise GuardError("quarantine is no longer on the workspace filesystem")

            commit_id = random_id("commit")
            quarantine_root = self.state_root / "quarantine" / commit_id
            apply_root = self.state_root / "apply" / commit_id
            quarantine_root.mkdir(mode=0o700)
            apply_root.mkdir(mode=0o700)

            roots = operation_roots(plan.changes)
            operations: list[CommitOperation] = []
            try:
                for change in roots:
                    if change.after is not None:
                        copy_entry(
                            safe_join(worktree, change.path),
                            safe_join(apply_root, change.path),
                        )
                    operations.append(
                        CommitOperation(
                            path=change.path,
                            change_kind=change.kind,
                            before_kind=change.before.kind if change.before else None,
                            after_kind=change.after.kind if change.after else None,
                            backup_path=(
                                str(safe_join(quarantine_root, change.path))
                                if change.before
                                else None
                            ),
                        )
                    )

                # Close the scan/copy race for this reference implementation.
                # Production should freeze the snapshot or use immutable handles.
                if self._scan(worktree).digest != plan.staged_digest:
                    raise StalePlan("worktree changed while commit payloads were staged")

                record = CommitRecord(
                    commit_id=commit_id,
                    plan_id=plan.plan_id,
                    transaction_id=transaction.transaction_id,
                    workspace_root=str(workspace),
                    quarantine_root=str(quarantine_root),
                    apply_root=str(apply_root),
                    operations=operations,
                    before_digest=baseline.digest,
                    after_digest=plan.staged_digest,
                    created_at=utc_epoch(),
                    status="prepared",
                )
                self._save_commit(record)

                for operation in record.operations:
                    destination = safe_join(workspace, operation.path)
                    staged_path = safe_join(apply_root, operation.path)
                    backup = (
                        Path(operation.backup_path)
                        if operation.backup_path is not None
                        else None
                    )

                    if operation.before_kind is not None:
                        if not os.path.lexists(destination):
                            raise StalePlan(
                                f"planned existing target disappeared: {operation.path}"
                            )
                        assert backup is not None
                        backup.parent.mkdir(parents=True, exist_ok=True)
                        operation.phase = "moving_backup"
                        self._save_commit(record)
                        os.rename(destination, backup)
                        operation.backup_moved = True
                        operation.phase = "backup_moved"
                        fsync_directory(destination.parent)
                        fsync_directory(backup.parent)
                        self._save_commit(record)

                    if operation.after_kind is not None:
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        operation.phase = "installing"
                        self._save_commit(record)
                        os.rename(staged_path, destination)
                        operation.installed = True
                        operation.phase = "installed"
                        fsync_directory(destination.parent)
                        self._save_commit(record)

                final_manifest = self._scan(workspace)
                if final_manifest.digest != plan.staged_digest:
                    raise IntegrityError(
                        "post-commit workspace digest does not match the approved staged digest"
                    )
                record.status = "committed"
                for operation in record.operations:
                    operation.phase = "complete"
                self._save_commit(record)
            except Exception:
                if "record" in locals():
                    self._rollback_failed_commit(record, workspace, baseline)
                else:
                    if apply_root.exists():
                        remove_state_tree(apply_root, self.state_root)
                    if quarantine_root.exists():
                        remove_state_tree(quarantine_root, self.state_root)
                raise

            if apply_root.exists():
                remove_state_tree(apply_root, self.state_root)
            committed_plan = replace(plan, state=PlanState.COMMITTED)
            self._save_plan(committed_plan)
            self._save_transaction(
                replace(transaction, state=TransactionState.COMMITTED)
            )
            self.audit.append(
                "commit_completed",
                {
                    "commit_id": record.commit_id,
                    "plan_id": plan.plan_id,
                    "transaction_id": transaction.transaction_id,
                    "before_digest": record.before_digest,
                    "after_digest": record.after_digest,
                    "operation_count": len(record.operations),
                },
            )
            return record

    def restore(self, commit_id: str) -> CommitRecord:
        record = self.load_commit(commit_id)
        if record.status != "committed":
            raise GuardError(f"commit is not restorable in state: {record.status}")
        plan = self.load_plan(record.plan_id)
        if plan.state is not PlanState.COMMITTED:
            raise IntegrityError("restorable commit references a non-committed plan")
        if (
            record.transaction_id != plan.transaction_id
            or record.workspace_root != plan.workspace_root
            or record.before_digest != plan.baseline_digest
            or record.after_digest != plan.staged_digest
        ):
            raise IntegrityError("commit record does not match its signed plan")
        workspace = Path(record.workspace_root)
        quarantine_root = Path(record.quarantine_root)

        with self._workspace_lock(workspace):
            current = self._scan(workspace)
            if current.digest != record.after_digest:
                raise StalePlan(
                    "workspace changed after commit; automatic restore would overwrite later work"
                )
            restored_new_root = quarantine_root / "_restore_current"
            for operation in reversed(record.operations):
                destination = safe_join(workspace, operation.path)
                backup = (
                    Path(operation.backup_path)
                    if operation.backup_path is not None
                    else None
                )
                if operation.installed:
                    if not os.path.lexists(destination):
                        raise StalePlan(
                            f"committed target disappeared before restore: {operation.path}"
                        )
                    displaced = safe_join(restored_new_root, operation.path)
                    displaced.parent.mkdir(parents=True, exist_ok=True)
                    os.rename(destination, displaced)
                    fsync_directory(destination.parent)
                if operation.backup_moved:
                    if backup is None or not os.path.lexists(backup):
                        raise IntegrityError(
                            f"quarantine backup is missing for restore: {operation.path}"
                        )
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    os.rename(backup, destination)
                    fsync_directory(destination.parent)
                operation.phase = "restored"

            restored = self._scan(workspace)
            if restored.digest != record.before_digest:
                raise IntegrityError("restored workspace does not match the original baseline")
            record.status = "restored"
            self._save_commit(record)
            self.audit.append(
                "commit_restored",
                {
                    "commit_id": record.commit_id,
                    "plan_id": plan.plan_id,
                    "workspace_root": record.workspace_root,
                    "restored_digest": restored.digest,
                },
            )
            return record

    # ------------------------------------------------------------------
    # Reads / verification
    # ------------------------------------------------------------------
    def load_transaction(self, transaction_id: str) -> Transaction:
        requested_id = validate_object_id(transaction_id, expected_prefix="tx")
        transaction = Transaction.from_dict(read_json(self._transaction_path(requested_id)))
        if transaction.transaction_id != requested_id:
            raise IntegrityError("transaction record identity does not match its state path")
        self.signer.verify(
            {"kind": "transaction", "record": transaction.signing_dict()},
            transaction.signature,
        )
        self._validate_transaction_record(transaction)
        return transaction

    def load_plan(self, plan_id: str) -> CommitPlan:
        requested_id = validate_object_id(plan_id, expected_prefix="plan")
        plan = CommitPlan.from_dict(read_json(self._plan_path(requested_id)))
        if plan.plan_id != requested_id:
            raise IntegrityError("commit plan identity does not match its state path")
        expected_fingerprint = digest_json(plan.core_dict())
        if expected_fingerprint != plan.fingerprint:
            raise IntegrityError("commit plan fingerprint does not match its contents")
        self.signer.verify(
            {"kind": "commit_plan", "record": plan.signing_dict()},
            plan.signature,
        )
        self._validate_plan_record(plan)
        return plan

    def load_commit(self, commit_id: str) -> CommitRecord:
        requested_id = validate_object_id(commit_id, expected_prefix="commit")
        record = CommitRecord.from_dict(read_json(self._commit_path(requested_id)))
        if record.commit_id != requested_id:
            raise IntegrityError("commit record identity does not match its state path")
        self.signer.verify(
            {"kind": "commit_record", "core": record.core_dict()}, record.signature
        )
        self._validate_commit_record(record)
        return record

    def verify_audit(self) -> int:
        return self.audit.verify()

    @staticmethod
    def inspect_command(command: str, shell: str = "unknown") -> CommandInspection:
        return inspect_shell_command(command, shell=shell)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _scan(self, root: Path) -> TreeManifest:
        return scan_tree(root, excluded_top_level=self.excluded_top_level)

    def _load_baseline(self, transaction: Transaction) -> TreeManifest:
        baseline = TreeManifest.from_dict(read_json(Path(transaction.baseline_path)))
        verify_manifest(baseline, expected_root=Path(transaction.workspace_root))
        if baseline.digest != transaction.baseline_digest:
            raise IntegrityError("baseline manifest does not match the signed transaction receipt")
        return baseline

    def _save_transaction(self, transaction: Transaction) -> None:
        transaction = replace(
            transaction,
            signature=self.signer.sign(
                {"kind": "transaction", "record": transaction.signing_dict()}
            ),
        )
        atomic_write_json(
            self._transaction_path(transaction.transaction_id), transaction.to_dict()
        )

    def _save_plan(self, plan: CommitPlan) -> None:
        plan = replace(
            plan,
            signature=self.signer.sign(
                {"kind": "commit_plan", "record": plan.signing_dict()}
            ),
        )
        atomic_write_json(self._plan_path(plan.plan_id), plan.to_dict())

    def _save_commit(self, record: CommitRecord) -> None:
        record.signature = self.signer.sign(
            {"kind": "commit_record", "core": record.core_dict()}
        )
        atomic_write_json(self._commit_path(record.commit_id), record.to_dict())

    def _transaction_path(self, transaction_id: str) -> Path:
        transaction_id = validate_object_id(transaction_id, expected_prefix="tx")
        return self.state_root / "transactions" / transaction_id / "transaction.json"

    def _plan_path(self, plan_id: str) -> Path:
        plan_id = validate_object_id(plan_id, expected_prefix="plan")
        return self.state_root / "plans" / f"{plan_id}.json"

    def _approval_path(self, token_id: str) -> Path:
        token_id = validate_object_id(token_id, expected_prefix="approval")
        return self.state_root / "approvals" / f"{token_id}.json"

    def _commit_path(self, commit_id: str) -> Path:
        commit_id = validate_object_id(commit_id, expected_prefix="commit")
        return self.state_root / "commits" / f"{commit_id}.json"

    def _assert_plan_pending_and_fresh(self, plan: CommitPlan) -> None:
        if plan.state is not PlanState.PENDING:
            raise GuardError(f"plan is not pending: {plan.state.value}")
        if utc_epoch() >= plan.expires_at:
            raise StalePlan("plan has expired")

    def _resolve_approval(
        self, approval: str | ApprovalToken | None
    ) -> ApprovalToken:
        if approval is None:
            raise ApprovalError("this plan requires an approval token")
        if isinstance(approval, ApprovalToken):
            return approval
        requested_id = validate_object_id(approval, expected_prefix="approval")
        token = ApprovalToken.from_dict(read_json(self._approval_path(requested_id)))
        if token.token_id != requested_id:
            raise IntegrityError("approval identity does not match its state path")
        return token

    def _verify_approval(self, token: ApprovalToken, plan: CommitPlan) -> None:
        validate_object_id(token.token_id, expected_prefix="approval")
        validate_object_id(token.plan_id, expected_prefix="plan")
        self.signer.verify(
            {"kind": "approval", "core": token.core_dict()}, token.signature
        )
        try:
            validate_text_field(
                token.actor, name="approval actor", max_length=MAX_ACTOR_LENGTH
            )
        except GuardError as exc:
            raise ApprovalError(str(exc)) from exc
        if token.created_at < 0 or token.expires_at <= token.created_at:
            raise ApprovalError("approval token has an invalid lifetime")
        if token.expires_at - token.created_at > MAX_APPROVAL_TTL_SECONDS:
            raise ApprovalError("approval token exceeds the maximum lifetime")
        if utc_epoch() >= token.expires_at:
            raise ApprovalError("approval token has expired")
        if token.expires_at > plan.expires_at:
            raise ApprovalError("approval token outlives its commit plan")
        try:
            validate_sha256(
                token.plan_fingerprint, name="approval plan fingerprint"
            )
        except GuardError as exc:
            raise ApprovalError(str(exc)) from exc
        if token.plan_id != plan.plan_id or token.plan_fingerprint != plan.fingerprint:
            raise ApprovalError("approval token is not bound to this exact plan")

    def _validate_transaction_record(self, transaction: Transaction) -> None:
        validate_object_id(transaction.transaction_id, expected_prefix="tx")
        validate_text_field(
            transaction.task_id, name="task id", max_length=MAX_TASK_ID_LENGTH
        )
        expected_root = self.state_root / "transactions" / transaction.transaction_id
        expected_paths = {
            "transaction root": expected_root,
            "worktree root": expected_root / "worktree",
            "home root": expected_root / "home",
            "temp root": expected_root / "tmp",
            "baseline path": expected_root / "baseline.json",
        }
        actual_paths = {
            "transaction root": Path(transaction.transaction_root),
            "worktree root": Path(transaction.worktree_root),
            "home root": Path(transaction.home_root),
            "temp root": Path(transaction.temp_root),
            "baseline path": Path(transaction.baseline_path),
        }
        for name, expected in expected_paths.items():
            if actual_paths[name] != expected:
                raise IntegrityError(f"signed {name} is outside the transaction namespace")
        workspace = Path(transaction.workspace_root)
        if not workspace.is_absolute():
            raise IntegrityError("signed workspace root is not absolute")
        if transaction.created_at < 0 or transaction.workspace_device < 0:
            raise IntegrityError("transaction record contains invalid metadata")
        try:
            validate_sha256(transaction.baseline_digest, name="transaction baseline digest")
        except GuardError as exc:
            raise IntegrityError(str(exc)) from exc

    def _validate_plan_record(self, plan: CommitPlan) -> None:
        if plan.protocol_version != PROTOCOL_VERSION:
            raise IntegrityError(
                f"unsupported commit-plan protocol version: {plan.protocol_version}"
            )
        validate_object_id(plan.plan_id, expected_prefix="plan")
        validate_object_id(plan.transaction_id, expected_prefix="tx")
        validate_text_field(plan.task_id, name="task id", max_length=MAX_TASK_ID_LENGTH)
        if not Path(plan.workspace_root).is_absolute():
            raise IntegrityError("commit plan workspace root is not absolute")
        if plan.created_at < 0 or plan.expires_at <= plan.created_at:
            raise IntegrityError("commit plan has an invalid lifetime")
        if plan.expires_at - plan.created_at > MAX_PLAN_TTL_SECONDS:
            raise IntegrityError("commit plan exceeds the maximum lifetime")
        try:
            validate_sha256(plan.baseline_digest, name="plan baseline digest")
            validate_sha256(plan.staged_digest, name="plan staged digest")
            validate_sha256(plan.policy_digest, name="plan policy digest")
            validate_sha256(plan.fingerprint, name="plan fingerprint")
        except GuardError as exc:
            raise IntegrityError(str(exc)) from exc
        for change in plan.changes:
            validate_relative_path(change.path)
            if change.before is not None and change.before.path != change.path:
                raise IntegrityError("commit plan before-entry path mismatch")
            if change.after is not None and change.after.path != change.path:
                raise IntegrityError("commit plan after-entry path mismatch")

    def _validate_commit_record(self, record: CommitRecord) -> None:
        validate_object_id(record.commit_id, expected_prefix="commit")
        validate_object_id(record.plan_id, expected_prefix="plan")
        validate_object_id(record.transaction_id, expected_prefix="tx")
        if not Path(record.workspace_root).is_absolute():
            raise IntegrityError("commit record workspace root is not absolute")
        expected_quarantine = self.state_root / "quarantine" / record.commit_id
        expected_apply = self.state_root / "apply" / record.commit_id
        if Path(record.quarantine_root) != expected_quarantine:
            raise IntegrityError("commit quarantine path is outside broker state")
        if Path(record.apply_root) != expected_apply:
            raise IntegrityError("commit apply path is outside broker state")
        if record.created_at < 0:
            raise IntegrityError("commit record contains an invalid timestamp")
        try:
            validate_sha256(record.before_digest, name="commit before digest")
            validate_sha256(record.after_digest, name="commit after digest")
        except GuardError as exc:
            raise IntegrityError(str(exc)) from exc
        allowed_statuses = {
            "prepared",
            "committed",
            "rolled_back",
            "rollback_failed",
            "restored",
        }
        if record.status not in allowed_statuses:
            raise IntegrityError(f"unknown commit status: {record.status}")
        seen_paths: set[str] = set()
        for operation in record.operations:
            validate_relative_path(operation.path)
            if operation.path in seen_paths:
                raise IntegrityError("commit record contains duplicate operation paths")
            seen_paths.add(operation.path)
            expected_backup = safe_join(expected_quarantine, operation.path)
            if operation.backup_path is None:
                if operation.before_kind is not None:
                    raise IntegrityError("existing target has no quarantine backup path")
            else:
                if operation.before_kind is None:
                    raise IntegrityError("new target unexpectedly has a quarantine backup")
                if Path(operation.backup_path) != expected_backup:
                    raise IntegrityError("commit backup path is outside quarantine")

    def _rollback_failed_commit(
        self,
        record: CommitRecord,
        workspace: Path,
        baseline: TreeManifest,
    ) -> None:
        quarantine_root = Path(record.quarantine_root)
        failed_new_root = quarantine_root / "_failed_new"
        rollback_errors: list[str] = []
        for operation in reversed(record.operations):
            destination = safe_join(workspace, operation.path)
            backup = (
                Path(operation.backup_path)
                if operation.backup_path is not None
                else None
            )
            try:
                if operation.installed and os.path.lexists(destination):
                    displaced = safe_join(failed_new_root, operation.path)
                    displaced.parent.mkdir(parents=True, exist_ok=True)
                    os.rename(destination, displaced)
                if operation.backup_moved and backup is not None and os.path.lexists(backup):
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    os.rename(backup, destination)
                operation.phase = "rolled_back"
            except OSError as exc:
                rollback_errors.append(f"{operation.path}: {exc}")
        record.status = "rollback_failed" if rollback_errors else "rolled_back"
        self._save_commit(record)
        if not rollback_errors:
            restored = self._scan(workspace)
            if restored.digest != baseline.digest:
                rollback_errors.append("workspace digest differs from baseline after rollback")
        self.audit.append(
            "commit_failed",
            {
                "commit_id": record.commit_id,
                "plan_id": record.plan_id,
                "status": record.status,
                "rollback_errors": rollback_errors,
            },
        )
        if rollback_errors:
            raise IntegrityError(
                "commit failed and rollback was incomplete: " + "; ".join(rollback_errors)
            )

    @contextmanager
    def _workspace_lock(self, workspace: Path) -> Iterator[None]:
        lock_name = digest_json({"workspace": str(workspace)})[:32] + ".lock"
        lock_path = self.state_root / "locks" / lock_name
        try:
            fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise GuardError(f"another broker operation holds the workspace lock: {workspace}") from exc
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(f"pid={os.getpid()}\n")
                handle.flush()
                os.fsync(handle.fileno())
            yield
        finally:
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass
