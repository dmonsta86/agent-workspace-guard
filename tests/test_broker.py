from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from agent_workspace_guard import GuardPolicy, WorkspaceGuard
from agent_workspace_guard.errors import (
    ApprovalError,
    GuardError,
    IntegrityError,
    PolicyDenied,
    StalePlan,
    UnsafePath,
)
from agent_workspace_guard.models import Decision


class WorkspaceGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.state = self.root / "state"
        self.workspace.mkdir()
        self.state.mkdir()
        (self.workspace / "src").mkdir()
        (self.workspace / "src" / "app.py").write_text("print('old')\n", encoding="utf-8")
        (self.workspace / "notes.txt").write_text("keep me\n", encoding="utf-8")
        self.guard = WorkspaceGuard(self.state)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def begin(self):
        return self.guard.begin(self.workspace, task_id="test-task")

    def test_real_workspace_is_untouched_and_environment_is_isolated(self) -> None:
        transaction = self.begin()
        worktree = Path(transaction.worktree_root)
        (worktree / "src" / "app.py").write_text("print('new')\n", encoding="utf-8")
        (worktree / "notes.txt").unlink()

        self.assertEqual(
            (self.workspace / "src" / "app.py").read_text(encoding="utf-8"),
            "print('old')\n",
        )
        self.assertTrue((self.workspace / "notes.txt").exists())

        env = self.guard.environment(transaction.transaction_id)
        self.assertEqual(env["AWG_WORKTREE"], transaction.worktree_root)
        self.assertEqual(env["HOME"], transaction.home_root)
        self.assertEqual(env["TMPDIR"], transaction.temp_root)
        self.assertEqual(
            env["XDG_CONFIG_HOME"], str(Path(transaction.home_root) / ".config")
        )
        self.assertEqual(
            env["LOCALAPPDATA"],
            str(Path(transaction.home_root) / "AppData" / "Local"),
        )
        self.assertNotEqual(Path(env["HOME"]).resolve(), Path.home().resolve())
        self.assertTrue(Path(env["HOME"]).is_dir())
        self.assertTrue(Path(env["TMPDIR"]).is_dir())

        receipt_path = Path(transaction.transaction_root) / "capability-receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        signature = receipt.pop("signature")
        self.guard.signer.verify(
            {"kind": "capability_receipt", "core": receipt}, signature
        )

    def test_add_only_plan_can_commit_without_approval(self) -> None:
        transaction = self.begin()
        worktree = Path(transaction.worktree_root)
        (worktree / "new.txt").write_text("new content\n", encoding="utf-8")

        plan = self.guard.plan(transaction.transaction_id)
        self.assertEqual(plan.decision, Decision.ALLOW)
        record = self.guard.commit(plan.plan_id)

        self.assertEqual(record.status, "committed")
        self.assertEqual((self.workspace / "new.txt").read_text(), "new content\n")
        self.assertGreaterEqual(self.guard.verify_audit(), 3)

    def test_modify_and_delete_require_approval_and_are_restorable(self) -> None:
        transaction = self.begin()
        worktree = Path(transaction.worktree_root)
        (worktree / "src" / "app.py").write_text("print('new')\n", encoding="utf-8")
        (worktree / "notes.txt").unlink()

        plan = self.guard.plan(transaction.transaction_id)
        self.assertEqual(plan.decision, Decision.REQUIRE_APPROVAL)
        with self.assertRaises(ApprovalError):
            self.guard.commit(plan.plan_id)

        token = self.guard.approve(plan.plan_id, actor="local-user")
        record = self.guard.commit(plan.plan_id, approval_token=token.token_id)
        self.assertEqual((self.workspace / "src" / "app.py").read_text(), "print('new')\n")
        self.assertFalse((self.workspace / "notes.txt").exists())
        self.assertTrue(Path(record.quarantine_root).exists())

        restored = self.guard.restore(record.commit_id)
        self.assertEqual(restored.status, "restored")
        self.assertEqual((self.workspace / "src" / "app.py").read_text(), "print('old')\n")
        self.assertEqual((self.workspace / "notes.txt").read_text(), "keep me\n")

    def test_real_workspace_drift_blocks_commit(self) -> None:
        transaction = self.begin()
        worktree = Path(transaction.worktree_root)
        (worktree / "new.txt").write_text("staged\n", encoding="utf-8")
        plan = self.guard.plan(transaction.transaction_id)
        (self.workspace / "external.txt").write_text("outside change\n", encoding="utf-8")
        with self.assertRaises(StalePlan):
            self.guard.commit(plan.plan_id)

    def test_staged_workspace_drift_blocks_commit(self) -> None:
        transaction = self.begin()
        worktree = Path(transaction.worktree_root)
        (worktree / "new.txt").write_text("v1\n", encoding="utf-8")
        plan = self.guard.plan(transaction.transaction_id)
        (worktree / "new.txt").write_text("v2\n", encoding="utf-8")
        with self.assertRaises(StalePlan):
            self.guard.commit(plan.plan_id)

    def test_policy_change_invalidates_an_existing_plan(self) -> None:
        transaction = self.begin()
        worktree = Path(transaction.worktree_root)
        (worktree / "src" / "app.py").write_text(
            "print('new')\n", encoding="utf-8"
        )
        plan = self.guard.plan(transaction.transaction_id)
        token = self.guard.approve(plan.plan_id, actor="local-user")

        changed_policy_guard = WorkspaceGuard(
            self.state,
            policy=GuardPolicy(auto_add_max_entries=199),
        )
        with self.assertRaises(StalePlan):
            changed_policy_guard.commit(
                plan.plan_id, approval_token=token.token_id
            )

    def test_tampered_plan_is_rejected(self) -> None:
        transaction = self.begin()
        worktree = Path(transaction.worktree_root)
        (worktree / "new.txt").write_text("new\n", encoding="utf-8")
        plan = self.guard.plan(transaction.transaction_id)
        plan_path = self.state / "plans" / f"{plan.plan_id}.json"
        data = json.loads(plan_path.read_text(encoding="utf-8"))
        data["summary"]["added"] = 999
        plan_path.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(IntegrityError):
            self.guard.load_plan(plan.plan_id)

    def test_tampered_transaction_state_is_rejected(self) -> None:
        transaction = self.begin()
        transaction_path = (
            self.state
            / "transactions"
            / transaction.transaction_id
            / "transaction.json"
        )
        data = json.loads(transaction_path.read_text(encoding="utf-8"))
        data["state"] = "committed"
        transaction_path.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(IntegrityError):
            self.guard.load_transaction(transaction.transaction_id)

    def test_tampered_plan_state_is_rejected(self) -> None:
        transaction = self.begin()
        plan = self.guard.plan(transaction.transaction_id)
        plan_path = self.state / "plans" / f"{plan.plan_id}.json"
        data = json.loads(plan_path.read_text(encoding="utf-8"))
        data["state"] = "committed"
        plan_path.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(IntegrityError):
            self.guard.load_plan(plan.plan_id)

    def test_untrusted_object_ids_cannot_traverse_state_paths(self) -> None:
        with self.assertRaises(UnsafePath):
            self.guard.load_transaction("../../secret.key")
        with self.assertRaises(UnsafePath):
            self.guard.load_plan("plan_../../secret")

    def test_mass_deletion_is_hard_denied(self) -> None:
        for index in range(30):
            (self.workspace / f"file-{index}.txt").write_text(str(index), encoding="utf-8")
        guard = WorkspaceGuard(
            self.state,
            policy=GuardPolicy(
                hard_delete_fraction=0.50,
                mass_delete_min_baseline_entries=20,
            ),
        )
        transaction = guard.begin(self.workspace, task_id="mass-delete")
        worktree = Path(transaction.worktree_root)
        for index in range(25):
            (worktree / f"file-{index}.txt").unlink()
        plan = guard.plan(transaction.transaction_id)
        self.assertEqual(plan.decision, Decision.DENY)
        self.assertIn("mass_deletion_denied", [item.code for item in plan.findings])
        with self.assertRaises(PolicyDenied):
            guard.commit(plan.plan_id)

    def test_approval_is_bound_to_one_exact_plan(self) -> None:
        transaction = self.begin()
        worktree = Path(transaction.worktree_root)
        (worktree / "src" / "app.py").write_text("print('v1')\n", encoding="utf-8")
        first = self.guard.plan(transaction.transaction_id)
        token = self.guard.approve(first.plan_id, actor="local-user")

        (worktree / "src" / "app.py").write_text("print('v2')\n", encoding="utf-8")
        second = self.guard.plan(transaction.transaction_id)
        with self.assertRaises(ApprovalError):
            self.guard.commit(second.plan_id, approval_token=token.token_id)

    def test_tampered_baseline_manifest_is_rejected(self) -> None:
        transaction = self.begin()
        baseline_path = Path(transaction.baseline_path)
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
        data["entries"]["notes.txt"]["size"] = 999
        baseline_path.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(IntegrityError):
            self.guard.plan(transaction.transaction_id)

    def test_tampered_baseline_entries_are_recomputed_not_trusted(self) -> None:
        transaction = self.begin()
        baseline_path = Path(transaction.baseline_path)
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
        original_digest = data["digest"]
        data["entries"]["notes.txt"]["digest"] = "f" * 64
        data["digest"] = original_digest
        baseline_path.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(IntegrityError):
            self.guard.plan(transaction.transaction_id)

    def test_state_records_cannot_be_swapped_between_valid_ids(self) -> None:
        first = self.begin()
        second = self.guard.begin(self.workspace, task_id="second-task")
        first_path = (
            self.state / "transactions" / first.transaction_id / "transaction.json"
        )
        second_path = (
            self.state / "transactions" / second.transaction_id / "transaction.json"
        )
        first_path.write_bytes(second_path.read_bytes())
        with self.assertRaises(IntegrityError):
            self.guard.load_transaction(first.transaction_id)

    def test_ttls_are_positive_and_bounded(self) -> None:
        transaction = self.begin()
        with self.assertRaises(GuardError):
            self.guard.plan(transaction.transaction_id, ttl_seconds=0)
        with self.assertRaises(GuardError):
            self.guard.plan(transaction.transaction_id, ttl_seconds=3601)

        plan = self.guard.plan(transaction.transaction_id)
        with self.assertRaises(ApprovalError):
            self.guard.approve(plan.plan_id, actor="local-user", ttl_seconds=0)
        with self.assertRaises(ApprovalError):
            self.guard.approve(plan.plan_id, actor="local-user", ttl_seconds=901)

    def test_directory_to_file_type_change_commits_as_one_operation(self) -> None:
        directory = self.workspace / "replace-me"
        directory.mkdir()
        (directory / "child.txt").write_text("child\n", encoding="utf-8")
        transaction = self.begin()
        worktree = Path(transaction.worktree_root)
        staged_directory = worktree / "replace-me"
        (staged_directory / "child.txt").unlink()
        staged_directory.rmdir()
        staged_directory.write_text("now a file\n", encoding="utf-8")
        plan = self.guard.plan(transaction.transaction_id)
        token = self.guard.approve(plan.plan_id, actor="local-user")
        record = self.guard.commit(plan.plan_id, approval_token=token.token_id)
        self.assertEqual(len(record.operations), 1)
        self.assertEqual((self.workspace / "replace-me").read_text(), "now a file\n")
        self.guard.restore(record.commit_id)
        self.assertEqual((self.workspace / "replace-me" / "child.txt").read_text(), "child\n")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlink_is_never_followed(self) -> None:
        outside = self.root / "outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        try:
            os.symlink(outside, self.workspace / "outside-link")
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        transaction = self.begin()
        worktree = Path(transaction.worktree_root)
        (worktree / "outside-link").unlink()
        plan = self.guard.plan(transaction.transaction_id)
        token = self.guard.approve(plan.plan_id, actor="local-user")
        self.guard.commit(plan.plan_id, approval_token=token.token_id)
        self.assertEqual(outside.read_text(), "outside\n")
        self.assertFalse(os.path.lexists(self.workspace / "outside-link"))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlink_that_escapes_workspace_is_hard_denied(self) -> None:
        transaction = self.begin()
        worktree = Path(transaction.worktree_root)
        try:
            os.symlink("../../outside", worktree / "escape-link")
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        plan = self.guard.plan(transaction.transaction_id)
        self.assertEqual(plan.decision, Decision.DENY)
        self.assertIn("unsafe_symlink_target", [item.code for item in plan.findings])

    def test_new_executable_content_requires_approval(self) -> None:
        transaction = self.begin()
        worktree = Path(transaction.worktree_root)
        executable = worktree / "tool.sh"
        executable.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
        executable.chmod(0o755)
        plan = self.guard.plan(transaction.transaction_id)
        self.assertEqual(plan.decision, Decision.REQUIRE_APPROVAL)
        self.assertIn("executable_file_added", [item.code for item in plan.findings])

    def test_vcs_metadata_is_not_exposed_or_committed(self) -> None:
        git_dir = self.workspace / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("real\n", encoding="utf-8")
        transaction = self.begin()
        worktree = Path(transaction.worktree_root)
        self.assertFalse((worktree / ".git").exists())
        (worktree / "new.txt").write_text("safe\n", encoding="utf-8")
        plan = self.guard.plan(transaction.transaction_id)
        self.assertEqual([change.path for change in plan.changes], ["new.txt"])
        self.guard.commit(plan.plan_id)
        self.assertEqual((git_dir / "config").read_text(), "real\n")

    def test_restore_refuses_to_overwrite_later_work(self) -> None:
        transaction = self.begin()
        worktree = Path(transaction.worktree_root)
        (worktree / "src" / "app.py").write_text("print('new')\n", encoding="utf-8")
        plan = self.guard.plan(transaction.transaction_id)
        token = self.guard.approve(plan.plan_id, actor="local-user")
        record = self.guard.commit(plan.plan_id, approval_token=token.token_id)
        (self.workspace / "later.txt").write_text("later\n", encoding="utf-8")
        with self.assertRaises(StalePlan):
            self.guard.restore(record.commit_id)

    def test_transaction_cannot_commit_two_pending_plans(self) -> None:
        transaction = self.begin()
        first = self.guard.plan(transaction.transaction_id)
        second = self.guard.plan(transaction.transaction_id)
        self.guard.commit(first.plan_id)
        with self.assertRaises(GuardError):
            self.guard.commit(second.plan_id)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_broker_state_subdirectory_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            target = root / "redirected"
            state.mkdir()
            target.mkdir()
            try:
                os.symlink(target, state / "plans", target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaises(UnsafePath):
                WorkspaceGuard(state)

    def test_state_root_may_not_be_inside_workspace(self) -> None:
        nested_state = self.workspace / "state"
        nested_state.mkdir()
        guard = WorkspaceGuard(nested_state)
        with self.assertRaises(UnsafePath):
            guard.begin(self.workspace, task_id="bad-state")


if __name__ == "__main__":
    unittest.main()
