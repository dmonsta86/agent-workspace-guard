#!/usr/bin/env python3
"""Safe local demonstration using a temporary toy workspace.

This does not launch an untrusted agent. It demonstrates transaction, plan,
approval, commit, quarantine, and restore semantics.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from agent_workspace_guard import Decision, WorkspaceGuard


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        workspace = root / "project"
        state = root / "broker-state"
        workspace.mkdir()
        state.mkdir()
        (workspace / "hello.txt").write_text("before\n", encoding="utf-8")

        guard = WorkspaceGuard(state)
        transaction = guard.begin(workspace, task_id="demo")
        staged = Path(transaction.worktree_root)
        (staged / "hello.txt").write_text("after\n", encoding="utf-8")
        (staged / "new.txt").write_text("new\n", encoding="utf-8")

        print("Real file before commit:", (workspace / "hello.txt").read_text().strip())
        plan = guard.plan(transaction.transaction_id)
        print("Decision:", plan.decision.value)
        print("Summary:", plan.summary)
        print("Fingerprint:", plan.fingerprint)

        if plan.decision is Decision.REQUIRE_APPROVAL:
            token = guard.approve(plan.plan_id, actor="demo-user")
            commit = guard.commit(plan.plan_id, approval_token=token.token_id)
        else:
            commit = guard.commit(plan.plan_id)

        print("Real file after commit:", (workspace / "hello.txt").read_text().strip())
        print("Quarantine:", commit.quarantine_root)
        guard.restore(commit.commit_id)
        print("Real file after restore:", (workspace / "hello.txt").read_text().strip())
        print("Audit events verified:", guard.verify_audit())


if __name__ == "__main__":
    main()
