"""Command-line interface for the reference broker."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .broker import WorkspaceGuard
from .errors import GuardError
from .shell_gate import inspect_shell_command


def _json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="awg",
        description="Transactional workspace and commit broker for coding agents",
    )
    parser.add_argument(
        "--state",
        default=os.environ.get("AWG_STATE_ROOT"),
        help="absolute broker state directory (or AWG_STATE_ROOT)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    begin = sub.add_parser("begin", help="create a disposable transaction")
    begin.add_argument("--workspace", required=True)
    begin.add_argument("--task-id", required=True)

    env = sub.add_parser("env", help="print isolated cwd/environment values")
    env.add_argument("--transaction", required=True)

    plan = sub.add_parser("plan", help="create a signed exact-diff commit plan")
    plan.add_argument("--transaction", required=True)
    plan.add_argument("--ttl", type=int, default=1800)

    approve = sub.add_parser("approve", help="approve one exact plan fingerprint")
    approve.add_argument("--plan", required=True)
    approve.add_argument("--actor", required=True)
    approve.add_argument("--ttl", type=int, default=900)

    commit = sub.add_parser("commit", help="quarantine-and-commit an approved plan")
    commit.add_argument("--plan", required=True)
    commit.add_argument("--token")

    restore = sub.add_parser("restore", help="restore a committed workspace from quarantine")
    restore.add_argument("--commit", required=True)

    discard = sub.add_parser("discard", help="destroy a disposable uncommitted transaction")
    discard.add_argument("--transaction", required=True)

    sub.add_parser("verify-audit", help="verify the hash-chained audit log")

    inspect = sub.add_parser("inspect", help="defense-in-depth command inspection")
    inspect.add_argument("--shell", default="unknown")
    source = inspect.add_mutually_exclusive_group(required=True)
    source.add_argument("--command-text")
    source.add_argument("--command-file")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            command = (
                args.command_text
                if args.command_text is not None
                else Path(args.command_file).read_text(encoding="utf-8")
            )
            _json(inspect_shell_command(command, args.shell).to_dict())
            return 0

        if not args.state:
            parser.error("--state or AWG_STATE_ROOT is required for broker operations")
        guard = WorkspaceGuard(args.state)

        if args.command == "begin":
            transaction = guard.begin(args.workspace, task_id=args.task_id)
            _json(
                {
                    "transaction": transaction.to_dict(),
                    "environment": guard.environment(transaction.transaction_id),
                    "cwd": transaction.worktree_root,
                }
            )
        elif args.command == "env":
            transaction = guard.load_transaction(args.transaction)
            _json(
                {
                    "cwd": transaction.worktree_root,
                    "environment": guard.environment(args.transaction),
                }
            )
        elif args.command == "plan":
            _json(guard.plan(args.transaction, ttl_seconds=args.ttl).to_dict())
        elif args.command == "approve":
            _json(
                guard.approve(
                    args.plan, actor=args.actor, ttl_seconds=args.ttl
                ).to_dict()
            )
        elif args.command == "commit":
            _json(guard.commit(args.plan, approval_token=args.token).to_dict())
        elif args.command == "restore":
            _json(guard.restore(args.commit).to_dict())
        elif args.command == "discard":
            guard.discard(args.transaction)
            _json({"discarded": args.transaction})
        elif args.command == "verify-audit":
            _json({"verified_events": guard.verify_audit()})
        else:  # pragma: no cover - argparse guarantees a known command
            parser.error(f"unknown command: {args.command}")
        return 0
    except GuardError as exc:
        print(
            json.dumps(
                {"error": exc.__class__.__name__, "message": str(exc)},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
