#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_workspace_guard.shell_gate import inspect_shell_command  # noqa: E402


def main() -> int:
    cases = json.loads((ROOT / "evals" / "destructive_replays.json").read_text())
    failed = 0
    for case in cases:
        actual = inspect_shell_command(case["command"], case["shell"]).decision.value
        status = "PASS" if actual == case["expected"] else "FAIL"
        print(f"{status:4} {case['id']}: expected={case['expected']} actual={actual}")
        failed += actual != case["expected"]
    print(f"\n{len(cases) - failed}/{len(cases)} replay cases passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
