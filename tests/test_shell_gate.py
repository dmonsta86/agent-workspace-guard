from __future__ import annotations

import json
import unittest
from pathlib import Path

from agent_workspace_guard.models import Decision
from agent_workspace_guard.shell_gate import inspect_shell_command


class ShellGateReplayTests(unittest.TestCase):
    def test_replay_corpus(self) -> None:
        corpus = Path(__file__).parents[1] / "evals" / "destructive_replays.json"
        cases = json.loads(corpus.read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["id"]):
                result = inspect_shell_command(case["command"], case["shell"])
                self.assertEqual(result.decision.value, case["expected"])

    def test_cross_shell_warning_does_not_claim_safety_boundary(self) -> None:
        result = inspect_shell_command("Get-Process 2>/dev/null", "powershell")
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertIn("not the security boundary", result.boundary_note)
        self.assertIn("cross_shell_redirection", [item.code for item in result.findings])

    def test_empty_command_fails_closed(self) -> None:
        self.assertEqual(inspect_shell_command("", "bash").decision, Decision.DENY)

    def test_inspection_output_does_not_echo_command_secrets(self) -> None:
        secret = "token=super-secret-value"
        result = inspect_shell_command(f"printf '%s' '{secret}'", "bash").to_dict()
        serialized = json.dumps(result)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("printf", serialized)
        self.assertEqual(result["command_length"], len(f"printf '%s' '{secret}'"))
        self.assertRegex(result["command_sha256"], r"^[0-9a-f]{64}$")

    def test_normal_path_customization_is_not_treated_as_temp_identity_mutation(self) -> None:
        result = inspect_shell_command('PATH="./bin:$PATH" make test', "bash")
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertNotIn(
            "reserved_environment_mutation", [item.code for item in result.findings]
        )


if __name__ == "__main__":
    unittest.main()
