from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from agent_workspace_guard.audit import AuditLog
from agent_workspace_guard.crypto import StateSigner
from agent_workspace_guard.errors import IntegrityError


class AuditLogTests(unittest.TestCase):
    def test_hash_chain_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            log = AuditLog(path)
            log.append("one", {"value": 1})
            log.append("two", {"value": 2})
            self.assertEqual(log.verify(), 2)

            lines = path.read_text(encoding="utf-8").splitlines()
            row = json.loads(lines[0])
            row["payload"]["value"] = 9
            lines[0] = json.dumps(row)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaises(IntegrityError):
                log.verify()

    def test_signed_chain_rejects_recomputed_unkeyed_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signer = StateSigner(root / "secret.key")
            path = root / "audit.jsonl"
            log = AuditLog(path, signer=signer)
            log.append("one", {"value": 1})
            self.assertEqual(log.verify(), 1)

            row = json.loads(path.read_text(encoding="utf-8"))
            row.pop("event_signature")
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")
            with self.assertRaises(IntegrityError):
                log.verify()

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_signing_key_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.key"
            target.write_bytes(b"x" * 32)
            key_path = root / "secret.key"
            try:
                os.symlink(target, key_path)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaises(IntegrityError):
                StateSigner(key_path)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_audit_log_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.jsonl"
            target.write_text("", encoding="utf-8")
            audit_path = root / "audit.jsonl"
            try:
                os.symlink(target, audit_path)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaises(IntegrityError):
                AuditLog(audit_path)

    def test_constructor_and_append_refuse_a_corrupt_existing_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            log = AuditLog(path)
            log.append("one", {"value": 1})
            path.write_text('{"not":"a valid chain row"}\n', encoding="utf-8")
            with self.assertRaises(IntegrityError):
                AuditLog(path)
            with self.assertRaises(IntegrityError):
                log.append("two", {"value": 2})

    def test_threaded_appends_preserve_one_linear_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            log = AuditLog(path)
            threads = [
                threading.Thread(target=log.append, args=("event", {"index": index}))
                for index in range(20)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(log.verify(), 20)


if __name__ == "__main__":
    unittest.main()
