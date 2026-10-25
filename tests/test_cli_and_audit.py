"""Integration tests for CLI commands (check vs run), file creation/deletion, and SQLite audit history (Section 16, 17)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.audit import AuditStore
from app.main import main


class TestCliAndAuditIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory(prefix="fence_test_cli_")
        self.workspace = str(Path(self.tmp_dir.name).resolve())
        self.db_path = str(Path(self.workspace) / "cli_audit.db")

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_check_command_never_executes(self) -> None:
        """Acceptance Criterion 2: A command submitted through `check` is NEVER launched."""
        target_file = Path(self.workspace) / "should_not_be_created.txt"
        exit_code = main(
            [
                "--provider",
                "mock",
                "--db-path",
                self.db_path,
                "--json",
                "check",
                "--cwd",
                self.workspace,
                "--command",
                f'New-Item -Path "{target_file.name}" -ItemType File -Value "hello"',
                "--intent",
                "Create a test file in the workspace",
            ]
        )
        self.assertEqual(exit_code, 0)
        self.assertFalse(target_file.exists(), "check command must never create or modify files!")

        store = AuditStore(db_path=self.db_path)
        events = store.list_recent(limit=5)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].final_decision, "ALLOW")
        self.assertEqual(events[0].execution_status, "NOT_EXECUTED")

    def test_run_command_evaluates_and_executes_safe_file_creation(self) -> None:
        """Acceptance Criterion 1 & Section 16: Safe file creation runs only after evaluation and authorization."""
        target_file = Path(self.workspace) / "created_by_run.txt"
        exit_code = main(
            [
                "--provider",
                "mock",
                "--db-path",
                self.db_path,
                "--json",
                "run",
                "--cwd",
                self.workspace,
                "--command",
                f'New-Item -Path "{target_file.name}" -ItemType File -Value "hello_fence"',
                "--intent",
                "Create a disposable test file in the workspace",
            ]
        )
        self.assertEqual(exit_code, 0)
        self.assertTrue(target_file.exists())
        self.assertEqual(target_file.read_text(encoding="utf-8"), "hello_fence")

        store = AuditStore(db_path=self.db_path)
        events = store.list_recent(limit=5)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].final_decision, "ALLOW")
        self.assertEqual(events[0].execution_status, "SUCCEEDED")

    def test_disposable_file_deletion_is_blocked_and_file_remains_intact(self) -> None:
        """Acceptance Criterion 8 & Section 16: File deletion is blocked, file is untouched, and audit event is saved."""
        disposable_file = Path(self.workspace) / "important_demo.txt"
        disposable_file.write_text("do not delete me", encoding="utf-8")

        exit_code = main(
            [
                "--provider",
                "mock",
                "--db-path",
                self.db_path,
                "--json",
                "run",
                "--cwd",
                self.workspace,
                "--command",
                f"Remove-Item .\\{disposable_file.name}",
                "--intent",
                "Check workspace files",
            ]
        )
        self.assertEqual(exit_code, 3)  # Blocked exit code
        self.assertTrue(disposable_file.exists(), "Blocked Remove-Item must not delete the file!")

        store = AuditStore(db_path=self.db_path)
        events = store.list_recent(limit=5)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].final_decision, "BLOCK")
        self.assertEqual(events[0].execution_status, "NOT_EXECUTED")
        self.assertIn("BLOCKED.", events[0].notification_message)
        self.assertIn("was not executed", events[0].notification_message)


if __name__ == "__main__":
    unittest.main()
