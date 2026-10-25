"""Unit and integration tests for ExecutionBroker security gate and SHA-256 digest binding (FR-07, Section 16)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.config import FenceSettings
from app.context import build_operation_request, compute_authorization_digest
from app.coordinator import PermissionFenceCoordinator
from app.executor.windows import ExecutionBroker, SecurityGateError
from app.policy import issue_authorization_token
from app.providers.mock import MockProvider
from app.schemas import ExecutionStatus, FinalDecision


class TestExecutorGate(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory(prefix="fence_test_exec_")
        self.workspace = str(Path(self.tmp_dir.name).resolve())
        self.db_path = str(Path(self.workspace) / "test_audit.db")
        self.settings = FenceSettings(
            model_provider="mock",
            allowed_workspace_root=self.workspace,
            audit_db_path=self.db_path,
            enable_windows_toast=False,
        )
        self.broker = ExecutionBroker(self.settings)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_digest_changes_when_command_or_cwd_changes(self) -> None:
        """Section 16: Authorization digest changes when command, shell, or working directory changes."""
        d1 = compute_authorization_digest("Get-ChildItem .", "powershell", self.workspace, ["."])
        d2 = compute_authorization_digest("Get-ChildItem -Force .", "powershell", self.workspace, ["."])
        d3 = compute_authorization_digest("Get-ChildItem .", "cmd", self.workspace, ["."])
        d4 = compute_authorization_digest("Get-ChildItem .", "powershell", str(Path(self.workspace).parent), ["."])

        self.assertNotEqual(d1, d2)
        self.assertNotEqual(d1, d3)
        self.assertNotEqual(d1, d4)

    def test_executor_rejects_missing_or_tampered_authorization_token(self) -> None:
        """FR-07 & Section 16: Executor rejects missing token or command modified after approval."""
        op = build_operation_request(
            command="Get-ChildItem .",
            working_directory=self.workspace,
            user_intent="List files",
        )

        # 1. Missing token
        with self.assertRaises(SecurityGateError):
            self.broker.execute(op, token=None)

        # 2. Valid token issued, then command tampered before execute()
        token = issue_authorization_token(op, FinalDecision.ALLOW, "HIGH_CONFIDENCE_IN_SCOPE")
        self.assertIsNotNone(token)

        op.command = "Remove-Item .\\important.txt"
        with self.assertRaises(SecurityGateError):
            self.broker.execute(op, token=token)

    def test_coordinator_blocks_post_approval_command_tampering(self) -> None:
        """Integration check: Coordinator invalidates authorization and records BLOCK if command changes post-approval."""
        coordinator = PermissionFenceCoordinator(
            settings=self.settings,
            provider=MockProvider(self.settings),
            emit_cli_notifications=False,
        )
        op = build_operation_request(
            command="Get-ChildItem .",
            working_directory=self.workspace,
            user_intent="List workspace files",
        )
        outcome = coordinator.handle_operation(
            op,
            execute_if_allowed=True,
            tamper_command_after_approval="Remove-Item .\\important.txt",
        )
        self.assertEqual(outcome.decision_result.decision, FinalDecision.BLOCK)
        self.assertEqual(outcome.decision_result.reason_code, "AUTHORIZATION_DIGEST_INVALIDATED")
        self.assertEqual(outcome.decision_result.execution_status, ExecutionStatus.NOT_EXECUTED)
        self.assertEqual(outcome.audit_record.final_decision, "BLOCK")


if __name__ == "__main__":
    unittest.main()
