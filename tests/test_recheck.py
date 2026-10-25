"""Integration tests for the 1-recheck cap, enriched recheck evidence, and fail-closed behavior (Section 16)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.audit import AuditStore
from app.config import FenceSettings
from app.context import build_operation_request
from app.coordinator import PermissionFenceCoordinator
from app.providers.mock import MockProvider
from app.schemas import ExecutionStatus, FinalDecision


class TestRecheckAndFailClosed(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory(prefix="fence_test_recheck_")
        self.workspace = str(Path(self.tmp_dir.name).resolve())
        self.db_path = str(Path(self.workspace) / "test_audit.db")
        self.settings = FenceSettings(
            model_provider="mock",
            allow_threshold=0.90,
            recheck_threshold=0.90,
            max_rechecks=1,
            allowed_workspace_root=self.workspace,
            audit_db_path=self.db_path,
            enable_windows_toast=False,
        )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_low_confidence_triggers_single_recheck_and_allows_when_resolved(self) -> None:
        """Section 16: Uncertain initial result triggers 1 recheck with enriched context and allows if resolved."""
        provider = MockProvider(self.settings, scenario_override="uncertain_then_allow")
        store = AuditStore(db_path=self.db_path, strict_mode=True)
        coordinator = PermissionFenceCoordinator(
            settings=self.settings,
            provider=provider,
            audit_store=store,
            emit_cli_notifications=False,
        )

        op = build_operation_request(
            command="Get-ChildItem .",
            working_directory=self.workspace,
            user_intent="List workspace directory contents",
        )
        outcome = coordinator.handle_operation(op, execute_if_allowed=True)

        self.assertEqual(provider.call_count, 2)  # Initial + 1 recheck
        self.assertEqual(outcome.decision_result.recheck_count, 1)
        self.assertEqual(outcome.decision_result.first_decision, FinalDecision.RECHECK)
        self.assertEqual(outcome.decision_result.decision, FinalDecision.ALLOW)
        self.assertEqual(outcome.decision_result.execution_status, ExecutionStatus.SUCCEEDED)
        self.assertIsNotNone(op.context.recheck_evidence)

    def test_recheck_still_uncertain_caps_at_one_and_blocks_without_process_creation(self) -> None:
        """Section 16: Uncertain result after 1 recheck never loops infinitely; it blocks and creates no process."""
        provider = MockProvider(self.settings, scenario_override="always_uncertain")
        store = AuditStore(db_path=self.db_path, strict_mode=True)
        coordinator = PermissionFenceCoordinator(
            settings=self.settings,
            provider=provider,
            audit_store=store,
            emit_cli_notifications=False,
        )

        marker_file = Path(self.workspace) / "should_not_exist.txt"
        op = build_operation_request(
            command=f'New-Item -Path "{marker_file.name}" -ItemType File -Value "created"',
            working_directory=self.workspace,
            user_intent="Uncertain operation",
        )
        outcome = coordinator.handle_operation(op, execute_if_allowed=True)

        self.assertEqual(provider.call_count, 2)  # Strictly capped at 1 initial + 1 recheck
        self.assertEqual(outcome.decision_result.recheck_count, 1)
        self.assertEqual(outcome.decision_result.decision, FinalDecision.BLOCK)
        self.assertEqual(outcome.decision_result.execution_status, ExecutionStatus.NOT_EXECUTED)
        self.assertIsNone(outcome.execution_result)
        self.assertFalse(marker_file.exists())
        self.assertIsNotNone(outcome.notification_outcome)
        self.assertIn("was not executed", outcome.notification_outcome.cli_message)

    def test_provider_timeout_and_auth_error_fail_closed(self) -> None:
        """Section 14 & 16: Provider timeout or auth failure immediately fails closed and does not execute."""
        for error_scenario in ("timeout", "auth_error"):
            provider = MockProvider(self.settings, scenario_override=error_scenario)
            coordinator = PermissionFenceCoordinator(
                settings=self.settings,
                provider=provider,
                emit_cli_notifications=False,
            )
            op = build_operation_request(
                command="Get-ChildItem .",
                working_directory=self.workspace,
                user_intent="List files",
            )
            outcome = coordinator.handle_operation(op, execute_if_allowed=True)
            self.assertEqual(outcome.decision_result.decision, FinalDecision.BLOCK)
            self.assertEqual(outcome.decision_result.reason_code, "FAIL_CLOSED_PROVIDER_OR_SCHEMA_ERROR")
            self.assertEqual(outcome.decision_result.execution_status, ExecutionStatus.NOT_EXECUTED)
            self.assertIsNone(outcome.execution_result)


if __name__ == "__main__":
    unittest.main()
