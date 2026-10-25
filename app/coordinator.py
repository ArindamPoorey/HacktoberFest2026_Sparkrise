"""Coordinator orchestrating evaluation, bounded 1x recheck, authorization, execution, and auditing (Section 9.1, 9.2)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from app.audit import AuditStorageError, AuditStore
from app.config import FenceSettings
from app.context import (
    check_targets_in_workspace,
    infer_target_paths,
    pack_context,
    redact_secrets,
    shorten_command,
)
from app.executor.windows import ExecutionBroker, SecurityGateError
from app.notifications import send_block_notification
from app.policy import evaluate_policy, issue_authorization_token, run_local_precheck
from app.providers import DecisionProvider, get_provider
from app.schemas import (
    ActionClass,
    AuditEventRecord,
    DecisionRequest,
    ExecutionResult,
    ExecutionStatus,
    FinalDecision,
    FinalDecisionResult,
    NormalizedDecisionResult,
    NotificationOutcome,
    OperationRequest,
)


@dataclass
class FenceEvaluationOutcome:
    """Complete bundle returned by PermissionFenceCoordinator.handle_operation."""

    operation: OperationRequest
    decision_result: FinalDecisionResult
    execution_result: Optional[ExecutionResult]
    notification_outcome: Optional[NotificationOutcome]
    audit_record: AuditEventRecord


def _collect_enriched_recheck_evidence(
    operation: OperationRequest,
    settings: FenceSettings,
) -> Dict[str, Any]:
    """
    FR-06: Gather additional local deterministic evidence for a single bounded recheck.
    Never simply repeats the identical request without new context.
    """
    targets = operation.context.target_paths or infer_target_paths(
        operation.command, operation.working_directory
    )
    in_workspace, out_of_scope = check_targets_in_workspace(
        targets, operation.working_directory, settings.allowed_workspace_root
    )
    cwd_path = Path(operation.working_directory)

    target_existence: Dict[str, str] = {}
    for t in targets[:8]:
        try:
            p = (cwd_path / t).resolve() if not Path(t).is_absolute() else Path(t).resolve()
            if p.exists():
                target_existence[t] = "directory" if p.is_dir() else f"file ({p.stat().st_size} bytes)"
            else:
                target_existence[t] = "does_not_exist_yet"
        except Exception:
            target_existence[t] = "unresolved"

    cmd_tokens = operation.command.strip().split()
    primary_verb = cmd_tokens[0] if cmd_tokens else ""

    return {
        "deterministic_analysis": {
            "primary_command_verb": primary_verb,
            "inferred_targets": targets,
            "all_targets_within_workspace": in_workspace,
            "out_of_scope_targets": out_of_scope,
            "target_filesystem_state": target_existence,
            "intent_explicitly_supplied": operation.context.intent_provided,
            "stated_user_intent": operation.user_intent or "NONE_PROVIDED",
            "workspace_file_count_sample": len(operation.context.project_files_sample),
        }
    }


class PermissionFenceCoordinator:
    """
    End-to-end orchestrator implementing the PRD data flow:
    Agent/CLI -> Operation -> Context packer -> Local policy pre-check -> Decision provider
    -> Policy evaluation -> Optional one-time recheck -> Authorization token/digest
    -> Executor -> Audit + notification
    """

    def __init__(
        self,
        settings: FenceSettings,
        provider: Optional[DecisionProvider] = None,
        audit_store: Optional[AuditStore] = None,
        executor: Optional[ExecutionBroker] = None,
        emit_cli_notifications: bool = True,
    ) -> None:
        self.settings = settings
        self.provider = provider or get_provider(settings)
        self.audit_store = audit_store or AuditStore(
            db_path=settings.audit_db_path,
            strict_mode=settings.strict_audit_mode,
        )
        self.executor = executor or ExecutionBroker(settings=settings)
        self.emit_cli_notifications = emit_cli_notifications

    def handle_operation(
        self,
        operation: OperationRequest,
        execute_if_allowed: bool = False,
        tamper_command_after_approval: Optional[str] = None,
    ) -> FenceEvaluationOutcome:
        """
        Evaluate an OperationRequest and optionally execute it if authorized.
        - `execute_if_allowed=False` (`check` / `--dry-run`) NEVER executes the command.
        - `execute_if_allowed=True` (`run` / `--execute`) launches the command via ExecutionBroker
          only after policy authorization and strict audit pre-recording succeed.
        """
        extra_secrets = [self.settings.model_api_key] if self.settings.model_api_key else []

        # Step 1: Pack initial context
        packed_initial = pack_context(operation=operation, settings=self.settings, recheck_attempt=0)

        # Step 2: Run deterministic local pre-checks
        precheck = run_local_precheck(operation=operation, settings=self.settings)

        first_model_result: NormalizedDecisionResult
        recheck_model_result: Optional[NormalizedDecisionResult] = None
        recheck_count = 0
        first_decision: FinalDecision
        recheck_decision: Optional[FinalDecision] = None
        final_decision: FinalDecision
        reason_code: str
        explanation: str

        # Step 3: Mandatory local precheck block short-circuits model evaluation for speed and safety (Section 9.2)
        if precheck.mandatory_block or not precheck.passed:
            first_model_result = NormalizedDecisionResult(
                provider=self.provider.provider_name,
                model_id=self.settings.model_id,
                action_class=ActionClass.SECURITY_SENSITIVE,
                confidence=1.0,
                confidence_source_field="local_deterministic_precheck",
                latency_ms=0.0,
                is_valid_schema=True,
            )
            first_decision = FinalDecision.BLOCK
            final_decision = FinalDecision.BLOCK
            reason_code = precheck.reason_code
            explanation = precheck.explanation
        else:
            # Step 4: First evaluation via configured System 1 provider
            req_initial = DecisionRequest(
                operation_id=operation.operation_id,
                packed_context=packed_initial,
                is_recheck=False,
            )
            first_model_result = self.provider.evaluate(req_initial)
            first_decision, reason_code, explanation = evaluate_policy(
                operation=operation,
                precheck=precheck,
                model_result=first_model_result,
                settings=self.settings,
                is_recheck=False,
            )
            final_decision = first_decision

            # Step 5: Bounded 1x recheck with enriched local evidence if first result is RECHECK
            max_rechecks = min(1, max(0, self.settings.max_rechecks))
            if first_decision == FinalDecision.RECHECK:
                if max_rechecks >= 1:
                    recheck_count = 1
                    enriched_evidence = _collect_enriched_recheck_evidence(
                        operation=operation, settings=self.settings
                    )
                    operation.context.recheck_evidence = enriched_evidence
                    packed_recheck = pack_context(
                        operation=operation,
                        settings=self.settings,
                        recheck_attempt=1,
                        prior_decision_reason=f"{reason_code}: {explanation}",
                        additional_recheck_evidence=enriched_evidence,
                    )
                    req_recheck = DecisionRequest(
                        operation_id=operation.operation_id,
                        packed_context=packed_recheck,
                        is_recheck=True,
                    )
                    recheck_model_result = self.provider.evaluate(req_recheck)
                    recheck_decision, reason_code, explanation = evaluate_policy(
                        operation=operation,
                        precheck=precheck,
                        model_result=recheck_model_result,
                        settings=self.settings,
                        is_recheck=True,
                    )
                    # FR-06: If recheck still returns RECHECK/uncertain, fail closed to BLOCK
                    if recheck_decision != FinalDecision.ALLOW:
                        recheck_decision = FinalDecision.BLOCK
                    final_decision = recheck_decision
                else:
                    final_decision = FinalDecision.BLOCK
                    reason_code = "BLOCKED_RECHECK_DISABLED"
                    explanation = "Initial evaluation was uncertain and automatic rechecks are disabled (MAX_RECHECKS=0)."

        # Step 6: Issue SHA-256 bound AuthorizationToken only if ALLOW
        auth_token = issue_authorization_token(
            operation=operation,
            decision=final_decision,
            reason_code=reason_code,
        )

        initial_exec_status = (
            ExecutionStatus.PENDING
            if (final_decision == FinalDecision.ALLOW and execute_if_allowed)
            else ExecutionStatus.NOT_EXECUTED
        )

        decision_result = FinalDecisionResult(
            operation_id=operation.operation_id,
            decision=final_decision,
            reason_code=reason_code,
            explanation=explanation,
            recheck_count=recheck_count,
            authorized_command_digest=auth_token.authorized_command_digest if auth_token else None,
            execution_status=initial_exec_status,
            first_decision=first_decision,
            recheck_decision=recheck_decision,
            first_model_result=first_model_result,
            recheck_model_result=recheck_model_result,
            precheck_result=precheck,
            authorization_token=auth_token,
        )

        # Effective model result for audit summary (use recheck model result if performed)
        active_model = recheck_model_result if recheck_model_result is not None else first_model_result
        total_latency_ms = first_model_result.latency_ms + (
            recheck_model_result.latency_ms if recheck_model_result else 0.0
        )

        notification_outcome: Optional[NotificationOutcome] = None
        notification_status = "NONE"
        notification_msg = ""

        # Step 7: Notify user on every BLOCK
        if final_decision == FinalDecision.BLOCK:
            notification_outcome = send_block_notification(
                operation=operation,
                decision_result=decision_result,
                enable_windows_toast=self.settings.enable_windows_toast,
                extra_secrets=extra_secrets,
                emit_to_stderr=self.emit_cli_notifications,
            )
            if notification_outcome.notification_error:
                notification_status = f"CLI_ONLY ({notification_outcome.notification_error})"
            elif notification_outcome.toast_succeeded:
                notification_status = "CLI_AND_TOAST"
            else:
                notification_status = "CLI_DELIVERED"
            notification_msg = notification_outcome.cli_message

        # Build AuditEventRecord before execution (Section 14: in strict mode, do not execute unless audit can be recorded)
        audit_record = AuditEventRecord(
            operation_id=operation.operation_id,
            timestamp=operation.timestamp,
            command_summary=shorten_command(operation.command, max_len=80, extra_secrets=extra_secrets),
            full_redacted_command=redact_secrets(operation.command, extra_secrets=extra_secrets),
            shell=operation.shell,
            working_directory=operation.working_directory,
            invocation_source=operation.invocation_source,
            user_intent_summary=(
                redact_secrets(operation.user_intent, extra_secrets=extra_secrets)
                if operation.user_intent
                else None
            ),
            redacted_context_summary=json.dumps(
                {
                    "target_paths": operation.context.target_paths,
                    "intent_provided": operation.context.intent_provided,
                    "recheck_count": recheck_count,
                },
                sort_keys=True,
            ),
            context_hash=packed_initial.context_hash,
            provider=active_model.provider,
            model_id=active_model.model_id,
            model_version=active_model.model_version,
            endpoint_label=self.settings.full_endpoint_url,
            latency_ms=round(total_latency_ms, 2),
            usage_json=json.dumps(active_model.usage) if active_model.usage else None,
            action_class=active_model.action_class.value,
            confidence=active_model.confidence,
            scores_json=json.dumps(active_model.scores.model_dump()),
            first_decision=first_decision.value,
            recheck_decision=recheck_decision.value if recheck_decision else None,
            final_decision=final_decision.value,
            recheck_count=recheck_count,
            policy_reason_code=reason_code,
            policy_explanation=explanation,
            authorization_digest=auth_token.authorized_command_digest if auth_token else None,
            execution_status=initial_exec_status.value,
            notification_status=notification_status,
            notification_message=notification_msg,
        )

        # Persist pre-execution audit record (strict mode raises AuditStorageError and prevents execution)
        try:
            self.audit_store.record_event(audit_record)
        except AuditStorageError as exc:
            decision_result.decision = FinalDecision.BLOCK
            decision_result.reason_code = "STRICT_AUDIT_FAILURE"
            decision_result.explanation = f"Blocked because audit event could not be recorded: {exc}"
            decision_result.execution_status = ExecutionStatus.NOT_EXECUTED
            return FenceEvaluationOutcome(
                operation=operation,
                decision_result=decision_result,
                execution_result=None,
                notification_outcome=notification_outcome,
                audit_record=audit_record,
            )

        # Step 8: Execute ONLY if execute_if_allowed=True and final_decision == ALLOW
        execution_result: Optional[ExecutionResult] = None
        if execute_if_allowed and final_decision == FinalDecision.ALLOW:
            # Optional hook used by security tests to simulate post-approval command tampering
            if tamper_command_after_approval is not None:
                operation.command = tamper_command_after_approval

            try:
                execution_result = self.executor.execute(operation=operation, token=auth_token)
                decision_result.execution_status = execution_result.execution_status
                audit_record.start_time = execution_result.start_time
                audit_record.end_time = execution_result.end_time
                audit_record.exit_code = execution_result.exit_code
                audit_record.execution_status = execution_result.execution_status.value
                if self.settings.persist_execution_output:
                    audit_record.redacted_stdout = execution_result.redacted_stdout
                    audit_record.redacted_stderr = execution_result.redacted_stderr
            except SecurityGateError as gate_err:
                # Command or working directory changed after approval -> Invalidate authorization and block
                decision_result.decision = FinalDecision.BLOCK
                decision_result.reason_code = "AUTHORIZATION_DIGEST_INVALIDATED"
                decision_result.explanation = str(gate_err)
                decision_result.execution_status = ExecutionStatus.NOT_EXECUTED

                execution_result = ExecutionResult(
                    operation_id=operation.operation_id,
                    execution_status=ExecutionStatus.NOT_EXECUTED,
                    error_message=str(gate_err),
                    digest_verified=False,
                )
                notification_outcome = send_block_notification(
                    operation=operation,
                    decision_result=decision_result,
                    enable_windows_toast=self.settings.enable_windows_toast,
                    extra_secrets=extra_secrets,
                    emit_to_stderr=self.emit_cli_notifications,
                )
                audit_record.final_decision = FinalDecision.BLOCK.value
                audit_record.policy_reason_code = "AUTHORIZATION_DIGEST_INVALIDATED"
                audit_record.policy_explanation = str(gate_err)
                audit_record.execution_status = ExecutionStatus.NOT_EXECUTED.value
                audit_record.notification_status = "CLI_DELIVERED"
                audit_record.notification_message = notification_outcome.cli_message

            # Update audit record with post-execution state
            try:
                self.audit_store.record_event(audit_record)
            except AuditStorageError:
                pass

        return FenceEvaluationOutcome(
            operation=operation,
            decision_result=decision_result,
            execution_result=execution_result,
            notification_outcome=notification_outcome,
            audit_record=audit_record,
        )
