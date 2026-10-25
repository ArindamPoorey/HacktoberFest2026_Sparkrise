"""Typed Pydantic data contracts for Permission Fence (FR-01 to FR-09, Section 12)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.config import compat_validator


class CompatBaseModel(BaseModel):
    """BaseModel subclass providing `.model_dump()` compatibility across Pydantic v1 and v2."""

    def model_dump(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:  # type: ignore
        if hasattr(super(), "model_dump"):
            return super().model_dump(*args, **kwargs)  # type: ignore
        return self.dict(*args, **kwargs)


class ActionClass(str, Enum):
    READ_ONLY = "read_only"
    ROUTINE_MUTATION = "routine_mutation"
    DESTRUCTIVE_MUTATION = "destructive_mutation"
    SECURITY_SENSITIVE = "security_sensitive"
    UNCLEAR = "unclear"


class FinalDecision(str, Enum):
    ALLOW = "ALLOW"
    RECHECK = "RECHECK"
    BLOCK = "BLOCK"


class ExecutionStatus(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    NOT_EXECUTED = "NOT_EXECUTED"


class OperationContextMetadata(CompatBaseModel):
    """Structured context metadata attached to an OperationRequest."""

    target_paths: List[str] = Field(default_factory=list)
    git_summary: Optional[str] = None
    intent_provided: bool = False
    target_inferred: bool = False
    recheck_evidence: Optional[Dict[str, Any]] = None
    project_files_sample: List[str] = Field(default_factory=list)


class OperationRequest(CompatBaseModel):
    """FR-01 & Section 12: Standardized operation intake record."""

    operation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    command: str = Field(..., description="Exact proposed command string")
    shell: str = Field(default="powershell", description="Target shell type")
    working_directory: str = Field(..., description="Validated working directory path")
    user_intent: Optional[str] = Field(
        default=None, description="Original user request or stated intent, if available"
    )
    invocation_source: str = Field(
        default="cli", description="cli, agent-hook, dashboard, or test"
    )
    agent_name: Optional[str] = Field(default=None, description="Coding agent name if known")
    environment: str = Field(default="local-development")
    context: OperationContextMetadata = Field(default_factory=OperationContextMetadata)

    @compat_validator("command")
    @classmethod
    def validate_non_empty_command(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Command cannot be empty or whitespace only.")
        return cleaned

    @compat_validator("shell")
    @classmethod
    def validate_shell(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned not in {"powershell", "pwsh", "cmd", "sh", "bash"}:
            raise ValueError(f"Unsupported shell '{value}'.")
        return cleaned


class PackedContext(CompatBaseModel):
    """FR-02: Redacted, minimal context package prepared for a System 1 provider."""

    operation_id: str
    redacted_command: str
    shell: str
    working_directory: str
    allowed_workspace_root: str
    redacted_user_intent: Optional[str] = None
    intent_explicitly_supplied: bool = False
    inferred_target_paths: List[str] = Field(default_factory=list)
    targets_within_workspace: bool = True
    invocation_source: str = "cli"
    agent_name: Optional[str] = None
    environment: str = "local-development"
    git_summary: Optional[str] = None
    project_files_sample: List[str] = Field(default_factory=list)
    recheck_attempt: int = 0
    prior_decision_reason: Optional[str] = None
    additional_recheck_evidence: Optional[Dict[str, Any]] = None
    context_hash: str = Field(..., description="SHA-256 hash of the packed context state")


class DecisionRequest(CompatBaseModel):
    """FR-03 & FR-04: Request sent to a DecisionProvider adapter."""

    operation_id: str
    packed_context: PackedContext
    is_recheck: bool = False


class DecisionScores(CompatBaseModel):
    """FR-04 & FR-06: Distinct probability scores returned by atomic System 1 questions."""

    matches_user_intent: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="Noul probability that action is directly justified by intent"
    )
    target_in_scope: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="Noul probability that target is within authorized scope"
    )
    unintended_damage_risk: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="Probability/score of unintended loss or side effects"
    )
    needs_human_review: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="Noul probability that human review is needed"
    )


class NormalizedDecisionResult(CompatBaseModel):
    """FR-03 & Section 12: Normalized decision result from any System 1 provider."""

    provider: str
    model_id: str
    model_version: Optional[str] = None
    action_class: ActionClass = ActionClass.UNCLEAR
    action_class_probabilities: Dict[str, float] = Field(default_factory=dict)
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Normalized confidence of the selected action_class choice (from answers.action_class.confidence or top probability)",
    )
    confidence_source_field: str = Field(
        default="answers.action_class.confidence",
        description="Documents which exact provider field produced the normalized confidence score (FR-06)",
    )
    scores: DecisionScores = Field(default_factory=DecisionScores)
    latency_ms: float = 0.0
    request_id: Optional[str] = None
    usage: Optional[Dict[str, int]] = None
    raw_sanitized_summary: Optional[Dict[str, Any]] = None
    provider_error: Optional[str] = None
    is_valid_schema: bool = True


class LocalPrecheckResult(CompatBaseModel):
    """Result of deterministic local pre-checks before or alongside model evaluation."""

    passed: bool = True
    mandatory_block: bool = False
    reason_code: str = "PRECHECK_OK"
    explanation: str = "Deterministic pre-checks passed."
    matched_rule: Optional[str] = None
    out_of_scope_targets: List[str] = Field(default_factory=list)
    protected_path_hits: List[str] = Field(default_factory=list)


class AuthorizationToken(CompatBaseModel):
    """FR-07: Cryptographically bound authorization object accepted by the Execution Broker."""

    operation_id: str
    decision: FinalDecision
    authorized_command: str
    shell: str
    working_directory: str
    target_paths: List[str] = Field(default_factory=list)
    authorized_command_digest: str = Field(
        ..., description="sha256:<hex> binding command, shell, working_directory, and target_paths"
    )
    issued_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    reason_code: str


class FinalDecisionResult(CompatBaseModel):
    """Section 12: Final decision contract returned by Policy & Coordinator."""

    operation_id: str
    decision: FinalDecision
    reason_code: str
    explanation: str
    recheck_count: int = 0
    authorized_command_digest: Optional[str] = None
    execution_status: ExecutionStatus = ExecutionStatus.NOT_EXECUTED
    first_decision: Optional[FinalDecision] = None
    recheck_decision: Optional[FinalDecision] = None
    first_model_result: Optional[NormalizedDecisionResult] = None
    recheck_model_result: Optional[NormalizedDecisionResult] = None
    precheck_result: Optional[LocalPrecheckResult] = None
    authorization_token: Optional[AuthorizationToken] = None


class ExecutionResult(CompatBaseModel):
    """FR-07: Result captured by the Execution Broker."""

    operation_id: str
    execution_status: ExecutionStatus
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_ms: float = 0.0
    exit_code: Optional[int] = None
    redacted_stdout: str = ""
    redacted_stderr: str = ""
    error_message: Optional[str] = None
    digest_verified: bool = False


class NotificationOutcome(CompatBaseModel):
    """FR-08: Record of user notification delivery."""

    notified: bool = False
    cli_message: str = ""
    toast_attempted: bool = False
    toast_succeeded: bool = False
    notification_error: Optional[str] = None


class AuditEventRecord(CompatBaseModel):
    """FR-09: Full auditable record persisted to SQLite."""

    operation_id: str
    timestamp: str
    command_summary: str
    full_redacted_command: str
    shell: str
    working_directory: str
    invocation_source: str
    user_intent_summary: Optional[str] = None
    redacted_context_summary: str
    context_hash: str
    provider: str
    model_id: str
    model_version: Optional[str] = None
    endpoint_label: str
    latency_ms: float = 0.0
    usage_json: Optional[str] = None
    action_class: str = ActionClass.UNCLEAR.value
    confidence: Optional[float] = None
    scores_json: str = "{}"
    first_decision: str
    recheck_decision: Optional[str] = None
    final_decision: str
    recheck_count: int = 0
    policy_reason_code: str
    policy_explanation: str
    authorization_digest: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    exit_code: Optional[int] = None
    execution_status: str = ExecutionStatus.NOT_EXECUTED.value
    redacted_stdout: str = ""
    redacted_stderr: str = ""
    notification_status: str = "NONE"
    notification_message: str = ""
