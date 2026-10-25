"""Deterministic local policy rules, threshold evaluation, and authorization token issuance (FR-05, FR-06, Section 8)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Tuple

from app.config import FenceSettings
from app.context import check_targets_in_workspace, compute_authorization_digest
from app.schemas import (
    ActionClass,
    AuthorizationToken,
    FinalDecision,
    LocalPrecheckResult,
    NormalizedDecisionResult,
    OperationRequest,
)


def _matches_protected_path(
    command: str,
    target_paths: List[str],
    working_directory: str,
    protected_paths: List[str],
) -> List[str]:
    """Identify any protected path referenced in the command or inferred target paths."""
    hits: List[str] = []
    cmd_norm = command.replace("\\", "/").lower()
    cwd = Path(working_directory)

    for prot in protected_paths:
        prot_norm = prot.replace("\\", "/").rstrip("/").lower()
        if not prot_norm:
            continue

        # Direct substring match in command for system directories or sensitive files
        if prot_norm in cmd_norm:
            hits.append(prot)
            continue

        for target in target_paths:
            t_norm = target.replace("\\", "/").lower()
            if prot_norm in t_norm or t_norm.endswith("/" + prot_norm) or t_norm == prot_norm:
                hits.append(prot)
                break
            try:
                resolved = str((cwd / target).resolve()).replace("\\", "/").lower()
                if prot_norm in resolved:
                    hits.append(prot)
                    break
            except Exception:
                pass

    return list(dict.fromkeys(hits))


def run_local_precheck(
    operation: OperationRequest,
    settings: FenceSettings,
) -> LocalPrecheckResult:
    """
    Section 8 & FR-05: Deterministic local pre-check for mandatory deny rules:
    - Prohibited high-impact patterns (disk formatting, recursive wildcard deletes, security/privilege bypass, etc.)
    - Protected paths (.env, C:/Windows, /etc, SSH keys, .git/hooks)
    - Out-of-scope target paths escaping the allowed workspace root
    """
    command = operation.command.strip()
    targets = operation.context.target_paths

    # 1. High-impact prohibited operation patterns
    for raw_pattern in settings.high_impact_patterns:
        if re.search(raw_pattern, command):
            return LocalPrecheckResult(
                passed=False,
                mandatory_block=True,
                reason_code="MANDATORY_DENY_HIGH_IMPACT_PATTERN",
                explanation=(
                    f"Command matches prohibited high-impact or destructive pattern ({raw_pattern}). "
                    "Blocked by mandatory local policy."
                ),
                matched_rule=raw_pattern,
            )

    # 2. Protected path check
    protected_hits = _matches_protected_path(
        command=command,
        target_paths=targets,
        working_directory=operation.working_directory,
        protected_paths=settings.protected_paths,
    )
    if protected_hits:
        return LocalPrecheckResult(
            passed=False,
            mandatory_block=True,
            reason_code="MANDATORY_DENY_PROTECTED_PATH",
            explanation=(
                f"Operation references protected path(s): {', '.join(protected_hits)}. "
                "Blocked by mandatory local policy."
            ),
            protected_path_hits=protected_hits,
        )

    # 3. Workspace scope verification
    in_workspace, out_of_scope = check_targets_in_workspace(
        target_paths=targets,
        working_directory=operation.working_directory,
        allowed_workspace_root=settings.allowed_workspace_root,
    )
    if not in_workspace:
        return LocalPrecheckResult(
            passed=False,
            mandatory_block=True,
            reason_code="MANDATORY_DENY_OUT_OF_SCOPE_TARGET",
            explanation=(
                f"Target path(s) resolve outside the authorized workspace root "
                f"('{settings.allowed_workspace_root}'): {', '.join(out_of_scope)}."
            ),
            out_of_scope_targets=out_of_scope,
        )

    return LocalPrecheckResult(
        passed=True,
        mandatory_block=False,
        reason_code="PRECHECK_OK",
        explanation="Local deterministic pre-checks passed.",
    )


def evaluate_policy(
    operation: OperationRequest,
    precheck: LocalPrecheckResult,
    model_result: NormalizedDecisionResult,
    settings: FenceSettings,
    is_recheck: bool = False,
) -> Tuple[FinalDecision, str, str]:
    """
    FR-05, FR-06 & Section 8: Combine deterministic pre-checks, model classification,
    confidence thresholds, and risk scores into ALLOW, RECHECK, or BLOCK.

    Security Principle:
    - The policy engine may downgrade an AI ALLOW to RECHECK or BLOCK,
      but the model can NEVER override mandatory local policy.
    - A model BLOCK (security_sensitive or destructive/out-of-scope) is never changed to ALLOW
      by confidence thresholds.
    """
    # 1. Mandatory local precheck block cannot be overridden
    if precheck.mandatory_block or not precheck.passed:
        return FinalDecision.BLOCK, precheck.reason_code, precheck.explanation

    # 2. Provider failure / timeout / auth / malformed response -> Fail closed
    if model_result.provider_error or not model_result.is_valid_schema:
        err_text = model_result.provider_error or "Invalid or incomplete model response schema."
        # Allow a single recheck only for malformed model output if recheck is enabled and not yet attempted
        if (
            not is_recheck
            and settings.max_rechecks > 0
            and "Incomplete model response" in err_text
        ):
            return (
                FinalDecision.RECHECK,
                "MALFORMED_MODEL_RESPONSE_RECHECK",
                f"{err_text} Scheduling one bounded recheck.",
            )
        return (
            FinalDecision.BLOCK,
            "FAIL_CLOSED_PROVIDER_OR_SCHEMA_ERROR",
            f"Fail-closed block: {err_text}",
        )

    confidence = model_result.confidence
    if confidence is None:
        return (
            FinalDecision.BLOCK,
            "FAIL_CLOSED_MISSING_CONFIDENCE",
            "Fail-closed block: Provider did not return a valid confidence score.",
        )

    scores = model_result.scores
    intent_score = scores.matches_user_intent if scores.matches_user_intent is not None else 0.0
    scope_score = scores.target_in_scope if scores.target_in_scope is not None else 0.0
    damage_risk = scores.unintended_damage_risk if scores.unintended_damage_risk is not None else 1.0
    needs_review = scores.needs_human_review if scores.needs_human_review is not None else 1.0

    action_class = model_result.action_class

    # 3. Security-sensitive operations are always blocked in prototype policy
    if action_class == ActionClass.SECURITY_SENSITIVE:
        return (
            FinalDecision.BLOCK,
            "BLOCKED_SECURITY_SENSITIVE_ACTION",
            "Command was classified as security-sensitive (privilege, policy, or system control modification).",
        )

    # 4. Model indicates target is out of scope
    if scope_score < 0.70:
        return (
            FinalDecision.BLOCK,
            "BLOCKED_MODEL_OUT_OF_SCOPE",
            f"Decision model flagged target as out of authorized scope (target_in_scope={scope_score:.2f}).",
        )

    # 5. Destructive mutations (delete/overwrite)
    if action_class == ActionClass.DESTRUCTIVE_MUTATION:
        if settings.require_manual_approval_for_destructive:
            return (
                FinalDecision.BLOCK,
                "BLOCKED_DESTRUCTIVE_REQUIRES_APPROVAL",
                (
                    "Command performs a destructive mutation (file deletion or overwrite) and policy "
                    "requires explicit human approval."
                ),
            )
        # Even when destructive mutations are permitted in workspace, require explicit intent, exact target, and low damage risk
        if (
            not operation.context.intent_provided
            or not operation.context.target_inferred
            or confidence < settings.allow_threshold
            or intent_score < settings.allow_threshold
            or damage_risk > settings.risk_ceiling
        ):
            return (
                FinalDecision.BLOCK,
                "BLOCKED_DESTRUCTIVE_INSUFFICIENT_JUSTIFICATION",
                (
                    f"Destructive operation blocked: confidence={confidence:.2f}, "
                    f"matches_user_intent={intent_score:.2f}, damage_risk={damage_risk:.2f}."
                ),
            )
        return (
            FinalDecision.ALLOW,
            "ALLOWED_EXPLICIT_SCOPED_DESTRUCTIVE",
            "Destructive operation inside test workspace matched explicit user intent and passed all thresholds.",
        )

    # 6. Unclear action class -> Recheck once, then block
    if action_class == ActionClass.UNCLEAR:
        if not is_recheck and settings.max_rechecks > 0:
            return (
                FinalDecision.RECHECK,
                "UNCERTAIN_ACTION_CLASS_RECHECK",
                f"Action class is unclear (confidence={confidence:.2f}). Performing one bounded recheck with enriched evidence.",
            )
        return (
            FinalDecision.BLOCK,
            "BLOCKED_UNCLEAR_AFTER_RECHECK",
            "Operation remained unclear or ambiguous after evaluation and was blocked by default.",
        )

    # 7. Routine mutations require explicit user intent
    if action_class == ActionClass.ROUTINE_MUTATION and not operation.context.intent_provided:
        if not is_recheck and settings.max_rechecks > 0:
            return (
                FinalDecision.RECHECK,
                "MISSING_USER_INTENT_FOR_MUTATION_RECHECK",
                "Routine file mutation requested without explicit user intent. Performing one recheck.",
            )
        return (
            FinalDecision.BLOCK,
            "BLOCKED_MISSING_INTENT_FOR_MUTATION",
            "Routine mutation blocked because no explicit user intent was supplied to justify modifying files.",
        )

    # 8. Check confidence threshold, intent alignment, damage risk, and human review score
    threshold = settings.allow_threshold
    is_confident = confidence >= threshold
    is_intent_aligned = intent_score >= threshold
    is_low_risk = damage_risk <= settings.risk_ceiling and needs_review < 0.50

    if is_confident and is_intent_aligned and is_low_risk:
        return (
            FinalDecision.ALLOW,
            "HIGH_CONFIDENCE_IN_SCOPE",
            (
                f"Operation authorized ({action_class.value}, confidence={confidence:.2f} >= {threshold:.2f}, "
                f"intent={intent_score:.2f}, risk={damage_risk:.2f})."
            ),
        )

    # 9. If below threshold or contradictory dimension -> Recheck once if not yet rechecked
    if not is_recheck and settings.max_rechecks > 0:
        reasons = []
        if not is_confident:
            reasons.append(f"confidence {confidence:.2f} < {threshold:.2f}")
        if not is_intent_aligned:
            reasons.append(f"intent alignment {intent_score:.2f} < {threshold:.2f}")
        if not is_low_risk:
            reasons.append(f"risk={damage_risk:.2f} / needs_review={needs_review:.2f}")
        return (
            FinalDecision.RECHECK,
            "LOW_CONFIDENCE_OR_AMBIGUOUS_RECHECK",
            f"Initial evaluation uncertain ({', '.join(reasons)}). Triggering one bounded recheck with additional local context.",
        )

    return (
        FinalDecision.BLOCK,
        "BLOCKED_BELOW_THRESHOLD_OR_UNRESOLVED",
        (
            f"Operation did not meet policy thresholds (confidence={confidence:.2f}, "
            f"threshold={threshold:.2f}, intent={intent_score:.2f}, risk={damage_risk:.2f})."
        ),
    )


def issue_authorization_token(
    operation: OperationRequest,
    decision: FinalDecision,
    reason_code: str,
) -> Optional[AuthorizationToken]:
    """FR-07: Issue a SHA-256 bound AuthorizationToken only when decision == ALLOW."""
    if decision != FinalDecision.ALLOW:
        return None

    digest = compute_authorization_digest(
        command=operation.command,
        shell=operation.shell,
        working_directory=operation.working_directory,
        target_paths=operation.context.target_paths,
    )
    return AuthorizationToken(
        operation_id=operation.operation_id,
        decision=FinalDecision.ALLOW,
        authorized_command=operation.command,
        shell=operation.shell,
        working_directory=operation.working_directory,
        target_paths=list(operation.context.target_paths),
        authorized_command_digest=digest,
        reason_code=reason_code,
    )
