"""Provider abstraction and normalization helpers (FR-03, FR-04, FR-06)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple

from app.config import FenceSettings
from app.schemas import (
    ActionClass,
    DecisionRequest,
    DecisionScores,
    NormalizedDecisionResult,
    PackedContext,
)


STANDARD_SYSTEMONE_QUESTIONS: Dict[str, Dict[str, Any]] = {
    "action_class": {
        "type": "choice",
        "instructions": (
            "Classify the proposed shell command into exactly one operational risk category based on its syntax, "
            "cmdlet/binary, flags, and target paths."
        ),
        "criteria": {
            "read_only": "Strictly read-only inspection, listing, searching, or status check with zero filesystem or state mutation.",
            "routine_mutation": "Standard development file creation, editing, copying, or test execution within the project workspace.",
            "destructive_mutation": "File or directory deletion, overwriting existing data, recursive removal, or irreversible state removal.",
            "security_sensitive": "Modifying permissions, execution policies, registry keys, credentials, network rules, system services, or privilege escalation.",
            "unclear": "Ambiguous, obfuscated, dynamic expression evaluation, or insufficient context to determine the exact effect.",
        },
    },
    "matches_user_intent": {
        "type": "noul",
        "instructions": "Is the proposed command directly and proportionally justified by the stated user intent?",
        "criteria": {
            "true": "The user intent is explicitly stated and directly requests the exact operation and targets.",
            "false": "The user intent is missing, vague, unrelated, or the command's side effects exceed what was requested.",
        },
    },
    "target_in_scope": {
        "type": "noul",
        "instructions": "Are all target files, directories, and resources strictly within the authorized project workspace?",
        "criteria": {
            "true": "Every affected path resolves inside the allowed workspace root and does not touch system or parent directories.",
            "false": "Any target escapes the workspace root, uses broad wildcards outside scope, or touches system/protected paths.",
        },
    },
    "unintended_damage_risk": {
        "type": "noul",
        "instructions": "Does this command carry a significant risk of unintended data loss, collateral file deletion, or system instability?",
        "criteria": {
            "true": "High risk of irreversible deletion, broad wildcard impact, or system corruption.",
            "false": "Low or negligible risk of unintended damage.",
        },
    },
    "needs_human_review": {
        "type": "noul",
        "instructions": "Is human review required before running this command because evidence is incomplete or the impact is high?",
        "criteria": {
            "true": "Evidence is ambiguous, intent is missing, or the operation is destructive/security-sensitive.",
            "false": "The operation is well-scoped, routine or read-only, and clearly justified.",
        },
    },
}


def build_systemone_state(packed: PackedContext) -> Dict[str, Any]:
    """Build the compact, secret-redacted state payload sent to /v1/systemone."""
    state: Dict[str, Any] = {
        "command": packed.redacted_command,
        "shell": packed.shell,
        "working_directory": packed.working_directory,
        "allowed_workspace_root": packed.allowed_workspace_root,
        "user_intent": (
            packed.redacted_user_intent
            if packed.intent_explicitly_supplied
            else "MISSING_USER_INTENT (No explicit user intent was provided)"
        ),
        "intent_explicitly_supplied": packed.intent_explicitly_supplied,
        "inferred_target_paths": packed.inferred_target_paths,
        "targets_within_workspace": packed.targets_within_workspace,
        "invocation_source": packed.invocation_source,
        "environment": packed.environment,
        "project_files_sample": packed.project_files_sample[:10],
    }
    if packed.git_summary:
        state["git_summary"] = packed.git_summary
    if packed.recheck_attempt > 0:
        state["recheck_attempt"] = packed.recheck_attempt
        state["prior_decision_reason"] = packed.prior_decision_reason
        state["additional_recheck_evidence"] = packed.additional_recheck_evidence or {}
    return state


def extract_noul_probability(answer_obj: Any) -> Optional[float]:
    """Extract calibrated probability [0, 1] from a System One 'noul' or 'score' answer object."""
    if not isinstance(answer_obj, dict):
        return None
    for key in ("noul", "probability", "score", "value"):
        val = answer_obj.get(key)
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            fval = float(val)
            if 0.0 <= fval <= 1.0:
                return fval
    # Fallback: check probabilities dict for 'true' or 'yes'
    probs = answer_obj.get("probabilities")
    if isinstance(probs, dict):
        for k in ("true", "yes", "True", "1"):
            if k in probs and isinstance(probs[k], (int, float)):
                fval = float(probs[k])
                if 0.0 <= fval <= 1.0:
                    return fval
    return None


def extract_choice_and_confidence(
    answer_obj: Any,
) -> Tuple[ActionClass, Optional[float], str, Dict[str, float]]:
    """
    Extract normalized ActionClass, calibrated confidence, source field documentation,
    and per-option probabilities from a System One `choice` answer.

    Documented confidence mapping (FR-06):
    1. Prefer `answers.action_class.confidence` if present and in [0, 1].
    2. Otherwise use `answers.action_class.probabilities[<selected_choice>]` if present and in [0, 1].
    3. Otherwise mark confidence as `None` (unavailable — never fabricate).
    """
    if not isinstance(answer_obj, dict):
        return ActionClass.UNCLEAR, None, "missing_action_class_answer", {}

    raw_choice = answer_obj.get("choice") or answer_obj.get("label") or answer_obj.get("value")
    try:
        action_class = ActionClass(str(raw_choice).strip().lower()) if raw_choice else ActionClass.UNCLEAR
    except ValueError:
        action_class = ActionClass.UNCLEAR

    raw_probs = answer_obj.get("probabilities")
    clean_probs: Dict[str, float] = {}
    if isinstance(raw_probs, dict):
        for k, v in raw_probs.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                clean_probs[str(k)] = float(v)

    # 1. Explicit confidence field on choice answer
    raw_conf = answer_obj.get("confidence")
    if isinstance(raw_conf, (int, float)) and not isinstance(raw_conf, bool):
        fconf = float(raw_conf)
        if 0.0 <= fconf <= 1.0:
            return action_class, fconf, "answers.action_class.confidence", clean_probs

    # 2. Selected option probability from probabilities map
    if isinstance(raw_choice, str) and raw_choice in clean_probs:
        sel_prob = clean_probs[raw_choice]
        if 0.0 <= sel_prob <= 1.0:
            return (
                action_class,
                sel_prob,
                f"answers.action_class.probabilities.{raw_choice}",
                clean_probs,
            )

    return action_class, None, "unavailable", clean_probs


def normalize_systemone_response(
    provider_name: str,
    default_model_id: str,
    payload: Any,
    latency_ms: float,
    request_id: Optional[str] = None,
) -> NormalizedDecisionResult:
    """Validate and normalize a /v1/systemone JSON response into NormalizedDecisionResult."""
    if not isinstance(payload, dict):
        return NormalizedDecisionResult(
            provider=provider_name,
            model_id=default_model_id,
            latency_ms=latency_ms,
            request_id=request_id,
            provider_error="Malformed response: root JSON payload is not an object.",
            is_valid_schema=False,
        )

    answers = payload.get("answers")
    if not isinstance(answers, dict) or not answers:
        return NormalizedDecisionResult(
            provider=provider_name,
            model_id=str(payload.get("model") or default_model_id),
            latency_ms=latency_ms,
            request_id=request_id,
            provider_error="Malformed response: missing or empty 'answers' object.",
            is_valid_schema=False,
        )

    model_id = str(payload.get("model") or default_model_id)
    model_version = payload.get("model_version")
    if not model_version and isinstance(payload.get("routing"), dict):
        model_version = payload["routing"].get("checkpoint")

    action_answer = answers.get("action_class")
    action_class, confidence, conf_source, class_probs = extract_choice_and_confidence(action_answer)

    matches_intent = extract_noul_probability(answers.get("matches_user_intent"))
    target_in_scope = extract_noul_probability(answers.get("target_in_scope"))
    damage_risk = extract_noul_probability(answers.get("unintended_damage_risk"))
    needs_review = extract_noul_probability(answers.get("needs_human_review"))

    scores = DecisionScores(
        matches_user_intent=matches_intent,
        target_in_scope=target_in_scope,
        unintended_damage_risk=damage_risk,
        needs_human_review=needs_review,
    )

    usage_raw = payload.get("usage")
    usage: Optional[Dict[str, int]] = None
    if isinstance(usage_raw, dict):
        usage = {
            "input_tokens": int(usage_raw.get("input_tokens", 0)),
            "output_tokens": int(usage_raw.get("output_tokens", 0)),
        }

    # Check completeness of critical fields
    schema_valid = (
        action_answer is not None
        and confidence is not None
        and matches_intent is not None
        and target_in_scope is not None
        and damage_risk is not None
    )
    err_msg: Optional[str] = None
    if not schema_valid:
        missing = []
        if action_answer is None:
            missing.append("action_class")
        if confidence is None:
            missing.append("confidence")
        if matches_intent is None:
            missing.append("matches_user_intent")
        if target_in_scope is None:
            missing.append("target_in_scope")
        if damage_risk is None:
            missing.append("unintended_damage_risk")
        err_msg = f"Incomplete model response: missing required fields [{', '.join(missing)}]."

    return NormalizedDecisionResult(
        provider=provider_name,
        model_id=model_id,
        model_version=str(model_version) if model_version else None,
        action_class=action_class,
        action_class_probabilities=class_probs,
        confidence=confidence,
        confidence_source_field=conf_source,
        scores=scores,
        latency_ms=round(latency_ms, 2),
        request_id=request_id or payload.get("id") or payload.get("request_id"),
        usage=usage,
        raw_sanitized_summary={
            "model": model_id,
            "action_class": action_class.value,
            "confidence": confidence,
            "confidence_source": conf_source,
            "scores": scores.model_dump(),
        },
        provider_error=err_msg,
        is_valid_schema=schema_valid,
    )


class DecisionProvider(ABC):
    """FR-03: Stable interface for all System 1 decision providers."""

    def __init__(self, settings: FenceSettings) -> None:
        self.settings = settings

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Unique provider name."""

    @abstractmethod
    def evaluate(self, request: DecisionRequest) -> NormalizedDecisionResult:
        """Evaluate a DecisionRequest and return a NormalizedDecisionResult."""
