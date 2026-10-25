"""Context packaging, secret redaction, and target path inference (FR-01, FR-02, FR-07)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.config import FenceSettings
from app.schemas import OperationContextMetadata, OperationRequest, PackedContext


SECRET_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    # Bearer / Authorization tokens
    (re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9\-._~+/]+=*"), r"\1[REDACTED_TOKEN]"),
    # Common API key prefixes (OpenAI, TypeSafe, Laya, GitHub PAT, AWS, Slack, Stripe)
    (
        re.compile(
            r"\b(sk-[A-Za-z0-9]{12,}|lsk_[A-Za-z0-9_]{8,}|ts_[A-Za-z0-9_]{8,}|ghp_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9\-]{10,})\b"
        ),
        "[REDACTED_API_KEY]",
    ),
    # Key=Value or Flag assignments for secrets/passwords/tokens
    (
        re.compile(
            r"(?i)(\b(?:api[_-]?key|token|secret|password|passwd|pwd|client[_-]?secret|access[_-]?key|auth[_-]?token)\s*[:=]\s*)(['\"]?)([^\s'\";]+)(\2)"
        ),
        r"\1\2[REDACTED_SECRET]\4",
    ),
    # PowerShell / CLI flags like -Password secret, --api-key secret, -Token secret
    (
        re.compile(
            r"(?i)(-{1,2}(?:password|passwd|token|api-key|apikey|secret|credential)\s+)(['\"]?)([^\s'\";]+)(\2)"
        ),
        r"\1\2[REDACTED_SECRET]\4",
    ),
    # Connection strings with embedded credentials
    (
        re.compile(r"(?i)((?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^:\s]+:)([^@\s]+)(@)"),
        r"\1[REDACTED_PASSWORD]\3",
    ),
]


def redact_secrets(text: Optional[str], extra_secrets: Optional[List[str]] = None) -> str:
    """Redact API keys, bearer tokens, passwords, and configured secrets from text."""
    if not text:
        return ""
    redacted = text
    if extra_secrets:
        for secret in extra_secrets:
            if secret and len(secret.strip()) >= 4 and secret.strip() != "replace_me":
                redacted = redacted.replace(secret.strip(), "[REDACTED_CONFIG_SECRET]")

    for pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def shorten_command(command: str, max_len: int = 80, extra_secrets: Optional[List[str]] = None) -> str:
    """Return a secret-redacted, length-limited command summary for notifications and tables."""
    clean = " ".join(redact_secrets(command, extra_secrets=extra_secrets).split())
    if len(clean) <= max_len:
        return clean
    return clean[: max_len - 3] + "..."


def compute_authorization_digest(
    command: str,
    shell: str,
    working_directory: str,
    target_paths: List[str],
) -> str:
    """FR-07: Compute a deterministic SHA-256 digest binding exact command, shell, cwd, and targets."""
    resolved_cwd = str(Path(working_directory).resolve())
    canonical_payload = {
        "command": command.strip(),
        "shell": shell.strip().lower(),
        "working_directory": resolved_cwd,
        "target_paths": sorted(str(p) for p in target_paths),
    }
    serialized = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def infer_target_paths(command: str, working_directory: str) -> List[str]:
    """Infer file or directory paths referenced by a PowerShell/shell command."""
    try:
        tokens = shlex.split(command, posix=False)
    except ValueError:
        tokens = command.split()

    cmdlets_and_verbs = {
        "get-childitem",
        "dir",
        "ls",
        "get-content",
        "cat",
        "type",
        "set-content",
        "add-content",
        "out-file",
        "new-item",
        "mkdir",
        "md",
        "remove-item",
        "rm",
        "del",
        "erase",
        "rd",
        "rmdir",
        "move-item",
        "mv",
        "move",
        "copy-item",
        "cp",
        "copy",
        "rename-item",
        "ren",
        "test-path",
        "select-string",
        "invoke-item",
        "start-process",
        "python",
        "python3",
        "pytest",
        "git",
    }

    inferred: List[str] = []

    skip_next = False
    for idx, raw_tok in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue

        tok = raw_tok.strip("'\"")
        if not tok:
            continue

        low = tok.lower()
        if idx == 0 and low in cmdlets_and_verbs:
            continue
        if low in {"|", ";", "&&", "||", ">", ">>", "<"}:
            continue

        # Named parameters that take a path right after
        if low in {"-path", "-literalpath", "-destination", "-filepath", "-outpath"}:
            if idx + 1 < len(tokens):
                next_tok = tokens[idx + 1].strip("'\"")
                inferred.append(next_tok)
                skip_next = True
            continue

        if tok.startswith("-"):
            continue

        looks_like_path = (
            tok in {".", "..", "~"}
            or "/" in tok
            or "\\" in tok
            or tok.startswith("./")
            or tok.startswith(".\\")
            or tok.startswith("..")
            or re.match(r"^[A-Za-z]:[/\\]", tok) is not None
            or "." in Path(tok).name
            or "*" in tok
        )

        if looks_like_path:
            inferred.append(tok)
        elif idx > 0 and tokens[0].strip("'\"").lower() in {
            "remove-item",
            "rm",
            "del",
            "get-content",
            "cat",
            "set-content",
            "new-item",
            "mkdir",
            "get-childitem",
            "ls",
            "dir",
            "copy-item",
            "move-item",
        }:
            # Positional target argument to a file cmdlet
            inferred.append(tok)

    # Deduplicate while preserving order
    seen = set()
    unique_paths: List[str] = []
    for p in inferred:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)
    return unique_paths


def check_targets_in_workspace(
    target_paths: List[str],
    working_directory: str,
    allowed_workspace_root: str,
) -> Tuple[bool, List[str]]:
    """Verify whether all inferred target paths resolve inside the allowed workspace root."""
    try:
        workspace_root = Path(allowed_workspace_root).resolve()
        cwd = Path(working_directory).resolve()
    except Exception:
        return False, target_paths

    out_of_scope: List[str] = []

    # First ensure working directory itself is inside workspace root
    try:
        cwd.relative_to(workspace_root)
    except ValueError:
        out_of_scope.append(str(cwd))

    for raw_target in target_paths:
        # Handle Windows drive root or home expansion
        if raw_target.startswith("~") or "$HOME" in raw_target.upper() or "$ENV:USERPROFILE" in raw_target.upper():
            out_of_scope.append(raw_target)
            continue

        # Check Windows drive paths on non-Windows hosts
        if re.match(r"^[A-Za-z]:[/\\]", raw_target) and os.name != "nt":
            norm_target = raw_target.replace("\\", "/").rstrip("/")
            norm_ws = str(allowed_workspace_root).replace("\\", "/").rstrip("/")
            if not norm_target.lower().startswith(norm_ws.lower()):
                out_of_scope.append(raw_target)
            continue

        # Normalize Windows backslashes so '..\\file' is properly resolved on POSIX hosts too
        normalized_separators = raw_target.replace("\\", "/")
        cleaned_wildcard = normalized_separators.replace("*", "wildcard_placeholder").replace("?", "q")
        candidate = Path(cleaned_wildcard)
        if not candidate.is_absolute():
            resolved = (cwd / candidate).resolve()
        else:
            resolved = candidate.resolve()

        try:
            resolved.relative_to(workspace_root)
        except ValueError:
            out_of_scope.append(raw_target)

    return len(out_of_scope) == 0, out_of_scope


def collect_safe_project_summary(working_directory: str, max_entries: int = 12) -> Tuple[List[str], Optional[str]]:
    """Collect a lightweight directory listing (excluding secret files) and optional git status summary."""
    cwd = Path(working_directory)
    if not cwd.exists() or not cwd.is_dir():
        return [], None

    safe_entries: List[str] = []
    try:
        for entry in sorted(cwd.iterdir(), key=lambda x: x.name)[: max_entries * 2]:
            name_low = entry.name.lower()
            if name_low.startswith(".env") or "secret" in name_low or "id_rsa" in name_low:
                continue
            suffix = "/" if entry.is_dir() else ""
            safe_entries.append(f"{entry.name}{suffix}")
            if len(safe_entries) >= max_entries:
                break
    except Exception:
        pass

    git_summary: Optional[str] = None
    if (cwd / ".git").exists():
        try:
            proc = subprocess.run(
                ["git", "status", "--short", "--branch"],
                cwd=str(cwd),
                capture_output=True,
                text=True,
                timeout=1.5,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                lines = proc.stdout.strip().splitlines()[:5]
                git_summary = " | ".join(lines)
        except Exception:
            git_summary = None

    return safe_entries, git_summary


def build_operation_request(
    command: str,
    working_directory: Optional[str] = None,
    user_intent: Optional[str] = None,
    shell: str = "powershell",
    invocation_source: str = "cli",
    agent_name: Optional[str] = None,
    environment: str = "local-development",
) -> OperationRequest:
    """FR-01: Validate command and working directory and build a structured OperationRequest."""
    if not command or not command.strip():
        raise ValueError("Command cannot be empty.")

    cwd_str = working_directory if working_directory is not None else os.getcwd()
    cwd_path = Path(cwd_str)
    if not cwd_path.exists() or not cwd_path.is_dir():
        raise ValueError(f"Invalid or non-existent working directory: '{cwd_str}'")

    resolved_cwd = str(cwd_path.resolve())
    inferred_targets = infer_target_paths(command, resolved_cwd)
    safe_files, git_summary = collect_safe_project_summary(resolved_cwd)

    cleaned_intent = user_intent.strip() if user_intent and user_intent.strip() else None

    metadata = OperationContextMetadata(
        target_paths=inferred_targets,
        git_summary=git_summary,
        intent_provided=cleaned_intent is not None,
        target_inferred=len(inferred_targets) > 0,
        project_files_sample=safe_files,
    )

    return OperationRequest(
        command=command.strip(),
        shell=shell,
        working_directory=resolved_cwd,
        user_intent=cleaned_intent,
        invocation_source=invocation_source,
        agent_name=agent_name,
        environment=environment,
        context=metadata,
    )


def pack_context(
    operation: OperationRequest,
    settings: FenceSettings,
    recheck_attempt: int = 0,
    prior_decision_reason: Optional[str] = None,
    additional_recheck_evidence: Optional[Dict[str, Any]] = None,
) -> PackedContext:
    """FR-02: Package minimal, secret-redacted context for evaluation and compute its SHA-256 hash."""
    extra_secrets = [settings.model_api_key] if settings.model_api_key else []
    redacted_cmd = redact_secrets(operation.command, extra_secrets=extra_secrets)
    redacted_intent = (
        redact_secrets(operation.user_intent, extra_secrets=extra_secrets)
        if operation.user_intent
        else None
    )

    inferred_targets = list(operation.context.target_paths)
    if not inferred_targets:
        inferred_targets = infer_target_paths(operation.command, operation.working_directory)

    in_workspace, _ = check_targets_in_workspace(
        inferred_targets,
        operation.working_directory,
        settings.allowed_workspace_root,
    )

    resolved_workspace = str(Path(settings.allowed_workspace_root).resolve())

    hash_payload = {
        "operation_id": operation.operation_id,
        "redacted_command": redacted_cmd,
        "shell": operation.shell,
        "working_directory": operation.working_directory,
        "allowed_workspace_root": resolved_workspace,
        "redacted_user_intent": redacted_intent,
        "inferred_target_paths": inferred_targets,
        "recheck_attempt": recheck_attempt,
        "additional_recheck_evidence": additional_recheck_evidence or {},
    }
    context_hash = hashlib.sha256(
        json.dumps(hash_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    return PackedContext(
        operation_id=operation.operation_id,
        redacted_command=redacted_cmd,
        shell=operation.shell,
        working_directory=operation.working_directory,
        allowed_workspace_root=resolved_workspace,
        redacted_user_intent=redacted_intent,
        intent_explicitly_supplied=bool(redacted_intent),
        inferred_target_paths=inferred_targets,
        targets_within_workspace=in_workspace,
        invocation_source=operation.invocation_source,
        agent_name=operation.agent_name,
        environment=operation.environment,
        git_summary=operation.context.git_summary,
        project_files_sample=operation.context.project_files_sample,
        recheck_attempt=recheck_attempt,
        prior_decision_reason=prior_decision_reason,
        additional_recheck_evidence=additional_recheck_evidence,
        context_hash=f"sha256:{context_hash}",
    )
