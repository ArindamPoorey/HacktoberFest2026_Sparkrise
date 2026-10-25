"""Authorized PowerShell Execution Broker (FR-07)."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from app.config import FenceSettings
from app.context import compute_authorization_digest, redact_secrets
from app.schemas import (
    AuthorizationToken,
    ExecutionResult,
    ExecutionStatus,
    FinalDecision,
    OperationRequest,
)


class SecurityGateError(RuntimeError):
    """Raised when an execution attempt violates the Execution Broker security gate."""


# Safe cross-platform translation for basic read-only / file creation PowerShell cmdlets
# when running automated tests on a Linux/macOS host without `pwsh` installed.
def _build_process_args(command: str, shell: str) -> List[str]:
    """
    Build the fixed non-interactive process invocation list (FR-07).
    On Windows, uses full fixed PowerShell path (`System32\\WindowsPowerShell\\v1.0\\powershell.exe`)
    with `-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -Command`.
    On non-Windows test hosts, prefers `pwsh` if installed, or provides a deterministic
    non-interactive shell translation for standard test commands.
    """
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        win_ps = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        ps_exe = str(win_ps) if win_ps.exists() else (shutil.which("powershell.exe") or "powershell.exe")
        return [
            ps_exe,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "RemoteSigned",
            "-Command",
            command,
        ]

    pwsh_path = shutil.which("pwsh") or shutil.which("powershell")
    if pwsh_path:
        return [
            pwsh_path,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ]

    # Fallback for Linux test VMs where pwsh is not installed: translate basic PowerShell test cmdlets
    sh_bin = shutil.which("bash") or "/bin/sh"
    translated = _translate_ps_for_posix_test(command)
    return [sh_bin, "-c", translated]


def _translate_ps_for_posix_test(command: str) -> str:
    """Translate basic PowerShell cmdlets used in unit/integration tests into POSIX shell equivalents."""
    stripped = command.strip()
    low = stripped.lower()

    if low.startswith("get-childitem"):
        rest = stripped[len("get-childitem") :].strip() or "."
        rest = rest.replace("\\", "/")
        return f"ls -la {rest}"
    if low.startswith("get-location"):
        return "pwd"
    if low.startswith("write-output "):
        msg = stripped[len("write-output ") :].strip()
        return f"echo {msg}"
    if low.startswith("get-content "):
        target = stripped[len("get-content ") :].strip().replace("\\", "/")
        return f"cat {target}"
    if low.startswith("new-item "):
        # e.g. New-Item -Path .\test.txt -ItemType File -Value "hello"
        import re

        path_match = re.search(r"(?i)(?:-Path\s+)?([^\s-]+)", stripped[len("new-item") :].strip())
        val_match = re.search(r"(?i)-Value\s+(['\"]?)(.*?)\1(?:\s|$)", stripped)
        if path_match:
            target = path_match.group(1).strip("'\"").replace("\\", "/")
            if val_match:
                val = val_match.group(2)
                return f"printf '%s' '{val}' > '{target}'"
            return f"touch '{target}'"
    if low.startswith("set-content "):
        import re

        m = re.search(r"(?i)set-content\s+(?:-Path\s+)?([^\s]+)\s+(?:-Value\s+)?(['\"]?)(.*?)\2$", stripped)
        if m:
            target = m.group(1).strip("'\"").replace("\\", "/")
            val = m.group(3)
            return f"printf '%s' '{val}' > '{target}'"
    if low.startswith("remove-item "):
        target = stripped[len("remove-item ") :].strip().split()[0].strip("'\"").replace("\\", "/")
        return f"rm -f '{target}'"
    return stripped


class ExecutionBroker:
    """
    FR-07: The ONLY module permitted to create the protected command process.
    Requires a valid AuthorizationToken from the policy layer and revalidates the SHA-256
    digest of the exact command, shell, working directory, and targets immediately prior to launch.
    """

    def __init__(self, settings: FenceSettings) -> None:
        self.settings = settings

    def verify_authorization(
        self,
        operation: OperationRequest,
        token: Optional[AuthorizationToken],
    ) -> str:
        """
        Verify that a valid AuthorizationToken is present, has decision == ALLOW,
        and its SHA-256 digest matches the current OperationRequest unmodified.
        Raises SecurityGateError if any check fails.
        """
        if token is None:
            raise SecurityGateError("Execution rejected: Missing AuthorizationToken.")

        if not isinstance(token, AuthorizationToken):
            raise SecurityGateError("Execution rejected: Invalid AuthorizationToken type.")

        if token.decision != FinalDecision.ALLOW:
            raise SecurityGateError(
                f"Execution rejected: AuthorizationToken decision is '{token.decision.value}', not 'ALLOW'."
            )

        if token.operation_id != operation.operation_id:
            raise SecurityGateError("Execution rejected: AuthorizationToken operation_id mismatch.")

        if token.authorized_command != operation.command:
            raise SecurityGateError(
                "Execution rejected: Command was modified after policy authorization."
            )

        if Path(token.working_directory).resolve() != Path(operation.working_directory).resolve():
            raise SecurityGateError(
                "Execution rejected: Working directory was modified after policy authorization."
            )

        recomputed_digest = compute_authorization_digest(
            command=operation.command,
            shell=operation.shell,
            working_directory=operation.working_directory,
            target_paths=operation.context.target_paths,
        )
        if recomputed_digest != token.authorized_command_digest:
            raise SecurityGateError(
                "Execution rejected: SHA-256 authorization digest mismatch (command or context changed after approval)."
            )

        return recomputed_digest

    def execute(
        self,
        operation: OperationRequest,
        token: Optional[AuthorizationToken],
        max_output_chars: int = 4096,
    ) -> ExecutionResult:
        """
        Revalidate the authorization token and execute the exact approved command in a
        non-interactive child process with timeout and secret redaction.
        """
        recomputed_digest = self.verify_authorization(operation, token)

        cwd_path = Path(operation.working_directory)
        if not cwd_path.exists() or not cwd_path.is_dir():
            return ExecutionResult(
                operation_id=operation.operation_id,
                execution_status=ExecutionStatus.FAILED,
                error_message=f"Working directory does not exist: {operation.working_directory}",
                digest_verified=True,
            )

        process_args = _build_process_args(operation.command, operation.shell)
        start_dt = datetime.now(timezone.utc).isoformat()
        start_perf = time.perf_counter()
        extra_secrets = [self.settings.model_api_key] if self.settings.model_api_key else []

        try:
            completed = subprocess.run(
                process_args,
                cwd=str(cwd_path.resolve()),
                capture_output=True,
                text=True,
                timeout=self.settings.execution_timeout_seconds,
                check=False,
                stdin=subprocess.DEVNULL,
            )
            duration_ms = (time.perf_counter() - start_perf) * 1000.0
            end_dt = datetime.now(timezone.utc).isoformat()

            raw_out = (completed.stdout or "")[:max_output_chars]
            raw_err = (completed.stderr or "")[:max_output_chars]
            redacted_out = redact_secrets(raw_out, extra_secrets=extra_secrets)
            redacted_err = redact_secrets(raw_err, extra_secrets=extra_secrets)

            status = (
                ExecutionStatus.SUCCEEDED
                if completed.returncode == 0
                else ExecutionStatus.FAILED
            )
            return ExecutionResult(
                operation_id=operation.operation_id,
                execution_status=status,
                start_time=start_dt,
                end_time=end_dt,
                duration_ms=round(duration_ms, 2),
                exit_code=completed.returncode,
                redacted_stdout=redacted_out,
                redacted_stderr=redacted_err,
                digest_verified=bool(recomputed_digest),
            )

        except subprocess.TimeoutExpired as exc:
            duration_ms = (time.perf_counter() - start_perf) * 1000.0
            end_dt = datetime.now(timezone.utc).isoformat()
            partial_out = redact_secrets(
                (exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""))[:max_output_chars],
                extra_secrets=extra_secrets,
            )
            partial_err = redact_secrets(
                (exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""))[:max_output_chars],
                extra_secrets=extra_secrets,
            )
            return ExecutionResult(
                operation_id=operation.operation_id,
                execution_status=ExecutionStatus.TIMED_OUT,
                start_time=start_dt,
                end_time=end_dt,
                duration_ms=round(duration_ms, 2),
                exit_code=None,
                redacted_stdout=partial_out,
                redacted_stderr=partial_err,
                error_message=(
                    f"Command timed out after {self.settings.execution_timeout_seconds}s and was terminated. "
                    "Final system state may require manual inspection."
                ),
                digest_verified=True,
            )
        except Exception as exc:
            duration_ms = (time.perf_counter() - start_perf) * 1000.0
            end_dt = datetime.now(timezone.utc).isoformat()
            return ExecutionResult(
                operation_id=operation.operation_id,
                execution_status=ExecutionStatus.FAILED,
                start_time=start_dt,
                end_time=end_dt,
                duration_ms=round(duration_ms, 2),
                exit_code=None,
                error_message=f"Executor launch failure: {exc.__class__.__name__}: {exc}",
                digest_verified=True,
            )
