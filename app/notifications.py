"""CLI and Windows desktop toast notification service for blocked operations (FR-08, Section 6.2)."""

from __future__ import annotations

import os
import sys
from typing import List, Optional

from app.context import shorten_command
from app.schemas import FinalDecisionResult, NotificationOutcome, OperationRequest


def format_block_notification(
    operation: OperationRequest,
    decision_result: FinalDecisionResult,
    extra_secrets: Optional[List[str]] = None,
) -> str:
    """
    Section 6.2 & FR-08: Build the user-visible block notification message.
    Includes the length-limited, secret-redacted command, the reason category/explanation,
    and the explicit statement that it was not executed.
    """
    cmd_short = shorten_command(operation.command, max_len=90, extra_secrets=extra_secrets)
    return (
        f"BLOCKED. `{cmd_short}` was not executed. "
        f"Reason [{decision_result.reason_code}]: {decision_result.explanation} "
        f"Review the event (ID: {operation.operation_id[:8]}) in Permission Fence."
    )


def send_block_notification(
    operation: OperationRequest,
    decision_result: FinalDecisionResult,
    enable_windows_toast: bool = True,
    extra_secrets: Optional[List[str]] = None,
    emit_to_stderr: bool = True,
) -> NotificationOutcome:
    """
    Deliver immediate block notification via CLI output and optional Windows desktop toast.
    Notification failure never changes a BLOCK into an ALLOW (FR-08, Section 14).
    """
    message = format_block_notification(
        operation=operation,
        decision_result=decision_result,
        extra_secrets=extra_secrets,
    )

    if emit_to_stderr:
        try:
            sys.stderr.write(f"\n[PERMISSION FENCE] {message}\n")
            sys.stderr.flush()
        except Exception:
            pass

    toast_attempted = False
    toast_succeeded = False
    toast_error: Optional[str] = None

    if enable_windows_toast and os.name == "nt":
        toast_attempted = True
        try:
            from winotify import Notification, audio  # type: ignore

            toast = Notification(
                app_id="Permission Fence",
                title="Permission Fence: Command Blocked",
                msg=message,
                duration="short",
            )
            toast.set_audio(audio.Default, loop=False)
            toast.show()
            toast_succeeded = True
        except Exception as exc:
            toast_error = f"Windows toast unavailable ({exc.__class__.__name__})"

    return NotificationOutcome(
        notified=True,
        cli_message=message,
        toast_attempted=toast_attempted,
        toast_succeeded=toast_succeeded,
        notification_error=toast_error,
    )
