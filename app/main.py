"""CLI entry point for Permission Fence (Section 13, FR-01, FR-11)."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.audit import AuditStore
from app.config import FenceSettings, load_settings, save_settings_to_env
from app.context import build_operation_request, pack_context
from app.coordinator import PermissionFenceCoordinator
from app.providers import get_provider
from app.schemas import DecisionRequest, FinalDecision


def _parse_stdin_json() -> Dict[str, Any]:
    """Read optional JSON payload from stdin for agent-hook integrations (FR-01)."""
    if sys.stdin is None or sys.stdin.isatty():
        return {}
    raw = sys.stdin.read().strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON provided on stdin: {exc}") from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="permission-fence",
        description="Permission Fence: Local System 1 command permission gateway for coding agents.",
    )
    parser.add_argument(
        "--provider",
        choices=["jev", "laya", "custom", "mock"],
        default=None,
        help="Override MODEL_PROVIDER (jev, laya, custom, mock).",
    )
    parser.add_argument(
        "--db-path",
        default=None,
        help="Override SQLite audit database path.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit structured JSON output.",
    )

    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # 1. check (Evaluate only — NEVER executes)
    check_parser = subparsers.add_parser(
        "check",
        help="Evaluate a command against System 1 provider and local policy without executing it.",
    )
    _add_operation_args(check_parser)

    # 2. run (Evaluate and execute ONLY if authorized)
    run_parser = subparsers.add_parser(
        "run",
        help="Evaluate a command and execute it via ExecutionBroker only if policy authorizes ALLOW.",
    )
    _add_operation_args(run_parser)
    run_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Force dry-run mode (evaluate only, do not execute).",
    )
    run_parser.add_argument(
        "--execute",
        action="store_true",
        default=True,
        help="Execute the command if allowed (default for 'run' unless --dry-run is passed).",
    )

    # 3. configure (Interactive prompt for Decision Model Endpoint + API Token)
     subparsers.add_parser(
        "configure",
        help="Interactively configure your Decision Model provider (Jev, Laya, or Custom), Endpoint URL, and API Token.",
    )

    # 4. claude-hook (PreToolUse hook adapter for Claude Code / AI Coding Agents)
    hook_parser = subparsers.add_parser(
        "claude-hook",
        help="Claude Code PreToolUse hook: reads tool_input JSON from stdin, evaluates via Permission Fence, and returns exit code 0 (allow) or 2 (block).",
    )
    hook_parser.add_argument(
        "--intent",
        default="Claude Code proposed a shell command in the local workspace",
        help="Default intent description if not present in hook payload.",
    )

    # 5. history (Read recent audit events)
    hist_parser = subparsers.add_parser(
        "history",
        help="Inspect recent audit events recorded in SQLite.",
    )
    hist_parser.add_argument("--limit", type=int, default=20, help="Maximum number of events to return.")
    hist_parser.add_argument(
        "--decision",
        choices=["ALLOW", "BLOCK", "RECHECK"],
        default=None,
        help="Filter by final decision.",
    )

    # 6. doctor (Check current provider & policy configuration)
    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Validate current provider configuration, thresholds, and audit database health.",
    )
    doctor_parser.add_argument(
        "--live-ping",
        action="store_true",
        help="Send a lightweight test evaluation to the configured provider.",
    )

    # 7. demo (Run 7 safe disposable demo scenarios from Section 16)
    subparsers.add_parser(
        "demo",
        help="Run the 7 PRD demo scenarios in a disposable temporary directory using MockProvider.",
    )

    return parser


def _add_operation_args(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument("--command", "-c", default=None, help="Proposed shell command string.")
    subparser.add_argument(
        "--shell",
        default="powershell",
        choices=["powershell", "pwsh", "cmd", "sh", "bash"],
        help="Shell type (default: powershell).",
    )
    subparser.add_argument("--cwd", default=None, help="Working directory for the command.")
    subparser.add_argument("--intent", "-i", default=None, help="Stated user intent / justification.")
    subparser.add_argument("--source", default="cli", help="Invocation source (cli, agent-hook, dashboard).")
    subparser.add_argument("--agent", default=None, help="Coding agent name if known.")
    subparser.add_argument(
        "--stdin-json",
        action="store_true",
        help="Read operation request fields from JSON on stdin.",
    )
    subparser.add_argument(
        "--mock-scenario",
        default=None,
        help="Optional MockProvider scenario override for testing.",
    )


def _handle_configure() -> int:
    """Interactively prompt the user for their Decision Model provider, Endpoint URL, Model ID, and API Token."""
    print("=== Permission Fence: Decision Model Configuration ===")
    print("Select your System 1 Decision Model Provider:")
    print("  1) jev    (TypeSafe AI Jev -> https://api.typesafe.ai/v1/systemone)")
    print("  2) laya   (Laya Studio     -> https://api.laya.studio/v1/systemone)")
    print("  3) custom (Custom compatible /v1/systemone endpoint)")
    print("  4) mock   (Local deterministic testing without an API key)")

    choice = input("Enter choice [1/2/3/4 or name, default=1]: ").strip().lower()
    mapping = {"1": "jev", "2": "laya", "3": "custom", "4": "mock"}
    provider = mapping.get(choice, choice if choice in {"jev", "laya", "custom", "mock"} else "jev")

    default_base = "https://api.laya.studio" if provider == "laya" else "https://api.typesafe.ai"
    default_model = "typed-decisions" if provider == "laya" else ("mock-systemone-v1" if provider == "mock" else "jev-latest")

    base_url = input(f"Enter Decision Model Base URL [default={default_base}]: ").strip() or default_base
    endpoint = input("Enter API Endpoint Path [default=/v1/systemone]: ").strip() or "/v1/systemone"
    model_id = input(f"Enter Model ID [default={default_model}]: ").strip() or default_model

    api_key = ""
    if provider != "mock":
        try:
            api_key = getpass.getpass("Enter your Decision Model API Token (input is hidden): ").strip()
        except Exception:
            api_key = input("Enter your Decision Model API Token: ").strip()
        if not api_key:
            api_key = input("API Token was empty — paste your token here (visible): ").strip()

    thresh_str = input("Enter Allow Confidence Threshold [default=0.90]: ").strip() or "0.90"

    env_path = Path(".env")
    updates: Dict[str, object] = {
        "MODEL_PROVIDER": provider,
        "MODEL_BASE_URL": base_url,
        "MODEL_ENDPOINT": endpoint,
        "MODEL_ID": model_id,
        "ALLOW_THRESHOLD": thresh_str,
        "RECHECK_THRESHOLD": thresh_str,
    }
    if api_key:
        updates["MODEL_API_KEY"] = api_key

    save_settings_to_env(env_path, updates)
    settings = load_settings(env_path=env_path)
    print("\n[OK] Saved configuration to .env!")
    print(f"  Provider     : {settings.model_provider}")
    print(f"  Endpoint URL : {settings.full_endpoint_url}")
    print(f"  Model ID     : {settings.model_id}")
    print(f"  API Token    : {settings.masked_api_key()}")

    if provider != "mock" and api_key:
        print("\nTesting live connection to your decision model...")
        prov_instance = get_provider(settings)
        op = build_operation_request(
            command="Get-ChildItem .",
            working_directory=os.getcwd(),
            user_intent="Configuration connectivity test",
            invocation_source="configure",
        )
        packed = pack_context(op, settings)
        res = prov_instance.evaluate(DecisionRequest(operation_id=op.operation_id, packed_context=packed))
        if res.is_valid_schema and not res.provider_error:
            print(f"[SUCCESS] Connected to {settings.full_endpoint_url} in {res.latency_ms}ms! (Confidence={res.confidence})")
        else:
            print(f"[WARNING] Connection test returned: {res.provider_error}")
    return 0


def _handle_claude_hook(args: argparse.Namespace, settings: FenceSettings) -> int:
    """
    Claude Code PreToolUse Hook handler.
    Claude Code sends JSON on stdin:
    {
      "session_id": "...",
      "cwd": "...",
      "hook_event_name": "PreToolUse",
      "tool_name": "Bash",
      "tool_input": {
        "command": "rm -rf build",
        "description": "Clean build folder"
      }
    }
    Exit code 0 = Allow Claude Code to run the command.
    Exit code 2 = Block Claude Code from running the command (stderr is shown to Claude and the user).
    """
    payload = _parse_stdin_json()
    tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else payload

    command = (
        tool_input.get("command")
        or payload.get("command")
        or ""
    )
    intent = (
        tool_input.get("description")
        or tool_input.get("intent")
        or payload.get("user_intent")
        or args.intent
    )
    cwd = payload.get("cwd") or payload.get("working_directory") or os.getcwd()

    if not command or not str(command).strip():
        return 0

    try:
        operation = build_operation_request(
            command=str(command),
            working_directory=str(cwd),
            user_intent=str(intent) if intent else None,
            shell="powershell",
            invocation_source="agent-hook",
            agent_name="claude-code",
        )
    except Exception as exc:
        sys.stderr.write(f"[PERMISSION FENCE BLOCKED] Invalid operation request: {exc}\n")
        return 2

    if settings.allowed_workspace_root in {".", os.getcwd()}:
        settings.allowed_workspace_root = operation.working_directory

    provider = get_provider(settings)
    coordinator = PermissionFenceCoordinator(
        settings=settings,
        provider=provider,
        emit_cli_notifications=True,
    )

    # PreToolUse hook evaluates and authorizes; if ALLOW, return 0 so Claude Code proceeds; if BLOCK, return 2!
    outcome = coordinator.handle_operation(operation=operation, execute_if_allowed=False)
    res = outcome.decision_result

    if res.decision == FinalDecision.ALLOW:
        return 0
    return 2


def _handle_check_or_run(
    args: argparse.Namespace,
    settings: FenceSettings,
    is_run_subcommand: bool,
) -> int:
    stdin_data = _parse_stdin_json() if getattr(args, "stdin_json", False) else {}

    command = args.command or stdin_data.get("command")
    shell = args.shell or stdin_data.get("shell", "powershell")
    cwd = args.cwd or stdin_data.get("working_directory") or os.getcwd()
    intent = args.intent if args.intent is not None else stdin_data.get("user_intent")
    source = args.source or stdin_data.get("invocation_source", "cli")
    agent = args.agent or stdin_data.get("agent_name")

    try:
        operation = build_operation_request(
            command=command or "",
            working_directory=cwd,
            user_intent=intent,
            shell=shell,
            invocation_source=source,
            agent_name=agent,
        )
    except Exception as exc:
        err_payload = {"error": str(exc), "decision": "BLOCK", "execution_status": "NOT_EXECUTED"}
        if args.json:
            print(json.dumps(err_payload, indent=2))
        else:
            sys.stderr.write(f"[PERMISSION FENCE ERROR] {exc}\n")
        return 2

    # Ensure workspace root covers cwd if ALLOWED_WORKSPACE_ROOT was default '.'
    if settings.allowed_workspace_root in {".", os.getcwd()}:
        settings.allowed_workspace_root = operation.working_directory

    provider = get_provider(settings, mock_scenario=getattr(args, "mock_scenario", None))
    coordinator = PermissionFenceCoordinator(
        settings=settings,
        provider=provider,
        emit_cli_notifications=not args.json,
    )

    # `check` NEVER executes. `run` executes only if --dry-run is False.
    execute_if_allowed = bool(is_run_subcommand and not getattr(args, "dry_run", False))

    outcome = coordinator.handle_operation(
        operation=operation,
        execute_if_allowed=execute_if_allowed,
    )
    res = outcome.decision_result
    exec_res = outcome.execution_result
    model_res = res.recheck_model_result or res.first_model_result

    if args.json:
        output = {
            "operation_id": res.operation_id,
            "decision": res.decision.value,
            "reason_code": res.reason_code,
            "explanation": res.explanation,
            "recheck_count": res.recheck_count,
            "authorized_command_digest": res.authorized_command_digest,
            "execution_status": res.execution_status.value,
            "provider": model_res.provider if model_res else settings.model_provider,
            "model_id": model_res.model_id if model_res else settings.model_id,
            "action_class": model_res.action_class.value if model_res else "unclear",
            "confidence": model_res.confidence if model_res else None,
            "scores": model_res.scores.model_dump() if model_res else {},
            "exit_code": exec_res.exit_code if exec_res else None,
            "stdout": exec_res.redacted_stdout if exec_res else "",
            "stderr": exec_res.redacted_stderr if exec_res else "",
        }
        print(json.dumps(output, indent=2))
    else:
        mode_label = "EXECUTE MODE (run)" if execute_if_allowed else "DRY-RUN MODE (check)"
        conf_str = f"{model_res.confidence:.2f}" if (model_res and model_res.confidence is not None) else "N/A"
        cls_str = model_res.action_class.value if model_res else "N/A"
        print(f"=== Permission Fence [{mode_label}] ===")
        print(f"Operation ID : {res.operation_id}")
        print(f"Command      : {outcome.audit_record.full_redacted_command}")
        print(f"Working Dir  : {operation.working_directory}")
        print(f"User Intent  : {outcome.audit_record.user_intent_summary or '<MISSING>'}")
        print(f"Provider     : {outcome.audit_record.provider} ({outcome.audit_record.model_id})")
        print(f"Classification: {cls_str} (confidence={conf_str}, rechecks={res.recheck_count})")
        print(f"Decision     : {res.decision.value} [{res.reason_code}]")
        print(f"Explanation  : {res.explanation}")
        print(f"Exec Status  : {res.execution_status.value}")
        if exec_res and exec_res.redacted_stdout:
            print(f"--- STDOUT ---\n{exec_res.redacted_stdout.rstrip()}")
        if exec_res and exec_res.redacted_stderr:
            print(f"--- STDERR ---\n{exec_res.redacted_stderr.rstrip()}")

    if res.decision != FinalDecision.ALLOW:
        return 3
    if exec_res and exec_res.exit_code not in (None, 0):
        return int(exec_res.exit_code)
    return 0


def _handle_history(args: argparse.Namespace, settings: FenceSettings) -> int:
    store = AuditStore(db_path=settings.audit_db_path, strict_mode=False)
    events = store.list_recent(limit=args.limit, decision_filter=args.decision)
    if args.json:
        print(json.dumps([e.model_dump() for e in events], indent=2))
        return 0

    print(f"=== Permission Fence Audit History (showing {len(events)} event(s)) ===")
    if not events:
        print("No audit events recorded yet.")
        return 0

    header = (
        f"{'TIMESTAMP (UTC)':<20} | {'DECISION':<7} | {'CLASS':<20} | "
        f"{'CONF':<5} | {'RECHK':<5} | {'EXEC STATUS':<12} | {'COMMAND'}"
    )
    print(header)
    print("-" * len(header))
    for ev in events:
        ts_short = ev.timestamp[:19].replace("T", " ")
        conf_str = f"{ev.confidence:.2f}" if ev.confidence is not None else " N/A "
        print(
            f"{ts_short:<20} | {ev.final_decision:<7} | {ev.action_class:<20} | "
            f"{conf_str:<5} | {ev.recheck_count:<5} | {ev.execution_status:<12} | {ev.command_summary}"
        )
    return 0


def _handle_doctor(args: argparse.Namespace, settings: FenceSettings) -> int:
    store = AuditStore(db_path=settings.audit_db_path, strict_mode=False)
    metrics = store.get_summary_metrics()
    key_configured = bool(settings.model_api_key and settings.model_api_key != "replace_me")
    provider_ready = settings.model_provider == "mock" or key_configured

    report: Dict[str, Any] = {
        "status": "READY" if provider_ready else "WARNING_MISSING_API_KEY",
        "settings": settings.to_safe_dict(),
        "endpoint_url": settings.full_endpoint_url,
        "audit_db_path": str(Path(settings.audit_db_path).resolve()),
        "audit_summary": metrics,
    }

    if args.live_ping:
        provider = get_provider(settings)
        op = build_operation_request(
            command="Get-ChildItem .",
            working_directory=os.getcwd(),
            user_intent="Doctor connectivity check",
            invocation_source="doctor",
        )
        packed = pack_context(op, settings)
        ping_res = provider.evaluate(DecisionRequest(operation_id=op.operation_id, packed_context=packed))
        report["live_ping"] = {
            "is_valid_schema": ping_res.is_valid_schema,
            "latency_ms": ping_res.latency_ms,
            "action_class": ping_res.action_class.value,
            "confidence": ping_res.confidence,
            "provider_error": ping_res.provider_error,
        }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("=== Permission Fence Doctor ===")
        print(f"Overall Status   : {report['status']}")
        print(f"Provider         : {settings.model_provider}")
        print(f"Endpoint URL     : {settings.full_endpoint_url}")
        print(f"Model ID         : {settings.model_id}")
        print(f"API Key          : {settings.masked_api_key()}")
        print(f"Allow Threshold  : {settings.allow_threshold:.2f} (experimental — calibrate on labeled tests)")
        print(f"Max Rechecks     : {settings.max_rechecks}")
        print(f"Model Timeout    : {settings.model_timeout_seconds}s")
        print(f"Audit DB Path    : {report['audit_db_path']} (strict_mode={settings.strict_audit_mode})")
        print(
            f"Audit Events     : {metrics['total_evaluated']} total "
            f"({metrics['allowed_count']} allowed, {metrics['blocked_count']} blocked, "
            f"{metrics['rechecked_count']} rechecked)"
        )
        if "live_ping" in report:
            lp = report["live_ping"]
            print(
                f"Live Ping Result : valid={lp['is_valid_schema']}, latency={lp['latency_ms']}ms, "
                f"error={lp['provider_error']}"
            )
    return 0


def _handle_demo(args: argparse.Namespace, settings: FenceSettings) -> int:
    """Run all 7 manual demo scenarios from Section 16 in a disposable directory and populate audit DB."""
    settings.model_provider = "mock"
    store = AuditStore(db_path=settings.audit_db_path, strict_mode=True)

    with tempfile.TemporaryDirectory(prefix="fence_demo_") as tmp_dir:
        settings.allowed_workspace_root = tmp_dir
        scenarios = [
            {
                "name": "1. Safe read-only command in disposable workspace",
                "command": "Get-ChildItem .",
                "intent": "List files in the demo workspace",
                "execute": True,
                "mock_scenario": None,
            },
            {
                "name": "2. Explicit creation of a disposable test file",
                "command": 'New-Item -Path .\\demo_note.txt -ItemType File -Value "hello fence"',
                "intent": "Create a disposable demo_note.txt file in the workspace",
                "execute": True,
                "mock_scenario": None,
            },
            {
                "name": "3. Attempt to delete a test file (blocked by policy/model)",
                "command": "Remove-Item .\\demo_note.txt",
                "intent": "Inspect project status",
                "execute": True,
                "mock_scenario": None,
            },
            {
                "name": "4. Uncertain result followed by a safe 1x recheck using enriched context",
                "command": "Get-ChildItem .",
                "intent": None,
                "execute": True,
                "mock_scenario": "uncertain_then_allow",
            },
            {
                "name": "5. Uncertain result after 1x recheck (fails closed and blocks)",
                "command": "Invoke-CustomBuildStep -Target all",
                "intent": None,
                "execute": True,
                "mock_scenario": "always_uncertain",
            },
            {
                "name": "6. Provider API unavailable / timeout (fails closed and blocks)",
                "command": "Get-Location",
                "intent": "Check current working directory",
                "execute": True,
                "mock_scenario": "timeout",
            },
            {
                "name": "7. Mandatory deny rule on recursive wildcard delete",
                "command": "Remove-Item -Recurse -Force C:\\Windows\\System32\\*",
                "intent": "Clean temporary files",
                "execute": True,
                "mock_scenario": None,
            },
        ]

        results_summary = []
        for sc in scenarios:
            provider = get_provider(settings, mock_scenario=sc["mock_scenario"])
            coordinator = PermissionFenceCoordinator(
                settings=settings,
                provider=provider,
                audit_store=store,
                emit_cli_notifications=not args.json,
            )
            op = build_operation_request(
                command=sc["command"],
                working_directory=tmp_dir,
                user_intent=sc["intent"],
                invocation_source="demo-suite",
                agent_name="demo-agent",
            )
            outcome = coordinator.handle_operation(op, execute_if_allowed=sc["execute"])
            results_summary.append(
                {
                    "scenario": sc["name"],
                    "command": sc["command"],
                    "decision": outcome.decision_result.decision.value,
                    "reason_code": outcome.decision_result.reason_code,
                    "recheck_count": outcome.decision_result.recheck_count,
                    "execution_status": outcome.decision_result.execution_status.value,
                }
            )

    if args.json:
        print(json.dumps(results_summary, indent=2))
    else:
        print("\n=== Permission Fence Demo Suite Completed (7 Scenarios) ===")
        for item in results_summary:
            print(
                f"- {item['scenario']}\n"
                f"  Decision: {item['decision']} | Rechecks: {item['recheck_count']} | "
                f"Exec: {item['execution_status']} | Reason: {item['reason_code']}"
            )
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.subcommand == "configure":
        return _handle_configure()

    overrides: Dict[str, object] = {}
    if args.provider:
        overrides["model_provider"] = args.provider
    if args.db_path:
        overrides["audit_db_path"] = args.db_path

    settings = load_settings(overrides=overrides)

    if args.subcommand == "check":
        return _handle_check_or_run(args, settings, is_run_subcommand=False)
    if args.subcommand == "run":
        return _handle_check_or_run(args, settings, is_run_subcommand=True)
    if args.subcommand == "claude-hook":
        return _handle_claude_hook(args, settings)
    if args.subcommand == "history":
        return _handle_history(args, settings)
    if args.subcommand == "doctor":
        return _handle_doctor(args, settings)
    if args.subcommand == "demo":
        return _handle_demo(args, settings)
    return 1


if __name__ == "__main__":
    sys.exit(main())
