"""Streamlit dark dashboard for Permission Fence (Section 6.3, FR-10, FR-11)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Ensure the project root directory is on sys.path when invoked via `streamlit run app/ui/dashboard.py` on Windows
PROJECT_ROOT = str(Path(__file__).resolve().parents[2])
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import streamlit as st

from app.audit import AuditStore
from app.config import load_settings, save_settings_to_env
from app.context import build_operation_request, pack_context
from app.coordinator import PermissionFenceCoordinator
from app.providers import get_provider
from app.schemas import DecisionRequest, FinalDecision


st.set_page_config(
    page_title="Permission Fence | Local Command Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Dark charcoal theme styling per Section 6.3
DARK_CSS = """
<style>
    .stApp {
        background-color: #121417;
        color: #F3F4F6;
    }
    div[data-testid="stMetric"] {
        background-color: #1A1D24;
        border: 1px solid #2A2F3A;
        border-radius: 8px;
        padding: 14px 16px;
    }
    .fence-card {
        background-color: #1A1D24;
        border: 1px solid #2A2F3A;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 14px;
    }
</style>
"""
st.markdown(DARK_CSS, unsafe_allow_html=True)


def render_dashboard() -> None:
    env_path = Path(PROJECT_ROOT) / ".env"
    settings = load_settings(env_path=env_path if env_path.exists() else None)
    audit_store = AuditStore(db_path=settings.audit_db_path, strict_mode=False)
    metrics = audit_store.get_summary_metrics()

    # Header
    st.markdown("## 🛡️ Permission Fence")
    st.caption(
        "Local-first System 1 command permission gateway for coding agents · "
        f"Active Provider: **{settings.model_provider.upper()}** (`{settings.full_endpoint_url}`)"
    )

    # Privacy disclosure banner required by FR-02 & Section 15
    st.info(
        f"**Endpoint Disclosure:** Submitted command and redacted workspace context are sent to "
        f"`{settings.full_endpoint_url}` (Provider: `{settings.model_provider}`, Model: `{settings.model_id}`). "
        "Secrets and `.env` values are automatically redacted before transmission."
    )

    # Overview metrics row (Section 6.3)
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    col1.metric("Evaluated", metrics["total_evaluated"])
    col2.metric("Allowed", metrics["allowed_count"])
    col3.metric("Blocked", metrics["blocked_count"])
    col4.metric("Rechecked (1x)", metrics["rechecked_count"])
    col5.metric("Avg Latency", f"{metrics['avg_latency_ms']} ms")
    col6.metric("Provider Health", metrics["provider_health"])

    tab_activity, tab_test, tab_detail, tab_provider, tab_policy = st.tabs(
        [
            "📋 Recent Activity",
            "🧪 Command Test Panel",
            "🔍 Event Detail Inspector",
            "🔌 Provider Settings",
            "⚖️ Policy & Thresholds",
        ]
    )

    # 1. Recent Activity Panel
    with tab_activity:
        c_filter, c_limit, c_btn = st.columns([2, 1, 1])
        with c_filter:
            decision_filter = st.selectbox("Filter by Decision", ["ALL", "ALLOW", "BLOCK", "RECHECK"])
        with c_limit:
            row_limit = st.number_input("Max Rows", min_value=5, max_value=200, value=30, step=5)
        with c_btn:
            if st.button("Seed 7 Demo Scenarios"):
                from app.main import _handle_demo
                import argparse

                _handle_demo(argparse.Namespace(json=True), settings)
                st.rerun()

        events = audit_store.list_recent(
            limit=int(row_limit),
            decision_filter=None if decision_filter == "ALL" else decision_filter,
        )
        if not events:
            st.warning("No audit events found. Use 'Seed 7 Demo Scenarios' or the Command Test Panel.")
        else:
            table_rows = []
            for ev in events:
                ctx_data = json.loads(ev.redacted_context_summary or "{}")
                targets = ", ".join(ctx_data.get("target_paths") or ["."])
                table_rows.append(
                    {
                        "Timestamp": ev.timestamp[:19].replace("T", " "),
                        "ID": ev.operation_id[:8],
                        "Command": ev.command_summary,
                        "Target": targets,
                        "Decision": ev.final_decision,
                        "Action Class": ev.action_class,
                        "Confidence": f"{ev.confidence:.2f}" if ev.confidence is not None else "N/A",
                        "Provider/Model": f"{ev.provider}:{ev.model_id}",
                        "Rechecks": ev.recheck_count,
                        "Exec Status": ev.execution_status,
                        "Reason": ev.policy_reason_code,
                    }
                )
            st.dataframe(table_rows, use_container_width=True, hide_index=True)

    # 2. Command Test Panel
    with tab_test:
        st.subheader("Interactive Command Evaluation & Execution")
        st.warning(
            "**Security Notice:** 'Evaluate Only' runs the System 1 model and deterministic policy checks without "
            "creating a child process. 'Evaluate and Execute' will run the PowerShell command locally if authorized."
        )
        test_cmd = st.text_input("Proposed PowerShell Command", value="Get-ChildItem .")
        test_intent = st.text_input(
            "Original User Intent / Context",
            value="Inspect files in the current project directory",
        )
        test_cwd = st.text_input("Working Directory", value=os.getcwd())
        mock_mode = st.selectbox(
            "Mock Scenario Override (used when provider is 'mock')",
            ["(Heuristic Default)", "uncertain_then_allow", "always_uncertain", "always_block", "timeout", "malformed"],
        )

        b_eval, b_exec = st.columns(2)
        eval_clicked = b_eval.button("🔎 Evaluate Only (Safe Dry-Run)", use_container_width=True)
        exec_clicked = b_exec.button("⚡ Evaluate and Execute", type="primary", use_container_width=True)

        if eval_clicked or exec_clicked:
            try:
                op = build_operation_request(
                    command=test_cmd,
                    working_directory=test_cwd,
                    user_intent=test_intent,
                    shell="powershell",
                    invocation_source="dashboard",
                )
                scenario = None if mock_mode == "(Heuristic Default)" else mock_mode
                provider = get_provider(settings, mock_scenario=scenario)
                coordinator = PermissionFenceCoordinator(
                    settings=settings,
                    provider=provider,
                    audit_store=audit_store,
                    emit_cli_notifications=False,
                )
                outcome = coordinator.handle_operation(op, execute_if_allowed=bool(exec_clicked))
                res = outcome.decision_result
                if res.decision == FinalDecision.ALLOW:
                    st.success(
                        f"**ALLOW** [{res.reason_code}] — {res.explanation} "
                        f"(Execution Status: `{res.execution_status.value}`)"
                    )
                else:
                    st.error(outcome.notification_outcome.cli_message if outcome.notification_outcome else res.explanation)

                st.json(
                    {
                        "operation_id": res.operation_id,
                        "decision": res.decision.value,
                        "reason_code": res.reason_code,
                        "recheck_count": res.recheck_count,
                        "authorized_command_digest": res.authorized_command_digest,
                        "execution_status": res.execution_status.value,
                        "model_result": (
                            (res.recheck_model_result or res.first_model_result).model_dump()
                            if (res.recheck_model_result or res.first_model_result)
                            else None
                        ),
                        "execution_output": (
                            outcome.execution_result.model_dump() if outcome.execution_result else None
                        ),
                    }
                )
            except Exception as exc:
                st.error(f"Validation / Intake Error: {exc}")

    # 3. Event Detail Inspector
    with tab_detail:
        st.subheader("Audit Event Inspector (Secrets Redacted)")
        all_events = audit_store.list_recent(limit=100)
        if not all_events:
            st.info("No audit events available.")
        else:
            selected_id = st.selectbox(
                "Select Operation Event",
                options=[e.operation_id for e in all_events],
                format_func=lambda oid: next(
                    (
                        f"{e.timestamp[:19]} | {e.final_decision} | {e.command_summary} ({oid[:8]})"
                        for e in all_events
                        if e.operation_id == oid
                    ),
                    oid,
                ),
            )
            ev_detail = audit_store.get_event(selected_id)
            if ev_detail:
                st.json(ev_detail.model_dump())

    # 4. Provider Settings
    with tab_provider:
        st.subheader("System 1 Decision Provider Settings")
        st.caption(f"Saved API Key Status: `{settings.masked_api_key()}` (Secrets are masked and never echoed)")
        with st.form("provider_settings_form"):
            prov_name = st.selectbox(
                "Provider",
                options=["jev", "laya", "custom", "mock"],
                index=["jev", "laya", "custom", "mock"].index(settings.model_provider),
            )
            base_url = st.text_input("Endpoint Base URL", value=settings.model_base_url)
            endpoint_route = st.text_input("API Route", value=settings.model_endpoint)
            model_id = st.text_input("Model ID", value=settings.model_id)
            new_api_key = st.text_input(
                "New API Key (leave blank to keep existing key)",
                value="",
                type="password",
            )
            timeout_sec = st.number_input(
                "Model Timeout (seconds)",
                min_value=0.5,
                max_value=60.0,
                value=float(settings.model_timeout_seconds),
                step=0.5,
            )
            save_prov = st.form_submit_button("Save Provider Settings")
            if save_prov:
                updates = {
                    "MODEL_PROVIDER": prov_name,
                    "MODEL_BASE_URL": base_url,
                    "MODEL_ENDPOINT": endpoint_route,
                    "MODEL_ID": model_id,
                    "MODEL_TIMEOUT_SECONDS": str(timeout_sec),
                }
                if new_api_key.strip():
                    updates["MODEL_API_KEY"] = new_api_key.strip()
                save_settings_to_env(env_path, updates)
                st.success("Provider settings saved to `.env`. API key remains masked.")

        if st.button("🔌 Test Provider Connection"):
            provider = get_provider(settings)
            op = build_operation_request(
                command="Get-ChildItem .",
                working_directory=os.getcwd(),
                user_intent="Dashboard connectivity check",
                invocation_source="dashboard",
            )
            packed = pack_context(op, settings)
            ping_res = provider.evaluate(DecisionRequest(operation_id=op.operation_id, packed_context=packed))
            if ping_res.is_valid_schema and not ping_res.provider_error:
                st.success(
                    f"Connection OK! Model `{ping_res.model_id}` responded in {ping_res.latency_ms} ms "
                    f"(action_class={ping_res.action_class.value}, confidence={ping_res.confidence})."
                )
            else:
                st.error(f"Provider test failed (Fail-Closed active): {ping_res.provider_error}")

    # 5. Policy Settings
    with tab_policy:
        st.subheader("Policy & Threshold Configuration")
        st.warning(
            "**Experimental Threshold Notice:** Confidence thresholds are experimental defaults for demonstration "
            "and must be calibrated and validated on your labeled workloads. A high model confidence score is never "
            "a substitute for deterministic security boundaries."
        )
        with st.form("policy_settings_form"):
            allow_thresh = st.slider(
                "Allow Confidence Threshold (ALLOW_THRESHOLD)",
                min_value=0.50,
                max_value=0.99,
                value=float(settings.allow_threshold),
                step=0.01,
            )
            risk_ceil = st.slider(
                "Maximum Unintended Damage Risk Ceiling (RISK_CEILING)",
                min_value=0.01,
                max_value=0.50,
                value=float(settings.risk_ceiling),
                step=0.01,
            )
            max_rechecks = st.selectbox(
                "Maximum Automatic Rechecks (MAX_RECHECKS — bounded at 1 for MVP)",
                options=[0, 1],
                index=1 if settings.max_rechecks >= 1 else 0,
            )
            prot_paths_str = st.text_area(
                "Protected Paths (semicolon-separated)",
                value="; ".join(settings.protected_paths),
            )
            save_pol = st.form_submit_button("Save Policy Settings")
            if save_pol:
                updates = {
                    "ALLOW_THRESHOLD": f"{allow_thresh:.2f}",
                    "RECHECK_THRESHOLD": f"{allow_thresh:.2f}",
                    "RISK_CEILING": f"{risk_ceil:.2f}",
                    "MAX_RECHECKS": str(max_rechecks),
                    "PROTECTED_PATHS": ";".join(
                        [p.strip() for p in prot_paths_str.split(";") if p.strip()]
                    ),
                }
                save_settings_to_env(env_path, updates)
                st.success("Policy settings updated in `.env`.")


if __name__ == "__main__":
    render_dashboard()
