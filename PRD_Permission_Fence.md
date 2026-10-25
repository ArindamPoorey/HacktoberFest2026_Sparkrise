# Permission Fence
## Product Requirements Document (PRD)

**Document status:** Implementation-ready draft for hackathon prototype  
**Version:** 1.0  
**Target platform:** Windows local laptop  
**Primary implementation language:** Python  
**Decision models:** Jev, Laya, or any compatible/custom decision endpoint  
**Scope:** Local command permission gateway with an extensible design for future integrations

---

## 1. Executive Summary

Permission Fence is a local-first authorization layer placed between a coding agent and the commands it is allowed to execute. Before a command routed through the fence can run, the system packages the command with relevant context, asks a configurable System 1 decision model to classify it, applies deterministic security policies and confidence thresholds, and then allows execution, performs one bounded recheck, or blocks the command. Every blocked attempt must notify the user and be recorded in an audit log.

The prototype targets Windows PowerShell commands and one explicit execution path. Its interfaces must be model-agnostic so a user can switch Jev, Laya, or another compatible decision API through configuration or a small provider adapter. It must not require a general-purpose LLM to review every command.

**Security principle:** the model recommends a decision; local policy and the execution broker enforce it. A confidence score alone is never sufficient evidence that an operation is safe.

## 2. Problem Statement

Coding agents can propose shell commands that modify files, delete data, change permissions, install software, or affect system configuration. An agent can misunderstand intent, infer incorrect requirements, or suggest a command whose side effects exceed what the user requested. The user needs a fast, visible permission boundary before supported commands execute.

The system should answer:

- What command or operation is about to run?
- What user request and environment context justify it?
- What does a specialized decision model predict about the action?
- Is the model's confidence sufficient, and do deterministic policies permit it?
- If the result is ambiguous or the provider fails, what happens next?
- If an operation is blocked, was the user notified and was the command prevented from running?

## 3. Product Goals

1. Intercept commands routed through the supported fence integration before process creation.
2. Attach relevant context, including the original user intent when available, command, shell, working directory, target paths, and optional project metadata.
3. Support Jev, Laya, and compatible custom decision endpoints through a provider abstraction.
4. Normalize provider-specific responses to a consistent decision schema.
5. Apply configurable confidence thresholds plus mandatory deterministic policies.
6. Perform at most one automatic recheck for an uncertain result, preferably with additional context. Never retry indefinitely.
7. Allow an operation only after it passes policy checks and its exact command and target remain unchanged.
8. Notify the user every time the fence blocks an operation.
9. Write an auditable record for every decision and execution outcome.
10. Provide a clean, dark local dashboard for status, recent decisions, provider configuration, thresholds, and safe testing.
11. Keep the design extensible for future database, API, MCP, Git, and cloud-resource connectors.

## 4. Non-Goals for the Hackathon MVP

- Intercepting every process or every application on Windows at the operating-system level.
- Claiming protection when an agent can bypass the wrapper and invoke PowerShell or another tool directly.
- Supporting database, remote server, cloud, API, MCP, and all coding-agent integrations on day one.
- Training or hosting a new decision model.
- Using a general-purpose LLM as the primary evaluator.
- Building a multi-user SaaS control plane, enterprise identity system, or remote policy-management service.
- Treating a high model confidence score as a formal security guarantee.
- Automatically retrying an uncertain operation forever.

## 5. Target Users and Primary Use Case

**Primary user:** a developer using a coding agent on a Windows laptop who wants a safety checkpoint before supported local commands execute.

**Primary use case:** the agent proposes a PowerShell command. Permission Fence receives the command and context, evaluates it using a configured decision model, applies policy, and either executes the approved command or blocks it with a visible reason.

**Secondary use case:** the developer uses the dashboard to test a command, view the decision and confidence, change the configured provider, and inspect past blocked actions.

## 6. MVP User Experience

### 6.1 Interaction flow

1. A supported agent hook or the user submits a command to `fence run`.
2. The gateway builds and validates a structured operation record.
3. Local deterministic rules identify prohibited targets and malformed or unsupported operations.
4. The configured decision provider evaluates the operation and context.
5. The policy layer evaluates the model output, confidence, scope, and mandatory rules.
6. A clear outcome is returned: **ALLOW**, **RECHECK**, or **BLOCK**.
7. If allowed, the execution broker launches the exact approved command in the approved working directory.
8. If blocked, the command is not launched. The CLI displays a warning, the dashboard records the event, and a Windows toast notification is attempted when available.
9. The audit log records the decision and execution result.

### 6.2 User-visible block notification

Every block must produce an immediate visible message, at minimum in the command output and the audit event. The dashboard must show the event in its recent activity feed. A Windows desktop toast should be implemented if feasible within the timebox.

**Example notification**

> BLOCKED. `Remove-Item .\important.txt` was not executed. Reason: the target is not sufficiently justified by the supplied intent, or the decision confidence did not meet the configured threshold. Review the event in Permission Fence.

The actual message must include the relevant command in a length-limited, secret-redacted form, the reason category, and the explicit statement that it was not executed. Do not expose API keys or environment-variable values.

### 6.3 Dashboard visual direction

Build a compact, responsive, dark dashboard with a charcoal background, white primary text, grey secondary text, subtle borders, and a restrained blue accent. Use semantic status colors only for decision states. Avoid decorative gradients that reduce readability.

**Required screens / panels**

- **Overview:** counts for evaluated, allowed, blocked, rechecked, recent model latency, and provider health.
- **Recent activity:** timestamp, shortened command, target, decision, confidence, model/provider, recheck count, and execution status.
- **Command test panel:** command input, original intent/context field, working-directory field, and separate **Evaluate only** and **Evaluate and execute** actions. Show a clear warning before executing a command.
- **Provider settings:** provider name, endpoint URL, API route, model ID, API key field, timeout, and connection test. Secrets must be masked and never shown again after save.
- **Policy settings:** allow threshold, recheck threshold, maximum rechecks, protected-path rules, and high-impact operation rules. Show a warning that thresholds are experimental and must be validated.
- **Event detail:** normalized input context, model result, confidence/scores, policy outcome, reason, timestamps, and process exit code where applicable. Redact secrets.

**MVP UI implementation:** Streamlit. This keeps the dashboard in Python and is faster than creating a separate React frontend. The CLI remains the primary command interception path.

## 7. Functional Requirements

### FR-01. Command intake

- Accept a command as a structured string or argument list, shell type, working directory, invocation source, and optional user intent/context.
- Reject empty commands and invalid working directories.
- Assign a unique operation ID and timestamp to every request.
- Accept context through CLI arguments, JSON on stdin, or an agent-hook adapter.
- Mark missing user intent or missing target context explicitly; do not invent it.

### FR-02. Context packaging

The context packer should include only information relevant to the decision:

- Original user request or stated intent, if available.
- Exact proposed command and shell type.
- Working directory and inferred target paths, if available.
- Invocation source and agent name, if known.
- Environment label when known, such as local development or production.
- Relevant policy rules and a short project-state summary, if requested and safe to collect.
- Prior decision and newly acquired evidence during recheck.

Do not upload entire repositories, arbitrary files, `.env` files, API keys, access tokens, or all conversation history by default. Redact likely secrets before sending context to a hosted provider. The UI must disclose that submitted command/context data is sent to the configured endpoint.

### FR-03. Decision provider abstraction

Define a stable interface such as:

```python
class DecisionProvider:
    def evaluate(self, request: DecisionRequest) -> DecisionResult:
        ...
```

Every provider adapter must:

- Send the request using the provider's required API schema.
- Apply a timeout and bounded retry for transport errors only.
- Validate the response schema and reject malformed results.
- Normalize model name/version, output labels, confidence/probabilities, latency, usage, and request ID when available.
- Never execute commands or modify the policy directly.
- Avoid logging API keys or raw sensitive context.

Required adapters for the prototype:

1. `JevProvider`.
2. `LayaProvider` where the selected endpoint supports the expected protocol.
3. `CustomProvider` for a configured endpoint compatible with the documented schema.
4. `MockProvider` for deterministic tests without API usage.

The endpoint is configurable. If a third-party provider uses a different request/response schema, add a small adapter rather than assuming that changing the URL is sufficient.

### FR-04. Standard decision request

Use a single structured state with several atomic questions rather than asking one vague question about overall safety. The exact question schema must match the selected provider's API.

Recommended decision dimensions:

- `action_class`: `read_only`, `routine_mutation`, `destructive_mutation`, `security_sensitive`, or `unclear`.
- `matches_user_intent`: whether the action is directly justified by the supplied request.
- `target_in_scope`: whether the target is within the known authorized workspace/scope.
- `unintended_damage_risk`: whether the command appears likely to cause unintended loss or side effects.
- `needs_human_review`: whether the evidence is insufficient for automatic execution.

Keep questions specific and independent. The policy engine combines their normalized results; the model must not choose its own thresholds.

### FR-05. Local policy evaluation

The policy layer must apply these checks after model evaluation:

- Model response is valid and complete.
- Exact command and target are present and unchanged.
- Confidence meets the configured threshold for the relevant decision class.
- The operation aligns with available user intent.
- The target is inside the allowed scope.
- No mandatory deny rule applies.
- The operation is not prohibited by prototype policy.
- The provider and context have not timed out or failed.

The policy engine may downgrade an AI `ALLOW` to `RECHECK` or `BLOCK`, but the model cannot override mandatory policy. A model `BLOCK` must never be changed to `ALLOW` by the confidence threshold alone.

### FR-06. Confidence thresholds and recheck

Initial thresholds are configurable defaults for demonstration, not calibrated guarantees:

- `ALLOW_THRESHOLD = 0.90`.
- `RECHECK_THRESHOLD = 0.90` for relevant allow confidence, or any inconsistent/uncertain dimension.
- `MAX_RECHECKS = 1`.
- `MODEL_TIMEOUT_SECONDS = 5` initially, configurable.

The implementation must document which exact provider field becomes the normalized confidence score. Do not confuse a probability that a statement is true, the confidence of a selected category, and the risk probability. Keep these as distinct fields.

**State machine**

- Confident allow + policy pass: authorize execution.
- Confident block or mandatory deny: block and notify.
- Uncertain, contradictory, incomplete, or low-confidence result: perform one recheck.
- Recheck must use additional relevant evidence if available, such as parsed target paths, working directory, user intent, or deterministic command analysis. Simply repeating the same request and hoping for a higher score is not sufficient evidence.
- If the recheck returns a valid, high-confidence allow and all policies pass, execution may proceed.
- If the recheck says block, remains uncertain, fails, or returns malformed data, block by default and notify.
- Never use an unbounded retry loop.

### FR-07. Execution broker

- The execution broker is the only module in the project permitted to create the protected command process.
- It must only accept an authorization object produced by the policy layer.
- Bind authorization to the exact command, shell, working directory, and relevant target context. A SHA-256 digest can detect changes between evaluation and execution.
- Revalidate the digest immediately before process creation.
- Use a non-interactive PowerShell process with a fixed executable path and no profile loading.
- Do not execute a modified or substituted command.
- Capture start/end time, exit code, bounded stdout/stderr, and execution duration. Redact secrets in persisted output.
- Apply a timeout and terminate the child process on timeout where practical.
- Do not run with elevated/admin privileges by default.
- Require explicit user action for manual test-panel execution.

### FR-08. Block and failure notifications

Notify the user when a command is blocked because of risk, policy, uncertainty, timeout, or provider failure. Include command summary, decision reason, and “not executed” status. Required delivery channels:

- CLI response to the caller.
- Persistent audit event.
- Dashboard activity feed.

Windows toast is a desired MVP enhancement. Notification failure must not change a block into an allow.

### FR-09. Audit history

Store each evaluation and execution outcome in SQLite. Minimum fields:

- `operation_id`, timestamp, command summary, shell, working directory, invocation source.
- Redacted context summary and a context hash.
- Provider, model ID/version, endpoint label, latency, usage if available.
- Normalized action class, probabilities/confidence, first decision, recheck decision, final decision, policy reason.
- Authorization digest, start/end time, exit code, execution status.
- Notification status.

Never store API keys. Full raw model responses are optional and must be sanitized. Provide a retention setting; a reasonable prototype default is 7 days, with the ability to clear local history.

### FR-10. Configuration and provider switching

Support local configuration via `.env` and a UI settings page. Required settings:

```dotenv
MODEL_PROVIDER=jev
MODEL_BASE_URL=https://api.typesafe.ai
MODEL_ENDPOINT=/v1/systemone
MODEL_ID=jev-latest
MODEL_API_KEY=replace_me
ALLOW_THRESHOLD=0.90
MODEL_TIMEOUT_SECONDS=5
MAX_RECHECKS=1
```

The Laya adapter should use its documented API base and route, or another explicitly selected compatible endpoint. Do not assume every provider accepts the same URL, key format, or body. `.env` must be in `.gitignore`; `.env.example` must contain placeholders only. For a hackathon, a local `.env` is acceptable. Windows Credential Manager or another OS secret store can replace it later.

### FR-11. Demo and dry-run mode

- `--dry-run` evaluates but never executes.
- `--execute` requests evaluation and, if allowed, execution.
- Default behavior should be dry-run unless `run`/execution is explicitly requested.
- Include a mock provider and disposable test fixtures.
- Never test destructive examples against actual user data.

## 8. Policy Defaults

Prototype policy should be conservative and easy to explain.

| Condition | Default outcome |
|---|---|
| Read-only, high-confidence, in-scope action | Allow if all policy checks pass |
| Routine file mutation, explicitly requested, high-confidence, in-scope | Allow if deterministic rules pass |
| Delete/overwrite with explicit, exact target inside the test workspace | Evaluate carefully; allow only if intent, target scope, and risk checks all pass |
| Recursive delete, wildcard against a broad target, disk/partition formatting, destructive system configuration, privilege/security control modification, or protected-path mutation | Block or require explicit human approval regardless of model confidence |
| Missing/ambiguous user intent or target | Recheck once; then block by default |
| API timeout, invalid JSON, unsupported schema, missing confidence, rate limit, or authentication failure | Fail closed: do not execute; notify and log |
| Command/context changes after approval | Invalidate authorization and evaluate again |

Static patterns and path rules are safety nets, not a complete parser for every PowerShell construct. Avoid claiming that a list of dangerous strings can detect all destructive commands.

## 9. Technical Architecture

### 9.1 Runtime components

1. **CLI and hook adapter:** receives a proposed command and optional context.
2. **Operation normalizer:** validates and builds the operation object.
3. **Context packer/redactor:** collects only relevant local context and removes secrets.
4. **Provider adapter:** makes the System 1 API request and normalizes the response.
5. **Policy engine:** combines model results with deterministic rules.
6. **Recheck coordinator:** performs a single evidence-enhanced retry when needed.
7. **Execution broker:** validates authorization and launches the approved command.
8. **Audit and notification service:** persists events and notifies the user.
9. **Streamlit dashboard:** displays activity and manages safe settings.

### 9.2 Data flow

`Agent/CLI → Operation → Context packer → Local policy pre-check → Decision provider → Policy evaluation → Optional one-time recheck → Authorization token/digest → Executor → Audit + notification`

The context must be sent to the model before the final execution decision. Local deterministic pre-checks may block clearly prohibited operations without calling the provider; if product requirements later insist that every mutation be sent to the model regardless of local rules, the system can still record the pre-check and issue a model evaluation without ever allowing the model to override the local block. For the first MVP, model evaluation is required for eligible commands routed through the fence, while mandatory deny rules can short-circuit obviously prohibited operations for speed and safety.

### 9.3 Model API protocol

Jev's documented System One endpoint is `POST https://api.typesafe.ai/v1/systemone`, with bearer authentication and a JSON request containing `model`, `state`, and `questions`. The response is structured under `answers` and includes usage data. Laya Studio documents a `POST /v1/systemone` endpoint and describes it as Jev-compatible. Verify the exact selected provider's current documentation before wiring the adapter. See References.

### 9.4 Security boundaries

The MVP protects operations only when they are routed through the fence. A Python wrapper or PowerShell helper by itself cannot stop an agent from launching an alternate shell, another executable, a direct database connector, or a separate tool integration. For a stronger deployment, restrict the agent to a least-privilege account and controlled tools, and consider Windows Application Control/AppLocker/Constrained Language Mode where appropriate. These OS-level controls are a later hardening task, not part of a two-hour prototype.

## 10. Proposed Technology Stack

| Layer | Technology | Why |
|---|---|---|
| Main application | Python 3.11+ | Fast implementation, HTTP libraries, easy adapters |
| API client | `httpx` | Configurable HTTP calls, timeouts, and response handling |
| Typed data | Pydantic | Validate operation, provider response, and policy objects |
| Local config | `python-dotenv` | Simple local configuration for the prototype |
| CLI | `argparse` or Typer | Easy command invocation and exit codes |
| Windows command execution | PowerShell via Python `subprocess` | Execute supported local commands after authorization |
| Dashboard | Streamlit | Fast Python-only UI |
| Audit database | SQLite | No database server or cloud dependency required |
| Windows notifications | `winotify` or equivalent, optional | Desktop toast for blocked events |
| Testing | `pytest` | Unit, policy, and mocked integration tests |
| Packaging | `requirements.txt` and virtual environment | Reproducible local install |

Avoid FastAPI for the first cut unless an actual HTTP integration is needed. The CLI and Streamlit dashboard can call the same Python service functions. Introduce FastAPI later if multiple agents need a local network API.

## 11. Suggested Folder Structure

```text
permission-fence/
├── app/
│   ├── main.py                 # CLI entry point
│   ├── config.py               # Environment and settings validation
│   ├── schemas.py              # Operation, request, decision, audit schemas
│   ├── context.py              # Context packaging and secret redaction
│   ├── policy.py               # Deterministic rules and thresholds
│   ├── coordinator.py          # Evaluate -> recheck -> authorize flow
│   ├── audit.py                # SQLite read/write operations
│   ├── notifications.py        # CLI and Windows notifications
│   ├── providers/
│   │   ├── base.py             # Provider protocol and normalized result
│   │   ├── jev.py               # Jev System One adapter
│   │   ├── laya.py              # Laya-compatible adapter
│   │   ├── custom.py            # Configurable compatible endpoint
│   │   └── mock.py              # Deterministic tests/demo
│   ├── executor/
│   │   └── windows.py           # Authorized PowerShell executor only
│   └── ui/
│       └── dashboard.py         # Streamlit dashboard
├── scripts/
│   └── safe-run.ps1             # Optional agent-friendly wrapper
├── tests/
│   ├── test_policy.py
│   ├── test_recheck.py
│   ├── test_provider_normalization.py
│   ├── test_executor_gate.py
│   └── fixtures/
├── .env.example
├── .gitignore
├── requirements.txt
├── README.md
└── PRD_Permission_Fence.md
```

Keep modules small. Do not build separate microservices for the prototype.

## 12. Standard Data Contracts

### Operation request

```json
{
  "operation_id": "uuid",
  "command": "Get-ChildItem .",
  "shell": "powershell",
  "working_directory": "C:/projects/demo",
  "user_intent": "Inspect the project files",
  "invocation_source": "cli",
  "environment": "local-development",
  "context": {
    "target_paths": [],
    "git_summary": null
  }
}
```

### Normalized decision result

```json
{
  "provider": "jev",
  "model_id": "jev-latest",
  "model_version": null,
  "action_class": "read_only",
  "confidence": 0.97,
  "scores": {
    "matches_user_intent": 0.98,
    "target_in_scope": 0.99,
    "unintended_damage_risk": 0.02
  },
  "latency_ms": 240,
  "request_id": null
}
```

These are internal normalized examples, not literal provider responses. Each adapter maps its actual response to this structure. If the provider does not provide a requested score or a reliable confidence field, mark it unavailable and do not fabricate it.

### Final decision result

```json
{
  "operation_id": "uuid",
  "decision": "ALLOW",
  "reason_code": "HIGH_CONFIDENCE_IN_SCOPE",
  "recheck_count": 0,
  "authorized_command_digest": "sha256:...",
  "execution_status": "PENDING"
}
```

Supported final decisions: `ALLOW`, `RECHECK`, `BLOCK`. Execution statuses: `NOT_STARTED`, `RUNNING`, `SUCCEEDED`, `FAILED`, `TIMED_OUT`, `NOT_EXECUTED`.

## 13. CLI Contract

Initial commands:

```powershell
# Evaluate only. Does not execute.
python -m app.main check --shell powershell --command "Get-ChildItem ." --intent "Inspect the project"

# Evaluate and execute only if authorized.
python -m app.main run --shell powershell --command "Get-ChildItem ." --intent "Inspect the project"

# Read recent audit events.
python -m app.main history --limit 20

# Check current provider configuration.
python -m app.main doctor
```

Commands and argument syntax may be simplified during implementation, but `check` must never execute. `run` must never skip evaluation.

## 14. Error Handling

- **Provider timeout/unavailable:** fail closed; do not execute; notify and record the reason.
- **Authentication/credit/rate-limit error:** fail closed; give a concise actionable message without exposing secrets.
- **Malformed model output:** fail closed; treat as uncertain and allow only the single configured recheck if appropriate.
- **Missing context:** request optional context where possible; otherwise recheck once and then block.
- **Executor launch failure:** record `FAILED`; never silently retry a destructive command.
- **Executor timeout:** terminate if possible, record `TIMED_OUT`, and state that final system state may need manual inspection.
- **Audit failure:** in strict mode, do not execute unless the audit event can be recorded. The prototype should use strict mode by default.
- **Notification failure:** keep the operation blocked; write the notification failure into the audit event.

## 15. Privacy and Security Requirements

- API keys must be stored locally and excluded from version control.
- Do not send secret files or full repository contents to the decision provider.
- Redact likely credentials, tokens, and sensitive command arguments before remote evaluation and logging where feasible.
- Make it explicit in the UI which provider receives command/context data.
- Use HTTPS for remote endpoints by default. Allow plain HTTP only for an explicitly configured local endpoint.
- Do not follow cross-host redirects with authorization headers.
- Treat model responses and agent-supplied context as untrusted input.
- The command is not safe simply because it has a high score. Deterministic path, scope, privilege, and impact checks still apply.
- Do not elevate privileges automatically.
- Require explicit user interaction to execute from the dashboard.
- The model must never be able to modify policy thresholds, provider configuration, or the command after approval.

## 16. Testing Plan

### Unit tests

- Provider response normalization and missing-confidence handling.
- Threshold comparisons at below, equal to, and above the threshold.
- One-recheck cap and fail-closed behavior.
- Protected paths and mandatory deny rules.
- Secret redaction in context and audit events.
- Authorization digest changes when the command or working directory changes.

### Integration tests

Use `MockProvider` and a disposable directory. No external model key should be required for the base test suite.

- Read-only command is evaluated and runs only when allowed.
- File creation/modification is evaluated before it runs.
- Disposable test file deletion is blocked when the mock decision is block.
- Low confidence causes exactly one recheck.
- Recheck still uncertain means no process is created.
- Provider error means no process is created.
- User-facing block notification and audit event exist.
- A command modified after approval is rejected.
- The `check` command never executes.

### Manual demo scenarios

1. Safe read-only command, such as listing a disposable demo directory.
2. Explicit creation of a disposable test file.
3. Attempt to delete a test file, with a mock or provider decision set to block.
4. Uncertain result followed by a safe recheck using new context.
5. Uncertain result after recheck, which must block.
6. API unavailable, which must block.
7. Show the blocked command in the CLI notification and dashboard activity feed.

Never use live personal files, production data, or privileged/destructive system commands in the demo.

## 17. Acceptance Criteria

The MVP is accepted when all critical items below pass:

1. A command submitted through `run` is not launched before evaluation and policy authorization finish.
2. A command submitted through `check` is never launched.
3. Jev or Laya can be configured without changing executor or policy code, assuming the provider adapter is implemented.
4. A compatible custom endpoint can be added through configuration or a small adapter.
5. Invalid, missing, or contradictory model results cannot authorize execution.
6. The uncertain path performs no more than one recheck.
7. An unresolved recheck blocks execution and notifies the user.
8. A blocked command is visibly reported as “not executed,” saved to SQLite, and shown in the dashboard.
9. Authorization is bound to the command and working directory evaluated; changes invalidate it.
10. API keys do not appear in logs, the audit database, or source control.
11. Unit and mock-based integration tests pass without a real API account.
12. The README accurately states that only commands routed through the fence are protected by the prototype.

## 18. Implementation Priority for a Two-Hour Hackathon

**P0, mandatory:** schemas, mock provider, one real provider adapter, CLI `check` and `run`, policy thresholds, one recheck maximum, restricted executor, fail-closed behavior, SQLite audit, visible block message, and core tests.

**P1, if time permits:** compact Streamlit dashboard with activity table, provider settings, threshold controls, and Windows toast notification.

**P2, future:** selected coding-agent hook, Windows hardening, additional shells, database connector, MCP gateway, remote API connector, and universal resource policy.

For speed, implement the CLI and core policy first. Add the dashboard only after the no-bypass-through-supported-path test passes. If the deadline is strict, a polished audit dashboard is less important than correct fail-closed execution behavior.

## 19. Future Roadmap

- **Phase 1: Windows local prototype.** PowerShell command path, Jev/Laya provider adapters, decision policy, bounded recheck, notifications, audit, and minimal dashboard.
- **Phase 2: Agent integrations.** Explicit pre-tool hook for one selected coding agent, with return codes and structured allow/block messages.
- **Phase 3: Resource connectors.** Controlled adapters for filesystem operations, Git, PostgreSQL/MySQL, HTTP APIs, and MCP tools. Each connector must intercept the actual mutation route rather than merely inspect a textual description.
- **Phase 4: Stronger enforcement.** Least-privilege user, process isolation, Windows Application Control/Constrained Language Mode where appropriate, protected policy files, and tamper-resistant audit.
- **Phase 5: Universal policy plane.** Shared operation schema, resource metadata, dependency/impact analysis, per-system policies, approval workflows, and cross-connector auditing.

## 20. Key Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Model labels a dangerous command safe | Deterministic mandatory rules, least privilege, test corpus, fail-closed behavior |
| High confidence is mistaken for true safety probability | Keep class confidence, risk probability, and scope results separate; calibrate thresholds on labeled tests |
| Agent bypasses the wrapper | State the integration boundary honestly; use an agent hook and OS-level restrictions for stronger enforcement |
| Context is incomplete or misleading | Include known intent/target/shell/cwd; label missing evidence; recheck once then block |
| Hosted provider receives sensitive material | Redact context, minimize payloads, disclose endpoint, and never send secrets intentionally |
| Same command changes between evaluation and execution | Bind authorization to a digest of exact command and target; revalidate immediately before launch |
| Infinite retry loop or repeated provider cost | Enforce `MAX_RECHECKS=1` for MVP and record attempt count |
| Model provider changes its behavior/version | Log provider and model version; use pinned model IDs during evaluation when supported |
| Notifications fail | The operation stays blocked; record the failure and always return a CLI/tool result |
| Two-hour deadline is exceeded | Deliver a testable CLI first; defer dashboard and advanced integrations |

## 21. Open Configuration Decisions

These should be configurable, not hard-coded:

- Provider and model ID.
- API base URL and endpoint path.
- Authentication method/header name where required.
- Decision labels and mapping to allow/recheck/block.
- Allow threshold and risk threshold per action class.
- Maximum rechecks.
- Provider timeout and transport retry limit.
- Protected paths and prohibited operations.
- Allowed workspace root.
- Whether specified high-impact categories always require manual approval.
- Audit retention period and whether execution output is persisted.
- Whether Windows toast notifications are enabled.

## 22. References

1. TypeSafe, **System One API**. Request format, typed questions, model identifier, answer schema, and token usage: https://docs.typesafe.ai/api/system-one
2. TypeSafe, **Introduction to System One**. Decision primitives and combining typed model results in code: https://docs.typesafe.ai/introduction
3. Laya Studio, **API Reference**. `/v1/systemone` endpoint, authentication, response probabilities, and provider compatibility: https://laya.studio/docs/api
4. Microsoft Learn, **Application Control for Windows**. Background on Windows-level execution control and its role in stronger enforcement: https://learn.microsoft.com/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control

Provider API details, model names, pricing, and compatibility can change. Verify the current official provider documentation when implementation begins.

---

**Definition of success:** A developer can submit a supported Windows command through Permission Fence, see it evaluated by a configurable System 1 model, receive an allow/block/recheck result, have only an authorized and unchanged command execute, and immediately see every blocked attempt in the CLI and audit dashboard. The prototype must demonstrate that uncertainty and provider failure result in no execution, while clearly documenting that un-routed execution paths are outside its current enforcement boundary.
