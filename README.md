# Permission Fence 🛡️

**Local-First System 1 Command Permission Gateway for Coding Agents**

Permission Fence sits between a coding agent (such as Claude Code, Codex, Cursor, or a PowerShell hook) and the local shell commands it proposes to run on a Windows laptop. Before any command routed through the fence can execute, Permission Fence packages the command with minimal secret-redacted workspace context, queries a specialized **System 1 decision model** ([TypeSafe Jev](https://docs.typesafe.ai/api/system-one), [Laya Studio](https://laya.studio/docs/api), or any compatible `/v1/systemone` endpoint), applies deterministic security policies and confidence thresholds, performs at most **one bounded recheck** with enriched local evidence when uncertain, and either authorizes the exact command or blocks it with an immediate user notification and SQLite audit record.

> **Security Principle:** The model recommends a decision; local policy and the execution broker enforce it. A confidence score alone is never sufficient evidence that an operation is safe.

---

## Enforcement Boundary & Honest Scope Disclosure

- **Only commands routed through Permission Fence are protected by this prototype.**
- Permission Fence is a user-space authorization gateway and PowerShell execution broker (`python -m app.main` / `scripts\safe-run.ps1`). It does **not** hook the Windows kernel or intercept arbitrary processes launched outside the wrapper.
- If a coding agent can bypass the configured hook and invoke `powershell.exe`, `cmd.exe`, or Python `subprocess` directly, those un-routed calls are outside this prototype's enforcement boundary. For production hardening, pair Permission Fence with least-privilege OS accounts and Windows Defender Application Control (AppLocker / Constrained Language Mode).

---

## Architecture & Data Flow

```text
Agent / CLI / Hook
   │
   ▼
Operation Intake (FR-01) ──► Context Packer & Secret Redactor (FR-02)
                                │
                                ▼
                     Local Policy Pre-Check (FR-05, Sec 8)
                     (Protected paths, workspace scope, high-impact patterns)
                                │
                                ▼
                     System 1 Decision Provider (FR-03, FR-04)
                     (Jev / Laya / Custom /v1/systemone / Mock)
                                │
                                ▼
                     Policy & Threshold Evaluation (FR-05, FR-06)
                     ┌──────────┼──────────┐
                     ▼          ▼          ▼
                   ALLOW     RECHECK     BLOCK
                     │      (Max 1x w/     │
                     │       enriched      ├──► CLI Warning + Windows Toast (FR-08)
                     │       evidence)     └──► SQLite Audit Log (FR-09)
                     ▼
          SHA-256 AuthorizationToken (FR-07)
          (Bound to exact command, shell, cwd, targets)
                     │
                     ▼
          Execution Broker (app/executor/windows.py)
          (Revalidates SHA-256 digest immediately before launch)
                     │
                     ▼
          SQLite Audit Store + Streamlit Dark Dashboard
```

### Documented Confidence & Score Mapping (FR-06)

Permission Fence never confuses category confidence with risk probability:

1. **`confidence`**: Extracted from `answers.action_class.confidence` (or `answers.action_class.probabilities[<selected_choice>]` if `confidence` is omitted by a compatible endpoint). If neither is present, `confidence` is set to `None` (unavailable — never fabricated) and the policy engine fails closed.
2. **`scores.matches_user_intent`**: Calibrated `noul` probability `[0, 1]` from `answers.matches_user_intent.noul`.
3. **`scores.target_in_scope`**: Calibrated `noul` probability `[0, 1]` from `answers.target_in_scope.noul`.
4. **`scores.unintended_damage_risk`**: Calibrated `noul` probability `[0, 1]` from `answers.unintended_damage_risk.noul`.
5. **`scores.needs_human_review`**: Calibrated `noul` probability `[0, 1]` from `answers.needs_human_review.noul`.

---

## Quick Start (Windows PowerShell)

### 1. Create a Virtual Environment & Install Dependencies

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure `.env`

```powershell
Copy-Item .env.example .env
# Edit .env and set MODEL_API_KEY (or use --provider mock for offline testing)
```

Supported providers in `.env`:
- **TypeSafe Jev:** `MODEL_PROVIDER=jev`, `MODEL_BASE_URL=https://api.typesafe.ai`, `MODEL_ENDPOINT=/v1/systemone`, `MODEL_ID=jev-latest`
- **Laya Studio:** `MODEL_PROVIDER=laya`, `MODEL_BASE_URL=https://api.laya.studio`, `MODEL_ENDPOINT=/v1/systemone`, `MODEL_ID=typed-decisions`
- **Custom Endpoint:** `MODEL_PROVIDER=custom`, `MODEL_BASE_URL=https://your-host.example.com`, `MODEL_ENDPOINT=/v1/systemone`
- **Deterministic Offline Mock:** `MODEL_PROVIDER=mock`

### 3. CLI Usage (`check`, `run`, `history`, `doctor`, `demo`)

```powershell
# 1. Evaluate only (Dry-Run — NEVER executes the command)
python -m app.main --provider mock check --shell powershell --command "Get-ChildItem ." --intent "Inspect the project files"

# 2. Evaluate and execute ONLY if authorized by policy
python -m app.main --provider mock run --shell powershell --command "Get-ChildItem ." --intent "Inspect the project files"

# 3. Run the 7 PRD demo scenarios in a disposable temporary workspace
python -m app.main --provider mock demo

# 4. Inspect recent SQLite audit events
python -m app.main history --limit 20

# 5. Check provider configuration and health
python -m app.main doctor --live-ping
```

### 4. Agent Hook Wrapper (`scripts/safe-run.ps1`)

```powershell
# Dry-run evaluation
.\scripts\safe-run.ps1 -Command "Get-ChildItem ." -Intent "List workspace files"

# Evaluate and execute if allowed
.\scripts\safe-run.ps1 -Command "Get-ChildItem ." -Intent "List workspace files" -Execute
```

### 5. Launch the Dark Streamlit Dashboard

```powershell
streamlit run app/ui/dashboard.py
```

---

## Running the Test Suite

All unit and integration tests run offline without requiring a live API key:

```powershell
# Run with pytest
pytest -v

# Or run with Python's built-in unittest runner
python -m unittest discover -s tests -v
```

---

## Pushing to Your GitHub Repository

This project is pre-initialized with structured Git commits for each architectural layer. To push to your GitHub repository without ever exposing your Personal Access Token (PAT) in code:

```powershell
# On Windows PowerShell:
.\scripts\git-push.ps1 -RepoUrl "https://github.com/<your-username>/permission-fence.git"
```

```bash
# On Linux / macOS / Git Bash:
./scripts/git-push.sh "https://github.com/<your-username>/permission-fence.git"
```
