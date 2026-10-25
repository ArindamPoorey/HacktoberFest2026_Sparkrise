"""Environment and settings validation for Permission Fence (FR-10, Section 21)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field

try:
    from pydantic import field_validator as _field_validator  # type: ignore

    def compat_validator(field_name: str):
        return _field_validator(field_name)

except ImportError:
    from pydantic import validator as _validator  # type: ignore

    def compat_validator(field_name: str):
        return _validator(field_name)


def model_to_dict(model: BaseModel) -> Dict[str, Any]:
    """Compatible dict serialization across Pydantic v1 and v2."""
    if hasattr(model, "model_dump"):
        return model.model_dump()  # type: ignore
    return model.dict()  # type: ignore


DEFAULT_PROTECTED_PATHS: List[str] = [
    "C:/Windows",
    "C:/Program Files",
    "C:/Program Files (x86)",
    "C:/ProgramData",
    "C:/Users/Default",
    "/etc",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/boot",
    "/root",
    ".git/config",
    ".git/hooks",
    ".env",
    "id_rsa",
    "authorized_keys",
]

DEFAULT_HIGH_IMPACT_PATTERNS: List[str] = [
    r"(?i)\bFormat-Volume\b",
    r"(?i)\bClear-Disk\b",
    r"(?i)\bInitialize-Disk\b",
    r"(?i)\bdiskpart\b",
    r"(?i)\bbcdedit\b",
    r"(?i)\bvssadmin\s+delete\s+shadows\b",
    r"(?i)\bwbadmin\s+delete\b",
    r"(?i)\bcipher\s+/w\b",
    r"(?i)\bStop-Computer\b",
    r"(?i)\bRestart-Computer\b",
    r"(?i)\bSet-ExecutionPolicy\s+(Bypass|Unrestricted)\b",
    r"(?i)\bSet-MpPreference\b.*Disable",
    r"(?i)\bsc\.exe\s+(delete|stop)\b",
    r"(?i)\breg\s+(delete|add)\s+HKLM\b",
    r"(?i)\bnet\s+(user|localgroup\s+administrators)\b",
    r"(?i)\bInvoke-Expression\b",
    r"(?i)\biex\s*\(",
    r"(?i)\bDownloadString\b",
    r"(?i)\bStart-Process\b.*-Verb\s+RunAs",
    r"(?i)\bRemove-Item\b.*(-Recurse|-r\b).*(\*|[A-Za-z]:\\$|[A-Za-z]:/$|\.\.|/|\$HOME|~)",
    r"(?i)\b(rm\s+-rf|del\s+/s\s+/q|rmdir\s+/s\s+/q)\b",
]


class FenceSettings(BaseModel):
    """Validated configuration settings for Permission Fence."""

    model_provider: str = Field(default="jev", description="Provider identifier: jev, laya, custom, or mock")
    model_base_url: str = Field(default="https://api.typesafe.ai")
    model_endpoint: str = Field(default="/v1/systemone")
    model_id: str = Field(default="jev-latest")
    model_api_key: str = Field(default="")
    auth_header_name: str = Field(default="Authorization")
    auth_scheme: str = Field(default="Bearer")

    allow_threshold: float = Field(default=0.90, ge=0.0, le=1.0)
    recheck_threshold: float = Field(default=0.90, ge=0.0, le=1.0)
    risk_ceiling: float = Field(default=0.15, ge=0.0, le=1.0)
    max_rechecks: int = Field(default=1, ge=0, le=3)

    model_timeout_seconds: float = Field(default=5.0, gt=0.1, le=60.0)
    model_max_transport_retries: int = Field(default=1, ge=0, le=3)
    execution_timeout_seconds: float = Field(default=30.0, gt=0.5, le=600.0)

    allowed_workspace_root: str = Field(default=".")
    protected_paths: List[str] = Field(default_factory=lambda: list(DEFAULT_PROTECTED_PATHS))
    high_impact_patterns: List[str] = Field(default_factory=lambda: list(DEFAULT_HIGH_IMPACT_PATTERNS))
    require_manual_approval_for_destructive: bool = Field(default=True)
    allow_http_localhost: bool = Field(default=True)

    strict_audit_mode: bool = Field(default=True)
    audit_retention_days: int = Field(default=7, ge=1, le=365)
    audit_db_path: str = Field(default="permission_fence_audit.db")
    persist_execution_output: bool = Field(default=True)
    enable_windows_toast: bool = Field(default=True)

    @compat_validator("model_provider")
    @classmethod
    def normalize_provider(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned not in {"jev", "laya", "custom", "mock"}:
            raise ValueError(f"Unsupported MODEL_PROVIDER '{value}'. Choose jev, laya, custom, or mock.")
        return cleaned

    @compat_validator("model_base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        cleaned = value.strip().rstrip("/")
        if not cleaned:
            raise ValueError("MODEL_BASE_URL cannot be empty.")
        if cleaned.startswith("http://"):
            host_part = cleaned[len("http://") :].split("/")[0].split(":")[0].lower()
            if host_part not in {"localhost", "127.0.0.1", "::1"}:
                raise ValueError(
                    "Plain HTTP is only permitted for local endpoints (localhost / 127.0.0.1). "
                    "Use HTTPS for remote decision providers."
                )
        elif not cleaned.startswith("https://"):
            raise ValueError("MODEL_BASE_URL must start with https:// (or http://localhost for local testing).")
        return cleaned

    @property
    def full_endpoint_url(self) -> str:
        ep = self.model_endpoint.strip()
        if not ep.startswith("/"):
            ep = "/" + ep
        return f"{self.model_base_url}{ep}"

    def masked_api_key(self) -> str:
        """Return a masked representation of the API key that never exposes the secret."""
        if not self.model_api_key or self.model_api_key == "replace_me":
            return "<not-configured>"
        if len(self.model_api_key) <= 6:
            return "***MASKED***"
        return f"{self.model_api_key[:3]}...{self.model_api_key[-2:]} (masked)"

    def to_safe_dict(self) -> Dict[str, object]:
        """Serialize settings with API keys strictly masked."""
        data = model_to_dict(self)
        data["model_api_key"] = self.masked_api_key()
        return data


def load_settings(env_path: Optional[Path] = None, overrides: Optional[Dict[str, object]] = None) -> FenceSettings:
    """Load FenceSettings from .env / environment variables with optional dictionary overrides."""
    if env_path and env_path.exists():
        load_dotenv(dotenv_path=env_path, override=False)
    else:
        load_dotenv(override=False)

    def _bool(val: Optional[str], default: bool) -> bool:
        if val is None:
            return default
        return val.strip().lower() in {"1", "true", "yes", "on"}

    raw_provider = os.getenv("MODEL_PROVIDER", "jev").strip().lower()
    default_base_url = "https://api.laya.studio" if raw_provider == "laya" else "https://api.typesafe.ai"
    default_model_id = "typed-decisions" if raw_provider == "laya" else "jev-latest"

    raw_protected = os.getenv("PROTECTED_PATHS")
    protected_paths = (
        [p.strip() for p in raw_protected.split(";") if p.strip()]
        if raw_protected
        else list(DEFAULT_PROTECTED_PATHS)
    )

    cfg_dict: Dict[str, object] = {
        "model_provider": raw_provider,
        "model_base_url": os.getenv("MODEL_BASE_URL", default_base_url),
        "model_endpoint": os.getenv("MODEL_ENDPOINT", "/v1/systemone"),
        "model_id": os.getenv("MODEL_ID", default_model_id),
        "model_api_key": os.getenv("MODEL_API_KEY", ""),
        "auth_header_name": os.getenv("AUTH_HEADER_NAME", "Authorization"),
        "auth_scheme": os.getenv("AUTH_SCHEME", "Bearer"),
        "allow_threshold": float(os.getenv("ALLOW_THRESHOLD", "0.90")),
        "recheck_threshold": float(os.getenv("RECHECK_THRESHOLD", "0.90")),
        "risk_ceiling": float(os.getenv("RISK_CEILING", "0.15")),
        "max_rechecks": int(os.getenv("MAX_RECHECKS", "1")),
        "model_timeout_seconds": float(os.getenv("MODEL_TIMEOUT_SECONDS", "5.0")),
        "model_max_transport_retries": int(os.getenv("MODEL_MAX_TRANSPORT_RETRIES", "1")),
        "execution_timeout_seconds": float(os.getenv("EXECUTION_TIMEOUT_SECONDS", "30.0")),
        "allowed_workspace_root": os.getenv("ALLOWED_WORKSPACE_ROOT", os.getcwd()),
        "protected_paths": protected_paths,
        "require_manual_approval_for_destructive": _bool(
            os.getenv("REQUIRE_MANUAL_APPROVAL_FOR_DESTRUCTIVE"), True
        ),
        "strict_audit_mode": _bool(os.getenv("STRICT_AUDIT_MODE"), True),
        "audit_retention_days": int(os.getenv("AUDIT_RETENTION_DAYS", "7")),
        "audit_db_path": os.getenv("AUDIT_DB_PATH", "permission_fence_audit.db"),
        "persist_execution_output": _bool(os.getenv("PERSIST_EXECUTION_OUTPUT"), True),
        "enable_windows_toast": _bool(os.getenv("ENABLE_WINDOWS_TOAST"), True),
    }

    if overrides:
        for k, v in overrides.items():
            if v is not None:
                cfg_dict[k] = v

    return FenceSettings(**cfg_dict)


def save_settings_to_env(env_path: Path, updates: Dict[str, object]) -> None:
    """Safely update key-value pairs in a local .env file."""
    existing_lines: List[str] = []
    if env_path.exists():
        existing_lines = env_path.read_text(encoding="utf-8").splitlines()

    updated_keys = set()
    new_lines: List[str] = []
    for line in existing_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            new_lines.append(line)
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in updates:
            new_lines.append(f"{key}={updates[key]}")
            updated_keys.add(key)
        else:
            new_lines.append(line)

    for key, val in updates.items():
        if key not in updated_keys:
            new_lines.append(f"{key}={val}")

    env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
