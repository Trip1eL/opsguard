"""Secret-aware runtime configuration for optional model calls."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from opsguard.config import read_dotenv


def _value(name: str, dotenv: dict[str, str], default: str = "") -> str:
    return os.environ.get(name, dotenv.get(name, default))


def _enabled(value: str) -> bool:
    return value.strip().casefold() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class ModelRuntimeConfig:
    enabled: bool = False
    provider: str = ""
    model: str = ""
    api_key: str = field(default="", repr=False)
    base_url: str = ""
    proxy_url: str = ""
    timeout_seconds: float = 60.0
    tracing_enabled: bool = False
    langsmith_endpoint: str = "https://api.smith.langchain.com"
    langsmith_api_key: str = field(default="", repr=False)
    langsmith_project: str = "opsguard-dev"

    @classmethod
    def from_env(cls, dotenv_path: Path | None = None) -> ModelRuntimeConfig:
        dotenv = read_dotenv(dotenv_path or Path(".env"))
        provider = _value("CHAT_MODEL_PROVIDER", dotenv).strip().casefold()
        prefix = provider.upper()
        base_url = _value(f"{prefix}_BASE_URL", dotenv) or _value(
            f"{prefix}_API_URL",
            dotenv,
        )
        model = _value("GPT_MODEL_NAME", dotenv)
        if provider == "dashscope":
            model = _value("DASHSCOPE_MODEL", dotenv, model)
        tracing_value = _value(
            "LANGSMITH_TRACING",
            dotenv,
            _value("LANGCHAIN_TRACING_V2", dotenv, "false"),
        )
        return cls(
            enabled=_enabled(_value("OPSGUARD_LLM_ENABLED", dotenv, "false")),
            provider=provider,
            model=model,
            api_key=_value(f"{prefix}_API_KEY", dotenv),
            base_url=base_url,
            proxy_url=_value("HTTP_PROXY_URL", dotenv),
            timeout_seconds=float(
                _value("OPSGUARD_LLM_TIMEOUT_SECONDS", dotenv, "60")
            ),
            tracing_enabled=_enabled(tracing_value),
            langsmith_endpoint=_value(
                "LANGSMITH_ENDPOINT",
                dotenv,
                "https://api.smith.langchain.com",
            ),
            langsmith_api_key=_value("LANGSMITH_API_KEY", dotenv),
            langsmith_project=_value(
                "LANGSMITH_PROJECT",
                dotenv,
                "opsguard-dev",
            ),
        )

    @property
    def openai_base_url(self) -> str:
        return (
            self.base_url.rstrip("/")
            if self.base_url.rstrip("/").endswith("/v1")
            else f"{self.base_url.rstrip('/')}/v1"
        )

    def validate(self) -> None:
        if not self.enabled:
            return
        missing = [
            name
            for name, value in (
                ("CHAT_MODEL_PROVIDER", self.provider),
                ("GPT_MODEL_NAME", self.model),
                ("provider API key", self.api_key),
                ("provider base URL", self.base_url),
            )
            if not value
        ]
        if missing:
            raise ValueError(
                "model runtime configuration is incomplete: "
                + ", ".join(missing)
            )
        self._require_http_url(self.base_url, "provider base URL")
        if self.timeout_seconds <= 0:
            raise ValueError("model timeout must be positive")
        if self.tracing_enabled:
            if not self.langsmith_api_key:
                raise ValueError(
                    "LANGSMITH_API_KEY is required when tracing is enabled"
                )
            self._require_http_url(
                self.langsmith_endpoint,
                "LangSmith endpoint",
            )

    @staticmethod
    def _require_http_url(value: str, label: str) -> None:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"{label} must be an absolute HTTP(S) URL")
