from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _read_dotenv(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _env_value(key: str, dotenv: dict[str, str], default: str) -> str:
    return os.environ.get(key, dotenv.get(key, default))


@dataclass(frozen=True)
class AppSettings:
    """Non-secret runtime settings loaded from environment or local .env."""

    app_name: str = "opsguard"
    environment: str = "development"
    log_level: str = "INFO"
    data_dir: Path = Path("datasets")
    reports_dir: Path = Path("reports/generated")
    model_provider: str = ""
    model_name: str = ""
    postgres_url: str = ""
    redis_url: str = ""
    opensearch_url: str = ""
    neo4j_uri: str = ""

    @classmethod
    def from_env(cls, dotenv_path: Path | None = None) -> AppSettings:
        dotenv = _read_dotenv(dotenv_path or Path(".env"))
        return cls(
            app_name=_env_value("OPSGUARD_APP_NAME", dotenv, "opsguard"),
            environment=_env_value("OPSGUARD_ENVIRONMENT", dotenv, "development"),
            log_level=_env_value("OPSGUARD_LOG_LEVEL", dotenv, "INFO").upper(),
            data_dir=Path(_env_value("OPSGUARD_DATA_DIR", dotenv, "datasets")),
            reports_dir=Path(
                _env_value("OPSGUARD_REPORTS_DIR", dotenv, "reports/generated")
            ),
            model_provider=_env_value("CHAT_MODEL_PROVIDER", dotenv, ""),
            model_name=_env_value("GPT_MODEL_NAME", dotenv, ""),
            postgres_url=_env_value("POSTGRES_URL", dotenv, ""),
            redis_url=_env_value("REDIS_URL", dotenv, ""),
            opensearch_url=_env_value("OPENSEARCH_URL", dotenv, ""),
            neo4j_uri=_env_value("NEO4J_URI", dotenv, ""),
        )

    def ensure_runtime_dirs(self) -> None:
        self.reports_dir.mkdir(parents=True, exist_ok=True)


def get_settings() -> AppSettings:
    return AppSettings.from_env()
