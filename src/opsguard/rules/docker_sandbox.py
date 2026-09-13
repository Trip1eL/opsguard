"""Container-level isolation wrapper for the deterministic Sigma replay worker."""

from __future__ import annotations

import json
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from opsguard.data.fixtures import DatasetRecord
from opsguard.domain.models import DetectionRule

from .models import RuleValidationReport
from .sandbox import OfflineRuleSandbox


class DockerSandboxError(RuntimeError):
    """Raised when the isolated replay container cannot return a report."""


class DockerRuleSandbox:
    """Replay a rule in a no-network, read-only, resource-limited container."""

    def __init__(
        self,
        image: str = "opsguard:latest",
        *,
        docker_bin: str = "docker",
        timeout_seconds: float = 30.0,
        memory: str = "256m",
        cpus: str = "1.0",
    ) -> None:
        if not image or any(char.isspace() for char in image):
            raise ValueError("image must be a non-empty Docker image reference")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.image = image
        self.docker_bin = docker_bin
        self.timeout_seconds = timeout_seconds
        self.memory = memory
        self.cpus = cpus

    def replay(
        self,
        rule: DetectionRule,
        records: Iterable[DatasetRecord],
        dataset: str,
        target_event_ids: set[str] | None = None,
    ) -> RuleValidationReport:
        with tempfile.TemporaryDirectory(prefix="opsguard-sandbox-") as temp:
            root = Path(temp)
            input_path = root / "input.json"
            output_path = root / "output.json"
            input_path.write_text(
                json.dumps(
                    {
                        "rule": rule.model_dump(mode="json"),
                        "records": [
                            record.model_dump(mode="json") for record in records
                        ],
                        "dataset": dataset,
                        "target_event_ids": sorted(target_event_ids)
                        if target_event_ids is not None
                        else None,
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            command = self.command(input_path, output_path)
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise DockerSandboxError("Docker replay timed out") from exc
            except OSError as exc:
                raise DockerSandboxError("Docker executable is unavailable") from exc
            if completed.returncode != 0:
                raise DockerSandboxError(
                    f"Docker replay failed with exit code {completed.returncode}"
                )
            if not output_path.exists():
                raise DockerSandboxError("Docker replay produced no report")
            try:
                return RuleValidationReport.model_validate_json(
                    output_path.read_text(encoding="utf-8")
                )
            except (OSError, ValueError) as exc:
                raise DockerSandboxError(
                    "Docker replay returned invalid report"
                ) from exc

    def command(self, input_path: Path, output_path: Path) -> list[str]:
        root = input_path.parent
        return [
            self.docker_bin,
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "64",
            "--memory",
            self.memory,
            "--cpus",
            self.cpus,
            "--user",
            "10001:10001",
            "-v",
            f"{input_path}:/run/opsguard/input.json:ro",
            "-v",
            f"{root}:/run/opsguard/work:rw",
            self.image,
            "python",
            "-m",
            "opsguard.rules.docker_worker",
            "/run/opsguard/input.json",
            "/run/opsguard/work/output.json",
        ]


def run_worker(input_path: Path, output_path: Path) -> None:
    payload: dict[str, Any] = json.loads(input_path.read_text(encoding="utf-8"))
    rule = DetectionRule.model_validate(payload["rule"])
    records = [DatasetRecord.model_validate(item) for item in payload["records"]]
    target = payload.get("target_event_ids")
    report = OfflineRuleSandbox().replay(
        rule,
        records,
        payload["dataset"],
        set(target) if target is not None else None,
    )
    output_path.write_text(
        report.model_dump_json(),
        encoding="utf-8",
    )
