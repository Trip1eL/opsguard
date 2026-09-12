"""Write machine-readable and review-friendly sanitized evaluation reports."""

from __future__ import annotations

import json
from pathlib import Path

from .models import EvalReport


def write_reports(report: EvalReport, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "latest.json"
    markdown_path = output_dir / "latest.md"
    json_path.write_text(
        json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(_markdown(report), encoding="utf-8")
    return json_path, markdown_path


def _percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _markdown(report: EvalReport) -> str:
    verdict = "PASS" if report.release_gate_passed else "FAIL"
    lines = [
        "# OpsGuard M11 Evaluation Report",
        "",
        f"- Suite: `{report.suite_version}`",
        f"- Mode: `{report.mode.value}`",
        f"- Model: `{report.model_provider}/{report.model_name}`",
        f"- Release gate: **{verdict}**",
        f"- Cases: {report.metrics.passed_cases}/{report.metrics.case_count} passed",
        f"- Total tokens: {report.metrics.total_tokens}",
        f"- Estimated cost: ${report.metrics.estimated_cost_usd:.6f}",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    for name, value in report.metrics.model_dump().items():
        if name.endswith("_rate"):
            rendered = _percent(value)
        elif isinstance(value, float):
            rendered = f"{value:.3f}"
        else:
            rendered = str(value)
        lines.append(f"| `{name}` | {rendered} |")
    lines.extend(
        [
            "",
            "## Release Gates",
            "",
            "| Gate | Required | Actual | Result |",
            "|---|---:|---:|---:|",
        ]
    )
    for gate in report.gates:
        lines.append(
            f"| `{gate.metric}` | {gate.operator} {_percent(gate.threshold)} "
            f"| {_percent(gate.actual)} | {'PASS' if gate.passed else 'FAIL'} |"
        )
    lines.extend(
        [
            "",
            "## Cases",
            "",
            "| Case | Category | Mode | Status | Result | Failures |",
            "|---|---|---|---|---:|---|",
        ]
    )
    for result in report.results:
        failures = ", ".join(result.failure_codes) or "-"
        lines.append(
            f"| `{result.case_id}` | {result.category.value} | "
            f"{result.actual_mode} | {result.status} | "
            f"{'PASS' if result.passed else 'FAIL'} | {failures} |"
        )
    lines.extend(
        [
            "",
            (
                "> Reports contain case IDs and sanitized metrics only. Raw model "
                "prompts, outputs, logs, and credentials are not written to this artifact."
            ),
            "",
        ]
    )
    return "\n".join(lines)
