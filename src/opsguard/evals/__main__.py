"""Command-line entry point for fixture and budgeted live evaluations."""

from __future__ import annotations

import argparse
from pathlib import Path

from .models import EvalMode
from .reporting import write_reports
from .runner import EvalRunner


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m opsguard.evals")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run", help="run the M11 evaluation suite")
    run.add_argument("--mode", choices=[item.value for item in EvalMode], required=True)
    run.add_argument("--max-cases", type=int)
    run.add_argument("--max-total-tokens", type=int, default=40_000)
    run.add_argument("--max-cost-usd", type=float, default=2.0)
    run.add_argument("--input-cost-per-million", type=float, default=0.0)
    run.add_argument("--output-cost-per-million", type=float, default=0.0)
    run.add_argument("--cases", type=Path, default=Path("evals/cases/m11_cases.json"))
    run.add_argument("--output-dir", type=Path, default=Path("reports/evals"))
    return parser


def main() -> int:
    args = _parser().parse_args()
    project_root = Path.cwd()
    runner = EvalRunner(
        project_root,
        max_total_tokens=args.max_total_tokens,
        max_cost_usd=args.max_cost_usd,
        input_cost_per_million=args.input_cost_per_million,
        output_cost_per_million=args.output_cost_per_million,
    )
    report = runner.run(
        project_root / args.cases,
        mode=EvalMode(args.mode),
        max_cases=args.max_cases,
    )
    json_path, markdown_path = write_reports(
        report,
        project_root / args.output_dir,
    )
    print(
        f"M11 {args.mode} evaluation: "
        f"{report.metrics.passed_cases}/{report.metrics.case_count} cases passed; "
        f"release_gate={'PASS' if report.release_gate_passed else 'FAIL'}"
    )
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")
    return 0 if report.release_gate_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
