# OpsGuard

OpsGuard is a personal, security-oriented AI application prototype for investigating abnormal behavior in enterprise production systems. It uses a controlled multi-agent workflow to turn multi-source events into an evidence-backed investigation, a candidate detection rule, a validation result, and a human-approved response proposal.

## Short-term deliverable

The first release is a runnable vertical slice, not a production SIEM/SOAR replacement:

```text
sample logs -> normalized events -> behavior timeline -> ATT&CK mapping
            -> Sigma candidate -> isolated validation -> approval -> simulated response
```

The slice covers three data sources and three scenarios:

- Linux SSH/audit events, web access logs, and process/network events;
- suspicious login plus scheduled-task persistence;
- web process spawning an unusual child process;
- a normal release window that should remain low risk.

## Architecture

- `src/opsguard/domain`: typed domain models and lifecycle states;
- `src/opsguard/agents`: narrow agent contracts and orchestration boundaries;
- `src/opsguard/rules`: constrained Sigma generation and offline replay validation;
- `src/opsguard/governance`: approval, response, canary, rollback, and audit controls;
- `src/opsguard/feedback`: version-isolated analyst feedback and candidate optimization;
- `src/opsguard/llm`: validated model planning and redacted LangSmith tracing;
- `src/opsguard/evals`: versioned Agent evaluation, red-team scoring, and release gates;
- `src/opsguard/web`: FastAPI endpoints and the local security operations workspace;
- `src/opsguard/tools`: allow-listed read/validate/simulate tools;
- `datasets/`: deterministic fixtures for normal and suspicious behavior;
- `docs/`: architecture notes and resume material.
- `docs/architecture.md`: component responsibilities, data flow, and security boundaries;
- `docs/demo.md`: a three-minute reproducible demonstration script;

Model calls, storage adapters, and external side effects remain behind interfaces. The
demonstration uses deterministic fixtures and in-memory state so the complete workflow
is reproducible without production access.

## Run the workspace

Install the package in the dedicated Conda environment and start the API:

```powershell
conda run -n opsguard python -m pip install -e ".[dev]"
conda run -n opsguard python -m uvicorn opsguard.web.app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. Submit the included fixture-backed question to run an
investigation, then review evidence, approve a response, evaluate canary metrics,
capture feedback, and compare candidate rules. Real model mode requires an explicit
submit action so loading or refreshing the page never consumes model tokens.

Real model planning is optional. Copy the non-secret fields from `.env.example`, set
`OPSGUARD_LLM_ENABLED=true`, and configure an OpenAI-compatible provider. When
`LANGSMITH_TRACING=true`, OpsGuard records model, latency, token usage, validation
status, and Trace IDs in LangSmith. Trace inputs and outputs are always hidden; only
sanitized operational metadata leaves the application.

The same demonstration can run in Docker:

```powershell
docker compose up --build api
```

PostgreSQL, Redis, OpenSearch, and Neo4j are optional adapter targets in the
`adapters` profile; the local M9 workflow does not require them.

## Safety boundary

The LLM may propose a structured investigation scope and advisory tool sequence, but
the deterministic allow-listed workflow performs detection, rule validation, approval,
and lifecycle transitions. Publishing a rule or performing a response action requires
validation and explicit approval. Response tools are simulations only; they do not
isolate a real host, disable an account, or block a real domain.

Run the free, deterministic Agent evaluation suite with:

```powershell
conda run -n opsguard python -m opsguard.evals run --mode fixture
```

The sanitized JSON and Markdown reports are written to `reports/evals/`. Live mode
uses the configured gateway, caps each run at 20 cases and stops at the Token budget.

Every push and pull request to `main` runs the full test suite, Ruff, and the fixture Eval
through [GitHub Actions](.github/workflows/ci.yml). The CI job uploads only the sanitized
evaluation report as an artifact.

## Status

M0-M11 are implemented: typed fixtures, normalization and retrieval, deterministic
anomaly detection, behavior graph correlation, evidence-based ATT&CK mapping, and an
auditable multi-agent investigation workflow with Sigma generation and sandbox
validation. Human-gated simulated response, canary evaluation, automatic rollback,
append-only auditing, version-isolated feedback optimization, a FastAPI API, and a
responsive operations workspace are included. An optional OpenAI-compatible Planner
adds schema-validated model reasoning, deterministic fallback, token/latency telemetry,
and privacy-preserving LangSmith traces. A 20-case Agent evaluation suite adds normal,
adversarial, and model-failure regression coverage with explicit security release gates.
The `v0.1.0` release scope and verification checklist are recorded in `docs/release.md`.
