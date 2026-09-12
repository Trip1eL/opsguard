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
- `src/opsguard/web`: FastAPI endpoints and the local security operations workspace;
- `src/opsguard/tools`: allow-listed read/validate/simulate tools;
- `datasets/`: deterministic fixtures for normal and suspicious behavior;
- `docs/`: architecture notes and resume material.

Model calls, storage adapters, and external side effects remain behind interfaces. The
demonstration uses deterministic fixtures and in-memory state so the complete workflow
is reproducible without production access.

## Run the workspace

Install the package in the dedicated Conda environment and start the API:

```powershell
conda run -n opsguard python -m pip install -e ".[dev]"
conda run -n opsguard python -m uvicorn opsguard.web.app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. The workspace automatically runs a fixture-backed
investigation and supports investigation, evidence review, human approval, canary
evaluation, feedback capture, and offline candidate comparison.

The same demonstration can run in Docker:

```powershell
docker compose up --build api
```

PostgreSQL, Redis, OpenSearch, and Neo4j are optional adapter targets in the
`adapters` profile; the local M9 workflow does not require them.

## Safety boundary

Agents may investigate and generate candidates automatically. Publishing a rule or performing a response action requires validation and explicit approval. The initial response tools are simulations only; they do not isolate a real host, disable an account, or block a real domain.

## Status

M0-M9 are implemented: typed fixtures, normalization and retrieval, deterministic
anomaly detection, behavior graph correlation, evidence-based ATT&CK mapping, and an
auditable multi-agent investigation workflow with Sigma generation and sandbox
validation. Human-gated simulated response, canary evaluation, automatic rollback,
append-only auditing, version-isolated feedback optimization, a FastAPI API, and a
responsive operations workspace are included.
