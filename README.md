# OpsGuard

OpsGuard is a personal, security-oriented AI application prototype for investigating abnormal behavior in enterprise production systems. It uses a controlled multi-agent workflow to turn multi-source events into an evidence-backed investigation, a candidate detection rule, a validation result, and a human-approved response proposal.

## Short-term deliverable

The first release is a runnable vertical slice, not a production SIEM/SOAR replacement:

```text
sample logs -> normalized events -> behavior timeline -> ATT&CK mapping
            -> Sigma candidate -> isolated validation -> approval -> simulated response
```

The slice will cover three data sources and three scenarios:

- Linux SSH/audit events, web access logs, and process/network events;
- suspicious login plus scheduled-task persistence;
- web process spawning an unusual child process;
- a normal release window that should remain low risk.

## Architecture

- `src/opsguard/domain`: typed domain models and lifecycle states;
- `src/opsguard/agents`: narrow agent contracts and orchestration boundaries;
- `src/opsguard/tools`: allow-listed read/validate/simulate tools;
- `datasets/`: deterministic fixtures for normal and suspicious behavior;
- `docs/`: architecture notes and resume material.

The initial scaffold deliberately keeps model calls, storage adapters, and external side effects behind interfaces. This makes the workflow testable with deterministic fixtures before connecting a model or real log backend.

## Safety boundary

Agents may investigate and generate candidates automatically. Publishing a rule or performing a response action requires validation and explicit approval. The initial response tools are simulations only; they do not isolate a real host, disable an account, or block a real domain.

## Status

The repository currently contains the project scaffold and typed workflow contracts. The implementation will be completed incrementally, with each milestone backed by fixtures and tests. See [`docs/resume.md`](docs/resume.md) for resume wording that matches the actual implementation stage.

