"""Container entry point for DockerRuleSandbox; no network or shell operations are used."""

from __future__ import annotations

import sys
from pathlib import Path

if __name__ == "__main__":
    from .docker_sandbox import run_worker

    if len(sys.argv) != 3:
        raise SystemExit("usage: python -m opsguard.rules.docker_worker INPUT OUTPUT")
    run_worker(Path(sys.argv[1]), Path(sys.argv[2]))
