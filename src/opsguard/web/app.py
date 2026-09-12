"""FastAPI routes for the OpsGuard local demonstration workspace."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from opsguard.feedback import FeedbackKind
from opsguard.llm import build_configured_planner

from .service import OpsGuardService

STATIC_DIR = Path(__file__).parent / "static"
DEFAULT_PROJECT_ROOT = Path(__file__).parents[3]


class InvestigationInput(BaseModel):
    question: str = Field(min_length=3, max_length=500)
    parameters: dict[str, Any] = Field(default_factory=dict)


class CanaryMetricsInput(BaseModel):
    evaluated_events: int = Field(default=1000, ge=1)
    false_positive_rate: float = Field(default=0.01, ge=0, le=1)
    error_rate: float = Field(default=0.001, ge=0, le=1)
    p95_latency_ms: float = Field(default=30, ge=0)


class DecisionInput(BaseModel):
    actor: str = Field(min_length=1, max_length=100)
    approved: bool
    reason: str = Field(min_length=3, max_length=500)
    canary_metrics: CanaryMetricsInput | None = None


class FeedbackInput(BaseModel):
    event_id: str
    kind: FeedbackKind
    actor: str = Field(min_length=1, max_length=100)
    comment: str = Field(min_length=3, max_length=500)


def create_app(
    project_root: Path | None = None,
    service: OpsGuardService | None = None,
    use_configured_model: bool = False,
) -> FastAPI:
    app = FastAPI(
        title="OpsGuard",
        version="0.1.0",
        description="Evidence-backed security investigation and rule governance.",
    )
    root = project_root or DEFAULT_PROJECT_ROOT
    if service is not None:
        runtime = service
    elif use_configured_model:
        planner, model_status = build_configured_planner(root / ".env")
        runtime = OpsGuardService(root, planner, model_status)
    else:
        runtime = OpsGuardService(root)
    app.state.service = runtime
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "opsguard"}

    @app.get("/api/events")
    def events() -> list[dict[str, Any]]:
        return runtime.event_options()

    @app.get("/api/model/status")
    def model_status() -> dict[str, Any]:
        return runtime.model_status()

    @app.post("/api/investigations")
    def investigate(payload: InvestigationInput) -> dict[str, Any]:
        try:
            return runtime.investigate(payload.question, payload.parameters)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/investigations/{investigation_id}")
    def get_investigation(investigation_id: str) -> dict[str, Any]:
        try:
            return runtime.serialize(runtime.get(investigation_id))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/investigations/{investigation_id}/decision")
    def decide(
        investigation_id: str,
        payload: DecisionInput,
    ) -> dict[str, Any]:
        try:
            return runtime.decide(
                investigation_id,
                payload.actor,
                payload.approved,
                payload.reason,
                (
                    payload.canary_metrics.model_dump()
                    if payload.canary_metrics
                    else None
                ),
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/investigations/{investigation_id}/feedback")
    def add_feedback(
        investigation_id: str,
        payload: FeedbackInput,
    ) -> dict[str, Any]:
        try:
            record = runtime.add_feedback(
                investigation_id,
                payload.event_id,
                payload.kind,
                payload.actor,
                payload.comment,
            )
            return record.model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/investigations/{investigation_id}/evolve")
    def evolve(investigation_id: str) -> dict[str, Any]:
        try:
            return runtime.evolve(investigation_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/feedback")
    def feedback() -> list[dict[str, Any]]:
        return runtime.list_feedback()

    return app


app = create_app(use_configured_model=True)
