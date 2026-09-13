"""LangGraph execution adapter over OpsGuard''s controlled tool workflow."""

from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from .orchestrator import DEFAULT_STEPS, AgentStep, InvestigationOrchestrator
from .schemas import InvestigationReport, InvestigationRequest, InvestigationStatus
from .tools import ToolRegistry


class InvestigationGraphState(TypedDict, total=False):
    request: InvestigationRequest
    report: InvestigationReport
    values: dict[str, Any]
    failed: bool


class LangGraphInvestigationOrchestrator:
    """Run one node per specialist role while retaining existing safety controls."""

    def __init__(
        self,
        registry: ToolRegistry,
        steps: tuple[AgentStep, ...] = DEFAULT_STEPS,
    ) -> None:
        self.registry = registry
        self.steps = steps
        self._controlled = InvestigationOrchestrator(registry, steps)
        self.graph = self._build_graph().compile()

    def run(self, request: InvestigationRequest) -> InvestigationReport:
        report = InvestigationReport(request=request)
        state: InvestigationGraphState = {
            "request": request,
            "report": report,
            "values": dict(request.parameters),
            "failed": False,
        }
        result = self.graph.invoke(state)
        return result["report"]

    def _build_graph(self) -> StateGraph:
        graph = StateGraph(InvestigationGraphState)
        node_names: list[str] = []
        for index, step in enumerate(self.steps):
            name = f"{step.agent}_{index}"
            node_names.append(name)
            graph.add_node(name, self._node(step))
        graph.add_node("finalize", self._finalize)
        if not node_names:
            graph.add_edge(START, "finalize")
        else:
            graph.add_edge(START, node_names[0])
            for index, name in enumerate(node_names):
                next_name = (
                    node_names[index + 1] if index + 1 < len(node_names) else "finalize"
                )
                graph.add_conditional_edges(
                    name,
                    lambda state: "failed" if state.get("failed") else "continue",
                    {"failed": "finalize", "continue": next_name},
                )
        graph.add_edge("finalize", END)
        return graph

    def _node(self, step: AgentStep):
        def invoke(state: InvestigationGraphState) -> dict[str, Any]:
            report = state["report"]
            request = state["request"]
            values = dict(state.get("values", {}))
            payload = {**request.parameters, "question": request.question}
            payload.update(
                {key: values[key] for key in step.input_keys if key in values}
            )
            ok, value = self._controlled._invoke_with_retry(
                report,
                step,
                payload,
                request.max_retries,
            )
            if not ok:
                report.status = (
                    InvestigationStatus.PARTIAL
                    if report.evidence
                    else InvestigationStatus.FAILED
                )
                return {"report": report, "values": values, "failed": True}
            values[step.output_key] = value
            report.evidence[step.output_key] = value
            return {"report": report, "values": values, "failed": False}

        return invoke

    @staticmethod
    def _finalize(state: InvestigationGraphState) -> dict[str, Any]:
        report = state["report"]
        governance = report.evidence.get("governance", [])
        if any(item.get("status") == "awaiting_approval" for item in governance):
            report.status = InvestigationStatus.AWAITING_APPROVAL
        report.summary = InvestigationOrchestrator._summarize(report)
        return {"report": report}
