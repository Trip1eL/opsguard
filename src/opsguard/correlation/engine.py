from __future__ import annotations

import itertools
from collections.abc import Iterable
from datetime import timedelta
from typing import ClassVar

from pydantic import BaseModel

from opsguard.correlation.graph import (
    BehaviorGraph,
    GraphEdge,
    GraphNode,
    GraphNodeKind,
)
from opsguard.domain.cases import Alert
from opsguard.domain.models import BehaviorChain, Event


class CorrelationResult(BaseModel):
    chain: BehaviorChain
    graph: BehaviorGraph


class BehaviorCorrelator:
    stage_by_action: ClassVar[dict[str, str]] = {
        "ssh_login": "initial_access",
        "http_request": "initial_access",
        "process_start": "execution",
        "scheduled_task_create": "persistence",
        "network_connect": "command_and_control",
    }
    causal_relations: ClassVar[dict[tuple[str, str], str]] = {
        ("ssh_login", "process_start"): "LEADS_TO",
        ("http_request", "process_start"): "LEADS_TO",
        ("process_start", "scheduled_task_create"): "LEADS_TO",
        ("process_start", "network_connect"): "LEADS_TO",
    }

    def __init__(self, window: timedelta = timedelta(minutes=10)) -> None:
        self.window = window

    def correlate(self, alert: Alert, events: Iterable[Event]) -> CorrelationResult:
        all_events = sorted(events, key=lambda event: (event.timestamp, event.event_id))
        anchor_events = [event for event in all_events if event.event_id in alert.event_ids]
        if not anchor_events:
            raise ValueError(f"alert events not found: {alert.event_ids}")

        related = [
            event
            for event in all_events
            if any(self._is_related(event, anchor) for anchor in anchor_events)
        ]
        graph = self._build_graph(related)
        stages = list(
            dict.fromkeys(
                self.stage_by_action[event.action]
                for event in related
                if event.action in self.stage_by_action
            )
        )
        chain = BehaviorChain(
            case_id=f"case-for-{alert.alert_id}",
            event_ids=[event.event_id for event in related],
            stages=stages,
            risk_score=alert.risk_score,
        )
        return CorrelationResult(chain=chain, graph=graph)

    def _is_related(self, event: Event, anchor: Event) -> bool:
        if abs(event.timestamp - anchor.timestamp) > self.window:
            return False
        if event.host and anchor.host and event.host == anchor.host:
            return True
        if event.user and anchor.user and event.user == anchor.user:
            return True
        identities = {
            value
            for value in (
                event.src_ip,
                event.dst_ip,
                event.domain,
                anchor.src_ip,
                anchor.dst_ip,
                anchor.domain,
            )
            if value
        }
        return bool(event.src_ip and event.src_ip in identities) or bool(
            event.dst_ip and event.dst_ip in identities
        )

    def _build_graph(self, events: list[Event]) -> BehaviorGraph:
        nodes: dict[str, GraphNode] = {}
        edges: dict[tuple[str, str, str], GraphEdge] = {}
        for event in events:
            event_node = f"event:{event.event_id}"
            nodes[event_node] = GraphNode(
                node_id=event_node,
                kind=GraphNodeKind.EVENT,
                properties={"event_id": event.event_id, "action": event.action},
            )
            for kind, value, relation in self._event_entities(event):
                entity_node = f"{kind.value}:{value}"
                nodes.setdefault(entity_node, GraphNode(node_id=entity_node, kind=kind))
                self._add_edge(
                    edges,
                    GraphEdge(
                        source=event_node,
                        target=entity_node,
                        relation=relation,
                        event_ids=[event.event_id],
                    ),
                )

        for left, right in itertools.pairwise(events):
            if left.host != right.host:
                continue
            relation = self.causal_relations.get((left.action, right.action))
            if relation is not None and right.timestamp - left.timestamp <= self.window:
                self._add_edge(
                    edges,
                    GraphEdge(
                        source=f"event:{left.event_id}",
                        target=f"event:{right.event_id}",
                        relation=relation,
                        event_ids=[left.event_id, right.event_id],
                    ),
                )
            if left.process and right.process and right.parent_process == left.process:
                parent = f"process:{left.process}"
                child = f"process:{right.process}"
                nodes.setdefault(parent, GraphNode(node_id=parent, kind=GraphNodeKind.PROCESS))
                nodes.setdefault(child, GraphNode(node_id=child, kind=GraphNodeKind.PROCESS))
                self._add_edge(
                    edges,
                    GraphEdge(
                        source=parent,
                        target=child,
                        relation="SPAWNED",
                        event_ids=[right.event_id],
                    ),
                )
        return BehaviorGraph(nodes=list(nodes.values()), edges=list(edges.values()))

    @staticmethod
    def _event_entities(event: Event) -> list[tuple[GraphNodeKind, str, str]]:
        values: list[tuple[GraphNodeKind, str, str]] = []
        for kind, value, relation in (
            (GraphNodeKind.HOST, event.host, "OBSERVED_ON"),
            (GraphNodeKind.USER, event.user, "PERFORMED_BY"),
            (GraphNodeKind.PROCESS, event.process, "EXECUTED_PROCESS"),
            (GraphNodeKind.FILE, event.file, "TOUCHED_FILE"),
            (GraphNodeKind.IP, event.src_ip, "SOURCE_IP"),
            (GraphNodeKind.IP, event.dst_ip, "DESTINATION_IP"),
            (GraphNodeKind.DOMAIN, event.domain, "DESTINATION_DOMAIN"),
        ):
            if value:
                values.append((kind, value, relation))
        return values

    @staticmethod
    def _add_edge(edges: dict[tuple[str, str, str], GraphEdge], edge: GraphEdge) -> None:
        key = (edge.source, edge.target, edge.relation)
        if key in edges:
            edges[key].event_ids = sorted(set(edges[key].event_ids + edge.event_ids))
        else:
            edges[key] = edge

