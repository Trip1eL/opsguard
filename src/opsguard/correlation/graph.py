from __future__ import annotations

from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, Field


class GraphNodeKind(StrEnum):
    EVENT = "event"
    HOST = "host"
    USER = "user"
    PROCESS = "process"
    FILE = "file"
    IP = "ip"
    DOMAIN = "domain"


class GraphNode(BaseModel):
    node_id: str
    kind: GraphNodeKind
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str
    event_ids: list[str] = Field(default_factory=list)
    properties: dict[str, Any] = Field(default_factory=dict)


class BehaviorGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class BehaviorGraphStore(Protocol):
    def upsert(self, graph: BehaviorGraph) -> None: ...

    def related(self, node_id: str, relation: str | None = None) -> list[GraphNode]: ...


class InMemoryBehaviorGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[tuple[str, str, str], GraphEdge] = {}

    def upsert(self, graph: BehaviorGraph) -> None:
        self.nodes.update({node.node_id: node for node in graph.nodes})
        self.edges.update(
            {(edge.source, edge.target, edge.relation): edge for edge in graph.edges}
        )

    def related(self, node_id: str, relation: str | None = None) -> list[GraphNode]:
        related_ids: set[str] = set()
        for edge in self.edges.values():
            if edge.source == node_id and (relation is None or edge.relation == relation):
                related_ids.add(edge.target)
            if edge.target == node_id and (relation is None or edge.relation == relation):
                related_ids.add(edge.source)
        return [self.nodes[item] for item in sorted(related_ids) if item in self.nodes]

    def edge_list(self) -> list[GraphEdge]:
        return list(self.edges.values())


class Neo4jBehaviorGraphAdapter:
    """Neo4j adapter boundary; the driver is injected to keep tests dependency-free."""

    def __init__(self, driver: Any | None = None) -> None:
        self.driver = driver

    @staticmethod
    def build_statements(graph: BehaviorGraph) -> list[tuple[str, dict[str, Any]]]:
        statements: list[tuple[str, dict[str, Any]]] = []
        for node in graph.nodes:
            statements.append(
                (
                    ("MERGE (n:OpsGuardNode {node_id: $node_id}) "
                    "SET n.kind = $kind, n.properties = $properties"),
                    {
                        "node_id": node.node_id,
                        "kind": node.kind.value,
                        "properties": node.properties,
                    },
                )
            )
        for edge in graph.edges:
            statements.append(
                (
                    ("MATCH (a:OpsGuardNode {node_id: $source}), "
                    "(b:OpsGuardNode {node_id: $target}) "
                    "MERGE (a)-[r:RELATED {relation: $relation}]->(b) "
                    "SET r.event_ids = $event_ids, r.properties = $properties"),
                    {
                        "source": edge.source,
                        "target": edge.target,
                        "relation": edge.relation,
                        "event_ids": edge.event_ids,
                        "properties": edge.properties,
                    },
                )
            )
        return statements

    def upsert(self, graph: BehaviorGraph) -> None:
        if self.driver is None:
            raise RuntimeError("Neo4j driver is required for graph upsert")
        with self.driver.session() as session:
            for statement, parameters in self.build_statements(graph):
                session.run(statement, parameters)

    def related(self, node_id: str, relation: str | None = None) -> list[GraphNode]:
        if self.driver is None:
            raise RuntimeError("Neo4j driver is required for graph queries")
        relation_filter = " AND r.relation = $relation" if relation else ""
        query = (
            "MATCH (a:OpsGuardNode {node_id: $node_id})"
            "-[r:RELATED]-(b:OpsGuardNode)"
            f" WHERE true{relation_filter}"
            " RETURN b.node_id AS node_id, b.kind AS kind, b.properties AS properties"
        )
        params = {"node_id": node_id}
        if relation:
            params["relation"] = relation
        with self.driver.session() as session:
            rows = session.run(query, params)
            return [
                GraphNode(node_id=row["node_id"], kind=row["kind"], properties=row["properties"])
                for row in rows
            ]

