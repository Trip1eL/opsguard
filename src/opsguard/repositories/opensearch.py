"""OpenSearch implementation of the normalized event repository contract."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any, ClassVar
from urllib.parse import urlparse

from opsguard.domain.models import Event

from .events import EventQuery, EventRepository, RepositoryError


class OpenSearchEventRepository(EventRepository):
    """Store and query normalized events through an injected OpenSearch client."""

    INDEX_MAPPING: ClassVar[dict[str, Any]] = {
        "properties": {
            "event_id": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "source": {"type": "keyword"},
            "host": {"type": "keyword"},
            "user": {"type": "keyword"},
            "action": {"type": "keyword"},
            "process": {"type": "keyword"},
            "parent_process": {"type": "keyword"},
            "src_ip": {"type": "ip"},
            "dst_ip": {"type": "ip"},
            "domain": {"type": "keyword"},
            "file": {"type": "keyword"},
            "attributes": {"type": "object", "enabled": True},
            "raw_log": {"type": "text", "index": False},
        }
    }

    def __init__(
        self,
        client: Any,
        index: str = "opsguard-events",
        *,
        create_index: bool = True,
    ) -> None:
        if not index or not index.replace("_", "").replace("-", "").isalnum():
            raise ValueError("index must contain only letters, numbers, ''_'' or ''-''")
        self.client = client
        self.index = index
        if create_index:
            self.ensure_index()

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        index: str = "opsguard-events",
        username: str | None = None,
        password: str | None = None,
        verify_certs: bool = True,
    ) -> OpenSearchEventRepository:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("OpenSearch URL must be an absolute HTTP(S) URL")
        try:
            from opensearchpy import OpenSearch
        except (
            ImportError
        ) as exc:  # pragma: no cover - dependency is installed in release env
            raise RuntimeError(
                "opensearch-py is required for OpenSearch adapter"
            ) from exc
        auth = (username, password) if username and password else None
        client = OpenSearch(
            hosts=[
                {
                    "host": parsed.hostname,
                    "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                    "scheme": parsed.scheme,
                }
            ],
            http_auth=auth,
            verify_certs=verify_certs,
        )
        return cls(client, index=index)

    def ensure_index(self) -> None:
        if self.client.indices.exists(index=self.index):
            return
        try:
            self.client.indices.create(
                index=self.index, body={"mappings": self.INDEX_MAPPING}
            )
        except Exception as exc:
            if not self.client.indices.exists(index=self.index):
                raise RepositoryError(
                    f"failed to create OpenSearch index: {type(exc).__name__}"
                ) from exc

    def add(self, event: Event) -> None:
        try:
            self.client.index(
                index=self.index,
                id=event.event_id,
                body=event.model_dump(mode="json"),
                refresh="wait_for",
            )
        except Exception as exc:
            raise RepositoryError(f"failed to index event {event.event_id}") from exc

    def add_many(self, events: Iterable[Event]) -> None:
        operations: list[dict[str, Any]] = []
        for event in events:
            operations.extend(
                [
                    {"index": {"_index": self.index, "_id": event.event_id}},
                    event.model_dump(mode="json"),
                ]
            )
        if not operations:
            return
        try:
            response = self.client.bulk(body=operations, refresh="wait_for")
        except Exception as exc:
            raise RepositoryError("failed to bulk index events") from exc
        if response.get("errors"):
            raise RepositoryError("OpenSearch bulk indexing returned errors")

    def get(self, event_id: str) -> Event | None:
        try:
            response = self.client.get(index=self.index, id=event_id)
        except Exception as exc:
            if type(exc).__name__ in {"NotFoundError", "OpenSearchNotFoundError"}:
                return None
            raise RepositoryError(f"failed to fetch event {event_id}") from exc
        return Event.model_validate(response.get("_source", {}))

    def search(self, query: EventQuery | None = None) -> list[Event]:
        query = query or EventQuery()
        clauses: list[dict[str, Any]] = []
        for field in (
            "event_ids",
            "source",
            "host",
            "user",
            "process",
            "src_ip",
            "dst_ip",
            "domain",
            "action",
        ):
            value = getattr(query, field)
            if field == "event_ids" and value:
                clauses.append({"terms": {"event_id": sorted(value)}})
            elif field != "event_ids" and value is not None:
                serialized = value.value if hasattr(value, "value") else value
                clauses.append({"term": {field: serialized}})
        if query.start_time or query.end_time:
            timestamp: dict[str, str] = {}
            if query.start_time:
                timestamp["gte"] = _iso(query.start_time)
            if query.end_time:
                timestamp["lte"] = _iso(query.end_time)
            clauses.append({"range": {"timestamp": timestamp}})
        body = {
            "query": {"bool": {"filter": clauses}} if clauses else {"match_all": {}},
            "sort": [{"timestamp": "asc"}, {"event_id": "asc"}],
            "size": 10_000,
        }
        try:
            response = self.client.search(index=self.index, body=body)
        except Exception as exc:
            raise RepositoryError("failed to query OpenSearch events") from exc
        return [
            Event.model_validate(hit.get("_source", {}))
            for hit in response.get("hits", {}).get("hits", [])
        ]

    def __len__(self) -> int:
        try:
            return int(self.client.count(index=self.index).get("count", 0))
        except Exception as exc:
            raise RepositoryError("failed to count OpenSearch events") from exc


def _iso(value: datetime) -> str:
    return value.isoformat()
