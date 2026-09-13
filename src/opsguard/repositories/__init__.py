"""Storage adapters for normalized OpsGuard events."""

from opsguard.repositories.events import (
    EventQuery,
    EventRepository,
    InMemoryEventRepository,
    JsonlEventRepository,
    RepositoryError,
)
from opsguard.repositories.opensearch import OpenSearchEventRepository

__all__ = [
    "EventQuery",
    "EventRepository",
    "InMemoryEventRepository",
    "JsonlEventRepository",
    "OpenSearchEventRepository",
    "RepositoryError",
]
