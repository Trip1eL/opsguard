from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from opsguard.domain.models import Event


class DatasetRecord(BaseModel):
    """A labeled fixture record; labels are evaluation metadata, not production data."""

    case_id: str
    scenario: str
    event_label: str
    expected_stages: list[str] = Field(default_factory=list)
    event: Event


class DatasetManifest(BaseModel):
    version: str
    description: str
    cases: list[dict[str, Any]]


def load_manifest(path: Path) -> DatasetManifest:
    return DatasetManifest.model_validate_json(path.read_text(encoding="utf-8"))


def iter_dataset(path: Path) -> Iterator[DatasetRecord]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            if not raw_line.strip():
                continue
            try:
                yield DatasetRecord.model_validate(json.loads(raw_line))
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError(
                    f"invalid dataset record at {path}:{line_number}"
                ) from exc


def load_dataset(path: Path) -> list[DatasetRecord]:
    return list(iter_dataset(path))
