"""Whitelist-based tools exposed to investigation agents."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

ToolHandler = Callable[[Mapping[str, Any]], Any]
OutputValidator = Callable[[Any], Any]


class ToolInvocationError(RuntimeError):
    """Base class for expected tool-boundary failures."""


class ToolNotAllowedError(ToolInvocationError):
    """Raised when an agent requests a tool outside its allowlist."""


class EmptyToolResultError(ToolInvocationError):
    """Raised when a required tool produces no usable evidence."""


class InvalidToolOutputError(ToolInvocationError):
    """Raised when a tool violates its structured output contract."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    handler: ToolHandler
    output_validator: OutputValidator | None = None


class ToolRegistry:
    """An explicit tool boundary: unknown tools can never be executed."""

    def __init__(self, specs: list[ToolSpec] | None = None) -> None:
        self._specs: dict[str, ToolSpec] = {}
        for spec in specs or []:
            self.register(spec)

    def register(self, spec: ToolSpec) -> None:
        if not spec.name.isidentifier():
            raise ValueError("tool names must be simple identifiers")
        if spec.name in self._specs:
            raise ValueError(f"tool already registered: {spec.name}")
        self._specs[spec.name] = spec

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._specs))

    def describe(self) -> list[dict[str, str]]:
        return [
            {"name": self._specs[name].name, "description": self._specs[name].description}
            for name in self.names()
        ]

    def invoke(self, name: str, payload: Mapping[str, Any]) -> Any:
        try:
            spec = self._specs[name]
        except KeyError as exc:
            raise ToolNotAllowedError(f"tool is not in the allowlist: {name}") from exc

        output = spec.handler(payload)
        if spec.output_validator is None:
            return output
        try:
            return spec.output_validator(output)
        except (TypeError, ValueError) as exc:
            raise InvalidToolOutputError(
                f"invalid structured output from {name}: {exc}"
            ) from exc
