"""OpenAI-compatible JSON gateway with optional LangSmith tracing."""

from __future__ import annotations

import json
from contextlib import nullcontext
from hashlib import sha256
from time import perf_counter
from typing import Protocol

import httpx
from langsmith import Client as LangSmithClient
from langsmith import trace, tracing_context
from langsmith.wrappers import wrap_openai
from openai import OpenAI

from .config import ModelRuntimeConfig
from .models import GatewayResponse, ModelCallTrace


class JsonModelGateway(Protocol):
    def complete_json(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        operation: str,
    ) -> GatewayResponse: ...


class OpenAICompatibleGateway:
    def __init__(self, config: ModelRuntimeConfig) -> None:
        config.validate()
        if not config.enabled:
            raise ValueError("model gateway cannot start while disabled")
        self.config = config
        http_client = httpx.Client(
            proxy=config.proxy_url or None,
            timeout=config.timeout_seconds,
        )
        raw_client = OpenAI(
            api_key=config.api_key,
            base_url=config.openai_base_url,
            http_client=http_client,
            max_retries=0,
        )
        self.langsmith_client: LangSmithClient | None = None
        if config.tracing_enabled:
            self.langsmith_client = LangSmithClient(
                api_url=config.langsmith_endpoint,
                api_key=config.langsmith_api_key,
                timeout_ms=int(config.timeout_seconds * 1000),
                hide_inputs=True,
                hide_outputs=True,
            )
            self.client = wrap_openai(
                raw_client,
                tracing_extra={
                    "client": self.langsmith_client,
                    "tags": ["opsguard", "model-gateway"],
                    "metadata": {
                        "opsguard_provider": config.provider,
                        "opsguard_component": "investigation-planner",
                    },
                },
                chat_name="OpsGuard model completion",
            )
        else:
            self.client = raw_client

    def complete_json(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        operation: str,
    ) -> GatewayResponse:
        started = perf_counter()
        tracing_scope = (
            tracing_context(
                enabled=True,
                client=self.langsmith_client,
                project_name=self.config.langsmith_project,
            )
            if self.langsmith_client
            else nullcontext()
        )
        request_digest = sha256(user_prompt.encode("utf-8")).hexdigest()[:16]
        run_context = (
            trace(
                f"OpsGuard {operation}",
                "chain",
                inputs={
                    "request_digest": request_digest,
                    "request_chars": len(user_prompt),
                },
                project_name=self.config.langsmith_project,
                tags=["opsguard", operation],
                metadata={
                    "provider": self.config.provider,
                    "model": self.config.model,
                },
                client=self.langsmith_client,
            )
            if self.langsmith_client
            else nullcontext(None)
        )
        with tracing_scope, run_context as run:
            completion = self.client.chat.completions.create(
                model=self.config.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
            )
            content = completion.choices[0].message.content
            if not content:
                raise ValueError("model returned empty JSON content")
            payload = json.loads(content)
            if not isinstance(payload, dict):
                raise TypeError("model JSON response must be an object")
            if run is not None:
                run.end(
                    outputs={
                        "json_object_received": True,
                        "response_keys": sorted(payload),
                    }
                )

        latency_ms = (perf_counter() - started) * 1000
        usage = completion.usage
        trace_id = str(run.id) if run is not None else None
        trace_url = None
        trace_persisted = False
        if self.langsmith_client is not None and run is not None:
            try:
                self.langsmith_client.flush(
                    timeout=self.config.timeout_seconds
                )
                trace_url = self.langsmith_client.get_run_url(
                    run=run,
                    project_name=self.config.langsmith_project,
                )
                trace_persisted = True
            except Exception:  # noqa: BLE001
                # Observability is best effort and cannot block investigation.
                trace_url = None
        return GatewayResponse(
            payload=payload,
            trace=ModelCallTrace(
                provider=self.config.provider,
                model=completion.model or self.config.model,
                trace_id=trace_id,
                trace_url=trace_url,
                latency_ms=latency_ms,
                prompt_tokens=(
                    usage.prompt_tokens if usage is not None else None
                ),
                completion_tokens=(
                    usage.completion_tokens if usage is not None else None
                ),
                total_tokens=usage.total_tokens if usage is not None else None,
                finish_reason=completion.choices[0].finish_reason,
                traced=trace_persisted,
            ),
        )
