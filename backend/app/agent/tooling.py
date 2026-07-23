"""Typed, bounded execution primitives for ReAct tools.

Legacy tool functions remain in :mod:`app.agent.tools`; this module wraps them
with a stable protocol so graph nodes never need to understand tool-specific
return shapes.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Literal, Mapping

from pydantic import BaseModel, Field


ToolStatus = Literal[
    "found", "not_found", "timeout", "failed", "invalid_arguments"
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Evidence(BaseModel):
    """A single attributable observation returned by a tool."""

    evidence_id: str
    source: str
    timestamp: str
    kind: str = "tool_observation"
    summary: str
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    usable: bool = True
    data: dict[str, Any] = Field(default_factory=dict)


class ToolResult(BaseModel):
    """Uniform result envelope shared by every Agent tool."""

    tool: str
    success: bool
    status: ToolStatus
    evidence: list[Evidence] = Field(default_factory=list)
    source: str
    timestamp: str
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    latency_ms: float = 0.0
    attempts: int = 1
    error: str | None = None
    summary: str = ""
    call_fingerprint: str = ""


@dataclass(slots=True)
class ToolContext:
    """Per-alert execution context, deliberately excluding evaluation labels."""

    alert: dict[str, Any]
    run_id: str | None = None
    sample_id: str | None = None
    deadline_monotonic: float | None = None
    event_callback: Callable[[dict[str, Any]], None] | None = field(
        default=None, repr=False
    )


@dataclass(frozen=True, slots=True)
class ExecutionPolicy:
    max_steps: int = 3
    tool_timeout_s: float = 10.0
    global_timeout_s: float = 120.0
    tool_retries: int = 1
    max_llm_calls: int = 5
    max_estimated_tokens: int = 30_000
    max_no_evidence: int = 2

    def as_dict(self) -> dict[str, int | float]:
        return {
            "max_steps": self.max_steps,
            "tool_timeout_s": self.tool_timeout_s,
            "global_timeout_s": self.global_timeout_s,
            "tool_retries": self.tool_retries,
            "max_llm_calls": self.max_llm_calls,
            "max_estimated_tokens": self.max_estimated_tokens,
            "max_no_evidence": self.max_no_evidence,
        }


def call_fingerprint(tool: str, arguments: Mapping[str, Any]) -> str:
    canonical = json.dumps(arguments, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(f"{tool}:{canonical}".encode("utf-8")).hexdigest()[:20]


def _evidence_id(
    tool: str, source: str, alert_id: str, arguments: Mapping[str, Any], raw: Any
) -> str:
    canonical = json.dumps(
        [tool, source, alert_id, arguments, raw],
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )
    return "EV-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


def _summary(raw: dict[str, Any]) -> str:
    for key in ("verdict", "note", "summary", "reason", "action", "status"):
        value = raw.get(key)
        if value not in (None, ""):
            return str(value)
    return "工具已返回结构化观测结果"


def _status(raw: dict[str, Any]) -> ToolStatus:
    status = str(raw.get("status", "")).lower()
    if status in {"no_records", "not_found", "empty", "no_match", "context_only"}:
        return "not_found"
    if raw.get("total") == 0 or raw.get("matches") == []:
        return "not_found"
    # A threat-intelligence miss means unknown, never a clean/safe verdict.
    if "malicious" in raw and raw.get("malicious") is None:
        return "not_found"
    return "found"


class AgentTool(ABC):
    """Stable async interface implemented by all ReAct tools."""

    name: str
    description: str
    source: str
    required_arguments: tuple[str, ...]

    @abstractmethod
    async def execute(
        self, arguments: dict[str, Any], context: ToolContext
    ) -> ToolResult:
        raise NotImplementedError


class FunctionAgentTool(AgentTool):
    """Adapter for the project's existing synchronous Python tool functions."""

    def __init__(
        self,
        *,
        name: str,
        description: str,
        source: str,
        function: Callable[..., dict[str, Any]],
        required_arguments: tuple[str, ...] = (),
    ) -> None:
        self.name = name
        self.description = description
        self.source = source
        self.function = function
        self.required_arguments = required_arguments

    async def execute(
        self, arguments: dict[str, Any], context: ToolContext
    ) -> ToolResult:
        missing = [
            name for name in self.required_arguments
            if arguments.get(name) in (None, "")
        ]
        fingerprint = call_fingerprint(self.name, arguments)
        if missing:
            return ToolResult(
                tool=self.name,
                success=False,
                status="invalid_arguments",
                source=self.source,
                timestamp=utc_now(),
                error=f"missing required arguments: {', '.join(missing)}",
                summary="工具参数不完整",
                call_fingerprint=fingerprint,
            )

        started = time.perf_counter()
        raw = await asyncio.to_thread(
            self.function, alert_ctx=context.alert, **arguments
        )
        if not isinstance(raw, dict):
            raise TypeError(f"tool {self.name} returned {type(raw).__name__}, expected dict")
        status = _status(raw)
        confidence = raw.get("confidence")
        if not isinstance(confidence, (int, float)):
            confidence = None
        summary = _summary(raw)
        evidence = [
            Evidence(
                evidence_id=_evidence_id(
                    self.name,
                    self.source,
                    str(context.alert.get("alert_id", "")),
                    arguments,
                    raw,
                ),
                source=self.source,
                timestamp=utc_now(),
                summary=summary,
                confidence=confidence,
                usable=status == "found",
                data=raw,
            )
        ]
        return ToolResult(
            tool=self.name,
            success=status == "found",
            status=status,
            evidence=evidence,
            source=self.source,
            timestamp=utc_now(),
            confidence=confidence,
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
            summary=summary,
            call_fingerprint=fingerprint,
        )


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, AgentTool] = {}

    def register(self, tool: AgentTool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"duplicate tool: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> AgentTool | None:
        return self._tools.get(name)

    def keys(self):
        return self._tools.keys()

    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def __iter__(self):
        return iter(self._tools)

    def __len__(self) -> int:
        return len(self._tools)


class ControlledToolExecutor:
    """Apply validation, duplicate detection, timeout and retry consistently."""

    def __init__(self, registry: ToolRegistry, policy: ExecutionPolicy) -> None:
        self.registry = registry
        self.policy = policy

    async def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: ToolContext,
        *,
        prior_fingerprints: set[str] | None = None,
    ) -> ToolResult:
        started = time.perf_counter()
        fingerprint = call_fingerprint(tool_name, arguments)
        tool = self.registry.get(tool_name)
        if tool is None:
            return ToolResult(
                tool=tool_name,
                success=False,
                status="invalid_arguments",
                source="registry",
                timestamp=utc_now(),
                error=f"unknown tool: {tool_name}",
                summary=f"未知工具；可用工具：{', '.join(self.registry.keys())}",
                call_fingerprint=fingerprint,
            )
        if prior_fingerprints and fingerprint in prior_fingerprints:
            return ToolResult(
                tool=tool_name,
                success=False,
                status="invalid_arguments",
                source=tool.source,
                timestamp=utc_now(),
                error="duplicate tool call",
                summary="拒绝执行完全相同的重复工具调用",
                call_fingerprint=fingerprint,
            )

        last_error: str | None = None
        attempts = 0
        for attempts in range(1, self.policy.tool_retries + 2):
            remaining = None
            if context.deadline_monotonic is not None:
                remaining = context.deadline_monotonic - time.monotonic()
                if remaining <= 0:
                    last_error = "global execution deadline exceeded"
                    break
            timeout = self.policy.tool_timeout_s
            if remaining is not None:
                timeout = max(0.001, min(timeout, remaining))
            try:
                result = await asyncio.wait_for(
                    tool.execute(arguments, context), timeout=timeout
                )
                result.attempts = attempts
                result.latency_ms = round(
                    (time.perf_counter() - started) * 1000, 3
                )
                return result
            except asyncio.TimeoutError:
                last_error = f"tool timed out after {timeout:.3f}s"
            except Exception as exc:  # tools are an external boundary
                last_error = f"{type(exc).__name__}: {exc}"

        status: ToolStatus = (
            "timeout" if last_error and "timed out" in last_error else "failed"
        )
        return ToolResult(
            tool=tool_name,
            success=False,
            status=status,
            source=tool.source,
            timestamp=utc_now(),
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
            attempts=max(1, attempts),
            error=last_error,
            summary="工具执行超时" if status == "timeout" else "工具执行失败",
            call_fingerprint=fingerprint,
        )

    def execute_sync(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: ToolContext,
        *,
        prior_fingerprints: set[str] | None = None,
    ) -> ToolResult:
        """Sync bridge used by the current synchronous LangGraph pipeline."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(
                self.execute(
                    tool_name,
                    arguments,
                    context,
                    prior_fingerprints=prior_fingerprints,
                )
            )
        raise RuntimeError("execute_sync cannot run inside an active event loop")
