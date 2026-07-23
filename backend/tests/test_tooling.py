from __future__ import annotations

import asyncio
import time

from app.agent.tooling import (
    ControlledToolExecutor,
    ExecutionPolicy,
    FunctionAgentTool,
    ToolContext,
    ToolRegistry,
)


def _registry(function, required_arguments=("value",)) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        FunctionAgentTool(
            name="probe",
            description="test probe",
            source="test",
            function=function,
            required_arguments=required_arguments,
        )
    )
    return registry


def test_controlled_executor_validates_arguments() -> None:
    executor = ControlledToolExecutor(
        _registry(lambda alert_ctx, value: {"value": value}), ExecutionPolicy()
    )
    result = asyncio.run(executor.execute("probe", {}, ToolContext(alert={})))
    assert result.status == "invalid_arguments"
    assert result.success is False


def test_controlled_executor_rejects_duplicate_fingerprint() -> None:
    executor = ControlledToolExecutor(
        _registry(lambda alert_ctx, value: {"value": value}), ExecutionPolicy()
    )
    first = asyncio.run(
        executor.execute("probe", {"value": "x"}, ToolContext(alert={}))
    )
    duplicate = asyncio.run(
        executor.execute(
            "probe",
            {"value": "x"},
            ToolContext(alert={}),
            prior_fingerprints={first.call_fingerprint},
        )
    )
    assert duplicate.status == "invalid_arguments"
    assert duplicate.error == "duplicate tool call"


def test_controlled_executor_enforces_timeout_and_retry() -> None:
    def slow(alert_ctx, value):
        time.sleep(0.05)
        return {"value": value}

    executor = ControlledToolExecutor(
        _registry(slow),
        ExecutionPolicy(tool_timeout_s=0.005, tool_retries=1),
    )
    result = asyncio.run(
        executor.execute("probe", {"value": "x"}, ToolContext(alert={}))
    )
    assert result.status == "timeout"
    assert result.attempts == 2


def test_tool_result_contains_attributable_evidence() -> None:
    executor = ControlledToolExecutor(
        _registry(lambda alert_ctx, value: {"value": value, "confidence": 0.8}),
        ExecutionPolicy(),
    )
    result = asyncio.run(
        executor.execute(
            "probe",
            {"value": "observed"},
            ToolContext(alert={"alert_id": "sample-1"}),
        )
    )
    assert result.status == "found"
    assert result.evidence[0].evidence_id.startswith("EV-")
    assert result.evidence[0].source == "test"
    assert result.evidence[0].data["value"] == "observed"


def test_not_found_evidence_is_not_usable_for_a_conclusion() -> None:
    executor = ControlledToolExecutor(
        _registry(
            lambda alert_ctx, value: {"status": "no_records", "value": value}
        ),
        ExecutionPolicy(),
    )
    result = asyncio.run(
        executor.execute("probe", {"value": "missing"}, ToolContext(alert={}))
    )
    assert result.status == "not_found"
    assert result.evidence[0].usable is False
