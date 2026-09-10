"""Bounded containment execution for the SuperAgent response loop.

The default adapter is a deterministic simulator, so a fresh clone can show
execute -> observe -> retry/rollback without touching a real firewall or EDR.
Live execution is opt-in and additionally blocked for public evaluation data.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from app.agent.state import AgentState
from app.core.config import Settings, get_settings

logger = logging.getLogger(__name__)

PUBLIC_EVAL_DATASETS = {
    "AIT-ADS",
    "AIT-ADS-EVENT-GOLD",
    "TON-IOT-INDUSTRIAL",
}
ACTION_TYPES = {"block_ip", "isolate_host"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _receipt(prefix: str, action_id: str, attempt: int) -> str:
    suffix = uuid.uuid5(
        uuid.NAMESPACE_URL, f"{prefix}:{action_id}:{attempt}"
    ).hex[:12]
    return f"{prefix}-{suffix}"


@dataclass(frozen=True, slots=True)
class ResponsePolicy:
    mode: Literal["disabled", "simulate", "webhook"] = "simulate"
    auto_execute: bool = True
    min_confidence: float = 0.85
    max_attempts: int = 2
    atomic: bool = True
    live_enabled: bool = False
    live_require_evidence: bool = True
    timeout_s: float = 10.0


class ResponseAdapter:
    """Small adapter contract shared by the simulator and live webhooks."""

    name = "base"

    def execute(
        self, action: dict[str, Any], alert: dict[str, Any], attempt: int
    ) -> dict[str, Any]:
        raise NotImplementedError

    def verify(
        self, action: dict[str, Any], alert: dict[str, Any], attempt: int
    ) -> dict[str, Any]:
        raise NotImplementedError

    def rollback(
        self, action: dict[str, Any], alert: dict[str, Any], attempt: int
    ) -> dict[str, Any]:
        raise NotImplementedError


class SimulatedResponseAdapter(ResponseAdapter):
    """Deterministic firewall/EDR simulator used by demos and tests."""

    name = "simulated_security_platform"

    @staticmethod
    def _scenario(alert: dict[str, Any]) -> dict[str, Any]:
        value = (alert.get("raw_payload") or {}).get("response_simulation")
        return value if isinstance(value, dict) else {}

    def execute(
        self, action: dict[str, Any], alert: dict[str, Any], attempt: int
    ) -> dict[str, Any]:
        scenario = self._scenario(alert)
        action_type = str(action["action"])
        fail_always = set(scenario.get("fail_actions") or [])
        fail_once = set(scenario.get("fail_once_actions") or [])
        failed = action_type in fail_always or (
            action_type in fail_once and attempt == 1
        )
        return {
            "executed": not failed,
            "status": "failed" if failed else "executed",
            "receipt_id": (
                None if failed else _receipt("SIM", action["action_id"], attempt)
            ),
            "connector": self.name,
            "message": (
                "模拟连接器按测试场景拒绝本次动作"
                if failed else "模拟安全平台已接受处置动作"
            ),
            "observed_at": _now(),
        }

    def verify(
        self, action: dict[str, Any], alert: dict[str, Any], attempt: int
    ) -> dict[str, Any]:
        scenario = self._scenario(alert)
        action_type = str(action["action"])
        verify_fail = set(scenario.get("verification_fail_actions") or [])
        verified = bool(action.get("executed")) and action_type not in verify_fail
        return {
            "verified": verified,
            "status": "active" if verified else "not_active",
            "connector": self.name,
            "message": (
                "已观测到策略生效"
                if verified else "未观测到策略生效"
            ),
            "observed_at": _now(),
        }

    def rollback(
        self, action: dict[str, Any], alert: dict[str, Any], attempt: int
    ) -> dict[str, Any]:
        scenario = self._scenario(alert)
        rollback_fail = set(scenario.get("rollback_fail_actions") or [])
        rolled_back = str(action["action"]) not in rollback_fail
        return {
            "rolled_back": rolled_back,
            "status": "rolled_back" if rolled_back else "rollback_failed",
            "connector": self.name,
            "message": (
                "模拟安全平台已撤销动作"
                if rolled_back else "模拟安全平台未能撤销动作"
            ),
            "observed_at": _now(),
        }


class WebhookResponseAdapter(ResponseAdapter):
    """Generic live connector for firewall and EDR automation gateways."""

    name = "security_webhook"

    def __init__(self, settings: Settings):
        self.settings = settings

    def _url(self, action_type: str) -> str:
        if action_type == "block_ip":
            return self.settings.response_firewall_webhook.strip()
        return self.settings.response_edr_webhook.strip()

    def _post(self, action: dict[str, Any], operation: str) -> dict[str, Any]:
        url = self._url(str(action["action"]))
        if not url:
            return {
                "success": False,
                "message": f"{action['action']} 未配置 webhook",
            }
        payload = json.dumps({
            "operation": operation,
            "action_id": action["action_id"],
            "action": action["action"],
            "target": action["target"],
            "reason": action.get("reason", ""),
            "receipt_id": action.get("receipt_id"),
        }, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        token = self.settings.response_webhook_token.strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            url, data=payload, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.settings.response_timeout_s
            ) as response:
                raw = response.read().decode("utf-8")
            parsed = json.loads(raw or "{}")
            return parsed if isinstance(parsed, dict) else {"success": False}
        except (OSError, ValueError, urllib.error.URLError) as exc:
            logger.warning("response webhook %s failed: %s", operation, exc)
            return {"success": False, "message": str(exc)}

    def execute(
        self, action: dict[str, Any], alert: dict[str, Any], attempt: int
    ) -> dict[str, Any]:
        result = self._post(action, "execute")
        executed = bool(result.get("success") or result.get("executed"))
        return {
            "executed": executed,
            "status": "executed" if executed else "failed",
            "receipt_id": result.get("receipt_id"),
            "connector": self.name,
            "message": str(result.get("message") or "live connector response"),
            "observed_at": _now(),
        }

    def verify(
        self, action: dict[str, Any], alert: dict[str, Any], attempt: int
    ) -> dict[str, Any]:
        result = self._post(action, "verify")
        verified = bool(result.get("verified") or result.get("active"))
        return {
            "verified": verified,
            "status": "active" if verified else "not_active",
            "connector": self.name,
            "message": str(result.get("message") or "live verification response"),
            "observed_at": _now(),
        }

    def rollback(
        self, action: dict[str, Any], alert: dict[str, Any], attempt: int
    ) -> dict[str, Any]:
        result = self._post(action, "rollback")
        rolled_back = bool(result.get("rolled_back") or result.get("success"))
        return {
            "rolled_back": rolled_back,
            "status": "rolled_back" if rolled_back else "rollback_failed",
            "connector": self.name,
            "message": str(result.get("message") or "live rollback response"),
            "observed_at": _now(),
        }


def _policy(settings: Settings) -> ResponsePolicy:
    return ResponsePolicy(
        mode=settings.response_execution_mode,
        auto_execute=settings.response_auto_execute,
        min_confidence=settings.response_min_confidence,
        max_attempts=settings.response_max_retries + 1,
        atomic=settings.response_atomic,
        live_enabled=settings.response_live_enabled,
        live_require_evidence=settings.response_live_require_evidence,
        timeout_s=settings.response_timeout_s,
    )


def _valid_target(action: dict[str, Any], alert: dict[str, Any]) -> tuple[bool, str]:
    target = str(action.get("target") or "")
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return False, "处置目标不是合法 IP 地址"
    if target not in {str(alert.get("src_ip") or ""), str(alert.get("dst_ip") or "")}:
        return False, "处置目标不属于当前告警"
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        return False, "禁止处置保留或本机地址"
    if action.get("action") == "isolate_host" and not (
        ip.is_private and not ip.is_reserved
    ):
        return False, "EDR 只能隔离当前告警中的内部主机"
    return True, "validated"


def _skip_reason(state: AgentState, policy: ResponsePolicy) -> str | None:
    if not policy.auto_execute:
        return "自动执行已关闭"
    if policy.mode == "disabled":
        return "处置执行模式为 disabled"
    if state.get("judgment") != "真阳":
        return "仅对真阳事件执行自动遏制"
    if float(state.get("confidence", 0.0)) < policy.min_confidence:
        return f"置信度低于自动处置阈值 {policy.min_confidence:.2f}"
    if not state.get("response_plan"):
        return "没有可执行的封禁或隔离动作"
    if policy.mode == "webhook":
        dataset = ((state.get("alert") or {}).get("raw_payload") or {}).get("dataset")
        if dataset in PUBLIC_EVAL_DATASETS:
            return "正式评测数据禁止触发真实安全设备"
        if not policy.live_enabled:
            return "真实执行需要显式开启 RESPONSE_LIVE_ENABLED"
        if policy.live_require_evidence and not state.get("cited_evidence"):
            return "真实执行必须引用本轮有效事件证据"
    return None


def make_response_nodes(settings: Settings | None = None):
    """Create execute/observe/rollback nodes sharing one bounded policy."""
    resolved = settings or get_settings()
    policy = _policy(resolved)
    adapter: ResponseAdapter = (
        WebhookResponseAdapter(resolved)
        if policy.mode == "webhook" else SimulatedResponseAdapter()
    )

    def response_execute_node(state: AgentState) -> AgentState:
        reason = _skip_reason(state, policy)
        previous = dict(state.get("response_execution", {}))
        attempt = int(previous.get("attempt", 0)) + 1
        trace = list(state.get("response_trace", []))
        if reason:
            execution = {
                "mode": policy.mode,
                "automated": False,
                "status": "skipped",
                "reason": reason,
                "attempt": 0,
                "max_attempts": policy.max_attempts,
                "actions": [],
                "updated_at": _now(),
            }
            trace.append({"phase": "execute", "status": "skipped", "reason": reason})
            return {"response_execution": execution, "response_trace": trace}

        alert = state["alert"]
        prior_actions = {
            item.get("action_id"): item
            for item in previous.get("actions", [])
            if item.get("action_id")
        }
        actions: list[dict[str, Any]] = []
        for planned in state.get("response_plan", []):
            item = dict(planned)
            prior = prior_actions.get(item.get("action_id"), {})
            if prior.get("verified"):
                actions.append(dict(prior))
                continue
            valid, validation = _valid_target(item, alert)
            if not valid:
                item.update({
                    "executed": False,
                    "status": "rejected",
                    "message": validation,
                    "connector": "policy_guard",
                })
            else:
                item.update(adapter.execute(item, alert, attempt))
            actions.append(item)

        execution = {
            "run_id": previous.get("run_id") or f"RESP-{uuid.uuid4().hex[:12]}",
            "mode": policy.mode,
            "automated": True,
            "status": "awaiting_observation",
            "reason": "处置动作已提交，等待独立验证",
            "attempt": attempt,
            "max_attempts": policy.max_attempts,
            "atomic": policy.atomic,
            "actions": actions,
            "updated_at": _now(),
        }
        trace.append({
            "phase": "execute",
            "attempt": attempt,
            "status": execution["status"],
            "actions": [item.get("status") for item in actions],
        })
        return {
            "response_execution": execution,
            "response_trace": trace,
            "cot_trace": state.get("cot_trace", []) + [
                f"[自主处置执行] 第 {attempt} 次提交 {len(actions)} 个受控动作。"
            ],
        }

    def response_observe_node(state: AgentState) -> AgentState:
        execution = dict(state.get("response_execution", {}))
        actions: list[dict[str, Any]] = []
        alert = state["alert"]
        attempt = int(execution.get("attempt", 1))
        for current in execution.get("actions", []):
            item = dict(current)
            if item.get("verified"):
                actions.append(item)
                continue
            if item.get("executed"):
                item.update(adapter.verify(item, alert, attempt))
            else:
                item["verified"] = False
            actions.append(item)

        all_verified = bool(actions) and all(item.get("verified") for item in actions)
        if all_verified:
            status = "contained"
            reason = "防火墙封禁和 EDR 隔离均已验证生效"
        elif attempt < policy.max_attempts:
            status = "retry_required"
            reason = "部分动作未执行或未生效，反馈给执行器重试"
        elif policy.atomic and any(item.get("executed") for item in actions):
            status = "rollback_required"
            reason = "重试后仍未形成完整闭环，进入补偿回滚"
        else:
            status = "manual_required"
            reason = "自动处置未形成闭环，升级人工处理"
        execution.update({
            "status": status,
            "reason": reason,
            "actions": actions,
            "updated_at": _now(),
        })
        trace = list(state.get("response_trace", []))
        trace.append({
            "phase": "observe",
            "attempt": attempt,
            "status": status,
            "verified": sum(1 for item in actions if item.get("verified")),
            "total": len(actions),
        })
        return {
            "response_execution": execution,
            "response_trace": trace,
            "cot_trace": state.get("cot_trace", []) + [
                f"[处置效果观测] {reason}"
            ],
        }

    def response_rollback_node(state: AgentState) -> AgentState:
        execution = dict(state.get("response_execution", {}))
        alert = state["alert"]
        attempt = int(execution.get("attempt", 1))
        actions: list[dict[str, Any]] = []
        for current in execution.get("actions", []):
            item = dict(current)
            if item.get("executed"):
                item["rollback"] = adapter.rollback(item, alert, attempt)
            actions.append(item)
        complete = all(
            not item.get("executed") or item.get("rollback", {}).get("rolled_back")
            for item in actions
        )
        status = "rolled_back" if complete else "manual_required"
        reason = (
            "原子处置未完整生效，已撤销本轮已执行动作"
            if complete else "自动回退不足：部分动作回滚失败，必须人工接管"
        )
        execution.update({
            "status": status,
            "reason": reason,
            "actions": actions,
            "updated_at": _now(),
        })
        trace = list(state.get("response_trace", []))
        trace.append({"phase": "rollback", "status": status, "reason": reason})
        return {
            "response_execution": execution,
            "response_trace": trace,
            "cot_trace": state.get("cot_trace", []) + [f"[处置补偿] {reason}"],
        }

    return response_execute_node, response_observe_node, response_rollback_node


def response_after_execute(state: AgentState) -> str:
    return (
        "observe"
        if state.get("response_execution", {}).get("status")
        == "awaiting_observation"
        else "output"
    )


def response_after_observe(state: AgentState) -> str:
    status = state.get("response_execution", {}).get("status")
    if status == "retry_required":
        return "retry"
    if status == "rollback_required":
        return "rollback"
    return "output"
