"""评测入口脚本。

赛题贴合：评分明确要求"准确性"——这是核心加分项。
方案 B6：在标注数据集上跑 Agent，算准确率/召回率。

用法：
    # mock 模式（不耗 token，验证工程链路）
    uv run python -m app.eval.run --mock

    # 真实 DeepSeek（需已配 .env，会产生 token 费用）
    uv run python -m app.eval.run

    # 指定数据集
    uv run python -m app.eval.run --mock --dataset app/data/datasets/sample_alerts.json
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from pathlib import Path
from typing import Callable, Literal

from langchain_core.callbacks import BaseCallbackHandler, UsageMetadataCallbackHandler

from app.agent.graph import judge_alert
from app.agent.prompts import PROMPT_VERSION
from app.core.config import get_settings
from app.core.logging import get_logger, setup_logging
from app.data.loader import DEFAULT_DATASET
from app.eval.dataset import load_eval_dataset
from app.eval.metrics import compute_metrics, format_report
from app.models.llm import get_llm
from app.rag.service import get_rag_service

logger = get_logger(__name__)

EvalStrategy = Literal["judge_only", "react"]


class _LLMCallCounter(BaseCallbackHandler):
    """Thread-safe count of actual chat-model requests made by LangChain."""

    def __init__(self) -> None:
        super().__init__()
        self.calls = 0
        self._lock = threading.Lock()

    def on_chat_model_start(self, serialized, messages, **kwargs) -> None:  # type: ignore[override]
        with self._lock:
            self.calls += len(messages)


def _token_totals(handler: UsageMetadataCallbackHandler) -> dict[str, int]:
    totals = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    for usage in handler.usage_metadata.values():
        for key in totals:
            totals[key] += int(usage.get(key, 0))
    return totals


def _usage_delta(after: dict[str, int], before: dict[str, int]) -> dict[str, int]:
    return {key: max(0, after[key] - before[key]) for key in after}


def _usage_sum(*items: dict[str, int]) -> dict[str, int]:
    keys = ("input_tokens", "output_tokens", "total_tokens")
    return {key: sum(int(item.get(key, 0)) for item in items) for key in keys}


def _paired_stage_summary(
    details: list[dict], *, before_key: str, after_key: str
) -> dict[str, int | float]:
    """Measure one stage against its input using the same model requests."""
    changed = fixes = regressions = changed_wrong = 0
    for detail in details:
        initial = detail.get(
            before_key, detail.get("initial_pred", detail.get("pred"))
        )
        final = detail.get(after_key, detail.get("pred"))
        truth = detail.get("label")
        if initial == final:
            continue
        changed += 1
        if initial != truth and final == truth:
            fixes += 1
        elif initial == truth and final != truth:
            regressions += 1
        else:
            changed_wrong += 1
    n = len(details)
    initial_correct = sum(
        detail.get(
            before_key, detail.get("initial_pred", detail.get("pred"))
        ) == detail.get("label")
        for detail in details
    )
    final_correct = sum(
        detail.get(after_key, detail.get("pred")) == detail.get("label")
        for detail in details
    )
    return {
        "n": n,
        "initial_correct": initial_correct,
        "final_correct": final_correct,
        "initial_accuracy": round(initial_correct / n, 4) if n else 0.0,
        "final_accuracy": round(final_correct / n, 4) if n else 0.0,
        "accuracy_delta": round((final_correct - initial_correct) / n, 4) if n else 0.0,
        "changed": changed,
        "fixes": fixes,
        "regressions": regressions,
        "changed_wrong": changed_wrong,
        "net_fixes": fixes - regressions,
    }


def _paired_react_summary(details: list[dict]) -> dict[str, int | float]:
    """Measure ReAct after RAG; without RAG, post-RAG equals initial Judge."""
    return _paired_stage_summary(
        details, before_key="post_rag_pred", after_key="pred"
    )


def _paired_rag_summary(details: list[dict]) -> dict[str, int | float]:
    """Measure only RAG late fusion, before any subsequent ReAct changes."""
    summary = _paired_stage_summary(
        details, before_key="initial_pred", after_key="post_rag_pred"
    )
    agent_results = [
        detail.get("agent_result") or {} for detail in details
    ]
    summary.update({
        "triggered": sum(
            bool(result.get("rag_attempted")) for result in agent_results
        ),
        "retrieval_used": sum(
            bool(result.get("rag_used")) for result in agent_results
        ),
        "refinement_attempted": sum(
            bool(result.get("rag_refinement", {}).get("attempted"))
            for result in agent_results
        ),
        "refinement_accepted": sum(
            bool(result.get("rag_refinement", {}).get("accepted"))
            for result in agent_results
        ),
        "refinement_errors": sum(
            result.get("rag_refinement", {}).get("reason")
            == "refinement_error"
            for result in agent_results
        ),
    })
    return summary


def run_eval(
    dataset_path: str | Path | None = None,
    mock: bool = False,
    save_results: bool = True,
    progress_callback: Callable[[dict], None] | None = None,
    agent_event_callback: Callable[[dict], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
    max_samples: int | None = None,
    strategy: EvalStrategy = "judge_only",
    enable_rag: bool = False,
    provider: str | None = None,
    model: str | None = None,
    initial_details: list[dict] | None = None,
) -> dict:
    """跑评测，返回 metrics dict + 明细。

    参数：
        dataset_path: 数据集 JSON 路径；None 则用 eval_alerts.json（不存在则回退 sample）
        mock: True 用 mock LLM；False 用配置的真实 Provider
        save_results: 是否把明细存到 data/eval_results.json
        progress_callback: 每完成一条样本后回调，供 SSE 实时推送
        agent_event_callback: Agent 每个节点/工具事件的回调，供实时轨迹与持久化
        should_stop: 返回 True 时在下一条样本前安全停止
        max_samples: 仅评测一个确定、标签均衡的子集；用于控制真实模型成本
        strategy: judge_only=单次模型、无工具基线；react=完整 ReAct Agent
    """
    setup_logging(level="INFO")
    if strategy not in {"judge_only", "react"}:
        raise ValueError("strategy must be 'judge_only' or 'react'")

    # 选数据集
    dataset = load_eval_dataset(dataset_path)
    path = dataset.path
    labeled = _balanced_subset(dataset.samples, max_samples)
    logger.info("eval dataset: %s", path)
    logger.info("labeled samples: %d", len(labeled))
    if dataset.metadata.get("label_basis") == "time_window_weak":
        logger.warning("AIT-ADS uses weak attack-window labels, not exact event-level truth")

    settings = get_settings()
    llm = get_llm(
        mock=mock,
        provider=provider,
        model=model,
        settings=settings,
    )
    effective_provider = provider or settings.llm_provider
    effective_model = (
        getattr(llm, "model_name", None)
        or model
        or settings.llm_model
        or "provider-default"
    )
    mode = "mock" if mock else effective_provider
    logger.info("LLM mode: %s, eval strategy: %s", mode, strategy)

    usage_handler = UsageMetadataCallbackHandler()
    call_counter = _LLMCallCounter()
    callbacks = [usage_handler, call_counter]
    experiment_config = {
        "strategy": strategy,
        "rag_enabled": enable_rag,
        "rag_strategy": (
            "selective_weak_signal_calibration_v3" if enable_rag else None
        ),
        "tools_enabled": strategy == "react",
        "provider": "mock" if mock else effective_provider,
        "model": "mock" if mock else effective_model,
        "temperature": settings.llm_temperature,
        "prompt_version": PROMPT_VERSION,
        "requested_max_samples": max_samples,
        "dataset_seed": dataset.metadata.get("seed"),
        "dataset_label_basis": dataset.metadata.get("label_basis"),
        "dataset_schema_version": dataset.metadata.get("schema_version"),
        "dataset_evaluation_unit": dataset.metadata.get("evaluation_unit"),
        "dataset_selection_basis": dataset.metadata.get("selection_basis"),
        "context_basis": dataset.metadata.get("context_basis"),
        "context_window_seconds": dataset.metadata.get("context_window_seconds"),
        "rag": get_rag_service().status() if enable_rag else None,
        "react_policy": {
            "max_steps": settings.react_max_steps,
            "tool_timeout_s": settings.react_tool_timeout_s,
            "global_timeout_s": settings.react_global_timeout_s,
            "tool_retries": settings.react_tool_retries,
            "max_llm_calls": settings.react_max_llm_calls,
            "max_estimated_tokens": settings.react_max_estimated_tokens,
            "max_no_evidence": settings.react_max_no_evidence,
        },
    }

    details = list(initial_details or [])
    if len(details) > len(labeled):
        raise ValueError("resume details exceed the selected evaluation set")
    expected_ids = [sample.alert.alert_id for sample in labeled[:len(details)]]
    actual_ids = [str(detail.get("alert_id", "")) for detail in details]
    if actual_ids != expected_ids:
        raise ValueError("resume details do not match the deterministic dataset prefix")

    predictions: list[tuple[str, str]] = [
        (str(detail.get("label", "")), str(detail.get("pred", "")))
        for detail in details
    ]
    initial_predictions: list[tuple[str, str]] = [
        (
            str(detail.get("label", "")),
            str(detail.get("initial_pred", detail.get("pred", ""))),
        )
        for detail in details
    ]
    latencies: list[float] = [
        float(detail.get("latency_s", 0.0)) for detail in details
    ]
    base_llm_calls = sum(int(detail.get("llm_calls", 0)) for detail in details)
    base_token_usage = _usage_sum(*[
        detail.get("token_usage", {}) for detail in details
        if isinstance(detail.get("token_usage"), dict)
    ])

    for i, sample in enumerate(labeled[len(details):], len(details) + 1):
        if should_stop and should_stop():
            logger.warning("评测收到停止请求，已完成 %d/%d 条", len(details), len(labeled))
            break

        alert = sample.alert
        label = sample.label
        alert_dict = alert.model_dump(mode="json", exclude={"label"})

        t0 = time.perf_counter()
        calls_before = call_counter.calls
        tokens_before = _token_totals(usage_handler)
        agent_result: dict | None = None
        try:
            agent_result = judge_alert(
                alert_dict,
                llm=llm,
                enable_react=strategy == "react",
                enable_rag=enable_rag,
                callbacks=callbacks,
                event_callback=(
                    lambda event, sample_index=i, sample_total=len(labeled):
                    agent_event_callback({
                        **event,
                        "sample_index": sample_index,
                        "sample_total": sample_total,
                    })
                ) if agent_event_callback else None,
            )
            pred = agent_result["judgment"]
            initial_pred = agent_result.get("initial_judgment", pred)
            post_rag_pred = agent_result.get(
                "post_rag_judgment", initial_pred
            )
            conf = agent_result["confidence"]
            reason = agent_result["reason"]
        except Exception as e:
            # 双重兜底：即使 judge_node 的兜底也崩了，整轮评测仍继续
            logger.exception("[%d] 异常跳过 %s: %s", i, alert.alert_id, e)
            pred = "待查"
            initial_pred = pred
            post_rag_pred = pred
            conf = 0.0
            reason = f"eval 异常: {e}"
        latency = time.perf_counter() - t0
        tokens_after = _token_totals(usage_handler)
        sample_usage = _usage_delta(tokens_after, tokens_before)
        sample_calls = max(0, call_counter.calls - calls_before)
        predictions.append((label, pred))
        initial_predictions.append((label, initial_pred))
        latencies.append(latency)
        detail = {
            "alert_id": alert.alert_id,
            "label": label,
            "truth_metadata": sample.truth_metadata,
            "pred": pred,
            "initial_pred": initial_pred,
            "post_rag_pred": post_rag_pred,
            "rag_changed": initial_pred != post_rag_pred,
            "react_changed": initial_pred != pred,
            "confidence": conf,
            "latency_s": round(latency, 3),
            "correct": pred == label,
            "reason": reason,
            "llm_calls": sample_calls,
            "token_usage": sample_usage,
            "eval_strategy": strategy,
            # 保留本次已经生成的完整流程，前端点开即可查看，不重复调用模型。
            "alert": alert_dict,
            "agent_result": agent_result,
        }
        details.append(detail)
        mark = "✓" if pred == label else "✗"
        logger.info(
            "[%d/%d] %s %s label=%s pred=%s conf=%.2f %.2fs",
            i, len(labeled), mark, alert.alert_id,
            label, pred, conf, latency,
        )

        if progress_callback:
            cumulative_usage = _usage_sum(base_token_usage, tokens_after)
            progress_callback(
                {
                    "completed": len(details),
                    "total": len(labeled),
                    "detail": detail,
                    "experiment_config": experiment_config,
                    "metrics": compute_metrics(
                        predictions,
                        latencies,
                        llm_calls=base_llm_calls + call_counter.calls,
                        token_usage=cumulative_usage,
                    ).as_dict(),
                    "initial_metrics": compute_metrics(initial_predictions).as_dict(),
                    "paired_react": _paired_react_summary(details),
                    "paired_rag": _paired_rag_summary(details),
                }
            )

    metrics = compute_metrics(
        predictions,
        latencies,
        llm_calls=base_llm_calls + call_counter.calls,
        token_usage=_usage_sum(base_token_usage, _token_totals(usage_handler)),
    )
    report = format_report(metrics)
    print("\n" + report)
    paired_react = _paired_react_summary(details)
    paired_rag = _paired_rag_summary(details)
    if enable_rag:
        print(
            "同轮 RAG 配对: "
            f"初判={paired_rag['initial_accuracy']:.4f} "
            f"RAG后={paired_rag['final_accuracy']:.4f} "
            f"净变化={paired_rag['accuracy_delta']:+.4f} "
            f"修正={paired_rag['fixes']} 退化={paired_rag['regressions']} "
            f"触发={paired_rag['triggered']} 采纳={paired_rag['refinement_accepted']} "
            f"失败={paired_rag['refinement_errors']}"
        )
    if strategy == "react":
        print(
            "同轮 ReAct 配对: "
            f"初判={paired_react['initial_accuracy']:.4f} "
            f"最终={paired_react['final_accuracy']:.4f} "
            f"净变化={paired_react['accuracy_delta']:+.4f} "
            f"修正={paired_react['fixes']} 退化={paired_react['regressions']}"
        )

    output = {
        "mode": mode,
        "strategy": strategy,
        "experiment_config": experiment_config,
        "dataset": str(path),
        "dataset_metadata": dataset.metadata,
        "metrics": metrics.as_dict(),
        "initial_metrics": compute_metrics(initial_predictions).as_dict(),
        "paired_react": paired_react,
        "paired_rag": paired_rag,
        "details": details,
    }

    if save_results:
        out_path = DEFAULT_DATASET.parent.parent.parent / "data" / "eval_results.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        logger.info("results saved to %s", out_path)

    return output


def _balanced_subset(samples: list, max_samples: int | None) -> list:
    """Return a deterministic label-balanced prefix without exposing labels to Agent.

    Ground truth is used only by the evaluation harness to choose an equally
    sized test subset.  The selected labels are still stripped before inference.
    """
    if max_samples is None or max_samples >= len(samples):
        return samples
    if max_samples < 1:
        raise ValueError("max_samples must be at least 1")
    groups: dict[str, list] = {}
    for sample in samples:
        groups.setdefault(sample.label, []).append(sample)
    order = [label for label in ("真阳", "假阳", "待查") if label in groups]
    order.extend(label for label in groups if label not in order)
    selected: list = []
    offset = 0
    while len(selected) < max_samples:
        added = False
        for label in order:
            group = groups[label]
            if offset < len(group):
                selected.append(group[offset])
                added = True
                if len(selected) == max_samples:
                    break
        if not added:
            break
        offset += 1
    return selected


def _main() -> None:
    parser = argparse.ArgumentParser(description="告警研判评测")
    parser.add_argument(
        "--mock", action="store_true",
        help="用 mock LLM（不耗 token，验证链路）",
    )
    parser.add_argument(
        "--dataset", type=str, default=None,
        help="数据集 JSON 路径（默认 eval_alerts.json）",
    )
    parser.add_argument(
        "--no-save", action="store_true",
        help="不保存结果到 data/eval_results.json",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="仅运行一个标签均衡的确定性子集，用于控制真实模型成本",
    )
    parser.add_argument(
        "--strategy", choices=("judge_only", "react"), default="judge_only",
        help="judge_only=无工具单次调用基线；react=完整 ReAct Agent",
    )
    parser.add_argument(
        "--rag", action="store_true",
        help="启用本地安全知识 RAG（默认关闭，用于公平基线）",
    )
    parser.add_argument(
        "--provider", type=str, default=None,
        help="Override LLM provider for this run (deepseek, siliconflow, openai_relay, qwen)",
    )
    parser.add_argument(
        "--model", type=str, default=None,
        help="Override model ID for this run",
    )
    args = parser.parse_args()
    run_eval(
        dataset_path=args.dataset,
        mock=args.mock,
        save_results=not args.no_save,
        max_samples=args.limit,
        strategy=args.strategy,
        enable_rag=args.rag,
        provider=args.provider,
        model=args.model,
    )


if __name__ == "__main__":
    _main()
