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
import time
from pathlib import Path
from typing import Callable

from app.agent.graph import judge_alert
from app.core.logging import get_logger, setup_logging
from app.data.loader import DEFAULT_DATASET, load_alerts
from app.eval.metrics import compute_metrics, format_report
from app.models.llm import get_llm

logger = get_logger(__name__)

EVAL_DATASET = DEFAULT_DATASET.parent / "eval_alerts.json"


def run_eval(
    dataset_path: str | Path | None = None,
    mock: bool = False,
    save_results: bool = True,
    progress_callback: Callable[[dict], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> dict:
    """跑评测，返回 metrics dict + 明细。

    参数：
        dataset_path: 数据集 JSON 路径；None 则用 eval_alerts.json（不存在则回退 sample）
        mock: True 用 mock LLM；False 用真实 DeepSeek
        save_results: 是否把明细存到 data/eval_results.json
        progress_callback: 每完成一条样本后回调，供 SSE 实时推送
        should_stop: 返回 True 时在下一条样本前安全停止
    """
    setup_logging(level="INFO")

    # 选数据集
    if dataset_path:
        path = Path(dataset_path)
    elif EVAL_DATASET.exists():
        path = EVAL_DATASET
    else:
        path = DEFAULT_DATASET
    logger.info("eval dataset: %s", path)

    alerts = load_alerts(path)
    labeled = [a for a in alerts if a.label in {"真阳", "假阳"}]
    if len(labeled) < len(alerts):
        logger.warning(
            "跳过 %d 条无标签样本", len(alerts) - len(labeled)
        )
    logger.info("labeled samples: %d", len(labeled))

    llm = get_llm(mock=mock)
    mode = "mock" if mock else "deepseek"
    logger.info("LLM mode: %s", mode)

    predictions: list[tuple[str, str]] = []
    latencies: list[float] = []
    details: list[dict] = []

    for i, alert in enumerate(labeled, 1):
        if should_stop and should_stop():
            logger.warning("评测收到停止请求，已完成 %d/%d 条", len(details), len(labeled))
            break

        alert_dict = alert.model_dump(mode="json")
        # 隐藏 label，避免泄露给 Agent
        alert_dict.pop("label", None)

        t0 = time.perf_counter()
        agent_result: dict | None = None
        try:
            agent_result = judge_alert(alert_dict, llm=llm)
            pred = agent_result["judgment"]
            conf = agent_result["confidence"]
            reason = agent_result["reason"]
        except Exception as e:
            # 双重兜底：即使 judge_node 的兜底也崩了，整轮评测仍继续
            logger.exception("[%d] 异常跳过 %s: %s", i, alert.alert_id, e)
            pred = "待查"
            conf = 0.0
            reason = f"eval 异常: {e}"
        latency = time.perf_counter() - t0
        predictions.append((alert.label, pred))  # type: ignore[arg-type]
        latencies.append(latency)
        detail = {
            "alert_id": alert.alert_id,
            "label": alert.label,
            "pred": pred,
            "confidence": conf,
            "latency_s": round(latency, 3),
            "correct": pred == alert.label,
            "reason": reason,
            # 保留本次已经生成的完整流程，前端点开即可查看，不重复调用模型。
            "alert": alert_dict,
            "agent_result": agent_result,
        }
        details.append(detail)
        mark = "✓" if pred == alert.label else "✗"
        logger.info(
            "[%d/%d] %s %s label=%s pred=%s conf=%.2f %.2fs",
            i, len(labeled), mark, alert.alert_id,
            alert.label, pred, conf, latency,
        )

        if progress_callback:
            progress_callback(
                {
                    "completed": len(details),
                    "total": len(labeled),
                    "detail": detail,
                    "metrics": compute_metrics(predictions, latencies).as_dict(),
                }
            )

    metrics = compute_metrics(predictions, latencies)
    report = format_report(metrics)
    print("\n" + report)

    output = {
        "mode": mode,
        "dataset": str(path),
        "metrics": metrics.as_dict(),
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
    args = parser.parse_args()
    run_eval(
        dataset_path=args.dataset,
        mock=args.mock,
        save_results=not args.no_save,
    )


if __name__ == "__main__":
    _main()
