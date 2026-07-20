"""数据大屏统计 + 评测接口。

stats 接口聚合数据集统计（给首页大屏用）；
eval 接口复用 run.py 逻辑给评测页用。
"""

from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.data.generator import EVAL_DATASET
from app.data.loader import DEFAULT_DATASET, load_alerts

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["stats"])


@router.get("/stats")
def get_stats() -> dict:
    """数据大屏统计接口。

    返回数据集的聚合统计：
        - total / by_label (真阳/假阳/待查)
        - by_source (edr/ids/waf/siem/ndr)
        - by_severity (high/medium/low/info)
        - attack_types (从 raw_payload.attck 聚合)
    """
    # 优先用 eval 数据集（50 条），不存在则用 sample（10 条）
    path = EVAL_DATASET if EVAL_DATASET.exists() else DEFAULT_DATASET
    try:
        alerts = load_alerts(path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"load dataset failed: {e}")

    by_label = Counter(a.label or "未标注" for a in alerts)
    by_source = Counter(a.source for a in alerts)
    by_severity = Counter(a.severity for a in alerts)

    # ATT&CK 战术聚合（从 raw_payload.attck 抽取）
    attack_types: list[dict] = []
    attck_counter: Counter = Counter()
    for a in alerts:
        attck = (a.raw_payload or {}).get("attck", [])
        if isinstance(attck, list):
            for tid in attck:
                attck_counter[tid] += 1
    # 把出现频次最高的战术排前面
    attack_types = [{"id": tid, "count": cnt} for tid, cnt in attck_counter.most_common(15)]

    return {
        "dataset": str(path.name),
        "total": len(alerts),
        "by_label": dict(by_label),
        "by_source": dict(by_source),
        "by_severity": dict(by_severity),
        "attack_types": attack_types,
    }


@router.get("/samples")
def list_samples() -> dict:
    """返回示例告警列表（给前端"加载示例"用）。

    从 sample_alerts.json 取前 8 条（覆盖不同类型），去掉 label。
    """
    alerts = load_alerts(DEFAULT_DATASET)
    samples = []
    for a in alerts[:8]:
        d = a.model_dump(mode="json")
        d.pop("label", None)
        samples.append(d)
    return {"samples": samples, "count": len(samples)}


@router.post("/eval/run")
def run_eval_endpoint(mock: bool = True) -> dict:
    """触发评测（给评测页用）。

    默认 mock=True（不耗 token，验证链路）。
    真实评测需要前端显式传 mock=false（会产生 token 费用）。
    """
    # 延迟导入，避免 main.py 启动时拉起整个评测模块
    from app.eval.run import run_eval

    try:
        result = run_eval(dataset_path=None, mock=mock, save_results=False)
        return result
    except Exception as e:
        logger.exception("eval run failed: %s", e)
        raise HTTPException(status_code=500, detail=f"eval failed: {e}")
