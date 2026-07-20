"""数据集加载与归一化。

赛题贴合：
- "多源安全数据" → 支持不同 source 字段，统一成内部 Alert schema
- "可正常运行" → load_alerts 是后续评测、demo 的数据入口
"""

from __future__ import annotations

import json
from pathlib import Path

from app.models.schemas import Alert, AlertList

# 默认样本数据路径
DEFAULT_DATASET = Path(__file__).parent / "datasets" / "sample_alerts.json"


def load_alerts(path: str | Path | None = None) -> list[Alert]:
    """从 JSON 文件加载告警，归一化为 Alert 列表。

    支持两种 JSON 格式：
        1. {"alerts": [...]}（推荐，对齐 AlertList schema）
        2. [...]（裸数组，自动包装）

    参数：
        path: JSON 文件路径；None 则用 DEFAULT_DATASET
    """
    p = Path(path) if path else DEFAULT_DATASET
    if not p.exists():
        raise FileNotFoundError(f"Dataset not found: {p}")

    with p.open(encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and "alerts" in data:
        return AlertList.model_validate(data).alerts
    if isinstance(data, list):
        return [Alert.model_validate(item) for item in data]
    raise ValueError(
        f"Unexpected dataset format in {p}: expected dict with 'alerts' or list, "
        f"got {type(data).__name__}"
    )


def _main() -> None:
    """命令行入口：python -m app.data.loader"""
    alerts = load_alerts()
    print(f"=== 加载告警样本 ===")
    print(f"数据集: {DEFAULT_DATASET.name}")
    print(f"总数: {len(alerts)}")

    label_count: dict[str, int] = {}
    for a in alerts:
        label_count[a.label or "未标注"] = label_count.get(a.label or "未标注", 0) + 1
    print(f"标签分布: {label_count}")

    print("\n=== 前 5 条 ===")
    for a in alerts[:5]:
        print(
            f"  [{a.alert_id}] {a.timestamp:%Y-%m-%d %H:%M} "
            f"{a.source:8s} {a.severity:6s} label={a.label} | {a.rule_name}"
        )


if __name__ == "__main__":
    _main()
