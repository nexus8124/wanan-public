"""评测指标计算。

赛题贴合：评分明确说"根据准确性评定"——必须有量化数字。
方案 B6 节要求指标：准确率 / 精确率 / 召回率 / 平均延迟 / token 成本。

判定问题建模为二分类（"真阳" vs "假阳"），"待查"按预测错误计：
  - "真阳" 是正类（Positive）
  - TP：真实真阳 且 预测真阳
  - FP：真实假阳 但 预测真阳（误报了，把好的说成坏的）
  - FN：真实真阳 但 预测假阳/待查（漏报）
  - TN：真实假阳 且 预测假阳
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ConfusionMatrix:
    tp: int = 0  # 真阳→真阳
    fp: int = 0  # 假阳→真阳
    fn: int = 0  # 真阳→其他（漏报）
    tn: int = 0  # 假阳→假阳

    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn


@dataclass
class EvalMetrics:
    """一次评测的全部指标。"""

    n: int
    cm: ConfusionMatrix
    accuracy: float          # (TP+TN)/total
    precision: float         # TP/(TP+FP)  预测真阳里的真阳比例
    recall: float            # TP/(TP+FN)  真实真阳被找出来的比例
    f1: float                # 2*P*R/(P+R)
    avg_latency_s: float     # 平均延迟
    unknown_count: int = 0   # 预测为"待查"的数量

    def as_dict(self) -> dict:
        return {
            "n": self.n,
            "confusion_matrix": {
                "tp": self.cm.tp, "fp": self.cm.fp,
                "fn": self.cm.fn, "tn": self.cm.tn,
            },
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "avg_latency_s": round(self.avg_latency_s, 3),
            "unknown_count": self.unknown_count,
        }


def compute_metrics(
    predictions: list[tuple[str, str]],
    latencies: list[float] | None = None,
) -> EvalMetrics:
    """从 (label, pred) 列表计算指标。

    参数：
        predictions: [(真实标签, 预测标签), ...]，标签为 "真阳"/"假阳"/"待查"
        latencies: 每条的延迟（秒），可选
    """
    cm = ConfusionMatrix()
    unknown = 0
    for label, pred in predictions:
        is_label_tp = label == "真阳"
        if pred == "真阳":
            if is_label_tp:
                cm.tp += 1
            else:
                cm.fp += 1
        elif pred == "假阳":
            if is_label_tp:
                cm.fn += 1
            else:
                cm.tn += 1
        else:  # 待查 / 其他
            unknown += 1
            if is_label_tp:
                cm.fn += 1   # 真阳没认出来 → 漏报
            else:
                cm.tn += 1   # 假阳没误报 → 算正确拒绝

    total = cm.total()
    accuracy = (cm.tp + cm.tn) / total if total else 0.0
    precision = cm.tp / (cm.tp + cm.fp) if (cm.tp + cm.fp) else 0.0
    recall = cm.tp / (cm.tp + cm.fn) if (cm.tp + cm.fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    avg_lat = sum(latencies) / len(latencies) if latencies else 0.0

    return EvalMetrics(
        n=total,
        cm=cm,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1=f1,
        avg_latency_s=avg_lat,
        unknown_count=unknown,
    )


def format_report(m: EvalMetrics) -> str:
    """格式化为可读的评测报告字符串。"""
    return (
        "=== 评测结果 ===\n"
        f"样本数: {m.n}\n"
        f"混淆矩阵: TP={m.cm.tp} FP={m.cm.fp} FN={m.cm.fn} TN={m.cm.tn}\n"
        f"准确率 (accuracy): {m.accuracy:.4f}\n"
        f"精确率 (precision): {m.precision:.4f}   ← 预测真阳里的真阳比例\n"
        f"召回率 (recall):    {m.recall:.4f}   ← 真实真阳被找回的比例\n"
        f"F1 分数:            {m.f1:.4f}\n"
        f"平均延迟: {m.avg_latency_s:.3f}s\n"
        f"待查数: {m.unknown_count} (占 {m.unknown_count/m.n*100:.1f}%)"
    )
