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
    abstain_positive: int = 0  # 真实真阳→待查
    abstain_negative: int = 0  # 真实假阳→待查

    def total(self) -> int:
        # fn 已包含真实真阳→待查；真实假阳→待查需要单独补入。
        return self.tp + self.fp + self.fn + self.tn + self.abstain_negative


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
    coverage: float = 0.0    # 给出真阳/假阳明确结论的比例
    selective_accuracy: float = 0.0  # 仅在已明确判定样本上的准确率
    macro_f1: float = 0.0     # 真阳/假阳两类 F1 的宏平均，待查会降低对应类别召回
    negative_f1: float = 0.0  # 以假阳为目标类别计算的 F1
    llm_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0

    def as_dict(self) -> dict:
        return {
            "n": self.n,
            "confusion_matrix": {
                "tp": self.cm.tp, "fp": self.cm.fp,
                "fn": self.cm.fn, "tn": self.cm.tn,
                "explicit_fn": self.cm.fn - self.cm.abstain_positive,
                "abstain_positive": self.cm.abstain_positive,
                "abstain_negative": self.cm.abstain_negative,
            },
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "avg_latency_s": round(self.avg_latency_s, 3),
            "unknown_count": self.unknown_count,
            "coverage": round(self.coverage, 4),
            "selective_accuracy": round(self.selective_accuracy, 4),
            "macro_f1": round(self.macro_f1, 4),
            "negative_f1": round(self.negative_f1, 4),
            "llm_calls": self.llm_calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "avg_llm_calls_per_sample": round(self.llm_calls / self.n, 3) if self.n else 0.0,
            "avg_tokens_per_sample": round(self.total_tokens / self.n, 1) if self.n else 0.0,
        }


def compute_metrics(
    predictions: list[tuple[str, str]],
    latencies: list[float] | None = None,
    *,
    llm_calls: int = 0,
    token_usage: dict[str, int] | None = None,
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
                cm.abstain_positive += 1
                cm.fn += 1   # 真阳没认出来 → 漏报
            else:
                cm.abstain_negative += 1

    total = len(predictions)
    decided = total - unknown
    accuracy = (cm.tp + cm.tn) / total if total else 0.0
    precision = cm.tp / (cm.tp + cm.fp) if (cm.tp + cm.fp) else 0.0
    recall = cm.tp / (cm.tp + cm.fn) if (cm.tp + cm.fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    # 以“假阳”为目标类别再计算一次。fn 中包含真阳弃权，不能把它误当成
    # “预测为假阳”，因此先扣除 abstain_positive。
    explicit_false_negative = cm.fn - cm.abstain_positive
    negative_precision = cm.tn / (cm.tn + explicit_false_negative) if (cm.tn + explicit_false_negative) else 0.0
    negative_recall = cm.tn / (cm.tn + cm.fp + cm.abstain_negative) if (cm.tn + cm.fp + cm.abstain_negative) else 0.0
    negative_f1 = (
        2 * negative_precision * negative_recall / (negative_precision + negative_recall)
        if (negative_precision + negative_recall) else 0.0
    )
    macro_f1 = (f1 + negative_f1) / 2
    avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
    coverage = decided / total if total else 0.0
    selective_accuracy = (cm.tp + cm.tn) / decided if decided else 0.0

    return EvalMetrics(
        n=total,
        cm=cm,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1=f1,
        avg_latency_s=avg_lat,
        unknown_count=unknown,
        coverage=coverage,
        selective_accuracy=selective_accuracy,
        macro_f1=macro_f1,
        negative_f1=negative_f1,
        llm_calls=llm_calls,
        input_tokens=int((token_usage or {}).get("input_tokens", 0)),
        output_tokens=int((token_usage or {}).get("output_tokens", 0)),
        total_tokens=int((token_usage or {}).get("total_tokens", 0)),
    )


def format_report(m: EvalMetrics) -> str:
    """格式化为可读的评测报告字符串。"""
    unknown_pct = m.unknown_count / m.n * 100 if m.n else 0.0
    return (
        "=== 评测结果 ===\n"
        f"样本数: {m.n}\n"
        f"已决混淆: TP={m.cm.tp} FP={m.cm.fp} "
        f"FN(真阳→假阳)={m.cm.fn - m.cm.abstain_positive} TN={m.cm.tn}\n"
        f"待查拆分: 真实真阳={m.cm.abstain_positive} "
        f"真实假阳={m.cm.abstain_negative} "
        f"(召回率中的 FN 总数={m.cm.fn})\n"
        f"准确率 (accuracy): {m.accuracy:.4f}\n"
        f"精确率 (precision): {m.precision:.4f}   ← 预测真阳里的真阳比例\n"
        f"召回率 (recall):    {m.recall:.4f}   ← 真实真阳被找回的比例\n"
        f"F1 分数:            {m.f1:.4f}\n"
        f"Macro-F1:           {m.macro_f1:.4f}\n"
        f"平均延迟: {m.avg_latency_s:.3f}s\n"
        f"待查数: {m.unknown_count} (占 {unknown_pct:.1f}%)\n"
        f"覆盖率: {m.coverage:.4f}\n"
        f"已决样本准确率: {m.selective_accuracy:.4f}\n"
        f"LLM 调用: {m.llm_calls}, Token: {m.total_tokens} "
        f"(输入 {m.input_tokens} / 输出 {m.output_tokens})"
    )
