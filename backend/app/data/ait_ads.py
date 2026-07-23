"""Streaming adapter from AIT-ADS JSONL files to the project Alert schema.

The public ``labels.csv`` contains attack *time windows*. It does not provide
event-level labels by itself, so generated ground truth is explicitly marked as
``time_window_weak``. Exact event labels require the related AIT-LDSv2/AIT-NDS
corpora and are intentionally not inferred from alert text or rule names here.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import hashlib
import heapq
import json
import math
import re
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from app.core.config import PROJECT_ROOT
from app.models.schemas import Alert


SCENARIOS = (
    "fox", "harrison", "russellmitchell", "santos",
    "shaw", "wardbeck", "wheeler", "wilson",
)
DETECTORS = ("wazuh", "aminer")


@dataclass(frozen=True)
class AttackWindow:
    scenario: str
    attack: str
    start: float
    end: float


@dataclass
class Candidate:
    priority: int
    alert: Alert
    truth: dict[str, Any]


CONTEXT_WINDOW_SECONDS = 300
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def load_attack_windows(labels_path: str | Path) -> dict[str, list[AttackWindow]]:
    path = Path(labels_path)
    if not path.exists():
        raise FileNotFoundError(
            f"AIT-ADS labels.csv not found: {path}. Download it from Zenodo record 8263181."
        )
    result: dict[str, list[AttackWindow]] = {}
    with path.open(encoding="utf-8-sig", newline="") as labels_file:
        for row in csv.DictReader(labels_file):
            window = AttackWindow(
                scenario=row["scenario"].strip(),
                attack=row["attack"].strip(),
                start=float(row["start"]),
                end=float(row["end"]),
            )
            result.setdefault(window.scenario, []).append(window)
    for windows in result.values():
        windows.sort(key=lambda item: item.start)
    return result


def attack_phase(timestamp: float, windows: Iterable[AttackWindow]) -> str | None:
    for window in windows:
        if window.start <= timestamp <= window.end:
            return window.attack
    return None


def _nested(data: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        value: Any = data
        for part in path.split("."):
            if not isinstance(value, dict) or part not in value:
                value = None
                break
            value = value[part]
        if value not in (None, ""):
            return value
    return None


def _as_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _severity_from_wazuh(level: Any) -> str:
    try:
        numeric = int(level)
    except (TypeError, ValueError):
        numeric = 0
    if numeric >= 12:
        return "high"
    if numeric >= 8:
        return "medium"
    if numeric >= 4:
        return "low"
    return "info"


def _is_suricata(record: dict[str, Any]) -> bool:
    groups = _nested(record, "rule.groups") or []
    location = str(record.get("location", "")).lower()
    decoder = str(_nested(record, "decoder.name") or "").lower()
    return (
        any("suricata" in str(group).lower() for group in groups)
        or "suricata" in location
        or (
            decoder == "json"
            and isinstance(record.get("data"), dict)
            and "event_type" in record["data"]
        )
    )


def _wazuh_source(record: dict[str, Any]) -> str:
    if _is_suricata(record):
        return "ids"
    location = str(record.get("location", "")).lower()
    groups = " ".join(str(item).lower() for item in (_nested(record, "rule.groups") or []))
    if any(marker in location or marker in groups for marker in ("audit", "sysmon", "process")):
        return "edr"
    return "siem"


def _stable_alert_id(scenario: str, detector: str, raw_line: str) -> str:
    digest = hashlib.sha256(raw_line.encode("utf-8")).hexdigest()
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"ait-ads:{scenario}:{detector}:{digest}"))


def _observable_ips(text: str) -> list[str]:
    """Extract valid IPv4 observables when a detector did not normalize them."""
    result: list[str] = []
    for value in _IPV4.findall(text):
        if all(0 <= int(part) <= 255 for part in value.split(".")) and value not in result:
            result.append(value)
    return result


def _convert_wazuh(record: dict[str, Any], scenario: str, raw_line: str) -> tuple[Alert, float]:
    timestamp_text = str(record.get("@timestamp") or _nested(record, "data.timestamp") or "")
    parsed_time = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
    timestamp = parsed_time.astimezone(timezone.utc)
    source = _wazuh_source(record)
    vendor = "suricata" if source == "ids" else "wazuh"
    rule_description = str(_nested(record, "rule.description") or "Unspecified detector alert")
    full_log = str(record.get("full_log") or _nested(record, "data.alert.signature") or rule_description)
    raw_payload = {
        "dataset": "AIT-ADS",
        "detector": vendor,
        "rule_id": str(_nested(record, "rule.id") or ""),
        "rule_level": _nested(record, "rule.level"),
        "rule_groups": list(_nested(record, "rule.groups") or []),
        "location": record.get("location"),
        "agent": record.get("agent", {}),
        "event": full_log[:4000],
        "vendor_data": record.get("data", {}),
    }
    src_ip = _nested(record, "data.src_ip", "data.source.ip")
    dst_ip = _nested(record, "data.dest_ip", "data.dst_ip", "data.destination.ip")
    # AIT-ADS 中部分 Apache/Suricata 告警只在 full_log 保留 IP，结构化字段为空。
    # 这里只提取可观测量，不依据标签或攻击时间窗推断方向。
    observed_ips = _observable_ips(full_log)
    if src_ip is None and observed_ips:
        src_ip = observed_ips[0]
    if dst_ip is None and source == "ids" and len(observed_ips) > 1:
        dst_ip = observed_ips[-1]
    raw_payload["observable_ips"] = observed_ips
    alert = Alert(
        alert_id=_stable_alert_id(scenario, "wazuh", raw_line),
        timestamp=timestamp,
        source=source,  # type: ignore[arg-type]
        severity=_severity_from_wazuh(_nested(record, "rule.level")),  # type: ignore[arg-type]
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=_as_port(_nested(record, "data.src_port", "data.source.port")),
        dst_port=_as_port(_nested(record, "data.dest_port", "data.dst_port", "data.destination.port")),
        protocol=_nested(record, "data.proto", "data.protocol"),
        rule_name=f"{vendor.title()}: {rule_description}",
        description=full_log[:4000],
        raw_payload=raw_payload,
    )
    return alert, timestamp.timestamp()


def _convert_aminer(record: dict[str, Any], scenario: str, raw_line: str) -> tuple[Alert, float]:
    timestamps = _nested(record, "LogData.DetectionTimestamp") or _nested(record, "LogData.Timestamps")
    if not isinstance(timestamps, list) or not timestamps:
        raise ValueError("AMiner alert has no detection timestamp")
    epoch = float(timestamps[-1])
    component_name = str(_nested(record, "AnalysisComponent.AnalysisComponentName") or "AMiner anomaly")
    message = str(_nested(record, "AnalysisComponent.Message") or "Anomalous log event")
    raw_logs = _nested(record, "LogData.RawLogData") or []
    raw_log = str(raw_logs[0]) if isinstance(raw_logs, list) and raw_logs else message
    host_ip = _nested(record, "AMiner.ID")
    raw_payload = {
        "dataset": "AIT-ADS",
        "detector": "aminer",
        "component_type": _nested(record, "AnalysisComponent.AnalysisComponentType"),
        "component_message": message,
        "training_mode": _nested(record, "AnalysisComponent.TrainingMode"),
        "log_resources": _nested(record, "LogData.LogResources") or [],
        "host_ip": host_ip,
        "event": raw_log[:4000],
    }
    alert = Alert(
        alert_id=_stable_alert_id(scenario, "aminer", raw_line),
        timestamp=datetime.fromtimestamp(epoch, tz=timezone.utc),
        source="siem",
        severity="medium",
        src_ip=host_ip,
        rule_name=component_name,
        description=f"{message}: {raw_log}"[:4000],
        raw_payload=raw_payload,
    )
    return alert, epoch


def convert_record(
    record: dict[str, Any], scenario: str, detector: str, raw_line: str
) -> tuple[Alert, float]:
    if detector == "wazuh":
        return _convert_wazuh(record, scenario, raw_line)
    if detector == "aminer":
        return _convert_aminer(record, scenario, raw_line)
    raise ValueError(f"Unsupported detector: {detector}")


def _priority(seed: int, alert_id: str) -> int:
    digest = hashlib.sha256(f"{seed}:{alert_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def _push_candidate(
    reservoirs: dict[tuple[str, ...], list[tuple[int, str, Candidate]]],
    key: tuple[str, ...],
    candidate: Candidate,
    capacity: int,
) -> None:
    heap = reservoirs.setdefault(key, [])
    item = (-candidate.priority, candidate.alert.alert_id, candidate)
    if any(existing[1] == candidate.alert.alert_id for existing in heap):
        return
    if len(heap) < capacity:
        heapq.heappush(heap, item)
    elif item > heap[0]:
        heapq.heapreplace(heap, item)


def _round_robin_select(
    reservoirs: dict[tuple[str, ...], list[tuple[int, str, Candidate]]],
    label: str,
    count: int,
) -> list[Candidate]:
    groups: list[list[Candidate]] = []
    for key in sorted(reservoirs):
        if key[0] != label:
            continue
        candidates = [item[2] for item in reservoirs[key]]
        groups.append(sorted(candidates, key=lambda item: item.priority))
    selected: list[Candidate] = []
    offset = 0
    while len(selected) < count:
        added = False
        for group in groups:
            if offset < len(group):
                selected.append(group[offset])
                added = True
                if len(selected) == count:
                    break
        if not added:
            break
        offset += 1
    return selected


def _add_temporal_context(
    selected: list[Candidate],
    source: Path,
    *,
    window_seconds: int = CONTEXT_WINDOW_SECONDS,
) -> None:
    """Attach label-free local event statistics to every selected alert.

    AIT-ADS ground truth describes attack time windows.  A single event (for
    example one HTTP 404) is often not distinguishable from normal traffic, so
    alert triage must retain nearby detector activity.  This second streaming
    pass only aggregates observable events; it never reads ``truth`` or attack
    windows and therefore does not leak the answer into Agent input.
    """
    grouped: dict[tuple[str, str], list[Candidate]] = {}
    for candidate in selected:
        key = (str(candidate.truth["scenario"]), str(candidate.truth["detector_file"]))
        grouped.setdefault(key, []).append(candidate)

    for (scenario, detector), targets in grouped.items():
        targets.sort(key=lambda item: item.alert.timestamp.timestamp())
        target_epochs = [item.alert.timestamp.timestamp() for item in targets]
        accumulators: dict[str, dict[str, Any]] = {
            item.alert.alert_id: {
                "event_count": 0,
                "same_rule_count": 0,
                "same_src_ip_count": 0,
                "same_dst_ip_count": 0,
                "rule_counts": Counter(),
                "source_ip_counts": Counter(),
                "nearby_examples": [],
            }
            for item in targets
        }
        input_path = source / f"{scenario}_{detector}.json"
        with input_path.open(encoding="utf-8") as input_file:
            for raw_line in input_file:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    record = json.loads(raw_line)
                    nearby, epoch = convert_record(record, scenario, detector, raw_line)
                except (json.JSONDecodeError, TypeError, ValueError, OverflowError):
                    continue
                left = bisect.bisect_left(target_epochs, epoch - window_seconds)
                right = bisect.bisect_right(target_epochs, epoch + window_seconds)
                if left == right:
                    continue
                for index in range(left, right):
                    target = targets[index]
                    bucket = accumulators[target.alert.alert_id]
                    bucket["event_count"] += 1
                    bucket["rule_counts"][nearby.rule_name] += 1
                    if nearby.rule_name == target.alert.rule_name:
                        bucket["same_rule_count"] += 1
                    if nearby.src_ip:
                        bucket["source_ip_counts"][nearby.src_ip] += 1
                    if target.alert.src_ip and nearby.src_ip == target.alert.src_ip:
                        bucket["same_src_ip_count"] += 1
                    if target.alert.dst_ip and nearby.dst_ip == target.alert.dst_ip:
                        bucket["same_dst_ip_count"] += 1
                    examples = bucket["nearby_examples"]
                    if nearby.alert_id != target.alert.alert_id and len(examples) < 5:
                        examples.append(
                            {
                                "offset_seconds": round(epoch - target_epochs[index], 3),
                                "rule_name": nearby.rule_name,
                                "src_ip": nearby.src_ip,
                                "dst_ip": nearby.dst_ip,
                                "description": nearby.description[:300],
                            }
                        )

        for target in targets:
            bucket = accumulators[target.alert.alert_id]
            target.alert.raw_payload["temporal_context"] = {
                "window_seconds_before_after": window_seconds,
                "detector_event_count": bucket["event_count"],
                "same_rule_count": bucket["same_rule_count"],
                "same_src_ip_count": bucket["same_src_ip_count"],
                "same_dst_ip_count": bucket["same_dst_ip_count"],
                "top_rules": [
                    {"rule_name": name, "count": count}
                    for name, count in bucket["rule_counts"].most_common(8)
                ],
                "top_source_ips": [
                    {"src_ip": value, "count": count}
                    for value, count in bucket["source_ip_counts"].most_common(8)
                ],
                "nearby_examples": bucket["nearby_examples"],
                "note": "Counts come from raw detector events around this alert; no ground-truth label was used.",
            }


def build_dataset(
    source_dir: str | Path,
    labels_path: str | Path,
    output_path: str | Path,
    *,
    per_class: int = 200,
    seed: int = 20260721,
    scenarios: Iterable[str] = SCENARIOS,
    detectors: Iterable[str] = DETECTORS,
) -> dict[str, Any]:
    """Stream raw JSONL files and write a balanced, reproducible pilot set."""
    if per_class < 1:
        raise ValueError("per_class must be at least 1")
    source = Path(source_dir)
    output = Path(output_path)
    windows_by_scenario = load_attack_windows(labels_path)
    selected_scenarios = tuple(dict.fromkeys(scenarios))
    selected_detectors = tuple(dict.fromkeys(detectors))
    unknown_scenarios = set(selected_scenarios) - set(windows_by_scenario)
    if unknown_scenarios:
        raise ValueError(f"Scenarios missing from labels.csv: {sorted(unknown_scenarios)}")

    positive_strata = max(
        1,
        sum(len(windows_by_scenario[item]) for item in selected_scenarios)
        * len(selected_detectors),
    )
    negative_strata = max(1, len(selected_scenarios) * len(selected_detectors))
    positive_capacity = max(4, math.ceil(per_class / positive_strata) * 3)
    negative_capacity = max(8, math.ceil(per_class / negative_strata) * 3)
    reservoirs: dict[tuple[str, ...], list[tuple[int, str, Candidate]]] = {}
    scanned = converted = skipped = 0

    for scenario in selected_scenarios:
        for detector in selected_detectors:
            input_path = source / f"{scenario}_{detector}.json"
            if not input_path.exists():
                raise FileNotFoundError(f"AIT-ADS source file not found: {input_path}")
            with input_path.open(encoding="utf-8") as input_file:
                for raw_line in input_file:
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    scanned += 1
                    try:
                        record = json.loads(raw_line)
                        alert, epoch = convert_record(record, scenario, detector, raw_line)
                    except (json.JSONDecodeError, TypeError, ValueError, OverflowError):
                        skipped += 1
                        continue
                    phase = attack_phase(epoch, windows_by_scenario[scenario])
                    label = "真阳" if phase else "假阳"
                    truth = {
                        "label": label,
                        "scenario": scenario,
                        "attack_phase": phase,
                        "detector_file": detector,
                        "label_basis": "time_window_weak",
                    }
                    candidate = Candidate(_priority(seed, alert.alert_id), alert, truth)
                    if phase:
                        key = (label, scenario, detector, phase)
                        capacity = positive_capacity
                    else:
                        key = (label, scenario, detector)
                        capacity = negative_capacity
                    _push_candidate(reservoirs, key, candidate, capacity)
                    converted += 1

    positives = _round_robin_select(reservoirs, "真阳", per_class)
    negatives = _round_robin_select(reservoirs, "假阳", per_class)
    if len(positives) < per_class or len(negatives) < per_class:
        raise ValueError(
            f"Insufficient samples: positives={len(positives)}, negatives={len(negatives)}"
        )
    selected = sorted(positives + negatives, key=lambda item: item.priority)
    _add_temporal_context(selected, source)
    alerts = [item.alert.model_dump(mode="json", exclude={"label"}) for item in selected]
    ground_truth = {item.alert.alert_id: item.truth for item in selected}
    document = {
        "metadata": {
            "name": "AIT-ADS pilot evaluation set",
            "source": "https://zenodo.org/records/8263181",
            "doi": "10.5281/zenodo.8263181",
            "license": "CC-BY-4.0",
            "label_storage": "separated",
            "label_basis": "time_window_weak",
            "label_warning": (
                "labels.csv marks attack time windows, not exact event causality; "
                "event-level truth requires AIT-LDSv2/AIT-NDS."
            ),
            "context_window_seconds": CONTEXT_WINDOW_SECONDS,
            "context_basis": "label_free_raw_detector_neighborhood",
            "seed": seed,
            "requested_per_class": per_class,
            "scenarios": list(selected_scenarios),
            "detectors": list(selected_detectors),
            "scanned_records": scanned,
            "converted_records": converted,
            "skipped_records": skipped,
        },
        "alerts": alerts,
        "ground_truth": ground_truth,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "output": str(output.resolve()),
        "samples": len(selected),
        "true_positive": len(positives),
        "false_positive": len(negatives),
        "scanned_records": scanned,
        "skipped_records": skipped,
    }


def _main() -> None:
    parser = argparse.ArgumentParser(description="Build a leakage-safe AIT-ADS pilot dataset")
    parser.add_argument(
        "--source", required=True,
        help="Directory containing *_wazuh.json and *_aminer.json",
    )
    parser.add_argument("--labels", required=True, help="Official AIT-ADS labels.csv")
    parser.add_argument(
        "--output",
        default=str(PROJECT_ROOT / "data" / "processed" / "ait_ads_eval.json"),
        help="Output evaluation JSON (default: data/processed/ait_ads_eval.json)",
    )
    parser.add_argument("--per-class", type=int, default=200, help="Samples per class")
    parser.add_argument("--seed", type=int, default=20260721)
    parser.add_argument("--scenarios", nargs="+", choices=SCENARIOS, default=list(SCENARIOS))
    parser.add_argument("--detectors", nargs="+", choices=DETECTORS, default=list(DETECTORS))
    args = parser.parse_args()
    summary = build_dataset(
        args.source,
        args.labels,
        args.output,
        per_class=args.per_class,
        seed=args.seed,
        scenarios=args.scenarios,
        detectors=args.detectors,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    _main()
