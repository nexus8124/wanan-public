"""Build the formal AIT-ADS event/time-consistent evaluation suite.

The official AIT ``alert-data-set`` repository publishes one compact alert
table per scenario.  Each row has both the original attack-window label and an
event label reconstructed from AIT-LDSv2/AIT-NDS.  This module treats a row as
gold only when both independent label sources agree on the binary class:

* positive: attack time window AND a non-empty event label;
* negative: false-positive time window AND no event label;
* every other combination is excluded and reported as a conflict.

The evaluation unit is a one-minute deduplicated case, not an alert burst.
Ground truth is stored separately from Agent-visible alerts.  Label-free
neighbourhood evidence is written to an out-of-band store so tools can query
real Wazuh, AMiner, and Suricata observations without seeing the answer.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import heapq
import json
import re
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_EVIDENCE_ROOT = PROJECT_ROOT / "data" / "processed" / "ait_ads_event_evidence"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "data" / "processed" / "ait_ads_event_gold"
EVENT_LABEL_REVISION = "ce927ddaeaa674f6909e1de676fa7dc293e393bd"
EVENT_LABEL_SHA256 = "2bf1a81527a3fe15d92079a7834c9d77c5305546e15569657d2097d6294825c3"
CONTEXT_WINDOW_SECONDS = 300
CASE_BUCKET_SECONDS = 60
_SAFE_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}")


SPLIT_SPECS: dict[str, dict[str, Any]] = {
    "development": {
        "scenarios": ("fox", "shaw", "wardbeck"),
        "per_class": 300,
        "frozen": False,
    },
    "validation": {
        "scenarios": ("santos", "wheeler"),
        "per_class": 100,
        "frozen": False,
    },
    "test_frozen": {
        "scenarios": ("harrison", "russellmitchell", "wilson"),
        "per_class": 500,
        "frozen": True,
    },
}


@dataclass(frozen=True)
class OfficialAlertRow:
    scenario: str
    ordinal: int
    epoch: int
    name: str
    ip: str
    host: str
    short: str
    time_label: str
    event_label: str

    @property
    def detector(self) -> str:
        prefix = self.name.split(":", 1)[0].strip().lower()
        return prefix if prefix in {"wazuh", "suricata", "aminer"} else "unknown"

    @property
    def binary_label(self) -> str | None:
        time_positive = self.time_label != "false_positive"
        event_positive = self.event_label not in {"", "-", "false_positive"}
        if time_positive and event_positive:
            return "真阳"
        if not time_positive and not event_positive:
            return "假阳"
        return None


@dataclass(frozen=True)
class Candidate:
    row: OfficialAlertRow
    alert_id: str
    case_digest: str
    priority: int
    label: str
    split: str


def parse_official_row(line: str, scenario: str, ordinal: int) -> OfficialAlertRow:
    """Parse the official comma-containing format from the right.

    It is not a valid conventional CSV because detector descriptions can
    contain unquoted commas.  The final five fields are stable; the remaining
    prefix is split once into time and name.
    """
    prefix, ip, host, short, time_label, event_label = line.rstrip("\r\n").rsplit(",", 5)
    epoch_text, name = prefix.split(",", 1)
    return OfficialAlertRow(
        scenario=scenario,
        ordinal=ordinal,
        epoch=int(float(epoch_text)),
        name=name.strip(),
        ip=ip.strip(),
        host=host.strip(),
        short=short.strip(),
        time_label=time_label.strip(),
        event_label=event_label.strip(),
    )


def _labels_dir(path: str | Path) -> Path:
    root = Path(path)
    nested = root / "alerts_csv"
    if nested.is_dir():
        return nested
    return root


def iter_scenario_rows(labels_dir: str | Path, scenario: str) -> Iterator[OfficialAlertRow]:
    path = _labels_dir(labels_dir) / f"{scenario}_alerts.txt"
    if not path.is_file():
        raise FileNotFoundError(f"official event-label file not found: {path}")
    with path.open(encoding="utf-8", errors="replace") as stream:
        header = next(stream, "").strip()
        if header != "time,name,ip,host,short,time_label,event_label":
            raise ValueError(f"unexpected official label header in {path}: {header!r}")
        for ordinal, line in enumerate(stream, start=1):
            if line.strip():
                yield parse_official_row(line, scenario, ordinal)


def _case_key(row: OfficialAlertRow) -> str:
    bucket = row.epoch // CASE_BUCKET_SECONDS
    return "\x1f".join(
        (row.scenario, row.detector, row.name, row.host, row.ip, str(bucket))
    )


def _case_identity(row: OfficialAlertRow) -> tuple[str, str]:
    key = _case_key(row)
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    alert_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"ait-ads-event-case:{digest}"))
    return alert_id, digest


def _priority(seed: int, alert_id: str) -> int:
    value = hashlib.sha256(f"{seed}:{alert_id}".encode("utf-8")).digest()
    return int.from_bytes(value[:8], "big")


def _split_for_scenario(scenario: str) -> str:
    for split, spec in SPLIT_SPECS.items():
        if scenario in spec["scenarios"]:
            return split
    raise ValueError(f"scenario is not assigned to a split: {scenario}")


def _stratum(row: OfficialAlertRow, label: str) -> tuple[str, ...]:
    if label == "真阳":
        return (row.scenario, row.detector, row.event_label)
    return (row.scenario, row.detector, row.short or row.name)


def _push(
    reservoirs: dict[tuple[str, str, tuple[str, ...]], list[tuple[int, str, Candidate]]],
    candidate: Candidate,
    *,
    capacity: int,
) -> None:
    key = (candidate.split, candidate.label, _stratum(candidate.row, candidate.label))
    heap = reservoirs.setdefault(key, [])
    item = (-candidate.priority, candidate.alert_id, candidate)
    if len(heap) < capacity:
        heapq.heappush(heap, item)
    elif item > heap[0]:
        heapq.heapreplace(heap, item)


def _round_robin(
    reservoirs: dict[tuple[str, str, tuple[str, ...]], list[tuple[int, str, Candidate]]],
    split: str,
    label: str,
    count: int,
    *,
    family_cap: int | None = None,
) -> list[Candidate]:
    groups: list[list[Candidate]] = []
    for key in sorted(reservoirs, key=lambda item: (item[0], item[1], item[2])):
        if key[0] != split or key[1] != label:
            continue
        groups.append(sorted((item[2] for item in reservoirs[key]), key=lambda item: item.priority))
    result: list[Candidate] = []
    family_counts: Counter[str] = Counter()
    offset = 0
    while len(result) < count:
        added = False
        for group in groups:
            if offset < len(group):
                candidate = group[offset]
                family = candidate.row.event_label if label == "真阳" else candidate.row.short
                if family_cap is not None and family_counts[family] >= family_cap:
                    continue
                result.append(candidate)
                family_counts[family] += 1
                added = True
                if len(result) == count:
                    break
        if not added:
            break
        offset += 1
    return result


def _source_for(row: OfficialAlertRow) -> str:
    if row.detector == "suricata":
        return "ids"
    host_markers = (
        "audit", "auth", "login", "user", "sudo", "service", "clamav", "file",
        "process", "apparmor", "system",
    )
    text = f"{row.name} {row.short}".lower()
    return "edr" if any(marker in text for marker in host_markers) else "siem"


def _public_event(row: OfficialAlertRow) -> dict[str, Any]:
    return {
        "timestamp": datetime.fromtimestamp(row.epoch, tz=timezone.utc).isoformat(),
        "detector": row.detector,
        "source": _source_for(row),
        "rule_name": row.name,
        "rule_short": row.short,
        "sensor_ip": row.ip,
        "sensor_host": row.host,
    }


def _bucket_key(epoch: int) -> int:
    return epoch // 60


def _collect_context(
    labels_dir: Path,
    selected: list[Candidate],
) -> dict[str, dict[str, Any]]:
    by_scenario: dict[str, list[Candidate]] = {}
    for candidate in selected:
        by_scenario.setdefault(candidate.row.scenario, []).append(candidate)
    result: dict[str, dict[str, Any]] = {}
    radius = CONTEXT_WINDOW_SECONDS // 60

    for scenario, targets in by_scenario.items():
        needed_minutes: set[int] = set()
        for target in targets:
            minute = _bucket_key(target.row.epoch)
            needed_minutes.update(range(minute - radius, minute + radius + 1))
        buckets: dict[int, dict[str, Any]] = {}
        for row in iter_scenario_rows(labels_dir, scenario):
            minute = _bucket_key(row.epoch)
            if minute not in needed_minutes:
                continue
            bucket = buckets.setdefault(
                minute,
                {
                    "count": 0,
                    "detectors": Counter(),
                    "rules": Counter(),
                    "hosts": Counter(),
                    "examples": {},
                },
            )
            bucket["count"] += 1
            bucket["detectors"][row.detector] += 1
            bucket["rules"][row.name] += 1
            bucket["hosts"][row.host] += 1
            example_key = (row.detector, row.name, row.host, row.ip)
            if len(bucket["examples"]) < 40 and example_key not in bucket["examples"]:
                bucket["examples"][example_key] = _public_event(row)

        for target in targets:
            minute = _bucket_key(target.row.epoch)
            detector_counts: Counter[str] = Counter()
            rule_counts: Counter[str] = Counter()
            host_counts: Counter[str] = Counter()
            examples: list[dict[str, Any]] = []
            event_count = 0
            seen_examples: set[tuple[str, str, str, str]] = set()
            for item_minute in range(minute - radius, minute + radius + 1):
                bucket = buckets.get(item_minute)
                if not bucket:
                    continue
                event_count += int(bucket["count"])
                detector_counts.update(bucket["detectors"])
                rule_counts.update(bucket["rules"])
                host_counts.update(bucket["hosts"])
                for example in bucket["examples"].values():
                    key = (
                        str(example["detector"]), str(example["rule_name"]),
                        str(example["sensor_host"]), str(example["sensor_ip"]),
                    )
                    if key not in seen_examples and len(examples) < 80:
                        seen_examples.add(key)
                        examples.append(example)
            result[target.alert_id] = {
                "event_count": event_count,
                "detector_counts": detector_counts,
                "rule_counts": rule_counts,
                "host_counts": host_counts,
                "examples": examples,
            }
    return result


def _query_targets(row: OfficialAlertRow, context: dict[str, Any]) -> dict[str, Any]:
    endpoint: list[dict[str, str]] = []
    network_ips: list[str] = []
    for event in context["examples"]:
        if event["detector"] == "suricata":
            if event["sensor_ip"] and event["sensor_ip"] not in network_ips:
                network_ips.append(event["sensor_ip"])
        else:
            value = {"host": str(event["sensor_host"]), "ip": str(event["sensor_ip"])}
            if value not in endpoint:
                endpoint.append(value)
    if row.detector == "suricata" and row.ip and row.ip not in network_ips:
        network_ips.insert(0, row.ip)
    elif row.ip:
        primary = {"host": row.host, "ip": row.ip}
        if primary in endpoint:
            endpoint.remove(primary)
        endpoint.insert(0, primary)
    return {"endpoint": endpoint[:12], "network_ips": network_ips[:12]}


def _write_evidence(
    candidate: Candidate,
    context: dict[str, Any],
    store: Path,
    store_id: str,
) -> dict[str, Any]:
    row = candidate.row
    targets = _query_targets(row, context)
    anchor = _public_event(row)
    endpoint_logs = [
        {
            **event,
            "host": event["sensor_host"],
            "host_ip": event["sensor_ip"],
            "record_kind": "host_detector_alert",
        }
        for event in context["examples"]
        if event["detector"] != "suricata"
    ]
    network_alerts = [
        {
            **event,
            "src_ip": event["sensor_ip"],
            "dst_ip": None,
            "record_kind": "suricata_alert",
        }
        for event in context["examples"]
        if event["detector"] == "suricata"
    ]
    evidence = {
        "case_id": candidate.alert_id,
        "case_type": "deduplicated_alert_case",
        "dataset": "AIT-ADS-EVENT-GOLD",
        "detector_event": anchor,
        "detector_events": [anchor] + [
            item for item in context["examples"] if item != anchor
        ][:39],
        "primary_host": row.host,
        "primary_host_ip": row.ip,
        "endpoint_targets": targets["endpoint"],
        "network_targets": targets["network_ips"],
        "endpoint_logs": endpoint_logs[:80],
        "network_alerts": network_alerts[:60],
        "temporal_context": {
            "window_seconds_before_after": CONTEXT_WINDOW_SECONDS,
            "detector_event_count": context["event_count"],
            "detector_counts": dict(context["detector_counts"]),
            "top_rules": [
                {"rule_name": name, "count": count}
                for name, count in context["rule_counts"].most_common(12)
            ],
            "top_hosts": [
                {"host": name, "count": count}
                for name, count in context["host_counts"].most_common(12)
            ],
            "note": "Only label-free official detector rows were aggregated.",
        },
        "coverage": {
            "endpoint_records": len(endpoint_logs),
            "network_alerts": len(network_alerts),
            "network_kind": "suricata_alerts_not_netflow",
            "netflow_available": False,
            "contains_ground_truth": False,
        },
    }
    (store / f"{candidate.alert_id}.json").write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    capabilities = ["detector_context"]
    if endpoint_logs:
        capabilities.append("endpoint_logs")
    if network_alerts:
        capabilities.append("network_alerts")
    return {
        "_evidence_store": store_id,
        "_evidence_ref": candidate.alert_id,
        "evidence_capabilities": capabilities,
        "query_targets": targets,
        "evidence_summary": {
            "detector_events": context["event_count"],
            "endpoint_records_available": len(endpoint_logs),
            "network_alerts_available": len(network_alerts),
            "netflow_available": False,
        },
        "temporal_context": evidence["temporal_context"],
    }


def _alert_document(
    candidate: Candidate,
    private_evidence: dict[str, Any],
) -> dict[str, Any]:
    row = candidate.row
    source = _source_for(row)
    return {
        "alert_id": candidate.alert_id,
        "timestamp": datetime.fromtimestamp(row.epoch, tz=timezone.utc).isoformat(),
        "source": source,
        "severity": "medium",
        "src_ip": row.ip,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "rule_name": row.name,
        "description": (
            f"{row.name}; 资产={row.host}; 传感器/主机IP={row.ip}; "
            f"官方规则简称={row.short}"
        ),
        "raw_payload": {
            "dataset": "AIT-ADS-EVENT-GOLD",
            "detector": row.detector,
            "sensor_host": row.host,
            "sensor_ip": row.ip,
            "ip_semantics": "sensor_or_monitored_host_ip_not_network_direction",
            "rule_short": row.short,
            "event": row.name,
            **private_evidence,
        },
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_formal_suite(
    labels_dir: str | Path,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    *,
    evidence_root: str | Path = DEFAULT_EVIDENCE_ROOT,
    seed: int = 20260819,
    reservoir_capacity: int = 1000,
) -> dict[str, Any]:
    """Build development, validation, and frozen-test JSON files plus audit."""
    if reservoir_capacity < 1:
        raise ValueError("reservoir_capacity must be positive")
    labels = _labels_dir(labels_dir)
    output = Path(output_dir)
    evidence_base = Path(evidence_root)
    store_id = f"event-gold-v1-{seed}"
    store = evidence_base / store_id
    output.mkdir(parents=True, exist_ok=True)
    store.mkdir(parents=True, exist_ok=True)
    # This directory is an entirely generated, versioned cache.  Remove stale
    # case documents from an earlier build with the same deterministic store ID.
    for stale in store.glob("*.json"):
        stale.unlink()

    reservoirs: dict[
        tuple[str, str, tuple[str, ...]], list[tuple[int, str, Candidate]]
    ] = {}
    audit: dict[str, Any] = {
        "rows_total": 0,
        "eligible_before_case_dedup": Counter(),
        "eligible_after_case_dedup": Counter(),
        "excluded_conflicts": Counter(),
        "time_event_pairs": Counter(),
        "scenario_rows": Counter(),
        "detectors": Counter(),
    }
    seen_cases: set[str] = set()
    all_scenarios = tuple(
        scenario for spec in SPLIT_SPECS.values() for scenario in spec["scenarios"]
    )
    for scenario in all_scenarios:
        split = _split_for_scenario(scenario)
        for row in iter_scenario_rows(labels, scenario):
            audit["rows_total"] += 1
            audit["scenario_rows"][scenario] += 1
            audit["detectors"][row.detector] += 1
            audit["time_event_pairs"][(row.time_label, row.event_label)] += 1
            label = row.binary_label
            if label is None:
                conflict = (
                    "attack_time_without_event"
                    if row.time_label != "false_positive"
                    else "event_outside_attack_time"
                )
                audit["excluded_conflicts"][conflict] += 1
                continue
            audit["eligible_before_case_dedup"][(scenario, label)] += 1
            alert_id, case_digest = _case_identity(row)
            if case_digest in seen_cases:
                continue
            seen_cases.add(case_digest)
            audit["eligible_after_case_dedup"][(scenario, label)] += 1
            candidate = Candidate(
                row=row,
                alert_id=alert_id,
                case_digest=case_digest,
                priority=_priority(seed, alert_id),
                label=label,
                split=split,
            )
            _push(reservoirs, candidate, capacity=reservoir_capacity)

    selected_by_split: dict[str, list[Candidate]] = {}
    for split, spec in SPLIT_SPECS.items():
        positives = _round_robin(
            reservoirs,
            split,
            "真阳",
            int(spec["per_class"]),
            family_cap=max(1, int(spec["per_class"] * 0.60)),
        )
        negatives = _round_robin(reservoirs, split, "假阳", int(spec["per_class"]))
        if len(positives) != spec["per_class"] or len(negatives) != spec["per_class"]:
            raise ValueError(
                f"insufficient deduplicated cases for {split}: "
                f"positive={len(positives)}, negative={len(negatives)}"
            )
        selected_by_split[split] = sorted(
            positives + negatives, key=lambda item: item.priority
        )

    selected_all = [item for values in selected_by_split.values() for item in values]
    context_by_id = _collect_context(labels, selected_all)
    files: dict[str, dict[str, Any]] = {}
    index_cases: list[str] = []
    for split, selected in selected_by_split.items():
        alerts: list[dict[str, Any]] = []
        ground_truth: dict[str, dict[str, Any]] = {}
        for candidate in selected:
            private = _write_evidence(
                candidate, context_by_id[candidate.alert_id], store, store_id
            )
            alerts.append(_alert_document(candidate, private))
            row = candidate.row
            ground_truth[candidate.alert_id] = {
                "label": candidate.label,
                "scenario": row.scenario,
                "time_label": row.time_label,
                "event_label": row.event_label,
                "detector": row.detector,
                "label_basis": "official_event_and_time_consistent",
                "case_digest": candidate.case_digest,
            }
            index_cases.append(candidate.alert_id)
        split_spec = SPLIT_SPECS[split]
        document = {
            "metadata": {
                "name": {
                    "development": "AIT-ADS 正式开发集",
                    "validation": "AIT-ADS 正式验证集",
                    "test_frozen": "AIT-ADS 正式冻结测试集",
                }[split],
                "source": "AIT Alert Data Set + official event labels",
                "source_dataset": "https://zenodo.org/records/8263181",
                "event_label_source": "https://github.com/ait-aecid/alert-data-set",
                "event_label_revision": EVENT_LABEL_REVISION,
                "event_label_archive_sha256": EVENT_LABEL_SHA256,
                "license": "AIT-ADS data: CC-BY-4.0; label-generation code: GPL-3.0",
                "schema_version": 1,
                "split": split,
                "frozen": bool(split_spec["frozen"]),
                "scenarios": list(split_spec["scenarios"]),
                "sample_count": len(selected),
                "class_balance": {"真阳": len(selected) // 2, "假阳": len(selected) // 2},
                "label_storage": "separated",
                "label_basis": "official_event_and_time_consistent",
                "evaluation_unit": "deduplicated_1_minute_case",
                "case_key": ["scenario", "detector", "rule_name", "host", "ip", "1m_bucket"],
                "conflict_policy": "exclude_any_time_event_disagreement",
                "positive_family_cap": "no_event_label_exceeds_60_percent_of_positive_cases",
                "context_basis": "label_free_cross_detector_neighbourhood",
                "context_window_seconds": CONTEXT_WINDOW_SECONDS,
                "ground_truth_policy": "pending_is_prediction_only_and_counts_as_error",
                "seed": seed,
                "acceptance_gate": {
                    "accuracy": 0.88,
                    "accuracy_wilson_95_lower": 0.85,
                    "macro_f1": 0.85,
                    "negative_f1": 0.85,
                    "coverage": 0.90,
                },
            },
            "alerts": alerts,
            "ground_truth": ground_truth,
        }
        path = output / f"ait_ads_event_gold_{split}.json"
        path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
        files[split] = {
            "path": str(path.resolve()),
            "samples": len(selected),
            "sha256": _sha256(path),
            "scenarios": list(split_spec["scenarios"]),
            "frozen": bool(split_spec["frozen"]),
        }

    index = {
        "version": 1,
        "store_id": store_id,
        "cases": index_cases,
        "contains_ground_truth": False,
        "event_label_revision": EVENT_LABEL_REVISION,
    }
    (store / "index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    audit_json = {
        "rows_total": audit["rows_total"],
        "scenario_rows": dict(audit["scenario_rows"]),
        "detectors": dict(audit["detectors"]),
        "eligible_before_case_dedup": {
            f"{scenario}:{label}": count
            for (scenario, label), count in audit["eligible_before_case_dedup"].items()
        },
        "eligible_after_case_dedup": {
            f"{scenario}:{label}": count
            for (scenario, label), count in audit["eligible_after_case_dedup"].items()
        },
        "excluded_conflicts": dict(audit["excluded_conflicts"]),
        "time_event_pairs": {
            f"{time_label}|{event_label}": count
            for (time_label, event_label), count in audit["time_event_pairs"].most_common()
        },
        "case_dedup_removed": (
            sum(audit["eligible_before_case_dedup"].values())
            - sum(audit["eligible_after_case_dedup"].values())
        ),
    }
    manifest = {
        "name": "AIT-ADS formal event-gold evaluation suite",
        "version": 1,
        "seed": seed,
        "event_label_revision": EVENT_LABEL_REVISION,
        "event_label_archive_sha256": EVENT_LABEL_SHA256,
        "files": files,
        "evidence_store": str(store.resolve()),
        "audit": audit_json,
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    manifest["manifest"] = str(manifest_path.resolve())
    return manifest


def load_case_evidence(store_id: str, case_id: str) -> dict[str, Any] | None:
    if not _SAFE_ID.fullmatch(store_id) or not _SAFE_ID.fullmatch(case_id):
        return None
    root = DEFAULT_EVIDENCE_ROOT.resolve()
    path = (root / store_id / f"{case_id}.json").resolve()
    if path.parent.parent != root or not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def evidence_for_alert(alert_ctx: dict[str, Any]) -> dict[str, Any] | None:
    payload = alert_ctx.get("raw_payload") or {}
    if payload.get("dataset") != "AIT-ADS-EVENT-GOLD":
        return None
    store_id = payload.get("_evidence_store")
    case_id = payload.get("_evidence_ref")
    if not isinstance(store_id, str) or not isinstance(case_id, str):
        return None
    return load_case_evidence(store_id, case_id)


def _main() -> None:
    parser = argparse.ArgumentParser(description="Build the formal AIT-ADS event-gold suite")
    parser.add_argument("--event-labels", required=True, help="Extracted official alerts_csv directory")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--evidence-root", default=str(DEFAULT_EVIDENCE_ROOT))
    parser.add_argument("--seed", type=int, default=20260819)
    parser.add_argument("--reservoir-capacity", type=int, default=1000)
    args = parser.parse_args()
    result = build_formal_suite(
        args.event_labels,
        args.output_dir,
        evidence_root=args.evidence_root,
        seed=args.seed,
        reservoir_capacity=args.reservoir_capacity,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    _main()
