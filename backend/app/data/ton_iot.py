"""Build a leakage-safe ToN_IoT industrial external-validation set.

The public Train_Test network table has no timestamp column, so it cannot be
honestly joined to device telemetry as one correlated incident.  This adapter
therefore creates a frozen, balanced *source-record* validation suite covering
network flows and Modbus telemetry.  It tests domain transfer and tool routing;
it is deliberately separate from the AIT-ADS credible-85 case-level gate.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import heapq
import json
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_NETWORK_CSV = PROJECT_ROOT / "data/raw/ton_iot/network/train_test_network.csv"
DEFAULT_MODBUS_CSV = PROJECT_ROOT / "data/raw/ton_iot/telemetry/IoT_Modbus.csv"
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "data/processed/ton_iot_industrial/ton_iot_industrial_external_validation.json"
)

NETWORK_REVISION = "45152c3ed1e33750e589bf708fdea60775d04660"
NETWORK_SHA256 = "3019999cb8a94172c2d24bdaa5cec64ffa308768ae3835938b786eb42657405d"
MODBUS_REVISION = "770a7d744b1a3754ccd16f0e8a53cbc16ad4039d"
MODBUS_SHA256 = "1cdb245661db3f15be52c3e8aeba5b1a3af37b8eed3f9132a7f1a03d8111aa16"

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


@dataclass(frozen=True)
class Candidate:
    modality: str
    ordinal: int
    label: str
    attack_type: str
    observation: dict[str, str]
    case_digest: str
    alert_id: str
    priority: int


def _clean_row(row: dict[str, str | None]) -> dict[str, str]:
    return {str(key).strip(): str(value or "").strip() for key, value in row.items()}


def _visible_observation(row: dict[str, str]) -> dict[str, str]:
    return {key: value for key, value in row.items() if key not in {"label", "type"}}


def _identity(modality: str, observation: dict[str, str]) -> tuple[str, str]:
    canonical = json.dumps(
        {"modality": modality, "observation": observation},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    alert_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"ton-iot-record:{digest}"))
    return alert_id, digest


def _priority(seed: int, alert_id: str) -> int:
    digest = hashlib.sha256(f"{seed}:{alert_id}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def _iter_csv(path: Path, modality: str) -> Iterator[Candidate]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        required = {"label", "type"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(f"{path} is missing required columns: {sorted(required)}")
        for ordinal, raw in enumerate(reader, start=1):
            row = _clean_row(raw)
            binary = row["label"]
            attack_type = row["type"].lower()
            if binary not in {"0", "1"}:
                continue
            label = "真阳" if binary == "1" else "假阳"
            observation = _visible_observation(row)
            alert_id, digest = _identity(modality, observation)
            yield Candidate(
                modality=modality,
                ordinal=ordinal,
                label=label,
                attack_type=attack_type,
                observation=observation,
                case_digest=digest,
                alert_id=alert_id,
                priority=0,
            )


def _push(
    reservoirs: dict[tuple[str, str, str], list[tuple[int, str, Candidate]]],
    candidate: Candidate,
    *,
    seed: int,
    capacity: int,
) -> None:
    candidate = Candidate(
        **{
            **candidate.__dict__,
            "priority": _priority(seed, candidate.alert_id),
        }
    )
    key = (candidate.modality, candidate.label, candidate.attack_type)
    heap = reservoirs.setdefault(key, [])
    item = (-candidate.priority, candidate.alert_id, candidate)
    if len(heap) < capacity:
        heapq.heappush(heap, item)
    elif item > heap[0]:
        heapq.heapreplace(heap, item)


def _select(
    reservoirs: dict[tuple[str, str, str], list[tuple[int, str, Candidate]]],
    conflicts: set[str],
    modality: str,
    label: str,
    count: int,
) -> list[Candidate]:
    groups: list[list[Candidate]] = []
    for key in sorted(reservoirs):
        if key[0] != modality or key[1] != label:
            continue
        values = [item[2] for item in reservoirs[key] if item[2].case_digest not in conflicts]
        groups.append(sorted(values, key=lambda item: (item.priority, item.alert_id)))
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
    if len(selected) != count:
        raise ValueError(
            f"insufficient unique {modality}/{label} records: {len(selected)} < {count}"
        )
    return selected


def _parse_modbus_time(observation: dict[str, str]) -> datetime:
    date_text = observation.get("date", "")
    time_text = observation.get("time", "")
    try:
        day_text, month_text, year_text = date_text.split("-")
        year = int(year_text)
        year += 2000 if year < 70 else 1900
        hour, minute, second = (int(part) for part in time_text.split(":"))
        return datetime(
            year, _MONTHS[month_text.lower()], int(day_text),
            hour, minute, second, tzinfo=timezone.utc,
        )
    except (KeyError, TypeError, ValueError):
        return datetime(2000, 1, 1, tzinfo=timezone.utc)


def _integer(value: str | None) -> int | None:
    try:
        parsed = int(float(str(value)))
    except (TypeError, ValueError):
        return None
    return parsed if 0 <= parsed <= 65535 else None


def _alert(candidate: Candidate) -> dict[str, Any]:
    observation = candidate.observation
    if candidate.modality == "network":
        timestamp = datetime(2000, 1, 1, tzinfo=timezone.utc) + timedelta(
            seconds=candidate.ordinal
        )
        src_ip = observation.get("src_ip") or None
        dst_ip = observation.get("dst_ip") or None
        source = "ndr"
        protocol = (observation.get("proto") or "").upper() or None
        rule_name = "ToN_IoT network behavior candidate"
        description = (
            f"工业互联网网络流候选：{src_ip}:{observation.get('src_port') or '-'} → "
            f"{dst_ip}:{observation.get('dst_port') or '-'}；"
            f"协议={protocol or '-'}，服务={observation.get('service') or '-'}，"
            f"连接状态={observation.get('conn_state') or '-'}"
        )
        capabilities = ["detector_context", "network_flows"]
        query_targets = {"endpoint": [], "network_ips": [ip for ip in (src_ip, dst_ip) if ip]}
        timestamp_semantics = "synthetic_source_order_only_network_subset_has_no_timestamp"
    else:
        timestamp = _parse_modbus_time(observation)
        src_ip = dst_ip = protocol = None
        source = "siem"
        rule_name = "ToN_IoT Modbus telemetry anomaly candidate"
        description = (
            "工业设备 Modbus 遥测候选："
            f"FC1={observation.get('FC1_Read_Input_Register') or '-'}，"
            f"FC2={observation.get('FC2_Read_Discrete_Value') or '-'}，"
            f"FC3={observation.get('FC3_Read_Holding_Register') or '-'}，"
            f"FC4={observation.get('FC4_Read_Coil') or '-'}"
        )
        capabilities = ["detector_context", "endpoint_logs"]
        query_targets = {
            "endpoint": [{"host": "ton-iot-modbus", "ip": "ton-iot-modbus"}],
            "network_ips": [],
        }
        timestamp_semantics = "source_local_naive_assumed_UTC_for_schema_only"
    return {
        "alert_id": candidate.alert_id,
        "timestamp": timestamp.isoformat(),
        "source": source,
        "severity": "medium",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": _integer(observation.get("src_port")),
        "dst_port": _integer(observation.get("dst_port")),
        "protocol": protocol,
        "rule_name": rule_name,
        "description": description,
        "raw_payload": {
            "dataset": "TON-IOT-INDUSTRIAL",
            "modality": candidate.modality,
            "source_row_ordinal": candidate.ordinal,
            "timestamp_semantics": timestamp_semantics,
            "observation": observation,
            "event": observation,
            "evidence_capabilities": capabilities,
            "query_targets": query_targets,
            "correlation_scope": "same_source_record_not_cross_source_incident",
        },
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_external_validation(
    network_csv: str | Path = DEFAULT_NETWORK_CSV,
    modbus_csv: str | Path = DEFAULT_MODBUS_CSV,
    output_path: str | Path = DEFAULT_OUTPUT,
    *,
    per_modality_class: int = 500,
    seed: int = 20260819,
    reservoir_capacity: int = 2000,
) -> dict[str, Any]:
    """Create a frozen 2-modality, balanced external validation document."""
    if per_modality_class < 1 or reservoir_capacity < per_modality_class:
        raise ValueError("reservoir_capacity must cover per_modality_class")
    paths = {
        "network": Path(network_csv),
        "modbus_telemetry": Path(modbus_csv),
    }
    expected_hashes = {
        "network": NETWORK_SHA256,
        "modbus_telemetry": MODBUS_SHA256,
    }
    input_hashes = {name: _sha256(path) for name, path in paths.items()}
    official_inputs = all(input_hashes[name] == expected_hashes[name] for name in paths)

    reservoirs: dict[tuple[str, str, str], list[tuple[int, str, Candidate]]] = {}
    observed_labels: dict[str, str] = {}
    conflicts: set[str] = set()
    audit: dict[str, Any] = {
        "rows": Counter(), "labels": Counter(), "attack_types": Counter(),
        "duplicates": Counter(), "label_type_conflicts": Counter(),
    }
    for modality, path in paths.items():
        for candidate in _iter_csv(path, modality):
            audit["rows"][modality] += 1
            audit["labels"][(modality, candidate.label)] += 1
            audit["attack_types"][(modality, candidate.attack_type)] += 1
            expected_type = candidate.attack_type == "normal"
            if (candidate.label == "假阳") != expected_type:
                audit["label_type_conflicts"][modality] += 1
                continue
            previous = observed_labels.get(candidate.case_digest)
            if previous is not None:
                audit["duplicates"][modality] += 1
                if previous != candidate.label:
                    conflicts.add(candidate.case_digest)
                continue
            observed_labels[candidate.case_digest] = candidate.label
            _push(
                reservoirs, candidate, seed=seed, capacity=reservoir_capacity
            )

    selected: list[Candidate] = []
    for modality in paths:
        for label in ("真阳", "假阳"):
            selected.extend(
                _select(
                    reservoirs, conflicts, modality, label, per_modality_class
                )
            )
    selected.sort(key=lambda item: (item.priority, item.alert_id))

    alerts = [_alert(candidate) for candidate in selected]
    ground_truth = {
        candidate.alert_id: {
            "label": candidate.label,
            "attack_type": candidate.attack_type,
            "modality": candidate.modality,
            "source_row_ordinal": candidate.ordinal,
            "case_digest": candidate.case_digest,
            "label_basis": "ToN_IoT_published_binary_and_attack_type_columns",
        }
        for candidate in selected
    }
    sample_count = len(selected)
    document = {
        "metadata": {
            "name": "ToN_IoT industrial multi-source external validation",
            "source": "UNSW ToN_IoT network and Modbus telemetry",
            "official_source": "https://research.unsw.edu.au/projects/toniot-datasets",
            "schema_version": 1,
            "split": "external_validation_frozen",
            "frozen": True,
            "external_validation": True,
            "sample_count": sample_count,
            "class_balance": {"真阳": sample_count // 2, "假阳": sample_count // 2},
            "modality_balance": {
                "network": per_modality_class * 2,
                "modbus_telemetry": per_modality_class * 2,
            },
            "label_storage": "separated",
            "label_basis": "ToN_IoT_published_binary_and_attack_type_columns",
            "evaluation_unit": "deduplicated_source_record",
            "sampling": "deterministic_hash_stratified_by_modality_class_attack_type",
            "seed": seed,
            "correlation_scope": "modality_coverage_not_cross_source_case_correlation",
            "network_timestamp_limitation": (
                "train_test_network.csv has no timestamp column; synthetic timestamps "
                "preserve source ordering only and must not be used for temporal claims"
            ),
            "acceptance_scope": (
                "industrial domain-transfer and tool-routing validation; this suite does "
                "not establish the AIT-ADS credible-85 claim"
            ),
            "ground_truth_policy": "pending_is_prediction_only_and_counts_as_error",
            "license": (
                "UNSW grants perpetual free academic research use; commercial use "
                "requires permission from the dataset author; cite the official papers"
            ),
            "source_revisions": {
                "network_mirror_commit": NETWORK_REVISION,
                "modbus_mirror_commit": MODBUS_REVISION,
            },
            "source_sha256": input_hashes,
            "pinned_inputs_match": official_inputs,
        },
        "alerts": alerts,
        "ground_truth": ground_truth,
    }
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")

    audit_json = {
        "rows": dict(audit["rows"]),
        "labels": {f"{m}:{label}": count for (m, label), count in audit["labels"].items()},
        "attack_types": {
            f"{m}:{kind}": count for (m, kind), count in audit["attack_types"].items()
        },
        "duplicates": dict(audit["duplicates"]),
        "label_type_conflicts": dict(audit["label_type_conflicts"]),
        "ambiguous_observation_conflicts": len(conflicts),
    }
    manifest = {
        "name": "ToN_IoT industrial external validation",
        "version": 1,
        "output": str(output.resolve()),
        "samples": sample_count,
        "sha256": _sha256(output),
        "input_sha256": input_hashes,
        "pinned_inputs_match": official_inputs,
        "audit": audit_json,
    }
    manifest_path = output.with_name("manifest.json")
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return {**manifest, "manifest": str(manifest_path.resolve())}


def _main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", default=str(DEFAULT_NETWORK_CSV))
    parser.add_argument("--modbus", default=str(DEFAULT_MODBUS_CSV))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--per-modality-class", type=int, default=500)
    parser.add_argument("--seed", type=int, default=20260819)
    args = parser.parse_args()
    result = build_external_validation(
        args.network,
        args.modbus,
        args.output,
        per_modality_class=args.per_modality_class,
        seed=args.seed,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    _main()
