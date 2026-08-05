"""Build a leakage-safe CAM-LDS pilot and its out-of-band evidence store.

The Agent receives a normalized detector alert with an opaque evidence reference.
AttackMate execution records and MITRE ground truth are kept only in the evaluation
document. Defender-side logs are stored separately and can only be read through
ReAct tools.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import uuid
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from app.core.config import PROJECT_ROOT
from app.models.schemas import Alert


CAM_EVIDENCE_ROOT = PROJECT_ROOT / "data" / "processed" / "cam_lds_evidence"
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "processed" / "cam_lds_pilot.json"
_SAFE_ID = re.compile(r"^[0-9A-Za-z._-]+$")
_SURICATA_LINE = re.compile(
    r"^(?P<timestamp>\S+)\s+\[\*\*\]\s+\[(?P<signature_id>[^]]+)\]\s+"
    r"(?P<signature>.*?)\s+\[\*\*\].*?\[Priority:\s*(?P<priority>\d+)\]\s+"
    r"\{(?P<protocol>[^}]+)\}\s+(?P<src_ip>[^: ]+):(?P<src_port>\d+)\s+->\s+"
    r"(?P<dst_ip>[^: ]+):(?P<dst_port>\d+)"
)
_ENDPOINT_NAMES = {
    "audit.log", "auth.log", "syslog", "messages", "daemon.log", "kern.log",
    "cron.log", "dpkg.log", "access.log", "error.log", "web_php.log",
    "mainlog", "vsftpd.log", "puppetserver.log", "puppetserver-access.log",
}
_HIGH_SIGNAL_MARKERS = (
    "execve", "proctitle", "syscall", "command=", "curl", "wget", "nmap",
    "dnsenum", "hydra", "tcpdump", "reverse shell", "rootkit", "ransom",
    "exploit", "malware", "brute", "scan", "download", "setuid", "setgid",
    "/etc/shadow", "authorized_keys", "chmod", "chown", "useradd", "sudo",
    "python", "bash", "docker", "cron", "ssh", "scp", "nc ", "netcat",
)
_GENERIC_DETECTOR_MARKERS = (
    "login session closed", "authentication success", "event queue", "buffer",
    "protocol only one direction", "unable to match response", "malformed",
    "serverbanner", "info ",
)


def _dataset_root(path: str | Path) -> Path:
    root = Path(path).expanduser().resolve()
    if (root / "steps").is_dir():
        return root
    nested = root / "manifestations_filtered"
    if (nested / "steps").is_dir():
        return nested
    raise FileNotFoundError(
        f"CAM-LDS steps directory not found below {root}; expected steps/ or "
        "manifestations_filtered/steps/"
    )


def _json_lines(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.is_file():
        return records
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                records.append(value)
    return records


def _attack_truth(step: Path) -> dict[str, Any] | None:
    candidates = list(step.glob("attacker/logs/attackmate.json"))
    if not candidates:
        return None
    records = _json_lines(candidates[0])
    if not records:
        return None
    parameters = records[0].get("parameters")
    if not isinstance(parameters, dict):
        return None
    metadata = parameters.get("metadata")
    if not isinstance(metadata, dict):
        return None
    techniques = [
        item.strip() for item in str(metadata.get("techniques", "")).split(",")
        if item.strip()
    ]
    tactics = [
        item.strip() for item in str(metadata.get("tactics", "")).split(",")
        if item.strip()
    ]
    scenario_match = re.match(r"^(\d+)", step.name)
    return {
        "label": "真阳",
        "scenario": scenario_match.group(1) if scenario_match else "unknown",
        "step": step.name,
        "techniques": techniques,
        "tactics": tactics,
        "technique_name": metadata.get("technique_name"),
        "label_basis": "controlled_attack_step_case",
    }


def _wazuh_events(step: Path) -> list[dict[str, Any]]:
    path = step / "wazuh" / "logs" / "alerts" / "alerts.json"
    return _json_lines(path)


def _suricata_events(step: Path, limit: int = 80) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for path in step.rglob("fast.log"):
        host = path.relative_to(step).parts[0]
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                match = _SURICATA_LINE.search(line.strip())
                if not match:
                    continue
                item: dict[str, Any] = match.groupdict()
                item.update(
                    {
                        "host": host,
                        "priority": int(item["priority"]),
                        "src_port": int(item["src_port"]),
                        "dst_port": int(item["dst_port"]),
                        "raw": line.strip()[:2000],
                    }
                )
                events.append(item)
                if len(events) >= limit:
                    return events
    return events


def _selected_wazuh(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not events:
        return None
    # Prefer detector-native ATT&CK mappings, then the highest severity rule.
    return max(
        events,
        key=lambda item: (
            bool(item.get("rule", {}).get("mitre")),
            int(item.get("rule", {}).get("level", 0) or 0),
        ),
    )


def _wazuh_score(item: dict[str, Any]) -> int:
    rule = item.get("rule", {})
    text = " ".join(
        (str(rule.get("description", "")), str(item.get("full_log", "")))
    ).lower()
    score = min(6, int(rule.get("level", 0) or 0) // 2)
    score += 5 if rule.get("mitre") else 0
    score += 3 if any(marker in text for marker in _HIGH_SIGNAL_MARKERS) else 0
    score -= 3 if any(marker in text for marker in _GENERIC_DETECTOR_MARKERS) else 0
    return score


def _suricata_score(item: dict[str, Any]) -> int:
    text = str(item.get("signature", "")).lower()
    score = {1: 8, 2: 6, 3: 3}.get(int(item.get("priority", 3)), 2)
    score += 3 if any(marker in text for marker in _HIGH_SIGNAL_MARKERS) else 0
    score -= 3 if any(marker in text for marker in _GENERIC_DETECTOR_MARKERS) else 0
    return score


def _compact_wazuh(item: dict[str, Any]) -> dict[str, Any]:
    rule = item.get("rule", {})
    agent = item.get("agent", {})
    return {
        "detector": "wazuh",
        "timestamp": item.get("timestamp"),
        "rule_id": str(rule.get("id", "")),
        "rule_name": rule.get("description"),
        "rule_level": int(rule.get("level", 0) or 0),
        "rule_groups": rule.get("groups", []),
        "detector_mitre": rule.get("mitre", {}),
        "agent": {"name": agent.get("name"), "ip": agent.get("ip")},
        "location": item.get("location"),
        "full_log": str(item.get("full_log", ""))[:2500],
        "signal_score": _wazuh_score(item),
    }


def _compact_suricata(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "detector": "suricata",
        "timestamp": item.get("timestamp"),
        "signature_id": item.get("signature_id"),
        "rule_name": item.get("signature"),
        "priority": item.get("priority"),
        "protocol": item.get("protocol"),
        "src_ip": item.get("src_ip"),
        "src_port": item.get("src_port"),
        "dst_ip": item.get("dst_ip"),
        "dst_port": item.get("dst_port"),
        "raw": item.get("raw"),
        "signal_score": _suricata_score(item),
    }


def _severity_from_wazuh(level: int) -> str:
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "info"


def _severity_from_suricata(priority: int) -> str:
    return "high" if priority <= 1 else "medium" if priority == 2 else "low"


def _case_id(seed: int, step_name: str) -> str:
    namespace = uuid.UUID("77fc38d5-082f-4b3e-9ef4-5fa4484e58db")
    return str(uuid.uuid5(namespace, f"{seed}:{step_name}"))


def _alert_from_step(
    step: Path, case_id: str, store_id: str,
) -> tuple[Alert, list[dict[str, Any]], str | None, str | None] | None:
    wazuh = _wazuh_events(step)
    selected = _selected_wazuh(wazuh)
    suricata = _suricata_events(step)
    private_ref = {"_evidence_store": store_id, "_evidence_ref": case_id}
    if not selected and not suricata:
        return None

    compact_wazuh = sorted(
        (_compact_wazuh(item) for item in wazuh),
        key=lambda item: (-int(item["signal_score"]), str(item.get("timestamp"))),
    )[:10]
    compact_suricata = sorted(
        (_compact_suricata(item) for item in suricata),
        key=lambda item: (-int(item["signal_score"]), str(item.get("timestamp"))),
    )[:10]
    detector_events = sorted(
        compact_wazuh + compact_suricata,
        key=lambda item: (-int(item["signal_score"]), str(item.get("timestamp"))),
    )[:16]
    primary = detector_events[0]
    network_primary = next(
        (item for item in detector_events if item["detector"] == "suricata"), None
    )
    endpoint_primary = next(
        (item for item in detector_events if item["detector"] == "wazuh"), None
    )
    primary_host = (
        endpoint_primary.get("agent", {}).get("name") if endpoint_primary else None
    )
    primary_host_ip = (
        endpoint_primary.get("agent", {}).get("ip") if endpoint_primary else None
    )
    observable_ips = list(dict.fromkeys(
        value
        for item in detector_events
        for value in (
            item.get("src_ip"), item.get("dst_ip"), item.get("agent", {}).get("ip")
        )
        if value
    ))
    rule_names = list(dict.fromkeys(
        str(item.get("rule_name")) for item in detector_events if item.get("rule_name")
    ))
    if primary["detector"] == "suricata":
        timestamp: Any = datetime.strptime(primary["timestamp"], "%m/%d/%Y-%H:%M:%S.%f")
        source = "ids"
        severity = _severity_from_suricata(int(primary.get("priority", 3)))
    else:
        timestamp = primary.get("timestamp")
        source = "siem"
        severity = _severity_from_wazuh(int(primary.get("rule_level", 0)))

    alert = Alert(
        alert_id=case_id,
        timestamp=timestamp,
        source=source,
        severity=severity,
        src_ip=network_primary.get("src_ip") if network_primary else None,
        dst_ip=(network_primary.get("dst_ip") if network_primary else primary_host_ip),
        src_port=network_primary.get("src_port") if network_primary else None,
        dst_port=network_primary.get("dst_port") if network_primary else None,
        protocol=network_primary.get("protocol") if network_primary else None,
        rule_name=f"Correlated security case: {primary.get('rule_name')}",
        description=(
            f"关联检测案例包含 {len(compact_wazuh)} 条 Wazuh 告警和 "
            f"{len(compact_suricata)} 条 Suricata 告警。高优先级观测："
            + "；".join(rule_names[:6])
        )[:2500],
        raw_payload={
            **private_ref,
            "detector": "correlated_case",
            "event": primary,
            "detector_events": detector_events,
            "detector_event_count": len(wazuh) + len(suricata),
            "observable_ips": observable_ips,
            "evidence_capabilities": ["detector_context"]
            + (["network_alerts"] if suricata else []),
        },
    )
    return alert, detector_events, primary_host, primary_host_ip


def _line_signal_score(value: str, source: str, *, primary: bool) -> int:
    lowered = value.lower()
    score = 2 if primary else 0
    score += 3 if source == "audit.log" else 0
    score += sum(2 for marker in _HIGH_SIGNAL_MARKERS if marker in lowered)
    if "type=execve" in lowered or "type=proctitle" in lowered:
        score += 5
    if "success=no" in lowered or "failed password" in lowered:
        score += 2
    return score


def _ranked_lines(path: Path, *, primary: bool, scan_limit: int = 2000) -> list[tuple[int, str]]:
    ranked: list[tuple[int, str]] = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle):
            if index >= scan_limit:
                break
            value = line.strip().replace("\x1d", " ")
            if value:
                value = value[:2000]
                ranked.append((_line_signal_score(value, path.name, primary=primary), value))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return ranked[:80]


def _endpoint_evidence(
    step: Path, primary_host: str | None, max_records: int = 120,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    paths = [path for path in step.rglob("*") if path.is_file() and path.name in _ENDPOINT_NAMES]
    paths.sort(key=lambda path: (path.relative_to(step).parts[0] != primary_host, str(path)))
    for path in paths:
        relative = path.relative_to(step)
        host = relative.parts[0]
        if host in {"attacker", "wazuh", "inetfw"}:
            continue
        for score, line in _ranked_lines(path, primary=host == primary_host):
            candidates.append(
                {
                    "host": host,
                    "source": path.name,
                    "path": str(relative),
                    "event": line,
                    "signal_score": score,
                }
            )
    candidates.sort(
        key=lambda item: (
            -int(item["signal_score"]),
            item["host"] != primary_host,
            item["source"],
            item["event"],
        )
    )
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in candidates:
        fingerprint = (item["host"], item["source"], item["event"])
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        records.append(item)
        if len(records) >= max_records:
            break
    return records


def _priority(seed: int, step_name: str) -> str:
    return hashlib.sha256(f"{seed}:{step_name}".encode()).hexdigest()


def _endpoint_targets(
    detector_events: list[dict[str, Any]], endpoint: list[dict[str, Any]],
) -> list[dict[str, str]]:
    evidence_hosts = {str(item.get("host")) for item in endpoint if item.get("host")}
    targets: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for event in detector_events:
        agent = event.get("agent") or {}
        host = agent.get("name")
        ip = agent.get("ip")
        if not host or not ip or host not in evidence_hosts:
            continue
        key = (str(host), str(ip))
        if key not in seen:
            seen.add(key)
            targets.append({"host": str(host), "ip": str(ip)})
    host_counts = Counter(str(item.get("host")) for item in endpoint)
    mapped_hosts = {item["host"] for item in targets}
    # Some filtered steps have defender logs but no Wazuh agent-to-IP mapping.
    # Keep the hostname as an explicit query identifier instead of discarding
    # a real evidence source or guessing an IP.
    for host in sorted(evidence_hosts - mapped_hosts):
        targets.append({"host": host, "ip": host, "identifier_type": "hostname"})
    targets.sort(key=lambda item: (-host_counts[item["host"]], item["host"], item["ip"]))
    return targets


def _network_targets(network: list[dict[str, Any]]) -> list[str]:
    counts: Counter[str] = Counter()
    for item in network:
        for field in ("src_ip", "dst_ip"):
            value = item.get(field)
            if value:
                counts[str(value)] += 1
    return [value for value, _ in counts.most_common(12)]


def _observability(
    detector_events: list[dict[str, Any]],
    endpoint: list[dict[str, Any]],
    network: list[dict[str, Any]],
) -> dict[str, Any]:
    detector_scores = [int(item.get("signal_score", 0)) for item in detector_events]
    endpoint_scores = [int(item.get("signal_score", 0)) for item in endpoint]
    high_detector = sum(score >= 6 for score in detector_scores)
    high_endpoint = sum(score >= 5 for score in endpoint_scores)
    high_network = sum(_suricata_score(item) >= 6 for item in network)
    score = (
        (max(detector_scores) if detector_scores else 0)
        + min(8, high_detector * 2)
        + min(10, high_endpoint)
        + min(6, high_network * 2)
    )
    return {
        "score": score,
        "high_signal_detector_events": high_detector,
        "high_signal_endpoint_records": high_endpoint,
        "high_signal_network_alerts": high_network,
        "basis": "defender_observations_only",
    }


def _round_robin(candidates: Iterable[dict[str, Any]], max_cases: int) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in candidates:
        groups[item["truth"]["scenario"]].append(item)
    for group in groups.values():
        group.sort(
            key=lambda item: (-int(item["observability"]["score"]), item["priority"])
        )
    selected: list[dict[str, Any]] = []
    offset = 0
    while len(selected) < max_cases:
        added = False
        for scenario in sorted(groups):
            if offset < len(groups[scenario]):
                selected.append(groups[scenario][offset])
                added = True
                if len(selected) >= max_cases:
                    break
        if not added:
            break
        offset += 1
    return selected


def build_dataset(
    source_dir: str | Path,
    output_path: str | Path = DEFAULT_OUTPUT,
    *,
    evidence_root: str | Path = CAM_EVIDENCE_ROOT,
    max_cases: int = 40,
    seed: int = 20260722,
    require_endpoint: bool = True,
    selected_steps: Iterable[str] | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    """Create a deterministic CAM-LDS pilot plus an external evidence store."""
    if max_cases < 1:
        raise ValueError("max_cases must be at least 1")
    root = _dataset_root(source_dir)
    output = Path(output_path).expanduser().resolve()
    evidence_base = Path(evidence_root).expanduser().resolve()
    store_id = f"pilot-{seed}"
    store = evidence_base / store_id
    store.mkdir(parents=True, exist_ok=True)
    requested_steps = tuple(dict.fromkeys(selected_steps or ()))
    requested_step_set = set(requested_steps)

    candidates: list[dict[str, Any]] = []
    skipped = Counter()
    for step in sorted((root / "steps").iterdir()):
        if not step.is_dir():
            continue
        if requested_step_set and step.name not in requested_step_set:
            continue
        truth = _attack_truth(step)
        if not truth:
            skipped["missing_ground_truth"] += 1
            continue
        case_id = _case_id(seed, step.name)
        converted = _alert_from_step(step, case_id, store_id)
        if not converted:
            skipped["missing_detector_alert"] += 1
            continue
        alert, detector_events, primary_host, primary_host_ip = converted
        endpoint = _endpoint_evidence(step, primary_host)
        if require_endpoint and not endpoint:
            skipped["missing_endpoint_evidence"] += 1
            continue
        network = _suricata_events(step)
        capabilities = alert.raw_payload.setdefault("evidence_capabilities", [])
        if endpoint and "endpoint_logs" not in capabilities:
            capabilities.append("endpoint_logs")
        if network and "network_alerts" not in capabilities:
            capabilities.append("network_alerts")
        endpoint_targets = _endpoint_targets(detector_events, endpoint)
        network_targets = _network_targets(network)
        if endpoint_targets:
            primary_host = endpoint_targets[0]["host"]
            primary_host_ip = endpoint_targets[0]["ip"]
        observability = _observability(detector_events, endpoint, network)
        alert.raw_payload["query_targets"] = {
            "endpoint": endpoint_targets,
            "network_ips": network_targets,
        }
        alert.raw_payload["evidence_summary"] = {
            "detector_events": len(detector_events),
            "endpoint_records_available": len(endpoint),
            "network_alerts_available": len(network),
            "observability_score": observability["score"],
        }
        candidates.append(
            {
                "priority": _priority(seed, step.name),
                "observability": observability,
                "alert": alert,
                "truth": {**truth, "observability": observability},
                "evidence": {
                    "case_id": case_id,
                    "case_type": "correlated_attack_step",
                    "detector_event": detector_events[0],
                    "detector_events": detector_events,
                    "primary_host": primary_host,
                    "primary_host_ip": primary_host_ip,
                    "endpoint_targets": endpoint_targets,
                    "network_targets": network_targets,
                    "endpoint_logs": endpoint,
                    "network_alerts": network,
                    "observability": observability,
                    "coverage": {
                        "endpoint_records": len(endpoint),
                        "network_alerts": len(network),
                        "network_kind": "suricata_fast_alerts",
                        "netflow_available": False,
                    },
                },
            }
        )

    if requested_steps:
        by_step = {item["truth"]["step"]: item for item in candidates}
        missing = [step for step in requested_steps if step not in by_step]
        if missing:
            raise ValueError(f"Requested CAM-LDS steps are unavailable: {missing}")
        selected = [by_step[step] for step in requested_steps[:max_cases]]
    else:
        selected = _round_robin(candidates, max_cases)
    if not selected:
        raise ValueError("No CAM-LDS cases satisfied the pilot selection criteria")

    alerts: list[dict[str, Any]] = []
    truth: dict[str, dict[str, Any]] = {}
    index_cases: list[str] = []
    for item in selected:
        alert: Alert = item["alert"]
        case_id = alert.alert_id
        (store / f"{case_id}.json").write_text(
            json.dumps(item["evidence"], ensure_ascii=False, indent=2), encoding="utf-8"
        )
        alerts.append(alert.model_dump(mode="json", exclude={"label"}))
        truth[case_id] = item["truth"]
        index_cases.append(case_id)

    index = {
        "version": 2,
        "store_id": store_id,
        "cases": index_cases,
        "source_root": str(root),
        "contains_ground_truth": False,
    }
    (store / "index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    document = {
        "metadata": {
            "name": name or "CAM-LDS correlated attack-step pilot v2",
            "source": "CAM-LDS manifestations_filtered",
            "label_storage": "separated",
            "label_basis": "controlled_attack_step_case",
            "label_warning": (
                "CAM-LDS filtered contains attack manifestations without simulated benign "
                "user activity; use it for attack recall/evidence-fusion experiments, not as "
                "a standalone false-positive benchmark."
            ),
            "context_basis": "out_of_band_defender_logs",
            "evaluation_unit": "correlated_attack_step",
            "selection_basis": "defender_observability_ranked_with_scenario_round_robin",
            "schema_version": 2,
            "network_evidence": "suricata_fast_alerts_not_netflow",
            "seed": seed,
            "available_candidates": len(candidates),
            "selected_cases": len(selected),
            "explicit_step_selection": bool(requested_steps),
        },
        "alerts": alerts,
        "ground_truth": truth,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "output": str(output),
        "evidence_store": str(store),
        "samples": len(selected),
        "available_candidates": len(candidates),
        "scenarios": dict(Counter(item["truth"]["scenario"] for item in selected)),
        "with_endpoint": sum(bool(item["evidence"]["endpoint_logs"]) for item in selected),
        "with_network_alerts": sum(bool(item["evidence"]["network_alerts"]) for item in selected),
        "observability_score": {
            "min": min(item["observability"]["score"] for item in selected),
            "max": max(item["observability"]["score"] for item in selected),
            "average": round(
                sum(item["observability"]["score"] for item in selected) / len(selected), 2
            ),
        },
        "skipped": dict(skipped),
    }


def load_case_evidence(store_id: str, case_id: str) -> dict[str, Any] | None:
    """Load an evidence case using validated opaque identifiers only."""
    if not _SAFE_ID.fullmatch(store_id) or not _SAFE_ID.fullmatch(case_id):
        return None
    root = CAM_EVIDENCE_ROOT.resolve()
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
    store_id = payload.get("_evidence_store")
    case_id = payload.get("_evidence_ref")
    if not isinstance(store_id, str) or not isinstance(case_id, str):
        return None
    return load_case_evidence(store_id, case_id)


def _main() -> None:
    parser = argparse.ArgumentParser(description="Build a leakage-safe CAM-LDS pilot")
    parser.add_argument("--source", required=True, help="Extracted manifestations_filtered path")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--evidence-root", default=str(CAM_EVIDENCE_ROOT))
    parser.add_argument("--max-cases", type=int, default=40)
    parser.add_argument("--seed", type=int, default=20260722)
    parser.add_argument("--steps", nargs="+", default=None, help="Exact step directory names for a paired evaluation")
    parser.add_argument("--name", default=None, help="Dataset display name")
    parser.add_argument("--allow-without-endpoint", action="store_true")
    args = parser.parse_args()
    result = build_dataset(
        args.source,
        args.output,
        evidence_root=args.evidence_root,
        max_cases=args.max_cases,
        seed=args.seed,
        require_endpoint=not args.allow_without_endpoint,
        selected_steps=args.steps,
        name=args.name,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    _main()
