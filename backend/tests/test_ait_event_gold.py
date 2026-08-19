from __future__ import annotations

import json
from pathlib import Path

from app.agent.tools import execute_tool
from app.data import ait_event_gold
from app.data.ait_event_gold import OfficialAlertRow, parse_official_row
from app.eval.metrics import compute_metrics


def test_official_row_parser_handles_unquoted_description_commas():
    row = parse_official_row(
        "1640000000,Wazuh: rule, with, commas,10.0.0.5,mail,W-Test,dirb,dirb\n",
        "fox",
        1,
    )
    assert row.name == "Wazuh: rule, with, commas"
    assert row.ip == "10.0.0.5"
    assert row.binary_label == "真阳"


def test_event_and_time_must_agree_for_binary_gold():
    base = dict(
        scenario="fox",
        ordinal=1,
        epoch=1640000000,
        name="Wazuh: test",
        ip="10.0.0.5",
        host="mail",
        short="W-Test",
    )
    assert OfficialAlertRow(**base, time_label="dirb", event_label="dirb").binary_label == "真阳"
    assert OfficialAlertRow(**base, time_label="false_positive", event_label="-").binary_label == "假阳"
    assert OfficialAlertRow(**base, time_label="dirb", event_label="-").binary_label is None
    assert OfficialAlertRow(
        **base, time_label="false_positive", event_label="dnsteal"
    ).binary_label is None


def test_case_identity_deduplicates_same_rule_host_and_minute():
    base = dict(
        scenario="fox",
        ordinal=1,
        name="Suricata: test",
        ip="10.0.0.5",
        host="mail",
        short="S-Test",
        time_label="dirb",
        event_label="dirb",
    )
    first = OfficialAlertRow(**base, epoch=120)
    second = OfficialAlertRow(**{**base, "ordinal": 2}, epoch=159)
    third = OfficialAlertRow(**{**base, "ordinal": 3}, epoch=181)
    assert ait_event_gold._case_identity(first) == ait_event_gold._case_identity(second)
    assert ait_event_gold._case_identity(first) != ait_event_gold._case_identity(third)


def test_event_gold_out_of_band_evidence_is_queryable(monkeypatch, tmp_path: Path):
    root = tmp_path / "evidence"
    store = root / "event-gold-v1-test"
    store.mkdir(parents=True)
    case_id = "case-1"
    evidence = {
        "dataset": "AIT-ADS-EVENT-GOLD",
        "detector_event": {"detector": "wazuh", "rule_name": "Wazuh: test"},
        "detector_events": [{"detector": "wazuh", "rule_name": "Wazuh: test"}],
        "coverage": {"endpoint_records": 1, "network_alerts": 1},
        "primary_host": "mail",
        "primary_host_ip": "10.0.0.5",
        "endpoint_targets": [{"host": "mail", "ip": "10.0.0.5"}],
        "network_targets": ["10.0.0.5"],
        "endpoint_logs": [{"host": "mail", "host_ip": "10.0.0.5", "source": "edr"}],
        "network_alerts": [{"src_ip": "10.0.0.5", "dst_ip": None, "rule_name": "S test"}],
    }
    (store / f"{case_id}.json").write_text(json.dumps(evidence), encoding="utf-8")
    monkeypatch.setattr(ait_event_gold, "DEFAULT_EVIDENCE_ROOT", root)
    alert = {
        "alert_id": case_id,
        "raw_payload": {
            "dataset": "AIT-ADS-EVENT-GOLD",
            "_evidence_store": "event-gold-v1-test",
            "_evidence_ref": case_id,
        },
    }

    context = execute_tool("inspect_alert_context", alert, {})
    endpoint = execute_tool("fetch_endpoint_logs", alert, {"host_ip": "10.0.0.5"})
    network = execute_tool(
        "fetch_network_flows", alert, {"host_ip": "10.0.0.5", "window_min": 30}
    )

    assert context["status"] == "found"
    assert context["evidence"][0]["data"]["dataset"] == "AIT-ADS-EVENT-GOLD"
    assert endpoint["status"] == "found"
    assert endpoint["evidence"][0]["data"]["record_count"] == 1
    assert network["status"] == "found"
    assert network["evidence"][0]["data"]["alert_count"] == 1


def test_credible_85_gate_uses_total_accuracy_and_wilson_bound():
    passing = compute_metrics([("真阳", "真阳")] * 440 + [("假阳", "假阳")] * 440 + [("真阳", "假阳")] * 60 + [("假阳", "真阳")] * 60)
    gate = passing.as_dict()["credible_85_gate"]
    assert passing.accuracy == 0.88
    assert passing.accuracy_wilson_95_lower >= 0.85
    assert gate["passed"] is True

    selective_only = compute_metrics(
        [("真阳", "真阳")] * 425
        + [("假阳", "假阳")] * 425
        + [("真阳", "待查")] * 75
        + [("假阳", "待查")] * 75
    )
    assert selective_only.selective_accuracy == 1.0
    assert selective_only.accuracy == 0.85
    assert selective_only.as_dict()["credible_85_gate"]["passed"] is False
