from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.agent.tools import execute_tool
from app.api import stats as stats_api
from app.data.ait_ads import build_dataset, load_attack_windows
from app.eval import dataset as dataset_module
from app.eval.dataset import (
    list_eval_datasets,
    load_eval_dataset,
    resolve_eval_dataset_path,
    select_eval_dataset,
)
from app.main import app


def _wazuh_record(epoch: float, event_id: str) -> dict:
    return {
        "@timestamp": datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(),
        "id": event_id,
        "agent": {"ip": "10.0.0.5", "name": "host-1"},
        "rule": {
            "id": "1001",
            "level": 8,
            "description": "Test detector rule",
            "groups": ["audit"],
        },
        "location": "/var/log/audit/audit.log",
        "full_log": f"test security event {event_id}",
    }


def test_build_dataset_separates_ground_truth(tmp_path):
    source = tmp_path / "raw"
    source.mkdir()
    labels = tmp_path / "labels.csv"
    labels.write_text(
        "scenario,attack,start,end\nfox,network_scans,1000,1100\n",
        encoding="utf-8",
    )
    records = [_wazuh_record(1050, "attack"), _wazuh_record(900, "background")]
    (source / "fox_wazuh.json").write_text(
        "\n".join(json.dumps(item) for item in records) + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "eval.json"

    summary = build_dataset(
        source,
        labels,
        output,
        per_class=1,
        scenarios=["fox"],
        detectors=["wazuh"],
    )

    assert summary["samples"] == 2
    document = json.loads(output.read_text(encoding="utf-8"))
    assert all("label" not in alert for alert in document["alerts"])
    assert all(not alert["alert_id"].startswith(("TP", "FP")) for alert in document["alerts"])
    assert {entry["label"] for entry in document["ground_truth"].values()} == {"真阳", "假阳"}
    assert document["metadata"]["label_basis"] == "time_window_weak"
    assert document["metadata"]["context_basis"] == "label_free_raw_detector_neighborhood"
    for alert in document["alerts"]:
        context = alert["raw_payload"]["temporal_context"]
        assert context["detector_event_count"] >= 1
        assert context["same_rule_count"] >= 1
        serialized_context = json.dumps(context, ensure_ascii=False)
        assert "真阳" not in serialized_context and "假阳" not in serialized_context
        assert "attack_phase" not in serialized_context

    evidence = execute_tool("inspect_alert_context", document["alerts"][0], {})
    assert evidence["status"] == "found"
    assert evidence["evidence"][0]["data"]["temporal_context"]["detector_event_count"] >= 1

    endpoint = execute_tool(
        "fetch_endpoint_logs",
        document["alerts"][0],
        {"host_ip": document["alerts"][0].get("src_ip") or "unknown"},
    )
    assert endpoint["status"] == "not_found"
    assert endpoint["evidence"][0]["usable"] is False
    assert "temporal_context" not in endpoint["evidence"][0]["data"]

    loaded = load_eval_dataset(output)
    assert len(loaded.samples) == 2
    assert all(sample.alert.label is None for sample in loaded.samples)
    assert {sample.label for sample in loaded.samples} == {"真阳", "假阳"}


def test_load_attack_windows_requires_official_file(tmp_path):
    with pytest.raises(FileNotFoundError, match="labels.csv"):
        load_attack_windows(tmp_path / "missing-labels.csv")


def test_mock_tool_result_does_not_depend_on_alert_id_prefix():
    base = {
        "src_ip": "10.20.33.51",
        "dst_ip": "185.220.101.34",
        "description": "same observable event",
    }
    tp_named = execute_tool(
        "fetch_endpoint_logs", {**base, "alert_id": "TP-LEAK"}, {"host_ip": "10.20.33.51"}
    )
    fp_named = execute_tool(
        "fetch_endpoint_logs", {**base, "alert_id": "FP-LEAK"}, {"host_ip": "10.20.33.51"}
    )
    assert tp_named["status"] == fp_named["status"]
    assert tp_named["summary"] == fp_named["summary"]
    assert tp_named["evidence"][0]["data"] == fp_named["evidence"][0]["data"]


def test_unknown_host_returns_no_records_instead_of_invented_normality():
    result = execute_tool(
        "fetch_endpoint_logs",
        {"alert_id": "c80d604f-1bd8-4af5-84ce-181e745fd6fc"},
        {"host_ip": "172.17.0.99"},
    )
    assert result["status"] == "not_found"
    assert result["evidence"][0]["data"]["status"] == "no_records"
    assert result["evidence"][0]["data"]["suspicious_processes"] == []


def _separated_dataset_document() -> dict:
    alert = _wazuh_record(1050, "uploaded")
    raw_line = json.dumps(alert)
    from app.data.ait_ads import convert_record

    converted, _ = convert_record(alert, "fox", "wazuh", raw_line)
    alert_data = converted.model_dump(mode="json", exclude={"label"})
    return {
        "metadata": {"name": "Uploaded test set", "label_storage": "separated"},
        "alerts": [alert_data],
        "ground_truth": {converted.alert_id: {"label": "真阳", "label_basis": "test"}},
    }


def _isolate_dataset_storage(monkeypatch, tmp_path):
    processed = tmp_path / "processed"
    uploaded = tmp_path / "uploaded"
    selection = tmp_path / "active.json"
    monkeypatch.setattr(dataset_module, "PROCESSED_DATASET_DIR", processed)
    monkeypatch.setattr(dataset_module, "UPLOADED_DATASET_DIR", uploaded)
    monkeypatch.setattr(dataset_module, "DATASET_SELECTION_FILE", selection)
    monkeypatch.setattr(stats_api, "UPLOADED_DATASET_DIR", uploaded)
    return processed, uploaded, selection


def test_dataset_catalog_selection_persists(monkeypatch, tmp_path):
    processed, _, selection = _isolate_dataset_storage(monkeypatch, tmp_path)
    processed.mkdir()
    path = processed / "pilot.json"
    path.write_text(json.dumps(_separated_dataset_document()), encoding="utf-8")

    catalog = list_eval_datasets()
    assert any(item["id"] == "processed:pilot.json" for item in catalog["datasets"])

    selected = select_eval_dataset("processed:pilot.json")
    assert selected["active"] is True
    assert selected["count"] == 1
    assert selection.exists()
    assert resolve_eval_dataset_path() == path.resolve()


def test_upload_endpoint_validates_and_selects_dataset(monkeypatch, tmp_path):
    _, uploaded, selection = _isolate_dataset_storage(monkeypatch, tmp_path)
    client = TestClient(app)
    payload = json.dumps(_separated_dataset_document()).encode()

    response = client.post(
        "/api/eval/datasets/upload?filename=my-eval.json",
        content=payload,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["dataset"]["count"] == 1
    assert body["dataset"]["id"].startswith("uploaded:my-eval-")
    assert len(list(uploaded.glob("*.json"))) == 1
    assert selection.exists()


def test_upload_endpoint_rejects_jsonl(monkeypatch, tmp_path):
    _isolate_dataset_storage(monkeypatch, tmp_path)
    client = TestClient(app)
    response = client.post(
        "/api/eval/datasets/upload?filename=raw.json",
        content=b'{"one": 1}\n{"two": 2}\n',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert "Invalid evaluation dataset" in response.text
