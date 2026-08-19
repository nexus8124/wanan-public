from __future__ import annotations

import csv
import json
from pathlib import Path

from app.agent.tools import (
    check_threat_intel,
    fetch_endpoint_logs,
    fetch_network_flows,
    inspect_alert_context,
)
from app.data.ton_iot import build_external_validation
from app.eval.dataset import load_eval_dataset


def _write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def test_builder_separates_truth_and_balances_modalities(tmp_path: Path):
    network = tmp_path / "network.csv"
    modbus = tmp_path / "modbus.csv"
    output = tmp_path / "external.json"
    _write_csv(
        network,
        ["src_ip", "src_port", "dst_ip", "dst_port", "proto", "service", "conn_state", "label", "type"],
        [
            {"src_ip": "10.0.0.1", "src_port": "1000", "dst_ip": "10.0.0.2", "dst_port": "80", "proto": "tcp", "service": "http", "conn_state": "SF", "label": "0", "type": "normal"},
            {"src_ip": "10.0.0.3", "src_port": "4444", "dst_ip": "10.0.0.4", "dst_port": "22", "proto": "tcp", "service": "ssh", "conn_state": "S0", "label": "1", "type": "backdoor"},
        ],
    )
    _write_csv(
        modbus,
        ["date", "time", "FC1_Read_Input_Register", "FC2_Read_Discrete_Value", "FC3_Read_Holding_Register", "FC4_Read_Coil", "label", "type"],
        [
            {"date": "31-Mar-19", "time": "12:00:00", "FC1_Read_Input_Register": "1", "FC2_Read_Discrete_Value": "2", "FC3_Read_Holding_Register": "3", "FC4_Read_Coil": "4", "label": "0", "type": "normal"},
            {"date": "31-Mar-19", "time": "12:00:01", "FC1_Read_Input_Register": "9", "FC2_Read_Discrete_Value": "8", "FC3_Read_Holding_Register": "7", "FC4_Read_Coil": "6", "label": "1", "type": "injection"},
        ],
    )

    result = build_external_validation(
        network, modbus, output, per_modality_class=1, reservoir_capacity=2
    )
    document = json.loads(output.read_text(encoding="utf-8"))

    assert result["samples"] == 4
    assert len(document["alerts"]) == len(document["ground_truth"]) == 4
    assert document["metadata"]["correlation_scope"] == "modality_coverage_not_cross_source_case_correlation"
    for alert in document["alerts"]:
        assert alert.get("label") is None
        observation = alert["raw_payload"]["observation"]
        assert "label" not in observation
        assert "type" not in observation
    loaded = load_eval_dataset(output)
    assert len(loaded.samples) == 4


def test_ton_iot_tools_use_real_embedded_records_not_demo_fixtures():
    network = {
        "src_ip": "10.0.0.3",
        "dst_ip": "10.0.0.4",
        "raw_payload": {
            "dataset": "TON-IOT-INDUSTRIAL",
            "modality": "network",
            "observation": {"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4", "proto": "tcp"},
            "query_targets": {"network_ips": ["10.0.0.3", "10.0.0.4"]},
            "correlation_scope": "same_source_record_not_cross_source_incident",
        },
    }
    telemetry = {
        "raw_payload": {
            "dataset": "TON-IOT-INDUSTRIAL",
            "modality": "modbus_telemetry",
            "observation": {"FC1_Read_Input_Register": "9"},
            "query_targets": {"endpoint": [{"host": "ton-iot-modbus", "ip": "ton-iot-modbus"}]},
            "correlation_scope": "same_source_record_not_cross_source_incident",
        },
    }

    assert inspect_alert_context(network)["data_source"] == "ton_iot_embedded_source_record"
    assert fetch_network_flows(network, "10.0.0.3")["data_source"] == "ton_iot_network_flow"
    assert fetch_network_flows(network, "10.0.0.3")["flow_count"] == 1
    endpoint = fetch_endpoint_logs(telemetry, "ton-iot-modbus")
    assert endpoint["data_source"] == "ton_iot_modbus_telemetry"
    assert endpoint["record_count"] == 1
    assert check_threat_intel(network, "185.220.101.34")["malicious"] is None
