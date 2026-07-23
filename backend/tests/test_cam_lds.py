from __future__ import annotations

import json

from app.agent.nodes import _agent_visible_alert, _normalize_multisource_action
from app.agent.graph import _judge_router, _react_router
from app.agent.tools import execute_tool
from app.data import cam_lds as cam_module
from app.data.cam_lds import build_dataset
from app.eval.dataset import load_eval_dataset


def _write_fixture(root):
    step = root / "steps" / "1_variant-13"
    attackmate = step / "attacker" / "logs"
    attackmate.mkdir(parents=True)
    attackmate_record = {
        "start-datetime": "2025-09-22T18:37:00",
        "type": "shell",
        "cmd": "secret attacker command",
        "parameters": {
            "metadata": {
                "techniques": "T1057,T1083",
                "tactics": "Discovery",
                "technique_name": "Process Discovery,File and Directory Discovery",
            }
        },
    }
    (attackmate / "attackmate.json").write_text(
        json.dumps(attackmate_record) + "\n", encoding="utf-8"
    )

    wazuh = step / "wazuh" / "logs" / "alerts"
    wazuh.mkdir(parents=True)
    wazuh_record = {
        "timestamp": "2025-09-22T18:37:00.601+00:00",
        "rule": {
            "level": 9,
            "description": "Processes queried with ps command",
            "id": "92604",
            "mitre": {"id": ["T1057"], "tactic": ["Discovery"]},
            "groups": ["audit_detections"],
        },
        "agent": {"id": "002", "name": "videoserver", "ip": "172.17.100.121"},
        "full_log": 'type=SYSCALL comm="ps" exe="/usr/bin/ps"',
        "data": {"audit": {"command": "ps"}},
        "location": "/var/log/audit/audit.log",
    }
    (wazuh / "alerts.json").write_text(
        json.dumps(wazuh_record) + "\n", encoding="utf-8"
    )

    audit = step / "videoserver" / "logs" / "log" / "audit"
    audit.mkdir(parents=True)
    (audit / "audit.log").write_text(
        'type=SYSCALL syscall=59 ppid=3135 pid=3136 comm="ps" exe="/usr/bin/ps"\n'
        'type=EXECVE argc=2 a0="ps" a1="auxwww"\n',
        encoding="utf-8",
    )

    suricata = step / "inetfw" / "logs" / "log" / "suricata"
    suricata.mkdir(parents=True)
    (suricata / "fast.log").write_text(
        "09/22/2025-18:41:46.240463  [**] [1:2037838:1] ET SCAN Web Scanner "
        "[**] [Classification: Web Application Attack] [Priority: 2] {TCP} "
        "192.42.1.174:33600 -> 172.17.100.121:80\n",
        encoding="utf-8",
    )


def test_cam_lds_builds_out_of_band_evidence_without_truth_leakage(tmp_path, monkeypatch):
    source = tmp_path / "manifestations_filtered"
    _write_fixture(source)
    output = tmp_path / "cam_eval.json"
    evidence_root = tmp_path / "evidence"
    monkeypatch.setattr(cam_module, "CAM_EVIDENCE_ROOT", evidence_root)

    summary = build_dataset(
        source,
        output,
        evidence_root=evidence_root,
        max_cases=1,
        seed=7,
        selected_steps=["1_variant-13"],
        name="Paired fixture",
    )

    assert summary["samples"] == 1
    assert summary["with_endpoint"] == 1
    assert summary["with_network_alerts"] == 1
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["metadata"]["name"] == "Paired fixture"
    assert document["metadata"]["explicit_step_selection"] is True
    alert = document["alerts"][0]
    alert_id = alert["alert_id"]
    assert alert_id in document["ground_truth"]
    assert document["ground_truth"][alert_id]["techniques"] == ["T1057", "T1083"]
    assert "label" not in alert
    assert not alert_id.startswith(("TP", "FP"))

    evidence_file = evidence_root / "pilot-7" / f"{alert_id}.json"
    serialized_evidence = evidence_file.read_text(encoding="utf-8")
    assert "secret attacker command" not in serialized_evidence
    assert '"label"' not in serialized_evidence
    assert '"techniques"' not in serialized_evidence

    visible = _agent_visible_alert(alert)
    assert "_evidence_ref" not in visible["raw_payload"]
    assert "_evidence_store" not in visible["raw_payload"]
    assert set(visible["raw_payload"]["evidence_capabilities"]) == {
        "detector_context", "endpoint_logs", "network_alerts"
    }
    assert visible["raw_payload"]["detector"] == "correlated_case"
    assert len(visible["raw_payload"]["detector_events"]) == 2
    assert visible["raw_payload"]["query_targets"]["endpoint"] == [
        {"host": "videoserver", "ip": "172.17.100.121"}
    ]

    loaded = load_eval_dataset(output)
    assert loaded.samples[0].label == "真阳"
    assert loaded.samples[0].alert.label is None

    context = execute_tool("inspect_alert_context", alert, {})
    assert context["status"] == "found"
    assert context["evidence"][0]["data"]["source_available"] is True
    assert context["evidence"][0]["data"]["recommended_queries"][
        "fetch_endpoint_logs"
    ] == {"host_ip": "172.17.100.121"}

    endpoint = execute_tool(
        "fetch_endpoint_logs", alert, {"host_ip": "172.17.100.121"}
    )
    endpoint_data = endpoint["evidence"][0]["data"]
    assert endpoint["status"] == "found"
    assert endpoint_data["data_source"] == "cam_lds_endpoint_logs"
    assert endpoint_data["record_count"] == 2
    assert "EXECVE" in json.dumps(endpoint_data["records"])
    wrong_host = execute_tool(
        "fetch_endpoint_logs", alert, {"host_ip": "192.42.1.174"}
    )
    assert wrong_host["status"] == "not_found"

    network = execute_tool(
        "fetch_network_flows", alert, {"host_ip": "172.17.100.121"}
    )
    network_data = network["evidence"][0]["data"]
    assert network["status"] == "found"
    assert network_data["netflow_available"] is False
    assert network_data["network_evidence_kind"] == "suricata_fast_alerts"
    assert network_data["alert_count"] == 1
    unrelated_network = execute_tool(
        "fetch_network_flows", alert, {"host_ip": "10.255.255.254"}
    )
    assert unrelated_network["status"] == "not_found"


def test_multisource_case_requires_one_independent_evidence_query():
    alert = {
        "raw_payload": {
            "_evidence_store": "pilot-7",
            "_evidence_ref": "case-1",
            "evidence_capabilities": ["detector_context", "endpoint_logs"],
            "query_targets": {
                "endpoint": [{"host": "server", "ip": "10.0.0.1"}],
                "network_ips": [],
            },
        }
    }
    assert _judge_router(
        {"alert": alert, "judgment": "真阳", "confidence": 0.99}
    ) == "react_decide"

    after_context = {
        "alert": alert,
        "confidence": 0.99,
        "execution_policy": {"max_steps": 3},
        "next_action": {"tool": "fetch_endpoint_logs", "args": {"host_ip": "10.0.0.1"}},
        "react_steps": [
            {"tool": "inspect_alert_context", "args": {}, "result": {"status": "found"}}
        ],
    }
    assert _react_router(after_context) == "tool_executor"

    after_endpoint = {
        **after_context,
        "next_action": None,
        "react_steps": after_context["react_steps"]
        + [
            {"tool": "fetch_endpoint_logs", "args": {"host_ip": "10.0.0.1"},
             "result": {"status": "found"}}
        ],
    }
    assert _react_router(after_endpoint) == "disposition"


def test_multisource_action_uses_real_capabilities_and_targets():
    alert = {
        "raw_payload": {
            "_evidence_store": "pilot-7",
            "_evidence_ref": "case-1",
            "evidence_capabilities": [
                "detector_context", "endpoint_logs", "network_alerts"
            ],
            "query_targets": {
                "endpoint": [{"host": "server", "ip": "10.0.0.5"}],
                "network_ips": ["10.0.0.5", "10.0.0.8"],
            },
        }
    }
    assert _normalize_multisource_action(
        alert, [], {"tool": "check_threat_intel", "args": {"indicator": "x"}}
    ) == {"tool": "inspect_alert_context", "args": {}}
    assert _normalize_multisource_action(
        alert,
        [{"tool": "inspect_alert_context"}],
        {"tool": "fetch_endpoint_logs", "args": {"host_ip": "wrong"}},
    ) == {"tool": "fetch_endpoint_logs", "args": {"host_ip": "10.0.0.5"}}
    assert _normalize_multisource_action(
        alert,
        [{"tool": "inspect_alert_context"}, {"tool": "fetch_endpoint_logs"}],
        {"tool": "query_similar_alerts", "args": {"rule_name": "x"}},
    ) == {
        "tool": "fetch_network_flows",
        "args": {"host_ip": "10.0.0.5", "window_min": 30},
    }
