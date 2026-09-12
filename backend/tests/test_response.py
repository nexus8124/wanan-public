from __future__ import annotations

from app.agent.graph import judge_alert
from app.agent.response import make_response_nodes
from app.core.config import Settings
from app.models.llm import get_llm
from app.operations import get_response_audit, record_alert_judgment


def _true_positive_alert() -> dict:
    return {
        "alert_id": "RESP-TP-001",
        "timestamp": "2026-09-10T08:00:00Z",
        "source": "edr",
        "severity": "high",
        "src_ip": "10.20.33.51",
        "dst_ip": "185.220.101.34",
        "rule_name": "Suspicious reverse shell to known C2",
        "description": "powershell.exe reverse shell to known C2 server",
    }


def test_true_positive_runs_execute_observe_closed_loop():
    result = judge_alert(
        _true_positive_alert(),
        llm=get_llm(mock=True),
        enable_react=False,
    )

    assert result["response_used"] is True
    assert result["containment_verified"] is True
    assert result["response_execution"]["status"] == "contained"
    assert result["response_execution"]["attempt"] == 1
    assert {item["action"] for item in result["response_execution"]["actions"]} == {
        "block_ip",
        "isolate_host",
    }
    assert all(item["verified"] for item in result["response_execution"]["actions"])


def test_failed_action_is_replanned_and_retried_once():
    alert = _true_positive_alert()
    alert["raw_payload"] = {
        "response_simulation": {"fail_once_actions": ["isolate_host"]}
    }

    result = judge_alert(alert, llm=get_llm(mock=True), enable_react=False)

    assert result["response_execution"]["status"] == "contained"
    assert result["response_execution"]["attempt"] == 2
    phases = [item["phase"] for item in result["response_trace"]]
    assert phases == ["execute", "observe", "execute", "observe"]


def test_unverified_atomic_response_rolls_back_after_retry_budget():
    alert = _true_positive_alert()
    alert["raw_payload"] = {
        "response_simulation": {
            "verification_fail_actions": ["isolate_host"],
        }
    }

    result = judge_alert(alert, llm=get_llm(mock=True), enable_react=False)

    assert result["containment_verified"] is False
    assert result["response_execution"]["status"] == "rolled_back"
    assert result["response_execution"]["attempt"] == 2
    assert all(
        item["rollback"]["rolled_back"]
        for item in result["response_execution"]["actions"]
        if item.get("executed")
    )
    assert result["response_trace"][-1]["phase"] == "rollback"


def test_live_connector_is_blocked_for_public_evaluation_data():
    settings = Settings(
        _env_file=None,
        RESPONSE_EXECUTION_MODE="webhook",
        RESPONSE_LIVE_ENABLED=True,
        RESPONSE_FIREWALL_WEBHOOK="https://security.invalid/firewall",
        RESPONSE_EDR_WEBHOOK="https://security.invalid/edr",
    )
    execute_node, _, _ = make_response_nodes(settings)
    alert = _true_positive_alert()
    alert["raw_payload"] = {"dataset": "AIT-ADS-EVENT-GOLD"}
    state = {
        "alert": alert,
        "judgment": "真阳",
        "confidence": 0.99,
        "cited_evidence": ["EV-test"],
        "response_plan": [{
            "action_id": "BLK-test",
            "action": "block_ip",
            "target": alert["dst_ip"],
            "reason": "test",
        }],
    }

    update = execute_node(state)

    assert update["response_execution"]["status"] == "skipped"
    assert "正式评测数据" in update["response_execution"]["reason"]


def test_response_receipts_are_persisted_in_audit_log(tmp_path):
    alert = _true_positive_alert()
    result = judge_alert(alert, llm=get_llm(mock=True), enable_react=False)
    db_path = tmp_path / "operations.db"

    record_alert_judgment(alert, result, db_path=db_path)
    audit = get_response_audit(db_path=db_path)

    assert audit["count"] == 1
    assert audit["records"][0]["alert_id"] == alert["alert_id"]
    assert audit["records"][0]["status"] == "contained"
    assert len(audit["records"][0]["actions"]) == 2
