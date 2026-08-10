from app import operations
from app.eval import history


def _alert(alert_id: str, *, source: str = "edr") -> dict:
    return {
        "alert_id": alert_id,
        "timestamp": "2026-08-09T08:00:00Z",
        "source": source,
        "severity": "high",
        "rule_name": "Suspicious process execution",
        "description": "test alert",
    }


def _result(alert_id: str, judgment: str, confidence: float = 0.9) -> dict:
    return {
        "alert_id": alert_id,
        "judgment": judgment,
        "confidence": confidence,
        "reason": "test result",
    }


def test_snapshot_deduplicates_alerts_and_tracks_latest_quality(tmp_path):
    db_path = tmp_path / "operations.db"
    operations.record_alert_judgment(
        _alert("ALERT-001"),
        _result("ALERT-001", "假阳", 0.7),
        truth_label="真阳",
        db_path=db_path,
    )
    operations.record_alert_judgment(
        _alert("ALERT-001"),
        _result("ALERT-001", "真阳", 0.96),
        truth_label="真阳",
        db_path=db_path,
    )
    operations.record_alert_judgment(
        _alert("ALERT-002", source="ndr"),
        _result("ALERT-002", "待查", 0.52),
        db_path=db_path,
    )

    snapshot = operations.get_operations_snapshot(db_path)

    assert snapshot["total_alerts"] == 2
    assert snapshot["confirmed_threats"] == 1
    assert snapshot["pending_review"] == 1
    assert snapshot["misjudgments"] == 0
    assert snapshot["labeled_alerts"] == 1
    assert snapshot["accuracy"] == 1.0
    assert snapshot["by_source"] == {"edr": 1, "ndr": 1}


def test_snapshot_includes_persisted_evaluation_samples(tmp_path, monkeypatch):
    db_path = tmp_path / "eval_history.db"
    monkeypatch.setattr(history, "DB_PATH", db_path)
    run_id = history.create_run(mode="mock", dataset="test.json", total=1)
    history.save_progress(
        run_id,
        {
            "completed": 1,
            "metrics": {},
            "detail": {
                "alert_id": "EVAL-001",
                "label": "假阳",
                "pred": "真阳",
                "confidence": 0.84,
                "correct": False,
                "reason": "test misjudgment",
                "alert": {
                    **_alert("EVAL-001", source="waf"),
                    "severity": "medium",
                },
            },
        },
    )

    snapshot = operations.get_operations_snapshot(db_path)

    assert snapshot["total_alerts"] == 1
    assert snapshot["confirmed_threats"] == 1
    assert snapshot["misjudgments"] == 1
    assert snapshot["accuracy"] == 0.0
    assert snapshot["recent_events"][0]["channel"] == "evaluation"
