"""SQLite 评测历史持久化测试。"""

from __future__ import annotations

from app.eval import history


def test_history_persists_partial_interrupted_run(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "eval_history.db")

    run_id = history.create_run(
        mode="deepseek", strategy="judge_only", dataset="eval_alerts.json", total=50
    )
    for i in range(1, 3):
        history.save_progress(
            run_id,
            {
                "completed": i,
                "total": 50,
                "metrics": {"n": i, "accuracy": 1.0, "f1": 1.0},
                "initial_metrics": {"n": i, "accuracy": 0.5},
                "paired_react": {"fixes": 1, "regressions": 0},
                "experiment_config": {"prompt_version": "test-v1"},
                "detail": {
                    "alert_id": f"TP-{i:03d}",
                    "pred": "真阳",
                    "agent_result": {"cot_trace": ["证据摘要"]},
                },
            },
        )
    history.save_event(
        run_id,
        {
            "type": "tool_completed",
            "alert_id": "TP-001",
            "tool": "check_threat_intel",
        },
    )

    history.finish_run(
        run_id,
        status="interrupted",
        metrics={"n": 2, "accuracy": 1.0, "f1": 1.0},
        initial_metrics={"n": 2, "accuracy": 0.5},
        paired_react={"fixes": 1, "regressions": 0},
        error="用户中止",
    )

    saved = history.get_run(run_id)
    assert saved is not None
    assert saved["status"] == "interrupted"
    assert saved["completed"] == 2
    assert len(saved["details"]) == 2
    assert saved["strategy"] == "judge_only"
    assert saved["experiment_config"]["prompt_version"] == "test-v1"
    assert saved["initial_metrics"]["accuracy"] == 0.5
    assert saved["paired_react"]["fixes"] == 1
    assert saved["details"][0]["agent_result"]["cot_trace"] == ["证据摘要"]
    assert saved["events"][0]["type"] == "tool_completed"
    assert saved["events"][0]["event_seq"] == 1

    summaries = history.list_runs()
    assert summaries[0]["id"] == run_id
    assert summaries[0]["metrics"]["n"] == 2

    assert history.delete_run(run_id) == "deleted"
    assert history.get_run(run_id) is None


def test_running_history_cannot_be_deleted(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "eval_history.db")
    run_id = history.create_run(mode="mock", dataset="eval_alerts.json", total=50)
    assert history.delete_run(run_id) == "running"


def test_stale_running_history_becomes_interrupted(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "eval_history.db")
    run_id = history.create_run(mode="mock", dataset="eval_alerts.json", total=50)

    history.mark_stale_runs_interrupted()

    saved = history.get_run(run_id)
    assert saved is not None
    assert saved["status"] == "interrupted"
