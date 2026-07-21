"""SQLite 评测历史存储。

每条样本完成后立即独立提交，确保浏览器中断、模型异常或服务重启时，
已经完成的结果仍可恢复查看。
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DB_PATH = Path(__file__).resolve().parent.parent / "data" / "eval_history.db"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS eval_runs (
                id TEXT PRIMARY KEY,
                mode TEXT NOT NULL,
                dataset TEXT NOT NULL,
                status TEXT NOT NULL,
                total INTEGER NOT NULL,
                completed INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                metrics_json TEXT,
                error TEXT
            );

            CREATE TABLE IF NOT EXISTS eval_samples (
                run_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                alert_id TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (run_id, seq),
                FOREIGN KEY (run_id) REFERENCES eval_runs(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_eval_runs_started
                ON eval_runs(started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_eval_samples_run
                ON eval_samples(run_id, seq);
            """
        )


def mark_stale_runs_interrupted() -> None:
    """服务重启后，将未正常收尾的 running 记录标记为中断。"""
    init_db()
    with _connect() as conn:
        conn.execute(
            """
            UPDATE eval_runs
            SET status = 'interrupted', finished_at = COALESCE(finished_at, ?),
                error = COALESCE(error, '服务重启或进程退出，评测未完整结束')
            WHERE status = 'running'
            """,
            (_now(),),
        )


def create_run(*, mode: str, dataset: str, total: int) -> str:
    init_db()
    run_id = uuid.uuid4().hex
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO eval_runs
                (id, mode, dataset, status, total, completed, started_at)
            VALUES (?, ?, ?, 'running', ?, 0, ?)
            """,
            (run_id, mode, dataset, total, _now()),
        )
    return run_id


def save_progress(run_id: str, progress: dict[str, Any]) -> None:
    """原子保存一条样本和该时刻的累计指标。"""
    detail = progress["detail"]
    completed = int(progress["completed"])
    with _connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO eval_samples
                (run_id, seq, alert_id, detail_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                run_id,
                completed,
                str(detail.get("alert_id", "")),
                json.dumps(detail, ensure_ascii=False, default=str),
                _now(),
            ),
        )
        conn.execute(
            """
            UPDATE eval_runs
            SET completed = ?, metrics_json = ?
            WHERE id = ?
            """,
            (
                completed,
                json.dumps(progress.get("metrics", {}), ensure_ascii=False),
                run_id,
            ),
        )


def finish_run(
    run_id: str,
    *,
    status: str,
    metrics: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    with _connect() as conn:
        conn.execute(
            """
            UPDATE eval_runs
            SET status = ?, finished_at = ?,
                metrics_json = COALESCE(?, metrics_json), error = ?
            WHERE id = ?
            """,
            (
                status,
                _now(),
                json.dumps(metrics, ensure_ascii=False) if metrics is not None else None,
                error,
                run_id,
            ),
        )


def _decode_run(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["metrics"] = json.loads(data.pop("metrics_json") or "null")
    return data


def list_runs(limit: int = 50) -> list[dict[str, Any]]:
    init_db()
    safe_limit = max(1, min(int(limit), 200))
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM eval_runs ORDER BY started_at DESC LIMIT ?",
            (safe_limit,),
        ).fetchall()
    return [_decode_run(row) for row in rows]


def get_run(run_id: str) -> dict[str, Any] | None:
    init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM eval_runs WHERE id = ?", (run_id,)
        ).fetchone()
        if row is None:
            return None
        sample_rows = conn.execute(
            """
            SELECT detail_json FROM eval_samples
            WHERE run_id = ? ORDER BY seq ASC
            """,
            (run_id,),
        ).fetchall()

    result = _decode_run(row)
    result["details"] = [json.loads(item["detail_json"]) for item in sample_rows]
    return result


def delete_run(run_id: str) -> str:
    """删除非运行中的历史；返回 deleted/not_found/running。"""
    init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT status FROM eval_runs WHERE id = ?", (run_id,)
        ).fetchone()
        if row is None:
            return "not_found"
        if row["status"] == "running":
            return "running"
        conn.execute("DELETE FROM eval_runs WHERE id = ?", (run_id,))
    return "deleted"
