"""Operational alert history and dashboard aggregation.

The dashboard deliberately reports processed alerts rather than the contents of
an evaluation dataset.  Interactive judgments are persisted here, while batch
evaluation samples are read from the existing evaluation history tables.  The
latest record for each alert ID wins so repeated investigations do not inflate
the headline total.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


DEFAULT_DB_PATH = Path(__file__).resolve().parent / "data" / "eval_history.db"
VALID_JUDGMENTS = {"真阳", "假阳", "待查"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_operations_db(db_path: Path = DEFAULT_DB_PATH) -> None:
    with _connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alert_judgments (
                id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                channel TEXT NOT NULL,
                judgment TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 0,
                truth_label TEXT,
                correct INTEGER,
                alert_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_alert_judgments_created
                ON alert_judgments(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_alert_judgments_alert
                ON alert_judgments(alert_id, created_at DESC);
            """
        )


def record_alert_judgment(
    alert: dict[str, Any],
    result: dict[str, Any],
    *,
    truth_label: str | None = None,
    channel: str = "interactive",
    db_path: Path = DEFAULT_DB_PATH,
) -> str:
    """Persist one completed interactive judgment and return its event ID."""
    init_operations_db(db_path)
    event_id = uuid.uuid4().hex
    alert_id = str(result.get("alert_id") or alert.get("alert_id") or event_id)
    judgment = str(result.get("judgment") or "待查")
    if judgment not in VALID_JUDGMENTS:
        judgment = "待查"
    normalized_truth = truth_label if truth_label in VALID_JUDGMENTS else None
    correct = None if normalized_truth is None else int(normalized_truth == judgment)
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO alert_judgments
                (id, alert_id, channel, judgment, confidence, truth_label,
                 correct, alert_json, result_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                alert_id,
                channel,
                judgment,
                float(result.get("confidence") or 0),
                normalized_truth,
                correct,
                json.dumps(alert, ensure_ascii=False, default=str),
                json.dumps(result, ensure_ascii=False, default=str),
                _now(),
            ),
        )
    return event_id


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone()
    return row is not None


def _interactive_records(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT rowid AS ordinal, * FROM alert_judgments ORDER BY created_at, rowid"
    ).fetchall()
    records: list[dict[str, Any]] = []
    for row in rows:
        alert = json.loads(row["alert_json"] or "{}")
        result = json.loads(row["result_json"] or "{}")
        records.append(
            {
                "alert_id": row["alert_id"],
                "judgment": row["judgment"],
                "confidence": float(row["confidence"] or 0),
                "truth_label": row["truth_label"],
                "correct": None if row["correct"] is None else bool(row["correct"]),
                "source": str(alert.get("source") or "unknown").lower(),
                "severity": str(alert.get("severity") or "unknown").lower(),
                "rule_name": str(alert.get("rule_name") or "未命名告警"),
                "reason": str(result.get("reason") or ""),
                "channel": row["channel"],
                "observed_at": row["created_at"],
                "ordinal": int(row["ordinal"]),
            }
        )
    return records


def _evaluation_records(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    if not _table_exists(conn, "eval_samples"):
        return []
    rows = conn.execute(
        """
        SELECT rowid AS ordinal, alert_id, detail_json, created_at
        FROM eval_samples ORDER BY created_at, rowid
        """
    ).fetchall()
    records: list[dict[str, Any]] = []
    for row in rows:
        try:
            detail = json.loads(row["detail_json"] or "{}")
        except json.JSONDecodeError:
            continue
        alert = detail.get("alert") or {}
        pred = str(detail.get("pred") or "待查")
        if pred not in VALID_JUDGMENTS:
            pred = "待查"
        truth = detail.get("label")
        if truth not in VALID_JUDGMENTS:
            truth = None
        correct_value = detail.get("correct")
        correct = (
            bool(correct_value)
            if isinstance(correct_value, bool)
            else (truth == pred if truth is not None else None)
        )
        records.append(
            {
                "alert_id": str(detail.get("alert_id") or row["alert_id"]),
                "judgment": pred,
                "confidence": float(detail.get("confidence") or 0),
                "truth_label": truth,
                "correct": correct,
                "source": str(alert.get("source") or "unknown").lower(),
                "severity": str(alert.get("severity") or "unknown").lower(),
                "rule_name": str(alert.get("rule_name") or "未命名告警"),
                "reason": str(detail.get("reason") or ""),
                "channel": "evaluation",
                "observed_at": row["created_at"],
                "ordinal": int(row["ordinal"]),
            }
        )
    return records


def get_operations_snapshot(db_path: Path = DEFAULT_DB_PATH) -> dict[str, Any]:
    """Return the live operational snapshot consumed by the overview screen."""
    init_operations_db(db_path)
    with _connect(db_path) as conn:
        records = _interactive_records(conn) + _evaluation_records(conn)

    records.sort(key=lambda item: (item["observed_at"], item["ordinal"]))
    latest_by_alert: dict[str, dict[str, Any]] = {}
    for record in records:
        latest_by_alert[record["alert_id"]] = record
    latest = sorted(
        latest_by_alert.values(),
        key=lambda item: (item["observed_at"], item["ordinal"]),
        reverse=True,
    )

    by_judgment = Counter(item["judgment"] for item in latest)
    by_source = Counter(item["source"] for item in latest)
    by_severity = Counter(item["severity"] for item in latest)
    labeled = [item for item in latest if item["correct"] is not None]
    correct_count = sum(1 for item in labeled if item["correct"] is True)
    misjudgments = sum(1 for item in labeled if item["correct"] is False)

    today = datetime.now(timezone.utc).date()
    trend_counter = Counter(item["observed_at"][:10] for item in latest)
    trend = []
    for offset in range(6, -1, -1):
        day = today - timedelta(days=offset)
        key = day.isoformat()
        trend.append({"date": key, "count": trend_counter.get(key, 0)})

    last_updated = latest[0]["observed_at"] if latest else None
    recent = [
        {key: value for key, value in item.items() if key != "ordinal"}
        for item in latest[:10]
    ]
    revision = ":".join(
        [
            str(len(latest)),
            str(misjudgments),
            last_updated or "empty",
        ]
    )
    return {
        "generated_at": _now(),
        "last_updated": last_updated,
        "revision": revision,
        "total_alerts": len(latest),
        "confirmed_threats": by_judgment.get("真阳", 0),
        "dismissed_risks": by_judgment.get("假阳", 0),
        "pending_review": by_judgment.get("待查", 0),
        "misjudgments": misjudgments,
        "labeled_alerts": len(labeled),
        "correct_judgments": correct_count,
        "accuracy": round(correct_count / len(labeled), 4) if labeled else None,
        "by_judgment": dict(by_judgment),
        "by_source": dict(by_source),
        "by_severity": dict(by_severity),
        "trend": trend,
        "recent_events": recent,
    }
