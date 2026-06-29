"""
SQLite Database Module — persistent storage for investigations, alerts, feeds, and notifications.
"""

import sqlite3
import json
import os
from datetime import datetime, timezone
from pathlib import Path

DB_DIR = Path(__file__).resolve().parents[1] / "data"
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = str(DB_DIR / "tia.db")


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc TEXT NOT NULL,
            ioc_type TEXT DEFAULT '',
            severity TEXT DEFAULT 'UNKNOWN',
            summary TEXT DEFAULT '',
            threat_category TEXT DEFAULT '',
            risk_score REAL DEFAULT 0.0,
            confidence_score REAL DEFAULT 0.0,
            ml_verdict TEXT DEFAULT NULL,
            ml_confidence REAL DEFAULT NULL,
            report_json TEXT DEFAULT '{}',
            workspace TEXT DEFAULT 'default',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_inv_ioc ON investigations(ioc);
        CREATE INDEX IF NOT EXISTS idx_inv_severity ON investigations(severity);
        CREATE INDEX IF NOT EXISTS idx_inv_created ON investigations(created_at);
        CREATE INDEX IF NOT EXISTS idx_inv_workspace ON investigations(workspace);

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc TEXT NOT NULL,
            severity TEXT NOT NULL,
            channel TEXT DEFAULT 'webhook',
            status TEXT DEFAULT 'sent',
            response_code INTEGER DEFAULT NULL,
            error TEXT DEFAULT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);

        CREATE TABLE IF NOT EXISTS feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL UNIQUE,
            feed_type TEXT DEFAULT 'rss',
            interval_minutes INTEGER DEFAULT 60,
            enabled INTEGER DEFAULT 1,
            last_polled TEXT DEFAULT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS feed_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_id INTEGER REFERENCES feeds(id),
            ioc TEXT NOT NULL,
            ioc_type TEXT DEFAULT '',
            title TEXT DEFAULT '',
            link TEXT DEFAULT '',
            severity TEXT DEFAULT NULL,
            seen INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_fe_ioc ON feed_entries(ioc);
        CREATE INDEX IF NOT EXISTS idx_fe_feed ON feed_entries(feed_id);

        CREATE TABLE IF NOT EXISTS export_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            format TEXT NOT NULL,
            ioc TEXT DEFAULT NULL,
            workspace TEXT DEFAULT 'default',
            file_size INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()


def save_investigation(entry: dict) -> int:
    conn = get_conn()
    cur = conn.execute("""
        INSERT INTO investigations (ioc, ioc_type, severity, summary, threat_category,
            risk_score, confidence_score, ml_verdict, ml_confidence, report_json, workspace)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        entry.get("ioc", ""),
        entry.get("ioc_type", ""),
        entry.get("severity", "UNKNOWN"),
        entry.get("summary", ""),
        entry.get("threat_category", ""),
        entry.get("risk_score", 0.0),
        entry.get("confidence_score", 0.0),
        entry.get("ml_verdict"),
        entry.get("ml_confidence"),
        json.dumps(entry.get("report", {})),
        entry.get("workspace", "default"),
    ))
    conn.commit()
    inv_id = cur.lastrowid
    conn.close()
    return inv_id


def search_investigations(
    workspace: str = "default",
    severity: str = None,
    ioc_type: str = None,
    search: str = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    conn = get_conn()
    query = "SELECT * FROM investigations WHERE workspace = ?"
    params: list = [workspace]
    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())
    if ioc_type:
        query += " AND ioc_type = ?"
        params.append(ioc_type)
    if search:
        query += " AND (ioc LIKE ? OR summary LIKE ? OR threat_category LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like, like])
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_investigation_stats(workspace: str = "default") -> dict:
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) FROM investigations WHERE workspace = ?", (workspace,)).fetchone()[0]
    by_sev = conn.execute("""
        SELECT severity, COUNT(*) as cnt FROM investigations
        WHERE workspace = ? GROUP BY severity
    """, (workspace,)).fetchall()
    by_type = conn.execute("""
        SELECT ioc_type, COUNT(*) as cnt FROM investigations
        WHERE workspace = ? AND ioc_type != '' GROUP BY ioc_type
    """, (workspace,)).fetchall()
    recent = conn.execute("""
        SELECT date(created_at) as d, COUNT(*) as cnt FROM investigations
        WHERE workspace = ? AND created_at >= datetime('now', '-14 days')
        GROUP BY d ORDER BY d
    """, (workspace,)).fetchall()
    conn.close()
    return {
        "total": total,
        "by_severity": {r["severity"]: r["cnt"] for r in by_sev},
        "by_type": {r["ioc_type"]: r["cnt"] for r in by_type},
        "trend": [{"date": r["d"], "count": r["cnt"]} for r in recent],
    }


def log_alert(ioc: str, severity: str, channel: str = "webhook",
              status: str = "sent", response_code: int = None, error: str = None) -> int:
    conn = get_conn()
    cur = conn.execute("""
        INSERT INTO alerts (ioc, severity, channel, status, response_code, error)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (ioc, severity, channel, status, response_code, error))
    conn.commit()
    aid = cur.lastrowid
    conn.close()
    return aid


def get_alerts(limit: int = 50, offset: int = 0) -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (limit, offset)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alert_stats() -> dict:
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    by_sev = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
    ).fetchall()
    recent = conn.execute("""
        SELECT date(created_at) as d, COUNT(*) as cnt FROM alerts
        WHERE created_at >= datetime('now', '-7 days')
        GROUP BY d ORDER BY d
    """).fetchall()
    conn.close()
    return {
        "total": total,
        "by_severity": {r["severity"]: r["cnt"] for r in by_sev},
        "trend": [{"date": r["d"], "count": r["cnt"]} for r in recent],
    }


def add_feed(name: str, url: str, feed_type: str = "rss", interval_minutes: int = 60) -> int:
    conn = get_conn()
    try:
        cur = conn.execute(
            "INSERT INTO feeds (name, url, feed_type, interval_minutes) VALUES (?, ?, ?, ?)",
            (name, url, feed_type, interval_minutes),
        )
        conn.commit()
        fid = cur.lastrowid
    except sqlite3.IntegrityError:
        fid = -1
    conn.close()
    return fid


def remove_feed(feed_id: int) -> bool:
    conn = get_conn()
    conn.execute("DELETE FROM feeds WHERE id = ?", (feed_id,))
    conn.execute("DELETE FROM feed_entries WHERE feed_id = ?", (feed_id,))
    conn.commit()
    removed = conn.total_changes > 0
    conn.close()
    return removed


def list_feeds() -> list[dict]:
    conn = get_conn()
    rows = conn.execute("SELECT * FROM feeds ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_pollable_feeds() -> list[dict]:
    conn = get_conn()
    rows = conn.execute("""
        SELECT * FROM feeds WHERE enabled = 1
        AND (last_polled IS NULL
             OR datetime(last_polled, '+' || interval_minutes || ' minutes') <= datetime('now'))
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_feed_poll_time(feed_id: int):
    conn = get_conn()
    conn.execute("UPDATE feeds SET last_polled = datetime('now') WHERE id = ?", (feed_id,))
    conn.commit()
    conn.close()


def add_feed_entry(feed_id: int, ioc: str, ioc_type: str = "", title: str = "", link: str = ""):
    conn = get_conn()
    conn.execute(
        "INSERT OR IGNORE INTO feed_entries (feed_id, ioc, ioc_type, title, link) VALUES (?, ?, ?, ?, ?)",
        (feed_id, ioc, ioc_type, title, link),
    )
    conn.commit()
    conn.close()


def get_feed_entries(feed_id: int = None, limit: int = 100) -> list[dict]:
    conn = get_conn()
    if feed_id:
        rows = conn.execute(
            "SELECT * FROM feed_entries WHERE feed_id = ? ORDER BY created_at DESC LIMIT ?",
            (feed_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT fe.*, f.name as feed_name FROM feed_entries fe JOIN feeds f ON fe.feed_id = f.id ORDER BY fe.created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Settings ────────────────────────────────────────────────────────────────

def get_setting(key: str, default: str = None) -> str | None:
    conn = get_conn()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_setting(key: str, value: str):
    conn = get_conn()
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()


# ── Init ────────────────────────────────────────────────────────────────────

init_db()
