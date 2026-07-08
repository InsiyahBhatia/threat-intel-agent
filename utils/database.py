"""
SQLite Database Module — persistent storage for investigations, alerts, feeds, and notifications.
"""

import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path

DB_DIR = Path(__file__).resolve().parents[1] / "data"
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = os.getenv("TIA_DB_PATH", str(DB_DIR / "tia.db"))

_RETENTION_DAYS = int(os.getenv("TIA_RETENTION_DAYS", "90"))
_RETRIES = int(os.getenv("SQLITE_RETRIES", "5"))
_RETRY_DELAY = float(os.getenv("SQLITE_RETRY_DELAY", "0.05"))
_DB_INITIALIZED = False
_init_lock = threading.Lock()
_local_conn = threading.local()


def get_conn() -> sqlite3.Connection:
    global _DB_INITIALIZED  # noqa: PLW0603
    if not _DB_INITIALIZED:
        with _init_lock:
            if not _DB_INITIALIZED:
                init_db()
                _DB_INITIALIZED = True
                _schedule_cleanup()
    # Reuse connection per thread via threading.local()
    conn = getattr(_local_conn, "conn", None)
    if conn is not None:
        try:
            conn.execute("SELECT 1")
            return conn
        except sqlite3.ProgrammingError:
            pass
        except sqlite3.OperationalError:
            pass
    last_err = None
    for attempt in range(_RETRIES):
        try:
            conn = sqlite3.connect(DB_PATH, timeout=20)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            _local_conn.conn = conn
            return conn
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower():
                last_err = e
                time.sleep(_RETRY_DELAY * (attempt + 1))
            else:
                raise
    raise last_err or sqlite3.OperationalError("could not connect to database")


def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
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
        CREATE INDEX IF NOT EXISTS idx_inv_ws_created ON investigations(workspace, created_at DESC);

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
        CREATE INDEX IF NOT EXISTS idx_alerts_severity_created ON alerts(severity, created_at DESC);

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

        DROP TABLE IF EXISTS export_log;

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()
    # ↑ this close is correct — init_db uses its own dedicated connection


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
    return inv_id


def search_investigations(  # noqa: PLR0913
    workspace: str = "default",
    severity: str | None = None,
    ioc_type: str | None = None,
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    conn = get_conn()
    query = "SELECT id, ioc, ioc_type, severity, summary, threat_category, risk_score, confidence_score, ml_verdict, ml_confidence, workspace, created_at FROM investigations WHERE workspace = ?"
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
    return {
        "total": total,
        "by_severity": {r["severity"]: r["cnt"] for r in by_sev},
        "by_type": {r["ioc_type"]: r["cnt"] for r in by_type},
        "trend": [{"date": r["d"], "count": r["cnt"]} for r in recent],
    }


def log_alert(ioc: str, severity: str, channel: str = "webhook",  # noqa: PLR0913
              status: str = "sent", response_code: int | None = None, error: str | None = None) -> int:
    conn = get_conn()
    cur = conn.execute("""
        INSERT INTO alerts (ioc, severity, channel, status, response_code, error)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (ioc, severity, channel, status, response_code, error))
    conn.commit()
    aid = cur.lastrowid
    return aid


def get_alerts(limit: int = 50, offset: int = 0) -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, ioc, severity, channel, status, response_code, error, created_at FROM alerts ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (limit, offset)
    ).fetchall()
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
    return fid


def remove_feed(feed_id: int) -> bool:
    conn = get_conn()
    conn.execute("DELETE FROM feeds WHERE id = ?", (feed_id,))
    conn.execute("DELETE FROM feed_entries WHERE feed_id = ?", (feed_id,))
    conn.commit()
    removed = conn.total_changes > 0
    return removed


def list_feeds() -> list[dict]:
    conn = get_conn()
    rows = conn.execute("SELECT * FROM feeds ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


def get_pollable_feeds() -> list[dict]:
    conn = get_conn()
    rows = conn.execute("""
        SELECT * FROM feeds WHERE enabled = 1
        AND (last_polled IS NULL
             OR datetime(last_polled, '+' || interval_minutes || ' minutes') <= datetime('now'))
    """).fetchall()
    return [dict(r) for r in rows]


def update_feed_poll_time(feed_id: int):
    conn = get_conn()
    conn.execute("UPDATE feeds SET last_polled = datetime('now') WHERE id = ?", (feed_id,))
    conn.commit()


def add_feed_entry(feed_id: int, ioc: str, ioc_type: str = "", title: str = "", link: str = ""):
    conn = get_conn()
    conn.execute(
        "INSERT OR IGNORE INTO feed_entries (feed_id, ioc, ioc_type, title, link) VALUES (?, ?, ?, ?, ?)",
        (feed_id, ioc, ioc_type, title, link),
    )
    conn.commit()


def get_feed_entries(feed_id: int | None = None, limit: int = 100) -> list[dict]:
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
    return [dict(r) for r in rows]


# ── Settings ────────────────────────────────────────────────────────────────

def get_setting(key: str, default: str | None = None) -> str | None:
    conn = get_conn()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str):
    conn = get_conn()
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()


# ── Cleanup ─────────────────────────────────────────────────────────────────
_cleanup_scheduled = False

def _cleanup_old_records():
    cutoff = f"datetime('now', '-{_RETENTION_DAYS} days')"
    conn = get_conn()
    conn.execute(f"DELETE FROM alerts WHERE created_at < {cutoff}")
    conn.execute(f"DELETE FROM investigations WHERE created_at < {cutoff}")
    conn.commit()
    logging.getLogger(__name__).info("Cleaned up records older than %d days", _RETENTION_DAYS)


def _schedule_cleanup():
    global _cleanup_scheduled
    if _cleanup_scheduled:
        return
    _cleanup_scheduled = True
    import atexit
    atexit.register(_cleanup_old_records)


# ── Init ────────────────────────────────────────────────────────────────────
# init_db() is now called lazily from get_conn() on first use.
