"""Shared dependencies, helpers, and module-level state for API routes."""

import asyncio
import ipaddress
import json
import logging
import os
import socket
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import Request

from utils.database import log_alert
from utils.notifications import send_notifications

logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parents[1]

# ── File Locking (thread-safe within process) ───────────────────────────
_file_locks: dict[str, threading.Lock] = {}

def _get_file_lock(path: str) -> threading.Lock:
    if path not in _file_locks:
        _file_locks[path] = threading.Lock()
    return _file_locks[path]

# ── Background Tasks ────────────────────────────────────────────────────
_BG_TASKS: set[asyncio.Task] = set()


def _run_bg(coro) -> None:
    task = asyncio.create_task(coro)
    _BG_TASKS.add(task)
    task.add_done_callback(_BG_TASKS.discard)


# ── Client IP ───────────────────────────────────────────────────────────
def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ── Workspace Helpers ───────────────────────────────────────────────────
WORKSPACE_DIR = ROOT_DIR / "data" / "workspaces"
WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
WORKSPACE_INDEX_FILE = WORKSPACE_DIR / "_index.json"

_workspace_cache: dict[str, tuple[dict, float]] = {}
_WORKSPACE_CACHE_TTL = 5.0


def _load_workspace_index() -> dict:
    if WORKSPACE_INDEX_FILE.exists():
        try:
            with _get_file_lock(str(WORKSPACE_INDEX_FILE)):
                return json.loads(WORKSPACE_INDEX_FILE.read_text())
        except Exception as e:
            logger.warning(f"Corrupt workspace index file, resetting: {e}")
    return {"workspaces": {}, "active": "default"}


def _save_workspace_index(idx: dict) -> None:
    with _get_file_lock(str(WORKSPACE_INDEX_FILE)):
        WORKSPACE_INDEX_FILE.write_text(json.dumps(idx, indent=2))
    _workspace_cache.clear()


def _load_workspace(name: str) -> dict:
    now = time.time()
    cached = _workspace_cache.get(name)
    if cached and (now - cached[1]) < _WORKSPACE_CACHE_TTL:
        return cached[0]
    path = WORKSPACE_DIR / f"{name}.json"
    if path.exists():
        try:
            with _get_file_lock(str(path)):
                data = json.loads(path.read_text())
            _workspace_cache[name] = (data, now)
            return data
        except Exception as e:
            logger.warning(f"Corrupt workspace file '{name}', creating fresh: {e}")
    data = {"name": name, "iocs": [], "blocklist": [],
            "ignored_iocs": [], "webhooks": [],
            "created": datetime.now(UTC).isoformat()}
    _workspace_cache[name] = (data, now)
    return data


def _save_workspace(name: str, data: dict) -> None:
    path = WORKSPACE_DIR / f"{name}.json"
    with _get_file_lock(str(path)):
        path.write_text(json.dumps(data, indent=2, default=str))
    _workspace_cache[name] = (data, time.time())


def _get_active_workspace() -> dict:
    idx = _load_workspace_index()
    return _load_workspace(idx.get("active", "default"))


def _save_active_workspace(data: dict) -> None:
    idx = _load_workspace_index()
    _save_workspace(idx.get("active", "default"), data)


def _get_active_workspace_name() -> str:
    idx = _load_workspace_index()
    return idx.get("active", "default")


# ── Blocklist Helpers ───────────────────────────────────────────────────
BLOCKLIST_FILE = ROOT_DIR / "data" / "managed_blocklist.json"


def _load_managed_blocklist() -> list[str]:
    if BLOCKLIST_FILE.exists():
        try:
            with _get_file_lock(str(BLOCKLIST_FILE)):
                return json.loads(BLOCKLIST_FILE.read_text())
        except Exception as e:
            logger.warning(f"Corrupt blocklist file, returning empty: {e}")
    return []


def _save_managed_blocklist(iocs: list[str]) -> None:
    BLOCKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    with _get_file_lock(str(BLOCKLIST_FILE)):
        BLOCKLIST_FILE.write_text(json.dumps(iocs, indent=2))


# ── SSRF Guard ──────────────────────────────────────────────────────────
def _is_safe_url(url: str) -> bool:  # noqa: PLR0911
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname or ""
        if not host:
            return False
        try:
            addr = ipaddress.ip_address(host)
            return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)
        except ValueError:
            pass
        try:
            addrs = socket.getaddrinfo(host, None)
            for _, _, _, _, sockaddr in addrs:
                ip_str = sockaddr[0]
                try:
                    resolved = ipaddress.ip_address(ip_str)
                    if resolved.is_private or resolved.is_loopback or resolved.is_link_local or resolved.is_multicast:
                        return False
                except ValueError:
                    return False
            return True
        except (socket.gaierror, OSError):
            return False
    except Exception:
        return False


# ── Webhook Dispatching ─────────────────────────────────────────────────
async def _fire_webhooks(severity: str, ioc: str, report: dict) -> None:
    ws = _get_active_workspace()
    hooks = ws.get("webhooks", [])
    if not hooks:
        return
    safe_hooks = [h for h in hooks if _is_safe_url(h.get("url", ""))]
    unsafe = len(hooks) - len(safe_hooks)
    if unsafe:
        logger.warning(f"Skipping {unsafe} webhooks with disallowed URLs (SSRF guard)")
    hooks = safe_hooks
    if not hooks:
        return
    payload = json.dumps({
        "event": "ioc_detected",
        "severity": severity,
        "ioc": ioc,
        "ioc_type": report.get("ioc_type", ""),
        "threat_category": report.get("threat_category", ""),
        "ml_verdict": report.get("ml_verdict"),
        "ml_confidence": report.get("ml_confidence"),
        "risk_score": report.get("risk_score"),
        "timestamp": datetime.now(UTC).isoformat(),
    })
    async with httpx.AsyncClient(timeout=5.0) as client:
        async def _dispatch(hook):
            try:
                resp = await client.post(hook["url"], json={"event": "ioc_detected", "data": json.loads(payload)}, headers={"Content-Type": "application/json"})
                log_alert(ioc, severity, "webhook", "sent" if resp.is_success else "failed", resp.status_code)
            except Exception as e:
                log_alert(ioc, severity, "webhook", "failed", error=str(e))
        eligible = [h for h in hooks if severity in h.get("events", ["CRITICAL", "HIGH"])]
        await asyncio.gather(*[_dispatch(h) for h in eligible])


async def _notify_and_log(ioc: str, severity: str, report: dict) -> None:
    await _fire_webhooks(severity, ioc, report)
    try:
        result = await send_notifications(ioc, severity, report)
        for channel, res in result.items():
            if res:
                log_alert(ioc, severity, channel, res.get("status", "unknown"), None, res.get("detail"))
    except Exception as e:
        log_alert(ioc, severity, "notification", "error", None, str(e))
        logger.warning(f"Notification dispatch failed for {ioc}: {e}")


async def _send_notification_async(ioc: str, severity: str, report: dict) -> None:
    try:
        result = await send_notifications(ioc, severity, report)
        for channel, res in result.items():
            if res:
                log_alert(ioc, severity, channel, res.get("status", "unknown"), None, res.get("detail"))
    except Exception as e:
        log_alert(ioc, severity, "notification", "error", None, str(e))
        logger.warning(f"Notification dispatch failed for {ioc}: {e}")


async def _was_notified(ioc: str) -> bool:
    from utils.database import get_setting
    val = await asyncio.to_thread(get_setting, f"notified:{ioc}")
    return val is not None


async def _mark_notified(ioc: str) -> None:
    from utils.database import set_setting
    await asyncio.to_thread(set_setting, f"notified:{ioc}", "1")


async def _notify_hunt_results(critical_high_nodes: list[tuple[str, str]]) -> None:
    from agent.orchestrator import investigate
    for ioc, severity in critical_high_nodes:
        if await _was_notified(ioc):
            continue
        await _mark_notified(ioc)
        try:
            result = await investigate(ioc)
            report = result.get("report", {})
            await send_notifications(ioc, severity, report)
            log_alert(ioc, severity, "notification", "sent", None, None)
        except Exception as e:
            log_alert(ioc, severity, "notification", "failed", None, error=str(e))
            logger.warning(f"Notification failed for hunt IOC {ioc}: {e}")


# ── Feedback Persistence ─────────────────────────────────────────────────
FEEDBACK_FILE = ROOT_DIR / "data" / "feedback_data.json"
_feedback_lock = threading.Lock()


def _load_feedback() -> list:
    if FEEDBACK_FILE.exists():
        try:
            return json.loads(FEEDBACK_FILE.read_text())
        except Exception as e:
            logger.warning(f"Corrupt feedback file, resetting: {e}")
    return []


def _save_feedback(records: list) -> None:
    FEEDBACK_FILE.parent.mkdir(parents=True, exist_ok=True)
    FEEDBACK_FILE.write_text(json.dumps(records, indent=2))


# ── Sanitize ────────────────────────────────────────────────────────────
def _sanitize_log_text(text: str, max_len: int = 256) -> str:
    sanitized = text[:max_len]
    sanitized = sanitized.replace("<", "&lt;").replace(">", "&gt;")
    return sanitized
