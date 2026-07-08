"""System endpoints: alerts, feeds, syslog, YARA, notification config, DB search."""

import logging
import re
from datetime import UTC, datetime

import feedparser
import httpx
from fastapi import APIRouter, HTTPException

from api.dependencies import ROOT_DIR, _get_active_workspace, _is_safe_url, _sanitize_log_text
from api.models import DBSearchRequest, FeedCreateRequest, NotificationConfig, SyslogRequest, YARARequest
from utils.database import (
    add_feed,
    add_feed_entry,
    get_alert_stats,
    get_alerts,
    get_feed_entries,
    get_investigation_stats,
    get_pollable_feeds,
    list_feeds,
    remove_feed,
    search_investigations,
    update_feed_poll_time,
)
from utils.notifications import _load_notification_config, _save_notification_config

logger = logging.getLogger(__name__)
router = APIRouter(tags=["system"])


@router.post("/api/syslog")
def ingest_syslog(req: SyslogRequest):
    ip_regex = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')

    blocklist_resp = get_blocklist_inline()
    blocklist = blocklist_resp["blocklist"]
    alerts = []

    for log in req.logs[:1000]:
        if len(log) > 4096:
            continue
        ips = ip_regex.findall(log)
        for ip in ips:
            if ip in blocklist:
                alerts.append({
                    "ip": ip,
                    "log": _sanitize_log_text(log),
                    "alert": "CRITICAL THREAT DETECTED IN SYSLOG",
                })
                logger.warning("[SIEM ALERT] Blocklisted IP found in traffic: %s", ip)

    return {"status": "ingested", "processed_logs": len(req.logs[:1000]), "alerts": alerts}


def get_blocklist_inline() -> dict:
    import pandas as pd

    ioc_list = []
    for ds_name in ["ioc_dataset.csv", "ioc_dataset_balanced.csv", "real_features.csv"]:
        dataset_path = ROOT_DIR / "data" / ds_name
        if dataset_path.exists():
            try:
                df = pd.read_csv(dataset_path)
                if "label" in df.columns and "ioc" in df.columns:
                    crit_high = df[df["label"].isin(["CRITICAL", "HIGH"])]["ioc"].dropna().unique().tolist()
                    ioc_list.extend(crit_high)
            except Exception as e:
                logger.warning(f"Failed to read dataset {ds_name}: {e}")

    common_iocs = list(set(ioc_list))
    return {"blocklist": common_iocs, "dataset_count": len(set(ioc_list)), "managed_count": 0}


@router.post("/api/db/search")
def db_search(req: DBSearchRequest):
    return {
        "results": search_investigations(
            workspace=req.workspace, severity=req.severity,
            ioc_type=req.ioc_type, search=req.search,
            limit=min(req.limit, 500), offset=req.offset,
        )
    }


@router.get("/api/db/stats")
def db_stats(workspace: str = "default"):
    return get_investigation_stats(workspace)


@router.get("/api/alerts")
def list_alerts(limit: int = 50, offset: int = 0):
    return {"alerts": get_alerts(limit, offset), "stats": get_alert_stats()}


@router.get("/api/feeds")
def list_feeds_api():
    return {"feeds": list_feeds()}


@router.post("/api/feeds")
def create_feed(req: FeedCreateRequest):
    if not _is_safe_url(req.url):
        raise HTTPException(400, "Feed URL must be HTTP/HTTPS to a public address")
    fid = add_feed(req.name, req.url, req.feed_type, req.interval_minutes)
    if fid == -1:
        raise HTTPException(400, "Feed URL already exists")
    return {"status": "created", "id": fid}


@router.delete("/api/feeds/{feed_id}")
def delete_feed(feed_id: int):
    if remove_feed(feed_id):
        return {"status": "deleted"}
    raise HTTPException(404, "Feed not found")


@router.get("/api/feeds/entries")
def feed_entries(feed_id: int | None = None, limit: int = 100):
    return {"entries": get_feed_entries(feed_id, limit)}


@router.post("/api/feeds/poll")
async def poll_feeds():
    feeds = get_pollable_feeds()
    results = []
    for feed in feeds:
        try:
            parsed = feedparser.parse(feed["url"])
            count = 0
            for entry in parsed.entries:
                title = entry.get("title", "")
                link = entry.get("link", "")
                content = title + " " + entry.get("summary", "") + " " + entry.get("description", "")
                iocs = set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", content))
                iocs.update(re.findall(r"\b[a-fA-F0-9]{32}\b", content))
                iocs.update(re.findall(r"\b[a-fA-F0-9]{40}\b", content))
                iocs.update(re.findall(r"\b[a-fA-F0-9]{64}\b", content))
                iocs.update(re.findall(r"(?:https?://)?(?:[\w-]+\.)+[\w-]+", content))
                for ioc in list(iocs)[:10]:
                    from utils.classifier import classify_ioc
                    add_feed_entry(feed["id"], ioc, classify_ioc(ioc), title, link)
                    count += 1
            update_feed_poll_time(feed["id"])
            results.append({"feed": feed["name"], "entries_added": count})
        except Exception as e:
            results.append({"feed": feed["name"], "error": str(e)})
    return {"polled": len(feeds), "results": results}


@router.post("/api/yara/generate")
def generate_yara(req: YARARequest):
    rules = []
    hashes = []
    domains = []
    others = []
    for raw_ioc in req.iocs:
        ioc = raw_ioc.strip()
        if not ioc:
            continue
        if re.match(r'^[a-fA-F0-9]{32}$', ioc) or re.match(r'^[a-fA-F0-9]{40}$', ioc) or re.match(r'^[a-fA-F0-9]{64}$', ioc):
            hashes.append(ioc)
        elif re.match(r'^[\w\-]+(\.[\w\-]+)+$', ioc):
            domains.append(ioc)
        else:
            others.append(ioc)

    base_rule_name = req.rule_name[:50].replace(' ', '_').replace('-', '_')
    now_iso = datetime.now(UTC).isoformat()

    def make_rule(suffix, ioc_list, prefix, modifier):
        if not ioc_list:
            return None
        meta_lines = [
            f'\tdescription = "{req.description} ({suffix})"',
            '\tgenerated_by = "Threat Intel Agent"',
            f'\tgenerated_at = "{now_iso}"',
            f'\tioc_count = "{len(ioc_list)}"',
        ]
        string_defs = []
        for i, val in enumerate(ioc_list):
            escaped = val.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r")
            string_defs.append(f'\t${prefix}_{i} = "{escaped}" {modifier}'.strip())

        return (
            f"rule {base_rule_name}_{suffix} {{\n"
            + "\tmeta:\n"
            + "\n".join(meta_lines) + "\n"
            + "\tstrings:\n"
            + "\n".join(string_defs) + "\n"
            + "\tcondition:\n"
            + "\t\tany of them\n"
            + "}"
        )

    if hashes:
        r = make_rule("hashes", hashes, "hash", "")
        if r:
            rules.append(r)
    if domains:
        r = make_rule("domains", domains, "domain", "nocase ascii wide")
        if r:
            rules.append(r)
    if others:
        r = make_rule("strings", others[:20], "ioc", "ascii wide")
        if r:
            rules.append(r)

    return {"status": "ok", "rules": rules, "rule_count": len(rules)}


@router.get("/api/yara/generate-from-workspace")
def generate_yara_from_workspace(rule_name: str = "threat_intel_blocklist", max_iocs: int = 50):
    ws = _get_active_workspace()
    iocs = [e["ioc"] for e in ws.get("iocs", []) if e.get("ioc")][:max_iocs]
    blocklist = ws.get("blocklist", [])
    all_iocs = list(set(iocs + blocklist))[:max_iocs]
    return generate_yara(YARARequest(iocs=all_iocs, rule_name=rule_name))


@router.get("/api/integrations/notifications")
def get_notification_config():
    cfg = _load_notification_config()
    safe = cfg.copy()
    if "smtp_pass" in safe.get("email", {}):
        safe["email"]["smtp_pass"] = "********" if safe["email"]["smtp_pass"] else ""
    return safe


@router.post("/api/integrations/notifications")
def set_notification_config(cfg: NotificationConfig):
    _save_notification_config(cfg.model_dump())
    return {"status": "ok"}


@router.post("/api/integrations/notifications/test")
async def test_notification(channel: str = "slack"):  # noqa: PLR0911
    cfg = _load_notification_config()
    async with httpx.AsyncClient(timeout=10) as client:
        if channel == "slack" and cfg.get("slack", {}).get("webhook_url"):
            url = cfg["slack"]["webhook_url"]
            if not _is_safe_url(url):
                return {"status": "error", "detail": "Webhook URL blocked by SSRF guard"}
            try:
                resp = await client.post(url, json={"text": "Test notification successful"})
                return {"status": "ok" if resp.status_code < 400 else "error"}
            except Exception as e:
                return {"status": "error", "detail": str(e)}
        if channel == "teams" and cfg.get("teams", {}).get("webhook_url"):
            url = cfg["teams"]["webhook_url"]
            if not _is_safe_url(url):
                return {"status": "error", "detail": "Webhook URL blocked by SSRF guard"}
            try:
                resp = await client.post(url, json={"title": "Test Notification", "text": "Threat Intel Agent — test successful"})
                return {"status": "ok" if resp.status_code < 400 else "error"}
            except Exception as e:
                return {"status": "error", "detail": str(e)}
        if channel == "email" and cfg.get("email", {}).get("enabled"):
            try:
                import smtplib
                from email.mime.text import MIMEText
                e = cfg["email"]
                msg = MIMEText("Threat Intel Agent — test notification successful.")
                msg["Subject"] = "TIA Test Notification"
                msg["From"] = e["from_addr"]
                msg["To"] = ", ".join(e["to_addrs"])
                with smtplib.SMTP(e["smtp_host"], e["smtp_port"]) as server:
                    if e.get("smtp_user"):
                        server.login(e["smtp_user"], e["smtp_pass"])
                    server.send_message(msg)
                return {"status": "ok"}
            except Exception as e:
                return {"status": "error", "detail": str(e)}
    return {"status": "error", "detail": "Channel not configured"}
