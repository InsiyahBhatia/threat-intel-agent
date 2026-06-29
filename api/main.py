"""
FastAPI REST API for the Threat Intelligence Agent.
Exposes POST /investigate for IOC analysis and /api/chat for the browser extension.
"""

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
import sys, os, re, json, asyncio, hashlib, logging
from pathlib import Path
from dotenv import load_dotenv
from datetime import datetime, timezone
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(ROOT_DIR, ".env"))
sys.path.insert(0, ROOT_DIR)

from agent.orchestrator import investigate
from utils.classifier import validate_ioc
from utils.risk_model import predict_risk
from utils.database import (save_investigation, search_investigations,
    get_investigation_stats, log_alert, get_alerts, get_alert_stats,
    add_feed, remove_feed, list_feeds, get_feed_entries, get_pollable_feeds,
    update_feed_poll_time, add_feed_entry)
from utils.notifications import send_notifications

app = FastAPI(
    title="Threat Intel Agent API",
    description="Local-model IOC investigation using VirusTotal, Shodan, AbuseIPDB, and MITRE ATT&CK",
    version="1.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class InvestigateRequest(BaseModel):
    ioc: str

    class Config:
        json_schema_extra = {
            "example": {"ioc": "8.8.8.8"}
        }

class InvestigateResponse(BaseModel):
    ioc: str
    ioc_type: str
    agent_output: str
    report: dict = Field(default_factory=dict)
    status: str = "success"

@app.get("/")
def root():
    return {
        "service": "Threat Intelligence Agent",
        "status": "online",
        "endpoints": {
            "POST /investigate": "Investigate an IOC (IP, domain, or file hash)",
            "POST /api/chat": "Browser extension chat endpoint",
            "GET /health": "Health check",
        }
    }

@app.get("/health")
def health():
    keys = {
        "VIRUSTOTAL_API_KEY": bool(os.getenv("VIRUSTOTAL_API_KEY")),
        "SHODAN_API_KEY": bool(os.getenv("SHODAN_API_KEY")),
        "ABUSEIPDB_API_KEY": bool(os.getenv("ABUSEIPDB_API_KEY")),
    }
    all_configured = all(keys.values())
    return {
        "status": "healthy" if all_configured else "degraded",
        "model": "Ensemble(XGB+LGB)",
        "llm_provider": None,
        "api_keys_configured": keys,
    }




# ── Extension Chat Endpoint ────────────────────────────────────────────────
class ChatRequest(BaseModel):
    message: str
    history: list[dict] = []

IOC_RE = re.compile(
    r'(?:'
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'  # IPv4
    r'|[a-fA-F0-9]{64}'       # SHA256
    r'|[a-fA-F0-9]{32}'       # MD5
    r'|(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|de|uk|xyz|top|info|biz|co|ai|app|gov|edu|mil|tv|cc|me|us|ca|fr|jp|br|au|in|nl|se|no|fi|dk|pl|cz|ch|at|be|es|pt|it|gr|tr|il|sa|ae|za|ng|ke|gh|tz|ug|rw|et|eg|ma|dz|sn|ci|cm|cd|ao|mz|zm|zw|bw|ls|sz|na|mg|mu|sc|km|cv|st|gw|gn|sl|lr|gm|ne|bf|ml|mr|td|sd|ss|so|dj|er|cf|cg|ga|gq|bi|rw|rw|ug|tz|ke|ng|gh|sn|ci|cm|cd|ao|mz|zm|zw|bw|ls|sz|na|mg|mu|sc|km|cv|st|gw|gn|sl|lr|gm|ne|bf|ml|mr|td|sd|ss|so|dj|er|cf|cg|ga|gq|bi)'
    r')'
)

def extract_ioc(text: str) -> Optional[str]:
    m = IOC_RE.search(text)
    return m.group(0) if m else None

def is_hunt_request(text: str) -> bool:
    keywords = ["hunt", "expand", "infrastructure", "campaign", "related", "find more", "trace"]
    return any(k in text.lower() for k in keywords)

@app.post("/api/chat")
async def chat_endpoint(req: ChatRequest):
    message  = req.message.strip()
    history  = req.history[-8:]

    ioc = extract_ioc(message)
    hunting = is_hunt_request(message) and ioc

    if hunting:
        try:
            from agent.hunter import hunt

            hunt_log = []
            graph_data = None

            async def progress(msg, graph):
                hunt_log.append(msg)
                nonlocal graph_data
                graph_data = graph.to_vis_json()

            graph = await hunt(ioc, progress_callback=progress, max_depth=3, max_nodes=25)
            summary = graph.get_campaign_summary()
            graph_data = graph.to_vis_json()

            campaign_block = f"|||CAMPAIGN:{__import__('json').dumps(summary)}|||"

            verdict_blocks = ""
            critical_high_nodes = []
            for node in list(graph.nodes.values())[:5]:
                if node.severity in ("CRITICAL", "HIGH") and node.investigated:
                    v = {
                        "ioc": node.ioc,
                        "ioc_type": node.ioc_type,
                        "severity": node.severity,
                        "confidence": node.confidence or 0,
                        "mitre_techniques": node.mitre_techniques[:3],
                    }
                    verdict_blocks += f"|||VERDICT:{__import__('json').dumps(v)}|||\n"
                    critical_high_nodes.append((node.ioc, node.severity))

            total = summary["total_iocs"]
            crit  = summary["critical_high"]
            depth = summary["depth_reached"]

            asyncio.create_task(_notify_hunt_results(critical_high_nodes))

            response_text = (
                f"🔍 **Autonomous hunt complete.** Starting from `{ioc}`, I traced the infrastructure "
                f"across **{depth} hops** and mapped **{total} IOCs** — **{crit} flagged as CRITICAL or HIGH**.\n\n"
                f"{campaign_block}\n\n"
                f"{verdict_blocks}"
                f"Want me to generate firewall block rules for all {total} IOCs?\n"
                f"Type **\"block rules for {ioc}\"** to export iptables/pfSense rules."
            )

            return {
                "response":      response_text,
                "graph":         graph_data,
                "hunt_log":      hunt_log,
                "hunt_complete": True,
            }

        except ImportError:
            pass
        except Exception as e:
            return {
                "response": f"Hunt failed: {e}. Falling back to single IOC investigation.",
                "graph": None,
                "hunt_log": [],
                "hunt_complete": False,
            }

    if ioc:
        try:
            result = investigate(ioc)
            report = result.get("report", {})
            import json

            verdict = {
                "ioc":              ioc,
                "ioc_type":         result.get("ioc_type", ""),
                "severity":         report.get("severity", "UNKNOWN"),
                "confidence":       report.get("confidence_score", 0),
                "mitre_techniques": report.get("mitre_techniques", [])[:4],
            }
            verdict_block = f"|||VERDICT:{json.dumps(verdict)}|||"

            sev        = report.get("severity", "UNKNOWN")
            cat        = report.get("threat_category", "Unknown")
            ml_v       = report.get("ml_verdict")
            ml_c       = report.get("ml_confidence")
            actions    = report.get("recommended_actions", [])[:2]

            if sev in ("CRITICAL", "HIGH"):
                asyncio.create_task(_fire_webhooks(sev, ioc, report))
                asyncio.create_task(_notify_and_log(ioc, sev, report))

            # One-line VT summary
            vt_line = ""
            for line in (result.get("agent_output") or "").splitlines():
                if "Detection ratio" in line:
                    vt_line = line.strip()
                    break

            # Tight summary lines
            lines = []
            if cat:        lines.append(f"**Category:** {cat}")
            if vt_line:    lines.append(f"**VT:** {vt_line}")
            if ml_v:       lines.append(f"**ML:** {ml_v} ({ml_c}% conf)")
            if actions:    lines.append(f"**Action:** {actions[0]}")

            hunt_hint = ""
            if sev in ("CRITICAL", "HIGH"):
                hunt_hint = f"\n\nType **hunt {ioc}** to trace the full campaign infrastructure."

            response_text = f"{verdict_block}\n\n" + "\n".join(lines) + hunt_hint

            return {
                "response":      response_text,
                "graph":         None,
                "hunt_log":      [],
                "hunt_complete": False,
            }

        except Exception as e:
            return {
                "response":      f"Investigation error: {e}",
                "graph":         None,
                "hunt_log":      [],
                "hunt_complete": False,
            }

    try:
        from langchain_groq import ChatGroq
        from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

        llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0.3)
        lc_history = [
            SystemMessage(content=(
                "You are a threat intelligence analyst assistant. "
                "You help SOC analysts investigate IOCs (IPs, domains, file hashes), "
                "interpret VirusTotal/Shodan/AbuseIPDB results, map to MITRE ATT&CK techniques, "
                "and generate firewall block rules. "
                "Be concise and technical. When the user gives you an IOC, investigate it. "
                "Format structured verdicts as |||VERDICT:{json}||| blocks."
            ))
        ]
        for turn in history:
            if turn["role"] == "user":
                lc_history.append(HumanMessage(content=turn["content"]))
            else:
                lc_history.append(AIMessage(content=turn["content"]))
        lc_history.append(HumanMessage(content=message))
        reply = llm.invoke(lc_history).content

    except Exception as e:
        reply = (
            "I'm your threat intelligence analyst. Share an IP address, domain, or file hash "
            "and I'll investigate it using VirusTotal, Shodan, AbuseIPDB, and my ML classifier.\n\n"
            f"(LLM unavailable: {e})"
        )

    return {
        "response": reply,
        "graph": None,
        "hunt_log": [],
        "hunt_complete": False,
    }

BLOCKLIST_FILE = Path(ROOT_DIR) / "data" / "managed_blocklist.json"

def _load_managed_blocklist() -> list[str]:
    if BLOCKLIST_FILE.exists():
        try: return json.loads(BLOCKLIST_FILE.read_text())
        except Exception as e:
            logger.warning(f"Corrupt blocklist file, returning empty: {e}")
    return []

def _save_managed_blocklist(iocs: list[str]) -> None:
    BLOCKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    BLOCKLIST_FILE.write_text(json.dumps(iocs, indent=2))

class BlocklistRequest(BaseModel):
    iocs: list[str]

@app.get("/api/blocklist")
def get_blocklist():
    import pandas as pd
    
    ioc_list = []
    
    for ds_name in ["ioc_dataset.csv", "ioc_dataset_balanced.csv", "real_features.csv"]:
        dataset_path = Path(ROOT_DIR) / "data" / ds_name
        if dataset_path.exists():
            try:
                df = pd.read_csv(dataset_path)
                if "label" in df.columns and "ioc" in df.columns:
                    crit_high = df[df["label"].isin(["CRITICAL", "HIGH"])]["ioc"].dropna().unique().tolist()
                    ioc_list.extend(crit_high)
            except Exception as e:
                logger.warning(f"Failed to read dataset {ds_name}: {e}")

    managed = _load_managed_blocklist()
    all_iocs = list(set(ioc_list + managed))
    return {"blocklist": all_iocs, "dataset_count": len(set(ioc_list)), "managed_count": len(managed)}


@app.post("/api/blocklist")
def add_blocklist(req: BlocklistRequest):
    current = _load_managed_blocklist()
    added = []
    for ioc in req.iocs:
        ioc = ioc.strip()
        if ioc and ioc not in current:
            current.append(ioc)
            added.append(ioc)
    _save_managed_blocklist(current)
    return {"status": "ok", "added": added, "total": len(current)}


@app.delete("/api/blocklist")
def remove_blocklist(req: BlocklistRequest):
    current = _load_managed_blocklist()
    removed = []
    for ioc in req.iocs:
        ioc = ioc.strip()
        if ioc in current:
            current.remove(ioc)
            removed.append(ioc)
    _save_managed_blocklist(current)
    return {"status": "ok", "removed": removed, "total": len(current)}

class SyslogRequest(BaseModel):
    logs: list[str]

@app.post("/api/syslog")
def ingest_syslog(req: SyslogRequest):
    import re
    # Extremely simplified real-time detection: check against blocklist
    ip_regex = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
    
    blocklist = get_blocklist()["blocklist"]
    alerts = []
    
    for log in req.logs:
        ips = ip_regex.findall(log)
        for ip in ips:
            if ip in blocklist:
                alerts.append({"ip": ip, "log": log, "alert": "CRITICAL THREAT DETECTED IN SYSLOG"})
                print(f"[SIEM ALERT] Blocklisted IP found in traffic: {ip}")
                
    return {"status": "ingested", "processed_logs": len(req.logs), "alerts": alerts}

# ── Workspace Management ──────────────────────────────────────────────────
WORKSPACE_DIR = Path(ROOT_DIR) / "data" / "workspaces"
WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
WORKSPACE_INDEX_FILE = WORKSPACE_DIR / "_index.json"

def _load_workspace_index() -> dict:
    if WORKSPACE_INDEX_FILE.exists():
        try: return json.loads(WORKSPACE_INDEX_FILE.read_text())
        except Exception as e:
            logger.warning(f"Corrupt workspace index file, resetting: {e}")
    return {"workspaces": {}, "active": "default"}

def _save_workspace_index(idx: dict) -> None:
    WORKSPACE_INDEX_FILE.write_text(json.dumps(idx, indent=2))
def _load_workspace(name: str) -> dict:
    path = WORKSPACE_DIR / f"{name}.json"
    if path.exists():
        try: return json.loads(path.read_text())
        except Exception as e:
            logger.warning(f"Corrupt workspace file '{name}', creating fresh: {e}")
    return {"name": name, "iocs": [], "blocklist": [],
            "ignored_iocs": [], "webhooks": [],
            "created": datetime.now(timezone.utc).isoformat()}
def _save_workspace(name: str, data: dict) -> None:
    path = WORKSPACE_DIR / f"{name}.json"
    path.write_text(json.dumps(data, indent=2, default=str))

def _get_active_workspace() -> dict:
    idx = _load_workspace_index()
    return _load_workspace(idx.get("active", "default"))

def _save_active_workspace(data: dict) -> None:
    idx = _load_workspace_index()
    _save_workspace(idx.get("active", "default"), data)

class WorkspaceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=64, pattern=r'^[a-zA-Z0-9_-]+$')

class WorkspaceSwitch(BaseModel):
    name: str

@app.get("/api/workspaces")
def list_workspaces():
    idx = _load_workspace_index()
    ws_list = []
    for name in idx.get("workspaces", {}):
        ws_list.append({"name": name, **idx["workspaces"][name]})
    if "default" not in idx.get("workspaces", {}):
        ws_list.insert(0, {"name": "default", "created": "first run"})
    return {"workspaces": ws_list, "active": idx.get("active", "default")}

@app.post("/api/workspaces")
def create_workspace(req: WorkspaceCreate):
    idx = _load_workspace_index()
    if req.name in idx.get("workspaces", {}):
        raise HTTPException(409, f"Workspace '{req.name}' already exists")
    ws = _load_workspace(req.name)
    _save_workspace(req.name, ws)
    if "workspaces" not in idx: idx["workspaces"] = {}
    idx["workspaces"][req.name] = {"created": ws["created"]}
    _save_workspace_index(idx)
    return {"status": "ok", "workspace": req.name}

@app.post("/api/workspaces/switch")
def switch_workspace(req: WorkspaceSwitch):
    idx = _load_workspace_index()
    if req.name not in idx.get("workspaces", {}) and req.name != "default":
        raise HTTPException(404, f"Workspace '{req.name}' not found")
    idx["active"] = req.name
    _save_workspace_index(idx)
    return {"status": "ok", "active": req.name}

@app.delete("/api/workspaces/{name}")
def delete_workspace(name: str):
    idx = _load_workspace_index()
    if name not in idx.get("workspaces", {}):
        raise HTTPException(404, f"Workspace '{name}' not found")
    if name == idx.get("active"):
        raise HTTPException(400, "Cannot delete active workspace")
    path = WORKSPACE_DIR / f"{name}.json"
    if path.exists(): path.unlink()
    del idx["workspaces"][name]
    _save_workspace_index(idx)
    return {"status": "ok", "deleted": name}


# ── Ignore / False Positive Marking ──────────────────────────────────────
class IgnoreMarkRequest(BaseModel):
    ioc: str
    note: Optional[str] = ""

@app.post("/api/ignore-mark")
def mark_ignored(req: IgnoreMarkRequest):
    ws = _get_active_workspace()
    existing = [x for x in ws.get("ignored_iocs", []) if x["ioc"] != req.ioc]
    existing.append({"ioc": req.ioc, "note": req.note or "", "timestamp": datetime.now(timezone.utc).isoformat()})
    ws["ignored_iocs"] = existing
    _save_active_workspace(ws)
    return {"status": "ok", "ioc": req.ioc}

@app.delete("/api/ignore-mark")
def unmark_ignored(req: IgnoreMarkRequest):
    ws = _get_active_workspace()
    ws["ignored_iocs"] = [x for x in ws.get("ignored_iocs", []) if x["ioc"] != req.ioc]
    _save_active_workspace(ws)
    return {"status": "ok", "ioc": req.ioc}

@app.get("/api/ignore-mark")
def get_ignored():
    ws = _get_active_workspace()
    return {"ignored": ws.get("ignored_iocs", [])}


# ── Bulk IOC Import ──────────────────────────────────────────────────────
class BulkInvestigateRequest(BaseModel):
    iocs: list[str] = Field(..., max_length=100)
    background: bool = False

class BulkInvestigateResponse(BaseModel):
    total: int
    succeeded: int
    failed: int
    results: list[dict]
    errors: list[dict]

@app.post("/api/bulk-investigate", response_model=BulkInvestigateResponse)
def bulk_investigate(req: BulkInvestigateRequest):
    results = []
    errors = []
    for ioc in req.iocs:
        ioc = ioc.strip()
        if not ioc: continue
        is_valid, msg = validate_ioc(ioc)
        if not is_valid:
            errors.append({"ioc": ioc, "error": msg})
            continue
        try:
            result = investigate(ioc)
            results.append(result)
        except Exception as e:
            errors.append({"ioc": ioc, "error": str(e)})
    return BulkInvestigateResponse(
        total=len(req.iocs),
        succeeded=len(results),
        failed=len(errors),
        results=results,
        errors=errors,
    )


# ── Webhook Notifications ────────────────────────────────────────────────
class WebhookConfig(BaseModel):
    url: str = Field(..., max_length=1024)
    events: list[str] = Field(default_factory=lambda: ["CRITICAL", "HIGH"])
    name: Optional[str] = ""

@app.get("/api/webhooks")
def get_webhooks():
    ws = _get_active_workspace()
    return {"webhooks": ws.get("webhooks", [])}

@app.post("/api/webhooks")
def add_webhook(req: WebhookConfig):
    ws = _get_active_workspace()
    hooks = ws.get("webhooks", [])
    hook_id = hashlib.md5(req.url.encode()).hexdigest()[:8]
    entry = {"id": hook_id, "url": req.url, "events": req.events, "name": req.name or req.url}
    hooks = [h for h in hooks if h["id"] != hook_id]
    hooks.append(entry)
    ws["webhooks"] = hooks
    _save_active_workspace(ws)
    return {"status": "ok", "webhook": entry}

@app.delete("/api/webhooks/{hook_id}")
def remove_webhook(hook_id: str):
    ws = _get_active_workspace()
    ws["webhooks"] = [h for h in ws.get("webhooks", []) if h["id"] != hook_id]
    _save_active_workspace(ws)
    return {"status": "ok", "deleted": hook_id}

async def _fire_webhooks(severity: str, ioc: str, report: dict) -> None:
    """Fire webhooks asynchronously without blocking the response."""
    ws = _get_active_workspace()
    hooks = ws.get("webhooks", [])
    if not hooks: return
    payload = json.dumps({
        "event": "ioc_detected",
        "severity": severity,
        "ioc": ioc,
        "ioc_type": report.get("ioc_type", ""),
        "threat_category": report.get("threat_category", ""),
        "ml_verdict": report.get("ml_verdict"),
        "ml_confidence": report.get("ml_confidence"),
        "risk_score": report.get("risk_score"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    import httpx
    async with httpx.AsyncClient(timeout=5.0) as client:
        for hook in hooks:
            if severity in hook.get("events", ["CRITICAL", "HIGH"]):
                try:
                    resp = await client.post(hook["url"], json={"event": "ioc_detected", "data": json.loads(payload)}, headers={"Content-Type": "application/json"})
                    log_alert(ioc, severity, "webhook", "sent" if resp.is_success else "failed", resp.status_code)
                except Exception as e:
                    log_alert(ioc, severity, "webhook", "failed", error=str(e))


async def _notify_hunt_results(critical_high_nodes: list[tuple[str, str]]) -> None:
    """Send notifications for hunt-discovered CRITICAL/HIGH IOCs."""
    from agent.orchestrator import investigate
    for ioc, severity in critical_high_nodes:
        try:
            result = await asyncio.to_thread(investigate, ioc)
            report = result.get("report", {})
            await send_notifications(ioc, severity, report)
            log_alert(ioc, severity, "notification", "sent", None, None)
        except Exception as e:
            log_alert(ioc, severity, "notification", "failed", None, error=str(e))
            logger.warning(f"Notification failed for hunt IOC {ioc}: {e}")


async def _send_notification_async(ioc: str, severity: str, report: dict) -> None:
    """Send notification and log result to alerts table."""
    try:
        result = await send_notifications(ioc, severity, report)
        for channel, res in result.items():
            if res:
                log_alert(ioc, severity, channel, res.get("status", "unknown"), None, res.get("detail"))
    except Exception as e:
        log_alert(ioc, severity, "notification", "error", None, str(e))
        logger.warning(f"Notification dispatch failed for {ioc}: {e}")


# ── STIX 2.1 Export ─────────────────────────────────────────────────────
@app.get("/api/export/stix")
def export_stix():
    """Export investigation history as STIX 2.1 bundle."""
    ws = _get_active_workspace()
    iocs = ws.get("iocs", [])

    objects = []
    identity = {
        "type": "identity",
        "id": "identity--" + hashlib.md5(b"threat-intel-agent").hexdigest()[:36],
        "name": "Threat Intelligence Agent",
        "identity_class": "system",
    }
    objects.append(identity)

    for entry in iocs[-200:]:
        threat_report = entry.get("report", {})
        sev = entry.get("severity", "UNKNOWN")
        obj_id = "indicator--" + hashlib.md5(entry.get("ioc", "").encode()).hexdigest()[:36]
        indicator = {
            "type": "indicator",
            "id": obj_id,
            "created": entry.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "modified": entry.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "name": f"IOC: {entry.get('ioc', '')}",
            "pattern": f"[{entry.get('ioc_type', 'unknown')}:value = '{entry.get('ioc', '')}']",
            "pattern_type": "stix",
            "valid_from": entry.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "severity": sev,
            "confidence": threat_report.get("confidence_score", 50),
            "description": threat_report.get("summary", ""),
            "labels": [sev.lower(), threat_report.get("threat_category", "unknown").lower().replace(" ", "-")],
            "created_by_ref": identity["id"],
        }
        objects.append(indicator)

        if threat_report.get("mitre_techniques"):
            for t in threat_report["mitre_techniques"][:3]:
                attack_id = t.get("technique_id", "")
                if attack_id:
                    rel_id = "relationship--" + hashlib.md5((entry.get("ioc", "") + attack_id).encode()).hexdigest()[:36]
                    objects.append({
                        "type": "relationship",
                        "id": rel_id,
                        "relationship_type": "indicates",
                        "source_ref": obj_id,
                        "target_ref": "attack-pattern--" + hashlib.md5(attack_id.encode()).hexdigest()[:36],
                        "created": entry.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        "modified": entry.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    })

    bundle = {"type": "bundle", "id": "bundle--" + hashlib.md5(str(datetime.now(timezone.utc).timestamp()).encode()).hexdigest()[:36], "objects": objects}
    return bundle


# ── Online Learning / Feedback ──────────────────────────────────────────
class FeedbackRecord(BaseModel):
    ioc: str
    features: dict = Field(default_factory=dict)
    predicted_severity: str
    user_label: str
    source: str = "user_feedback"

FEEDBACK_FILE = Path(ROOT_DIR) / "data" / "feedback_data.json"

def _load_feedback():
    if FEEDBACK_FILE.exists():
        try: return json.loads(FEEDBACK_FILE.read_text())
        except Exception as e:
            logger.warning(f"Corrupt feedback file, resetting: {e}")
    return []

def _save_feedback(records: list):
    FEEDBACK_FILE.write_text(json.dumps(records, indent=2))

@app.post("/api/feedback")
def submit_feedback(req: FeedbackRecord):
    records = _load_feedback()
    records.append({"ioc": req.ioc, "features": req.features, "predicted": req.predicted_severity, "user_label": req.user_label, "source": req.source, "timestamp": datetime.now(timezone.utc).isoformat()})
    _save_feedback(records)
    return {"status": "ok", "total_feedback": len(records)}

@app.get("/api/feedback")
def get_feedback():
    records = _load_feedback()
    return {"feedback": records[-200:], "total": len(records)}

@app.post("/api/feedback/retrain")
async def retrain_from_feedback(background_tasks: BackgroundTasks):
    """Trigger online learning from collected feedback."""
    records = _load_feedback()
    if len(records) < 10:
        raise HTTPException(400, f"Need at least 10 feedback records, have {len(records)}")
    background_tasks.add_task(_run_online_learning, records)
    return {"status": "started", "records": len(records)}

def _run_online_learning(records: list):
    """Update risk model weights from feedback (simulated online learning)."""
    from utils.risk_model import extract_features, train_model, save_model, MODEL_PATH
    training = []
    for r in records[-100:]:
        text = f"[VirusTotal] IOC: {r['ioc']}\n  ML prediction: {r['predicted']}\n  User label: {r['user_label']}"
        features_text = "  ".join(f"{k}={v}" for k, v in r.get("features", {}).items())
        text += f"\n  Features: {features_text}"
        label = 1 if r["user_label"].upper() in ("CRITICAL", "HIGH", "MEDIUM") else 0
        training.append({"text": text, "label": label})
    if training:
        model = train_model(training, epochs=200, learning_rate=0.05)
        save_model(model, MODEL_PATH)
        print(f"[Online Learning] Retrained on {len(training)} feedback records.")


# ── ML Explainability (SHAP-style feature contributions) ────────────────
class ExplainRequest(BaseModel):
    ioc: str

_SHAP_EXPLAINER = None
_SHAP_FEATURE_COLS = None

def _get_shap_explainer():
    global _SHAP_EXPLAINER, _SHAP_FEATURE_COLS
    if _SHAP_EXPLAINER is None:
        try:
            import joblib, shap, pandas as pd
            artifact = joblib.load(os.path.join(ROOT_DIR, "models", "severity_classifier.joblib"))
            _SHAP_FEATURE_COLS = joblib.load(os.path.join(ROOT_DIR, "models", "feature_cols.joblib"))
            _SHAP_EXPLAINER = shap.TreeExplainer(artifact["xgb"])
            logger.info("SHAP TreeExplainer initialized for XGBoost model")
        except Exception as e:
            logger.warning(f"Failed to load SHAP explainer, falling back to raw features: {e}")
            _SHAP_EXPLAINER = False
    return _SHAP_EXPLAINER, _SHAP_FEATURE_COLS

FEATURE_LABELS = {
    "vt_malicious_ratio": "VT Malicious Ratio", "vt_suspicious_count": "VT Suspicious Count",
    "vt_reputation": "VT Reputation", "abuse_confidence": "AbuseIPDB Confidence",
    "abuse_total_reports": "AbuseIPDB Reports", "abuse_distinct_users": "AbuseIPDB Users",
    "abuse_is_tor": "Tor Exit Node", "abuse_categories_count": "Abuse Categories",
    "shodan_open_ports_count": "Open Ports", "shodan_cve_count": "CVEs on Ports",
    "shodan_has_port_22": "SSH Port Open", "shodan_has_port_445": "SMB Port Open",
    "shodan_has_port_3389": "RDP Port Open", "tag_count": "Threat Tags",
    "has_known_family": "Known Malware Family", "is_ip": "Is IP", "is_domain": "Is Domain",
    "is_hash": "Is Hash", "is_tor": "Tor Network", "otx_pulse_count": "OTX Pulse Count",
    "otx_avg_confidence": "OTX Avg Confidence", "otx_has_scan": "OTX Port Scan",
    "vt_abuse_agreement": "VT+Abuse Agreement", "threat_signal_sum": "Threat Signal Sum",
    "port_attack_surface": "Port Attack Surface", "cve_per_port": "CVE Density",
    "reports_per_user": "Reports per Reporter", "malicious_family": "Malicious Family",
    "tor_reputation_risk": "Tor Reputation Risk", "otx_vt_corroboration": "OTX+VT Corroboration",
    "shodan_exposure_score": "Shodan Exposure", "has_vt_data": "Has VT Data",
    "has_abuse_data": "Has AbuseIPDB Data", "has_shodan_data": "Has Shodan Data",
    "vt_harmless_ratio": "VT Harmless Ratio",
}

def _get_xgb_importance():
    """Get global feature importance from the XGBoost model as static fallback."""
    try:
        import joblib
        artifact = joblib.load(os.path.join(ROOT_DIR, "models", "severity_classifier.joblib"))
        cols = joblib.load(os.path.join(ROOT_DIR, "models", "feature_cols.joblib"))
        xgb = artifact["xgb"]
        imp = xgb.feature_importances_
        return {col: float(imp[i]) for i, col in enumerate(cols) if i < len(imp)}
    except Exception:
        return None

def _compute_shap_contributions(ml_features: dict) -> list | None:
    explainer, feature_cols = _get_shap_explainer()
    if not explainer or not feature_cols or not ml_features:
        return None
    try:
        import pandas as pd
        import numpy as np
        X = pd.DataFrame([ml_features])[feature_cols]
        shap_values = explainer.shap_values(X)
        pred = explainer.model.predict(X)
        predicted_class = int(pred[0].item() if hasattr(pred[0], "item") else pred[0])
        if shap_values.ndim == 3:
            class_shap = shap_values[0, :, predicted_class]
        elif isinstance(shap_values, list):
            class_shap = shap_values[predicted_class][0]
        else:
            class_shap = shap_values[0]
        return [
            {"feature": col, "value": round(abs(float(v)), 4),
             "name": FEATURE_LABELS.get(col, col.replace("_", " ").title()),
             "direction": "increases" if v > 0 else "decreases", "impact": round(abs(float(v)), 4)}
            for col, v in zip(feature_cols, class_shap) if abs(float(v)) > 0.0001
        ]
    except Exception as e:
        logger.warning(f"SHAP computation failed: {e}")
        return None

@app.post("/api/explain")
def explain_prediction(req: ExplainRequest):
    """Return SHAP feature contributions for an IOC prediction."""
    ioc = req.ioc.strip()
    if not ioc:
        raise HTTPException(400, "IOC cannot be empty")
    is_valid, msg = validate_ioc(ioc)
    if not is_valid:
        raise HTTPException(422, msg)
    try:
        result = investigate(ioc)
    except Exception as e:
        raise HTTPException(500, f"Investigation failed: {e}")

    report = result.get("report", {})
    ml_features = result.get("ml_features", {})

    has_data = any(ml_features.get(k, 0) for k in ("has_vt_data", "has_abuse_data", "has_shodan_data"))

    contributions = _compute_shap_contributions(ml_features) if has_data else None
    if contributions is not None:
        contributions.sort(key=lambda x: -abs(x["impact"]))
    elif has_data:
        xgb_imp = _get_xgb_importance()
        if xgb_imp:
            contributions = [
                {"feature": k, "name": FEATURE_LABELS.get(k, k.replace("_", " ").title()),
                 "value": round(abs(ml_features.get(k, 0)), 4), "direction": "increases" if ml_features.get(k, 0) > 0 else "decreases",
                 "impact": round(v, 6)}
                for k, v in sorted(xgb_imp.items(), key=lambda x: -x[1])[:10]
                if abs(ml_features.get(k, 0)) > 0
            ]
        else:
            contributions = [
                {"feature": k, "name": FEATURE_LABELS.get(k, k.replace("_", " ").title()),
                 "value": round(abs(v), 4), "direction": "increases" if v > 0 else "decreases",
                 "impact": round(abs(v), 4)}
                for k, v in sorted(ml_features.items(), key=lambda x: -abs(x[1]) if isinstance(x[1], (int, float)) else 0)
                if isinstance(v, (int, float)) and abs(v) > 0
            ][:10]

    return {
        "ioc": ioc,
        "severity": report.get("severity", "UNKNOWN"),
        "confidence": report.get("confidence_score", 0),
        "model_name": report.get("model_name", "Ensemble(XGB+LGB)"),
        "ml_verdict": report.get("ml_verdict"),
        "ml_confidence": report.get("ml_confidence"),
        "feature_contributions": contributions[:15] if contributions else [],
        "explanation": _generate_explanation(report, contributions, has_data),
    }

def _generate_explanation(report: dict, contributions: list | None, has_data: bool = False) -> str:
    sev = report.get("severity", "UNKNOWN")
    ml_sev = report.get("ml_verdict")
    summary = (report.get("summary") or "").lower()

    if not has_data:
        if ml_sev:
            return f"The ML model predicts {ml_sev} based on IOC type and limited signals, but no real-time enrichment data was available (API keys may not be configured). The primary severity ({sev}) is from the fallback text-analysis model reading the evidence text."
        return f"No API enrichment data available. The severity ({sev}) is based on text analysis of the evidence output."

    top_features = contributions[:5] if contributions else []
    if not top_features:
        return "No feature data available for explanation."

    feat_labels = {
        "abuse_confidence": "reported by multiple security sources",
        "abuse_total_reports": "total reports from security researchers",
        "abuse_distinct_users": "unique reporters flagging this",
        "is_ip": "identified as an IP address",
        "is_domain": "identified as a domain name",
        "is_hash": "identified as a file hash",
        "threat_signal_sum": "combined threat signals detected",
        "vt_malicious": "flagged malicious by VirusTotal scanners",
        "vt_suspicious": "flagged suspicious by VirusTotal scanners",
        "vt_harmless": "flagged harmless by VirusTotal scanners",
        "vt_undetected": "no detection from VirusTotal scanners",
        "risk_score": "overall risk assessment score",
        "has_mx_record": "has a mail exchange record",
        "has_nameserver": "has a nameserver record",
        "domain_age_days": "age of the domain in days",
        "domain_uses_https": "uses HTTPS connection",
        "ssl_grade": "SSL certificate grade",
        "cdn_uses_cloudflare": "uses Cloudflare CDN",
        "cdn_uses_akamai": "uses Akamai CDN",
        "cdn_uses_fastly": "uses Fastly CDN",
        "port_80_open": "port 80 (HTTP) is open",
        "port_443_open": "port 443 (HTTPS) is open",
        "port_22_open": "port 22 (SSH) is open",
        "port_21_open": "port 21 (FTP) is open",
        "has_rdns": "has a reverse DNS record",
        "rdns_matches_domain": "reverse DNS matches the domain",
        "asn_number": "autonomous system number",
        "asn_name": "network provider name",
        "country": "country of origin",
        "cloud_provider": "hosted by a cloud provider",
        "ml_confidence": "ML model confidence score",
    }

    bullet_labels = []
    bullet_severity = []
    for feat in top_features:
        key = feat["feature"]
        label = feat_labels.get(key, key.replace("_", " ").title())
        if feat["direction"] == "increases":
            bullet_labels.append(label)
            bullet_severity.append("higher")
        else:
            bullet_labels.append(label)
            bullet_severity.append("lower")

    lines = []
    ioc_type = report.get("ioc_type", "")

    if bullet_labels:
        if len(bullet_labels) <= 3:
            reasons = ", ".join(bullet_labels[:-1]) + ", and " + bullet_labels[-1] if len(bullet_labels) > 1 else bullet_labels[0]
        else:
            reasons = ", ".join(bullet_labels[:3]) + ", and other factors"
        lines.append(f"Our system flagged this because {reasons} point to suspicious behavior.")
    else:
        lines.append("Our system detected suspicious activity associated with this indicator.")

    ml_v = report.get("ml_verdict")
    conf = report.get("ml_confidence", 0)
    if ml_v and conf:
        if conf >= 80:
            conf_text = "We are highly confident"
        elif conf >= 60:
            conf_text = "We are moderately confident"
        else:
            conf_text = "We suspect"
        lines.append(f"{conf_text} this is {ml_v.lower() if ml_v != 'CLEAN' else 'safe'} ({conf}% confidence).")

    return " ".join(lines)


# ── Enhanced Dashboard Metrics ──────────────────────────────────────────
@app.get("/api/metrics")
def get_metrics():
    """Return aggregate statistics for dashboard."""
    ws = _get_active_workspace()
    iocs = ws.get("iocs", [])
    total = len(iocs)
    sev_dist = defaultdict(int)
    cat_dist = defaultdict(int)
    type_dist = defaultdict(int)
    for e in iocs:
        r = e.get("report", {})
        sev_dist[r.get("severity", "UNKNOWN")] += 1
        cat_dist[r.get("threat_category", "Unclassified")] += 1
        type_dist.get(e.get("ioc_type", "unknown"), 0)
        type_dist[e.get("ioc_type", "unknown")] += 1

    ml_confidences = [r.get("report", {}).get("ml_confidence", 0) for r in iocs if r.get("report", {}).get("ml_confidence")]
    risk_scores = [r.get("report", {}).get("risk_score", 0) for r in iocs if r.get("report", {}).get("risk_score") is not None]

    # Trend: investigations per day (last 7 days)
    from collections import Counter
    day_counts = Counter()
    for e in iocs:
        ts = e.get("timestamp", "")
        day = ts[:10] if ts else ""
        if day: day_counts[day] += 1
    trend = sorted([{"date": d, "count": c} for d, c in day_counts.items()], key=lambda x: x["date"])[-14:]

    return {
        "total_investigations": total,
        "severity_distribution": dict(sev_dist),
        "category_distribution": dict(cat_dist),
        "type_distribution": dict(type_dist),
        "avg_ml_confidence": round(sum(ml_confidences) / len(ml_confidences), 1) if ml_confidences else 0,
        "avg_risk_score": round(sum(risk_scores) / len(risk_scores), 4) if risk_scores else 0,
        "trend": trend,
        "feedback_count": len(_load_feedback()),
        "ignored_count": len(ws.get("ignored_iocs", [])),
        "blocklist_count": len(ws.get("blocklist", [])),
        "webhook_count": len(ws.get("webhooks", [])),
    }


# ── Integrate webhook firing into investigate path ──────────────────────
@app.post("/investigate", response_model=InvestigateResponse)
async def investigate_ioc_async(request: InvestigateRequest):
    ioc = request.ioc.strip()
    if not ioc:
        raise HTTPException(status_code=400, detail="IOC cannot be empty.")
    is_valid, msg = validate_ioc(ioc)
    if not is_valid:
        raise HTTPException(status_code=422, detail=msg)
    try:
        result = investigate(ioc)
        # Save to active workspace (JSON, for backward compatibility)
        ws = _get_active_workspace()
        entry = {"ioc": result["ioc"], "ioc_type": result["ioc_type"], "severity": result.get("severity"), "report": result.get("report"), "timestamp": datetime.now(timezone.utc).isoformat()}
        ws.setdefault("iocs", []).insert(0, entry)
        ws["iocs"] = ws["iocs"][:500]
        _save_active_workspace(ws)

        # Save to SQLite database
        try:
            r = result.get("report", {})
            save_investigation({
                "ioc": result["ioc"], "ioc_type": result["ioc_type"],
                "severity": result.get("severity", "UNKNOWN"),
                "summary": r.get("summary", ""),
                "threat_category": r.get("threat_category", ""),
                "risk_score": r.get("risk_score", 0),
                "confidence_score": r.get("confidence_score", 0),
                "ml_verdict": r.get("ml_verdict"),
                "ml_confidence": r.get("ml_confidence"),
                "report": r,
                "workspace": _get_active_workspace_name(),
            })
        except Exception as e:
            logger.error(f"Failed to save investigation for {result.get('ioc', 'unknown')}: {e}")

        # Fire webhooks asynchronously
        severity = result.get("severity", "UNKNOWN")
        if severity in ("CRITICAL", "HIGH"):
            asyncio.create_task(_fire_webhooks(severity, result["ioc"], result.get("report", {})))
            asyncio.create_task(_send_notification_async(result["ioc"], severity, result.get("report", {})))

        return InvestigateResponse(
            ioc=result["ioc"],
            ioc_type=result["ioc_type"],
            agent_output=result["agent_output"],
            report=result["report"],
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")


# ───────────────────────────────────────────────────────────────────────────
# TIER 6 — Database, Alerts, Feeds & Export
# ───────────────────────────────────────────────────────────────────────────

def _get_active_workspace_name() -> str:
    idx = _load_workspace_index()
    return idx.get("active", "default")

class DBSearchRequest(BaseModel):
    workspace: str = "default"
    severity: Optional[str] = None
    ioc_type: Optional[str] = None
    search: Optional[str] = None
    limit: int = 100
    offset: int = 0

@app.post("/api/db/search")
def db_search(req: DBSearchRequest):
    return {"results": search_investigations(
        workspace=req.workspace, severity=req.severity,
        ioc_type=req.ioc_type, search=req.search,
        limit=min(req.limit, 500), offset=req.offset,
    )}

@app.get("/api/db/stats")
def db_stats(workspace: str = "default"):
    return get_investigation_stats(workspace)

# ── Alerts ─────────────────────────────────────────────────────────────

@app.get("/api/alerts")
def list_alerts(limit: int = 50, offset: int = 0):
    return {"alerts": get_alerts(limit, offset), "stats": get_alert_stats()}

# ── Feeds ──────────────────────────────────────────────────────────────

class FeedCreateRequest(BaseModel):
    name: str
    url: str
    feed_type: str = "rss"
    interval_minutes: int = 60

@app.get("/api/feeds")
def list_feeds_api():
    return {"feeds": list_feeds()}

@app.post("/api/feeds")
def create_feed(req: FeedCreateRequest):
    fid = add_feed(req.name, req.url, req.feed_type, req.interval_minutes)
    if fid == -1:
        raise HTTPException(400, "Feed URL already exists")
    return {"status": "created", "id": fid}

@app.delete("/api/feeds/{feed_id}")
def delete_feed(feed_id: int):
    if remove_feed(feed_id):
        return {"status": "deleted"}
    raise HTTPException(404, "Feed not found")

@app.get("/api/feeds/entries")
def feed_entries(feed_id: Optional[int] = None, limit: int = 100):
    return {"entries": get_feed_entries(feed_id, limit)}

@app.post("/api/feeds/poll")
async def poll_feeds():
    """Poll all due feeds and extract IOCs."""
    import feedparser
    import re
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

# ── PDF Export ──────────────────────────────────────────────────────────

class PDFExportRequest(BaseModel):
    ioc: str
    workspace: str = "default"

@app.post("/api/export/pdf")
def export_pdf(req: PDFExportRequest):
    """Generate an HTML-based PDF report for an investigation."""
    results = search_investigations(workspace=req.workspace, search=req.ioc, limit=1)
    if not results:
        raise HTTPException(404, "Investigation not found")
    inv = results[0]
    try:
        report = json.loads(inv.get("report_json", "{}"))
    except Exception:
        report = {}
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Investigation Report - {inv['ioc']}</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; margin: 32px; color: #13202e; }}
  h1 {{ font-size: 22px; border-bottom: 2px solid #1a6cf0; padding-bottom: 8px; }}
  .field {{ margin: 8px 0; }}
  .label {{ font-weight: 700; font-size: 11px; color: #5f738c; text-transform: uppercase; }}
  .value {{ font-size: 14px; }}
  .table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
  .table th, .table td {{ padding: 6px 10px; border: 1px solid #dce3ed; text-align: left; font-size: 12px; }}
  .table th {{ background: #f3f6fa; font-weight: 700; }}
  .severity-UNKNOWN {{ color: #5f738c; }}
  .severity-CLEAN {{ color: #1ba861; }}
  .severity-LOW {{ color: #0ea58e; }}
  .severity-MEDIUM {{ color: #d48a1a; }}
  .severity-HIGH {{ color: #c2490a; }}
  .severity-CRITICAL {{ color: #dc3545; }}
</style></head><body>
<h1>Threat Intelligence Report</h1>
<div class="field"><div class="label">IOC</div><div class="value">{inv['ioc']}</div></div>
<div class="field"><div class="label">Type</div><div class="value">{inv.get('ioc_type', '')}</div></div>
<div class="field"><div class="label">Severity</div><div class="value severity-{inv.get('severity', 'UNKNOWN')}"><strong>{inv.get('severity', 'UNKNOWN')}</strong></div></div>
<div class="field"><div class="label">Threat Category</div><div class="value">{inv.get('threat_category', '')}</div></div>
<div class="field"><div class="label">Risk Score</div><div class="value">{inv.get('risk_score', 0)}</div></div>
<div class="field"><div class="label">Confidence</div><div class="value">{inv.get('confidence_score', 0)}</div></div>
<div class="field"><div class="label">Summary</div><div class="value">{inv.get('summary', '')}</div></div>
<div class="field"><div class="label">Investigaton Timestamp</div><div class="value">{inv.get('created_at', '')}</div></div>
<h2>MITRE ATT&CK Techniques</h2>
<table class="table"><tr><th>ID</th><th>Name</th><th>Tactic</th></tr>
"""
    for t in report.get("mitre_techniques", []):
        html += f"<tr><td>{t.get('technique_id', '')}</td><td>{t.get('name', '')}</td><td>{t.get('tactic', '')}</td></tr>"
    html += "</table><h2>Recommended Actions</h2><ul>"
    for a in report.get("recommended_actions", []):
        html += f"<li>{a}</li>"
    html += "</ul></body></html>"
    from fastapi.responses import HTMLResponse
    return HTMLResponse(html)

# ───────────────────────────────────────────────────────────────────────────
# TIER 4 — Integration & Automation
# ───────────────────────────────────────────────────────────────────────────

# ── SIEM Forwarding ──────────────────────────────────────────────────────
SIEM_CONFIG_FILE = Path(ROOT_DIR) / "data" / "siem_config.json"

def _load_siem_config() -> dict:
    if SIEM_CONFIG_FILE.exists():
        try: return json.loads(SIEM_CONFIG_FILE.read_text())
        except Exception as e:
            logger.warning(f"Corrupt SIEM config file, using defaults: {e}")
    return {"enabled": False, "format": "cef", "target": "", "port": 514, "protocol": "udp"}

def _save_siem_config(cfg: dict) -> None:
    SIEM_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    SIEM_CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

class SIEMConfig(BaseModel):
    enabled: bool = False
    format: str = "cef"
    target: str = ""
    port: int = 514
    protocol: str = "udp"

@app.get("/api/integrations/siem")
def get_siem_config():
    return _load_siem_config()

@app.post("/api/integrations/siem")
def set_siem_config(cfg: SIEMConfig):
    _save_siem_config(cfg.model_dump())
    return {"status": "ok"}

@app.post("/api/integrations/siem/forward")
async def forward_to_siem():
    """Forward recent CRITICAL/HIGH IOCs to SIEM as CEF."""
    cfg = _load_siem_config()
    if not cfg.get("enabled") or not cfg.get("target"):
        raise HTTPException(400, "SIEM not configured or disabled")
    ws = _get_active_workspace()
    iocs = ws.get("iocs", [])
    critical_high = [e for e in iocs if e.get("severity") in ("CRITICAL", "HIGH")][:50]
    if not critical_high:
        return {"status": "ok", "forwarded": 0, "message": "No critical/high IOCs to forward"}
    forwarded = 0
    for entry in critical_high:
        r = entry.get("report", {})
        if cfg["format"] == "cef":
            msg = (
                f"CEF:0|ThreatIntel|Agent|1.2|ioc-detected|IOC Detected|5|"
                f"src={entry['ioc'] if entry.get('ioc_type') == 'ip' else ''}"
                f"cs1={entry.get('ioc','')} cs1Label=ioc "
                f"cs2={r.get('severity','UNKNOWN')} cs2Label=severity "
                f"cs3={r.get('threat_category','')} cs3Label=category "
                f"cs4={r.get('ml_verdict','')} cs4Label=ml_verdict "
                f"cn1={r.get('ml_confidence',0)} cn1Label=ml_confidence "
                f"cn2={int(r.get('risk_score',0)*100)} cn2Label=risk_score "
                f"flexString1={entry.get('ioc_type','')} flexString1Label=ioc_type"
            )
        else:
            msg = json.dumps(entry)
        try:
            if cfg["protocol"] == "udp":
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(msg.encode(), (cfg["target"], cfg["port"]))
                sock.close()
            else:
                import socket as sock_mod
                s = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
                s.settimeout(3)
                s.connect((cfg["target"], cfg["port"]))
                s.sendall((msg + "\n").encode())
                s.close()
            forwarded += 1
        except Exception as e:
            logger.warning(f"SIEM forward failed for {entry.get('ioc', 'unknown')}: {e}")
    return {"status": "ok", "forwarded": forwarded, "total": len(critical_high)}


# ── MISP Integration ─────────────────────────────────────────────────────
MISP_CONFIG_FILE = Path(ROOT_DIR) / "data" / "misp_config.json"

def _load_misp_config() -> dict:
    cfg = {"enabled": False, "url": "", "api_key": "", "verify_ssl": True}
    if MISP_CONFIG_FILE.exists():
        try:
            cfg.update(json.loads(MISP_CONFIG_FILE.read_text()))
        except Exception as e:
            logger.warning(f"Corrupt MISP config file, using defaults: {e}")
    if os.getenv("MISP_URL"): cfg["url"] = os.getenv("MISP_URL")
    if os.getenv("MISP_API_KEY"): cfg["api_key"] = os.getenv("MISP_API_KEY")
    if os.getenv("MISP_VERIFY_SSL"): cfg["verify_ssl"] = os.getenv("MISP_VERIFY_SSL").lower() == "true"
    return cfg

def _save_misp_config(cfg: dict) -> None:
    MISP_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    MISP_CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

class MISPConfig(BaseModel):
    enabled: bool = False
    url: str = ""
    api_key: str = ""
    verify_ssl: bool = True

@app.get("/api/integrations/misp")
def get_misp_config():
    cfg = _load_misp_config()
    # Don't expose API key in response
    return {**cfg, "api_key": "********" if cfg.get("api_key") else ""}

@app.post("/api/integrations/misp")
def set_misp_config(cfg: MISPConfig):
    data = cfg.model_dump()
    if data.get("api_key") == "********":
        existing = _load_misp_config()
        data["api_key"] = existing.get("api_key", "")
    _save_misp_config(data)
    return {"status": "ok"}

@app.post("/api/integrations/misp/push")
async def push_to_misp():
    """Push recent CRITICAL/HIGH IOCs to MISP as events."""
    cfg = _load_misp_config()
    if not cfg.get("enabled") or not cfg.get("url") or not cfg.get("api_key"):
        raise HTTPException(400, "MISP not configured")
    ws = _get_active_workspace()
    iocs = ws.get("iocs", [])
    critical_high = [e for e in iocs if e.get("severity") in ("CRITICAL", "HIGH")][:20]
    if not critical_high:
        return {"status": "ok", "pushed": 0}
    import httpx
    pushed = 0
    async with httpx.AsyncClient(verify=cfg["verify_ssl"], timeout=15) as client:
        for entry in critical_high:
            r = entry.get("report", {})
            event = {
                "Event": {
                    "info": f"TIA IOC: {entry['ioc']} — {r.get('severity','UNKNOWN')}",
                    "threat_level_id": 4 if r.get('severity') == 'CRITICAL' else 3,
                    "analysis": 2,
                    "Attribute": [{
                        "type": entry.get('ioc_type') == 'ip' and 'ip-src' or entry.get('ioc_type') == 'domain' and 'domain' or 'md5',
                        "value": entry['ioc'],
                        "category": "Network activity" if entry.get('ioc_type') in ('ip', 'domain') else "Payload delivery",
                        "to_ids": True,
                    }]
                }
            }
            try:
                resp = await client.post(
                    f"{cfg['url'].rstrip('/')}/events",
                    headers={"Authorization": cfg["api_key"], "Accept": "application/json", "Content-Type": "application/json"},
                    json=event,
                )
                if resp.status_code < 400: pushed += 1
            except Exception as e:
                logger.warning(f"MISP push failed for {entry['ioc']}: {e}")
    return {"status": "ok", "pushed": pushed}


# ── OpenCTI Integration ──────────────────────────────────────────────────
OPENCTI_CONFIG_FILE = Path(ROOT_DIR) / "data" / "opencti_config.json"

def _load_opencti_config() -> dict:
    cfg = {"enabled": False, "url": "", "api_key": ""}
    if OPENCTI_CONFIG_FILE.exists():
        try:
            cfg.update(json.loads(OPENCTI_CONFIG_FILE.read_text()))
        except Exception as e:
            logger.warning(f"Corrupt OpenCTI config file, using defaults: {e}")
    if os.getenv("OPENCTI_URL"): cfg["url"] = os.getenv("OPENCTI_URL")
    if os.getenv("OPENCTI_API_KEY"): cfg["api_key"] = os.getenv("OPENCTI_API_KEY")
    return cfg

def _save_opencti_config(cfg: dict) -> None:
    OPENCTI_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    OPENCTI_CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

class OpenCTIConfig(BaseModel):
    enabled: bool = False
    url: str = ""
    api_key: str = ""

@app.get("/api/integrations/opencti")
def get_opencti_config():
    cfg = _load_opencti_config()
    return {**cfg, "api_key": "********" if cfg.get("api_key") else ""}

@app.post("/api/integrations/opencti")
def set_opencti_config(cfg: OpenCTIConfig):
    data = cfg.model_dump()
    if data.get("api_key") == "********":
        existing = _load_opencti_config()
        data["api_key"] = existing.get("api_key", "")
    _save_opencti_config(data)
    return {"status": "ok"}

@app.post("/api/integrations/opencti/push")
async def push_to_opencti():
    cfg = _load_opencti_config()
    if not cfg.get("enabled") or not cfg.get("url") or not cfg.get("api_key"):
        raise HTTPException(400, "OpenCTI not configured")
    ws = _get_active_workspace()
    iocs = ws.get("iocs", [])
    critical_high = [e for e in iocs if e.get("severity") in ("CRITICAL", "HIGH")][:20]
    if not critical_high:
        return {"status": "ok", "pushed": 0}
    import httpx
    pushed = 0
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        for entry in critical_high:
            r = entry.get("report", {})
            query = """
            mutation CreateIndicator($input: IndicatorAddInput!) {
                indicatorAdd(input: $input) { id name }
            }
            """
            variables = {
                "input": {
                    "name": entry['ioc'],
                    "pattern": f"[{entry.get('ioc_type','unknown')}:value = '{entry['ioc']}']",
                    "pattern_type": "stix",
                    "score": 80 if r.get('severity') == 'CRITICAL' else 60,
                    "description": r.get('summary', ''),
                    "x_opencti_main_observable_type": entry.get('ioc_type', 'Unknown'),
                }
            }
            try:
                resp = await client.post(
                    cfg["url"].rstrip("/") + "/graphql",
                    json={"query": query, "variables": variables},
                    headers={"Authorization": f"Bearer {cfg['api_key']}"},
                )
                if resp.status_code < 400: pushed += 1
            except Exception as e:
                logger.warning(f"OpenCTI push failed for {entry['ioc']}: {e}")
    return {"status": "ok", "pushed": pushed}


# ── TheHive Integration ──────────────────────────────────────────────────
THEHIVE_CONFIG_FILE = Path(ROOT_DIR) / "data" / "thehive_config.json"

def _load_thehive_config() -> dict:
    cfg = {"enabled": False, "url": "", "api_key": "", "organisation": ""}
    if THEHIVE_CONFIG_FILE.exists():
        try:
            cfg.update(json.loads(THEHIVE_CONFIG_FILE.read_text()))
        except Exception as e:
            logger.warning(f"Corrupt TheHive config file, using defaults: {e}")
    if os.getenv("THEHIVE_URL"): cfg["url"] = os.getenv("THEHIVE_URL")
    if os.getenv("THEHIVE_API_KEY"): cfg["api_key"] = os.getenv("THEHIVE_API_KEY")
    if os.getenv("THEHIVE_ORG"): cfg["organisation"] = os.getenv("THEHIVE_ORG")
    return cfg

def _save_thehive_config(cfg: dict) -> None:
    THEHIVE_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    THEHIVE_CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

class TheHiveConfig(BaseModel):
    enabled: bool = False
    url: str = ""
    api_key: str = ""
    organisation: str = ""

@app.get("/api/integrations/thehive")
def get_thehive_config():
    cfg = _load_thehive_config()
    return {**cfg, "api_key": "********" if cfg.get("api_key") else ""}

@app.post("/api/integrations/thehive")
def set_thehive_config(cfg: TheHiveConfig):
    data = cfg.model_dump()
    if data.get("api_key") == "********":
        existing = _load_thehive_config()
        data["api_key"] = existing.get("api_key", "")
    _save_thehive_config(data)
    return {"status": "ok"}

@app.post("/api/integrations/thehive/create-case")
async def create_thehive_case(severity_filter: str = "HIGH"):
    """Create a TheHive alert/case from recent IOCs."""
    cfg = _load_thehive_config()
    if not cfg.get("enabled") or not cfg.get("url") or not cfg.get("api_key"):
        raise HTTPException(400, "TheHive not configured")
    ws = _get_active_workspace()
    sevs = ["CRITICAL"] if severity_filter == "CRITICAL" else ["CRITICAL", "HIGH"]
    iocs = [e for e in ws.get("iocs", []) if e.get("severity") in sevs][:10]
    if not iocs:
        return {"status": "ok", "created": False, "message": "No matching IOCs"}
    import httpx
    observables = []
    for e in iocs:
        observables.append({
            "dataType": e.get("ioc_type", "unknown"),
            "data": e["ioc"],
            "message": f"{e.get('severity','UNKNOWN')} — {e.get('report',{}).get('threat_category','')}",
            "tags": [e.get('severity','UNKNOWN').lower(), e.get('report',{}).get('threat_category','unknown').lower()],
        })
    alert = {
        "title": f"TIA: {len(iocs)} malicious IOCs detected",
        "description": f"Auto-created from Threat Intel Agent investigation. {len(iocs)} IOCs with severity {severity_filter}.",
        "severity": 3 if severity_filter == "CRITICAL" else 2,
        "date": int(datetime.now().timestamp()) * 1000,
        "tags": ["threat-intel-agent", "auto"],
        "type": "internal",
        "source": "Threat Intel Agent",
        "sourceRef": f"tia-{int(datetime.now().timestamp())}",
        "observables": observables,
    }
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            resp = await client.post(
                f"{cfg['url'].rstrip('/')}/api/alert",
                json=alert,
                headers={"Authorization": f"Bearer {cfg['api_key']}", "Content-Type": "application/json"},
            )
            if resp.status_code < 400:
                return {"status": "ok", "created": True, "id": resp.json().get("_id", ""), "ioc_count": len(iocs)}
    except Exception as e:
        logger.error(f"TheHive case creation failed: {e}")
    return {"status": "error", "created": False}


# ── YARA Rule Generation ─────────────────────────────────────────────────
class YARARequest(BaseModel):
    iocs: list[str] = Field(default_factory=list)
    rule_name: str = "auto_generated_rule"
    description: str = "Auto-generated YARA rule from Threat Intel Agent"

@app.post("/api/yara/generate")
def generate_yara(req: YARARequest):
    """Generate YARA rules from IOC patterns."""
    rules = []
    hashes = []
    domains = []
    for ioc in req.iocs:
        ioc = ioc.strip()
        if not ioc: continue
        if re.match(r'^[a-fA-F0-9]{32}$', ioc): hashes.append(ioc)
        elif re.match(r'^[a-fA-F0-9]{64}$', ioc): hashes.append(ioc)
        elif re.match(r'^[a-fA-F0-9]{40}$', ioc): hashes.append(ioc)
        elif re.match(r'^[\w\-]+(\.[\w\-]+)+$', ioc): domains.append(ioc)

    conditions = []
    if hashes:
        conditions.append(" or ".join(f"$hash_{i} = \"{h}\"" for i, h in enumerate(hashes)))
    if domains:
        conditions.append(" or ".join(f"$domain_{i} contains \"{d}\"" for i, d in enumerate(domains)))

    if not conditions:
        # Generate from IOCs as strings
        conditions = [f"$ioc_{i} contains \"{ioc}\"" for i, ioc in enumerate(req.iocs[:20])]

    meta_lines = [
        f"\tdescription = \"{req.description}\"",
        f"\tgenerated_by = \"Threat Intel Agent\"",
        f"\tgenerated_at = \"{datetime.now(timezone.utc).isoformat()}\"",
        f"\tioc_count = \"{len(req.iocs)}\"",
    ]
    if hashes: meta_lines.append(f"\thash_count = \"{len(hashes)}\"")
    if domains: meta_lines.append(f"\tdomain_count = \"{len(domains)}\"")

    rule = (
        f"rule {req.rule_name[:64].replace(' ', '_').replace('-', '_')} {{\n"
        + "\n".join(meta_lines) + "\n"
        + "\tcondition:\n"
        + "\t\t" + " or ".join(f"({c})" for c in conditions) + "\n"
        + "}"
    )
    rules.append(rule)

    return {"status": "ok", "rules": rules, "rule_count": len(rules)}

@app.get("/api/yara/generate-from-workspace")
def generate_yara_from_workspace(rule_name: str = "threat_intel_blocklist", max_iocs: int = 50):
    """Generate YARA rule from workspace IOCs."""
    ws = _get_active_workspace()
    iocs = [e["ioc"] for e in ws.get("iocs", []) if e.get("ioc")][:max_iocs]
    blocklist = ws.get("blocklist", [])
    all_iocs = list(set(iocs + blocklist))[:max_iocs]
    return generate_yara(YARARequest(iocs=all_iocs, rule_name=rule_name))


# ── Email / Slack / Teams Notifications ───────────────────────────────────
NOTIFICATION_CONFIG_FILE = Path(ROOT_DIR) / "data" / "notification_config.json"

def _load_notification_config() -> dict:
    cfg = {"email": {"enabled": False, "smtp_host": "", "smtp_port": 587, "smtp_user": "", "smtp_pass": "", "from_addr": "", "to_addrs": []}, "slack": {"enabled": False, "webhook_url": ""}, "teams": {"enabled": False, "webhook_url": ""}}
    if NOTIFICATION_CONFIG_FILE.exists():
        try:
            cfg.update(json.loads(NOTIFICATION_CONFIG_FILE.read_text()))
        except Exception as e:
            logger.warning(f"Corrupt notification config file, using defaults: {e}")
    if os.getenv("SLACK_WEBHOOK_URL"): cfg["slack"]["webhook_url"] = os.getenv("SLACK_WEBHOOK_URL")
    if os.getenv("TEAMS_WEBHOOK_URL"): cfg["teams"]["webhook_url"] = os.getenv("TEAMS_WEBHOOK_URL")
    if os.getenv("SMTP_HOST"): cfg["email"]["smtp_host"] = os.getenv("SMTP_HOST")
    if os.getenv("SMTP_PORT"): cfg["email"]["smtp_port"] = int(os.getenv("SMTP_PORT"))
    if os.getenv("SMTP_USER"): cfg["email"]["smtp_user"] = os.getenv("SMTP_USER")
    if os.getenv("SMTP_PASS"): cfg["email"]["smtp_pass"] = os.getenv("SMTP_PASS")
    if os.getenv("SMTP_FROM"): cfg["email"]["from_addr"] = os.getenv("SMTP_FROM")
    if os.getenv("SMTP_TO"): cfg["email"]["to_addrs"] = os.getenv("SMTP_TO").split(",")
    return cfg

def _save_notification_config(cfg: dict) -> None:
    NOTIFICATION_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    NOTIFICATION_CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

@app.get("/api/integrations/notifications")
def get_notification_config():
    cfg = _load_notification_config()
    safe = cfg.copy()
    if "smtp_pass" in safe.get("email", {}): safe["email"]["smtp_pass"] = "********" if safe["email"]["smtp_pass"] else ""
    return safe

@app.post("/api/integrations/notifications")
def set_notification_config(cfg: dict):
    _save_notification_config(cfg)
    return {"status": "ok"}

@app.post("/api/integrations/notifications/test")
async def test_notification(channel: str = "slack"):
    """Send a test notification."""
    cfg = _load_notification_config()
    import httpx
    async with httpx.AsyncClient(timeout=10) as client:
        if channel == "slack" and cfg.get("slack", {}).get("webhook_url"):
            try:
                resp = await client.post(cfg["slack"]["webhook_url"], json={"text": "🟢 Threat Intel Agent — Test notification successful"})
                return {"status": "ok" if resp.status_code < 400 else "error"}
            except Exception as e: return {"status": "error", "detail": str(e)}
        if channel == "teams" and cfg.get("teams", {}).get("webhook_url"):
            try:
                resp = await client.post(cfg["teams"]["webhook_url"], json={"title": "Test Notification", "text": "Threat Intel Agent — test successful"})
                return {"status": "ok" if resp.status_code < 400 else "error"}
            except Exception as e: return {"status": "error", "detail": str(e)}
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
                    if e.get("smtp_user"): server.login(e["smtp_user"], e["smtp_pass"])
                    server.send_message(msg)
                return {"status": "ok"}
            except Exception as e: return {"status": "error", "detail": str(e)}
    return {"status": "error", "detail": "Channel not configured"}


# ── SSE Investigation Streaming (Tier 5) ─────────────────────────────────
@app.get("/api/investigate/stream/{ioc:path}")
async def stream_investigation(ioc: str, background_tasks: BackgroundTasks):
    """SSE endpoint that streams investigation progress."""
    from fastapi.responses import StreamingResponse
    import asyncio

    async def event_stream():
        yield f"data: {json.dumps({'event': 'start', 'ioc': ioc})}\n\n"
        await asyncio.sleep(0.1)

        is_valid, msg = validate_ioc(ioc)
        if not is_valid:
            yield f"data: {json.dumps({'event': 'error', 'detail': msg})}\n\n"
            return

        ioc_type = msg.split(": ")[-1] if ": " in msg else "unknown"
        yield f"data: {json.dumps({'event': 'classified', 'ioc_type': ioc_type})}\n\n"
        await asyncio.sleep(0.05)

        try:
            yield f"data: {json.dumps({'event': 'progress', 'message': 'Querying enrichment sources...'})}\n\n"
            result = await asyncio.to_thread(investigate, ioc)
            severity = result.get("severity", "UNKNOWN")
            report = result.get("report", {})

            if severity in ("CRITICAL", "HIGH"):
                background_tasks.add_task(_notify_and_log, ioc, severity, report)

            ml_features = result.get("ml_features", {})
            yield f"data: {json.dumps({'event': 'result', 'severity': severity, 'ioc_type': result.get('ioc_type'), 'confidence': report.get('confidence_score', 0), 'risk_score': report.get('risk_score', 0), 'ml_verdict': report.get('ml_verdict'), 'ml_confidence': report.get('ml_confidence'), 'summary': report.get('summary', ''), 'threat_category': report.get('threat_category'), 'mitre_techniques': report.get('mitre_techniques', []), 'recommended_actions': report.get('recommended_actions', []), 'ml_features': ml_features})}\n\n"
            yield f"data: {json.dumps({'event': 'complete'})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'event': 'error', 'detail': str(e)})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "Connection": "keep-alive"})


async def _notify_and_log(ioc: str, severity: str, report: dict) -> None:
    """Run webhooks and notifications, then log to alerts DB. Called via BackgroundTasks."""
    await _fire_webhooks(severity, ioc, report)
    try:
        result = await send_notifications(ioc, severity, report)
        for channel, res in result.items():
            if res:
                log_alert(ioc, severity, channel, res.get("status", "unknown"), None, res.get("detail"))
    except Exception as e:
        log_alert(ioc, severity, "notification", "error", None, str(e))
        logger.warning(f"Notification dispatch failed for {ioc}: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
