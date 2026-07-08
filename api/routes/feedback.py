"""Feedback loop, metrics, and online learning endpoints."""

import logging
from collections import defaultdict
from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request

from api.dependencies import (
    _feedback_lock,
    _get_active_workspace,
    _get_client_ip,
    _load_feedback,
    _save_feedback,
)
from api.models import FeedbackRecord

logger = logging.getLogger(__name__)
router = APIRouter(tags=["feedback"])

VALID_SEVERITIES = {"CRITICAL", "HIGH", "LOW", "CLEAN", "UNKNOWN"}
SEVERITY_RANK_FB = {"CLEAN": 0, "LOW": 1, "HIGH": 2, "CRITICAL": 3}

_feedback_flips: dict[str, list[dict]] = defaultdict(list)
_FLIP_WINDOW = 3600
_FLIP_THRESHOLD = 0.20


def _is_label_flip(predicted: str, user_label: str) -> bool:
    if predicted == user_label:
        return False
    rank = SEVERITY_RANK_FB
    if abs(rank.get(predicted, 1) - rank.get(user_label, 1)) >= 2:
        return True
    return {predicted, user_label} == {"HIGH", "CLEAN"}


def _run_online_learning(records: list):
    from utils.risk_model import MODEL_PATH, save_model, train_model
    training = []
    for r in records[-100:]:
        text = f"[VirusTotal] IOC: {r['ioc']}\n  ML prediction: {r['predicted']}\n  User label: {r['user_label']}"
        features_text = "  ".join(f"{k}={v}" for k, v in r.get("features", {}).items())
        text += f"\n  Features: {features_text}"
        label = 1 if r["user_label"].upper() in ("CRITICAL", "HIGH") else 0
        training.append({"text": text, "label": label})
    if training:
        model = train_model(training, epochs=200, learning_rate=0.05)
        save_model(model, MODEL_PATH)
        logger.info("Online learning retrained on %d feedback records", len(training))


@router.post("/api/feedback")
def submit_feedback(req: FeedbackRecord, request: Request):
    client_ip = _get_client_ip(request)
    now = datetime.now(UTC).timestamp()
    flips = _feedback_flips[client_ip]
    flips[:] = [f for f in flips if now - f["ts"] < _FLIP_WINDOW]
    flip_count = sum(1 for f in flips if f["is_flip"])
    total_count = len(flips)
    if total_count >= 5 and flip_count / total_count > _FLIP_THRESHOLD:
        logger.warning(f"Label-flip anomaly detected from {client_ip}: {flip_count}/{total_count} flips in 1h")
        raise HTTPException(status_code=429, detail="Feedback rejected: anomalous label pattern detected")
    is_flip = _is_label_flip(req.predicted_severity, req.user_label)
    flips.append({"ioc": req.ioc, "predicted": req.predicted_severity, "user_label": req.user_label, "is_flip": is_flip, "ts": now})
    with _feedback_lock:
        records = _load_feedback()
        records.append({
            "ioc": req.ioc, "features": req.features,
            "predicted": req.predicted_severity, "user_label": req.user_label,
            "source": req.source, "timestamp": datetime.now(UTC).isoformat(),
        })
        _save_feedback(records)
    return {"status": "ok", "total_feedback": len(records)}


@router.get("/api/feedback")
def get_feedback():
    records = _load_feedback()
    return {"feedback": records[-200:], "total": len(records)}


@router.post("/api/feedback/retrain")
async def retrain_from_feedback(background_tasks: BackgroundTasks):
    records = _load_feedback()
    if len(records) < 10:
        raise HTTPException(400, f"Need at least 10 feedback records, have {len(records)}")
    background_tasks.add_task(_run_online_learning, records)
    return {"status": "started", "records": len(records)}


@router.get("/api/metrics")
def get_metrics():
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
        type_dist[e.get("ioc_type", "unknown")] += 1

    ml_confidences = [r.get("report", {}).get("ml_confidence", 0) for r in iocs if r.get("report", {}).get("ml_confidence")]
    risk_scores = [r.get("report", {}).get("risk_score", 0) for r in iocs if r.get("report", {}).get("risk_score") is not None]

    from collections import Counter
    day_counts = Counter()
    for e in iocs:
        ts = e.get("timestamp", "")
        day = ts[:10] if ts else ""
        if day:
            day_counts[day] += 1
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
