"""IOC investigation, bulk investigation, and SSE streaming."""

import asyncio
import json
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import StreamingResponse

from api.dependencies import (
    _fire_webhooks,
    _get_active_workspace,
    _get_active_workspace_name,
    _notify_and_log,
    _run_bg,
    _save_active_workspace,
    _send_notification_async,
)
from api.models import BulkInvestigateRequest, BulkInvestigateResponse, InvestigateRequest, InvestigateResponse
from utils.classifier import validate_ioc
from utils.database import save_investigation

logger = logging.getLogger(__name__)
router = APIRouter(tags=["investigate"])


@router.post("/investigate", response_model=InvestigateResponse)
async def investigate_ioc_async(request: InvestigateRequest):
    from agent.orchestrator import investigate

    ioc = request.ioc.strip()
    if not ioc:
        raise HTTPException(status_code=400, detail="IOC cannot be empty.")
    is_valid, msg = validate_ioc(ioc)
    if not is_valid:
        raise HTTPException(status_code=422, detail=msg)
    try:
        result = await investigate(ioc)
        ws = _get_active_workspace()
        entry = {
            "ioc": result["ioc"], "ioc_type": result["ioc_type"],
            "severity": result.get("severity"),
            "report": result.get("report"),
            "timestamp": datetime.now(UTC).isoformat(),
        }
        ws.setdefault("iocs", []).insert(0, entry)
        ws["iocs"] = ws["iocs"][:500]
        _save_active_workspace(ws)

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

        severity = result.get("severity", "UNKNOWN")
        if severity in ("CRITICAL", "HIGH"):
            _run_bg(_fire_webhooks(severity, result["ioc"], result.get("report", {})))
            _run_bg(_send_notification_async(result["ioc"], severity, result.get("report", {})))

        return InvestigateResponse(
            ioc=result["ioc"],
            ioc_type=result["ioc_type"],
            agent_output=result["agent_output"],
            report=result["report"],
        )
    except Exception:
        logger.exception("Investigation failed for %s", ioc)
        raise HTTPException(status_code=500, detail="Agent error: internal investigation failure") from None


@router.post("/api/bulk-investigate", response_model=BulkInvestigateResponse)
async def bulk_investigate(req: BulkInvestigateRequest):
    from agent.orchestrator import investigate

    results = []
    errors = []
    for raw_ioc in req.iocs:
        ioc = raw_ioc.strip()
        if not ioc:
            continue
        is_valid, msg = validate_ioc(ioc)
        if not is_valid:
            errors.append({"ioc": ioc, "error": msg})
            continue
        try:
            result = await investigate(ioc)
            results.append(result)
        except Exception:
            logger.exception("Bulk investigate failed for %s", ioc)
            errors.append({"ioc": ioc, "error": "Internal investigation error"})
    return BulkInvestigateResponse(
        total=len(req.iocs),
        succeeded=len(results),
        failed=len(errors),
        results=results,
        errors=errors,
    )


@router.get("/api/investigate/stream/{ioc:path}")
async def stream_investigation(ioc: str, background_tasks: BackgroundTasks):
    from agent.orchestrator import investigate

    async def event_stream():
        try:
            yield f"data: {json.dumps({'event': 'start', 'ioc': ioc})}\n\n"
            await asyncio.sleep(0.1)

            is_valid, msg = validate_ioc(ioc)
            if not is_valid:
                yield f"data: {json.dumps({'event': 'error', 'detail': msg})}\n\n"
                return

            ioc_type = msg.split(": ")[-1] if ": " in msg else "unknown"
            yield f"data: {json.dumps({'event': 'classified', 'ioc_type': ioc_type})}\n\n"
            await asyncio.sleep(0.05)

            yield f"data: {json.dumps({'event': 'progress', 'message': 'Querying enrichment sources...'})}\n\n"
            result = await asyncio.wait_for(investigate(ioc), timeout=300.0)
            severity = result.get("severity", "UNKNOWN")
            report = result.get("report", {})

            try:
                save_investigation({
                    "ioc": result["ioc"],
                    "ioc_type": result.get("ioc_type", ""),
                    "severity": severity,
                    "summary": report.get("summary", ""),
                    "threat_category": report.get("threat_category", ""),
                    "risk_score": report.get("risk_score", 0),
                    "confidence_score": report.get("confidence_score", 0),
                    "ml_verdict": report.get("ml_verdict"),
                    "ml_confidence": report.get("ml_confidence"),
                    "report": report,
                    "workspace": "default",
                })
            except Exception as save_err:
                logger.error(f"Failed to save investigation for {ioc}: {save_err}")

            if severity in ("CRITICAL", "HIGH"):
                background_tasks.add_task(_notify_and_log, ioc, severity, report)

            ml_features = result.get("ml_features", {})
            yield f"data: {json.dumps({'event': 'result', 'severity': severity, 'ioc_type': result.get('ioc_type'), 'confidence': report.get('confidence_score', 0), 'risk_score': report.get('risk_score', 0), 'ml_verdict': report.get('ml_verdict'), 'ml_confidence': report.get('ml_confidence'), 'summary': report.get('summary', ''), 'threat_category': report.get('threat_category'), 'mitre_techniques': report.get('mitre_techniques', []), 'recommended_actions': report.get('recommended_actions', []), 'ml_features': ml_features})}\n\n"
            yield f"data: {json.dumps({'event': 'complete'})}\n\n"
        except asyncio.TimeoutError:
            logger.warning("Stream investigation timed out for %s", ioc)
            yield f"data: {json.dumps({'event': 'error', 'detail': 'Investigation timed out after 300s'})}\n\n"
        except Exception:
            logger.exception("Stream investigation failed for %s", ioc)
            yield f"data: {json.dumps({'event': 'error', 'detail': 'Internal investigation error'})}\n\n"
        finally:
            logger.debug("Stream investigation finished for %s", ioc)

    return StreamingResponse(event_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "Connection": "keep-alive"})
