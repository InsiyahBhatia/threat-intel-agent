"""Webhook management endpoints."""

import hashlib
import logging

from fastapi import APIRouter

from api.dependencies import _get_active_workspace, _save_active_workspace
from api.models import WebhookConfig

logger = logging.getLogger(__name__)
router = APIRouter(tags=["webhooks"])


@router.get("/api/webhooks")
def get_webhooks():
    ws = _get_active_workspace()
    return {"webhooks": ws.get("webhooks", [])}


@router.post("/api/webhooks")
def add_webhook(req: WebhookConfig):
    ws = _get_active_workspace()
    hooks = ws.get("webhooks", [])
    hook_id = hashlib.sha256(req.url.encode()).hexdigest()[:8]
    entry = {"id": hook_id, "url": req.url, "events": req.events, "name": req.name or req.url}
    hooks = [h for h in hooks if h["id"] != hook_id]
    hooks.append(entry)
    ws["webhooks"] = hooks
    _save_active_workspace(ws)
    return {"status": "ok", "webhook": entry}


@router.delete("/api/webhooks/{hook_id}")
def remove_webhook(hook_id: str):
    ws = _get_active_workspace()
    ws["webhooks"] = [h for h in ws.get("webhooks", []) if h["id"] != hook_id]
    _save_active_workspace(ws)
    return {"status": "ok", "deleted": hook_id}
