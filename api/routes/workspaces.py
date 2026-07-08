"""Workspace management and ignore-mark endpoints."""

import logging
import re
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException

from api.dependencies import (
    WORKSPACE_DIR,
    _get_active_workspace,
    _load_workspace,
    _load_workspace_index,
    _save_active_workspace,
    _save_workspace,
    _save_workspace_index,
)
from api.models import IgnoreMarkRequest, WorkspaceCreate, WorkspaceSwitch

logger = logging.getLogger(__name__)
router = APIRouter(tags=["workspaces"])


@router.get("/api/workspaces")
def list_workspaces():
    idx = _load_workspace_index()
    ws_list = []
    for name in idx.get("workspaces", {}):
        ws_list.append({"name": name, **idx["workspaces"][name]})
    if "default" not in idx.get("workspaces", {}):
        ws_list.insert(0, {"name": "default", "created": "first run"})
    return {"workspaces": ws_list, "active": idx.get("active", "default")}


@router.post("/api/workspaces")
def create_workspace(req: WorkspaceCreate):
    idx = _load_workspace_index()
    if req.name in idx.get("workspaces", {}):
        raise HTTPException(409, f"Workspace '{req.name}' already exists")
    ws = _load_workspace(req.name)
    _save_workspace(req.name, ws)
    if "workspaces" not in idx:
        idx["workspaces"] = {}
    idx["workspaces"][req.name] = {"created": ws["created"]}
    _save_workspace_index(idx)
    return {"status": "ok", "workspace": req.name}


@router.post("/api/workspaces/switch")
def switch_workspace(req: WorkspaceSwitch):
    idx = _load_workspace_index()
    if req.name not in idx.get("workspaces", {}) and req.name != "default":
        raise HTTPException(404, f"Workspace '{req.name}' not found")
    idx["active"] = req.name
    _save_workspace_index(idx)
    return {"status": "ok", "active": req.name}


@router.delete("/api/workspaces/{name}")
def delete_workspace(name: str):
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        raise HTTPException(400, "Invalid workspace name")
    idx = _load_workspace_index()
    if name not in idx.get("workspaces", {}):
        raise HTTPException(404, f"Workspace '{name}' not found")
    if name == idx.get("active"):
        raise HTTPException(400, "Cannot delete active workspace")
    path = WORKSPACE_DIR / f"{name}.json"
    if path.exists():
        resolved = path.resolve()
        if WORKSPACE_DIR not in resolved.parents:
            raise HTTPException(400, "Invalid workspace path")
        path.unlink()
    del idx["workspaces"][name]
    _save_workspace_index(idx)
    return {"status": "ok", "deleted": name}


@router.post("/api/ignore-mark")
def mark_ignored(req: IgnoreMarkRequest):
    ws = _get_active_workspace()
    existing = [x for x in ws.get("ignored_iocs", []) if x["ioc"] != req.ioc]
    existing.append({"ioc": req.ioc, "note": req.note or "",
                     "timestamp": datetime.now(UTC).isoformat()})
    ws["ignored_iocs"] = existing
    _save_active_workspace(ws)
    return {"status": "ok", "ioc": req.ioc}


@router.delete("/api/ignore-mark")
def unmark_ignored(req: IgnoreMarkRequest):
    ws = _get_active_workspace()
    ws["ignored_iocs"] = [x for x in ws.get("ignored_iocs", []) if x["ioc"] != req.ioc]
    _save_active_workspace(ws)
    return {"status": "ok", "ioc": req.ioc}


@router.get("/api/ignore-mark")
def get_ignored():
    ws = _get_active_workspace()
    return {"ignored": ws.get("ignored_iocs", [])}
