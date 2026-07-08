"""Blocklist management endpoints."""

import logging

from fastapi import APIRouter

from api.dependencies import ROOT_DIR, _load_managed_blocklist, _save_managed_blocklist
from api.models import BlocklistRequest
from utils.classifier import validate_ioc

logger = logging.getLogger(__name__)
router = APIRouter(tags=["blocklist"])


@router.get("/api/blocklist")
def get_blocklist():
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

    managed = _load_managed_blocklist()
    all_iocs = list(set(ioc_list + managed))
    return {"blocklist": all_iocs, "dataset_count": len(set(ioc_list)), "managed_count": len(managed)}


@router.post("/api/blocklist")
def add_blocklist(req: BlocklistRequest):
    current = _load_managed_blocklist()
    added = []
    for raw_ioc in req.iocs:
        ioc = raw_ioc.strip()[:256]
        if not ioc:
            continue
        is_valid, _ = validate_ioc(ioc)
        if not is_valid:
            continue
        if ioc not in current:
            current.append(ioc)
            added.append(ioc)
    _save_managed_blocklist(current)
    return {"status": "ok", "added": added, "total": len(current)}


@router.delete("/api/blocklist")
def remove_blocklist(req: BlocklistRequest):
    current = _load_managed_blocklist()
    removed = []
    for raw_ioc in req.iocs:
        ioc = raw_ioc.strip()[:256]
        if ioc in current:
            current.remove(ioc)
            removed.append(ioc)
    _save_managed_blocklist(current)
    return {"status": "ok", "removed": removed, "total": len(current)}
