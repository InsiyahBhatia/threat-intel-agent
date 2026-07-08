"""Health check and root endpoint."""

import logging
import os
import sqlite3
from pathlib import Path

from fastapi import APIRouter

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])

ROOT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT_DIR / "data"
DB_PATH = str(DATA_DIR / "tia.db")


def _check_db() -> dict:
    results = {"reachable": False, "error": None}
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.execute("SELECT 1")
        conn.close()
        results["reachable"] = True
    except sqlite3.OperationalError as e:
        results["error"] = str(e)
    except Exception as e:
        results["error"] = str(e)
    return results


def _check_ml_model() -> dict:
    model_path = ROOT_DIR / "models" / "severity_classifier.joblib"
    exists = model_path.exists()
    return {"loaded": exists, "path": str(model_path) if exists else None}


def _check_api_keys() -> dict:
    required_keys = {
        "virustotal": "VIRUSTOTAL_API_KEY",
        "shodan": "SHODAN_API_KEY",
        "abuseipdb": "ABUSEIPDB_API_KEY",
        "otx": "OTX_API_KEY",
        "groq": "GROQ_API_KEY",
    }
    configured = {}
    for name, env_var in required_keys.items():
        val = os.getenv(env_var, "")
        configured[name] = bool(val) and val != "your_" + env_var.lower().replace("api_key", "api_key_here")
    return {"configured": configured, "any_configured": any(configured.values())}


@router.get("/")
def root():
    return {
        "service": "Threat Intelligence Agent",
        "status": "online",
        "endpoints": {
            "POST /investigate": "Investigate an IOC (IP, domain, or file hash)",
            "POST /api/chat": "Browser extension chat endpoint",
            "GET /health": "Health check",
            "GET /healthz": "Detailed health check (k8s compatible)",
        }
    }


@router.get("/health")
@router.get("/healthz")
def health():
    db_status = _check_db()
    ml_status = _check_ml_model()
    api_keys = _check_api_keys()

    all_ok = db_status["reachable"] and ml_status["loaded"]

    return {
        "status": "healthy" if all_ok else "degraded",
        "version": "1.2.0",
        "checks": {
            "database": db_status,
            "ml_model": ml_status,
            "api_keys": api_keys,
        },
    }
