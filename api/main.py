"""
FastAPI REST API for the Threat Intelligence Agent.
"""

import asyncio
import contextlib
import hmac
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")
sys.path.insert(0, str(ROOT_DIR))


@contextlib.asynccontextmanager
async def lifespan(application: FastAPI):
    if os.getenv("TIA_HOST", "127.0.0.1") not in ("127.0.0.1", "localhost") and not os.getenv("TIA_USE_TLS"):
        logger.warning("SECURITY: Exposing API without TLS. Set TIA_USE_TLS=true or terminate TLS at reverse proxy.")
    logger.info("Pre-loading ML model on startup...")
    try:
        from tools.ml_classifier import _load_model
        _load_model()
        logger.info("ML model loaded successfully on startup")
    except Exception as e:
        logger.warning("Failed to pre-load ML model: %s", e)
    try:
        from api.routes.explain import _get_shap_explainer
        _get_shap_explainer()
    except Exception:
        pass
    yield


app = FastAPI(
    title="Threat Intel Agent API",
    description="Local-model IOC investigation using VirusTotal, Shodan, AbuseIPDB, and MITRE ATT&CK",
    version="1.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:8000").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth ──────────────────────────────────────────────────────────────────
TIA_API_KEY = os.getenv("TIA_API_KEY", "")
_DISABLE_AUTH = os.getenv("TIA_DISABLE_AUTH", "").lower() in ("true", "1", "yes") or not TIA_API_KEY

_AUTH_EXEMPT = ("/health", "/", "/docs", "/openapi.json")

if not TIA_API_KEY and not _DISABLE_AUTH:
    logger.warning("No TIA_API_KEY set — auth disabled. Set TIA_API_KEY in .env to enable.")
    _DISABLE_AUTH = True


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if not _DISABLE_AUTH:
        auth = request.headers.get("Authorization", "")
        if request.url.path in _AUTH_EXEMPT:
            return await call_next(request)
        if not auth.startswith("Bearer ") or not hmac.compare_digest(auth[len("Bearer "):], TIA_API_KEY):
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=401, content={"detail": "Missing or invalid API key."},
                                headers={"Access-Control-Allow-Origin": "*"})
    return await call_next(request)


# ── Rate Limiting ─────────────────────────────────────────────────────────
_RATE_LIMIT_CACHE: dict[str, list[float]] = {}
_RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
_RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
_RATE_LIMIT_MAX_ENTRIES = 10000
_RATE_LIMIT_LOCK = asyncio.Lock()

_HEAVY_ENDPOINT_LIMITS: dict[str, int] = {
    "/api/feedback/retrain": 5,
    "/api/bulk-investigate": 3,
    "/api/feeds/poll": 10,
}


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.url.path in ("/health", "/", "/docs", "/openapi.json"):
        return await call_next(request)
    client_ip = _get_client_ip(request)
    limit = _HEAVY_ENDPOINT_LIMITS.get(request.url.path, _RATE_LIMIT_REQUESTS)
    now = asyncio.get_event_loop().time()
    async with _RATE_LIMIT_LOCK:
        timestamps = _RATE_LIMIT_CACHE.setdefault(client_ip, [])
        timestamps[:] = [t for t in timestamps if now - t < _RATE_LIMIT_WINDOW]
        if len(timestamps) >= limit:
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Try again later."},
                                headers={"Access-Control-Allow-Origin": "*"})
        timestamps.append(now)
        if len(_RATE_LIMIT_CACHE) > _RATE_LIMIT_MAX_ENTRIES:
            _RATE_LIMIT_CACHE.clear()
    return await call_next(request)


# ── Route Registration ────────────────────────────────────────────────────
# ruff: noqa: E402 — FastAPI pattern: routers imported after app creation
from api.routes.blocklist import router as blocklist_router
from api.routes.chat import router as chat_router
from api.routes.explain import router as explain_router
from api.routes.exports import router as exports_router
from api.routes.feedback import router as feedback_router
from api.routes.health import router as health_router
from api.routes.investigate import router as investigate_router
from api.routes.system import router as system_router
from api.routes.webhooks import router as webhooks_router
from api.routes.workspaces import router as workspaces_router

app.include_router(health_router)
app.include_router(investigate_router)
app.include_router(chat_router)
app.include_router(blocklist_router)
app.include_router(webhooks_router)
app.include_router(workspaces_router)
app.include_router(explain_router)
app.include_router(feedback_router)
app.include_router(exports_router)
app.include_router(system_router)


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("TIA_HOST", "127.0.0.1")
    port = int(os.getenv("TIA_PORT", "8000"))
    reload_enabled = os.getenv("TIA_RELOAD", "false").lower() == "true"
    uvicorn.run("main:app", host=host, port=port, reload=reload_enabled)
