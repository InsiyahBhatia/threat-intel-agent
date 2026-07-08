"""
Centralised configuration for the Threat Intelligence Agent.

All magic numbers, thresholds, and default values live here
so they can be audited and overridden in one place.
"""

import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data"

# ── IOC Classification ────────────────────────────────────────────────
MAX_IOC_LENGTH = 512
MAX_URL_LENGTH = 2048

# ── Investigation ─────────────────────────────────────────────────────
INVESTIGATION_TIMEOUT = 120  # seconds
MAX_CONCURRENT_ENRICHMENTS = 5
ENRICH_CACHE_TTL = 3600  # seconds

# ── Threat Graph ──────────────────────────────────────────────────────
GRAPH_MAX_DEPTH = 4
GRAPH_MAX_NODES = 50
GRAPH_MAX_EDGES = 200
DEFAULT_HUNT_DEPTH = 3
DEFAULT_HUNT_NODES = 25

# ── ML Classifier ─────────────────────────────────────────────────────
ML_FEATURE_VERSION = 1
ML_CONFIDENCE_THRESHOLD = 0.5
ML_ENABLE_SHAP = True

# ── Risk Model ────────────────────────────────────────────────────────
RISK_WEIGHT_VT_MALICIOUS = 0.30
RISK_WEIGHT_ABUSEIPDB = 0.15
RISK_WEIGHT_SHODAN = 0.10
RISK_WEIGHT_OTX = 0.10
RISK_WEIGHT_ML = 0.20
RISK_WEIGHT_MITRE = 0.15

RISK_LOW_THRESHOLD = 0.30
RISK_MEDIUM_THRESHOLD = 0.50
RISK_HIGH_THRESHOLD = 0.75

CLASSIFIER_MODEL_PATH = DATA_DIR / "severity_classifier.joblib"
LABEL_ENCODER_PATH = DATA_DIR / "label_encoder.joblib"
FEATURE_COLS_PATH = DATA_DIR / "feature_columns.joblib"
RISK_MODEL_PATH = DATA_DIR / "risk_model.json"
TRAINING_REPORT_PATH = DATA_DIR / "training_report.json"

# ── Database ──────────────────────────────────────────────────────────
DATABASE_PATH = DATA_DIR / "tia.db"
POLL_INTERVAL_SECONDS = 300
SEARCH_DEFAULT_LIMIT = 50
ALERT_PAGE_SIZE = 20

# ── API Server ────────────────────────────────────────────────────────
API_HOST = os.getenv("TIA_HOST", "127.0.0.1")
API_PORT = int(os.getenv("TIA_PORT", "8000"))
API_RELOAD = os.getenv("TIA_RELOAD", "false").lower() in ("true", "1", "yes")
API_KEY = os.getenv("TIA_API_KEY", "")
DISABLE_AUTH = os.getenv("TIA_DISABLE_AUTH", "").lower() in ("true", "1", "yes")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:8000").split(",")
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

# ── LLM ───────────────────────────────────────────────────────────────
LLM_MODEL = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.3"))
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "1024"))
LLM_TIMEOUT = 30  # seconds

# ── External API Timeouts (seconds) ───────────────────────────────────
TIMEOUT_VIRUSTOTAL = 30
TIMEOUT_SHODAN = 15
TIMEOUT_ABUSEIPDB = 15
TIMEOUT_OTX = 20
TIMEOUT_GREYNOISE = 15

# ── YARA ──────────────────────────────────────────────────────────────
YARA_DEFAULT_RULE_NAME = "threat_intel_auto"
YARA_DEFAULT_MAX_IOCS = 50
YARA_MAX_RULE_LENGTH = 65536

# ── Blocklist ─────────────────────────────────────────────────────────
BLOCKLIST_AUTO_REMOVE_DAYS = 30
BLOCKLIST_DEFAULT_EXPORT_FORMAT = "plaintext"

# ── Workspace ─────────────────────────────────────────────────────────
WORKSPACE_AUTOSAVE_DELAY = 2.0  # seconds (debounce)
WORKSPACE_MAX_IOCS = 1000
