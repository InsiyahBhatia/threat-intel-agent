"""ML Severity Classifier Tool — wraps trained models (XGBoost/LightGBM ensemble)
as both a LangChain @tool and direct Python callable.

Tier 4 improvements:
- Multi-model ensemble (XGB + LGB soft voting)
- Learned ensemble weights (stored in model artifact, not hardcoded)
- Temperature-scaled confidence calibration (learned on validation set)
- Expanded 30-feature set with interaction/ratio features
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Optional

from langchain_core.tools import tool

ROOT = Path(__file__).resolve().parents[1]
MODELS_DIR = ROOT / "models"

_MODEL = None
_LE = None
_COLS: list[str] | None = None
_LOAD_ERROR: str | None = None
_ENSEMBLE_MODELS: list[tuple[str, object]] = []

LABEL_ORDER = ["CLEAN", "LOW", "HIGH", "CRITICAL"]

_DEFAULT_ENSEMBLE_WEIGHTS = {"xgb": 0.5, "lgb": 0.5}
_DEFAULT_CALIBRATION_TEMP = 1.0

_ENSEMBLE_WEIGHTS: dict[str, float] = dict(_DEFAULT_ENSEMBLE_WEIGHTS)
_CALIBRATION_TEMPERATURE: float = _DEFAULT_CALIBRATION_TEMP


def _load_model() -> bool:
    """Lazy-load model artifacts. Returns True if successful."""
    global _MODEL, _LE, _COLS, _LOAD_ERROR, _ENSEMBLE_MODELS
    global _ENSEMBLE_WEIGHTS, _CALIBRATION_TEMPERATURE

    if _MODEL is not None:
        return True
    if _LOAD_ERROR is not None:
        return False

    model_path = MODELS_DIR / "severity_classifier.joblib"
    le_path = MODELS_DIR / "label_encoder.joblib"
    cols_path = MODELS_DIR / "feature_cols.joblib"

    if not model_path.exists():
        _LOAD_ERROR = (
            "Model not trained yet. Run: python scripts/balance_and_train.py"
        )
        return False

    try:
        import joblib
        import numpy as np

        _LE = joblib.load(le_path)
        _COLS = joblib.load(cols_path)

        raw = joblib.load(model_path)
        if isinstance(raw, dict) and "mode" in raw and raw["mode"] == "ensemble":
            _ENSEMBLE_MODELS = [("xgb", raw["xgb"]), ("lgb", raw["lgb"])]
            _MODEL = raw["xgb"]
            _ENSEMBLE_WEIGHTS = raw.get("ensemble_weights", _DEFAULT_ENSEMBLE_WEIGHTS)
            _CALIBRATION_TEMPERATURE = raw.get("calibration_temp", _DEFAULT_CALIBRATION_TEMP)
        else:
            _MODEL = raw
            _ENSEMBLE_MODELS = [("primary", _MODEL)]
            _ENSEMBLE_WEIGHTS = {"primary": 1.0}
            _CALIBRATION_TEMPERATURE = _DEFAULT_CALIBRATION_TEMP

        return True
    except Exception as exc:
        _LOAD_ERROR = f"Failed to load model: {exc}"
        return False


def _calibrate_confidence(proba: float) -> float:
    """Apply temperature scaling for calibrated confidence."""
    if _CALIBRATION_TEMPERATURE <= 0:
        return proba
    scaled = math.exp(math.log(max(proba, 1e-10)) / _CALIBRATION_TEMPERATURE)
    return min(scaled, 1.0)


def predict_ml_severity(features: dict) -> Optional[dict]:
    """
    Direct Python callable — ensemble prediction with calibration.

    Parameters
    ----------
    features : dict
        Feature dict as returned by utils.ml_features.extract_ml_features().

    Returns
    -------
    dict with keys:
    severity str — CLEAN / LOW / HIGH / CRITICAL
    confidence int — 0–100 (calibrated max probability x 100)
    probabilities dict — {class_name: calibrated_probability, ...}
    model_name str — "Ensemble(XGB+LGB)"
    feature_count int
    ensemble_breakdown list — per-model predictions
    Returns None if the model is unavailable.
    """
    if not _load_model():
        return None

    import numpy as np

    X = np.array([[features.get(c, 0.0) for c in _COLS]])

    if len(_ENSEMBLE_MODELS) > 1:
        n_classes = len(_LE.classes_)
        combined_proba = np.zeros(n_classes)
        model_names = []
        per_model = []

        total_weight = sum(
            _ENSEMBLE_WEIGHTS.get(name, 1.0 / len(_ENSEMBLE_MODELS))
            for name, _ in _ENSEMBLE_MODELS
        )

        for name, model in _ENSEMBLE_MODELS:
            weight = _ENSEMBLE_WEIGHTS.get(name, 1.0 / len(_ENSEMBLE_MODELS))
            if hasattr(model, "predict_proba"):
                proba = model.predict_proba(X)[0]
                if len(proba) < n_classes:
                    proba = np.pad(proba, (0, n_classes - len(proba)), constant_values=0)
                elif len(proba) > n_classes:
                    proba = proba[:n_classes]
                combined_proba += weight * proba
                pred_idx = np.argmax(proba)
                pred_class = _LE.inverse_transform([pred_idx])[0]
                per_model.append({"model": name, "prediction": pred_class, "confidence": int(round(max(proba) * 100))})
                model_names.append(name)

        combined_proba /= total_weight or 1.0
        pred_idx = np.argmax(combined_proba)
        pred_class = _LE.inverse_transform([pred_idx])[0]
        raw_confidence = max(combined_proba)

        model_name = f"Ensemble({'+'.join(model_names)})"
    else:
        proba = _MODEL.predict_proba(X)[0]
        pred_idx = _MODEL.predict(X)[0]
        pred_class = _LE.inverse_transform([pred_idx])[0]
        raw_confidence = max(proba)
        combined_proba = proba
        model_name = type(_MODEL).__name__
        per_model = [{"model": model_name, "prediction": pred_class, "confidence": int(round(raw_confidence * 100))}]

    # CRITICAL confidence floor: downgrade to next-highest if < 75%
    if pred_class == "CRITICAL" and raw_confidence < 0.75:
        critical_idx = np.where(_LE.classes_ == "CRITICAL")[0][0]
        sorted_idx = np.argsort(combined_proba)[::-1]
        for idx in sorted_idx:
            if idx != critical_idx:
                pred_class = _LE.inverse_transform([idx])[0]
                raw_confidence = combined_proba[idx]
                break

    calibrated_confidence = _calibrate_confidence(raw_confidence)
    confidence = int(round(calibrated_confidence * 100))

    probabilities = {
        cls: round(float(combined_proba[i]), 4)
        for i, cls in enumerate(_LE.classes_)
    }

    return {
        "severity": pred_class,
        "confidence": min(confidence, 100),
        "probabilities": probabilities,
        "model_name": model_name,
        "feature_count": len(_COLS),
        "ensemble_breakdown": per_model,
        "calibrated": _CALIBRATION_TEMPERATURE != 1.0,
        "calibration_temp": _CALIBRATION_TEMPERATURE,
    }


@tool
def ml_severity_tool(features_json: str) -> str:
    """
    Run the trained ML severity classifier on extracted IOC features.

    Input: JSON string of feature key-value pairs. Keys must match the
    31 features extracted from VirusTotal, AbuseIPDB, Shodan, and OTX:
    vt_malicious_ratio, vt_suspicious_count, vt_reputation,
    abuse_confidence, abuse_total_reports, abuse_distinct_users,
    abuse_is_tor, abuse_categories_count, shodan_open_ports_count,
    shodan_cve_count, shodan_has_port_22, shodan_has_port_445,
    shodan_has_port_3389, tag_count, has_known_family,
    is_ip, is_domain, is_hash, is_tor, otx_pulse_count,
    otx_avg_confidence, otx_has_scan, vt_abuse_agreement,
    threat_signal_sum, port_attack_surface, cve_per_port,
    reports_per_user, malicious_family, tor_reputation_risk,
    otx_vt_corroboration, shodan_exposure_score

    Returns the predicted severity class, confidence score, and per-class
    probability breakdown. Call this AFTER gathering data from virustotal,
    shodan, abuseipdb, and otx tools.
    """
    if not _load_model():
        return f"[ML Classifier] Unavailable — {_LOAD_ERROR}"

    try:
        features = json.loads(features_json)
    except json.JSONDecodeError as exc:
        return f"[ML Classifier] Invalid JSON input: {exc}"

    result = predict_ml_severity(features)
    if result is None:
        return "[ML Classifier] Prediction failed — model unavailable."

    proba_str = " " + "\n ".join(
        f"{cls:<10} {int(p * 100):>3}% {'█' * int(p * 30)}"
        for cls, p in sorted(
            result["probabilities"].items(),
            key=lambda x: -x[1],
        )
    )

    return (
        f"[ML Classifier] Severity: {result['severity']} | "
        f"Confidence: {result['confidence']}%\n"
        f" Model: {result['model_name']} ({result['feature_count']} features)\n"
        f" Class probabilities:\n{proba_str}\n"
        f" Note: Data-driven verdict, independent of LLM reasoning."
    )
