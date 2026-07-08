"""ML explainability endpoint with SHAP feature contributions."""

import logging
import threading
from pathlib import Path

from fastapi import APIRouter, HTTPException

from api.models import ExplainRequest
from utils.classifier import validate_ioc

logger = logging.getLogger(__name__)
router = APIRouter(tags=["explain"])

ROOT_DIR = Path(__file__).resolve().parents[2]

_SHAP_EXPLAINER = None
_SHAP_FEATURE_COLS = None
_SHAP_LOCK = threading.Lock()

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


def _get_shap_explainer():
    global _SHAP_EXPLAINER, _SHAP_FEATURE_COLS  # noqa: PLW0603
    if _SHAP_EXPLAINER is None:
        with _SHAP_LOCK:
            if _SHAP_EXPLAINER is not None:
                return _SHAP_EXPLAINER, _SHAP_FEATURE_COLS
        try:
            import joblib
            import shap
            artifact = joblib.load(ROOT_DIR / "models" / "severity_classifier.joblib")
            _SHAP_FEATURE_COLS = joblib.load(ROOT_DIR / "models" / "feature_cols.joblib")
            _SHAP_EXPLAINER = shap.TreeExplainer(artifact["xgb"])
            logger.info("SHAP TreeExplainer initialized for XGBoost model")
        except Exception as e:
            logger.warning(f"Failed to load SHAP explainer, falling back to raw features: {e}")
            _SHAP_EXPLAINER = False
    return _SHAP_EXPLAINER, _SHAP_FEATURE_COLS


def _get_xgb_importance():
    try:
        import joblib
        artifact = joblib.load(ROOT_DIR / "models" / "severity_classifier.joblib")
        cols = joblib.load(ROOT_DIR / "models" / "feature_cols.joblib")
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
        x_df = pd.DataFrame([ml_features])[feature_cols]
        shap_values = explainer.shap_values(x_df)
        pred = explainer.model.predict(x_df)
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
            for col, v in zip(feature_cols, class_shap, strict=False) if abs(float(v)) > 0.0001
        ]
    except Exception as e:
        logger.warning(f"SHAP computation failed: {e}")
        return None


def _generate_explanation(report: dict, contributions: list | None, has_data: bool = False) -> str:  # noqa: PLR0912
    sev = report.get("severity", "UNKNOWN")
    ml_sev = report.get("ml_verdict")

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


@router.post("/api/explain")
async def explain_prediction(req: ExplainRequest):
    from agent.orchestrator import investigate

    ioc = req.ioc.strip()
    if not ioc:
        raise HTTPException(400, "IOC cannot be empty")
    is_valid, msg = validate_ioc(ioc)
    if not is_valid:
        raise HTTPException(422, msg)
    try:
        result = await investigate(ioc)
    except Exception:
        logger.exception("Explain prediction failed for %s", ioc)
        raise HTTPException(500, "Investigation failed during explanation") from None

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
                 "value": round(abs(ml_features.get(k, 0)), 4),
                 "direction": "increases" if ml_features.get(k, 0) > 0 else "decreases",
                 "impact": round(v, 6)}
                for k, v in sorted(xgb_imp.items(), key=lambda x: -x[1])[:10]
                if abs(ml_features.get(k, 0)) > 0
            ]
        else:
            contributions = [
                {"feature": k, "name": FEATURE_LABELS.get(k, k.replace("_", " ").title()),
                 "value": round(abs(v), 4),
                 "direction": "increases" if v > 0 else "decreases",
                 "impact": round(abs(v), 4)}
                for k, v in sorted(ml_features.items(), key=lambda x: -abs(x[1]) if isinstance(x[1], int | float) else 0)
                if isinstance(v, int | float) and abs(v) > 0
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
