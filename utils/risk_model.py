"""
Local trainable IOC risk model.

The model is intentionally dependency-free so the project can train and run in
fresh environments without scikit-learn. It learns a small logistic scorer over
features extracted from tool output, then maps the probability to analyst-facing
severity levels.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "risk_model.json"

FEATURES = [
    "vt_malicious_ratio",
    "vt_suspicious_ratio",
    "abuse_confidence",
    "abuse_reports",
    "cve_count",
    "tor_signal",
    "proxy_signal",
    "bruteforce_signal",
    "phishing_signal",
    "malware_signal",
    "c2_signal",
    "clean_signal",
    "api_error_ratio",
]

DEFAULT_MODEL = {
    "version": 2,
    "features": FEATURES,
    "bias": -2.25,
    "weights": {
        "vt_malicious_ratio": 4.6,
        "vt_suspicious_ratio": 1.5,
        "abuse_confidence": 3.0,
        "abuse_reports": 1.1,
        "cve_count": 0.9,
        "tor_signal": 0.75,
        "proxy_signal": 0.65,
        "bruteforce_signal": 0.8,
        "phishing_signal": 1.0,
        "malware_signal": 1.2,
        "c2_signal": 1.4,
        "clean_signal": -1.6,
        "api_error_ratio": -0.25,
    },
    "thresholds": {
        "CRITICAL": 0.86,
        "HIGH": 0.66,
        "LOW": 0.18,
    },
}


@dataclass
class RiskPrediction:
    severity: str
    confidence_score: int
    risk_score: float
    features: dict[str, float]
    model_version: int


def _bounded(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _first_ratio(pattern: str, text: str) -> float:
    match = re.search(pattern, text, flags=re.IGNORECASE)
    if not match:
        return 0.0
    numerator = float(match.group(1))
    denominator = max(float(match.group(2)), 1.0)
    return _bounded(numerator / denominator)


def _keyword(text: str, *words: str) -> float:
    text = text.lower()
    return 1.0 if any(word in text for word in words) else 0.0


def extract_features(text: str, ml_features: dict | None = None) -> dict[str, float]:
    """Convert tool and agent output into normalized model features.

    When ml_features (from extract_ml_features()) is provided, maps the
    structured feature dict directly to the risk model's feature space
    instead of regex-parsing raw text. This avoids contradictory dual-model
    feature extraction.
    """
    text = text or ""

    if ml_features is not None:
        tags = ml_features.get("tags", [])
        shodan_tags = ml_features.get("shodan_tags", [])
        all_tags = [t.lower() for t in (list(tags) + list(shodan_tags))]
        has_phishing_tag = 1.0 if "phishing" in str(all_tags) else 0.0
        has_vt = ml_features.get("has_vt_data", 0)
        has_abuse = ml_features.get("has_abuse_data", 0)
        return {
            "vt_malicious_ratio": min(ml_features.get("vt_malicious_ratio", 0.0), 1.0),
            "vt_suspicious_ratio": min(ml_features.get("vt_suspicious_count", 0) / 100.0, 1.0),
            "abuse_confidence": min(ml_features.get("abuse_confidence", 0.0) / 100.0, 1.0),
            "abuse_reports": min(math.log1p(ml_features.get("abuse_total_reports", 0)) / math.log1p(1000), 1.0),
            "cve_count": min(ml_features.get("shodan_cve_count", 0) / 10.0, 1.0),
            "tor_signal": ml_features.get("abuse_is_tor", 0.0) or ml_features.get("is_tor", 0.0),
            "proxy_signal": 1.0 if any(w in all_tags for w in ["proxy", "vpn", "tor"]) else 0.0,
            "bruteforce_signal": 1.0 if any(w in all_tags for w in ["brute", "ssh"]) or ml_features.get("abuse_confidence", 0) > 50 else 0.0,
            "phishing_signal": has_phishing_tag,
            "malware_signal": 1.0 if ml_features.get("vt_malicious_ratio", 0) > 0.3 or any(w in all_tags for w in ["malware", "trojan", "ransomware", "dropper", "infostealer"]) else 0.0,
            "c2_signal": 1.0 if any(w in all_tags for w in ["c2", "c&c", "command and control", "botnet"]) else 0.0,
            "clean_signal": 1.0 if (has_vt or has_abuse) and ml_features.get("vt_malicious_ratio", 0) < 0.01 and ml_features.get("abuse_confidence", 0) < 5 else 0.0,
            "api_error_ratio": 0.0,
        }

    abuse_match = re.search(r"abuse confidence score:\s*(\d+(?:\.\d+)?)\s*/\s*100", text, re.I)
    report_match = re.search(r"total abuse reports.*?:\s*(\d+)", text, re.I)
    cves = set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I))
    errors = len(re.findall(r"\b(ERROR|Request failed|not set|Skipped)\b", text, re.I))
    sections = max(len(re.findall(r"^\[[^\]]+\]", text, re.M)), 1)

    features = {
        "vt_malicious_ratio": _first_ratio(r"detection ratio:\s*(\d+)\s*/\s*(\d+)", text),
        "vt_suspicious_ratio": _first_ratio(r"suspicious votes:\s*(\d+)\D+(\d+)", text),
        "abuse_confidence": float(abuse_match.group(1)) / 100 if abuse_match else 0.0,
        "abuse_reports": _bounded(math.log1p(float(report_match.group(1))) / math.log1p(1000)) if report_match else 0.0,
        "cve_count": _bounded(len(cves) / 10),
        "tor_signal": _keyword(text, "tor exit", " tor ", "multi-hop proxy"),
        "proxy_signal": _keyword(text, "open proxy", "proxy"),
        "bruteforce_signal": _keyword(text, "brute force", "brute-force", "ssh"),
        "phishing_signal": _keyword(text, "phishing", "credential harvesting"),
        "malware_signal": _keyword(text, "malware", "trojan", "ransomware", "dropper", "infostealer"),
        "c2_signal": _keyword(text, "c2", "c&c", "command and control", "botnet"),
        "clean_signal": _keyword(text, "clean", "no malicious", "low risk", "few or no abuse"),
        "api_error_ratio": _bounded(errors / sections),
    }
    return {name: round(features.get(name, 0.0), 4) for name in FEATURES}


def load_model(path: Path = MODEL_PATH) -> dict:
    if path.exists():
        with path.open("r", encoding="utf-8") as f:
            model = json.load(f)
        if model.get("features") == FEATURES:
            return model
    return DEFAULT_MODEL


def save_model(model: dict, path: Path = MODEL_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(model, f, indent=2, sort_keys=True)
        f.write("\n")


def train_model(records: list[dict], epochs: int = 700, learning_rate: float = 0.18) -> dict:
    """Train logistic weights from [{"text": "...", "label": 0|1}, ...]."""
    weights = {name: 0.0 for name in FEATURES}
    bias = 0.0

    for _ in range(epochs):
        for record in records:
            features = extract_features(record["text"])
            label = float(record["label"])
            z = bias + sum(weights[name] * features[name] for name in FEATURES)
            pred = 1 / (1 + math.exp(-z))
            error = pred - label
            bias -= learning_rate * error
            for name in FEATURES:
                weights[name] -= learning_rate * error * features[name]

    return {
        **DEFAULT_MODEL,
        "bias": round(bias, 6),
        "weights": {name: round(weights[name], 6) for name in FEATURES},
    }


def predict_risk(text: str, model: dict | None = None, ml_features: dict | None = None) -> RiskPrediction:
    model = model or load_model()
    features = extract_features(text, ml_features)
    z = model["bias"] + sum(model["weights"].get(name, 0.0) * features[name] for name in FEATURES)
    risk_score = 1 / (1 + math.exp(-z))

    thresholds = model.get("thresholds", DEFAULT_MODEL["thresholds"])
    if features["clean_signal"] and risk_score < thresholds["LOW"]:
        severity = "CLEAN"
    elif risk_score >= thresholds["CRITICAL"]:
        severity = "CRITICAL"
    elif risk_score >= thresholds["HIGH"]:
        severity = "HIGH"
    elif risk_score >= thresholds["LOW"]:
        severity = "LOW"
    else:
        severity = "CLEAN"

    confidence = _compute_confidence(risk_score, ml_features)
    return RiskPrediction(
        severity=severity,
        confidence_score=int(_bounded(confidence, 0, 100)),
        risk_score=round(risk_score, 4),
        features=features,
        model_version=int(model.get("version", 1)),
    )


def _compute_confidence(risk_score: float, ml_features: dict | None = None) -> int:
    base = round(55 + abs(risk_score - 0.5) * 90)
    if ml_features is None:
        return base
    data_coverage = sum([
        bool(ml_features.get("has_vt_data", 0)),
        bool(ml_features.get("has_abuse_data", 0)),
        bool(ml_features.get("has_shodan_data", 0)),
    ]) / 3.0
    coverage_factor = 0.60 + 0.40 * data_coverage
    return max(10, int(base * coverage_factor))
