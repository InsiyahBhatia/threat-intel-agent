"""
ML Feature Extractor — converts raw API dicts into the numeric feature vector
used by the ensemble severity classifier.

Features (Tier 4 — extended with interaction/ratio features):
Base (21): vt_malicious_ratio, vt_suspicious_count, vt_reputation,
  abuse_confidence, abuse_total_reports, abuse_distinct_users, abuse_is_tor,
  abuse_categories_count, shodan_open_ports_count, shodan_cve_count,
  shodan_has_port_22, shodan_has_port_445, shodan_has_port_3389,
  tag_count, has_known_family, is_ip, is_domain, is_hash, is_tor,
  otx_pulse_count, otx_avg_confidence, otx_has_scan
Derived (9): vt_abuse_agreement, threat_signal_sum, port_attack_surface,
  cve_per_port, reports_per_user, malicious_family, tor_reputation_risk,
  otx_vt_corroboration, shodan_exposure_score
"""

from __future__ import annotations

import math

_BASE_COLS: list[str] = [
    "vt_malicious_ratio",
    "vt_suspicious_count",
    "vt_reputation",
    "abuse_confidence",
    "abuse_total_reports",
    "abuse_distinct_users",
    "abuse_is_tor",
    "abuse_categories_count",
    "shodan_open_ports_count",
    "shodan_cve_count",
    "shodan_has_port_22",
    "shodan_has_port_445",
    "shodan_has_port_3389",
    "tag_count",
    "has_known_family",
    "is_ip",
    "is_domain",
    "is_hash",
    "is_tor",
    "otx_pulse_count",
    "otx_avg_confidence",
    "otx_has_scan",
]

_DERIVED_COLS: list[str] = [
    "vt_abuse_agreement",
    "threat_signal_sum",
    "port_attack_surface",
    "cve_per_port",
    "reports_per_user",
    "tor_reputation_risk",
    "otx_vt_corroboration",
    "shodan_exposure_score",
]

_NEW_COLS: list[str] = [
    "has_vt_data",
    "has_abuse_data",
    "has_shodan_data",
    "vt_harmless_ratio",
    "has_malicious_vt_tags",
]

FEATURE_COLS: list[str] = _BASE_COLS + _DERIVED_COLS + _NEW_COLS


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    ey = math.exp(x)
    return ey / (1.0 + ey)


def extract_ml_features(  # noqa: PLR0915
    ioc_type: str,
    vt_raw: dict | None = None,
    abuse_raw: dict | None = None,
    shodan_raw: dict | None = None,
    otx_raw: dict | None = None,
) -> dict[str, float]:
    """Build the extended feature vector from raw API response dicts."""
    vt = vt_raw or {}
    ab = abuse_raw or {}
    sh = shodan_raw or {}
    otx = otx_raw or {}

    total_engines = max(vt.get("total_engines", 0), 1)
    malicious = vt.get("malicious_votes", 0)
    vt_malicious_ratio = float(malicious / total_engines)
    vt_suspicious_count = float(vt.get("suspicious_votes", 0))
    vt_reputation = float(vt.get("reputation", 0))

    abuse_confidence = float(ab.get("confidence", 0))
    abuse_total_reports = float(ab.get("total_reports", 0))
    abuse_distinct_users = float(ab.get("distinct_users", 0))
    abuse_is_tor = float(bool(ab.get("is_tor", False)))
    abuse_categories_count = float(ab.get("categories_count", 0))

    shodan_open_ports = sh.get("open_ports", [])
    shodan_open_ports_count = float(len(shodan_open_ports))
    shodan_cves = sh.get("cves", [])
    shodan_cve_count = float(len(shodan_cves))
    shodan_has_port_22 = 1.0 if 22 in shodan_open_ports else 0.0
    shodan_has_port_445 = 1.0 if 445 in shodan_open_ports else 0.0
    shodan_has_port_3389 = 1.0 if 3389 in shodan_open_ports else 0.0

    tags = vt.get("tags", [])
    tag_count = float(len(tags))

    meaningful_name = vt.get("meaningful_name", "Unknown")
    has_known_family = 1.0 if meaningful_name != "Unknown" else 0.0

    is_ip = 1.0 if ioc_type == "ip" else 0.0
    is_domain = 1.0 if ioc_type == "domain" else 0.0
    is_hash = 1.0 if ioc_type == "hash" else 0.0

    is_tor = float(bool(ab.get("is_tor", False)) or "tor" in [t.lower() for t in tags])

    otx_pulse_count = float(len(otx.get("pulses", [])))
    otx_avg_confidence = float(otx.get("avg_confidence", 0))
    otx_has_scan = float(bool(otx.get("has_scan", False)))

    # ── New indicator / harmless features ─────────────────────────────────────
    total_engines_raw = vt.get("total_engines", 0)
    has_vt_data = 1.0 if total_engines_raw > 1 else 0.0
    has_abuse_data = 1.0 if ioc_type == "ip" and bool(ab) else 0.0
    has_shodan_data = 1.0 if ioc_type == "ip" and bool(sh) else 0.0

    harmless = vt.get("harmless_votes", 0)
    vt_harmless_ratio = float(harmless / total_engines) if total_engines > 1 else 0.0

    # Check VT + Shodan tags for malicious keywords (works for all IOC types)
    _malicious_tag_keywords = {"malware", "c2", "c&c", "command and control", "trojan", "ransomware", "botnet", "phishing", "malicious", "dropper", "loader", "backdoor", "spyware", "worm", "exploit", "rat", "infostealer"}
    all_tags = [t.lower() for t in tags] + [t.lower() for t in sh.get("tags", [])]
    has_malicious_vt_tags = 1.0 if any(kw in t for t in all_tags for kw in _malicious_tag_keywords) else 0.0

    # ── Derived interaction/ratio features ──────────────────────────────────

    vt_abuse_agreement = math.sqrt(
        max(vt_malicious_ratio, 0.0) * max(abuse_confidence / 100.0, 0.0)
    )

    threat_signal_sum = (
        abuse_is_tor
        + shodan_has_port_22
        + shodan_has_port_445
        + shodan_has_port_3389
        + has_known_family
        + otx_has_scan
        + (1.0 if vt_malicious_ratio > 0.4 else 0.0)
        + (1.0 if abuse_confidence > 50 else 0.0)
    )

    port_attack_surface = (
        shodan_has_port_22 * 1.5
        + shodan_has_port_445 * 2.0
        + shodan_has_port_3389 * 2.5
    ) / 6.0

    cve_per_port = shodan_cve_count / max(shodan_open_ports_count, 1.0)

    if abuse_total_reports > 0 and abuse_distinct_users > 0:
        reports_per_user = min(_sigmoid((abuse_total_reports / abuse_distinct_users) / 10.0), 1.0)
    else:
        reports_per_user = 0.0

    tor_reputation_risk = is_tor * _sigmoid(-vt_reputation / 30.0)

    otx_vt_corroboration = min(otx_pulse_count / 10.0, 1.0) * vt_malicious_ratio

    shodan_exposure_score = (
        _sigmoid(shodan_open_ports_count / 5.0) * 0.4
        + _sigmoid(shodan_cve_count / 3.0) * 0.3
        + port_attack_surface * 0.3
    )

    features = {
        "vt_malicious_ratio": round(vt_malicious_ratio, 6),
        "vt_suspicious_count": vt_suspicious_count,
        "vt_reputation": vt_reputation,
        "abuse_confidence": abuse_confidence,
        "abuse_total_reports": abuse_total_reports,
        "abuse_distinct_users": abuse_distinct_users,
        "abuse_is_tor": abuse_is_tor,
        "abuse_categories_count": abuse_categories_count,
        "shodan_open_ports_count": shodan_open_ports_count,
        "shodan_cve_count": shodan_cve_count,
        "shodan_has_port_22": shodan_has_port_22,
        "shodan_has_port_445": shodan_has_port_445,
        "shodan_has_port_3389": shodan_has_port_3389,
        "tag_count": tag_count,
        "has_known_family": has_known_family,
        "is_ip": is_ip,
        "is_domain": is_domain,
        "is_hash": is_hash,
        "is_tor": is_tor,
        "otx_pulse_count": otx_pulse_count,
        "otx_avg_confidence": otx_avg_confidence,
        "otx_has_scan": otx_has_scan,
        "vt_abuse_agreement": round(vt_abuse_agreement, 6),
        "threat_signal_sum": round(threat_signal_sum, 6),
        "port_attack_surface": round(port_attack_surface, 6),
        "cve_per_port": round(cve_per_port, 6),
        "reports_per_user": round(reports_per_user, 6),
        "tor_reputation_risk": round(tor_reputation_risk, 6),
        "otx_vt_corroboration": round(otx_vt_corroboration, 6),
        "shodan_exposure_score": round(shodan_exposure_score, 6),
        "has_vt_data": has_vt_data,
        "has_abuse_data": has_abuse_data,
        "has_shodan_data": has_shodan_data,
        "vt_harmless_ratio": round(vt_harmless_ratio, 6),
        "has_malicious_vt_tags": has_malicious_vt_tags,
    }

    # Include raw tags list as metadata (not a model feature) for downstream consumers
    features["tags"] = list(tags)
    features["shodan_tags"] = list(sh.get("tags", []))

    for col in FEATURE_COLS:
        features.setdefault(col, 0.0)

    return features
