"""Shared synthetic data generator for IOC feature distributions.

Single source of truth used by both training and validation scripts to
avoid code duplication and ensure consistent synthetic augmentation.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from utils.ml_features import FEATURE_COLS, _BASE_COLS, _DERIVED_COLS, _NEW_COLS


def _compute_derived(df: pd.DataFrame) -> pd.DataFrame:
    """Compute derived interaction/ratio features from base columns."""
    vt_mr = df["vt_malicious_ratio"].values
    abuse_conf = df["abuse_confidence"].values
    abuse_tor = df["abuse_is_tor"].values
    abuse_reports = df["abuse_total_reports"].values
    abuse_users = df["abuse_distinct_users"].values
    abuse_cats = df["abuse_categories_count"].values
    sh_ports = df["shodan_open_ports_count"].values
    sh_cves = df["shodan_cve_count"].values
    sh_22 = df["shodan_has_port_22"].values
    sh_445 = df["shodan_has_port_445"].values
    sh_3389 = df["shodan_has_port_3389"].values
    has_family = df["has_known_family"].values
    vt_rep = df["vt_reputation"].values
    is_tor = df["is_tor"].values
    otx_pulses = df["otx_pulse_count"].values
    otx_scan = df["otx_has_scan"].values

    def _sigmoid(x):
        return np.where(x >= 0, 1.0 / (1.0 + np.exp(-x)), np.exp(x) / (1.0 + np.exp(x)))

    df["vt_abuse_agreement"] = np.sqrt(np.maximum(vt_mr, 0.0) * np.maximum(abuse_conf / 100.0, 0.0))
    df["threat_signal_sum"] = (
        abuse_tor
        + sh_22
        + sh_445
        + sh_3389
        + has_family
        + otx_scan
        + (vt_mr > 0.4).astype(float)
        + (abuse_conf > 50).astype(float)
    )
    df["port_attack_surface"] = (sh_22 * 1.5 + sh_445 * 2.0 + sh_3389 * 2.5) / 6.0
    df["cve_per_port"] = sh_cves / np.maximum(sh_ports, 1.0)
    raw_rpu = abuse_reports / np.maximum(abuse_users, 1.0)
    df["reports_per_user"] = np.where(
        (abuse_reports > 0) & (abuse_users > 0),
        np.minimum(_sigmoid(raw_rpu / 10.0), 1.0),
        0.0,
    )
    df["malicious_family"] = vt_mr * has_family
    df["tor_reputation_risk"] = is_tor * _sigmoid(-vt_rep / 30.0)
    df["otx_vt_corroboration"] = np.minimum(otx_pulses / 10.0, 1.0) * vt_mr
    df["shodan_exposure_score"] = (
        _sigmoid(sh_ports / 5.0) * 0.4
        + _sigmoid(sh_cves / 3.0) * 0.3
        + df["port_attack_surface"] * 0.3
    )

    for col in _DERIVED_COLS:
        df[col] = df[col].round(6)

    # ── New indicator / harmless features ─────────────────────────────────────
    df["has_vt_data"] = 1.0
    df["has_abuse_data"] = df["is_ip"]
    df["has_shodan_data"] = df["is_ip"]
    df["vt_harmless_ratio"] = np.clip(0.88 - df["vt_malicious_ratio"].values + np.random.default_rng(42).normal(0, 0.06, len(df)), 0.0, 1.0)

    for col in _NEW_COLS:
        df[col] = df[col].round(6)

    return df


def assign_features_realistic(label: str, n: int, rng: np.random.Generator | None = None) -> pd.DataFrame:
    """Generate synthetic base features for a given severity label.

    Returns a DataFrame with ALL columns in FEATURE_COLS (base + derived).
    IOC type is sampled across all types for each severity to prevent
    the model from learning a spurious ioc_type→severity mapping.
    """
    rng = rng or np.random.default_rng(42)

    def gauss(mean, std, low=0.0, high=1.0, size=None):
        return np.clip(rng.normal(mean, std, size or n), low, high)

    def gauss_int(mean, std, low=0, high=10000):
        return np.clip(rng.normal(mean, std, n).astype(int), low, high)

    def choice_float(vals, probs, size=None):
        return rng.choice(vals, size or n, p=probs).astype(float)

    base = {c: np.zeros(n) for c in _BASE_COLS}

    if label == "CRITICAL":
        half = n // 2
        known = {
            "vt_malicious_ratio": gauss(0.82, 0.12, 0, 1, half),
            "vt_suspicious_count": gauss_int(8, 4, 0, 30)[:half],
            "vt_reputation": gauss(-40, 20, -100, 0, half),
            "abuse_confidence": gauss(88, 12, 0, 100, half),
            "abuse_total_reports": gauss_int(1200, 800, 0, 5000)[:half],
            "abuse_distinct_users": gauss_int(80, 40, 0, 400)[:half],
            "abuse_is_tor": choice_float([0,1], [0.35, 0.65], half),
            "abuse_categories_count": gauss_int(3, 1.5, 0, 8)[:half],
            "shodan_open_ports_count": gauss_int(4, 2, 0, 10)[:half],
            "shodan_cve_count": gauss_int(2, 1.5, 0, 6)[:half],
            "shodan_has_port_22": choice_float([0,1], [0.3, 0.7], half),
            "shodan_has_port_445": choice_float([0,1], [0.5, 0.5], half),
            "shodan_has_port_3389": choice_float([0,1], [0.6, 0.4], half),
            "tag_count": gauss_int(5, 2, 0, 15)[:half],
            "has_known_family": choice_float([0,1], [0.1, 0.9], half),
            "is_ip": choice_float([0,1], [0.4, 0.6], half),
            "is_domain": choice_float([0,1], [0.3, 0.7], half),
            "is_hash": choice_float([0,1], [0.3, 0.7], half),
            "is_tor": choice_float([0,1], [0.3, 0.7], half),
            "otx_pulse_count": gauss_int(8, 4, 0, 25)[:half],
            "otx_avg_confidence": gauss(0.75, 0.12, 0, 1, half),
            "otx_has_scan": choice_float([0,1], [0.2, 0.8], half),
        }
        new_c2 = {
            "vt_malicious_ratio": gauss(0.09, 0.06, 0, 0.35, n-half),
            "vt_suspicious_count": gauss_int(2, 2, 0, 10)[:(n-half)],
            "vt_reputation": gauss(-10, 10, -50, 0, n-half),
            "abuse_confidence": gauss(93, 6, 60, 100, n-half),
            "abuse_total_reports": gauss_int(2200, 900, 300, 6000)[:(n-half)],
            "abuse_distinct_users": gauss_int(150, 60, 20, 500)[:(n-half)],
            "abuse_is_tor": choice_float([0,1], [0.15, 0.85], n-half),
            "abuse_categories_count": gauss_int(2, 1, 0, 5)[:(n-half)],
            "shodan_open_ports_count": gauss_int(2, 1.5, 0, 6)[:(n-half)],
            "shodan_cve_count": gauss_int(1, 1, 0, 4)[:(n-half)],
            "shodan_has_port_22": choice_float([0,1], [0.5, 0.5], n-half),
            "shodan_has_port_445": choice_float([0,1], [0.4, 0.6], n-half),
            "shodan_has_port_3389": choice_float([0,1], [0.7, 0.3], n-half),
            "tag_count": gauss_int(3, 2, 0, 8)[:(n-half)],
            "has_known_family": np.zeros(n-half),
            "is_ip": choice_float([0,1], [0.5, 0.5], n-half),
            "is_domain": choice_float([0,1], [0.3, 0.7], n-half),
            "is_hash": choice_float([0,1], [0.2, 0.8], n-half),
            "is_tor": choice_float([0,1], [0.1, 0.9], n-half),
            "otx_pulse_count": gauss_int(5, 3, 0, 15)[:(n-half)],
            "otx_avg_confidence": gauss(0.65, 0.15, 0, 1, n-half),
            "otx_has_scan": choice_float([0,1], [0.3, 0.7], n-half),
        }
        for k, v in known.items():
            base[k] = v
        df1 = pd.DataFrame({k: base[k] for k in _BASE_COLS})
        for k, v in new_c2.items():
            base[k] = v
        df2 = pd.DataFrame({k: base[k] for k in _BASE_COLS})
        df = pd.concat([df1, df2], ignore_index=True)
    else:
        params = {
            "HIGH": {
                "vt_malicious_ratio": gauss(0.02, 0.02, 0, 0.1),
                "vt_suspicious_count": gauss_int(0.5, 1, 0, 3),
                "vt_reputation": gauss(0, 10, -20, 20),
                "abuse_confidence": gauss(35, 10, 0, 100),
                "abuse_total_reports": gauss_int(15, 10, 0, 50),
                "abuse_distinct_users": gauss_int(5, 4, 0, 20),
                "abuse_is_tor": choice_float([0,1], [0.8, 0.2]),
                "abuse_categories_count": gauss_int(1, 1, 0, 3),
                "shodan_open_ports_count": gauss_int(3, 2, 0, 8),
                "shodan_cve_count": gauss_int(1, 1, 0, 3),
                "shodan_has_port_22": choice_float([0,1], [0.4, 0.6]),
                "shodan_has_port_445": choice_float([0,1], [0.5, 0.5]),
                "shodan_has_port_3389": choice_float([0,1], [0.6, 0.4]),
                "tag_count": gauss_int(1, 1, 0, 4),
                "has_known_family": choice_float([0,1], [0.8, 0.2]),
                "is_ip": choice_float([0,1], [0.05, 0.95]),
                "is_domain": choice_float([0,1], [0.95, 0.05]),
                "is_hash": choice_float([0,1], [0.98, 0.02]),
                "is_tor": choice_float([0,1], [0.8, 0.2]),
                "otx_pulse_count": gauss_int(2, 2, 0, 8),
                "otx_avg_confidence": gauss(0.3, 0.15, 0, 1),
                "otx_has_scan": choice_float([0,1], [0.5, 0.5]),
            },

            "LOW": {
                "vt_malicious_ratio": gauss(0.00, 0.01, 0, 0.05),
                "vt_suspicious_count": gauss_int(0.1, 0.3, 0, 1),
                "vt_reputation": gauss(10, 8, 0, 40),
                "abuse_confidence": gauss(36, 10, 0, 80),
                "abuse_total_reports": gauss_int(9000, 2000, 500, 20000),
                "abuse_distinct_users": gauss_int(1, 1.5, 0, 8),
                "abuse_is_tor": np.zeros(n),
                "abuse_categories_count": gauss_int(0.3, 0.5, 0, 2),
                "shodan_open_ports_count": gauss_int(1, 1, 0, 4),
                "shodan_cve_count": np.zeros(n),
                "shodan_has_port_22": choice_float([0,1], [0.8, 0.2]),
                "shodan_has_port_445": choice_float([0,1], [0.9, 0.1]),
                "shodan_has_port_3389": choice_float([0,1], [0.95, 0.05]),
                "tag_count": gauss_int(0.1, 0.3, 0, 1),
                "has_known_family": np.zeros(n),
                "is_ip": np.ones(n),
                "is_domain": np.zeros(n),
                "is_hash": np.zeros(n),
                "is_tor": np.zeros(n),
                "otx_pulse_count": gauss_int(0.5, 0.8, 0, 3),
                "otx_avg_confidence": gauss(0.1, 0.1, 0, 0.3),
                "otx_has_scan": np.zeros(n),
            },
            "CLEAN": {
                "vt_malicious_ratio": gauss(0.003, 0.005, 0, 0.05),
                "vt_suspicious_count": gauss_int(0.1, 0.3, 0, 2),
                "vt_reputation": gauss(30, 15, 0, 60),
                "abuse_confidence": gauss(2, 3, 0, 15),
                "abuse_total_reports": gauss_int(0.8, 1.5, 0, 10),
                "abuse_distinct_users": gauss_int(0.3, 0.6, 0, 3),
                "abuse_is_tor": np.zeros(n),
                "abuse_categories_count": np.zeros(n),
                "shodan_open_ports_count": gauss_int(1, 1, 0, 3),
                "shodan_cve_count": np.zeros(n),
                "shodan_has_port_22": choice_float([0,1], [0.9, 0.1]),
                "shodan_has_port_445": choice_float([0,1], [0.95, 0.05]),
                "shodan_has_port_3389": choice_float([0,1], [0.98, 0.02]),
                "tag_count": np.zeros(n),
                "has_known_family": np.zeros(n),
                "is_ip": choice_float([0,1], [0.5, 0.5]),
                "is_domain": choice_float([0,1], [0.4, 0.6]),
                "is_hash": choice_float([0,1], [0.1, 0.9]),
                "is_tor": np.zeros(n),
                "otx_pulse_count": np.zeros(n),
                "otx_avg_confidence": np.zeros(n),
                "otx_has_scan": np.zeros(n),
            },
        }
        p = params[label]
        for k in _BASE_COLS:
            base[k] = p.get(k, np.zeros(n))
        df = pd.DataFrame(base)

    # Ensure one-hot constraint: is_ip + is_domain + is_hash <= 1
    ioc_type_sum = df["is_ip"] + df["is_domain"] + df["is_hash"]
    no_type = ioc_type_sum == 0
    if no_type.any():
        choices = rng.choice(["is_ip", "is_domain", "is_hash"], size=no_type.sum())
        for i, (idx, _) in enumerate(df[no_type].iterrows()):
            df.loc[idx, choices[i]] = 1.0

    df = _compute_derived(df)
    return df[FEATURE_COLS]


def generate_dataset(n_per_class: int = 1500, seed: int = 42) -> tuple[pd.DataFrame, np.ndarray]:
    """Generate a balanced synthetic dataset with n_per_class per severity level."""
    rng = np.random.default_rng(seed)
    dfs = []
    labels = []
    for label in ["CLEAN", "LOW", "HIGH", "CRITICAL"]:
        df = assign_features_realistic(label, n_per_class, rng)
        dfs.append(df)
        labels.extend([label] * n_per_class)
    X = pd.concat(dfs, ignore_index=True)
    return X, np.array(labels)


def generate_imbalanced_dataset(total: int = 5000, seed: int = 42) -> tuple[pd.DataFrame, np.ndarray]:
    """Generate a realistic imbalanced dataset matching SOC production ratios."""
    ratios = {"CLEAN": 0.40, "LOW": 0.25, "HIGH": 0.30, "CRITICAL": 0.05}
    rng = np.random.default_rng(seed)
    dfs = []
    labels = []
    for label, ratio in ratios.items():
        n = max(1, int(total * ratio))
        df = assign_features_realistic(label, n, rng)
        dfs.append(df)
        labels.extend([label] * n)
    X = pd.concat(dfs, ignore_index=True)
    return X, np.array(labels)
