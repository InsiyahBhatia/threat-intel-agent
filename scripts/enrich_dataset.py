"""
Bulk IOC Enrichment — fills real feature values for rows where features are NaN/zero.

Design principles:
- Checkpoint-based: saves progress every CHECKPOINT_EVERY rows, safe to interrupt/resume
- Rate-limit aware: per-API delays, respects VT free tier (4 req/min)
- Multi-key rotation: discovers ALL API keys in .env (VIRUSTOTAL_API_KEY, VIRUSTOTAL_API_KEY1, ...)
  and round-robins through them to maximize throughput
- IOC-type routing: hashes → VT only, IPs → VT + AbuseIPDB + Shodan, domains → VT only
- Never overwrites first_seen
- Skips rows already enriched (has non-zero vt_malicious_ratio OR abuse_confidence)
- Writes enriched rows back to ioc_dataset.csv in-place

Usage:
    python scripts/enrich_dataset.py                   # enrich all unenriched rows
    python scripts/enrich_dataset.py --label CRITICAL  # enrich specific label only
    python scripts/enrich_dataset.py --limit 200       # cap API calls (budget-safe)
    python scripts/enrich_dataset.py --dry-run         # print what would be enriched
"""

import argparse
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")
load_dotenv(ROOT / ".env", override=True)

from utils.ml_features import FEATURE_COLS, extract_ml_features

DATA_DIR = ROOT / "data"
CKPT_PATH = DATA_DIR / "enrich_checkpoint.csv"

VT_DELAY = 15.5
ABUSE_DELAY = 0.5
SHODAN_DELAY = 1.1
CHECKPOINT_EVERY = 25
NOW_UTC = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def discover_keys(prefix: str) -> list[str]:
    """Discover all env keys matching PREFIX, PREFIX1, PREFIX2, etc.

    Reads directly from .env file to avoid env-var collision (dotenv
    does not load KEY1 if KEY already exists with override=False).
    Returns keys in order: primary, then 1, 2, 3...
    """
    keys = []
    env_path = ROOT / ".env"
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip()
                if k == prefix:
                    keys.insert(0, v)
                elif re.match(rf"^{prefix}\d+$", k):
                    keys.append(v)
    if not keys:
        fallback = os.getenv(prefix, "")
        if fallback:
            keys = [fallback]
    return keys


VT_KEYS = discover_keys("VIRUSTOTAL_API_KEY")
ABUSE_KEYS = discover_keys("ABUSEIPDB_API_KEY")
SHODAN_KEYS = discover_keys("SHODAN_API_KEY")
OTX_KEYS = discover_keys("OTX_API_KEY")


class KeyRotator:
    """Round-robin through a pool of API keys."""

    def __init__(self, keys: list[str], name: str):
        self.keys = keys
        self.name = name
        self._idx = 0
        if not keys:
            print(f"  WARNING: No {name} keys found")

    def get(self) -> str | None:
        if not self.keys:
            return None
        key = self.keys[self._idx % len(self.keys)]
        self._idx += 1
        return key

    @property
    def count(self) -> int:
        return len(self.keys)


vt_rotator = KeyRotator(VT_KEYS, "VirusTotal")
abuse_rotator = KeyRotator(ABUSE_KEYS, "AbuseIPDB")
shodan_rotator = KeyRotator(SHODAN_KEYS, "Shodan")
otx_rotator = KeyRotator(OTX_KEYS, "OTX")


def query_vt(ioc: str, ioc_type: str) -> dict:
    key = vt_rotator.get()
    if not key:
        return {}
    headers = {"x-apikey": key}
    base = "https://www.virustotal.com/api/v3"
    try:
        if ioc_type == "ip":
            url = f"{base}/ip_addresses/{ioc}"
        elif ioc_type == "domain":
            url = f"{base}/domains/{ioc}"
        elif ioc_type == "hash":
            url = f"{base}/files/{ioc}"
        else:
            return {}

        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 404:
            return {
                "malicious_votes": 0, "total_engines": 1,
                "suspicious_votes": 0, "harmless_votes": 0,
                "reputation": 0,
                "tags": [], "meaningful_name": "Unknown",
            }
        if r.status_code != 200:
            return {}

        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        total = max(sum(stats.values()), 1)
        return {
            "malicious_votes": stats.get("malicious", 0),
            "suspicious_votes": stats.get("suspicious", 0),
            "harmless_votes": stats.get("harmless", 0),
            "total_engines": total,
            "reputation": data.get("reputation", 0),
            "tags": data.get("tags", []),
            "meaningful_name": data.get("meaningful_name", "Unknown"),
        }
    except Exception as e:
        print(f" VT error for {ioc}: {e}")
        return {}


def query_abuse(ip: str) -> dict:
    key = abuse_rotator.get()
    if not key:
        return {}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=8,
        )
        if r.status_code != 200:
            return {}
        d = r.json().get("data", {})
        return {
            "confidence": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "distinct_users": d.get("numDistinctUsers", 0),
            "is_tor": bool(d.get("isTor", False)),
            "categories": list(set(
                cat for report in d.get("reports", [])
                for cat in report.get("categories", [])
            )) if d.get("reports") else [],
        }
    except Exception as e:
        print(f" AbuseIPDB error for {ip}: {e}")
        return {}


def query_shodan(ip: str) -> dict:
    key = shodan_rotator.get()
    if not key:
        return {}
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": key},
            timeout=10,
        )
        if r.status_code == 404:
            return {"open_ports": [], "cves": []}
        if r.status_code != 200:
            return {}
        d = r.json()
        cves = []
        for item in d.get("data", []):
            cves.extend(item.get("vulns", {}).keys())
        return {
            "open_ports": d.get("ports", []),
            "cves": list(set(cves)),
        }
    except Exception as e:
        print(f" Shodan error for {ip}: {e}")
        return {}


def classify_ioc_type(ioc: str) -> str:
    clean = ioc.strip().strip('"').strip("'")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", clean):
        return "ip"
    if re.match(r"^[0-9a-fA-F]{32,64}$", clean):
        return "hash"
    return "domain"


def clean_ioc(ioc: str) -> str:
    s = ioc.strip().strip('"').strip("'")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}", s) and ":" in s:
        s = s.split(":")[0]
    return s


def is_already_enriched(row: pd.Series) -> bool:
    es = str(row.get("enrichment_source", ""))
    src = str(row.get("source", ""))
    # Actual synthetic data from training generator — never needs API enrichment
    if src == "synthetic":
        return True
    if es == "real_api":
        return True
    # "synthetic" tag here means "not yet enriched" (legacy default), needs enrichment
    if src in ("known_cdn_range", "enriched_real"):
        return True
    ioc_type = str(row.get("ioc_type", "unknown")).lower()
    vt_ok = pd.notna(row.get("vt_malicious_ratio")) and float(row.get("vt_malicious_ratio", 0)) > 0
    for_ip = ioc_type == "ip"
    abuse_ok = pd.notna(row.get("abuse_confidence")) and float(row.get("abuse_confidence", 0)) > 0
    shodan_ok = pd.notna(row.get("shodan_open_ports_count")) and float(row.get("shodan_open_ports_count", 0)) > 0
    if for_ip:
        return vt_ok and abuse_ok and shodan_ok
    return vt_ok


def enrich_row(ioc: str, ioc_type: str) -> dict:
    vt_raw = query_vt(ioc, ioc_type)
    time.sleep(VT_DELAY / max(vt_rotator.count, 1))

    abuse_raw = {}
    shodan_raw = {}
    if ioc_type == "ip":
        abuse_raw = query_abuse(ioc)
        time.sleep(ABUSE_DELAY / max(abuse_rotator.count, 1))
        if shodan_rotator.keys:
            shodan_raw = query_shodan(ioc)
            time.sleep(SHODAN_DELAY / max(shodan_rotator.count, 1))

    return extract_ml_features(
        ioc_type=ioc_type, vt_raw=vt_raw,
        abuse_raw=abuse_raw, shodan_raw=shodan_raw,
    )


def run_enrichment(label_filter: str | None, limit: int | None, dry_run: bool):
    dataset_path = DATA_DIR / "ioc_dataset.csv"
    if not dataset_path.exists():
        print("ERROR: data/ioc_dataset.csv not found. Run build_dataset.py first.")
        sys.exit(1)

    df = pd.read_csv(dataset_path)
    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = np.nan

    if "enrichment_source" not in df.columns:
        df["enrichment_source"] = "synthetic"
        print(f"Tagged {len(df)} existing rows as 'synthetic' enrichment_source")

    enriched_iocs = set()
    if CKPT_PATH.exists():
        ckpt = pd.read_csv(CKPT_PATH)
        enriched_iocs = set(ckpt["ioc"].tolist())
        print(f"Checkpoint loaded: {len(enriched_iocs)} IOCs already enriched")

    needs_enrichment = df[
        ~df["ioc"].isin(enriched_iocs)
        & ~df.apply(is_already_enriched, axis=1)
    ].copy()

    for idx, row in needs_enrichment.iterrows():
        ioc_type = classify_ioc_type(str(row["ioc"]))
        needs_enrichment.at[idx, "ioc_type"] = ioc_type

    if label_filter:
        needs_enrichment = needs_enrichment[needs_enrichment["label"] == label_filter]
    if limit:
        needs_enrichment = needs_enrichment.head(limit)

    total = len(needs_enrichment)
    print(f"\nAPI key pools: VT={vt_rotator.count} Abuse={abuse_rotator.count} Shodan={shodan_rotator.count} OTX={otx_rotator.count}")
    print(f"\nIOCs needing enrichment: {total}")
    if total > 0:
        print(needs_enrichment["label"].value_counts().to_string())

    if dry_run:
        print("\n[DRY RUN] Would enrich the above. Exiting.")
        return

    if total == 0:
        print("Nothing to enrich. Dataset is up to date.")
        return

    ip_count = (needs_enrichment["ioc_type"] == "ip").sum()
    other_count = total - ip_count
    vt_effective_delay = VT_DELAY / max(vt_rotator.count, 1)
    est_seconds = ip_count * (vt_effective_delay + ABUSE_DELAY + SHODAN_DELAY) + other_count * vt_effective_delay
    print(f"\nEstimated time: {est_seconds/60:.1f} minutes ({ip_count} IPs, {other_count} other)")
    print(f"VT effective delay: {vt_effective_delay:.1f}s (key rotation ×{vt_rotator.count})")
    print("Press Ctrl+C to interrupt — progress is checkpointed.\n")

    enriched_count = 0
    checkpoint_buf = []

    for i, (idx, row) in enumerate(needs_enrichment.iterrows()):
        raw_ioc = str(row["ioc"])
        ioc = clean_ioc(raw_ioc)
        ioc_type = classify_ioc_type(raw_ioc)
        label = row.get("label", "?")

        print(f" [{i+1}/{total}] {ioc[:60]} ({ioc_type}, {label})...", end=" ", flush=True)

        try:
            features = enrich_row(ioc, ioc_type)
            for col, val in features.items():
                if col in df.columns:
                    df.at[idx, col] = val
            df.at[idx, "last_seen"] = NOW_UTC
            df.at[idx, "enrichment_source"] = "real_api"
            enriched_count += 1
            checkpoint_buf.append({"ioc": raw_ioc})
            print(
                f"vt={features.get('vt_malicious_ratio', 0):.3f} "
                f"abuse={features.get('abuse_confidence', 0):.0f} "
                f"tags={features.get('tag_count', 0):.0f}"
            )
        except KeyboardInterrupt:
            print("\n\nInterrupted — saving checkpoint...")
            _save_checkpoint(checkpoint_buf, df, dataset_path)
            sys.exit(0)
        except Exception as e:
            print(f"ERROR: {e}")
            continue

        if enriched_count % CHECKPOINT_EVERY == 0:
            _save_checkpoint(checkpoint_buf, df, dataset_path)
            checkpoint_buf = []
            print(f"  [Checkpoint saved — {enriched_count}/{total} enriched]")

    _save_checkpoint(checkpoint_buf, df, dataset_path)
    print(f"\nDone. {enriched_count} IOCs enriched and saved to ioc_dataset.csv")
    print("\nUpdated label distribution:")
    print(df["label"].value_counts().to_string())


def _save_checkpoint(buf: list[dict], df: pd.DataFrame, dataset_path: Path):
    if buf:
        new_ckpt = pd.DataFrame(buf)
        if CKPT_PATH.exists():
            old_ckpt = pd.read_csv(CKPT_PATH)
            new_ckpt = pd.concat([old_ckpt, new_ckpt], ignore_index=True).drop_duplicates()
        new_ckpt.to_csv(CKPT_PATH, index=False)
    df.to_csv(dataset_path, index=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bulk IOC enrichment with API rate limiting and multi-key rotation")
    parser.add_argument("--label", help="Only enrich IOCs with this label (CRITICAL/HIGH/MEDIUM/LOW/CLEAN)")
    parser.add_argument("--limit", type=int, help="Max IOCs to enrich (for budget/quota control)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be enriched without calling APIs")
    args = parser.parse_args()
    run_enrichment(
        label_filter=args.label,
        limit=args.limit,
        dry_run=args.dry_run,
    )
