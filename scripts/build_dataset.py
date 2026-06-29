"""
Bulk download and dataset builder for the ML severity classifier.
Combines zero-API CSV bulk exports with targeted API calls for missing gaps.

Tracks timestamps:
  - first_seen: UTC timestamp of initial IOC ingest (immutable on re-run)
  - last_seen:  UTC timestamp of most recent update for this IOC
  - source_collected_at: upstream feed timestamp (e.g. first_seen_utc from
    MalwareBazaar, dateadded from URLhaus) — preserved when available
"""

import io
import os
import random
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
import ipaddress
import numpy as np
import pandas as pd
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env")

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROC_DIR = DATA_DIR / "processed"
RAW_DIR.mkdir(parents=True, exist_ok=True)
PROC_DIR.mkdir(parents=True, exist_ok=True)

NOW_UTC = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

FEEDS = {
    "feodo_ips": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
    "malwarebazaar": "https://bazaar.abuse.ch/export/csv/recent/",
    "urlhaus_recent": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "ipsum": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
}

CLEAN_RANGES = [
    "8.8.8.0/24", "1.1.1.0/24", "208.67.222.0/24", "13.32.0.0/15",
    "104.16.0.0/13", "142.250.0.0/15", "20.33.0.0/16", "199.232.0.0/16",
]

def download_feeds():
    for name, url in FEEDS.items():
        if (RAW_DIR / f"{name}.csv").exists() or (RAW_DIR / f"{name}.txt").exists():
            print(f"Skipping download, {name} already exists.")
            continue
        print(f"Downloading {name}...")
        r = requests.get(url, timeout=30)
        ext = "txt" if name == "ipsum" else "csv"
        with open(RAW_DIR / f"{name}.{ext}", "wb") as f:
            f.write(r.content)
        print(f"[OK] {name}: {len(r.content)//1024}KB downloaded")

def fetch_clean_samples():
    clean_iocs = []

    try:
        # Tranco top-1K domains (verifiably legitimate)
        r = requests.get("https://tranco-list.eu/top-1m.csv.zip", timeout=30)
        import zipfile, io
        z = zipfile.ZipFile(io.BytesIO(r.content))
        lines = z.read(z.namelist()[0]).decode().splitlines()[:600]
        for line in lines:
            parts = line.split(",")
            if len(parts) >= 2:
                domain = parts[1].strip()
                clean_iocs.append({
                    "ioc": domain, "ioc_type": "domain", "label": "CLEAN",
                    "source": "tranco_top1k", "vt_malicious_ratio": np.nan,
                    "abuse_confidence": np.nan, "abuse_total_reports": np.nan,
                    "abuse_is_tor": 0, "tag_count": 0, "has_known_family": 0,
                    "first_seen": NOW_UTC, "last_seen": NOW_UTC, "source_collected_at": None,
                })
        print(f"[OK] Tranco: {len(clean_iocs)} clean domains")
    except Exception as e:
        print(f"[!] Tranco fetch failed: {e}")

    try:
        # Cloudflare IP ranges
        cf = requests.get("https://www.cloudflare.com/ips-v4", timeout=15).text.splitlines()
        sampled = 0
        for cidr in cf[:8]:
            net = ipaddress.ip_network(cidr)
            hosts = list(net.hosts())
            for ip in hosts[:15]:
                clean_iocs.append({
                    "ioc": str(ip), "ioc_type": "ip", "label": "CLEAN",
                    "source": "cloudflare", "vt_malicious_ratio": np.nan,
                    "abuse_confidence": np.nan, "abuse_total_reports": np.nan,
                    "abuse_is_tor": 0, "tag_count": 0, "has_known_family": 0,
                    "first_seen": NOW_UTC, "last_seen": NOW_UTC, "source_collected_at": None,
                })
                sampled += 1
        print(f"[OK] Cloudflare: {sampled} clean IPs")
    except Exception as e:
        print(f"[!] Cloudflare fetch failed: {e}")

    # Known clean DNS / infrastructure IPs
    known_clean = [
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
        "208.67.222.222", "208.67.220.220", "9.9.9.9", "149.112.112.112",
    ]
    for ip in known_clean:
        clean_iocs.append({
            "ioc": ip, "ioc_type": "ip", "label": "CLEAN",
            "source": "known_infrastructure", "vt_malicious_ratio": np.nan,
            "abuse_confidence": np.nan, "abuse_total_reports": np.nan,
            "abuse_is_tor": 0, "tag_count": 0, "has_known_family": 0,
            "first_seen": NOW_UTC, "last_seen": NOW_UTC, "source_collected_at": None,
        })

    df = pd.DataFrame(clean_iocs).drop_duplicates(subset=["ioc"])
    df.to_csv(PROC_DIR / "clean_iocs.csv", index=False)
    print(f"[OK] Total clean samples collected: {len(df)}")
    return df


def generate_clean():
    clean_ips = []
    for cidr in CLEAN_RANGES:
        network = ipaddress.ip_network(cidr)
        hosts = list(network.hosts())
        sampled = random.sample(hosts, min(250, len(hosts)))
        clean_ips.extend([str(ip) for ip in sampled])
    
    df_clean = pd.DataFrame({
        "ioc": clean_ips,
        "ioc_type": "ip",
        "label": "CLEAN",
        "source": "known_cdn_range",
        "vt_malicious_ratio": np.nan,
        "abuse_confidence": np.nan,
        "abuse_total_reports": np.nan,
        "abuse_is_tor": np.nan,
        "tag_count": np.nan,
        "has_known_family": np.nan,
        "first_seen": NOW_UTC,
        "last_seen": NOW_UTC,
        "source_collected_at": None,
    })
    df_clean.to_csv(PROC_DIR / "clean_samples.csv", index=False)
    print(f"[OK] Generated {len(df_clean)} clean samples")

def parse_feeds():
    samples = []

    # MalwareBazaar
    if (RAW_DIR / "malwarebazaar.csv").exists():
        mb_cols = [
            "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter",
            "file_name","file_type_guess","mime_type","signature","clamav",
            "vtpercent","imphash","ssdeep","tlsh"
        ]
        mb = pd.read_csv(RAW_DIR / "malwarebazaar.csv", comment="#", names=mb_cols, on_bad_lines="skip")
        mb = mb.rename(columns={"sha256_hash":"ioc"})
        mb["ioc_type"] = "hash"
        mb["label"] = "CRITICAL"
        mb["source"] = "malwarebazaar"
        mb["has_known_family"] = mb.get("signature", pd.Series(dtype=object)).notna().astype(int)
        mb["tag_count"] = mb.get("tags", pd.Series(dtype=object)).fillna("").str.count(",") + 1
        mb["vt_malicious_ratio"] = np.nan
        mb["abuse_confidence"] = 0
        mb["abuse_total_reports"] = 0
        mb["abuse_is_tor"] = 0
        mb["first_seen"] = NOW_UTC
        mb["last_seen"] = NOW_UTC
        mb["source_collected_at"] = mb.get("first_seen_utc", None)
        samples.append(mb[["ioc","ioc_type","label","source","vt_malicious_ratio","abuse_confidence","abuse_total_reports","abuse_is_tor","tag_count","has_known_family","first_seen","last_seen","source_collected_at"]].head(2500))

    # Feodo IPs
    if (RAW_DIR / "feodo_ips.csv").exists():
        feodo = pd.read_csv(RAW_DIR / "feodo_ips.csv", comment="#", names=["first_seen","dst_port","c2_status","ip","country","hostname"], on_bad_lines="skip")
        feodo["ioc"] = feodo["ip"]
        feodo["ioc_type"] = "ip"
        feodo["label"] = "CRITICAL"
        feodo["source"] = "feodo_tracker"
        feodo["vt_malicious_ratio"] = np.nan
        feodo["abuse_confidence"] = np.nan
        feodo["abuse_total_reports"] = np.nan
        feodo["abuse_is_tor"] = 0
        feodo["tag_count"] = 2
        feodo["has_known_family"] = 1
        feodo["first_seen"] = NOW_UTC
        feodo["last_seen"] = NOW_UTC
        feodo["source_collected_at"] = feodo.get("first_seen", None)
        samples.append(feodo[["ioc","ioc_type","label","source","vt_malicious_ratio","abuse_confidence","abuse_total_reports","abuse_is_tor","tag_count","has_known_family","first_seen","last_seen","source_collected_at"]].head(800))

    # URLhaus
    if (RAW_DIR / "urlhaus_recent.csv").exists():
        urlhaus = pd.read_csv(RAW_DIR / "urlhaus_recent.csv", comment="#", names=["id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"], on_bad_lines="skip")
        urlhaus["ioc"] = urlhaus["url"].str.extract(r"https?://([^/]+)")[0]
        urlhaus["ioc_type"] = urlhaus["ioc"].apply(
            lambda x: "ip" if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", str(x)) else "domain"
        )
        urlhaus["ioc"] = urlhaus["ioc"].apply(
            lambda x: x.split(":")[0] if re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d+", str(x)) else x
        )
        urlhaus["label"] = "HIGH"
        urlhaus["source"] = "urlhaus"
        urlhaus["vt_malicious_ratio"] = np.nan
        urlhaus["abuse_confidence"] = np.nan
        urlhaus["abuse_total_reports"] = np.nan
        urlhaus["abuse_is_tor"] = np.nan
        urlhaus["tag_count"] = urlhaus["tags"].fillna("").str.count(",") + 1
        urlhaus["has_known_family"] = 0
        urlhaus["first_seen"] = NOW_UTC
        urlhaus["last_seen"] = NOW_UTC
        urlhaus["source_collected_at"] = urlhaus.get("dateadded", None)
        samples.append(urlhaus[["ioc","ioc_type","label","source","vt_malicious_ratio","abuse_confidence","abuse_total_reports","abuse_is_tor","tag_count","has_known_family","first_seen","last_seen","source_collected_at"]].dropna(subset=["ioc"]).head(2000))

    if samples:
        df = pd.concat(samples, ignore_index=True).drop_duplicates(subset=["ioc"])
        df.to_csv(PROC_DIR / "dataset_no_api.csv", index=False)
        print(f"[OK] Total CSV samples parsed: {len(df)}")
    else:
        print("No samples to parse.")

def _refine_label_from_abuse(abuse_confidence: float, abuse_reports: int) -> str:
    if abuse_confidence >= 80:
        return "HIGH"
    elif abuse_confidence >= 40:
        return "MEDIUM"
    elif abuse_confidence >= 10 or abuse_reports >= 5:
        return "LOW"
    return "CLEAN"


def enrich_low_samples():
    if not ABUSE_KEY:
        print("Skipping AbuseIPDB enrichment - missing key")
        return

    low_samples = []
    if (RAW_DIR / "ipsum.txt").exists():
        with open(RAW_DIR / "ipsum.txt") as f:
            ipsum = f.readlines()
        
        low_candidates = [
            line.split()[0] for line in ipsum 
            if not line.startswith("#") and len(line.split()) > 1 and int(line.split()[1]) <= 3
        ][:400] # Take 400 candidates (respects 1000/day limit)

        print(f"Enriching {len(low_candidates)} LOW samples with AbuseIPDB...")
        for i, ip in enumerate(low_candidates):
            try:
                ab = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": ABUSE_KEY, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    timeout=5
                ).json().get("data", {})
                
                low_samples.append({
                    "ioc": ip, "ioc_type": "ip",
                    "label": _refine_label_from_abuse(ab.get("abuseConfidenceScore", 0), ab.get("totalReports", 0)),
                    "source": "ipsum_low",
                    "abuse_confidence": ab.get("abuseConfidenceScore", 0),
                    "abuse_total_reports": ab.get("totalReports", 0),
                    "abuse_is_tor": int(ab.get("isTor", 0)),
                    "vt_malicious_ratio": np.nan,
                    "tag_count": 0,
                    "has_known_family": 0,
                    "first_seen": NOW_UTC,
                    "last_seen": NOW_UTC,
                    "source_collected_at": None,
                })
                time.sleep(0.25)
            except Exception as e:
                continue
            if (i+1) % 50 == 0:
                print(f"  Enriched {i+1}/{len(low_candidates)}")

    pd.DataFrame(low_samples).to_csv(PROC_DIR / "low_samples.csv", index=False)
    print(f"[OK] Collected {len(low_samples)} LOW samples via API")

def merge_all():
    """Merge new samples with existing dataset, preserving first_seen."""
    new_parts = []
    for f in ["dataset_no_api.csv", "clean_samples.csv", "clean_iocs.csv", "low_samples.csv"]:
        path = PROC_DIR / f
        if path.exists():
            df = pd.read_csv(path)
            if df.empty:
                continue
            for col in ["first_seen", "last_seen", "source_collected_at"]:
                if col not in df.columns:
                    df[col] = NOW_UTC if col != "source_collected_at" else None
            new_parts.append(df)

    if not new_parts:
        print("No new data to merge.")
        return

    new_df = pd.concat(new_parts, ignore_index=True).drop_duplicates(subset=["ioc"])
    existing_path = DATA_DIR / "ioc_dataset.csv"

    if existing_path.exists():
        old_df = pd.read_csv(existing_path)

        for col in new_df.columns:
            if col not in old_df.columns:
                old_df[col] = None

        new_iocs = new_df[~new_df["ioc"].isin(old_df["ioc"])]
        known_new = new_df[new_df["ioc"].isin(old_df["ioc"])]

        known_old = old_df[old_df["ioc"].isin(known_new["ioc"])].copy()
        known_old["last_seen"] = NOW_UTC

        known_new = known_new.set_index("ioc")
        known_old = known_old.set_index("ioc")

        # Merge all columns — first_seen uses combine_first to preserve non-null old values
        for col in known_new.columns:
            if col in known_old.columns:
                if col == "first_seen":
                    known_old[col] = known_old[col].combine_first(known_new[col])
                elif col != "last_seen":
                    known_old[col] = known_new[col].combine_first(known_old[col])

        known_old.reset_index(inplace=True)

        for col in ["first_seen", "last_seen", "source_collected_at"]:
            if col not in known_old.columns:
                known_old[col] = None

        unchanged_old = old_df[~old_df["ioc"].isin(new_df["ioc"])].copy()
        result = pd.concat([unchanged_old, known_old, new_iocs], ignore_index=True)

        print(f"Merged: {len(unchanged_old)} unchanged, "
              f"{len(known_old)} updated, {len(new_iocs)} new")
    else:
        result = new_df
        print(f"Fresh dataset: {len(result)} samples")

    result.drop_duplicates(subset=["ioc"], inplace=True)
    result.to_csv(existing_path, index=False)

    print("Final distribution:")
    print(result["label"].value_counts())
    print(f"[OK] Dataset merged to data/ioc_dataset.csv ({len(result)} samples)")

if __name__ == "__main__":
    download_feeds()
    generate_clean()
    fetch_clean_samples()
    parse_feeds()
    enrich_low_samples()
    merge_all()
