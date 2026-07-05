"""
VirusTotal Tool — queries VT API for IP, domain, or file hash reputation.
Free tier: 500 requests/day, 4 requests/minute.
"""

import os
import requests
from langchain_core.tools import tool


VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"

HEADERS = {
    "accept": "application/json",
    "x-apikey": VT_API_KEY or "",
}


def _query_ip(ip: str) -> dict:
    resp = requests.get(f"{VT_BASE}/ip_addresses/{ip}", headers=HEADERS, timeout=10)
    resp.raise_for_status()
    data = resp.json()["data"]["attributes"]
    stats = data.get("last_analysis_stats", {})
    return {
        "malicious_votes": stats.get("malicious", 0),
        "suspicious_votes": stats.get("suspicious", 0),
        "harmless_votes": stats.get("harmless", 0),
        "total_engines": sum(stats.values()),
        "country": data.get("country", "Unknown"),
        "asn": data.get("asn", "Unknown"),
        "as_owner": data.get("as_owner", "Unknown"),
        "reputation": data.get("reputation", 0),
        "tags": data.get("tags", []),
    }


def _query_domain(domain: str) -> dict:
    resp = requests.get(f"{VT_BASE}/domains/{domain}", headers=HEADERS, timeout=10)
    resp.raise_for_status()
    data = resp.json()["data"]["attributes"]
    stats = data.get("last_analysis_stats", {})
    return {
        "malicious_votes": stats.get("malicious", 0),
        "suspicious_votes": stats.get("suspicious", 0),
        "harmless_votes": stats.get("harmless", 0),
        "total_engines": sum(stats.values()),
        "reputation": data.get("reputation", 0),
        "categories": data.get("categories", {}),
        "registrar": data.get("registrar", "Unknown"),
        "creation_date": data.get("creation_date", "Unknown"),
        "tags": data.get("tags", []),
    }


def _query_hash(file_hash: str) -> dict:
    resp = requests.get(f"{VT_BASE}/files/{file_hash}", headers=HEADERS, timeout=10)
    resp.raise_for_status()
    data = resp.json()["data"]["attributes"]
    stats = data.get("last_analysis_stats", {})
    return {
        "malicious_votes": stats.get("malicious", 0),
        "suspicious_votes": stats.get("suspicious", 0),
        "harmless_votes": stats.get("harmless", 0),
        "total_engines": sum(stats.values()),
        "file_type": data.get("type_description", "Unknown"),
        "file_size": data.get("size", 0),
        "meaningful_name": data.get("meaningful_name", "Unknown"),
        "tags": data.get("tags", []),
        "sigma_rules": data.get("sigma_analysis_results", []),
    }


@tool
def virustotal_tool(ioc: str) -> str:
    """
    Query VirusTotal for reputation data on an IP address, domain, or file hash (MD5/SHA1/SHA256).
    Returns detection counts, engine verdicts, metadata, and tags.
    Input: a single IOC string (IP, domain, or hash).
    """
    if not VT_API_KEY:
        return "ERROR: VIRUSTOTAL_API_KEY not set in environment."

    ioc = ioc.strip()

    # Detect IOC type from format
    import re
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        result = _query_ip(ioc)
        label = "IP"
    elif re.match(r"^[a-fA-F0-9]{32,64}$", ioc):
        result = _query_hash(ioc)
        label = "FileHash"
    else:
        result = _query_domain(ioc)
        label = "Domain"

    malicious = result.get("malicious_votes", 0)
    total = result.get("total_engines", 0)

    output = f"[VirusTotal] {label}: {ioc}\n"
    output += f"  Detection ratio: {malicious}/{total} engines flagged as malicious\n"
    output += f"  Suspicious votes: {result.get('suspicious_votes', 0)}\n"

    for k, v in result.items():
        if k not in ("malicious_votes", "suspicious_votes", "total_engines"):
            output += f"  {k}: {v}\n"

    return output
