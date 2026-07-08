"""
AbuseIPDB Tool — checks IP abuse history and community reports.
Free tier: 1000 checks/day.
"""

import os
import threading

import httpx

from utils.decorators import tool

_tls = threading.local()

def _get_client() -> httpx.Client:
    if not hasattr(_tls, "client"):
        _tls.client = httpx.Client(timeout=10.0, follow_redirects=False)
    return _tls.client

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"

# Map category IDs to human-readable names
CATEGORY_MAP = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
    12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


def _query_abuseipdb(ip: str) -> dict:
    """Return structured AbuseIPDB data for an IP. Raises on network error."""
    client = _get_client()
    resp = client.get(
        f"{ABUSEIPDB_BASE}/check",
        headers={
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        },
        params={
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True,
        },
    )
    resp.raise_for_status()
    data = resp.json().get("data", {})

    # Aggregate distinct category IDs across recent reports
    category_ids: set[int] = set()
    category_counts: dict[str, int] = {}
    for report in data.get("reports", [])[:20]:
        for cat_id in report.get("categories", []):
            category_ids.add(cat_id)
            name = CATEGORY_MAP.get(cat_id, f"Category {cat_id}")
            category_counts[name] = category_counts.get(name, 0) + 1

    return {
        "confidence": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "distinct_users": data.get("numDistinctUsers", 0),
        "last_reported": data.get("lastReportedAt", "Never"),
        "country": data.get("countryCode", "Unknown"),
        "domain": data.get("domain", "Unknown"),
        "isp": data.get("isp", "Unknown"),
        "is_tor": bool(data.get("isTor", False)),
        "is_whitelisted": bool(data.get("isWhitelisted", False)),
        "categories_count": len(category_ids),
        "category_counts": category_counts,
    }


@tool
def abuseipdb_tool(ip: str) -> str:
    """
    Query AbuseIPDB for community-reported abuse history on an IP address.
    Returns abuse confidence score, total reports, categories of abuse, and recent report samples.
    Only works for IP addresses, not domains or file hashes.
    Input: an IPv4 address string.
    """
    if not ABUSEIPDB_API_KEY:
        return "ERROR: ABUSEIPDB_API_KEY not set in environment."

    ip = ip.strip()
    import re
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return f"[AbuseIPDB] Skipped: '{ip}' is not an IP address."

    try:
        data = _query_abuseipdb(ip)
    except httpx.HTTPError as e:
        return f"[AbuseIPDB] Request failed: {e}"

    confidence = data["confidence"]
    total_reports = data["total_reports"]
    distinct_users = data["distinct_users"]
    last_reported = data["last_reported"]
    country = data["country"]
    domain = data["domain"]
    isp = data["isp"]
    is_tor = data["is_tor"]
    is_whitelisted = data["is_whitelisted"]

    categories_str = ", ".join(
        f"{cat} ({count}x)"
        for cat, count in sorted(data["category_counts"].items(), key=lambda x: -x[1])
    ) or "None"

    output = f"[AbuseIPDB] IP: {ip}\n"
    output += f"  Abuse Confidence Score: {confidence}/100\n"
    output += f"  Total abuse reports (last 90 days): {total_reports} from {distinct_users} users\n"
    output += f"  Last reported: {last_reported}\n"
    output += f"  Country: {country} | ISP: {isp} | Domain: {domain}\n"
    output += f"  Is Tor exit node: {is_tor}\n"
    output += f"  Is whitelisted: {is_whitelisted}\n"
    output += f"  Abuse categories reported: {categories_str}\n"

    if confidence >= 75:
        output += "  ⚠ HIGH RISK: This IP has a high abuse confidence score.\n"
    elif confidence >= 25:
        output += "  ⚠ MODERATE RISK: This IP has moderate abuse reports.\n"
    else:
        output += "  ✓ LOW RISK: Few or no abuse reports found.\n"

    return output
