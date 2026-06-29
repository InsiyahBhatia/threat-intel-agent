"""
AlienVault OTX Tool — queries OTX for threat intelligence pulses and indicators.
Free tier: 1M requests/month.
"""

import os
import requests
from langchain_core.tools import tool

OTX_API_KEY = os.getenv("OTX_API_KEY")
OTX_BASE = "https://otx.alienvault.com/api/v1"


def _query_otx(ioc: str) -> dict:
    """Return structured OTX data for an IOC. Raises on network error."""
    if not OTX_API_KEY:
        return {"pulses": [], "avg_confidence": 0, "has_scan": False}
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    import re
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        url = f"{OTX_BASE}/indicators/IPv4/{ioc}/general"
    elif re.match(r"^[a-fA-F0-9]{32,64}$", ioc):
        url = f"{OTX_BASE}/indicators/file/{ioc}/general"
    else:
        url = f"{OTX_BASE}/indicators/domain/{ioc}/general"
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        pulses = data.get("pulse_info", {}).get("pulses", [])[:10]
        confs = [p.get("confidence", 0) for p in pulses if p.get("confidence")]
        avg_conf = round(sum(confs) / len(confs), 1) if confs else 0
        return {
            "pulses": [{"name": p.get("name", ""), "confidence": p.get("confidence", 0),
                        "tags": p.get("tags", []), "created": p.get("created", "")} for p in pulses],
            "avg_confidence": avg_conf,
            "has_scan": bool(data.get("has_scan", False)),
            "country": data.get("country_code", ""),
            "asn": data.get("asn", ""),
        }
    except requests.RequestException:
        return {"pulses": [], "avg_confidence": 0, "has_scan": False}


@tool
def otx_tool(ioc: str) -> str:
    """
    Query AlienVault OTX for threat intelligence pulses and indicator reputation.
    Returns pulse names, confidence levels, tags, and related indicators.
    Input: a single IOC string (IP, domain, or hash).
    """
    if not OTX_API_KEY:
        return ""
    ioc = ioc.strip()
    data = _query_otx(ioc)
    pulses = data.get("pulses", [])
    if not pulses:
        return ""
    output = f"[AlienVault OTX] IOC: {ioc}\n"
    output += f"  Pulses found: {len(pulses)}\n"
    if data.get("avg_confidence"):
        output += f"  Average pulse confidence: {data['avg_confidence']}/100\n"
    for p in pulses[:5]:
        tags = ", ".join(p.get("tags", [])[:5]) or "none"
        output += f"  - {p['name']} (confidence: {p['confidence']}, tags: {tags})\n"
    return output
