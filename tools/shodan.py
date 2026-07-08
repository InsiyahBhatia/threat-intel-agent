"""
Shodan Tool — queries Shodan for open ports, services, CVEs on an IP.
Free tier: limited to /shodan/host/{ip} endpoint.
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

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
SHODAN_BASE = "https://api.shodan.io"


def _query_shodan(ip: str) -> dict:
    """Return structured Shodan data for an IP. Raises on network error."""
    client = _get_client()
    resp = client.get(
        f"{SHODAN_BASE}/shodan/host/{ip}",
        params={"key": SHODAN_API_KEY},
    )
    if resp.status_code == 404:
        return {
            "org": "Unknown", "isp": "Unknown", "country": "Unknown",
            "hostnames": [], "ports": [], "tags": [], "cves": [],
            "cve_count": 0, "services": [],
        }
    resp.raise_for_status()
    data = resp.json()

    ports = data.get("ports", [])
    tags = data.get("tags", [])
    all_cves: list[str] = []
    services: list[dict] = []
    for service in data.get("data", []):
        port = service.get("port")
        transport = service.get("transport", "tcp")
        product = service.get("product", "")
        version = service.get("version", "")
        cves = list(service.get("vulns", {}).keys())
        all_cves.extend(cves)
        services.append({
            "port": port, "transport": transport,
            "product": product, "version": version, "cves": cves,
        })

    unique_cves = list(dict.fromkeys(all_cves))  # deduplicate, preserve order
    return {
        "org": data.get("org", "Unknown"),
        "isp": data.get("isp", "Unknown"),
        "country": data.get("country_name", "Unknown"),
        "hostnames": data.get("hostnames", []),
        "ports": ports,
        "tags": tags,
        "cves": unique_cves,
        "cve_count": len(unique_cves),
        "services": services,
    }


@tool
def shodan_tool(ip: str) -> str:
    """
    Query Shodan for open ports, running services, banners, and known CVEs on an IP address.
    Only works for IP addresses, not domains or file hashes.
    Input: an IPv4 address string.
    """
    if not SHODAN_API_KEY:
        return "ERROR: SHODAN_API_KEY not set in environment."

    ip = ip.strip()
    import re
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return f"[Shodan] Skipped: '{ip}' is not an IP address. Shodan only accepts IPs."

    try:
        result = _query_shodan(ip)
    except httpx.HTTPError as e:
        return f"[Shodan] Request failed: {e}"

    if not result["ports"]:
        return f"[Shodan] No data found for IP: {ip}"

    services_summary = []
    for svc in result["services"][:10]:  # cap at 10 to avoid token overflow
        svc_line = f"    {svc['port']}/{svc['transport']} — {svc['product']} {svc['version']}".strip(" —")
        if svc["cves"]:
            svc_line += f" [CVEs: {', '.join(svc['cves'])}]"
        services_summary.append(svc_line)

    output = f"[Shodan] IP: {ip}\n"
    output += f"  Organization: {result['org']} / ISP: {result['isp']}\n"
    output += f"  Country: {result['country']}\n"
    output += f"  Hostnames: {', '.join(result['hostnames']) if result['hostnames'] else 'None'}\n"
    output += f"  Open ports: {', '.join(str(p) for p in sorted(result['ports']))}\n"
    output += f"  Tags: {', '.join(result['tags']) if result['tags'] else 'None'}\n"
    output += f"  Known CVEs: {', '.join(result['cves']) if result['cves'] else 'None'}\n"
    output += "  Services:\n"
    for s in services_summary:
        output += s + "\n"

    return output
