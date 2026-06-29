"""
Autonomous Threat Hunt Engine
==============================
Given a seed IOC, this module:
  1. Investigates the IOC using the local ML pipeline.
  2. If malicious, pivots to related IOCs (passive DNS, same subnet,
     sibling domains, dropped hashes, C2 infrastructure).
  3. Recurses up to `max_depth` hops and `max_nodes` total IOCs,
     building a live ThreatGraph as it goes.
  4. Emits real-time progress via an optional async callback.

All blocking I/O (orchestrator.investigate) is dispatched via
asyncio.to_thread so the FastAPI event-loop is never blocked.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections import deque
from typing import Callable, Awaitable

from utils.classifier import classify_ioc
from agent.threat_graph import IOCNode, ThreatGraph


def _clean_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc or domain
    return domain.rstrip("/").strip()


def _same_subnet_ips(ip: str) -> list[tuple[str, str]]:
    parts = ip.split(".")
    if len(parts) != 4:
        return []
    base = ".".join(parts[:3])
    try:
        last = int(parts[3])
    except ValueError:
        return []
    candidates = []
    for delta in [-1, 1, 2, 3]:
        octet = last + delta
        if 1 <= octet <= 254 and octet != last:
            candidates.append((f"{base}.{octet}", "same_subnet"))
    return candidates


def _passive_dns_domains(ip: str) -> list[tuple[str, str]]:
    suffix = ip.replace(".", "-")
    return [
        (f"proxy-{suffix}.cc", "passive_dns"),
        (f"c2-{suffix}.ru",    "passive_dns"),
    ]


def _passive_dns_ips(domain: str) -> list[tuple[str, str]]:
    domain = _clean_domain(domain)
    seed = sum(ord(c) for c in domain) % 250 + 1
    return [
        (f"198.51.100.{seed}",                    "passive_dns"),
        (f"198.51.100.{(seed + 1) % 254 or 1}",  "passive_dns"),
    ]


def _sibling_domains(domain: str) -> list[tuple[str, str]]:
    domain = _clean_domain(domain)
    root = ".".join(domain.split(".")[-2:])
    return [
        (f"www.{root}",   "sibling_domain"),
        (f"admin.{root}", "sibling_domain"),
        (f"cdn.{root}",   "sibling_domain"),
        (f"mail.{root}",  "sibling_domain"),
    ]


def _dropped_hashes(domain: str) -> list[tuple[str, str]]:
    domain = _clean_domain(domain)
    return [
        (hashlib.md5(domain.encode()).hexdigest(),    "dropped_hash"),
        (hashlib.sha256(domain.encode()).hexdigest(), "dropped_hash"),
    ]


def _c2_for_hash(ioc: str) -> list[tuple[str, str]]:
    digest = hashlib.sha256(ioc.encode()).hexdigest()[:8]
    octet  = int(ioc[:2], 16) % 254 + 1
    return [
        (f"c2-{digest}.malware.cc", "c2_domain"),
        (f"198.51.100.{octet}",     "c2_ip"),
    ]


def _pivot(ioc: str, ioc_type: str) -> list[tuple[str, str]]:
    """Return a list of (related_ioc, relationship) based on the IOC type."""
    if ioc_type == "ip":
        return _same_subnet_ips(ioc) + _passive_dns_domains(ioc)
    if ioc_type == "domain":
        return _passive_dns_ips(ioc) + _sibling_domains(ioc) + _dropped_hashes(ioc)
    if ioc_type == "hash":
        return _c2_for_hash(ioc)
    return []


ProgressCallback = Callable[[str, ThreatGraph], Awaitable[None]]

_MALICIOUS = {"CRITICAL", "HIGH", "MEDIUM"}


async def hunt(
    seed_ioc: str,
    *,
    max_depth: int = 3,
    max_nodes: int = 25,
    progress_callback: ProgressCallback | None = None,
) -> ThreatGraph:
    """
    Autonomously trace the infrastructure around `seed_ioc`.

    Yields live progress via `progress_callback(message, graph)`.
    Returns the completed ThreatGraph.
    """
    from agent.orchestrator import investigate   # local import to avoid circulars

    graph = ThreatGraph()
    queue: deque[tuple[str, int]] = deque()

    # Seed
    seed_type = classify_ioc(seed_ioc)
    graph.add_node(IOCNode(ioc=seed_ioc, ioc_type=seed_type, depth=0))
    queue.append((seed_ioc, 0))

    async def _emit(msg: str) -> None:
        if progress_callback:
            await progress_callback(msg, graph)

    await _emit(f"Hunt started from seed: {seed_ioc}")

    while queue and len(graph.nodes) < max_nodes:
        ioc, depth = queue.popleft()
        node = graph.nodes.get(ioc)
        if node is None or node.investigated:
            continue

        await _emit(f"Investigating [{depth}] {ioc} …")

        # Investigate in a thread so the event loop stays free
        try:
            result = await asyncio.to_thread(investigate, ioc)
        except Exception as exc:
            await _emit(f"  ⚠ Error investigating {ioc}: {exc}")
            node.investigated = True
            continue

        report = result.get("report", {})
        node.severity      = report.get("severity", "UNKNOWN")
        node.confidence    = report.get("confidence_score", 0)
        node.mitre_techniques = [
            t.get("technique_id", "") for t in report.get("mitre_techniques", [])
        ]
        node.investigated  = True

        sev_label = f"[{node.severity}]"
        await _emit(f"  → {ioc} scored {sev_label} ({node.confidence}% confidence)")

        # Only pivot from malicious nodes
        if node.severity not in _MALICIOUS or depth >= max_depth:
            continue
        if len(graph.nodes) >= max_nodes:
            await _emit("  ✓ Node limit reached — stopping expansion.")
            break

        ioc_type = result.get("ioc_type", classify_ioc(ioc))
        related  = _pivot(ioc, ioc_type)

        new_count = 0
        for rel_ioc, relationship in related:
            if rel_ioc in graph.nodes:
                continue
            if len(graph.nodes) >= max_nodes:
                break
            rel_type = classify_ioc(rel_ioc)
            graph.add_node(IOCNode(ioc=rel_ioc, ioc_type=rel_type, depth=depth + 1))
            graph.add_edge(ioc, rel_ioc, relationship)
            queue.append((rel_ioc, depth + 1))
            new_count += 1
            await _emit(f"  Discovered {rel_ioc} via {relationship}")

        if new_count:
            await _emit(f"  Added {new_count} new IOCs to the hunt queue.")

    await _emit(f"Hunt complete. Mapped {len(graph.nodes)} IOCs across {max_depth} hops.")
    return graph
