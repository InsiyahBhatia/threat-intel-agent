from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


# Node colours & shapes per severity

_SEV_STYLE: dict[str, dict] = {
    "CRITICAL": {"color": {"background": "#ff2a55", "border": "#ff0040"},
                 "font":  {"color": "#ffffff"},
                 "shape": "dot", "size": 22},
    "HIGH":     {"color": {"background": "#ff8800", "border": "#e57200"},
                 "font":  {"color": "#ffffff"},
                 "shape": "dot", "size": 18},
    "MEDIUM":   {"color": {"background": "#facc15", "border": "#d4a000"},
                 "font":  {"color": "#0a0a0b"},
                 "shape": "dot", "size": 14},
    "LOW":      {"color": {"background": "#3b82f6", "border": "#2563eb"},
                 "font":  {"color": "#ffffff"},
                 "shape": "dot", "size": 12},
    "CLEAN":    {"color": {"background": "#10b981", "border": "#059669"},
                 "font":  {"color": "#ffffff"},
                 "shape": "dot", "size": 12},
    "UNKNOWN":  {"color": {"background": "#3f3f46", "border": "#52525b"},
                 "font":  {"color": "#a1a1aa"},
                 "shape": "dot", "size": 10},
}

_TYPE_SHAPE: dict[str, str] = {
    "ip":     "dot",
    "domain": "diamond",
    "hash":   "square",
}


@dataclass
class IOCNode:
    ioc: str
    ioc_type: str
    depth: int = 0
    investigated: bool = False
    severity: str | None = None
    confidence: int | None = None
    mitre_techniques: list[str] = field(default_factory=list)


class ThreatGraph:
    def __init__(self) -> None:
        self.nodes: Dict[str, IOCNode] = {}
        self.edges: list[dict] = []

    def add_node(self, node: IOCNode) -> None:
        self.nodes[node.ioc] = node

    def add_edge(self, source: str, target: str, relationship: str) -> None:
        self.edges.append({"from": source, "to": target, "label": relationship})

    def to_vis_json(self) -> dict:
        vis_nodes = []
        for node in self.nodes.values():
            sev = (node.severity or "UNKNOWN").upper()
            style = dict(_SEV_STYLE.get(sev, _SEV_STYLE["UNKNOWN"]))
            # Override shape based on IOC type
            shape = _TYPE_SHAPE.get(node.ioc_type, "dot")
            style["shape"] = shape
            vis_nodes.append({
                "id":       node.ioc,
                "label":    node.ioc,
                "group":    node.ioc_type,
                "severity": sev,
                "ioc_type": node.ioc_type,
                "title":    self._node_title(node),
                **style,
            })

        vis_edges = []
        for edge in self.edges:
            vis_edges.append({
                "from":  edge["from"],
                "to":    edge["to"],
                "label": edge["label"],
                "color": {"color": "#52525b", "highlight": "#ff2a55"},
                "width": 1.5,
                "dashes": edge["label"] in ("passive_dns", "same_subnet"),
            })

        return {"nodes": vis_nodes, "edges": vis_edges}

    def _node_title(self, node: IOCNode) -> str:
        parts = [
            f"IOC: {node.ioc}",
            f"Type: {node.ioc_type}",
            f"Depth: {node.depth}",
        ]
        if node.severity:
            parts.append(f"Severity: {node.severity}")
        if node.confidence is not None:
            parts.append(f"Confidence: {node.confidence}%")
        if node.mitre_techniques:
            parts.append("MITRE: " + ", ".join(node.mitre_techniques[:3]))
        return "\n".join(parts)

    def get_campaign_summary(self) -> dict:
        depths    = [node.depth for node in self.nodes.values()] or [0]
        ips       = [n.ioc for n in self.nodes.values() if n.ioc_type == "ip"]
        domains   = [n.ioc for n in self.nodes.values() if n.ioc_type == "domain"]
        hashes    = [n.ioc for n in self.nodes.values() if n.ioc_type == "hash"]
        crit_high = sum(1 for n in self.nodes.values() if n.severity in ("CRITICAL", "HIGH"))
        return {
            "total_iocs":     len(self.nodes),
            "depth_reached":  max(depths),
            "investigated":   sum(1 for n in self.nodes.values() if n.investigated),
            "critical_high":  crit_high,
            "high_or_critical": crit_high,   # backwards compat alias
            "ips":            ips,
            "domains":        domains,
            "hashes":         hashes,
        }
