"""Browser extension chat endpoint with IOC investigation and hunt integration."""

import json

from fastapi import APIRouter

from api.models import ChatRequest
from utils.classifier import extract_ioc_from_text

router = APIRouter(tags=["chat"])


def is_hunt_request(text: str) -> bool:
    keywords = ["hunt", "expand", "infrastructure", "campaign", "related", "find more", "trace"]
    return any(k in text.lower() for k in keywords)


@router.post("/api/chat")
async def chat_endpoint(req: ChatRequest):  # noqa: PLR0915
    import os

    from agent.hunter import hunt

    message = req.message.strip()
    history = req.history[-8:]

    ioc = extract_ioc_from_text(message)
    hunting = is_hunt_request(message) and ioc

    if hunting:
        try:
            hunt_log = []
            graph_data = None

            async def progress(msg, graph):
                hunt_log.append(msg)
                nonlocal graph_data
                graph_data = graph.to_vis_json()

            graph = await hunt(ioc, progress_callback=progress, max_depth=3, max_nodes=25)
            summary = graph.get_campaign_summary()
            graph_data = graph.to_vis_json()

            campaign_block = f"|||CAMPAIGN:{json.dumps(summary)}|||"

            verdict_blocks = ""
            critical_high_nodes = []
            for node in list(graph.nodes.values())[:5]:
                if node.severity in ("CRITICAL", "HIGH") and node.investigated:
                    v = {
                        "ioc": node.ioc,
                        "ioc_type": node.ioc_type,
                        "severity": node.severity,
                        "confidence": node.confidence or 0,
                        "mitre_techniques": node.mitre_techniques[:3],
                    }
                    verdict_blocks += f"|||VERDICT:{json.dumps(v)}|||\n"
                    critical_high_nodes.append((node.ioc, node.severity))

            total = summary["total_iocs"]
            crit = summary["critical_high"]
            depth = summary["depth_reached"]

            from api.dependencies import _notify_hunt_results, _run_bg
            _run_bg(_notify_hunt_results(critical_high_nodes))

            response_text = (
                f"Autonomous hunt complete. Starting from `{ioc}`, I traced the infrastructure "
                f"across **{depth} hops** and mapped **{total} IOCs** — **{crit} flagged as CRITICAL or HIGH**.\n\n"
                f"{campaign_block}\n\n"
                f"{verdict_blocks}"
                f"Want me to generate firewall block rules for all {total} IOCs?\n"
                f"Type \"block rules for {ioc}\" to export iptables/pfSense rules."
            )

            return {
                "response": response_text,
                "graph": graph_data,
                "hunt_log": hunt_log,
                "hunt_complete": True,
                "campaign_summary": summary,
            }
        except Exception as e:
            return {
                "response": f"Hunt failed: {e}. Try again or investigate the IOC directly.",
                "graph": None,
                "hunt_log": [],
                "hunt_complete": False,
            }

    if ioc:
        from agent.orchestrator import investigate

        try:
            result = await investigate(ioc)
            report = result.get("report", {})

            verdict = {
                "ioc": ioc,
                "ioc_type": result.get("ioc_type", ""),
                "severity": report.get("severity", "UNKNOWN"),
                "confidence": report.get("confidence_score", 0),
                "mitre_techniques": report.get("mitre_techniques", [])[:4],
            }
            verdict_block = f"|||VERDICT:{json.dumps(verdict)}|||"

            sev = report.get("severity", "UNKNOWN")
            cat = report.get("threat_category", "Unknown")
            ml_v = report.get("ml_verdict")
            ml_c = report.get("ml_confidence")
            actions = report.get("recommended_actions", [])[:2]

            parts = [f"**Investigation complete for `{ioc}`**"]
            parts.append(f"*Severity:* {sev}  |  *Category:* {cat}")
            if ml_v:
                parts.append(f"*ML Verdict:* {ml_v} ({ml_c}% confidence)")
            if actions:
                parts.append(f"*Recommendation:* {actions[0]}")
            parts.append(verdict_block)
            parts.append(f"\nType \"hunt {ioc}\" to trace related infrastructure.")

            return {
                "response": "\n\n".join(parts),
                "graph": None,
                "hunt_log": [],
                "hunt_complete": False,
            }
        except Exception as e:
            return {
                "response": f"Investigation failed: {e}. Try again later.",
                "graph": None,
                "hunt_log": [],
                "hunt_complete": False,
            }

    try:
        from groq import Groq

        client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        groq_messages = [
            {"role": "system", "content": (
                "You are a threat intelligence analyst assistant. "
                "You help SOC analysts investigate IOCs (IPs, domains, file hashes), "
                "interpret VirusTotal/Shodan/AbuseIPDB results, map to MITRE ATT&CK techniques, "
                "and generate firewall block rules. "
                "Be concise and technical. When the user gives you an IOC, investigate it. "
                "Format structured verdicts as |||VERDICT:{json}||| blocks."
            )}
        ]
        for turn in history:
            groq_messages.append({"role": turn["role"], "content": turn["content"]})
        groq_messages.append({"role": "user", "content": message})
        reply = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=groq_messages,
            temperature=0.3,
        ).choices[0].message.content or ""

    except Exception as e:
        reply = (
            "I'm your threat intelligence analyst. Share an IP address, domain, or file hash "
            "and I'll investigate it using VirusTotal, Shodan, AbuseIPDB, and my ML classifier.\n\n"
            f"(LLM unavailable: {e})"
        )

    return {
        "response": reply,
        "graph": None,
        "hunt_log": [],
        "hunt_complete": False,
    }
