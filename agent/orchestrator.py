"""
Threat Intelligence Agent - Core Orchestrator.

Default pipeline:
1. classify the IOC locally
2. call configured enrichment tools in parallel
3. map observed behavior to MITRE ATT&CK
4. score evidence with the trainable local risk model

No external LLM is used by this pipeline.
"""

import asyncio
import contextlib
import functools
import logging
import os
import re
import time
from pathlib import Path

logger = logging.getLogger(__name__)

from dotenv import load_dotenv  # noqa: E402

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

_DEMO_MODE = os.getenv("TIA_DEMO_MODE", "").lower() in ("true", "1", "yes")

_HAS_API_KEYS = any(os.getenv(k) for k in ("VIRUSTOTAL_API_KEY", "SHODAN_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY"))
if not _DEMO_MODE and not _HAS_API_KEYS:
    logger.warning("No API keys found — enabling demo mode. Set VIRUSTOTAL_API_KEY, SHODAN_API_KEY, ABUSEIPDB_API_KEY, or OTX_API_KEY in .env for live enrichment.")
    _DEMO_MODE = True

from models.report import ThreatReport  # noqa: E402
from tools.abuseipdb import _query_abuseipdb, abuseipdb_tool  # noqa: E402
from tools.mitre_mapper import mitre_mapper_tool  # noqa: E402
from tools.ml_classifier import predict_ml_severity  # noqa: E402
from tools.otx import _query_otx, otx_tool  # noqa: E402
from tools.shodan import _query_shodan, shodan_tool  # noqa: E402
from tools.virustotal import _query_domain, _query_hash, _query_ip, virustotal_tool  # noqa: E402
from utils.classifier import classify_ioc  # noqa: E402
from utils.ml_features import extract_ml_features  # noqa: E402
from utils.risk_model import predict_risk  # noqa: E402

# Severity levels in order (used for disagreement distance)
_SEVERITY_RANK = {"CLEAN": 0, "LOW": 1, "HIGH": 2, "CRITICAL": 3}


DEMO_FIXTURES = {
    "185.220.101.1": """
[Offline Demo Mode] Feed API keys are not configured, so this report uses bundled sample intelligence for UI and workflow demonstration.
[VirusTotal] IP: 185.220.101.1
  Detection ratio: 47/94 engines flagged as malicious
  Suspicious votes: 4
  tags: tor, proxy, abuse
[Shodan] IP: 185.220.101.1
  Open ports: 22, 80, 443
  Tags: tor
  Known CVEs: None
[AbuseIPDB] IP: 185.220.101.1
  Abuse Confidence Score: 100/100
  Total abuse reports (last 90 days): 2847 from 311 users
  Is Tor exit node: True
  Abuse categories reported: Open Proxy, SSH, Brute-Force
[MITRE ATT&CK Mapper] Techniques matched:
  [T1090.003] Command and Control -> Proxy: Multi-hop Proxy
  [T1110.001] Credential Access -> Brute Force: Password Guessing
""",
    "8.8.8.8": """
[Offline Demo Mode] Feed API keys are not configured, so this report uses bundled sample intelligence for UI and workflow demonstration.
[VirusTotal] IP: 8.8.8.8
  Detection ratio: 0/94 engines flagged as malicious
  Suspicious votes: 0
  tags: public-dns
[AbuseIPDB] IP: 8.8.8.8
  Abuse Confidence Score: 0/100
  Total abuse reports (last 90 days): 0 from 0 users
  LOW RISK: Few or no abuse reports found.
[MITRE ATT&CK Mapper] No matching techniques found from the provided context.
clean no malicious
""",
    "d41d8cd98f00b204e9800998ecf8427e": """
[Offline Demo Mode] Feed API keys are not configured, so this report uses bundled sample intelligence for UI and workflow demonstration.
[VirusTotal] FileHash: d41d8cd98f00b204e9800998ecf8427e
  Detection ratio: 0/72 engines flagged as malicious
  Suspicious votes: 0
  file_type: empty file
  clean no malicious
""",
    "malware-c2.ru": """
[Offline Demo Mode] Feed API keys are not configured, so this report uses bundled sample intelligence for UI and workflow demonstration.
[VirusTotal] Domain: malware-c2.ru
  Detection ratio: 31/88 engines flagged as malicious
  Suspicious votes: 8
  tags: malware, c2, phishing
[MITRE ATT&CK Mapper] Techniques matched:
  [T1071] Command and Control -> Application Layer Protocol
  [T1566] Initial Access -> Phishing
""",
}


def _extract_mitre_techniques(text: str) -> list[dict]:
    techniques = []
    seen = set()
    pattern = re.compile(
        r"\[(T\d{4}(?:\.\d{3})?)\]\s+([^\n]+?)\s+(?:->|→|-)\s+([^\n]+)",
        re.IGNORECASE,
    )
    for match in pattern.finditer(text):
        technique_id, tactic, name = match.groups()
        if technique_id in seen:
            continue
        seen.add(technique_id)
        techniques.append(
            {
                "technique_id": technique_id,
                "tactic": tactic.strip(),
                "name": name.strip(),
                "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
            }
        )
    return techniques


def _recommended_actions(severity: str, text: str) -> list[str]:
    actions = [
        "Preserve raw enrichment evidence and attach this report to the investigation case.",
        "Search recent proxy, DNS, EDR, and firewall logs for this IOC and adjacent indicators.",
    ]
    text_lower = text.lower()

    if severity in {"CRITICAL", "HIGH"}:
        actions.insert(0, "Block the IOC at perimeter, DNS, proxy, and endpoint controls while validation continues.")
        actions.append("Open an incident ticket and triage any internal hosts that communicated with the IOC.")
    if "ssh" in text_lower or "brute" in text_lower:
        actions.append("Review authentication logs for failed login bursts and enforce MFA on exposed services.")
    if "phishing" in text_lower:
        actions.append("Hunt mail telemetry for matching senders, URLs, subjects, and credential-submission events.")
    if "cve-" in text_lower:
        actions.append("Prioritize patch verification for exposed services associated with the listed CVEs.")
    if severity in {"CLEAN", "LOW"}:
        actions.append("Keep the IOC on watchlist monitoring instead of escalating unless new detections appear.")

    return actions[:6]


def _generate_recommended_actions_groq(ioc: str, ioc_type: str, severity: str, confidence: float, evidence: str, mitre_techniques: list, ml_result: dict | None) -> list[str]:
    """Generate context-aware recommended actions using Groq LLM."""
    groq_key = os.getenv("GROQ_API_KEY")
    if not groq_key:
        return _recommended_actions(severity, evidence)

    try:
        from groq import Groq
        client = Groq(api_key=groq_key)

        mitre_summary = ", ".join([f"{t['technique_id']} ({t['name']})" for t in mitre_techniques[:5]])
        ml_info = f"ML verdict: {ml_result.get('severity', 'N/A')} (conf: {ml_result.get('confidence', 'N/A')}%)" if ml_result else "ML: unavailable"

        prompt = f"""You are a senior SOC analyst. Generate 5-6 specific, actionable recommended steps for investigating this IOC.

IOC: {ioc} ({ioc_type})
Severity: {severity} (confidence: {confidence}%)
{ml_info}
MITRE ATT&CK: {mitre_summary or "None identified"}
Evidence summary: {evidence[:1500]}

Return ONLY a JSON array of strings, each a concrete recommended action. No markdown, no explanation.
Example: ["Block IOC at perimeter and DNS", "Search firewall logs for connections to this IP", "..."]"""

        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=500,
        )
        content = resp.choices[0].message.content.strip()
        import json
        actions = json.loads(content)
        if isinstance(actions, list) and all(isinstance(a, str) for a in actions):
            return actions[:6]
    except Exception as e:
        logger.warning(f"Groq recommended actions failed: {e}")

    return _recommended_actions(severity, evidence)


def _threat_category(text: str, ioc_type: str) -> str:
    text_lower = text.lower()
    category_map = [
        ("ransomware", "Ransomware"),
        ("phishing", "Phishing"),
        ("credential", "Credential Abuse"),
        ("brute", "Brute Force Infrastructure"),
        ("tor", "Anonymized Proxy Infrastructure"),
        ("proxy", "Proxy Infrastructure"),
        ("c2", "Command and Control"),
        ("malware", "Malware"),
        ("cve-", "Vulnerable Exposed Service"),
    ]
    for needle, label in category_map:
        if needle in text_lower:
            return label
    return {"ip": "Network Indicator", "domain": "Domain Indicator", "hash": "File Indicator"}.get(ioc_type, "Unknown")


def _ml_verdict_block(
    ml: dict,
    logistic_severity: str,
) -> str:
    """Format the ML classifier result as an agent-output text block."""
    sev = ml["severity"]
    conf = ml["confidence"]
    model = ml["model_name"]
    n_feat = ml["feature_count"]

    proba_str = "  ".join(
        f"{cls}={int(p * 100)}%"
        for cls, p in sorted(ml["probabilities"].items(), key=lambda x: -x[1])
    )

    ml_rank  = _SEVERITY_RANK.get(sev, 2)
    log_rank = _SEVERITY_RANK.get(logistic_severity, 2)
    gap = abs(ml_rank - log_rank)

    if gap >= 2:
        verdict_note = (
            "  \u26a0\ufe0f VERDICT CONFLICT: ML and logistic models disagree by "
            f"{gap} severity levels — recommend human review."
        )
    elif gap == 1:
        verdict_note = "  i Minor divergence between ML and logistic verdict (+/-1 level)."
    else:
        verdict_note = "  ✓ ML and logistic verdicts agree."

    return (
        f"[ML Classifier] Severity: {sev} | Confidence: {conf}%\n"
        f"  Model: {model} ({n_feat} features)\n"
        f"  Class probabilities: {proba_str}\n"
        f"{verdict_note}"
    )


def build_structured_report(
    ioc: str,
    ioc_type: str,
    evidence: str,
    ml_result: dict | None = None,
    ml_features_dict: dict | None = None,
) -> dict:
    summary_lines = [
        line.strip(" -")
        for line in evidence.splitlines()
        if line.strip() and not line.strip().startswith(("[", "{", "}"))
    ]
    summary = " ".join(summary_lines[:3]) or "Investigation completed. Review raw output for source-level evidence."

    if ml_result and ml_features_dict:
        has_data = any([
            ml_features_dict.get("has_vt_data", 0),
            ml_features_dict.get("has_abuse_data", 0),
            ml_features_dict.get("has_shodan_data", 0),
        ])
        use_ensemble = has_data
    else:
        use_ensemble = False

    if ml_result and use_ensemble:
        # If ML confidence is very low (<30%) but we have strong risk signals,
        # fall back to the logistic risk model which is better calibrated for clear threats
        ml_conf = ml_result["confidence"]
        strong_signals = (
            ml_features_dict and (
                ml_features_dict.get("abuse_confidence", 0) >= 90 or
                ml_features_dict.get("vt_malicious_ratio", 0) >= 0.15 or
                ml_features_dict.get("abuse_is_tor", 0) or
                ml_features_dict.get("is_tor", 0)
            )
        )
        if ml_conf < 30 and strong_signals:
            logger.warning("ML confidence %d%% below threshold with strong signals — using risk model", ml_conf)
            prediction = predict_risk(evidence, ml_features=ml_features_dict)
            primary_severity = prediction.severity
            primary_confidence = prediction.confidence_score
            risk_score = prediction.risk_score
            risk_features = prediction.features
            model_name = "local-ioc-risk-model (fallback from low-conf ML)"
            model_version = prediction.model_version

            # Safety override: if risk model returns LOW but raw signals are unequivocally malicious,
            # force HIGH severity. This handles cases where feature mapping fails silently.
            abuse_conf = ml_features_dict.get("abuse_confidence", 0)
            vt_mal = ml_features_dict.get("vt_malicious_ratio", 0)
            is_tor = ml_features_dict.get("abuse_is_tor", 0) or ml_features_dict.get("is_tor", 0)
            if primary_severity == "LOW" and abuse_conf >= 90 and (is_tor or vt_mal >= 0.15):
                logger.warning("Risk model returned LOW despite abuse_conf=%d, is_tor=%s, vt_mal=%.3f — overriding to HIGH",
                               abuse_conf, is_tor, vt_mal)
                primary_severity = "HIGH"
                primary_confidence = max(primary_confidence, 75)
        else:
            primary_severity = ml_result["severity"]
            primary_confidence = ml_result["confidence"]
            risk_score = _ensemble_risk_score(ml_result["probabilities"])
            risk_features = ml_features_dict or {}
            model_name = ml_result.get("model_name", "Ensemble(XGB+LGB)")
            model_version = 2
    else:
        has_enrichment = ml_features_dict and any(ml_features_dict.get(k, 0) for k in ("has_vt_data", "has_abuse_data", "has_shodan_data"))
        if ml_features_dict is not None and not has_enrichment:
            primary_severity = "UNKNOWN"
            primary_confidence = 0
            risk_score = 0.0
            risk_features = {}
            model_name = "local-ioc-risk-model"
            model_version = 1
        else:
            prediction = predict_risk(evidence, ml_features=ml_features_dict if has_enrichment else None)
            primary_severity = prediction.severity
            primary_confidence = prediction.confidence_score
            risk_score = prediction.risk_score
            risk_features = prediction.features
            model_name = "local-ioc-risk-model"
            model_version = prediction.model_version

    base = ThreatReport(
        ioc=ioc,
        ioc_type=ioc_type,
        severity=primary_severity,
        confidence_score=primary_confidence,
        summary=summary[:700],
        threat_category=_threat_category(evidence, ioc_type),
        mitre_techniques=_extract_mitre_techniques(evidence),
        recommended_actions=_generate_recommended_actions_groq(
            ioc, ioc_type, primary_severity, primary_confidence, evidence, _extract_mitre_techniques(evidence), ml_result
        ),
        tool_findings=[],
    ).model_dump() | {
        "risk_score": risk_score,
        "risk_features": risk_features,
        "risk_model_version": model_version,
        "model_name": model_name,
    }

    base["ml_verdict"]     = ml_result["severity"] if ml_result else None
    base["ml_confidence"]  = ml_result["confidence"] if ml_result else None
    base["ml_proba"]       = ml_result["probabilities"] if ml_result else None
    base["ml_model_name"]  = ml_result["model_name"] if ml_result else None

    return base


SEVERITY_LEVEL = {"CLEAN": 0.0, "LOW": 0.25, "HIGH": 0.75, "CRITICAL": 1.0}


def _ensemble_risk_score(probabilities: dict) -> float:
    return round(sum(SEVERITY_LEVEL.get(cls, 0.5) * p for cls, p in probabilities.items()), 4)


def _tool_text(name: str, result: str) -> str:
    return result if result.startswith("[") else f"[{name}] {result}"


def _call_tool(name: str, tool_obj, value: str) -> str:
    try:
        return _tool_text(name, tool_obj.invoke(value))
    except Exception:
        return f"[{name}] Request failed"


async def _build_local_evidence(  # noqa: PLR0915
    ioc: str, ioc_type: str
) -> tuple[str, list[dict], dict | None, dict | None]:
    """
    Run all enrichment tools in parallel using asyncio.to_thread and return:
      (evidence_text, intermediate_steps, ml_result, features)
    ml_result is None when the model is not trained yet.
    """
    steps = []
    results: dict[str, str] = {}
    raw_data: dict[str, dict] = {}
    chunks = [
        "[Local Investigator] First-party model pipeline active. No external LLM reasoning was used.",
        f"[Local Classifier] IOC: {ioc}\n  Classified type: {ioc_type}",
    ]

    async def _run_vt():
        raw: dict = {}
        text = ""
        try:
            ioc_clean = ioc.split(":")[0] if re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d+$", ioc) else ioc
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc_clean):
                raw = await asyncio.to_thread(_query_ip, ioc_clean)
            elif re.match(r"^[a-fA-F0-9]{32,64}$", ioc_clean):
                raw = await asyncio.to_thread(_query_hash, ioc_clean)
            else:
                raw = await asyncio.to_thread(_query_domain, ioc_clean)
        except Exception as exc:
            logger.warning("VirusTotal query failed for %s: %s", ioc, exc)
        text = await asyncio.to_thread(_call_tool, "VirusTotal", virustotal_tool, ioc)
        return ("vt_raw", raw, "VirusTotal", text)

    async def _run_shodan():
        raw: dict = {}
        text = f"[Shodan] Skipped: '{ioc}' is not an IP address. Shodan only accepts IPs."
        if ioc_type == "ip":
            with contextlib.suppress(Exception):
                raw = await asyncio.to_thread(_query_shodan, ioc)
            text = await asyncio.to_thread(_call_tool, "Shodan", shodan_tool, ioc)
        return ("shodan_raw", raw, "Shodan", text)

    async def _run_abuse():
        raw: dict = {}
        text = f"[AbuseIPDB] Skipped: '{ioc}' is not an IP address."
        if ioc_type == "ip":
            with contextlib.suppress(Exception):
                raw = await asyncio.to_thread(_query_abuseipdb, ioc)
            text = await asyncio.to_thread(_call_tool, "AbuseIPDB", abuseipdb_tool, ioc)
        return ("abuse_raw", raw, "AbuseIPDB", text)

    async def _run_otx():
        raw: dict = {}
        text = ""
        try:
            raw = await asyncio.to_thread(_query_otx, ioc)
            text = await asyncio.to_thread(_call_tool, "AlienVault OTX", otx_tool, ioc)
        except Exception as exc:
            logger.warning("OTX query failed for %s: %s", ioc, exc)
        return ("otx_raw", raw, "AlienVault OTX", text)

    tool_coros = [_run_vt(), _run_shodan(), _run_abuse(), _run_otx()]
    for coro in asyncio.as_completed(tool_coros):
        try:
            key, raw, tool_name, text = await coro
        except Exception as exc:
            logger.warning("A parallel tool failed for %s: %s", ioc, exc)
            continue
        raw_data[key] = raw
        if key == "otx_raw" and not text:
            continue
        results[tool_name] = text
        steps.append({"tool": tool_name.lower().replace(" ", "_"), "input": ioc, "output": text})

    for tool_name in ["VirusTotal", "Shodan", "AbuseIPDB", "AlienVault OTX"]:
        if tool_name in results:
            chunks.append(results[tool_name])

    # ── MITRE mapping (sync, fast) ─────────────────────────────────────────
    context = "\n".join(chunks)
    mitre = await asyncio.to_thread(_call_tool, "MITRE ATT&CK Mapper", mitre_mapper_tool, context)
    chunks.append(mitre)
    steps.append({"tool": "mitre_mapper", "input": "combined evidence", "output": mitre})

    # ── ML Classifier (sync, CPU-bound) ─────────────────────────────────────
    ml_result: dict | None = None
    features: dict | None = None
    try:
        features = await asyncio.to_thread(extract_ml_features,
            ioc_type,
            raw_data.get("vt_raw", {}),
            raw_data.get("abuse_raw", {}),
            raw_data.get("shodan_raw", {}),
            raw_data.get("otx_raw", {}),
        )
        ml_result = await asyncio.to_thread(predict_ml_severity, features)
    except Exception as e:
        logger.warning("ML classifier failed for %s: %s", ioc, e)

    return "\n\n".join(chunks), steps, ml_result, features


_INVESTIGATE_CACHE: dict[str, tuple[float, dict]] = {}
_INVESTIGATE_CACHE_TTL = int(os.getenv("TIA_CACHE_TTL_SECONDS", "300"))
_INVESTIGATE_CACHE_MAX = int(os.getenv("TIA_CACHE_MAX_ENTRIES", "100"))


async def investigate(ioc: str) -> dict:
    """Investigate an IOC using only the local model pipeline."""
    key = ioc.strip().lower()
    now = time.time()
    cached = _INVESTIGATE_CACHE.get(key)
    if cached and (now - cached[0]) < _INVESTIGATE_CACHE_TTL:
        logger.debug("Cache hit for %s", key)
        return cached[1]

    ioc_type = await asyncio.to_thread(classify_ioc, ioc)

    if _DEMO_MODE and ioc in DEMO_FIXTURES:
        evidence = DEMO_FIXTURES[ioc]
        intermediate_steps = []
        features = None
        ml_result = None
    else:
        evidence, intermediate_steps, ml_result, features = await _build_local_evidence(ioc, ioc_type)

    if ml_result:
        has_enrichment = features and any(features.get(k, 0) for k in ("has_vt_data", "has_abuse_data", "has_shodan_data"))
        logistic_sev = "UNKNOWN"
        if has_enrichment:
            logistic_sev = (await asyncio.to_thread(predict_risk, evidence, ml_features=features)).severity
        ml_block = _ml_verdict_block(ml_result, logistic_sev)
        evidence = evidence + "\n\n" + ml_block

    report = await asyncio.to_thread(build_structured_report, ioc, ioc_type, evidence, ml_result, features)
    result = {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "agent_output": evidence,
        "report": report,
        "ml_features": features,
        "intermediate_steps": intermediate_steps,
        "severity": report.get("severity", "UNKNOWN"),
        "confidence": report.get("confidence_score", 50),
        "summary": report.get("summary", ""),
        "mitre_techniques": report.get("mitre_techniques", []),
    }
    if len(_INVESTIGATE_CACHE) >= _INVESTIGATE_CACHE_MAX:
        oldest = min(_INVESTIGATE_CACHE, key=lambda k: _INVESTIGATE_CACHE[k][0])
        del _INVESTIGATE_CACHE[oldest]
    _INVESTIGATE_CACHE[key] = (time.time(), result)
    return result
