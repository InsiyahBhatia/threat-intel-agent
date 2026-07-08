"""STIX 2.1 and PDF report export endpoints."""

import hashlib
import json
import logging
from datetime import UTC, datetime
from io import BytesIO

from fastapi import APIRouter, HTTPException, Response
from fpdf import FPDF

from api.dependencies import _get_active_workspace
from api.models import PDFExportRequest
from utils.database import search_investigations

logger = logging.getLogger(__name__)
router = APIRouter(tags=["exports"])


@router.get("/api/export/stix")
def export_stix():
    ws = _get_active_workspace()
    iocs = ws.get("iocs", [])

    objects = []
    identity = {
        "type": "identity",
        "id": "identity--" + hashlib.sha256(b"threat-intel-agent").hexdigest()[:36],
        "name": "Threat Intelligence Agent",
        "identity_class": "system",
    }
    objects.append(identity)

    for entry in iocs[-200:]:
        threat_report = entry.get("report", {})
        sev = entry.get("severity", "UNKNOWN")
        obj_id = "indicator--" + hashlib.sha256(entry.get("ioc", "").encode()).hexdigest()[:36]
        indicator = {
            "type": "indicator",
            "id": obj_id,
            "created": entry.get("timestamp", datetime.now(UTC).isoformat()),
            "modified": entry.get("timestamp", datetime.now(UTC).isoformat()),
            "name": f"IOC: {entry.get('ioc', '')}",
            "pattern": f"[{entry.get('ioc_type', 'unknown')}:value = '{entry.get('ioc', '')}']",
            "pattern_type": "stix",
            "valid_from": entry.get("timestamp", datetime.now(UTC).isoformat()),
            "severity": sev,
            "confidence": threat_report.get("confidence_score", 50),
            "description": threat_report.get("summary", ""),
            "labels": [sev.lower(), threat_report.get("threat_category", "unknown").lower().replace(" ", "-")],
            "created_by_ref": identity["id"],
        }
        objects.append(indicator)

        if threat_report.get("mitre_techniques"):
            for t in threat_report["mitre_techniques"][:3]:
                attack_id = t.get("technique_id", "")
                if attack_id:
                    rel_id = "relationship--" + hashlib.sha256((entry.get("ioc", "") + attack_id).encode()).hexdigest()[:36]
                    objects.append({
                        "type": "relationship",
                        "id": rel_id,
                        "relationship_type": "indicates",
                        "source_ref": obj_id,
                        "target_ref": "attack-pattern--" + hashlib.sha256(attack_id.encode()).hexdigest()[:36],
                        "created": entry.get("timestamp", datetime.now(UTC).isoformat()),
                        "modified": entry.get("timestamp", datetime.now(UTC).isoformat()),
                    })

    bundle = {
        "type": "bundle",
        "id": "bundle--" + hashlib.sha256(str(datetime.now(UTC).timestamp()).encode()).hexdigest()[:36],
        "objects": objects,
    }
    return bundle


@router.post("/api/export/pdf")
def export_pdf(req: PDFExportRequest):  # noqa: PLR0915
    results = search_investigations(workspace=req.workspace, search=req.ioc, limit=1)
    if not results:
        raise HTTPException(404, "Investigation not found")
    inv = results[0]
    try:
        report = json.loads(inv.get("report_json", "{}"))
    except Exception:
        report = {}

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 12, "Threat Intelligence Report", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    fields = [
        ("IOC", inv["ioc"]),
        ("Type", inv.get("ioc_type", "")),
        ("Severity", inv.get("severity", "UNKNOWN")),
        ("Threat Category", inv.get("threat_category", "")),
        ("Risk Score", str(inv.get("risk_score", 0))),
        ("Confidence", f'{inv.get("confidence_score", 0):.2f}'),
        ("Investigation Timestamp", inv.get("created_at", "")),
    ]
    for label, value in fields:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, label, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 7, value or "")
        pdf.ln(1)

    summary = inv.get("summary", "")
    if summary:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, "Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 7, summary)
        pdf.ln(2)

    techniques = report.get("mitre_techniques", [])
    if techniques:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, "MITRE ATT&CK Techniques", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "B", 9)
        col_w = [20, 100, 60]
        pdf.cell(col_w[0], 7, "ID", border=1)
        pdf.cell(col_w[1], 7, "Name", border=1)
        pdf.cell(col_w[2], 7, "Tactic", border=1)
        pdf.ln()
        pdf.set_font("Helvetica", "", 9)
        for t in techniques:
            tid = t.get("technique_id", "") or ""
            name = t.get("name", "") or ""
            tactic = t.get("tactic", "") or ""
            pdf.cell(col_w[0], 6, tid, border=1)
            pdf.cell(col_w[1], 6, name, border=1)
            pdf.cell(col_w[2], 6, tactic, border=1)
            pdf.ln()
        pdf.ln(2)

    actions = report.get("recommended_actions", [])
    if actions:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, "Recommended Actions", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for i, a in enumerate(actions, 1):
            pdf.multi_cell(0, 7, f"{i}. {a}")
            pdf.ln(1)

    buf = BytesIO()
    pdf.output(buf)
    buf.seek(0)
    return Response(
        content=buf.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="tia-report-{inv["ioc"]}.pdf"'},
    )
