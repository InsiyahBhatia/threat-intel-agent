"""
Notification Engine — dispatches alerts to Slack and Email (SMTP)
when CRITICAL or HIGH severity IOCs are detected.
"""

import asyncio
import json
import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import httpx
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")
NOTIFICATION_CONFIG_FILE = ROOT_DIR / "data" / "notification_config.json"


def _load_notification_config() -> dict:  # noqa: PLR0912
    cfg = {
        "email": {
            "enabled": False, "smtp_host": "", "smtp_port": 587,
            "smtp_user": "", "smtp_pass": "", "from_addr": "", "to_addrs": []
        },
        "slack": {"enabled": False, "webhook_url": ""},
        "teams": {"enabled": False, "webhook_url": ""},
    }
    if NOTIFICATION_CONFIG_FILE.exists():
        try:
            file_cfg = json.loads(NOTIFICATION_CONFIG_FILE.read_text())
            for key in ("slack", "teams"):
                if key in file_cfg:
                    cfg[key].update(
                        {k: v for k, v in file_cfg[key].items()
                         if k != "webhook_url" or not os.getenv(f"{key.upper()}_WEBHOOK_URL")}
                    )
            if "email" in file_cfg:
                cfg["email"].update(
                    {k: v for k, v in file_cfg["email"].items()
                     if k not in ("smtp_pass", "smtp_user")}
                )
        except Exception as e:
            logger.warning(f"Corrupt notification config: {e}")

    if os.getenv("SLACK_WEBHOOK_URL"):
        cfg["slack"]["webhook_url"] = os.getenv("SLACK_WEBHOOK_URL")
        cfg["slack"]["enabled"] = True
    if os.getenv("TEAMS_WEBHOOK_URL"):
        cfg["teams"]["webhook_url"] = os.getenv("TEAMS_WEBHOOK_URL")
        cfg["teams"]["enabled"] = True
    if os.getenv("SMTP_HOST"):
        cfg["email"]["smtp_host"] = os.getenv("SMTP_HOST")
        cfg["email"]["enabled"] = True
    if os.getenv("SMTP_PORT"):
        cfg["email"]["smtp_port"] = int(os.getenv("SMTP_PORT"))
    if os.getenv("SMTP_USER"):
        cfg["email"]["smtp_user"] = os.getenv("SMTP_USER")
    if os.getenv("SMTP_PASS"):
        cfg["email"]["smtp_pass"] = os.getenv("SMTP_PASS")
    if os.getenv("SMTP_FROM"):
        cfg["email"]["from_addr"] = os.getenv("SMTP_FROM")
    if os.getenv("SMTP_TO"):
        cfg["email"]["to_addrs"] = [a.strip() for a in os.getenv("SMTP_TO").split(",") if a.strip()]

    return cfg


def _save_notification_config(cfg: dict) -> None:
    safe = {
        "slack": {"enabled": cfg.get("slack", {}).get("enabled", False)},
        "teams": {"enabled": cfg.get("teams", {}).get("enabled", False)},
        "email": {
            "enabled": cfg.get("email", {}).get("enabled", False),
            "smtp_host": cfg.get("email", {}).get("smtp_host", ""),
            "smtp_port": cfg.get("email", {}).get("smtp_port", 587),
            "from_addr": cfg.get("email", {}).get("from_addr", ""),
            "to_addrs": cfg.get("email", {}).get("to_addrs", []),
        },
    }
    NOTIFICATION_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    NOTIFICATION_CONFIG_FILE.write_text(json.dumps(safe, indent=2))


def _severity_emoji(sev: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "LOW": "🟢", "CLEAN": "✅"}.get(sev, "⬜")


def _build_alert_text(ioc: str, severity: str, report: dict) -> str:
    emoji = _severity_emoji(severity)
    sev_label = f"{emoji} **{severity}**"
    lines = [
        f"{sev_label} Threat Detected — IOC: `{ioc}`",
        f"*Type:* {report.get('ioc_type', 'unknown')}",
        f"*Category:* {report.get('threat_category', 'Unknown')}",
    ]
    if report.get("ml_verdict"):
        lines.append(f"*ML Verdict:* {report.get('ml_verdict')} ({report.get('ml_confidence', 0)}% conf)")
    if report.get("risk_score"):
        lines.append(f"*Risk Score:* {report.get('risk_score'):.4f}")
    if report.get("summary"):
        lines.append(f"*Summary:* {report.get('summary')[:200]}")
    if report.get("mitre_techniques"):
        techniques = report.get("mitre_techniques", [])
        technique_str = ", ".join(t.get("technique_id", "") for t in techniques[:5])
        lines.append(f"*MITRE ATT&CK:* {technique_str}")
    if report.get("recommended_actions"):
        lines.append(f"*Recommended Action:* {report.get('recommended_actions', [])[0]}")
    return "\n".join(lines)


def _build_html_body(ioc: str, severity: str, report: dict) -> str:
    emoji = _severity_emoji(severity)
    sev_color = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "LOW": "#28a745", "CLEAN": "#28a745"}.get(severity, "#6c757d")

    mitre_rows = ""
    for t in report.get("mitre_techniques", [])[:5]:
        mitre_rows += f"<tr><td>{t.get('technique_id','')}</td><td>{t.get('name','')}</td><td>{t.get('tactic','')}</td></tr>"

    action_items = ""
    for action in report.get("recommended_actions", [])[:4]:
        action_items += f"<li>{action}</li>"

    return f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <div style="background: {sev_color}; color: white; padding: 16px 24px; border-radius: 8px 8px 0 0;">
        <h2 style="margin:0;">{emoji} Threat Intel Alert — {severity}</h2>
        <p style="margin: 8px 0 0;">IOC: <strong>{ioc}</strong></p>
      </div>
      <div style="border: 1px solid #ddd; border-top: none; padding: 20px; border-radius: 0 0 8px 8px;">
        <table style="width: 100%; border-collapse: collapse; margin-bottom: 16px;">
          <tr><td style="padding: 4px 0; color: #666; width: 120px;">Type</td><td>{report.get('ioc_type', 'unknown')}</td></tr>
          <tr><td style="padding: 4px 0; color: #666;">Category</td><td>{report.get('threat_category', 'Unknown')}</td></tr>
          <tr><td style="padding: 4px 0; color: #666;">Risk Score</td><td>{report.get('risk_score', 0):.4f}</td></tr>
          <tr><td style="padding: 4px 0; color: #666;">ML Verdict</td><td>{report.get('ml_verdict', 'N/A')} ({report.get('ml_confidence', 0)}%)</td></tr>
        </table>
        <p style="color: #333; line-height: 1.5;">{report.get('summary', 'No summary available.')}</p>
        <h3 style="color: #333; border-bottom: 2px solid {sev_color}; padding-bottom: 4px;">MITRE ATT&CK Techniques</h3>
        <table style="width: 100%; border-collapse: collapse; margin-bottom: 16px;">
          <tr style="background: #f8f9fa;"><th style="padding: 6px 8px; text-align: left;">ID</th><th style="padding: 6px 8px; text-align: left;">Name</th><th style="padding: 6px 8px; text-align: left;">Tactic</th></tr>
          {mitre_rows or '<tr><td colspan="3">None detected</td></tr>'}
        </table>
        <h3 style="color: #333; border-bottom: 2px solid {sev_color}; padding-bottom: 4px;">Recommended Actions</h3>
        <ol style="color: #444;">{action_items or '<li>No specific actions recommended</li>'}</ol>
      </div>
      <p style="color: #999; font-size: 12px; margin-top: 16px;">
        Sent by Threat Intelligence Agent • {report.get('timestamp', '')}
      </p>
    </body>
    </html>
    """


async def send_slack_alert(ioc: str, severity: str, report: dict) -> tuple[bool, str]:
    cfg = _load_notification_config()
    webhook_url = cfg.get("slack", {}).get("webhook_url")
    if not webhook_url:
        return False, "Slack webhook not configured"

    text = _build_alert_text(ioc, severity, report)
    payload = {
        "text": text,
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"🚨 Threat Alert — {severity}", "emoji": True}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*IOC:*\n`{ioc}`"},
                    {"type": "mrkdwn", "text": f"*Type:*\n{report.get('ioc_type', 'unknown')}"},
                    {"type": "mrkdwn", "text": f"*Category:*\n{report.get('threat_category', 'Unknown')}"},
                    {"type": "mrkdwn", "text": f"*Risk Score:*\n{report.get('risk_score', 0):.4f}"},
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Summary:*\n{report.get('summary', 'N/A')[:300]}"}
            }
        ],
        "attachments": [{
            "color": "#dc3545" if severity == "CRITICAL" else "#fd7e14",
            "fields": [
                {"title": "ML Verdict", "value": f"{report.get('ml_verdict', 'N/A')} ({report.get('ml_confidence', 0)}%)", "short": True},
                {"title": "MITRE ATT&CK", "value": ", ".join(t.get("technique_id","") for t in report.get("mitre_techniques",[])[:5]) or "None", "short": True},
            ]
        }]
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code < 400:
                logger.info(f"Slack alert sent for {ioc} ({severity})")
                return True, "sent"
            return False, f"HTTP {resp.status_code}: {resp.text[:100]}"
    except Exception as e:
        logger.error(f"Slack alert failed for {ioc}: {e}")
        return False, str(e)


def send_email_alert(ioc: str, severity: str, report: dict) -> tuple[bool, str]:
    cfg = _load_notification_config()
    email_cfg = cfg.get("email", {})
    if not email_cfg.get("enabled"):
        return False, "Email notifications not enabled"
    if not email_cfg.get("smtp_host") or not email_cfg.get("from_addr") or not email_cfg.get("to_addrs"):
        return False, "SMTP not fully configured"

    subject = f"[{severity}] Threat Alert — {ioc} ({report.get('ioc_type', 'unknown')})"
    html_body = _build_html_body(ioc, severity, report)

    text_body = _build_alert_text(ioc, severity, report)

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = email_cfg["from_addr"]
        msg["To"] = ", ".join(email_cfg["to_addrs"])
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        smtp_cfg = email_cfg
        with smtplib.SMTP(smtp_cfg["smtp_host"], smtp_cfg["smtp_port"], timeout=15) as server:
            if smtp_cfg.get("smtp_user"):
                server.starttls()
                server.login(smtp_cfg["smtp_user"], smtp_cfg["smtp_pass"])
            server.send_message(msg)

        logger.info(f"Email alert sent for {ioc} ({severity})")
        return True, "sent"
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP auth failed for {ioc}: {e}")
        return False, f"SMTP auth failed: {e}"
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error for {ioc}: {e}")
        return False, f"SMTP error: {e}"
    except Exception as e:
        logger.error(f"Email alert failed for {ioc}: {e}")
        return False, str(e)


async def send_notifications(ioc: str, severity: str, report: dict) -> dict:
    results = {"slack": None, "email": None}

    if severity in ("CRITICAL", "HIGH"):
        email_coro = asyncio.to_thread(send_email_alert, ioc, severity, report)
        slack_coro = send_slack_alert(ioc, severity, report)
        slack_result, email_result = await asyncio.gather(slack_coro, email_coro)
        slack_ok, slack_msg = slack_result
        email_ok, email_msg = email_result
        results["slack"] = {"status": "sent" if slack_ok else "failed", "detail": slack_msg}
        results["email"] = {"status": "sent" if email_ok else "failed", "detail": email_msg}

    return results
