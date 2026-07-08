"""
MITRE ATT&CK Mapper Tool — maps observed IOC behaviors to ATT&CK techniques.
Uses a curated lookup table + LLM reasoning; no external API required.
"""

from utils.decorators import tool

# Curated mapping: observable signals -> ATT&CK techniques
# Format: signal_keyword -> [(TID, Tactic, Technique Name, Description)]
SIGNAL_MAP = {
    # Network / Infrastructure
    "port_scan": [("T1595.001", "Reconnaissance", "Active Scanning: Scanning IP Blocks",
                   "Adversaries scan victim IP ranges to gather info.")],
    "ssh_brute": [("T1110.001", "Credential Access", "Brute Force: Password Guessing",
                   "Repeated SSH authentication attempts.")],
    "smb_brute": [("T1110.001", "Credential Access", "Brute Force: Password Guessing",
                   "Repeated SMB/NTLM authentication attempts.")],
    "rdp": [("T1021.001", "Lateral Movement", "Remote Services: Remote Desktop Protocol",
             "Adversaries use RDP for lateral movement.")],
    "open_proxy": [("T1090", "Command and Control", "Proxy",
                    "Adversaries use proxies to route C2 traffic.")],
    "tor": [("T1090.003", "Command and Control", "Proxy: Multi-hop Proxy",
             "Use of Tor network to anonymize C2.")],
    "c2": [("T1071", "Command and Control", "Application Layer Protocol",
            "C2 communication over standard application protocols.")],
    "ddos": [("T1498", "Impact", "Network Denial of Service",
              "Flood attacks against network infrastructure.")],

    # Malware / File
    "trojan": [("T1204", "Execution", "User Execution",
                "Malicious file executed by user action.")],
    "ransomware": [
        ("T1486", "Impact", "Data Encrypted for Impact", "Files encrypted for ransom."),
        ("T1490", "Impact", "Inhibit System Recovery", "Shadow copies / backups deleted."),
    ],
    "dropper": [("T1105", "Command and Control", "Ingress Tool Transfer",
                 "Malware downloads additional payloads.")],
    "keylogger": [("T1056.001", "Collection", "Input Capture: Keylogging",
                   "Records keystrokes to harvest credentials.")],
    "infostealer": [("T1555", "Credential Access", "Credentials from Password Stores",
                     "Steals stored credentials from browsers/vaults.")],
    "persistence": [("T1547", "Persistence", "Boot or Logon Autostart Execution",
                     "Malware establishes persistence via startup locations.")],

    # Web / Phishing
    "phishing": [("T1566", "Initial Access", "Phishing",
                  "Deceptive emails or pages to steal credentials.")],
    "sql_injection": [("T1190", "Initial Access", "Exploit Public-Facing Application",
                       "SQL injection against web applications.")],
    "web_shell": [("T1505.003", "Persistence", "Server Software Component: Web Shell",
                   "Web shell uploaded for persistent remote access.")],
    "credential_harvesting": [("T1078", "Initial Access", "Valid Accounts",
                                "Use of stolen valid credentials.")],

    # OSINT / Recon
    "shodan": [("T1596", "Reconnaissance", "Search Open Technical Databases",
                "Adversaries search Shodan-like databases for exposed assets.")],
    "dns_recon": [("T1590.002", "Reconnaissance", "Gather Victim Network Info: DNS",
                   "DNS enumeration of target infrastructure.")],
}


def extract_signals(context: str) -> list[str]:
    """Extract matching signal keywords from freeform context text."""
    context_lower = context.lower()
    matched = []
    for signal in SIGNAL_MAP:
        keyword = signal.replace("_", " ")
        if keyword in context_lower or signal in context_lower:
            matched.append(signal)
    return matched


@tool
def mitre_mapper_tool(context: str) -> str:
    """
    Map observed threat behaviors to MITRE ATT&CK techniques.
    Provide a description of what was observed (e.g., 'SSH brute force attempts,
    open proxy, port scan detected'). Returns matching ATT&CK technique IDs,
    tactics, and descriptions.
    Input: a plain-text description of observed behaviors or IOC findings.
    """
    signals = extract_signals(context)

    if not signals:
        return (
            "[MITRE ATT&CK Mapper] No matching techniques found from the provided context.\n"
            f"Context received: {context[:200]}\n"
            "Tip: Include keywords like 'brute force', 'port scan', 'phishing', "
            "'ransomware', 'tor', 'c2', 'dropper', etc."
        )

    output = "[MITRE ATT&CK Mapper] Techniques matched:\n\n"
    seen_tids = set()

    for signal in signals:
        techniques = SIGNAL_MAP[signal]
        for tid, tactic, name, desc in techniques:
            if tid in seen_tids:
                continue
            seen_tids.add(tid)
            output += f"  [{tid}] {tactic} → {name}\n"
            output += f"    Signal: '{signal.replace('_', ' ')}'\n"
            output += f"    Description: {desc}\n"
            output += f"    ATT&CK URL: https://attack.mitre.org/techniques/{tid.replace('.', '/')}/\n\n"

    output += f"  Total techniques matched: {len(seen_tids)}\n"
    output += f"  Tactics involved: {', '.join(set(tactic for s in signals for _, tactic, _, _ in SIGNAL_MAP[s]))}\n"

    return output
