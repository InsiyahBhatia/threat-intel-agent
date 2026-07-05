"""
Train the local IOC risk model.

Usage:
    python tools/train_risk_model.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from utils.risk_model import MODEL_PATH, save_model, train_model


TRAINING_RECORDS = [
    # ── HIGH / CRITICAL ──────────────────────────────────────────────────────
    {
        "label": 1,
        "text": """
        [VirusTotal] IP: 185.220.101.1
          Detection ratio: 47/94 engines flagged as malicious
          Suspicious votes: 4
        [Shodan] Tags: tor, proxy
        [AbuseIPDB] Abuse Confidence Score: 100/100
          Total abuse reports (last 90 days): 2847 from 311 users
          Is Tor exit node: True
          Abuse categories reported: Open Proxy, SSH, Brute-Force
        [MITRE ATT&CK Mapper] T1090.003, T1110.001
        """,
    },
    {
        "label": 1,
        "text": """
        [VirusTotal] Domain: malware-c2.ru
          Detection ratio: 31/88 engines flagged as malicious
          Suspicious votes: 8
          tags: malware, c2, trojan, phishing
        [MITRE ATT&CK Mapper] c2, phishing, credential harvesting
        """,
    },
    {
        "label": 1,
        "text": """
        [VirusTotal] FileHash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
          Detection ratio: 62/71 engines flagged as malicious
          Suspicious votes: 2
          file_type: Win32 EXE
          tags: ransomware, dropper, infostealer
        """,
    },
    {
        "label": 1,
        "text": """
        [Shodan] IP: 203.0.113.22
          Open ports: 22, 3389, 445
          Tags: malware, c2
          Known CVEs: CVE-2024-3094, CVE-2023-3519, CVE-2022-1388
        [AbuseIPDB] Abuse Confidence Score: 77/100
          Total abuse reports (last 90 days): 328 from 74 users
          Abuse categories reported: SSH, Brute-Force, Port Scan
        """,
    },
    {
        "label": 1,
        "text": """
        [VirusTotal] IP: 45.33.32.156
          Detection ratio: 18/94 engines flagged as malicious
          Suspicious votes: 3
          tags: botnet, c2
        [AbuseIPDB] Abuse Confidence Score: 65/100
          Total abuse reports (last 90 days): 142 from 38 users
          Abuse categories reported: Brute-Force, Port Scan
        """,
    },
    {
        "label": 1,
        "text": """
        [VirusTotal] FileHash: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
          Detection ratio: 45/72 engines flagged as malicious
          Suspicious votes: 6
          file_type: Win32 DLL
          tags: malware, infostealer, credential
        """,
    },
    {
        "label": 1,
        "text": """
        [Shodan] IP: 192.0.2.55
          Open ports: 22, 80, 443, 3389, 8080
          Tags: vpn, proxy
          Known CVEs: CVE-2021-3449
        [AbuseIPDB] Abuse Confidence Score: 82/100
          Total abuse reports (last 90 days): 415 from 92 users
          Abuse categories reported: Open Proxy, Bad Web Bot
        """,
    },
    # ── CLEAN / LOW ──────────────────────────────────────────────────────────
    {
        "label": 0,
        "text": """
        [VirusTotal] IP: 8.8.8.8
          Detection ratio: 0/94 engines flagged as malicious
          Suspicious votes: 0
          tags: public-dns
        [AbuseIPDB] Abuse Confidence Score: 0/100
          Total abuse reports (last 90 days): 0 from 0 users
          LOW RISK: Few or no abuse reports found.
        """,
    },
    {
        "label": 0,
        "text": """
        [VirusTotal] Domain: google.com
          Detection ratio: 0/91 engines flagged as malicious
          Suspicious votes: 0
          categories: search engines, business
        [MITRE ATT&CK Mapper] No matching techniques found
        clean no malicious
        """,
    },
    {
        "label": 0,
        "text": """
        [VirusTotal] FileHash: d41d8cd98f00b204e9800998ecf8427e
          Detection ratio: 0/72 engines flagged as malicious
          Suspicious votes: 0
          file_type: empty file
          clean benign empty file
        """,
    },
    {
        "label": 0,
        "text": """
        [Shodan] IP: 192.0.2.10
          No data found for IP
        [AbuseIPDB] Abuse Confidence Score: 6/100
          Total abuse reports (last 90 days): 1 from 1 users
          LOW RISK: Few or no abuse reports found.
        """,
    },
    {
        "label": 0,
        "text": """
        [VirusTotal] IP: 1.1.1.1
          Detection ratio: 0/94 engines flagged as malicious
          Suspicious votes: 1
          tags: public-dns, cloudflare
        [MITRE ATT&CK Mapper] No matching techniques found
        """,
    },
    {
        "label": 0,
        "text": """
        [VirusTotal] Domain: github.com
          Detection ratio: 0/92 engines flagged as malicious
          Suspicious votes: 0
          categories: software hosting, development
        [AbuseIPDB] Abuse Confidence Score: 2/100
          Total abuse reports (last 90 days): 3 from 2 users
          LOW RISK: Few or no abuse reports found.
        """,
    },
    {
        "label": 0,
        "text": """
        [VirusTotal] FileHash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
          Detection ratio: 0/72 engines flagged as malicious
          Suspicious votes: 0
          file_type: empty file
          clean harmless
        """,
    },
    # ── BORDERLINE / LOW ─────────────────────────────────────────────────────
    {
        "label": 0,
        "text": """
        [VirusTotal] IP: 198.51.100.15
          Detection ratio: 0/94 engines flagged as malicious
          Suspicious votes: 0
          tags: none
        [AbuseIPDB] Abuse Confidence Score: 15/100
          Total abuse reports (last 90 days): 5 from 3 users
          LOW RISK: Low abuse confidence.
        """,
    },
    {
        "label": 1,
        "text": """
        [VirusTotal] IP: 198.51.100.99
          Detection ratio: 2/94 engines flagged as malicious
          Suspicious votes: 0
          tags: none
        [AbuseIPDB] Abuse Confidence Score: 35/100
          Total abuse reports (last 90 days): 22 from 8 users
          Abuse categories reported: Port Scan
        """,
    },
]


def main() -> None:
    model = train_model(TRAINING_RECORDS)
    save_model(model, MODEL_PATH)
    print(f"trained risk model -> {MODEL_PATH}")
    print(f"features: {', '.join(model['features'])}")
    print(f"bias: {model['bias']}")
    for name, w in model["weights"].items():
        print(f"  {name}: {w}")


if __name__ == "__main__":
    main()
