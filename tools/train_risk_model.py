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
    {
        "label": 1,
        "text": """
        [VirusTotal] IP: 185.220.101.1
          Detection ratio: 47/94 engines flagged as malicious
          Suspicious votes: 4
        [AbuseIPDB] IP: 185.220.101.1
          Abuse Confidence Score: 100/100
          Total abuse reports (last 90 days): 2847 from 311 users
          Is Tor exit node: True
          Abuse categories reported: Open Proxy, SSH, Brute-Force
        [MITRE ATT&CK Mapper] Techniques matched: T1090.003, T1110.001
        """,
    },
    {
        "label": 1,
        "text": """
        [VirusTotal] Domain: malware-c2.ru
          Detection ratio: 31/88 engines flagged as malicious
          Suspicious votes: 8
          tags: malware, c2, trojan
        [MITRE ATT&CK Mapper] phishing, credential harvesting, c2
        """,
    },
    {
        "label": 1,
        "text": """
        [VirusTotal] FileHash: sample
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
          Known CVEs: CVE-2024-3094, CVE-2023-3519, CVE-2022-1388
        [AbuseIPDB] Abuse Confidence Score: 77/100
          Total abuse reports (last 90 days): 328 from 74 users
          Abuse categories reported: SSH, Brute-Force, Port Scan
        """,
    },
    {
        "label": 0,
        "text": """
        [VirusTotal] IP: 8.8.8.8
          Detection ratio: 0/94 engines flagged as malicious
          Suspicious votes: 0
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
]


def main() -> None:
    model = train_model(TRAINING_RECORDS)
    save_model(model, MODEL_PATH)
    print(f"trained risk model -> {MODEL_PATH}")
    print(f"features: {', '.join(model['features'])}")


if __name__ == "__main__":
    main()
