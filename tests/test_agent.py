"""
Tests for the Threat Intel Agent.
Run with: pytest tests/ -v
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.orchestrator import build_structured_report
from tools.mitre_mapper import extract_signals, mitre_mapper_tool
from utils.classifier import classify_ioc, validate_ioc
from utils.risk_model import extract_features, predict_risk

# ── IOC Classifier Tests ────────────────────────────────────────────────────

class TestClassifier:
    def test_ipv4_valid(self):
        assert classify_ioc("8.8.8.8") == "ip"
        assert classify_ioc("192.168.1.1") == "ip"
        assert classify_ioc("10.0.0.1") == "ip"

    def test_ipv4_invalid(self):
        assert classify_ioc("999.999.999.999") == "unknown"
        assert classify_ioc("256.1.1.1") == "unknown"

    def test_domain(self):
        assert classify_ioc("malware.example.com") == "domain"
        assert classify_ioc("google.com") == "domain"
        assert classify_ioc("sub.domain.co.uk") == "domain"

    def test_url_strips_to_domain(self):
        assert classify_ioc("https://phishing.ru/login") == "domain"
        assert classify_ioc("http://bad-site.com/malware.exe") == "domain"

    def test_md5_hash(self):
        assert classify_ioc("d41d8cd98f00b204e9800998ecf8427e") == "hash"

    def test_sha1_hash(self):
        assert classify_ioc("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash"

    def test_sha256_hash(self):
        assert classify_ioc(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ) == "hash"

    def test_unknown(self):
        assert classify_ioc("not_an_ioc") == "unknown"
        assert classify_ioc("") == "unknown"
        assert classify_ioc("just some text") == "unknown"

    def test_validate_valid(self):
        valid, msg = validate_ioc("8.8.8.8")
        assert valid is True
        assert "ip" in msg

    def test_validate_invalid(self):
        valid, msg = validate_ioc("not_valid")
        assert valid is False
        assert "Could not classify" in msg


# ── MITRE Mapper Tests ───────────────────────────────────────────────────────

class TestMITREMapper:
    def test_ssh_brute_signal(self):
        signals = extract_signals("SSH brute force detected on port 22")
        assert "ssh_brute" in signals

    def test_port_scan_signal(self):
        signals = extract_signals("Nmap port scan from external IP")
        assert "port_scan" in signals

    def test_tor_signal(self):
        signals = extract_signals("IP is a known Tor exit node")
        assert "tor" in signals

    def test_multiple_signals(self):
        signals = extract_signals(
            "SSH brute force attempts, open proxy, phishing domain"
        )
        assert len(signals) >= 3

    def test_no_signals(self):
        signals = extract_signals("nothing relevant here")
        assert signals == []

    def test_tool_returns_techniques(self):
        result = mitre_mapper_tool.invoke(
            "SSH brute force, port scan, open proxy detected"
        )
        assert "T1110" in result      # Brute Force
        assert "T1595" in result      # Active Scanning
        assert "T1090" in result      # Proxy
        assert "attack.mitre.org" in result

    def test_tool_no_match_message(self):
        result = mitre_mapper_tool.invoke("nothing to match here")
        assert "No matching techniques" in result


class TestRiskModel:
    def test_extracts_risk_features(self):
        features = extract_features(
            """
            [VirusTotal] IP: 185.220.101.1
              Detection ratio: 47/94 engines flagged as malicious
            [AbuseIPDB] Abuse Confidence Score: 100/100
              Total abuse reports (last 90 days): 2847 from 311 users
              Is Tor exit node: True
            """
        )
        assert features["vt_malicious_ratio"] > 0.4
        assert features["abuse_confidence"] == 1.0
        assert features["tor_signal"] == 1.0

    def test_predicts_high_risk_ioc(self):
        prediction = predict_risk(
            """
            Detection ratio: 58/72 engines flagged as malicious
            Abuse Confidence Score: 100/100
            Total abuse reports (last 90 days): 900 from 80 users
            malware c2 open proxy brute force
            """
        )
        assert prediction.severity in {"HIGH", "CRITICAL"}
        assert prediction.confidence_score >= 70

    def test_predicts_clean_ioc(self):
        prediction = predict_risk(
            """
            Detection ratio: 0/94 engines flagged as malicious
            Suspicious votes: 0 / 94
            Abuse Confidence Score: 0/100
            Total abuse reports (last 90 days): 0 from 0 users
            clean no malicious low risk
            """
        )
        assert prediction.severity == "CLEAN"

    def test_structured_report_contains_model_fields(self):
        report = build_structured_report(
            "185.220.101.1",
            "ip",
            """
            [VirusTotal] IP: 185.220.101.1
              Detection ratio: 47/94 engines flagged as malicious
            [MITRE ATT&CK Mapper] Techniques matched:
              [T1090.003] Command and Control -> Proxy: Multi-hop Proxy
            """,
        )
        assert report["severity"] in {"HIGH", "CRITICAL"}
        assert report["risk_score"] > 0
        assert report["model_name"] == "local-ioc-risk-model"
        assert report["mitre_techniques"][0]["technique_id"] == "T1090.003"


# ── API Tests (requires running server) ─────────────────────────────────────
# Run separately with: pytest tests/test_api.py -v --run-api

@pytest.mark.skip(reason="Requires running API server")
class TestAPI:
    def test_health_endpoint(self):
        import httpx
        r = httpx.get("http://localhost:8000/health")
        assert r.status_code == 200
        assert "status" in r.json()

    def test_investigate_valid_ip(self):
        import httpx
        r = httpx.post(
            "http://localhost:8000/investigate",
            json={"ioc": "8.8.8.8"},
            timeout=60,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["ioc"] == "8.8.8.8"
        assert data["ioc_type"] == "ip"
        assert len(data["agent_output"]) > 0

    def test_investigate_invalid_ioc(self):
        import httpx
        r = httpx.post(
            "http://localhost:8000/investigate",
            json={"ioc": "not_valid_ioc"},
        )
        assert r.status_code == 422
