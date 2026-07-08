"""
Integration tests using FastAPI TestClient (no running server required).

These tests exercise the API endpoints in-process, hitting the real
application code including middleware, validation, and the investigation pipeline.
"""

import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("TIA_DISABLE_AUTH", "true")
os.environ.setdefault("TIA_DEMO_MODE", "true")

from api.main import app

client = TestClient(app)


class TestHealth:
    def test_root(self):
        r = client.get("/")
        assert r.status_code == 200

    def test_health(self):
        r = client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert "status" in data


class TestInvestigate:
    def test_valid_ip_demo(self):
        r = client.post("/investigate", json={"ioc": "185.220.101.1"})
        assert r.status_code == 200
        data = r.json()
        assert data["ioc"] == "185.220.101.1"
        assert data["ioc_type"] == "ip"
        assert len(data["agent_output"]) > 0
        assert "severity" in data["report"]

    def test_invalid_ioc(self):
        r = client.post("/investigate", json={"ioc": ""})
        assert r.status_code in (400, 422)

    def test_unknown_ioc(self):
        r = client.post("/investigate", json={"ioc": "not_an_ioc_at_all_12345"})
        assert r.status_code in (200, 422)
        data = r.json() if r.status_code == 200 else {}
        if r.status_code == 200:
            assert data["ioc_type"] == "unknown"

    def test_missing_field(self):
        r = client.post("/investigate", json={})
        assert r.status_code == 422


class TestChat:
    def test_chat_no_ioc(self):
        r = client.post("/api/chat", json={"message": "hello"})
        assert r.status_code == 200
        data = r.json()
        assert "response" in data

    def test_chat_with_ioc(self):
        r = client.post("/api/chat", json={"message": "check 8.8.8.8"})
        assert r.status_code == 200
        data = r.json()
        assert "response" in data


class TestBulk:
    def test_bulk_single(self):
        r = client.post("/api/bulk-investigate", json={"iocs": ["8.8.8.8"]})
        assert r.status_code in (200, 429)
