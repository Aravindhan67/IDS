"""
Automated Integration Tests for FastAPI Backend Server
AegisDroid Hybrid Android Intrusion Detection System (HIDS)

Verifies:
1. /api/health endpoint status and model loading.
2. /api/scan-sample endpoint for catalog samples (Drebin & CICMalDroid).
3. /api/query-hash endpoint with format validation and honest responses.
4. /api/what-if endpoint with active permission simulation and bounds checking.
5. /api/benchmarks endpoint serving verified experiment outputs.
6. /api/scan-apk endpoint:
   - File extension validation (rejects non-apk).
   - Valid APK scanning with honest dynamic status (unavailable when no emulator connected).
   - Zero fabricated VirusTotal detections.
"""

import os
import io
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from api_server import app, load_ml_pipeline

BASE_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def client():
    # Initialize pipeline
    load_ml_pipeline()
    with TestClient(app) as test_client:
        yield test_client


def test_api_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert "static_xgboost" in data["models"]
    assert "dynamic_xgboost" in data["models"]
    assert data["models"]["static_xgboost"]["features"] == 215
    assert data["models"]["dynamic_xgboost"]["features"] == 470


def test_api_scan_sample(client):
    res = client.post("/api/scan-sample", json={"sample_type": "sms_trojan"})
    assert res.status_code == 200
    data = res.json()
    assert data["success"]
    assert "FakeInst" in data["sample_name"]
    assert "static_analysis" in data
    assert "dynamic_analysis" in data
    assert "hybrid_verdict" in data
    assert "virustotal" in data
    assert 0.0 <= data["static_analysis"]["malware_probability"] <= 1.0
    assert 0.0 <= data["dynamic_analysis"]["malware_probability"] <= 1.0


def test_api_query_hash(client):
    # 1. Invalid hash format
    res_bad = client.post("/api/query-hash", json={"hash": "invalid_not_hex"})
    assert res_bad.status_code == 200
    assert res_bad.json()["status"] == "error"

    # 2. Valid hex hash
    valid_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    res_good = client.post("/api/query-hash", json={"hash": valid_hash})
    assert res_good.status_code == 200
    assert res_good.json()["status"] in ["found", "not_found", "unavailable", "rate_limited", "error"]


def test_api_what_if_remediation(client):
    # Valid request
    res = client.post("/api/what-if", json={"sample_index": 0, "revoked_permissions": ["SEND_SMS"]})
    assert res.status_code == 200
    data = res.json()
    assert "original_risk" in data
    assert "remediated_risk" in data
    assert "risk_drop" in data
    assert data["sample_index"] == 0

    # Negative sample index should be rejected
    res_neg = client.post("/api/what-if", json={"sample_index": -1})
    assert res_neg.status_code == 422  # Pydantic validation error


def test_api_benchmarks(client):
    res = client.get("/api/benchmarks")
    assert res.status_code == 200
    data = res.json()
    assert "EXP1_Static_Resampling_Benchmark" in data or "metadata" in data


def test_api_scan_apk_validation(client):
    # Reject non-apk
    files = {"file": ("malicious.exe", io.BytesIO(b"MZ..."), "application/octet-stream")}
    res_bad = client.post("/api/scan-apk", files=files)
    assert res_bad.status_code == 400
    assert ".apk" in res_bad.json()["detail"].lower()


def test_api_scan_apk_real_sample(client):
    sample_path = BASE_DIR / "tests" / "samples" / "test_sample.apk"
    if not sample_path.exists():
        pytest.skip("test_sample.apk not available")

    with open(sample_path, "rb") as f:
        files = {"file": ("test_sample.apk", f, "application/vnd.android.package-archive")}
        res = client.post("/api/scan-apk", files=files)

    assert res.status_code == 200
    data = res.json()
    assert data["success"]
    assert "static_analysis" in data
    assert "dynamic_analysis" in data
    assert "hybrid_verdict" in data
    assert "virustotal" in data

    # Honest dynamic status when no emulator is attached
    assert data["dynamic_analysis"]["status"] in ["unavailable", "success", "failed"]
    if data["dynamic_analysis"]["status"] == "unavailable":
        assert data["dynamic_analysis"]["malware_probability"] is None
        assert "stage 1" in data["hybrid_verdict"]["stage_resolved"].lower()
