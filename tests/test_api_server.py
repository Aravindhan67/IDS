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
    # Dataset pairing integrity: unpaired benchmark cohorts must NOT produce a fused hybrid verdict
    assert data["hybrid_verdict"]["status"] == "fusion_unavailable"
    assert data["hybrid_verdict"]["is_fused"] is False
    assert data["hybrid_verdict"]["is_malware"] is None
    assert "unpaired" in data["hybrid_verdict"]["reason"].lower()
    # Unverified hash safely skipped
    assert data["virustotal"]["status"] == "unverified_hash_skipped"
    # Historical dataset provenance
    assert "Historical" in data["static_analysis"]["data_provenance"]
    assert "Historical" in data["dynamic_analysis"]["data_provenance"]


def test_api_scan_sample_invalid_identifier(client):
    # Invalid sample type returns 404 client error
    res = client.post("/api/scan-sample", json={"sample_type": "nonexistent_trojan_xyz"})
    assert res.status_code == 404
    assert "not found in catalog" in res.json()["detail"].lower()


def test_api_scan_sample_paired_eligibility(client):
    from api_server import SAMPLE_CATALOG
    # Test that genuine paired observations CAN enter the fusion path
    SAMPLE_CATALOG["mock_paired_sample"] = {
        "title": "Mock Verified Paired APK",
        "category": "Paired Sample Test",
        "filename": "mock_paired.apk",
        "hash": None,
        "hash_status": "hash_unverified",
        "pairing_status": "verified_paired",
        "is_paired": True,
        "static_sample": {
            "source": "Drebin (Static Dataset)",
            "index": 4,
            "description": "Paired test sample static"
        },
        "dynamic_sample": {
            "source": "CICMalDroid (Dynamic Dataset)",
            "index": 3297,
            "description": "Paired test sample dynamic"
        }
    }
    try:
        res = client.post("/api/scan-sample", json={"sample_type": "mock_paired_sample"})
        assert res.status_code == 200
        data = res.json()
        assert data["is_paired"] is True
        assert data["hybrid_verdict"]["status"] == "fused"
        assert data["hybrid_verdict"]["is_fused"] is True
        assert data["hybrid_verdict"]["verdict"] in ["Malware", "Benign", "Ambiguous (Sandbox Required)"]
    finally:
        SAMPLE_CATALOG.pop("mock_paired_sample", None)


def test_api_scan_trace_empty_and_oversized(client):
    # 1. Empty trace returns 400
    files_empty = {"file": ("empty.log", io.BytesIO(b""), "text/plain")}
    res_empty = client.post("/api/scan-trace", files=files_empty)
    assert res_empty.status_code == 400

    # 2. Oversized trace returns 413
    oversized_data = b"A" * (11 * 1024 * 1024)
    files_big = {"file": ("big.log", io.BytesIO(oversized_data), "text/plain")}
    res_big = client.post("/api/scan-trace", files=files_big)
    assert res_big.status_code == 413


def test_api_scan_trace_no_supported_events(client):
    # Log with valid text lines but zero recognized CICMalDroid syscalls or Binders
    content = b"unrelated_log_entry_one()\nrandom_text_two()\n--- SIGUSR1 ---\n"
    files = {"file": ("unsupported.log", io.BytesIO(content), "text/plain")}
    res = client.post("/api/scan-trace", files=files)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "no_supported_events"
    assert data["malware_probability"] is None  # Must NOT predict on all-zero vectors
    assert data["telemetry_stats"]["total_events"] == 0


def test_api_scan_trace_valid_log(client):
    # Log with recognized syscalls and binders
    content = (
        b"100  open(\"/system/bin/app_process\", O_RDONLY) = 3\n"
        b"100  ioctl(3, BINDER_WRITE_READ, 0x123) = 0\n"
        b"100  close(3) = 0\n"
        b"100  sendMultipartText(12345, \"payload\") = 1\n"
    )
    files = {"file": ("trace.log", io.BytesIO(content), "text/plain")}
    res = client.post("/api/scan-trace", files=files)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["malware_probability"] is not None
    assert 0.0 <= data["malware_probability"] <= 1.0
    assert data["extracted_events"]["recognized_events"] >= 3


def test_api_query_hash(client):
    # 1. Invalid hash format
    res_bad = client.post("/api/query-hash", json={"hash": "invalid_not_hex"})
    assert res_bad.status_code == 200
    assert res_bad.json()["status"] == "error"

    # 2. Empty-file digest rejected
    res_empty_sha = client.post("/api/query-hash", json={"hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"})
    assert res_empty_sha.status_code == 200
    assert res_empty_sha.json()["status"] == "error"
    assert res_empty_sha.json()["error"] == "empty_file_digest_rejected"

    # 3. Valid hex hash
    valid_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    res_good = client.post("/api/query-hash", json={"hash": valid_hash})
    assert res_good.status_code == 200
    assert res_good.json()["status"] in ["found", "not_found", "unavailable", "rate_limited", "error"]


def test_api_what_if_remediation(client):
    # Valid request
    res = client.post("/api/what-if", json={"sample_index": 0, "revoked_permissions": ["SEND_SMS", "NON_EXISTENT_PERM"]})
    assert res.status_code == 200
    data = res.json()
    assert "original_risk" in data
    assert "remediated_risk" in data
    assert "risk_drop" in data
    assert data["sample_index"] == 0
    assert "simulation_disclaimer" in data
    assert "NON_EXISTENT_PERM" in data["invalid_or_inactive_permissions"]

    # Negative sample index should be rejected with 400 or 422
    res_neg = client.post("/api/what-if", json={"sample_index": -1})
    assert res_neg.status_code in [400, 422]

    # Out of bounds sample index
    res_oob = client.post("/api/what-if", json={"sample_index": 999999})
    assert res_oob.status_code == 400


def test_api_benchmarks(client):
    res = client.get("/api/benchmarks")
    assert res.status_code == 200
    data = res.json()
    assert "EXP1_Static_Resampling_Benchmark" in data or "metadata" in data


def test_api_benchmarks_missing_returns_404(client):
    from unittest.mock import patch
    with patch("api_server.BASE_DIR", Path("/tmp/nonexistent_ids_test_dir")):
        res = client.get("/api/benchmarks")
        assert res.status_code == 404
        assert "not found" in res.json()["detail"].lower()


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


def test_model_startup_no_silent_training():
    import tempfile
    from api_server import load_validated_model
    # 1. Missing model must raise FileNotFoundError, NOT silently train
    with pytest.raises(FileNotFoundError) as exc_info:
        load_validated_model(BASE_DIR / "models" / "nonexistent_model.json", expected_features=215, model_name="test")
    assert "not found" in str(exc_info.value).lower()

    # 2. Corrupted model file must raise ValueError
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write("{not valid json or model bytes}")
        corrupt_path = Path(f.name)
    try:
        with pytest.raises(ValueError) as exc_corrupt:
            load_validated_model(corrupt_path, expected_features=215, model_name="test_corrupt")
        assert "corrupted" in str(exc_corrupt.value).lower()
    finally:
        if corrupt_path.exists():
            os.remove(corrupt_path)


def test_api_simulate_dynamic(client):
    res = client.post("/api/simulate-dynamic", json={"static_probability": 0.85, "activity_level": "medium"})
    assert res.status_code == 200
    data = res.json()
    assert data["success"]
    assert data["status"] == "simulation"
    assert data["malware_probability"] is not None
    assert data["telemetry_stats"]["total_system_events"] > 0
    assert len(data["top_invoked"]) > 0


def test_api_scan_apk_with_simulation(client):
    sample_path = BASE_DIR / "tests" / "samples" / "test_sample.apk"
    if not sample_path.exists():
        pytest.skip("test_sample.apk not available")

    with open(sample_path, "rb") as f:
        files = {"file": ("test_sample.apk", f, "application/vnd.android.package-archive")}
        res = client.post("/api/scan-apk?simulate_dynamic=true", files=files)

    assert res.status_code == 200
    data = res.json()
    assert data["success"]
    assert data["dynamic_analysis"]["status"] == "simulation"
    assert data["dynamic_analysis"]["malware_probability"] is not None
    assert data["dynamic_analysis"]["telemetry_stats"]["total_system_events"] > 0
    assert "stage 2" in data["hybrid_verdict"]["stage_resolved"].lower() or "simulation" in data["hybrid_verdict"]["stage_resolved"].lower()
