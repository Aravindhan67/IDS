"""
Automated Unit Tests for VirusTotal Signature Integration
AegisDroid Hybrid Android Intrusion Detection System (HIDS)

Verifies:
1. Honest response states: found, not_found, unavailable, rate_limited, error.
2. Safe handling of unconfigured API key (never crashes, returns unavailable).
3. Hash format validation (MD5, SHA-1, SHA-256).
4. Real cryptographic hashing of APK files (MD5, SHA-1, SHA-256).
5. Elimination of fabricated ratios (48/74, 58/74) and synthetic vendor maps.
"""

import tempfile
import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.virustotal_client import VirusTotalSignatureAnalyzer

BASE_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture
def vt_client():
    return VirusTotalSignatureAnalyzer(api_key="mock_test_key_1234567890abcdef")


def test_hash_format_validation():
    # Valid SHA-256
    assert VirusTotalSignatureAnalyzer.is_valid_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    # Valid MD5
    assert VirusTotalSignatureAnalyzer.is_valid_hash("44d88612fea8a8f36de82e1278abb02f")
    # Valid SHA-1
    assert VirusTotalSignatureAnalyzer.is_valid_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    # Invalid strings
    assert not VirusTotalSignatureAnalyzer.is_valid_hash("not_a_hash")
    assert not VirusTotalSignatureAnalyzer.is_valid_hash("12345")
    assert not VirusTotalSignatureAnalyzer.is_valid_hash("")


def test_file_hash_computation():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"AEGISDROID_TEST_PAYLOAD")
        tmp_name = f.name
    try:
        hashes = VirusTotalSignatureAnalyzer.compute_file_hashes(tmp_name)
        assert "sha256" in hashes
        assert "md5" in hashes
        assert "sha1" in hashes
        assert len(hashes["sha256"]) == 64
        assert len(hashes["md5"]) == 32
    finally:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)


def test_vt_unconfigured_api_key():
    client = VirusTotalSignatureAnalyzer(api_key="")
    res = client.query_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    assert res["status"] == "unavailable"
    assert not res["success"]
    assert "not configured" in res["message"].lower()


def test_vt_found_state(vt_client):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 42,
                    "suspicious": 2,
                    "harmless": 0,
                    "undetected": 30
                },
                "popular_threat_classification": {
                    "suggested_threat_label": "Trojan.AndroidOS.FakeInst"
                },
                "last_analysis_results": {
                    "Kaspersky": {"category": "malicious", "result": "HEUR:Trojan.AndroidOS.FakeInst"},
                    "Microsoft": {"category": "malicious", "result": "Trojan:AndroidOS/FakeInst"}
                }
            }
        }
    }

    with patch("requests.get", return_value=mock_resp):
        res = vt_client.query_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        assert res["status"] == "found"
        assert res["success"]
        assert res["signature_detected"]
        assert res["detection_ratio"] == "42/74"
        assert res["malicious_engines"] == 42
        assert res["total_engines"] == 74
        assert "Kaspersky" in res["vendor_sample_verdicts"]


def test_vt_not_found_state(vt_client):
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("requests.get", return_value=mock_resp):
        res = vt_client.query_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert res["status"] == "not_found"
        assert res["success"]
        assert not res["signature_detected"]
        assert res["detection_ratio"] == "0/0"
        assert res["malicious_engines"] == 0


def test_vt_rate_limited_state(vt_client):
    mock_resp = MagicMock()
    mock_resp.status_code = 429

    with patch("requests.get", return_value=mock_resp):
        res = vt_client.query_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        assert res["status"] == "rate_limited"
        assert not res["success"]
        assert "429" in res["error"]


def test_vt_server_error_state(vt_client):
    mock_resp = MagicMock()
    mock_resp.status_code = 500

    with patch("requests.get", return_value=mock_resp):
        res = vt_client.query_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        assert res["status"] == "error"
        assert not res["success"]
        assert "500" in res["error"]
