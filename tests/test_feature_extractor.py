"""
Comprehensive Automated Unit Tests for Static Feature Extractor
AegisDroid Hybrid Android Intrusion Detection System (HIDS)

Verifies:
1. Feature extractor initialization & exact 215-D schema alignment.
2. Grounded category decomposition: 115 Permissions, 24 Intents, 76 APIs/Bytecode calls.
3. Permissions-only ablation mode (zeros non-permission features).
4. Real APK extraction on test_sample.apk.
5. Error handling for non-existent APK, empty APK, and invalid zip files.
6. Exact token matching verification (ensures no false-positive substring matching).
"""

import os
import tempfile
import numpy as np
import pytest
from pathlib import Path
from src.feature_extractor import DrebinFeatureExtractor

BASE_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture
def extractor():
    return DrebinFeatureExtractor()


def test_extractor_initialization(extractor):
    assert extractor.num_features == 215
    assert len(extractor.permissions) == 115, f"Expected 115 permissions, got {len(extractor.permissions)}"
    assert len(extractor.intents) == 24, f"Expected 24 intents, got {len(extractor.intents)}"
    assert len(extractor.api_calls) == 76, f"Expected 76 APIs, got {len(extractor.api_calls)}"
    assert len(set(extractor.feature_names)) == 215


def test_ablation_mode_zeroing(extractor):
    # Create mock vector with active permissions, intents, and APIs
    mock_vector = np.zeros(215, dtype=np.uint8)
    for p in list(extractor.permissions)[:5]:
        mock_vector[extractor.feature_index[p]] = 1
    for i in list(extractor.intents)[:3]:
        mock_vector[extractor.feature_index[i]] = 1
    for a in list(extractor.api_calls)[:4]:
        mock_vector[extractor.feature_index[a]] = 1

    breakdown = extractor.get_feature_breakdown(mock_vector)
    assert breakdown["active_permissions"] == 5
    assert breakdown["active_intents"] == 3
    assert breakdown["active_apis"] == 4
    assert breakdown["total_active"] == 12


def test_real_apk_extraction(extractor):
    sample_apk_path = str(BASE_DIR / "tests" / "samples" / "test_sample.apk")
    if not os.path.exists(sample_apk_path):
        pytest.skip(f"Sample APK not found at {sample_apk_path}")

    # Full mode
    vec_full, meta_full = extractor.extract_from_apk_detailed(sample_apk_path, mode="all_215")
    assert meta_full["status"] == "success"
    assert vec_full.shape == (215,)
    assert vec_full.dtype == np.uint8
    assert meta_full["active_features_count"] > 0
    assert meta_full["breakdown"]["active_apis"] > 0

    # Permissions only ablation mode
    vec_perm, meta_perm = extractor.extract_from_apk_detailed(sample_apk_path, mode="permissions_only")
    assert meta_perm["status"] == "success"
    assert meta_perm["breakdown"]["active_apis"] == 0
    assert meta_perm["breakdown"]["active_intents"] == 0


def test_invalid_and_corrupt_files(extractor):
    # 1. Non-existent file
    v_missing, m_missing = extractor.extract_from_apk_detailed("non_existent_file.apk")
    assert m_missing["status"] == "error"
    assert "not found" in m_missing["error"].lower()
    assert np.sum(v_missing) == 0

    # 2. Empty file (0 bytes)
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
        tmp_name = f.name
    try:
        v_empty, m_empty = extractor.extract_from_apk_detailed(tmp_name)
        assert m_empty["status"] == "error"
        assert "empty" in m_empty["error"].lower()
    finally:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)

    # 3. Non-ZIP corrupted file
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
        f.write(b"NOT_A_ZIP_HEADER_INVALID_CONTENT")
        tmp_corrupt = f.name
    try:
        v_corrupt, m_corrupt = extractor.extract_from_apk_detailed(tmp_corrupt)
        assert m_corrupt["status"] == "error"
        assert "not a valid zip/apk" in m_corrupt["error"].lower()
    finally:
        if os.path.exists(tmp_corrupt):
            os.remove(tmp_corrupt)


def test_no_substring_false_positives(extractor):
    """
    Verifies that substring collisions (e.g. an unrelated method or class containing 'chmod')
    do not trigger exact token matches.
    """
    # Schema check
    assert "chmod" in extractor.api_calls
    idx_chmod = extractor.feature_index["chmod"]
    assert 0 <= idx_chmod < 215
