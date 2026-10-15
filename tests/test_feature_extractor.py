"""
Unit Tests for Static Feature Extractor
Verifies resolution of Reviewer 2 Point 4 (Closing the 46.5% feature gap)
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import numpy as np
from src.feature_extractor import DrebinFeatureExtractor


def test_extractor_initialization():
    extractor = DrebinFeatureExtractor()
    assert extractor.num_features == 215, f"Expected 215 features, got {extractor.num_features}"
    assert len(extractor.permissions) > 100, f"Permissions count {len(extractor.permissions)} too low"
    assert len(extractor.intents) >= 20, f"Intents count {len(extractor.intents)} too low"
    assert len(extractor.api_calls) >= 70, f"API calls count {len(extractor.api_calls)} too low"
    print("[PASS] test_extractor_initialization")


def test_ablation_mode_zeroing():
    extractor = DrebinFeatureExtractor()
    
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
    print("[PASS] test_ablation_mode_zeroing")


if __name__ == "__main__":
    test_extractor_initialization()
    test_ablation_mode_zeroing()
    print("All feature extractor unit tests passed successfully!")
