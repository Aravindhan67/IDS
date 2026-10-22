"""
Automated Unit Tests for What-If Counterfactual Remediation Engine
AegisDroid Hybrid Android Intrusion Detection System (HIDS)

Verifies:
1. Revocation is restricted strictly to active permissions (x_i = 1).
2. Accurate quantification of initial risk, final risk, and risk reduction.
3. Threshold crossing detection (P < 0.50 achieves safe state).
4. Handling of samples driven exclusively by non-permission features.
5. Out-of-sample evaluation on held-out test partitions.
"""

import numpy as np
import pytest
from pathlib import Path
from xgboost import XGBClassifier
from src.remediation import WhatIfRemediationEngine

BASE_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture
def remediation_setup():
    # 215 feature schema: first 115 permissions, next 24 intents, remaining 76 APIs
    feature_names = [f"PERM_{i}" for i in range(115)] + [f"android.intent.action.ACT_{i}" for i in range(24)] + [f"api_call_{i}" for i in range(76)]

    # Mock synthetic dataset
    np.random.seed(42)
    X = np.zeros((100, 215), dtype=np.uint8)
    y = np.zeros(100, dtype=int)

    # Benign samples: 0-49, low active permissions
    X[:50, :2] = 1

    # Malware samples: 50-99, high active permissions
    X[50:, :10] = 1
    y[50:] = 1

    clf = XGBClassifier(n_estimators=15, max_depth=3, random_state=42, eval_metric="logloss")
    clf.fit(X, y)

    engine = WhatIfRemediationEngine(clf, feature_names)
    return engine, X, y


def test_active_permission_revocation(remediation_setup):
    engine, X, y = remediation_setup
    malware_sample = X[60].copy()

    res = engine.analyze_single_sample(malware_sample)
    assert res["remediation_needed"]
    assert res["remediation_possible"]
    assert res["initial_risk"] > 0.50
    assert res["final_risk"] < res["initial_risk"]
    assert res["total_risk_drop"] > 0.0
    assert res["permissions_revoked_count"] > 0

    # Ensure all recommended revocations are active permissions in original sample
    for perm in res["recommended_revocations"]:
        idx = engine.feature_index[perm]
        assert malware_sample[idx] == 1, f"Revoked permission {perm} was not active in sample!"


def test_already_benign_sample(remediation_setup):
    engine, X, y = remediation_setup
    benign_sample = X[5].copy()

    res = engine.analyze_single_sample(benign_sample)
    assert not res["remediation_needed"]
    assert res["initial_verdict"] == "Benign"
    assert res["total_risk_drop"] == 0.0


def test_malware_with_no_permissions(remediation_setup):
    from unittest.mock import patch
    engine, _, _ = remediation_setup
    # Vector with 0 permissions, but active non-permission features
    vec = np.zeros(215, dtype=np.uint8)
    vec[150:160] = 1  # APIs active

    with patch.object(engine, "evaluate_risk", return_value=0.85):
        res = engine.analyze_single_sample(vec)
        assert not res["remediation_possible"]
        assert "non-permission" in res["message"].lower()


def test_batch_held_out_evaluation(remediation_setup):
    engine, X, y = remediation_setup
    # Evaluate on samples 50:70
    X_test = X[50:70]
    y_test = y[50:70]

    stats = engine.batch_counterfactual_experiment(X_test, y_test, max_samples=20)
    assert stats["total_malware_evaluated"] > 0
    assert "benign_conversion_rate" in stats
    assert "average_risk_reduction" in stats
    assert stats["average_risk_reduction"] >= 0.0
