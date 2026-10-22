"""
Automated Unit Tests for Hybrid Fusion & Cascaded Triage Pipeline
AegisDroid Hybrid Android Intrusion Detection System (HIDS)

Verifies:
1. Operational triage threshold routing (Stage 1 vs Stage 2).
2. Handling of ambiguous samples with and without available dynamic telemetry.
3. Parametric late-fusion weight sweeping logic.
4. Evaluation of routing efficiency without cross-dataset row-zipping.
"""

import numpy as np
import pytest
from src.hybrid_fusion import CascadedTriagePipeline, late_fusion_weight_sweep


def test_triage_threshold_boundaries():
    triage = CascadedTriagePipeline(tau_benign=0.35, tau_malware=0.75)

    # 1. Clear Benign (Stage 1)
    r_benign = triage.evaluate_sample(p_static=0.15)
    assert r_benign["verdict"] == "Benign"
    assert not r_benign["sandbox_invoked"]
    assert "Stage 1" in r_benign["stage_resolved"]

    # 2. Clear Malware (Stage 1)
    r_malware = triage.evaluate_sample(p_static=0.88)
    assert r_malware["verdict"] == "Malware"
    assert not r_malware["sandbox_invoked"]
    assert "Stage 1" in r_malware["stage_resolved"]

    # 3. Borderline with Dynamic Evidence (Stage 2)
    r_hybrid = triage.evaluate_sample(p_static=0.52, p_dynamic=0.90)
    assert r_hybrid["verdict"] == "Malware"
    assert r_hybrid["sandbox_invoked"]
    assert "Stage 2" in r_hybrid["stage_resolved"]
    assert r_hybrid["p_dynamic"] == 0.90

    # 4. Borderline without Dynamic Evidence (Honest Fallback)
    r_pending = triage.evaluate_sample(p_static=0.52, p_dynamic=None)
    assert r_pending["sandbox_invoked"]
    assert r_pending["p_dynamic"] is None
    assert "Sandbox" in r_pending["verdict"]


def test_invalid_thresholds():
    with pytest.raises(ValueError):
        CascadedTriagePipeline(tau_benign=0.80, tau_malware=0.20)


def test_synthetic_fixture_triage_evaluation():
    triage = CascadedTriagePipeline(tau_benign=0.35, tau_malware=0.75)
    p_static = np.array([0.1, 0.2, 0.5, 0.6, 0.8, 0.9])
    p_dynamic = np.array([0.1, 0.1, 0.7, 0.8, 0.9, 0.9])
    y_true = np.array([0, 0, 1, 1, 1, 1])

    stats = triage.evaluate_synthetic_fixture_cohort(p_static, p_dynamic, y_true)
    assert stats["total_samples"] == 6
    assert 0.0 <= stats["stage1_resolution_rate"] <= 1.0
    assert 0.0 <= stats["sandbox_invocation_rate"] <= 1.0
    assert stats["stage1_resolution_rate"] + stats["sandbox_invocation_rate"] == 1.0


def test_late_fusion_weight_sweep():
    p_s = np.array([0.2, 0.8, 0.4])
    p_d = np.array([0.1, 0.9, 0.7])
    y = np.array([0, 1, 1])

    sweep = late_fusion_weight_sweep(p_s, p_d, y, steps=5)
    assert len(sweep) == 5
    assert sweep[0]["w_static"] == 0.0
    assert sweep[-1]["w_static"] == 1.0
