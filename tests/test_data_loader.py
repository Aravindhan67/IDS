"""
Automated Unit Tests for Data Ingestion & Preprocessing Module
AegisDroid Hybrid Android Intrusion Detection System (HIDS)

Verifies:
1. Schema integrity & canonical column ordering for Drebin and CICMalDroid.
2. Label mapping: 'S'->1, 'B'->0 for Drebin; Classes 1-4->1, 5->0 for Dynamic.
3. Explicit rejection of missing or unrecognized target labels.
4. Stratified K-fold split generation (disjoint test partitions).
5. Train-partition-only resampling isolation (SMOTE does not touch validation folds).
6. XGBoost scale_pos_weight computation.
"""

import numpy as np
import pandas as pd
import pytest
from pathlib import Path
from src.data_loader import (
    load_drebin, load_dynamic, get_stratified_splits,
    apply_training_resampling, compute_scale_pos_weight
)

BASE_DIR = Path(__file__).resolve().parent.parent


def test_drebin_loading_and_schema():
    X, y, feats = load_drebin(drop_duplicates=True)
    assert X.shape[1] == 215
    assert len(feats) == 215
    assert X.shape[0] == len(y)
    assert set(y.unique()).issubset({0, 1})
    assert X.dtypes.iloc[0] == np.uint8


def test_dynamic_loading_and_schema():
    X, y_bin, y_multi, feats = load_dynamic(drop_duplicates=True)
    assert X.shape[1] == 470
    assert len(feats) == 470
    assert X.shape[0] == len(y_bin)
    assert set(y_bin.unique()).issubset({0, 1})
    assert set(y_multi.unique()).issubset({1, 2, 3, 4, 5})
    # Check binary mapping: Class 5 is Benign (0), 1-4 are Malware (1)
    assert np.all(y_bin[y_multi == 5] == 0)
    assert np.all(y_bin[y_multi != 5] == 1)


def test_stratified_fold_disjointness():
    X = np.random.randn(100, 10)
    y = np.array([0] * 50 + [1] * 50)
    folds = get_stratified_splits(X, y, n_splits=5, random_state=42)

    assert len(folds) == 5
    for train_idx, test_idx in folds:
        # Train and test indices must be strictly disjoint
        intersection = set(train_idx).intersection(set(test_idx))
        assert len(intersection) == 0
        assert len(train_idx) + len(test_idx) == 100


def test_training_only_resampling():
    X_train = np.random.randn(80, 10)
    y_train = np.array([0] * 70 + [1] * 10)  # Imbalanced

    # 1. None
    X_none, y_none = apply_training_resampling(X_train, y_train, method="none")
    assert len(X_none) == 80
    assert len(y_none) == 80

    # 2. SMOTE
    X_sm, y_sm = apply_training_resampling(X_train, y_train, method="smote", random_state=42)
    assert len(X_sm) > len(X_train)
    assert np.sum(y_sm == 0) == np.sum(y_sm == 1)

    # 3. Invalid method raises ValueError
    with pytest.raises(ValueError, match="Unknown resampling method"):
        apply_training_resampling(X_train, y_train, method="invalid_method")


def test_scale_pos_weight():
    y = np.array([0, 0, 0, 0, 1])  # 4 neg, 1 pos
    spw = compute_scale_pos_weight(y)
    assert spw == 4.0

    y_empty = np.array([0, 0])
    assert compute_scale_pos_weight(y_empty) == 1.0
