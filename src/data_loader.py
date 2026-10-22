"""
Data Ingestion, Cleaning, and Leakage-Free Preprocessing Module
AegisDroid Hybrid Android Intrusion Detection System (HIDS)

Provides validated loading for:
1. Drebin static analysis dataset (215 binary features, deduplicated).
2. CICMalDroid dynamic behavioral dataset (470 syscall and binder frequency features, deduplicated).

Enforces:
- Schema alignment against reference JSON definitions.
- Strict binary label mapping and rejection of malformed records.
- Train-fold-only resampling to guarantee zero cross-validation leakage.
- Project-relative path resolution.
"""

import os
import json
import logging
from pathlib import Path
from typing import Tuple, List, Optional, Dict, Any
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from imblearn.over_sampling import SMOTE, BorderlineSMOTE

logger = logging.getLogger("AegisDroid.DataLoader")

BASE_DIR = Path(__file__).resolve().parent.parent


def load_drebin(
    filepath: Optional[str] = None,
    schema_path: Optional[str] = None,
    drop_duplicates: bool = True
) -> Tuple[pd.DataFrame, pd.Series, List[str]]:
    """
    Loads, validates, and cleans the Drebin static analysis dataset.

    Data Integrity & Quality Rules:
    - Resolves project-relative path if None.
    - Validates presence of all 215 schema features in exact order.
    - Replaces '?' artifact with '0' in TelephonyManager.getSimCountryIso.
    - Validates binary labels: 'S' (Malware) -> 1, 'B' (Benign) -> 0.
    - Transparent deduplication by exact row equality across all 215 features.

    Returns:
        X (pd.DataFrame): 215 static binary features (uint8).
        y (pd.Series): Binary labels (1 = Malware, 0 = Benign).
        feature_names (List[str]): Names of the 215 features in canonical order.
    """
    if filepath is None:
        filepath = str(BASE_DIR / "dataset" / "drebin.csv")
    if schema_path is None:
        schema_path = str(BASE_DIR / "models" / "drebin_feature_names.json")

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Drebin dataset not found at: {filepath}")
    if not os.path.exists(schema_path):
        raise FileNotFoundError(f"Drebin schema not found at: {schema_path}")

    with open(schema_path, "r", encoding="utf-8") as f:
        expected_features = json.load(f)

    logger.info("Loading Drebin static dataset from %s ...", filepath)
    df = pd.read_csv(filepath)
    initial_len = len(df)

    if 'class' not in df.columns:
        raise ValueError("Missing 'class' label column in Drebin dataset")

    # 1. Clean target column nulls
    null_labels = df['class'].isnull().sum()
    if null_labels > 0:
        logger.warning("Dropping %d rows with null target class", null_labels)
        df = df.dropna(subset=['class'])

    # 2. Fix known legacy Drebin string artifact in TelephonyManager.getSimCountryIso
    if 'TelephonyManager.getSimCountryIso' in df.columns:
        df['TelephonyManager.getSimCountryIso'] = (
            df['TelephonyManager.getSimCountryIso']
            .replace('?', '0')
            .fillna('0')
            .astype(int)
        )

    # 3. Deduplication by feature-row equality
    if drop_duplicates:
        df = df.drop_duplicates()
        logger.info(
            "Drebin row deduplication: %d -> %d samples (dropped %d duplicates by full-row identity)",
            initial_len, len(df), initial_len - len(df)
        )

    # 4. Separate target and features
    y_raw = df['class']
    X_raw = df.drop(columns=['class'])

    # 5. Schema verification and canonical re-ordering
    missing_cols = set(expected_features) - set(X_raw.columns)
    if missing_cols:
        raise ValueError(f"Drebin dataset missing {len(missing_cols)} schema features: {list(missing_cols)[:5]}")

    X = X_raw[expected_features].copy()

    # 6. Validate numeric binary integrity
    for col in X.columns:
        if not pd.api.types.is_numeric_dtype(X[col]):
            X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

    X = X.astype(np.uint8)

    # 7. Strict target mapping: 'S' -> 1, 'B' -> 0
    y = y_raw.map({'S': 1, 'B': 0})
    if y.isnull().any():
        unmapped = y_raw[y.isnull()].unique()
        raise ValueError(f"Unrecognized class labels in Drebin dataset: {unmapped}")
    y = y.astype(int)

    logger.info("Drebin loaded successfully: %d samples, %d features aligned to schema", X.shape[0], X.shape[1])
    logger.info(
        "Drebin distribution: Malware (1): %d (%.2f%%), Benign (0): %d (%.2f%%)",
        int((y == 1).sum()), float((y == 1).mean() * 100),
        int((y == 0).sum()), float((y == 0).mean() * 100)
    )

    return X, y, expected_features


def load_dynamic(
    filepath: Optional[str] = None,
    schema_path: Optional[str] = None,
    drop_duplicates: bool = True
) -> Tuple[pd.DataFrame, pd.Series, pd.Series, List[str]]:
    """
    Loads, validates, and cleans the CICMalDroid dynamic syscalls & binder frequencies dataset.

    Data Properties:
    - 470 features (Linux kernel syscalls and Android Binder IPC categories).
    - Multi-class: Classes 1 to 5.
      - Class 1: Adware
      - Class 2: Banking Malware
      - Class 3: SMS Malware
      - Class 4: Ransomware
      - Class 5: Benign Utility (Clean)
    - Binary mapping: Classes 1-4 = Malware (1), Class 5 = Benign (0).

    Returns:
        X (pd.DataFrame): 470 dynamic numerical frequency features (int32).
        y_binary (pd.Series): Binary labels (1 = Malware, 0 = Benign).
        y_multi (pd.Series): Original 5-class labels (1 to 5).
        feature_names (List[str]): Names of the 470 dynamic features.
    """
    if filepath is None:
        filepath = str(BASE_DIR / "dataset" / "feature_vectors_syscallsbinders_frequency_5_Cat.csv")
    if schema_path is None:
        schema_path = str(BASE_DIR / "models" / "dynamic_feature_names.json")

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dynamic dataset not found at: {filepath}")
    if not os.path.exists(schema_path):
        raise FileNotFoundError(f"Dynamic schema not found at: {schema_path}")

    with open(schema_path, "r", encoding="utf-8") as f:
        expected_features = json.load(f)

    logger.info("Loading dynamic syscalls/binders dataset from %s ...", filepath)
    df = pd.read_csv(filepath)
    initial_len = len(df)

    if 'Class' not in df.columns:
        raise ValueError("Missing 'Class' column in dynamic dataset")

    # 1. Drop rows with null target class
    if df['Class'].isnull().any():
        df = df.dropna(subset=['Class'])

    # 2. Deduplication by feature-row equality
    if drop_duplicates:
        df = df.drop_duplicates()
        logger.info(
            "Dynamic row deduplication: %d -> %d samples (dropped %d duplicates by full-row identity)",
            initial_len, len(df), initial_len - len(df)
        )

    # 3. Separate target and features
    y_multi = df['Class'].astype(int)
    valid_classes = {1, 2, 3, 4, 5}
    if not set(y_multi.unique()).issubset(valid_classes):
        raise ValueError(f"Unexpected classes in dynamic dataset: {set(y_multi.unique()) - valid_classes}")

    # Binary mapping: Classes 1-4 = Malware (1), Class 5 = Benign (0)
    y_binary = (y_multi != 5).astype(int)

    X_raw = df.drop(columns=['Class'])

    # 4. Schema verification and canonical re-ordering
    missing_cols = set(expected_features) - set(X_raw.columns)
    if missing_cols:
        raise ValueError(f"Dynamic dataset missing {len(missing_cols)} schema features: {list(missing_cols)[:5]}")

    X = X_raw[expected_features].copy()

    # 5. Validate numeric integrity
    for col in X.columns:
        if not pd.api.types.is_numeric_dtype(X[col]):
            X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

    X = X.astype(np.int32)

    logger.info("Dynamic dataset loaded: %d samples, %d features aligned to schema", X.shape[0], X.shape[1])
    logger.info(
        "Dynamic binary distribution: Malware (1): %d (%.2f%%), Benign (0): %d (%.2f%%)",
        int((y_binary == 1).sum()), float((y_binary == 1).mean() * 100),
        int((y_binary == 0).sum()), float((y_binary == 0).mean() * 100)
    )
    logger.info("Dynamic multi-class distribution: %s", y_multi.value_counts().to_dict())

    return X, y_binary, y_multi, expected_features


def get_stratified_splits(
    X: np.ndarray,
    y: np.ndarray,
    n_splits: int = 5,
    random_state: int = 42
) -> List[Tuple[np.ndarray, np.ndarray]]:
    """
    Generates indices for Leakage-Free Stratified K-Fold Cross Validation.
    """
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    return list(skf.split(X, y))


def apply_training_resampling(
    X_train: np.ndarray,
    y_train: np.ndarray,
    method: str = "none",
    random_state: int = 42
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Applies resampling strictly to training partitions to eliminate data leakage.
    Ensures that validation and test partitions remain untouched.

    Args:
        X_train: Training feature matrix.
        y_train: Training target array.
        method: 'none', 'smote', or 'borderline_smote'.
        random_state: Seed for reproducibility.

    Returns:
        Tuple[np.ndarray, np.ndarray]: (X_resampled, y_resampled)
    """
    method = method.lower().strip()
    if method == "none":
        return X_train, y_train

    elif method == "smote":
        sm = SMOTE(random_state=random_state)
        X_res, y_res = sm.fit_resample(X_train, y_train)
        return X_res, y_res

    elif method in ["borderline", "borderline_smote"]:
        bsm = BorderlineSMOTE(random_state=random_state)
        X_res, y_res = bsm.fit_resample(X_train, y_train)
        return X_res, y_res

    else:
        raise ValueError(f"Unknown resampling method: '{method}'. Choose from 'none', 'smote', 'borderline'.")


def compute_scale_pos_weight(y: np.ndarray) -> float:
    """
    Computes scale_pos_weight parameter for XGBoost cost-sensitive learning:
    scale_pos_weight = count(negative class) / count(positive class)
    """
    neg = np.sum(y == 0)
    pos = np.sum(y == 1)
    if pos == 0:
        return 1.0
    return float(neg / pos)


if __name__ == "__main__":
    print("Testing data loader execution...")
    X_s, y_s, feats_s = load_drebin()
    X_d, y_d, y_m, feats_d = load_dynamic()
    print("DataLoader verification successful!")
