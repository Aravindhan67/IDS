"""
Data Ingestion, Cleaning, and Leakage-Free Preprocessing Module
Hybrid Android APK Intrusion Detection System (HIDS)
"""

import os
import logging
from typing import Tuple, List, Generator, Optional
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from imblearn.over_sampling import SMOTE, BorderlineSMOTE

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def load_drebin(
    filepath: str = "c:/ids/dataset/drebin.csv",
    drop_duplicates: bool = True
) -> Tuple[pd.DataFrame, pd.Series, List[str]]:
    """
    Loads and cleans the Drebin static analysis dataset.
    
    Data Integrity & Quality Fixes:
    - Replaces '?' with '0' in TelephonyManager.getSimCountryIso.
    - Drops any rows missing class labels.
    - Optionally drops duplicate rows to ensure realistic generalization.
    - Encodes 'S' (Suspicious/Malware) -> 1, 'B' (Benign) -> 0.
    - Memory optimization: casts binary indicators to uint8.
    
    Returns:
        X (pd.DataFrame): 215 static binary features.
        y (pd.Series): Binary labels (1 = Malware, 0 = Benign).
        feature_names (List[str]): Names of the 215 features.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Drebin dataset not found at: {filepath}")

    logger.info("Loading Drebin static dataset from %s ...", filepath)
    df = pd.read_csv(filepath)
    initial_len = len(df)
    
    # 1. Clean target column nulls
    if 'class' not in df.columns:
        raise ValueError("Missing 'class' column in Drebin dataset")
    df = df.dropna(subset=['class'])
    
    # 2. Fix non-numeric '?' in TelephonyManager.getSimCountryIso
    if 'TelephonyManager.getSimCountryIso' in df.columns:
        df['TelephonyManager.getSimCountryIso'] = (
            df['TelephonyManager.getSimCountryIso']
            .replace('?', '0')
            .fillna('0')
            .astype(int)
        )
    
    # 3. Handle duplicates
    if drop_duplicates:
        df = df.drop_duplicates()
        logger.info("Drebin deduplication: %d -> %d samples (dropped %d duplicates)", 
                    initial_len, len(df), initial_len - len(df))
    
    # 4. Separate features and target
    y_raw = df['class']
    X = df.drop(columns=['class'])
    
    # 5. Fill any remaining feature NaNs with 0 and cast to uint8
    X = X.fillna(0).astype(np.uint8)
    
    # 6. Encode target: 'S' -> 1, 'B' -> 0
    y = y_raw.map({'S': 1, 'B': 0}).astype(int)
    if y.isnull().any():
        unmapped = y_raw[y.isnull()].unique()
        raise ValueError(f"Unrecognized class labels in Drebin: {unmapped}")
        
    feature_names = X.columns.tolist()
    
    logger.info("Drebin loaded successfully: %d samples, %d features", X.shape[0], X.shape[1])
    logger.info("Class distribution: Malware (1): %d (%.2f%%), Benign (0): %d (%.2f%%)", 
                (y == 1).sum(), (y == 1).mean() * 100,
                (y == 0).sum(), (y == 0).mean() * 100)
    
    return X, y, feature_names


def load_dynamic(
    filepath: str = "c:/ids/dataset/feature_vectors_syscallsbinders_frequency_5_Cat.csv",
    drop_duplicates: bool = True
) -> Tuple[pd.DataFrame, pd.Series, pd.Series, List[str]]:
    """
    Loads and cleans the CICMalDroid dynamic syscalls & binder frequencies dataset.
    
    Data Properties:
    - 470 features (150 Linux kernel syscalls, 320 Binder & IPC categories).
    - Multi-class: Classes 1 to 5.
    - Binary mapping: Classes 1, 2, 3, 4 = Malware (1), Class 5 = Benign (0).
      Note: Class 5 (Benign) is the minority class in CICMalDroid.
      
    Returns:
        X (pd.DataFrame): 470 dynamic numerical frequency features.
        y_binary (pd.Series): Binary labels (1 = Malware, 0 = Benign).
        y_multi (pd.Series): 5-class labels (1 to 5).
        feature_names (List[str]): Names of the 470 dynamic features.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dynamic dataset not found at: {filepath}")

    logger.info("Loading dynamic syscalls/binders dataset from %s ...", filepath)
    df = pd.read_csv(filepath)
    initial_len = len(df)
    
    if 'Class' not in df.columns:
        raise ValueError("Missing 'Class' column in dynamic dataset")
    df = df.dropna(subset=['Class'])
    
    if drop_duplicates:
        df = df.drop_duplicates()
        logger.info("Dynamic deduplication: %d -> %d samples (dropped %d duplicates)",
                    initial_len, len(df), initial_len - len(df))
        
    y_multi = df['Class'].astype(int)
    # Binary mapping: 1-4 = Malware (1), 5 = Benign (0)
    y_binary = (y_multi != 5).astype(int)
    
    X = df.drop(columns=['Class']).fillna(0).astype(np.int32)
    feature_names = X.columns.tolist()
    
    logger.info("Dynamic dataset loaded: %d samples, %d features", X.shape[0], X.shape[1])
    logger.info("Binary distribution: Malware (1): %d (%.2f%%), Benign (0): %d (%.2f%%)",
                (y_binary == 1).sum(), (y_binary == 1).mean() * 100,
                (y_binary == 0).sum(), (y_binary == 0).mean() * 100)
    logger.info("Multi-class distribution: %s", y_multi.value_counts().to_dict())
    
    return X, y_binary, y_multi, feature_names


def get_stratified_splits(
    X: pd.DataFrame, 
    y: pd.Series, 
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
    
    Args:
        X_train: Training feature matrix.
        y_train: Training target array.
        method: 'none', 'smote', or 'borderline_smote'.
        random_state: Seed for reproducibility.
        
    Returns:
        X_resampled, y_resampled
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
        raise ValueError(f"Unknown resampling method: {method}. Choose from 'none', 'smote', 'borderline'.")


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
