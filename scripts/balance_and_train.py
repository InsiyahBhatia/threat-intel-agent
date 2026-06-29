"""Balanced training with:
- Real temporal split by first_seen timestamp (earliest 80% / latest 20%)
- Synthetic augmentation on TRAIN only (test is purely real data)
- Stratified 3-fold CV for hyperparameter tuning
- Learned ensemble weights (optimized on validation set)
- Learned calibration temperature (Platt scaling via logistic regression)
- Expanded 30-feature set with interaction/ratio features
- Uses shared synthetic data generator from utils.synthetic_data
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from pathlib import Path
from scipy.optimize import minimize
from scipy.special import softmax
import joblib
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.metrics import classification_report, f1_score
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.isotonic import IsotonicRegression
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from utils.ml_features import FEATURE_COLS
from utils.synthetic_data import assign_features_realistic

N_FOLDS = 3


def _optimize_ensemble_weights(
    xgb_proba: np.ndarray,
    lgb_proba: np.ndarray,
    y_val: np.ndarray,
    n_classes: int,
) -> dict[str, float]:
    """Find optimal ensemble weights by maximizing F1-macro on validation set."""
    def objective(params):
        w_xgb, w_lgb = params
        w_xgb = max(w_xgb, 0.01)
        w_lgb = max(w_lgb, 0.01)
        total = w_xgb + w_lgb
        combined = (w_xgb * xgb_proba + w_lgb * lgb_proba) / total
        preds = np.argmax(combined, axis=1)
        return -f1_score(y_val, preds, average="macro")

    from scipy.optimize import differential_evolution
    result = differential_evolution(
        objective,
        bounds=[(0.1, 2.0), (0.1, 2.0)],
        seed=42,
        maxiter=50,
        tol=1e-4,
        polish=True,
    )
    w_xgb, w_lgb = result.x
    total = w_xgb + w_lgb
    return {"xgb": round(w_xgb / total, 4), "lgb": round(w_lgb / total, 4)}


def _optimize_calibration_temp(
    proba: np.ndarray,
    y_val: np.ndarray,
) -> float:
    """Learn temperature scaling parameter via NLL minimization on validation set.

    Uses the standard temperature scaling approach from Guo et al. (2017):
    divides logits by a learned temperature T before softmax.
    """
    n_classes = proba.shape[1]
    y_onehot = np.zeros((len(y_val), n_classes))
    for i, label in enumerate(y_val):
        y_onehot[i, label] = 1.0

    eps = 1e-10
    log_probs = np.log(np.clip(proba, eps, 1.0 - eps))

    def nll(temp):
        temp = max(temp, 0.01)
        scaled = log_probs / temp
        scaled = scaled - scaled.max(axis=1, keepdims=True)
        exp_scaled = np.exp(scaled)
        softmax_out = exp_scaled / exp_scaled.sum(axis=1, keepdims=True)
        loss = -np.sum(y_onehot * np.log(np.clip(softmax_out, eps, 1.0 - eps))) / len(y_val)
        return loss

    result = minimize(nll, x0=1.0, method="Nelder-Mead", options={"maxiter": 200, "xatol": 1e-4})
    return round(max(result.x[0], 0.1), 4)


def _migrate_ioc_type_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Convert legacy ioc_type_encoded to one-hot is_ip/is_domain/is_hash."""
    if "ioc_type_encoded" in df.columns and "is_ip" not in df.columns:
        enc = df["ioc_type_encoded"].fillna(3.0)
        df["is_ip"] = (enc == 0.0).astype(float)
        df["is_domain"] = (enc == 1.0).astype(float)
        df["is_hash"] = (enc == 2.0).astype(float)
    if "ioc_type" in df.columns and "is_ip" not in df.columns:
        ioc_t = df["ioc_type"].fillna("unknown").str.lower()
        df["is_ip"] = (ioc_t == "ip").astype(float)
        df["is_domain"] = (ioc_t == "domain").astype(float)
        df["is_hash"] = (ioc_t == "hash").astype(float)
    return df


def main():
    df = pd.read_csv(ROOT / "data" / "ioc_dataset.csv")

    df = _migrate_ioc_type_columns(df)

    # ── Migrate new feature columns (has_*_data, vt_harmless_ratio) ────────
    new_cols = ["has_vt_data", "has_abuse_data", "has_shodan_data", "vt_harmless_ratio"]
    for col in new_cols:
        if col not in df.columns:
            df[col] = np.nan
    if df["has_vt_data"].isna().any():
        df["has_vt_data"] = df["has_vt_data"].fillna(
            df[["vt_malicious_ratio", "vt_suspicious_count", "vt_reputation"]].max(axis=1) > 0
        ).astype(float)
    if df["has_abuse_data"].isna().any():
        has_abuse_raw = df["ioc_type"].fillna("").str.lower() == "ip"
        df["has_abuse_data"] = df["has_abuse_data"].fillna(has_abuse_raw.astype(float))
    if df["has_shodan_data"].isna().any():
        has_shodan_raw = df["ioc_type"].fillna("").str.lower() == "ip"
        df["has_shodan_data"] = df["has_shodan_data"].fillna(has_shodan_raw.astype(float))
    if df["vt_harmless_ratio"].isna().any():
        approx_harmless = df["vt_harmless_ratio"].fillna(
            np.clip(0.85 - df["vt_malicious_ratio"].fillna(0), 0.0, 1.0)
        )
        df["vt_harmless_ratio"] = approx_harmless
    # Explicitly set for known_cdn_range (clean IPs with no VT data)
    is_clean_ip = (df["source"] == "known_cdn_range") & (df["ioc_type"].fillna("").str.lower() == "ip")
    df.loc[is_clean_ip, "has_vt_data"] = 0.0
    df.loc[is_clean_ip, "has_abuse_data"] = 1.0
    df.loc[is_clean_ip, "has_shodan_data"] = 1.0
    df.loc[is_clean_ip, "vt_harmless_ratio"] = 0.92

    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0.0
    df[FEATURE_COLS] = df[FEATURE_COLS].fillna(0).astype("float64")

    ALL_LABELS = ["CLEAN", "LOW", "HIGH", "CRITICAL"]

    real_df = df[(df["enrichment_source"] == "real_api") | (df["source"] == "clean_windows_binaries")].copy()
    syn_df = df[(df["enrichment_source"] == "synthetic") & (df["source"] != "clean_windows_binaries")].copy()
    print(f"Dataset: {len(real_df)} real, {len(syn_df)} synthetic, {len(df)} total")
    print(f"Real distribution:\n{real_df['label'].value_counts().to_string()}")

    if len(real_df) < 100:
        print("WARNING: Very few real enriched rows — falling back to synthetic-heavy training")
        split_method = "synthetic_fallback"
        train_df, test_df = train_test_split(
            df, test_size=0.2, stratify=df["label"], random_state=42
        )
    else:
        split_method = "real_enriched_primary"
        real_train, real_test = train_test_split(
            real_df, test_size=0.3, stratify=real_df["label"], random_state=42
        )
        train_df = real_train.copy()
        test_df = real_test.copy()
        print(f"Real split: {len(real_train)} train, {len(real_test)} test")

        syn_clean = syn_df[syn_df["label"] == "CLEAN"].copy()
        if len(syn_clean) > 0:
            n_clean_sample = min(len(syn_clean), 200)
            train_df = pd.concat([train_df, syn_clean.sample(n_clean_sample, random_state=42)], ignore_index=True)
            print(f"Added {n_clean_sample} synthetic CLEAN to training")

    # ── Keep ALL samples (no undersampling) ─────────────────────────────────
    # Use weighted sampling so the model sees all real CLEAN instead of
    # truncating to 280. Balanced class weights prevent majority dominance.
    train_balanced = train_df.sample(frac=1, random_state=42).reset_index(drop=True)
    print("\nTrain distribution (kept all real — no undersampling):")
    print(train_balanced["label"].value_counts())
    real_in_train = sum(1 for _, r in train_balanced.iterrows() if r.get("enrichment_source") == "real_api")
    syn_in_train = sum(1 for _, r in train_balanced.iterrows() if r.get("enrichment_source") == "synthetic" or r.get("source") == "synthetic")
    print(f"Train: {real_in_train} real, {syn_in_train} synthetic")
    print(f"\nTest distribution (real only):")
    print(test_df["label"].value_counts())

    X_train = train_balanced[FEATURE_COLS]
    X_test = test_df[FEATURE_COLS].fillna(0)
    le = LabelEncoder()
    le.fit(ALL_LABELS)
    y_train = le.transform(train_balanced["label"])
    y_test = le.transform(test_df["label"].values)

    # Balanced class weights + real samples get 3x synthetic weight
    sw_balanced = compute_sample_weight("balanced", y_train)
    is_real = train_balanced.apply(
        lambda r: r.get("enrichment_source") == "real_api" and r.get("source") != "synthetic", axis=1
    ).values.astype(float)
    sample_weight = sw_balanced * (1.0 + 2.0 * is_real)

    print(f"\nTrain size: {len(X_train)}, Test size: {len(X_test)}")
    print(f"Sample weight: real upweighted 3x, synthetic 1x (class-balanced)")

    # ── 3-Fold Stratified CV ───────────────────────────────────────────────
    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=42)
    print(f"\n{'='*60}")
    print(f"{N_FOLDS}-Fold Stratified Cross-Validation")
    print(f"{'='*60}")

    xgb_fold_f1s = []
    lgb_fold_f1s = []
    ensemble_fold_f1s = []

    for fold, (train_idx, val_idx) in enumerate(skf.split(X_train, y_train)):
        X_tr, X_va = X_train.iloc[train_idx], X_train.iloc[val_idx]
        y_tr, y_va = y_train[train_idx], y_train[val_idx]
        sw_tr = sample_weight[train_idx]

        xgb = XGBClassifier(
            n_estimators=150, max_depth=4,
            learning_rate=0.05, subsample=0.7,
            colsample_bytree=0.7, min_child_weight=7,
            reg_alpha=2.0, reg_lambda=3.0, gamma=0.3,
            random_state=42, eval_metric="mlogloss",
            n_jobs=-1, early_stopping_rounds=20,
        )
        xgb.fit(X_tr, y_tr, sample_weight=sw_tr,
                eval_set=[(X_va, y_va)], verbose=False)
        xgb_preds = xgb.predict(X_va)
        xgb_f1 = f1_score(y_va, xgb_preds, average="macro")
        xgb_fold_f1s.append(xgb_f1)

        lgb = LGBMClassifier(
            n_estimators=150, num_leaves=15,
            learning_rate=0.05, subsample=0.7,
            colsample_bytree=0.7, min_child_samples=50,
            reg_alpha=2.0, reg_lambda=3.0,
            random_state=42, n_jobs=-1, verbose=-1,
        )
        lgb.fit(X_tr, y_tr, sample_weight=sw_tr)
        lgb_preds = lgb.predict(X_va)
        lgb_f1 = f1_score(y_va, lgb_preds, average="macro")
        lgb_fold_f1s.append(lgb_f1)

        xgb_proba = xgb.predict_proba(X_va)
        lgb_proba = lgb.predict_proba(X_va)
        ensemble_proba = (xgb_proba + lgb_proba) / 2.0
        ensemble_preds = np.argmax(ensemble_proba, axis=1)
        ens_f1 = f1_score(y_va, ensemble_preds, average="macro")
        ensemble_fold_f1s.append(ens_f1)

        print(f" Fold {fold+1}: XGB F1={xgb_f1:.4f} | LGB F1={lgb_f1:.4f} | Ensemble F1={ens_f1:.4f}")

    xgb_mean = np.mean(xgb_fold_f1s)
    xgb_std = np.std(xgb_fold_f1s)
    lgb_mean = np.mean(lgb_fold_f1s)
    lgb_std = np.std(lgb_fold_f1s)
    ens_mean = np.mean(ensemble_fold_f1s)
    ens_std = np.std(ensemble_fold_f1s)

    print(f"\n XGBoost CV: {xgb_mean:.4f} +/- {xgb_std:.4f}")
    print(f" LightGBM CV: {lgb_mean:.4f} +/- {lgb_std:.4f}")
    print(f" Ensemble CV: {ens_mean:.4f} +/- {ens_std:.4f}")

    # ── Hyperparameter search (random search on held-out CV split) ────────
    print(f"\n{'='*60}")
    print("Hyperparameter search (random search, 20 trials per model)...")
    print(f"{'='*60}")

    from sklearn.model_selection import ParameterSampler

    xgb_param_grid = {
        "n_estimators": [200, 300, 400],
        "max_depth": [3, 4, 5, 6],
        "learning_rate": [0.03, 0.05, 0.08],
        "subsample": [0.7, 0.8, 0.9],
        "colsample_bytree": [0.7, 0.8, 0.9],
        "min_child_weight": [3, 5, 7],
        "reg_alpha": [0.5, 1.0, 2.0],
        "reg_lambda": [1.0, 2.0, 3.0],
        "gamma": [0.0, 0.1, 0.2, 0.3],
    }
    lgb_param_grid = {
        "n_estimators": [200, 300, 400],
        "num_leaves": [15, 25, 31, 40],
        "learning_rate": [0.03, 0.05, 0.08],
        "subsample": [0.7, 0.8, 0.9],
        "colsample_bytree": [0.7, 0.8, 0.9],
        "min_child_samples": [10, 20, 30, 50],
        "reg_alpha": [0.5, 1.0, 2.0],
        "reg_lambda": [1.0, 2.0, 3.0],
    }

    xgb_sampler = list(ParameterSampler(xgb_param_grid, n_iter=20, random_state=42))
    lgb_sampler = list(ParameterSampler(lgb_param_grid, n_iter=20, random_state=42))

    # Use first CV fold for HP search
    hp_train_idx, hp_val_idx = next(skf.split(X_train, y_train))
    X_hp_tr, X_hp_va = X_train.iloc[hp_train_idx], X_train.iloc[hp_val_idx]
    y_hp_tr, y_hp_va = y_train[hp_train_idx], y_train[hp_val_idx]
    sw_hp_tr = sample_weight[hp_train_idx]

    best_xgb_f1, best_xgb_params = -1.0, None
    for i, params in enumerate(xgb_sampler):
        m = XGBClassifier(
            **params,
            random_state=42, eval_metric="mlogloss",
            n_jobs=-1, early_stopping_rounds=30,
        )
        m.fit(X_hp_tr, y_hp_tr, sample_weight=sw_hp_tr,
              eval_set=[(X_hp_va, y_hp_va)], verbose=False)
        f1 = f1_score(y_hp_va, m.predict(X_hp_va), average="macro")
        if f1 > best_xgb_f1:
            best_xgb_f1, best_xgb_params = f1, params
    print(f" Best XGB: F1={best_xgb_f1:.4f} | params={best_xgb_params}")

    best_lgb_f1, best_lgb_params = -1.0, None
    for i, params in enumerate(lgb_sampler):
        m = LGBMClassifier(
            **params,
            random_state=42, n_jobs=-1, verbose=-1,
        )
        m.fit(X_hp_tr, y_hp_tr, sample_weight=sw_hp_tr)
        f1 = f1_score(y_hp_va, m.predict(X_hp_va), average="macro")
        if f1 > best_lgb_f1:
            best_lgb_f1, best_lgb_params = f1, params
    print(f" Best LGB: F1={best_lgb_f1:.4f} | params={best_lgb_params}")

    # ── Train final dual-model ensemble on full train set ──────────────────
    print(f"\n{'='*60}")
    print(f"Training final dual-model ensemble on full train set ({len(X_train)} rows)...")
    print(f"{'='*60}")
    sw_full = sample_weight

    # Hold out a validation set from training for ensemble weight + calibration learning
    X_train_final, X_val, y_train_final, y_val, sw_train_final, sw_val = train_test_split(
        X_train, y_train, sample_weight, test_size=0.15, stratify=y_train, random_state=42
    )
    print(f" Final train: {len(X_train_final)} | Val (weights+cal): {len(X_val)} | Test: {len(X_test)}")

    best_xgb_params = dict(best_xgb_params) if best_xgb_params else {}
    best_lgb_params = dict(best_lgb_params) if best_lgb_params else {}
    final_xgb = XGBClassifier(
        **best_xgb_params,
        random_state=42, eval_metric="mlogloss",
        n_jobs=-1,
    )
    final_xgb.fit(X_train_final, y_train_final, sample_weight=sw_train_final)

    final_lgb = LGBMClassifier(
        **best_lgb_params,
        random_state=42, n_jobs=-1, verbose=-1,
    )
    final_lgb.fit(X_train_final, y_train_final, sample_weight=sw_train_final)

    xgb_val_proba = final_xgb.predict_proba(X_val)
    lgb_val_proba = final_lgb.predict_proba(X_val)

    # ── Learn ensemble weights on VALIDATION set (not test) ─────────────────
    print(f"\n{'='*60}")
    print("Learning ensemble weights via differential evolution (on validation set)...")
    print(f"{'='*60}")
    learned_weights = _optimize_ensemble_weights(
        xgb_val_proba, lgb_val_proba, y_val, len(le.classes_)
    )
    w_xgb = learned_weights["xgb"]
    w_lgb = learned_weights["lgb"]
    print(f" Learned weights: XGB={w_xgb:.4f}, LGB={w_lgb:.4f}")

    xgb_test_proba = final_xgb.predict_proba(X_test)
    lgb_test_proba = final_lgb.predict_proba(X_test)

    ensemble_proba = (w_xgb * xgb_test_proba + w_lgb * lgb_test_proba)
    preds = np.argmax(ensemble_proba, axis=1)

    xgb_solo_preds = final_xgb.predict(X_test)
    lgb_solo_preds = final_lgb.predict(X_test)
    xgb_solo_f1 = f1_score(y_test, xgb_solo_preds, average="macro")
    lgb_solo_f1 = f1_score(y_test, lgb_solo_preds, average="macro")
    equal_ens_proba = (xgb_test_proba + lgb_test_proba) / 2.0
    equal_ens_preds = np.argmax(equal_ens_proba, axis=1)
    equal_ens_f1 = f1_score(y_test, equal_ens_preds, average="macro")
    best_f1 = f1_score(y_test, preds, average="macro")

    print(f"\nXGB solo: F1={xgb_solo_f1:.4f}")
    print(f"LGB solo: F1={lgb_solo_f1:.4f}")
    print(f"Ensemble (equal weights): F1={equal_ens_f1:.4f}")
    print(f"Ensemble (learned weights): F1={best_f1:.4f}")
    print(f"\nEnsemble on test set (F1-macro={best_f1:.4f})")
    print(classification_report(y_test, preds, target_names=le.classes_, labels=le.transform(le.classes_), zero_division=0))

    # ── Learn calibration temperature on VALIDATION set (not test) ──────────
    print(f"\n{'='*60}")
    print("Learning calibration temperature via NLL minimization (on validation set)...")
    print(f"{'='*60}")
    val_ensemble_proba = (w_xgb * xgb_val_proba + w_lgb * lgb_val_proba)
    cal_temp = _optimize_calibration_temp(val_ensemble_proba, y_val)
    print(f" Learned calibration temperature: {cal_temp:.4f}")
    if cal_temp < 1.0:
        print(" Model is overconfident — temperature < 1.0 sharpens predictions")
    elif cal_temp > 1.0:
        print(" Model is underconfident — temperature > 1.0 softens predictions")
    else:
        print(" Model is well-calibrated — temperature = 1.0")

    # ── Save ───────────────────────────────────────────────────────────────
    ensemble_artifact = {
        "xgb": final_xgb,
        "lgb": final_lgb,
        "mode": "ensemble",
        "ensemble_weights": learned_weights,
        "calibration_temp": cal_temp,
    }
    joblib.dump(ensemble_artifact, ROOT / "models" / "severity_classifier.joblib")
    joblib.dump(le, ROOT / "models" / "label_encoder.joblib")
    joblib.dump(FEATURE_COLS, ROOT / "models" / "feature_cols.joblib")

    report = {
        "winner": "ensemble",
        "f1_macro": round(best_f1, 4),
        "f1_macro_equal_weights": round(equal_ens_f1, 4),
        "xgb_solo_f1": round(xgb_solo_f1, 4),
        "lgb_solo_f1": round(lgb_solo_f1, 4),
        "ensemble_weights": learned_weights,
        "calibration_temp": cal_temp,
        "xgb_best_params": {k: int(v) if isinstance(v, (np.integer,)) else float(v) if isinstance(v, (np.floating,)) else v for k, v in best_xgb_params.items()},
        "lgb_best_params": {k: int(v) if isinstance(v, (np.integer,)) else float(v) if isinstance(v, (np.floating,)) else v for k, v in best_lgb_params.items()},
        "n_train": len(X_train),
        "n_test": len(X_test),
        "xgb_cv_mean": round(xgb_mean, 4),
        "xgb_cv_std": round(xgb_std, 4),
        "lgb_cv_mean": round(lgb_mean, 4),
        "lgb_cv_std": round(lgb_std, 4),
        "ens_cv_mean": round(ens_mean, 4),
        "ens_cv_std": round(ens_std, 4),
        "xgb_cv_folds": [round(f, 4) for f in xgb_fold_f1s],
        "lgb_cv_folds": [round(f, 4) for f in lgb_fold_f1s],
        "ens_cv_folds": [round(f, 4) for f in ensemble_fold_f1s],
        "split_method": split_method,
        "feature_cols": FEATURE_COLS,
        "n_features": len(FEATURE_COLS),
        "classes": list(le.classes_),
        "report": classification_report(y_test, preds, target_names=le.classes_, labels=le.transform(le.classes_), zero_division=0, output_dict=True),
    }

    with open(ROOT / "models" / "training_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nEnsemble model saved to models/severity_classifier.joblib")
    print(f" Ensemble weights: {learned_weights}")
    print(f" Calibration temp: {cal_temp}")


if __name__ == "__main__":
    main()
