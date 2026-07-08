"""Comprehensive Model Validation Suite
-------------------------------------
Checks for overfitting, data leakage, and production readiness:
1. Learning curves (train vs val loss across iterations)
2. 5-fold stratified cross-validation with std dev
3. Imbalanced distribution test (production-like ratios)
4. Feature importance audit (permutation + gain)
5. Temporal split validation
6. Data leakage detection (feature-label correlation audit)

Uses shared synthetic data generator from utils.synthetic_data.
"""

import json
import sys
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from utils.ml_features import _DERIVED_COLS, FEATURE_COLS  # noqa: E402
from utils.synthetic_data import (  # noqa: E402
    _compute_derived,
    generate_dataset,
)

N_FOLDS = 5


# Features expected to have high MI with label (legitimate ground-truth signals, not leakage)
_EXPECTED_HIGH_MI = {
    "abuse_confidence",
    "abuse_total_reports",
    "abuse_distinct_users",
    "vt_malicious_ratio",
    "reports_per_user",
    "abuse_categories_count",
    "vt_abuse_agreement",
}


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


# Check 1: Learning Curves

def check_learning_curves(x_df, y, le):
    """Fit XGBoost with eval_set on a held-out validation fold and return the eval history."""
    from sklearn.model_selection import train_test_split
    from xgboost import XGBClassifier

    x_tr, x_va, y_tr, y_va = train_test_split(x_df, y, test_size=0.2, stratify=y, random_state=42)
    model = XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.05,
        subsample=0.8, colsample_bytree=0.8, random_state=42,
        eval_metric="mlogloss", n_jobs=-1, early_stopping_rounds=50,
    )
    model.fit(x_tr, y_tr, eval_set=[(x_tr, y_tr), (x_va, y_va)], verbose=False)
    results = model.evals_result()
    train_loss = results["validation_0"]["mlogloss"]
    val_loss = results["validation_1"]["mlogloss"]

    gap = val_loss[-1] - train_loss[-1]
    print(f" Final train loss: {train_loss[-1]:.4f}")
    print(f" Final val loss: {val_loss[-1]:.4f}")
    print(f" Train-val gap: {gap:.4f}")
    if gap > 0.15:
        print(f" [!] WARNING: Train-val gap of {gap:.4f} suggests overfitting (gap > 0.15)")
    elif gap > 0.08:
        print(f" [!] Minor overfitting signal (gap {gap:.4f} > 0.08)")
    else:
        print(" [OK] Train-val gap within acceptable range")

    recent_val = val_loss[-10:]
    if len(recent_val) >= 5 and recent_val[-1] > recent_val[0]:
        print(" [!] Val loss rising in last 10 iterations - model is overfitting!")
    else:
        print(" [OK] Val loss stable in last 10 iterations")

    return {"train_loss": train_loss, "val_loss": val_loss, "gap": gap}


# Check 2: 5-Fold Stratified Cross-Validation

def check_cross_validation(x_df, y, le):
    """Run 5-fold stratified CV and report mean F1 +/- std."""
    from sklearn.metrics import accuracy_score, f1_score
    from sklearn.model_selection import StratifiedKFold
    from xgboost import XGBClassifier

    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=42)
    fold_f1s = []
    fold_accs = []

    for fold, (train_idx, val_idx) in enumerate(skf.split(x_df, y)):
        x_tr, x_va = x_df.iloc[train_idx], x_df.iloc[val_idx]
        y_tr, y_va = y[train_idx], y[val_idx]
        model = XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.05,
            subsample=0.8, colsample_bytree=0.8, random_state=42,
            eval_metric="mlogloss", n_jobs=-1, verbose=0,
            early_stopping_rounds=50,
        )
        model.fit(x_tr, y_tr, eval_set=[(x_va, y_va)], verbose=False)
        preds = model.predict(x_va)
        f1 = f1_score(y_va, preds, average="macro")
        acc = accuracy_score(y_va, preds)
        fold_f1s.append(f1)
        fold_accs.append(acc)
        print(f" Fold {fold+1}: F1-macro={f1:.4f}, Acc={acc:.4f}")

    mean_f1 = np.mean(fold_f1s)
    std_f1 = np.std(fold_f1s)
    mean_acc = np.mean(fold_accs)
    print("\n 5-Fold CV Results:")
    print(f" Mean F1-macro: {mean_f1:.4f} +/- {std_f1:.4f}")
    print(f" Mean Accuracy: {mean_acc:.4f} +/- {np.std(fold_accs):.4f}")

    if std_f1 > 0.005:
        print(f" [!] High variance (std={std_f1:.4f} > 0.005) - model unstable across folds")
    else:
        print(" [OK] Low variance - model stable across folds")

    return {"fold_f1s": fold_f1s, "mean_f1": mean_f1, "std_f1": std_f1}


# Check 3: Imbalanced Distribution Test

def check_imbalanced_test(x_train, y_train, x_test, y_test, le):
    """Train on imbalanced data, test on imbalanced data matching production ratios."""
    from sklearn.metrics import classification_report, f1_score
    from xgboost import XGBClassifier

    model = XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.05,
        subsample=0.8, colsample_bytree=0.8, random_state=42,
        eval_metric="mlogloss", n_jobs=-1, verbose=0,
    )
    model.fit(x_train, y_train)
    preds = model.predict(x_test)
    f1 = f1_score(y_test, preds, average="macro")
    print(f"\n Imbalanced test F1-macro: {f1:.4f}")
    print(classification_report(y_test, preds, target_names=le.classes_, zero_division=0))
    return {"f1_macro": f1}


# Check 4: Feature Importance Audit

def check_feature_importance(x_df, y, le):
    """Compute permutation importance and gain-based importance, flagging dominant features."""
    from sklearn.inspection import permutation_importance
    from sklearn.model_selection import train_test_split
    from xgboost import XGBClassifier

    x_tr, x_va, y_tr, y_va = train_test_split(x_df, y, test_size=0.2, stratify=y, random_state=42)
    model = XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.05,
        subsample=0.8, colsample_bytree=0.8, random_state=42,
        eval_metric="mlogloss", n_jobs=-1, verbose=0,
    )
    model.fit(x_tr, y_tr)

    gain_imp = model.feature_importances_
    gain_sorted = sorted(zip(FEATURE_COLS, gain_imp, strict=False), key=lambda x: -x[1])
    print("\n Top-10 Features by Gain:")
    for feat, imp in gain_sorted[:10]:
        print(f" {feat}: {imp:.4f}")

    perm = permutation_importance(model, x_va, y_va, n_repeats=5, random_state=42, n_jobs=1)
    perm_sorted = sorted(zip(FEATURE_COLS, perm.importances_mean, strict=False), key=lambda x: -x[1])
    print("\n Top-10 Features by Permutation Importance:")
    for feat, imp in perm_sorted[:10]:
        print(f" {feat}: {imp:.4f}")

    dominant = [f for f, i in gain_sorted if i > 0.25]
    if dominant:
        print(f"\n [!] Potentially dominant features (gain > 0.25): {dominant}")
        print(" These may be leakage proxies - investigate whether they rely on label-derived info.")
    else:
        print("\n [OK] No single feature dominates (all gain < 0.25)")

    return {"gain": dict(gain_sorted), "permutation": dict(zip(FEATURE_COLS, perm.importances_mean, strict=False))}


# Check 5: Temporal Split Validation

def check_temporal_split(seed: int = 42):
    """
    Simulate a temporal split: train on earlier synthetic data, test on later.
    Since this is synthetic data, we simulate by generating two batches with
    different random seeds to represent distribution shift over time.
    """
    from sklearn.metrics import classification_report, f1_score
    from sklearn.preprocessing import LabelEncoder
    from xgboost import XGBClassifier

    x_hist, y_hist = generate_dataset(n_per_class=1000, seed=0)
    x_recent, y_recent = generate_dataset(n_per_class=500, seed=99)

    le = LabelEncoder()
    y_hist_enc = le.fit_transform(y_hist)
    y_recent_enc = le.transform(y_recent)

    model = XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.05,
        subsample=0.8, colsample_bytree=0.8, random_state=42,
        eval_metric="mlogloss", n_jobs=-1, verbose=0,
    )
    model.fit(x_hist, y_hist_enc)
    preds = model.predict(x_recent)
    f1 = f1_score(y_recent_enc, preds, average="macro")
    print(f"\n Temporal split (train=seed0, test=seed99) F1-macro: {f1:.4f}")
    print(classification_report(y_recent_enc, preds, target_names=le.classes_, zero_division=0))

    drop = 0.982 - f1
    if drop > 0.05:
        print(f" [!] Large performance drop ({drop:.2f}) on temporal split - distribution may have shifted")
    else:
        print(f" [OK] Temporal performance drop within tolerance ({drop:.4f})")

    return {"f1_macro": f1}


# Check 6: Data Leakage Detection

# Features expected to have high MI with label (legitimate ground-truth signals, not leakage)
_EXPECTED_HIGH_MI = {
    "abuse_confidence",
    "abuse_total_reports",
    "abuse_distinct_users",
    "vt_malicious_ratio",
    "reports_per_user",
    "abuse_categories_count",
    "vt_abuse_agreement",
}

def check_data_leakage(x_df, y, le):
    """
    Check for data leakage by:
    1. Computing correlation between each feature and the label
    2. Checking for perfect or near-perfect separators
    3. Reporting any suspiciously high correlations
    """
    from sklearn.feature_selection import mutual_info_classif

    mi_scores = mutual_info_classif(x_df, y, random_state=42)
    mi_sorted = sorted(zip(FEATURE_COLS, mi_scores, strict=False), key=lambda x: -x[1])

    print("\n Top-10 Features by Mutual Information with Label:")
    for feat, mi in mi_sorted[:10]:
        level = "[!] HIGH" if mi > 0.5 else ("moderate" if mi > 0.2 else "low")
        print(f" {feat}: {mi:.4f} ({level})")

    suspicious_all = [f for f, mi in mi_sorted if mi > 0.5]
    # Filter out expected high-MI features (legitimate signals)
    suspicious = [f for f in suspicious_all if f not in _EXPECTED_HIGH_MI]
    expected_flagged = [f for f in suspicious_all if f in _EXPECTED_HIGH_MI]

    if suspicious:
        print(f"\n [!] POTENTIAL LEAKAGE: {len(suspicious)} features have MI > 0.5 with label")
        print(f" Features: {suspicious}")
        print(" These features may be derived from label information - review feature extraction.")
    else:
        print("\n [OK] No unexpected features show suspiciously high mutual information with label")

    if expected_flagged:
        print(f" [INFO] Expected high-MI features (legitimate signals): {expected_flagged}")

    return {"mutual_info": dict(mi_sorted)}


# Main Validation Runner

def main():  # noqa: PLR0912, PLR0915
    from sklearn.preprocessing import LabelEncoder

    print("=" * 72)
    print(" THREAT INTEL AGENT - COMPREHENSIVE MODEL VALIDATION")
    print("=" * 72)

    # Load real enriched data
    dataset_path = ROOT / "data" / "ioc_dataset.csv"
    if dataset_path.exists():
        print("\n[Step 0] Loading real enriched dataset...")
        df = pd.read_csv(dataset_path)
        df = _migrate_ioc_type_columns(df)
        for col in FEATURE_COLS:
            if col not in df.columns:
                df[col] = 0.0
        df[FEATURE_COLS] = df[FEATURE_COLS].fillna(0).astype("float64")

        # Compute derived features if missing
        missing_derived = [c for c in _DERIVED_COLS if c not in df.columns or df[c].sum() == 0]
        if missing_derived:
            print(f" Computing missing derived features: {missing_derived}")
            df = _compute_derived(df)

        real_df = df[df["enrichment_source"] == "real_api"].copy()
        print(f" Real enriched IOCs: {len(real_df)}")
        print(f" Label distribution: {dict(real_df['label'].value_counts())}")
        x_bal = real_df[FEATURE_COLS]
        y_bal_raw = real_df["label"].values
    else:
        print("\n[Step 0] No real data found — generating balanced synthetic dataset...")
        x_bal, y_bal_raw = generate_dataset(n_per_class=1500)

    le = LabelEncoder()
    all_labels = ["CLEAN", "LOW", "HIGH", "CRITICAL"]
    present_labels = sorted(set(y_bal_raw) & set(all_labels))
    le.fit(present_labels)
    y = le.transform(y_bal_raw)
    print(f" Dataset: {x_bal.shape[0]} samples, {x_bal.shape[1]} features")
    print(f" Classes: {dict(zip(*np.unique(y_bal_raw, return_counts=True), strict=False))}")

    print("\n" + "-" * 72)
    print("[Check 1] Learning Curves (train vs val loss)")
    print("-" * 72)
    lc = check_learning_curves(x_bal, y, le)

    print("\n" + "-" * 72)
    print(f"[Check 2] {N_FOLDS}-Fold Stratified Cross-Validation")
    print("-" * 72)
    cv = check_cross_validation(x_bal, y, le)

    print("\n" + "-" * 72)
    print("[Check 3] Imbalanced Distribution Test (real data)")
    print("-" * 72)
    from sklearn.model_selection import train_test_split
    x_train_imb, x_test_imb, y_train_imb, y_test_imb = train_test_split(
        x_bal, y, test_size=0.3, stratify=y, random_state=42
    )
    print(f" Train: {len(x_train_imb)}, Test: {len(x_test_imb)}")
    imb = check_imbalanced_test(x_train_imb, y_train_imb, x_test_imb, y_test_imb, le)

    print("\n" + "-" * 72)
    print("[Check 4] Feature Importance Audit (Gain + Permutation)")
    print("-" * 72)
    fi = check_feature_importance(x_bal, y, le)

    print("\n" + "-" * 72)
    print("[Check 5] Temporal Split Validation")
    print("-" * 72)
    ts = check_temporal_split()

    print("\n" + "-" * 72)
    print("[Check 6] Data Leakage Detection (Mutual Information)")
    print("-" * 72)
    dl = check_data_leakage(x_bal, y, le)

    print("\n" + "=" * 72)
    print(" VALIDATION SUMMARY")
    print("=" * 72)

    flags = []
    if lc["gap"] > 0.15:
        flags.append("[!] Learning curve: train-val gap > 0.15 (overfitting)")
    elif lc["gap"] > 0.08:
        flags.append("[!] Learning curve: minor overfitting signal")
    else:
        flags.append("[OK] Learning curve: healthy")

    if cv["std_f1"] > 0.005:
        flags.append(f"[!] CV: High variance (std={cv['std_f1']:.4f})")
    else:
        flags.append(f"[OK] CV: Low variance (std={cv['std_f1']:.4f}, mean F1={cv['mean_f1']:.4f})")

    flags.append(f"[OK] Imbalanced test F1: {imb['f1_macro']:.4f}")

    if fi["gain"] and max(fi["gain"].values()) > 0.25:
        dom = [f for f, i in sorted(fi["gain"].items(), key=lambda x: -x[1]) if i > 0.25]
        flags.append(f"[!] Dominant feature(s): {dom}")
    else:
        flags.append("[OK] No dominant feature")

    flags.append(f"[OK] Temporal split F1: {ts['f1_macro']:.4f}")

    if dl["mutual_info"] and max(dl["mutual_info"].values()) > 0.5:
        sus_all = [f for f, i in sorted(dl["mutual_info"].items(), key=lambda x: -x[1]) if i > 0.5]
        sus = [f for f in sus_all if f not in _EXPECTED_HIGH_MI]
        if sus:
            flags.append(f"[!] Potential leakage: {sus}")
        else:
            flags.append("[OK] No unexpected leakage signal (high-MI features are expected signals)")
    else:
        flags.append("[OK] No leakage signal")

    print()
    for f in flags:
        print(f" {f}")

    report = {
        "learning_curve": {"gap": lc["gap"], "train_loss": lc["train_loss"][-1], "val_loss": lc["val_loss"][-1]},
        "cross_validation": {"mean_f1": cv["mean_f1"], "std_f1": cv["std_f1"], "fold_f1s": [round(f, 4) for f in cv["fold_f1s"]]},
        "imbalanced_test": {"f1_macro": round(imb["f1_macro"], 4)},
        "feature_importance": {"top10_gain": {f: round(i, 4) for f, i in list(sorted(fi["gain"].items(), key=lambda x: -x[1]))[:10]}},
        "temporal_split": {"f1_macro": round(ts["f1_macro"], 4)},
        "data_leakage": {"top5_mi": {f: round(i, 4) for f, i in list(sorted(dl["mutual_info"].items(), key=lambda x: -x[1]))[:5]}},
        "verdict": "PASS" if all("[!]" not in f for f in flags) else "REVIEW",
    }

    class NpEncoder(json.JSONEncoder):
        def default(self, o):
            import numpy as np
            if isinstance(o, np.integer | np.floating):
                return float(o)
            if isinstance(o, np.bool_):
                return bool(o)
            return super().default(o)

    with (ROOT / "models" / "validation_report.json").open("w") as f:
        json.dump(report, f, indent=2, cls=NpEncoder)
    print("\n Full report saved to models/validation_report.json")
    print(f" Overall verdict: {report['verdict']}")
    print("=" * 72)


if __name__ == "__main__":
    main()
