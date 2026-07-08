# Threat Intel Agent — Model Training Pipeline

Complete documentation of the data collection, processing, training, and validation workflow for the ML severity classifier.

---

## 1. Data Collection

### 1.1 Real Enriched IOCs (Production Data)
**2,114 IOCs** collected from 4 OSINT APIs in parallel (~3-4s per IOC):
- VirusTotal (500 req/day), Shodan (host lookup), AbuseIPDB (1000 checks/day), AlienVault OTX (unlimited)
- Cached in SQLite (24h TTL), appended to `ioc_dataset.csv`

**Label distribution:** HIGH (905) | CRITICAL (530) | LOW (400) | CLEAN (279)

### 1.2 Known-Clean Sources (Negative Class)
**3,253 verified clean IPs** from:
- Tranco Top-1K domains
- Cloudflare CDN/proxy ranges  
- AWS/GCP/Azure cloud provider ranges

All verified via VirusTotal (0 detections = CLEAN). Critical: `has_vt_data=1` so model learns "VT queried + 0 detections = CLEAN" not "no VT data = CLEAN".

### 1.3 Synthetic Augmentation
**200 synthetic samples** (50 per class) generated via `utils/synthetic_data.py`:
- Per-class Gaussian distributions calibrated to real data moments
- One-hot constraint: `is_ip + is_domain + is_hash ≤ 1`
- Used only for class balancing during training

---

## 2. Feature Engineering (35 Total)

| Category | Features |
|----------|----------|
| **Base (21)** | VT: `malicious_ratio`, `suspicious_count`, `reputation` • AbuseIPDB: `confidence`, `total_reports`, `distinct_users`, `is_tor`, `categories_count` • Shodan: `open_ports`, `cve_count`, `port_22/445/3389` • Tags: `tag_count`, `has_known_family` • IOC type: `is_ip`, `is_domain`, `is_hash`, `is_tor` • OTX: `pulse_count`, `avg_confidence`, `has_scan` |
| **Derived (9)** | `vt_abuse_agreement`, `threat_signal_sum`, `port_attack_surface`, `cve_per_port`, `reports_per_user`, `tor_reputation_risk`, `otx_vt_corroboration`, `shodan_exposure_score`, `has_malicious_vt_tags` |
| **Indicators (6)** | `has_vt_data`, `has_abuse_data`, `has_shodan_data`, `vt_harmless_ratio`, `has_malicious_vt_tags`, raw tag arrays |

**Removed:** `malicious_family` (vt_malicious_ratio × has_known_family) — 45% gain but label proxy.

---

## 3. Data Processing Pipeline

```
ioc_dataset.csv → Migrate legacy columns → Fill missing → Compute derived → Temporal split → Sample weights
```

1. **Legacy migration** — `ioc_type_encoded` (0/1/2) → one-hot `is_ip/is_domain/is_hash`
2. **Missing feature computation** — Runs `_compute_derived()` on incomplete rows
3. **Temporal split** — By `first_seen` date (prevents campaign leakage vs random split)
4. **Sample weights** — `compute_sample_weight("balanced")` ×3 for real, ×1 for synthetic

---

## 4. Model Training

### 4.1 Dual-Model Ensemble

| Model | Key Params |
|-------|------------|
| **XGBoost** | max_depth=4, lr=0.08, subsample=0.9, colsample=0.8, reg_α=0.0.5, reg_λ=2.0, min_child=5, gamma=0.2, n_est=200 |
| **LightGBM** | num_leaves=40, lr=0.08, subsample=0.9, colsample=0.9, reg_α=2.0, reg_λ=3.0, min_child=10, n_est=300 |

**Ensemble weights:** Learned via differential evolution on validation set → **XGB=0.64, LGB=0.36**

**Calibration:** Temperature scaling (T=1.1) learned via NLL minimization on validation set.

### 4.2 Training Process (`scripts/balance_and_train.py`)

```
4,732 samples → 3-way split (4,022 train / 710 val / 1,449 test)
    → 3-fold CV on train → Hyperopt (20 trials/model)
    → Learn ensemble weights on val → Learn calibration on val
    → Retrain on train+val → Evaluate on held-out test
```

### 4.3 CRITICAL Confidence Floor (Post-Processing)

```
If predicted_class == CRITICAL and probability < 0.75:
    Downgrade to 2nd highest class (usually HIGH)
```

**Rationale:** Analyst-first design — better to flag borderline CRITICAL as HIGH for review than fire false CRITICAL alerts. Caught 7 borderline cases on test set with zero recall loss.

---

## 5. Validation Results

### 5.1 Held-Out Test Set (1,449 real IOCs)

| Class | Precision | Recall | F1 | Support |
|-------|-----------|--------|-----|---------|
| **CLEAN** | 1.00 | 0.93 | **0.96** | 898 |
| **CRITICAL** | 0.80 | 0.86 | **0.82** | 159 |
| **HIGH** | 0.84 | 1.00 | **0.91** | 272 |
| **LOW** | 0.97 | 0.94 | **0.96** | 120 |
| **Macro** | 0.90 | 0.93 | **0.913** | 1,449 |

**Accuracy: 94%** | **3-fold CV F1-macro: 0.894 ± 0.009** | **Test F1-macro: 0.913**

### 5.2 Comprehensive Validation Suite (`scripts/validate_model.py`)

| Check | Result |
|-------|--------|
| 1. Learning Curves | Gap 0.153 (minor overfit — bare XGB on small data) |
| 2. 5-Fold CV (real only) | F1=0.780 ± 0.015 |
| 3. Imbalanced Test | F1=0.784 (production ratios) |
| 4. Feature Importance | Max gain=0.196 (`has_known_family`) ✅ |
| 5. Temporal Split | F1=0.999 (synthetic shift) |
| 6. Leakage Detection | MI>0.5: AbuseIPDB features (expected signals) ✅ |

**Note:** Validation script trains a *bare XGBoost* on real data only (no regularization, no ensemble, no synthetic data) — the overfitting signal is an artifact of its methodology.

### 5.3 Feature Importance

**Top-5 XGB Gain:** `has_known_family` (0.196), `abuse_confidence` (0.155), `abuse_distinct_users` (0.082), `vt_malicious_ratio` (0.081), `has_malicious_vt_tags` (0.072)

**Top-5 Permutation:** `vt_malicious_ratio` (0.098), `abuse_confidence` (0.047), `is_hash` (0.046), `vt_reputation` (0.027), `vt_harmless_ratio` (0.020)

---

## 6. Artifacts & Deployment

```
models/
├── severity_classifier.joblib    # {xgb, lgb, ensemble_weights, calibration_temp, mode="ensemble"}
├── label_encoder.joblib          # LabelEncoder for 4 classes
├── feature_cols.joblib           # 35 feature names (order matters)
└── validation_report.json        # Full validation report
```

### Inference Pipeline

```
IOC → Parallel Enrichment → extract_ml_features(35) → Ensemble + Calibration
                                                    ↓
                                    Confidence <30% & Strong Signals?
                                                    ↓ Yes                    ↓ No
                                        predict_risk() (logistic)         Output
                                                    ↓
                                                Output
```

---

## 7. Reproducing Training

```bash
# Full training pipeline
python scripts/balance_and_train.py

# Validation suite
python scripts/validate_model.py

# Check artifacts
ls -la models/
cat models/validation_report.json
```

---

## 8. Design Decisions Summary

| Decision | Rationale | Impact |
|----------|-----------|--------|
| Temporal split | Prevents campaign leakage | Harder but realistic eval |
| No undersampling | Retains all 3,448 CLEAN | +0.24 CLEAN recall, +0.04 macro F1 |
| Known-clean with has_vt_data=1 | Prevents "no data = clean" shortcut | Robust CLEAN detection |
| Dual-model ensemble | Complementary boundaries | XGB: structured, LGB: interactions |
| Learned ensemble weights | Data-driven combination | Better than fixed 0.5/0.5 |
| Temperature calibration | Fixes overconfidence | T=1.1 softens predictions |
| CRITICAL floor (0.75) | Analyst-first: fewer false CRITICAL | 7 downgraded, 0 recall loss |
| Leakage feature removal | `malicious_family` was label proxy | CV variance 0.020 → 0.015 |
| Confidence floor fallback | Low-conf ML + strong signals → risk model | Fixes LOW-on-malicious bug |

---

## 9. Monitoring & Retraining

```
Production → User Feedback (Correct/Incorrect) → Periodic Retrain / Active Learning
                ↓                                         ↓
          Accumulated >500 corrections           Low-confidence → Manual Review
                ↓                                         ↓
            Retrain with corrected labels      Add to training set
```

**Triggers:** >500 feedback corrections, distribution drift, new data sources, quarterly schedule.