# Threat Intel Agent

[![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square)](https://react.dev)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.1-FF6600?style=flat-square)](https://xgboost.readthedocs.io)


An AI-powered threat intelligence platform that takes an IOC (IP, domain, or file hash), enriches it across four OSINT APIs in parallel, scores it with a custom-trained ML ensemble, maps behaviors to MITRE ATT&CK, and returns a structured verdict with severity, confidence, risk score, and recommended actions. Built for SOC analysts and blue-team practitioners who need fast, explainable threat scoring without a commercial TI subscription.

## Features

- **Parallel IOC enrichment** — Queries VirusTotal, Shodan, AbuseIPDB, and AlienVault OTX simultaneously (~3-4s vs 12s sequential)
- **ML threat scoring** — XGBoost + LightGBM ensemble with logistic regression fallback, **91.3% macro F1** on held-out real data
- **Autonomous hunt engine** — BFS pivots from seed IOC across subnets, DNS, sibling domains, and hashes
- **MITRE ATT&CK mapping** — 20+ technique signals matched locally, no external API needed
- **Chrome extension** — Hover tooltips on IOCs, live detection feed, right-click investigate
- **Slack & email alerts** — Webhook + SMTP notifications on critical findings
- **Bulk investigation** — Up to 100 IOCs in a single request
- **Threat feed subscriptions** — RSS/ATOM polling with auto-investigation
- **Workspaces** — Named, isolated investigation spaces
- **Blocklists** — Flag known-bad IOCs instantly, save API quota
- **Feedback loop** — Mark verdicts correct/incorrect for periodic retraining
- **SSE streaming** — Real-time investigation progress in the browser
- **Browser extension** — DOM IOC scanning, sidebar, popup, context menu

## Model Performance

Trained on 4,732 samples (1,479 real API + 3,253 verified clean sources + 200 synthetic), tested on 1,449 real-only IOCs (temporarily held out, no synthetic contamination). Class-balanced sample weights: real samples 3×, synthetic 1×. No undersampling.

| Class    | Precision | Recall | F1    | Support |
|----------|-----------|--------|-------|---------|
| CLEAN    | 1.00      | 0.93   | 0.96  | 898     |
| CRITICAL | 0.80      | 0.86   | 0.82  | 159     |
| HIGH     | 0.84      | 1.00   | 0.91  | 272     |
| LOW      | 0.97      | 0.94   | 0.96  | 120     |

**Test F1-macro: 0.913** | **Accuracy: 94%** | **CV F1-macro: 0.894 ± 0.009** (3-fold stratified)  
Ensemble: XGBoost (0.64) + LightGBM (0.36), temperature T=1.1. Ensemble weights learned via differential evolution on a held-out validation set — separate from both training and test splits.

**CRITICAL confidence floor:** The classifier refuses to label an IOC CRITICAL unless ensemble probability ≥ 75%. This post-processing step catches false positives by downgrading borderline CRITICAL predictions to HIGH — 7 caught on the test set with no recall loss. Deliberate analyst-first design: better to let an analyst review a borderline HIGH than burn credibility on a false CRITICAL alert.

**Top features by importance:** `has_known_family` (XGB gain 19.6%), `abuse_confidence` (15.5%), `vt_malicious_ratio` (8.1%), `has_malicious_vt_tags` (7.2%). LightGBM relies on `vt_harmless_ratio` (13.9% of splits) and `abuse_total_reports` (11.2%), showing the two models learn complementary decision boundaries. `is_hash` at rank 2 in XGB makes sense — hashes lack Shodan/AbuseIPDB data, so IOC type provides a strong prior for the fallback path.

**Design decisions:**
- *Temporal split* — Standard random splits leak future context into training (IOCs from the same campaign appear in both train and test). Temporal split by `first_seen` is a harder evaluation that reflects real deployment conditions. The ~0.02 gap between CV (random-fold) and test (temporal) metrics is expected and healthy — it shows the model generalizes beyond cross-contaminated random folds.
- *No undersampling* — Previous versions truncated CLEAN to 280 samples, discarding 60% of real CLEAN signal. Switching to `compute_sample_weight("balanced")` with all 3,448 CLEAN samples retained gave +0.24 CLEAN recall and +0.04 macro F1 while using 2.8× more training data.
- *Known-clean sourcing* — 3,253 IPs from Tranco top-1K, Cloudflare, and reputable cloud ranges were added with `has_vt_data=1` (VT returned 0 detections — absence of malicious findings, not absence of data). This prevents the model from learning the shortcut "no VT data = CLEAN."
- *Leakage removal* — Removed `malicious_family` (vt_malicious_ratio × has_known_family) which had 45% gain importance but was a label proxy. Retraining without it improved stability and dropped CV variance from 0.020 to 0.015.

## Quickstart

```bash
# Clone and set up backend
git clone https://github.com/InsiyahBhatia/threat-intel-agent
cd threat-intel-agent
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# (Optional) Install Groq SDK for the chat endpoint
pip install groq

# Configure API keys (all free tier)
cp .env.example .env
# Fill in VIRUSTOTAL_API_KEY, SHODAN_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY

# Start backend
cd api && uvicorn main:app --reload --port 8000

# Start frontend (separate terminal)
cd frontend
npm install
npm run dev                  # opens on localhost:5173

# Quick test
curl -X POST http://localhost:8000/investigate \
   -H "Content-Type: application/json" \
   -d '{"ioc": "185.220.101.1"}'
```

**Free-tier API keys:** VirusTotal (500 req/day), Shodan (host lookup), AbuseIPDB (1000 checks/day), AlienVault OTX (unlimited). Total cost: **$0**.

## Project Structure

```
threat-intel-agent/
├── agent/              Pipeline orchestrator, threat hunt engine, threat graph
├── tools/              Tool modules (VT, Shodan, AbuseIPDB, OTX, MITRE mapper, ML classifier)
├── models/             Pydantic schemas + trained model artifacts
├── utils/              Feature engineering, synthetic data generator, risk model,
│                       IOC classification, notification engine, lightweight decorators
├── config/             Centralized settings (magic numbers, thresholds, defaults)
├── scripts/            Training pipeline, dataset builder, enrichment pipeline, validation
├── api/                FastAPI server (REST + SSE streaming)
├── frontend/           React 18 + Vite + Tailwind dashboard
├── threat-intel-extension/  Chrome MV3 extension (sidebar, popup, content script, background worker)
├── data/               Training dataset (ioc_dataset.csv) + enrichment cache
├── tests/              pytest test suite
├── pyproject.toml      Ruff linter + pytest + coverage config
└── .env.example        API key template
```

## Browser Extension Setup

```bash
cd threat-intel-extension
# Ensure manifest.json points to your backend URL in host_permissions
# Load unpacked in chrome://extensions (enable Developer Mode)
```

Verdicts appear as hover tooltips on scanned IOCs across any webpage. The sidebar shows a live detection feed, severity distribution, and on-demand lookup. The popup provides quick IOC input for ad-hoc checks. Right-click any IOC to "Investigate with Threat Intel Agent."

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Backend | Python 3.11, FastAPI, Groq SDK | Async-first, auto-docs, Pydantic validation |
| ML | XGBoost + LightGBM, scikit-learn | Gradient-boosted ensembles excel on tabular threat data |
| APIs | asyncio (4 parallel) | Drops enrichment latency from 12s to 3-4s |
| Frontend | React 18, Vite, Tailwind CSS, Framer Motion | Dark enterprise dashboard with animated transitions |
| Extension | Chrome MV3 (service worker, content script) | DOM IOC scanning + hover cards without page permissions |
| Storage | SQLite + JSON workspaces | Zero-infrastructure persistence |
| Streaming | Server-Sent Events | Real-time investigation progress without WebSocket overhead |

## Roadmap

- **Active learning loop** — Flag low-confidence predictions for manual review; retrain with corrected labels to target CLEAN recall above 0.80.
- **GreyNoise integration** — Differentiate internet background noise from targeted threats without burning VT quota.
- **Multi-user workspace** — Add user auth + shared workspaces so teams can collaborate on investigations.
- **Knowledge graph** — Persist hunting results as a Neo4j graph for cross-campaign correlation.

## Screenshots

| | |
|---|---|
| ![Dashboard](screenshots/02-dashboard-investigation-results.png) | ![Extension](screenshots/01-threat-intel-extention.png) |
| **Dashboard & investigation results** | **Browser extension** |

| | |
|---|---|
|---|---|
| ![Report MITRE](screenshots/03-report-mitre-techniques.png) | ![Raw JSON](screenshots/04-report-raw-json-evidence.png) |
| **Report: MITRE techniques** | **Raw JSON evidence** |

| | |
|---|---|
|---|---|
| ![Alerts](screenshots/05-alerts-history-table.png) | ![Hunt](screenshots/07-hunt-certificate-transparency.png) |
| **Alerts history** | **Autonomous hunt graph** |

| | |
|---|---|
|---|---|
| ![Slack](screenshots/06-slack-threat-alert-notification.png) | ![Email](screenshots/08-email-alert-screenshot.png) |
| **Slack notification** | **Email alert** |

| | |
|---|---|
|---|---|
| ![Explain](screenshots/09-explain-shap-features.png) | ![CSV Export](screenshots/10-investigations-csv-excel.png) |
| **ML Explainability (SHAP)** | **Investigations CSV in Excel** |

| | |
|---|---|
|---|---|
| ![PDF Report](screenshots/11-pdf-report-export.png) | |
| **Generated PDF report** | |