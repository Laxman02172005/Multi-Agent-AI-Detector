# Multi-Agent AI Phishing Email Detector

A modular, interpretable, hierarchical multi-agent system for detecting phishing emails with calibrated uncertainty quantification and selective abstention.

---

## Architecture Overview

The system employs a hierarchical multi-agent architecture designed for high security, interpretability, and fault tolerance:

```
                          Raw RFC 5322 Email (.eml)
                                     │
                                     ▼
                [Layer 0] Ingestion & Parsing Engine (EmailData)
                                     │
        ┌────────────────────────────┼────────────────────────────┬────────────────────────────┐
        ▼                            ▼                            ▼                            ▼
[Layer 1] Header Agent       [Layer 1] URL Agent         [Layer 1] Text Agent       [Layer 1] Attachment Agent
 (41 active features)        (37 active features)        (29 active features)        (25 active features)
        │                            │                            │                            │
        └────────────────────────────┼────────────────────────────┴────────────────────────────┘
                                     ▼
                [Layer 2] Evidence Aggregator (132 Meta-Features)
                 • Modality Health Assessment (AVAILABLE / EMPTY / DEGRADED / FAILED)
                 • Missingness Imputation & Active Missingness Mask
                 • Modality-Weighted Completeness Metric
                 • Unified Forensic Evidence Trail (Tier 2, capped at 150 items)
                                     │
                                     ▼
                [Layer 3] Calibrated Meta-Classifier & Selective Abstention
                 • Tier 1: Health-Driven Abstention Override (modality failure floor)
                 • Tier 2: Uncertainty-Band Abstention (τ_low <= P <= τ_high)
                 • Platt-Calibrated Probability P(phishing | evidence)
                 • Linear Explainability: Signed Feature Contributions (w_i · x̃_i)
                                     │
                                     ▼
          [Layer 4] End-to-End Orchestrator & Forensic Report
           • Output: PhishingAnalysisReport (PHISHING | LEGITIMATE | ABSTAIN)
           • Interactive Streamlit Dashboard & Unified CLI Tool
```

---

## Project Status

- **Complete Multi-Agent Pipeline Operational**:
  - **Layer 0**: RFC 5322 MIME parsing, parser defect tracking, header/auth/url/body/attachment extractors.
  - **Layer 1 Specialist Agents**:
    - **Header Agent**: 41 active predictive features (4 quarantined), sender alignment, routing anomalies, unverified auth claims.
    - **URL Agent**: 37 active predictive features (2 quarantined), PSL trie domain resolver, RFC IP classifier, visual anchor mismatch heuristics.
    - **Text Agent**: 29 active features, intent/urgency cues, credential lures, hidden text/CSS tricks, zero-width characters, lexical entropy.
    - **Attachment Agent**: 25 active features, executable binaries, macro-enabled files, HTML smuggling, double extension, RLO spoofing, MIME mismatch.
  - **Layer 2 Evidence Aggregator**: 132-feature meta-vector assembly, missingness masks, modality health manifests, unified evidence deduplication and sorting.
  - **Layer 3 Meta-Classifier**: Regularized `StandardScaler + LogisticRegression` with `CalibratedClassifierCV` (Platt scaling), two-tier selective abstention policy, linear attribution explainability, and SHA-256 verified model bundles.
  - **Layer 4 Orchestrator & Interfaces**: `PhishingDetectorPipeline` with fault isolation, CLI tool (`analyze_email_cli.py`), and unified interactive Streamlit web dashboard (`unified_dashboard.py`).
- **Test Suite**: **765 automated tests passing with 0 failures and 0 regressions**.

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Language | Python 3.11+ | Type hints, dataclasses, pattern matching |
| Validation & Contracts | Pydantic v2 | Strict schema validation, immutability, fail-closed contracts |
| HTML & Text Extraction | BeautifulSoup4 | Clean textual and anchor extraction from HTML email parts |
| Machine Learning | scikit-learn | Regularized Logistic Regression, StandardScaler, CalibratedClassifierCV |
| Model Persistence | joblib + hashlib | Binary serialization with SHA-256 cryptographic integrity verification |
| Web Dashboard | Streamlit | Real-time interactive forensic cybersecurity dashboard |
| Testing | pytest | Unit, integration, and regression test runner (765 tests) |

---

## Quickstart & Environment Setup

### 1. Prerequisites
- Python 3.11+
- Windows PowerShell, macOS, or Linux terminal

### 2. Enter the project directory
```powershell
cd phishing-detector
```

### 3. Create and activate virtual environment
```powershell
python -m venv .venv

# Windows PowerShell:
.venv\Scripts\Activate.ps1

# Linux / macOS:
source .venv/bin/activate
```

### 4. Install dependencies
```powershell
pip install -r requirements.txt
```

---

## Training and Model Evaluation

To generate a synthetic dataset through the full multi-agent pipeline and train a calibrated meta-classifier bundle:

```powershell
python scripts/train_and_evaluate.py --synthetic-demo --samples 80
```

This will:
1. Generate realistic legitimate and phishing emails.
2. Ingest and extract all 132 active features across all 4 specialist agents.
3. Train and calibrate the meta-classifier via Platt scaling.
4. Save the SHA-256 verified bundle to `models/meta_classifier_v1/`.
5. Output `models/meta_classifier_v1/evaluation_report.json` with accuracy, ROC-AUC, Brier score, abstention rate, and selective accuracy.

---

## Running the End-to-End CLI Analyzer

To analyze any `.eml` email file and print a forensic terminal audit report:

```powershell
# Analyze sample email
python scripts/analyze_email_cli.py data/samples/synthetic_demo.eml

# Export full JSON audit report
python scripts/analyze_email_cli.py data/samples/synthetic_demo.eml --json-out report.json
```

Example terminal output:
```
==========================================================================
      MULTI-AGENT PHISHING DETECTOR - FORENSIC ANALYSIS REPORT      
==========================================================================
 Email ID        : email_73ea707b805c4ceeb56adca01d9fbb51
 Analyzed At     : 2026-11-20T06:39:11.805970+00:00
 Processing Time : 23.4 ms
 Active Features : 132 (Quarantined: 6)
--------------------------------------------------------------------------

[✓] FINAL VERDICT: LEGITIMATE (CLEAN)
 Calibrated Probability : 0.06%
 Decision Confidence    : 99.88%
 Overall Completeness   : 84.00%
 Model Version          : 1.0.0

[+] MODALITY HEALTH MANIFEST
  ----------------------------------------------------------------------
  Modality       Status       Completeness   Active Feats   Missing Feats
  ----------------------------------------------------------------------
  Header         AVAILABLE    90.00%         41             1
  Url            AVAILABLE    87.50%         37             0
  Text           AVAILABLE    100.00%        29             1
  Attachment     EMPTY        0.00%          25             0
  ----------------------------------------------------------------------

[+] TOP FEATURES DRIVING PHISHING PREDICTION:
  1. [HEADER] header_from_reply_to_domain_mismatch: +0.141 (val: 1.0)
  2. [HEADER] header_from_return_path_domain_mismatch: +0.141 (val: 1.0)
  3. [HEADER] header_display_name_contains_email: +0.141 (val: 1.0)

[+] TOP FEATURES DRIVING LEGITIMATE PREDICTION:
  1. [ATTACHMENT] attachment_total_attachment_size_bytes: -8.371 (val: 0.0)
  2. [URL] url_max_url_length: -0.244 (val: 43.0)
  3. [TEXT] text_word_count: -0.200 (val: 24.0)

[+] TIER 2 FORENSIC EVIDENCE (10 items, 0 omitted):
  1. [HIGH] [HEADER] dkim_signature_present_without_pass: DKIM failed
  2. [HIGH] [HEADER] from_reply_to_domain_mismatch: Reply-To domain mismatch
  3. [HIGH] [TEXT] has_credential_lures: Detected credential cue
==========================================================================
```

---

## Running the Interactive Streamlit Web Dashboard

To launch the complete cybersecurity dashboard:

```powershell
streamlit run scripts/unified_dashboard.py
```

Open `http://localhost:8501` in your browser. Features include:
- **Interactive File Upload & Preset Selection**: Upload custom `.eml` files or select pre-loaded samples.
- **Dynamic Decision Threshold Sliders**: Adjust $\tau_{\text{low}}$ and $\tau_{\text{high}}$ in real time to observe selective abstention behavior.
- **Verdict Banner**: Real-time verdict (Red = Phishing, Green = Legitimate, Orange = Abstain) with calibrated probability and confidence gauges.
- **Modality Health Cards**: Health status badges and completeness progress bars for Header, URL, Text, and Attachment agents.
- **Linear Explainability Decomposition**: Side-by-side tables detailing positive (phishing) and negative (legitimate) feature contributions ($w_i \cdot \tilde{x}_i$).
- **Tier 2 Forensic Evidence Table**: Filterable by modality and severity (`critical`, `high`, `medium`, `low`).
- **132-Feature Meta-Vector Explorer**: Searchable table displaying observed feature values and missingness masks.
- **One-Click JSON Audit Export**: Download complete `PhishingAnalysisReport` JSON artifacts.

---

## Running Tests

Run the full automated test suite (765 tests):

```powershell
pytest -q
```

Run specific test modules:
```powershell
# Pipeline Orchestrator tests
pytest tests/test_orchestrator.py -v

# Layer 3 Meta-Classifier tests
pytest tests/test_meta_classifier.py -v

# Layer 2 Evidence Aggregator tests
pytest tests/test_evidence_aggregator.py -v

# Layer 1 Specialist Agent tests
pytest tests/test_header_agent.py tests/test_url_agent.py tests/test_text_agent.py tests/test_attachment_agent.py -v
```

---

## Repository Structure

```
phishing-detector/
├── app/
│   ├── agents/                   # Layer 1 specialist agents
│   │   ├── attachment_components/
│   │   ├── text_components/
│   │   ├── url_components/
│   │   ├── attachment_agent.py
│   │   ├── header_agent.py
│   │   ├── text_agent.py
│   │   └── url_agent.py
│   ├── aggregation/              # Layer 2 evidence aggregator
│   │   └── evidence_aggregator.py
│   ├── data/                     # Offline local registries (PSL, shorteners)
│   ├── ingestion/                # Layer 0 email ingestion and extractors
│   ├── meta_classifier/          # Layer 3 calibrated meta-classifier & trainer
│   │   ├── meta_classifier.py
│   │   └── trainer.py
│   ├── pipeline/                 # Layer 4 end-to-end pipeline orchestrator
│   │   └── orchestrator.py
│   └── schemas/                  # Pydantic v2 data contracts across all layers
├── data/samples/                 # Sample demonstration emails
├── models/                       # Trained versioned model bundles & metadata
├── scripts/                      # Standalone CLI tools & Streamlit dashboards
│   ├── analyze_email_cli.py
│   ├── train_and_evaluate.py
│   ├── unified_dashboard.py
│   └── header_agent_dashboard.py
├── tests/                        # Comprehensive test suites (765 tests)
├── requirements.txt
└── README.md
```
