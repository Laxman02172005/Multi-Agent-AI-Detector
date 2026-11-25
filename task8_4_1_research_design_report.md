# Task 8.4.1: Research Design and Dataset Bias Mitigation Report

**Project**: Multi-Agent AI Phishing Email Detector  
**Task**: 8.4.1 Research Design and Dataset Bias Mitigation  
**Date**: November 12, 2026  
**Status**: COMPLETE (Approved Research Design Specification)  
**Deliverables Produced**:
1. `docs/research/feature_policy.md`
2. `docs/research/dataset_split_strategy.md`
3. `docs/research/experimental_design.md`
4. `docs/research/h5_feasibility_and_data_requirements.md`
5. `docs/research/threats_to_validity.md`
6. `task8_4_1_research_design_report.md` (this report)

---

## Executive Summary

Task 8.4.1 establishes a rigorous, formal research design and experimental protocol for the Multi-Agent AI Phishing Email Detector, directly addressing the empirical vulnerabilities, leakage shortcuts, and statistical confounders identified during the Task 8.4 dataset analysis.

The research design is grounded entirely in actual measurements from the 1,000-email development dataset (750 SpamAssassin ham from 2002–2003, 188 Nazario phishing from 2015, and 62 Nazario phishing from 2021). It enforces a four-tier data separation architecture, an out-of-fold cross-validation training strategy for the Logistic Regression meta-classifier, an explicit three-tier decision policy with selective abstention, and an exhaustive threat-to-validity taxonomy. 

Furthermore, the design documents the mathematical impossibility of a source-held-out split on this corpus, formally classifies Hypothesis H5 as **Exploratory Only**, and specifies the precise data requirements for future contemporary benchmarking without mutating existing code, schemas, or raw archives.

---

## 1. Feature Policy by Agent

A four-tier data architecture strictly separates immutable raw evidence (Tier 1) and extracted forensic models (Tier 2) from approved agent feature spaces (Tier 3) and isolated dataset provenance (Tier 4).

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Tier 1: Original Raw Evidence (data/dev/eml/ — 1,000 Immutable EML Files)    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ (EmailIngestor Pipeline)
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ Tier 2: Extracted Forensic Metadata (Pydantic EmailData Contracts)           │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ (Approved Feature Policy Filter)
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ Tier 3: Approved Model Features (Header, URL, Text, Attachment Agent Spaces)│
└─────────────────────────────────────────────────────────────────────────────┘
                                       ▲
  STRICT SEPARATION FIREWALL          │ (PROVENANCE LEAKAGE BLOCKED)
┌──────────────────────────────────────┴──────────────────────────────────────┐
│ Tier 4: Provenance Metadata (Manifests, Archive Names, MBOX Keys, Labels)   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Approved Agent Feature Domains:
1. **Header Agent**:
   - *Approved Evidence*: Domain alignment between `From`, `Reply-To`, and `Return-Path`; syntax and presence of `Message-ID`; Received header hop counts and internal transit delays; unverified authentication status claims (`Authentication-Results`, `Received-SPF`, `DKIM-Signature`).
   - *Prohibited*: Live DNS lookups; treating header presence as cryptographic validity; inferring failure from missing authentication; absolute dates.
2. **URL Agent**:
   - *Approved Evidence*: URL normalization, scheme validation (flagging `javascript`, `data`, `file`), port checks, path/query lexical complexity, anchor-text vs destination URL discrepancy (visual spoofing), contextual source (`html_href` vs `html_src` vs `plain_text`), domain divergence.
   - *Prohibited*: Live HTTP fetching; DNS/WHOIS resolution; external reputation APIs; raw link quantity as an isolated phishing score (protecting `ham_hard` digest emails).
3. **Text Agent**:
   - *Approved Evidence*: Semantic urgency, coercive threats, credential-harvesting phrases, financial/wire instructions, brand/authority impersonation patterns evaluated over normalized `cleaned_text`.
   - *Prohibited*: Collection headers; absolute years; learning raw HTML markup formatting as an artificial substitute for semantic meaning.
4. **Attachment Agent**:
   - *Approved Evidence*: Static MIME types, declared file extensions, double extensions, dangerous executable signatures (`.exe`, `.scr`, `.bat`), HTML attachment lures, static size in bytes, content disposition.
   - *Prohibited*: Attachment execution or rendering; archive decompression; inferring maliciousness solely from attachment presence; non-neutral outputs when attachments are absent.

---

## 2. Corpus-Artifact Exclusion Policy

The Task 8.4 exploratory analysis revealed severe corpus-specific artifact leakage vectors. To eliminate artificial classification shortcuts, the following exclusion matrix is formally enforced:

| Field / Header Name | Dev Set Prevalence (Ham vs Phish) | Preserved in Raw Evidence? | Allowed in Model Features? | Empirical Risk & Mitigation |
|---|---|:---:|:---:|---|
| **`X-Spam-*`** | Ham: 0.0% (0/750)<br>Phish: **99.6% (249/250)** | **YES** (Tier 1 & 2) | **NO** (Strictly Purged) | Nazario honeypot spam-filter stamps. If unstripped, models learn filter tags instead of email features. |
| **`List-*`** | Ham: **53.1% (398/750)**<br>Phish: 2.0% (5/250) | **YES** (Tier 1 & 2) | **NO** (Strictly Purged) | Mailing list artifacts characteristic of SpamAssassin open-source lists. |
| **`Date` (Absolute Header)** | Ham: **100% 2002** (748/748)<br>Phish: **100% 2015/21** (250/250) | **YES** (Tier 1 & 2) | **NO** (Strictly Purged) | **Critical Leakage**: $\text{Year} < 2010$ splits classes with 100.0% accuracy. Absolute date is completely barred. |
| **`User-Agent` / `X-Mailer`** | Ham: 42.8% (321/750)<br>Phish: 16.4% (41/250) | **YES** (Tier 1 & 2) | **NO** (Strictly Purged) | Historical MUA signatures (Mutt, Eudora, OE 6) act as temporal shortcuts. |
| **`source_archive`, `mbox_key`** | 100% coverage | **YES** (Tier 4 Only) | **NO** (Strictly Purged) | Provenance tracking metadata. Strictly barred from feature extractors. |

---

## 3. Dataset Splitting and Evaluation Strategy

### 3.1 Mathematical Limitation on Source Independence
Because 100% of ham originates from SpamAssassin and 100% of phishing originates from Nazario, a source-held-out split is mathematically impossible on this dataset. Performance evaluated on this dataset measures **in-distribution development generalization only**.

### 3.2 Grouped Stratified Partition Protocol
To prevent campaign near-duplicates from leaking across splits while maintaining the exact 75% ham / 25% phishing balance, the dataset is split using **Grouped Stratified Partitioning** with fixed `seed=42`:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1,000-Email Development Dataset                                              │
├───────────────────────────────┬──────────────────────────────┬──────────────┤
│ Training Split: 60% (n=600)   │ Validation Split: 20% (n=200)│ Test: 20%    │
│ 300 easy_ham, 150 hard_ham    │ 100 easy_ham, 50 hard_ham    │ 100 easy_ham │
│ 113 phish 2015, 37 phish 2021 │ 38 phish 2015, 12 phish 2021 │ 50 hard_ham  │
│                               │                              │ 37 phish '15 │
│                               │                              │ 13 phish '21 │
└───────────────────────────────┴──────────────────────────────┴──────────────┘
```

- **Training Split (60%, n=600)**: Used for agent feature extraction and 5-fold cross-validation meta-training.
- **Validation Split (20%, n=200)**: Used for hyperparameter tuning ($C$), probability calibration, and abstention threshold selection.
- **Test Split (20%, n=200) — "Sealed Vault"**: Held out untouched until final project benchmarking; evaluated exactly once.

---

## 4. Baseline Models and Meta-Classifier Design

### 4.1 Progressive Experimental Baselines
The multi-agent system will be benchmarked against six reference baselines:
1. **Majority-Class Baseline**: 75.0% accuracy, 0% recall floor.
2. **Header-Only Baseline**: Isolates sender alignment and header syntax signals.
3. **URL-Only Baseline**: Isolates domain lexical complexity and anchor discrepancies.
4. **Text-Only Baseline**: Isolates NLP semantic urgency and credential requests.
5. **Attachment-Only Baseline**: Isolates static attachment metadata.
6. **Flat Monolithic Baseline**: Single flat concatenation of all approved features directly into a classifier.
7. **Multi-Agent Meta-Classifier (Proposed)**: Hierarchical synthesis of calibrated agent belief states.

### 4.2 Logistic Regression Meta-Classifier Specification
- **Input Space (10 Features)**: 4 agent probabilities ($p_h, p_u, p_t, p_a$), 4 agent confidences ($c_h, c_u, c_t, c_a$), and 2 missingness flags ($m_u, m_a$).
- **Mathematical Form**: $\hat{P}(\text{phishing} \mid \mathbf{x}) = \sigma(\mathbf{w}^T \mathbf{x} + b)$.
- **Strict Leakage Prevention**: **Out-of-Fold (OOF) Training Protocol**. The meta-classifier is trained on 5-fold stratified cross-validation predictions generated on the 600-sample training split. **In-sample self-predictions are strictly prohibited.**
- **Regularization & Class Weighting**: L2 Ridge penalty; balanced class weights ($w_{\text{phishing}} = 3.0, w_{\text{ham}} = 1.0$) to counteract the 3:1 class imbalance.
- **No Manual Weights**: All coefficients $\mathbf{w}$ are learned via regularized empirical risk minimization. Confidence intervals for weights are computed via 1,000 bootstrap iterations.

---

## 5. Confidence, Uncertainty, and Selective Abstention Policy

A single 0.5 decision threshold is rejected as unsafe for security operations. The system implements a **three-tier classification policy with selective abstention**:

$$\text{Verdict}(P) = \begin{cases} 
\text{\textbf{Likely Phishing}}, & \text{if } P \ge \tau_{\text{high}} \\ 
\text{\textbf{Likely Legitimate}}, & \text{if } P \le \tau_{\text{low}} \\ 
\text{\textbf{Inconclusive (Abstain)}}, & \text{if } \tau_{\text{low}} < P < \tau_{\text{high}} 
\end{cases}$$

- **Threshold Tuning on Validation Set (n=200)**:
  - $\tau_{\text{high}}$ tuned to enforce $FPR \le 1.0\%$ (minimizing false alarms).
  - $\tau_{\text{low}}$ tuned to enforce $FNR \le 5.0\%$ (achieving $\ge 95\%$ recall).
  - Inconclusive samples are quarantined for secondary expert inspection or automated URL/attachment sandboxing.
- **Probability Calibration**: Calibrated via Platt Scaling and Isotonic Regression; evaluated using Expected Calibration Error ($ECE \le 0.05$) and Brier Score.

---

## 6. Hypothesis H5 Feasibility and Data Requirements

### 6.1 Empirical Finding & Verdict
- **Task 8.4 Findings**: 25 SPF pass, 31 DKIM pass, and 9 DMARC pass claims exist in phishing (mostly 2021 cohort), but **exactly 0 exist in legitimate ham**. All claims remain unverified receiver assertions.
- **Confounding Problem**: Because authentication claims are 100% exclusive to phishing in this dataset, models would learn that authentication pass indicates phishing.
- **Formal Verdict**: **EXPLORATORY ONLY**. Formal hypothesis testing is impossible on the development set alone.

### 6.2 Specification for Supplementary Contemporary Dataset
To evaluate H5 in a future phase without confounding, the following supplementary corpus is required:
1. **Contemporary Legitimate Ham (2020–2026)**: Minimum 500 emails with authentic, verified SPF pass, DKIM pass, and DMARC pass claims.
2. **Contemporary Phishing (2020–2026)**: Minimum 250 phishing emails originating from compromised accounts or forwarders with passing SPF/DKIM.
3. **Format**: Raw RFC 822 `.eml` files preserving unstripped `Authentication-Results` and `DKIM-Signature` headers.
4. **Evaluation**: Comparative evaluation measuring Recall Degradation ($\Delta R = R_{\text{unauth}} - R_{\text{auth}}$) between monolithic baselines and the multi-agent system.

---

## 7. Comprehensive Evaluation Metrics

| Metric | Role | Target Operational Threshold | Rationale |
|---|:---:|:---:|---|
| **Macro-Averaged F1** | **Primary** | $\ge 0.90$ | Balances performance equally across 75% ham and 25% phishing. |
| **FPR at 95% Recall ($FPR_{R \ge 95\%}$)** | **Primary** | $\le 1.0\%$ | Critical operational requirement: prevents legitimate email loss during security filtering. |
| **Precision-Recall AUC (PR-AUC)** | **Primary** | $\ge 0.95$ | Evaluates precision-recall trade-off robustly under class imbalance. |
| **Coverage & Selective Risk** | **Primary** | Coverage $\ge 85\%$, Risk $\le 2.0\%$ | Evaluates performance of the selective abstention policy. |
| **ROC-AUC** | Secondary | $\ge 0.98$ | Measures global discrimination across all operating thresholds. |
| **Brier Score & ECE** | Secondary | $\text{Brier} \le 0.08, ECE \le 0.05$ | Validates probability calibration and confidence reliability. |

---

## 8. Threats to Validity Summary

| Threat | Empirical Status | Severity | Enforced Research Mitigation |
|---|:---:|:---:|---|
| **Date Leakage** | Observed Problem (100% 2002 vs 2015/21) | **CRITICAL** | `Date` header completely barred from model features. |
| **Scanner Artifact Leakage** | Observed Problem (99.6% `X-Spam-*` in phish) | **HIGH** | Strict regex blacklist stripping all scanner and mailing list headers. |
| **Authentication Confounder** | Observed Problem (0% claims in ham) | **HIGH** | H5 classified as Exploratory Only; authentication decoupled from core features. |
| **Formatting Disparity** | Observed Problem (99.8% plain vs 92% HTML) | **MEDIUM** | Text Agent operates exclusively on normalized `cleaned_text`. |
| **URL Density in Ham** | Observed Problem (mean 60 URLs in hard_ham) | **MEDIUM** | URL Agent evaluates domain alignment, not raw link quantity. |
| **Attachment Sparsity** | Observed Problem (5.9% emails have attachments) | **MEDIUM** | Attachment Agent emits neutral belief ($p=0.5, c=0.0$) with missing flag $m_a=1$. |
| **Class Imbalance** | Observed Problem (75% ham / 25% phish) | **LOW** | Accuracy barred; macro-F1, PR-AUC, and class-weighted loss enforced. |
| **Claim Forgery** | Potential Deployment Risk | **MEDIUM** | Authserv-ID consistency checked against outermost Received hop. |
| **AI-Generated Phishing** | Potential Deployment Risk | **HIGH** | Multi-agent redundancy ensures URL/Header agents detect lure even if text appears benign. |

---

## 9. Key Decisions Required Before Implementation (Task 8.5)

Before starting agent implementation or meta-classifier coding in subsequent tasks, the following formal design decisions must be confirmed:
1. **Pre-Extraction Header Sanitizer**: Confirm deployment of the regex header sanitizer stripping `X-Spam-*`, `List-*`, and `Date` across all agent pipelines.
2. **Fixed Split Manifest**: Confirm generation of `data/dev/manifests/split_manifest.json` persisting the 60/20/20 grouped split before any feature extraction.
3. **Out-of-Fold Agent Architecture**: Confirm that agent training pipelines will expose a `fit_predict_oof()` interface to generate leak-free meta-training data.
4. **H5 Scope Boundary**: Reaffirm that H5 remains exploratory in Task 8.5–8.7, deferring formal statistical validation to a dedicated contemporary benchmark phase.

---

## 10. Regression Suite and Deliverables Verification

All existing and new tests pass cleanly with zero regressions:
- Full repository test suite (`pytest -v`): **441 passed** in 18.91s.
- Raw archives and development EML files remain byte-unmodified.
- Git privacy verified: all research documentation resides under `docs/research/` and root; no email data or manifests are tracked.

### Deliverables Checklist:
- [x] `docs/research/feature_policy.md` (Feature policy, whitelist, and exclusion framework)
- [x] `docs/research/dataset_split_strategy.md` (60/20/20 grouped stratified split protocol)
- [x] `docs/research/experimental_design.md` (Baselines, meta-classifier, abstention policy, metrics)
- [x] `docs/research/h5_feasibility_and_data_requirements.md` (H5 analysis, data specifications, protocol)
- [x] `docs/research/threats_to_validity.md` (Observed problems vs potential risks)
- [x] `task8_4_1_research_design_report.md` (Comprehensive synthesis report)

---

## Strict Stopping Condition Adherence

Task 8.4.1 is complete. In accordance with explicit user instructions:
- No machine-learning models were trained.
- No agents or meta-classifiers were implemented.
- Application schemas and ingestion code remain unmodified.
- The 1,000 approved EML files and manifests remain untouched.
- Task 8.5 has not been started.

**I have stopped and am awaiting your explicit approval before proceeding to any further tasks.**
