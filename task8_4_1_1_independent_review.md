# Task 8.4.1.1: Independent Research Design Review

**Review Target**: Task 8.4.1 Research Design and Dataset Bias Mitigation  
**Project Root**: `C:\Users\laxma\Documents\Mini_Project\Multi-Agent-AI-Detector\phishing-detector`  
**Review Type**: Independent, Read-Only Audit  
**Date**: November 12, 2026  
**Final Recommendation**: **APPROVE WITH CONDITIONS**  

---

## Executive Summary

An independent, read-only scientific and methodological audit of the research design formulated in Task 8.4.1 was conducted. The audit inspected all six core design deliverables:
1. `docs/research/feature_policy.md`
2. `docs/research/dataset_split_strategy.md`
3. `docs/research/experimental_design.md`
4. `docs/research/h5_feasibility_and_data_requirements.md`
5. `docs/research/threats_to_validity.md`
6. `task8_4_1_research_design_report.md`

The research framework is methodologically rigorous, thoroughly grounded in the empirical findings of Task 8.4, and enforces exemplary safeguards against data leakage, source contamination, and circular training. The four-tier data architecture strictly separates raw immutable evidence from model inputs and provenance metadata. The out-of-fold (OOF) cross-validation protocol prevents meta-classifier over-fitting, and Hypothesis H5 is appropriately classified as **Exploratory Only** due to the confirmed 0% authentication rate in historical ham.

The recommendation is **APPROVE WITH CONDITIONS**. The conditions address statistical granularity constraints on the 200-sample validation split, vocabulary isolation within cross-validation folds, and server hostname sanitization in Received headers during agent implementation.

---

## Findings Classification Matrix

| Audit Area | Finding Classification | Summary / Verdict |
|---|:---:|---|
| **1. Feature Policy & Leakage Quarantine** | **NO ISSUE** | Strict 4-tier separation. `X-Spam-*`, `List-*`, and `Date` purged from Tier 3. Authentication claims maintained unverified. |
| **2. Data Split & Source Confounding** | **NO ISSUE** | 60/20/20 split reconciles to 1,000 (600/200/200). Impossibility of source-held-out testing is explicitly documented. |
| **3. Validation Target Feasibility** | **MEDIUM** | Discrete jump problem: on $N_{\text{val\_ham}}=150$, 1 FP = 0.67%, 2 FP = 1.33% (exceeds 1%). Targets must be aspirational objectives, not hard guarantees. |
| **4. Meta-Classifier & OOF Protocol** | **NO ISSUE** | 5-fold OOF training prevents in-sample over-fitting. No manual weights. 10 features provide 60:1 sample-to-feature ratio. |
| **5. Preprocessing & Vocabulary Isolation** | **LOW** | All vectorizer/scaler fitting must be confined strictly within training folds to prevent out-of-fold vocabulary leakage. |
| **6. Received Header Hostname Sanitization** | **LOW** | Received header hostnames (e.g. `dogma.slashnull.org`) must be masked to prevent institutional server leakage. |
| **7. Calibration & Abstention Policy** | **LOW** | With $N_{\text{val}}=200$, ECE reliability bins should be reduced from 10 to 5 (or adaptive binning) to avoid sparse bin artifacts. |
| **8. Hypothesis H5 Feasibility** | **NO ISSUE** | Fully substantiated: 0% authenticated ham confirmed. Correctly designated as Exploratory Only. |
| **9. Implementation Readiness** | **NO ISSUE** | Agent boundaries, meta-feature vectors, and evaluation metrics are unambiguous and implementable. |
| **10. Repository & Regression Verification**| **NO ISSUE** | 441/441 tests pass in 18.83s. Raw archives, EMLs, schemas, and extractors remain byte-unmodified. |

---

## 1. Feature Policy and Leakage Quarantine Audit

### Verified Invariants:
1. **Raw Evidence Preservation**: Raw EML files (`data/dev/eml/`) remain untouched in Tier 1.
2. **Provenance Quarantine**: Tier 4 metadata (`source_archive`, `source_year`, `original_mbox_key`, `sample_id`) is strictly segregated into manifests and barred from feature extraction.
3. **Artifact Purge Matrix**:
   - `X-Spam-*`: Present in 99.6% of phishing (249/250); purged from Tier 3.
   - `List-*`: Present in 53.1% of ham (398/750); purged from Tier 3.
   - `X-Mailman-*`, `X-Loop`, `Precedence`: Purged from Tier 3.
4. **Temporal Separation**:
   - Claimed `Date` header is completely excluded from model features, successfully mitigating the 100% 2002 ham vs 2015/2021 phishing shortcut.
   - Relative transit duration between earliest and latest Received hops is permitted as an internal delta, but absolute timestamps are stripped.
5. **Authentication Claims**:
   - Maintained as `unverified` receiver assertions.
   - `DKIM-Signature` presence is not treated as a pass.
   - Missing authentication is explicitly recorded as neutral `missing` rather than failure.

### Identified Leakage Risk to Condition:
- **`Received` Header Hostname Leakage**: While absolute timestamps are stripped, raw `Received` headers in the SpamAssassin corpus frequently contain institutional domain names or relay hosts (e.g., `dogma.slashnull.org`, `yalma.flirble.org`). If the Header Agent extracts raw hostname tokens, it could inadvertently identify the SpamAssassin archive infrastructure.
- **Condition**: The Header Agent implementation must extract structural routing properties (hop count, private IP presence, syntax validity, relative transit delta) and must **not** tokenize server domain names from `Received` headers.

---

## 2. Dataset Split Audit

### Quantitative Reconciliation:

| Partition | Total Samples | ham_easy (SA) | ham_hard (SA) | Total Ham | Phish 2015 | Phish 2021 | Total Phish | Ratio (Ham : Phish) |
|---|---:|---:|---:|---:|---:|---:|---:|:---:|
| **Train (60%)** | 600 | 300 | 150 | 450 | 113 | 37 | 150 | 75.0% : 25.0% |
| **Validation (20%)** | 200 | 100 | 50 | 150 | 38 | 12 | 50 | 75.0% : 25.0% |
| **Test (20%)** | 200 | 100 | 50 | 150 | 37 | 13 | 50 | 75.0% : 25.0% |
| **Total** | **1,000** | **500** | **250** | **750** | **188** | **62** | **250** | **75.0% : 25.0%** |

### Split Properties & Integrity:
- **Sum Reconciled**: $600 + 200 + 200 = 1,000$ exactly. Both classes are represented in identical 75.0% / 25.0% proportions across all three splits.
- **Campaign Grouping**: Grouping by `From` domain + stripped subject skeleton + primary URL destination prevents near-duplicate campaign leakage across splits.
- **Scope of Validity**: The document explicitly concedes that a source-held-out evaluation is mathematically impossible because SpamAssassin has 0 phishing and Nazario has 0 ham. It states unambiguously that performance on the test split measures **in-distribution development generalization only**, not external real-world generalization.
- **Test Set Isolation**: Designated as a "Sealed Vault" evaluated exactly once at project conclusion.

---

## 3. Statistical Feasibility of Validation Targets

The experimental design proposes tuning decision thresholds on the validation set ($N = 200$: 150 ham, 50 phishing) to achieve:
- $FPR \le 1.0\%$
- $FNR \le 5.0\%$ ($\ge 95\%$ Recall)

### 3.1 Mathematical Calculation of Discrete Sensitivity

#### A. False Positive Rate on 150 Ham Samples:
Because the sample size is $N_{\text{ham}} = 150$, each individual false positive changes the observed rate by:
$$\Delta FPR = \frac{1}{150} \approx 0.67\%$$

| False Positives ($k$) | Observed Rate ($\hat{p}$) | 95% Wilson Score Confidence Interval | Target Status ($FPR \le 1.0\%$) |
|:---:|:---:|:---:|:---:|
| $k = 0$ | **0.00%** | $[0.00\%, 2.50\%]$ | PASSES |
| $k = 1$ | **0.67%** | $[0.12\%, 3.68\%]$ | PASSES |
| $k = 2$ | **1.33%** | $[0.37\%, 4.73\%]$ | **FAILS** |
| $k = 3$ | **2.00%** | $[0.68\%, 5.71\%]$ | **FAILS** |

#### B. False Negative Rate on 50 Phishing Samples:
Because the sample size is $N_{\text{phish}} = 50$, each individual false negative changes the observed rate by:
$$\Delta FNR = \frac{1}{50} = 2.00\%$$

| False Negatives ($k$) | Observed Rate ($\hat{p}$) | 95% Wilson Score Confidence Interval | Target Status ($FNR \le 5.0\%$) |
|:---:|:---:|:---:|:---:|
| $k = 0$ | **0.00%** | $[0.00\%, 7.13\%]$ | PASSES |
| $k = 1$ | **2.00%** | $[0.35\%, 10.50\%]$ | PASSES |
| $k = 2$ | **4.00%** | $[1.10\%, 13.46\%]$ | PASSES |
| $k = 3$ | **6.00%** | $[2.06\%, 16.22\%]$ | **FAILS** |

### 3.2 Statistical Verdict on Validation Targets
1. **High Sample Variance**: If the true underlying system FPR is $1.0\%$, the probability of observing 2 or more false positives in a sample of 150 is approximately $44.3\%$ (binomial distribution), causing an arbitrary failure.
2. **Wide Confidence Intervals**: Even if $k=1$ is observed on the validation set ($\hat{p} = 0.67\%$), the 95% confidence interval spans up to **$3.68\%$**. One cannot claim with 95% confidence that the true population FPR is $\le 1.0\%$.
3. **Formal Recommendation**:
   - The criteria $FPR \le 1.0\%$ and $FNR \le 5.0\%$ **must not be treated as hard statistical pass/fail acceptance gates**.
   - They must be designated as **Aspirational Operating Objectives** or **Optimization Loss Criteria** for threshold selection.
   - All reported validation and test performance metrics must accompany 95% Wilson score confidence intervals to prevent over-stating statistical precision.

---

## 4. Meta-Classifier and Out-of-Fold (OOF) Audit

### Leakage and Architecture Review:
- **10-Feature Vector**: Synthesizes 4 probabilities ($p_h, p_u, p_t, p_a$), 4 confidences ($c_h, c_u, c_t, c_a$), and 2 missingness flags ($m_u, m_a$).
- **Sample-to-Feature Ratio**: 600 training samples across 10 parameters yields a $60:1$ ratio, comfortably above the standard $10:1$ guideline for linear models.
- **5-Fold OOF Protocol**:
  - The 600-sample training partition is divided into 5 folds.
  - Agents train on 480 samples and predict on the held-out 120 samples.
  - The meta-classifier trains exclusively on these out-of-fold predictions.
  - **Verdict**: In-sample self-prediction leakage is completely eliminated.
- **Class-Weighting**: $w_{\text{phish}} = 3.0, w_{\text{ham}} = 1.0$ correctly compensates for the 3:1 class imbalance without synthetic data fabrication.
- **Non-Causal Interpretation**: The design explicitly warns that meta-classifier weights represent partial collinear association within the ensemble, not standalone causal importance.

### Identified Preprocessing Leakage Risk to Condition:
- **Vocabulary / Feature Scaling Isolation**: In fold-based training, if Text Agent TF-IDF vocabularies or numerical scalers are fitted on the entire 600-sample training set before fold partitioning, vocabulary tokens from the test folds will leak into the training folds.
- **Condition**: All preprocessing, vocabulary construction, token selection, and feature scalers must be fitted **strictly inside the 4-fold training split of each cross-validation iteration**.

---

## 5. Calibration and Abstention Audit

- **Independent Calibration**: Calibrated using Platt Scaling or Isotonic Regression on the 200-sample validation set. Test data is never used for calibration or threshold selection.
- **Three-Tier Policy**:
  - `Likely Phishing`: $P \ge \tau_{\text{high}}$
  - `Likely Legitimate`: $P \le \tau_{\text{low}}$
  - `Inconclusive / Abstain`: $\tau_{\text{low}} < P < \tau_{\text{high}}$
- **Coverage vs Selective Risk**: Evaluated via $\text{Coverage} = N_{\text{decided}} / N_{\text{total}}$ and $\text{Risk} = N_{\text{errors}} / N_{\text{decided}}$.
- **Binning Recommendation**: In standard 10-bin ECE calculation, 200 validation samples result in an average of only 20 samples per bin, leading to empty or noisy bins in the low-probability spectrum.
- **Condition**: Calibration assessment on the validation set should employ **5 equal-frequency bins** or kernel-density calibration to maintain statistical robustness.

---

## 6. Hypothesis H5 Audit

- **Empirical Grounding**:
  - 0 of 750 ham emails have authentication claims (SpamAssassin 2002–2003 precedes SPF/DKIM/DMARC deployment).
  - Phishing emails contain 25 SPF pass, 31 DKIM pass, and 9 DMARC pass claims.
  - All claims remain unverified receiver assertions.
- **Confounder Assessment**: Confirmed. Because authentication claims correlate 100% with phishing in this corpus, treating authentication claims as positive signals would invert real-world logic.
- **Verdict**: **EXPLORATORY ONLY**. The document adheres strictly to prompt instructions and refuses to claim statistical testability on the current dataset.
- **Data Specification**: Correctly specifies the need for a contemporary (2020–2026) corpus with $\ge 500$ authenticated legitimate emails and $\ge 250$ authenticated phishing emails before formal hypothesis testing can proceed.

---

## 7. Implementation Readiness

The research deliverables provide clear, unambiguous specifications for all downstream components:
- **Header Agent**: Clear whitelist; Return-Path/From/Reply-To alignment; Message-ID syntax; Received hop counts; unverified auth claims.
- **URL Agent**: Lexical complexity; scheme validation; anchor-text mismatch; contextual extraction sources.
- **Text Agent**: Semantic intent patterns (urgency, credential solicitation) evaluated on normalized `cleaned_text`.
- **Attachment Agent**: Static MIME types, extensions, double extensions, sizes; neutral default ($p=0.5, c=0.0, m_a=1$) when absent.
- **Meta-Classifier**: Explicit 10-feature vector, regularized logistic loss, inverse class weights, bootstrap confidence intervals.

---

## 8. Repository and Regression Verification

- **Deliverables Existence**: All six documents are present, complete, and formatted correctly.
- **Git Working Tree**: Clean working tree verified. Documentation resides in `docs/research/` and project root. Raw archives and development EMLs remain completely ignored by Git (`.gitignore:50` and `.gitignore:51`).
- **Regression Execution**: `pytest -v` executed across the entire repository:
  ```text
  ============================ 441 passed in 18.83s =============================
  ```
  Zero failures, zero warnings, zero regressions.

---

## Required Implementation Conditions (for Task 8.5+)

The research design is approved subject to the following **four explicit implementation conditions**:

1. **Condition 1 (Aspirational Operational Targets)**:
   The validation criteria $FPR \le 1.0\%$ and $FNR \le 5.0\%$ must be treated during optimization as **Aspirational Operating Objectives**, not hard statistical pass/fail gates. All reported rates must include 95% Wilson score confidence intervals reflecting small-sample granularity.
2. **Condition 2 (Received Header Hostname Stripping)**:
   The Header Agent feature extractor must extract structural routing properties (hop count, transit delay, private IP presence) and must **strictly exclude server hostnames/domains** (e.g. `dogma.slashnull.org`) from `Received` headers to prevent infrastructure memorization.
3. **Condition 3 (Fold-Isolated Preprocessing)**:
   During 5-fold out-of-fold meta-training, all preprocessing steps (TF-IDF vectorizers, token selection, feature scalers) must be fitted **strictly inside the training folds of each iteration** to prevent out-of-fold vocabulary leakage.
4. **Condition 4 (Adaptive Calibration Binning)**:
   When evaluating Expected Calibration Error (ECE) on the 200-sample validation split, reliability diagrams must use **5 bins or adaptive binning** rather than 10 fixed bins to avoid sparse bin artifacts.

---

## Final Recommendation

### **Verdict: APPROVE WITH CONDITIONS**

The Task 8.4.1 research design satisfies all methodological, security, and integrity requirements. Implementation of Task 8.5 (Agent Implementation) may proceed upon acknowledging the four operational conditions outlined above. No modifications to existing code, tests, datasets, or manifests are required.
