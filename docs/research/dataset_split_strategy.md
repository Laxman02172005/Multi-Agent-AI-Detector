# Dataset Splitting and Evaluation Strategy

**Document**: `docs/research/dataset_split_strategy.md`  
**Task**: 8.4.1 Research Design and Dataset Bias Mitigation  
**Date**: November 12, 2026  
**Status**: APPROVED RESEARCH DESIGN SPECIFICATION  

---

## 1. Corpus Confounding & Structural Limitations

### 1.1 The Source-Class Confounding Problem
The development dataset contains 1,000 emails composed of:
- **750 Ham emails**: 500 `easy_ham` and 250 `hard_ham`, all originating from SpamAssassin (2002–2003).
- **250 Phishing emails**: 188 from Nazario 2015 and 62 from Nazario 2021.

This structure creates **perfect confounding** between data source and ground-truth class:
- $P(\text{SpamAssassin} \mid \text{Ham}) = 1.0$
- $P(\text{Nazario} \mid \text{Phishing}) = 1.0$

### 1.2 Mathematical Impossibility of a Source-Held-Out Split
In rigorous machine-learning evaluation, a "source-held-out" (Leave-One-Source-Out) validation split is standard for assessing whether a model generalizes across different email collection systems.
However, in this dataset:
- No source contains both ham and phishing.
- Holding out SpamAssassin removes 100% of the legitimate ham samples.
- Holding out Nazario removes 100% of the phishing samples.

> **Formal Limitation**: A true source-held-out evaluation is **mathematically impossible** on the 1,000-email development dataset. Consequently, performance measured on any test split of this dataset assesses **in-distribution development generalization only**, and **cannot prove real-world out-of-distribution generalization**. A separate contemporary benchmark corpus containing both modern ham and modern phishing is required for external validation.

---

## 2. Pitfalls of Unconstrained Random Stratified Splitting

If an unconstrained random stratified split is applied to this dataset, reported evaluation metrics will severely overestimate real-world performance due to:

1. **Sender and Campaign Clustering**:
   - Multiple phishing emails in Nazario archives belong to identical phishing campaigns (e.g., identical phishing kits sent to different recipients with varying timestamps).
   - In SpamAssassin, multiple ham emails belong to the same mailing list threads with shared participants.
   - If related messages fall randomly into both training and test sets, the model achieves high test accuracy simply by memorizing specific sending domains or subjects.
2. **Formatting & Encoding Leakage**:
   - Random sampling spreads subtle corpus-level MIME boundary styles and character-set quirks across all splits, enabling models to classify based on formatting artifacts rather than malicious intent.

---

## 3. Proposed Evaluation Protocol: Grouped Stratified Partitioning

To mitigate campaign leakage while preserving exact category and source-year proportions across all partitions, the dataset is split using **Grouped Stratified Partitioning**.

### 3.1 Partition Allocation
The 1,000-email development dataset is partitioned into three strictly separated splits:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1,000-Email Development Dataset                                              │
├───────────────────────────────┬──────────────────────────────┬──────────────┤
│ Train Split: 60.0% (n=600)    │ Validation Split: 20% (n=200)│ Test: 20%    │
│ 300 easy_ham, 150 hard_ham    │ 100 easy_ham, 50 hard_ham    │ 100 easy_ham │
│ 113 phish 2015, 37 phish 2021 │ 38 phish 2015, 12 phish 2021 │ 50 hard_ham  │
│                               │                              │ 37 phish '15 │
│                               │                              │ 13 phish '21 │
└───────────────────────────────┴──────────────────────────────┴──────────────┘
```

| Partition | Total Samples | ham_easy (SA) | ham_hard (SA) | Total Ham | Phishing 2015 | Phishing 2021 | Total Phish | Phish % |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Training Set** | **600** | 300 | 150 | 450 | 113 | 37 | 150 | 25.0% |
| **Validation Set** | **200** | 100 | 50 | 150 | 38 | 12 | 50 | 25.0% |
| **Test Set** | **200** | 100 | 50 | 150 | 37 | 13 | 50 | 25.0% |
| **Total Dataset** | **1,000** | **500** | **250** | **750** | **188** | **62** | **250** | **25.0%** |

### 3.2 Partition Roles and Boundary Enforcement

1. **Training Split (60%, n=600)**:
   - Used exclusively for training individual agent feature extractors, vocabulary building, and estimating model weights.
   - Out-of-fold cross-validation on this partition is used to fit the meta-classifier.
2. **Validation Split (20%, n=200)**:
   - Used for hyperparameter tuning (regularization strength $C$), agent confidence calibration (Platt scaling / isotonic regression), and decision threshold optimization ($\tau_{\text{high}}, \tau_{\text{low}}$).
   - Under no circumstances is the validation set used for fitting model coefficients.
3. **Test Split (20%, n=200) — "Sealed Vault"**:
   - Completely quarantined during all stages of model development, feature selection, agent design, and threshold tuning.
   - Evaluated **exactly once** at the conclusion of the research study to report final unbiased performance metrics.
   - Any modification of model weights, thresholds, or features after inspecting test-set performance is strictly prohibited.

---

## 4. Leakage-Prevention Constraints

### 4.1 Campaign Clustering & Grouped Partitioning
To prevent near-duplicate campaign leakage across splits:
1. **Grouping Key Construction**: Each email is assigned a campaign cluster key based on:
   - Normalized `From` domain + normalized `Subject` skeleton (all numbers and punctuation stripped).
   - For emails with URLs: registered domain of primary destination URL.
2. **Group Constraint**: All messages sharing a campaign cluster key must reside entirely within a single split (Train, Validation, or Test). They are never distributed across split boundaries.
3. **Class Stratification**: Because grouping can skew class ratios, a constrained group-shuffle algorithm is used that maintains the exact 75% ham / 25% phishing balance in each split while respecting cluster boundaries.

### 4.2 Seed and Reproducibility Invariant
- **Random Seed**: Fixed at `seed=42`.
- **Deterministic Sort**: Candidates are sorted by `(source_category, sha256)` before partitioning to guarantee bit-for-bit reproducibility across runs, platforms, and Python interpreter versions.
- **Manifest Persistence**: The partition assignment for every sample (`train`, `val`, `test`) is persisted to `data/dev/manifests/split_manifest.json` before any downstream modeling begins.
