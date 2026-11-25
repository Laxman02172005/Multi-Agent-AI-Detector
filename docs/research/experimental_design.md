# Experimental Design and Meta-Classifier Specification

**Document**: `docs/research/experimental_design.md`  
**Task**: 8.4.1 Research Design and Dataset Bias Mitigation  
**Date**: November 12, 2026  
**Status**: APPROVED RESEARCH DESIGN SPECIFICATION  

---

## 1. Experimental Architecture Overview

The detection architecture employs a **hierarchical multi-agent structure** wherein specialized, domain-isolated agents independently extract evidence, compute belief scores, and quantify domain-specific uncertainty. An aggregation layer then coordinates an interpretable Logistic Regression meta-classifier to synthesize agent outputs into a calibrated overall verdict with an explicit abstention policy.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Preprocessed & Sanitized Email (Tier 3 Approved Features)                   │
└───────┬───────────────┬───────────────────────────────┬──────────────┬──────┘
        │               │                               │              │
        ▼               ▼                               ▼              ▼
┌──────────────┐┌──────────────┐                ┌──────────────┐┌──────────────┐
│ Header Agent ││  URL Agent   │                │  Text Agent  ││ Attach Agent │
└───────┬──────┘└───────┬──────┘                └───────┬──────┘└───────┬──────┘
        │               │                               │              │
        │ p_h, c_h, u_h │ p_u, c_u, u_u, m_u            │ p_t, c_t, u_t│ p_a, c_a, m_a
        └───────┬───────┴───────────────┬───────────────┴──────────────┘
                │                       │
                ▼                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Evidence Aggregation Layer & Feature Vector Assembler                       │
│ x_meta = [p_h, p_u, p_t, p_a, c_h, c_u, c_t, c_a, m_u, m_a]                 │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Logistic Regression Meta-Classifier (Learned Weights via 5-Fold OOF)         │
│ P(phishing | x) = σ(w^T x_meta + b)                                         │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Decision Policy & Uncertainty Band (Validation-Tuned Thresholds)            │
│ P >= τ_high  ──► LIKELY PHISHING                                            │
│ P <= τ_low   ──► LIKELY LEGITIMATE                                          │
│ Otherwise    ──► INCONCLUSIVE / ABSTAIN                                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Experimental Baselines

To rigorously evaluate the multi-agent hypothesis, the architecture will be benchmarked against seven progressive baselines:

| Baseline Model | Purpose & Hypothesis Tested | Input Features | Expected Limitations | Key Evaluation Metrics |
|---|---|---|---|---|
| **1. Majority-Class Baseline** | Establish floor performance under class imbalance (75% ham / 25% phishing). | None (always outputs `ham`). | Zero detection utility; 0% phishing recall. | Accuracy (75.0%), Phishing Recall (0.0%), F1 (0.0). |
| **2. Header-Only Baseline** | Measure phishing signal isolated to RFC 5322 header anomalies and sender mismatches. | Approved Header Agent feature vector. | Blind to malicious URLs, attachments, and coercive body text. | Precision, Recall, ROC-AUC, FPR at 95% Recall. |
| **3. URL-Only Baseline** | Measure phishing signal isolated to link lexical structure and anchor mismatches. | Approved URL Agent feature vector. | Ineffective on emails without URLs (12.1% of dev set) or attachment-based attacks. | Precision, Recall, PR-AUC, Coverage on URL emails. |
| **4. Text-Only Baseline** | Measure natural language semantic cues (urgency, credential solicitation). | Approved Text Agent NLP vector (TF-IDF / Embedding). | Sensitive to vocabulary shifts; blind to header spoofing or clean URLs. | F1-Score, ROC-AUC, Precision at high Recall. |
| **5. Attachment-Only Baseline** | Measure detection capability isolated to static attachment metadata. | Approved Attachment Agent feature vector. | Inactive on 94.1% of emails; must output neutral predictions when absent. | Precision on attachment subset, Selective Risk. |
| **6. Flat Monolithic Concatenation Baseline** | Test whether hierarchical agent abstraction outperforms an uncoordinated single classifier. | Flat concatenation of all approved features into a single model (e.g. Ridge / Random Forest). | Prone to overfitting on dominant modalities; lacks modular uncertainty quantification. | Test Macro-F1, ROC-AUC, Brier Score, ECE. |
| **7. Multi-Agent Meta-Classifier (Proposed)** | Evaluate cooperative synthesis, domain confidence weighting, and selective abstention. | Multi-agent state vector (probabilities, confidences, missingness flags). | Performance bound by agent quality; meta-sample size limited to 600 training samples. | Macro-F1, ROC-AUC, PR-AUC, FPR at 99% Recall, Coverage. |

---

## 3. Logistic Regression Meta-Classifier Design

### 3.1 Meta-Feature Input Space ($\mathbf{x}_{\text{meta}}$)
The meta-classifier synthesizes 10 low-dimensional meta-features emitted by the four agents:

1. $p_h \in [0, 1]$: Header Agent phishing probability.
2. $p_u \in [0, 1]$: URL Agent phishing probability ($0.5$ if no URLs present).
3. $p_t \in [0, 1]$: Text Agent phishing probability.
4. $p_a \in [0, 1]$: Attachment Agent phishing probability ($0.5$ if no attachments present).
5. $c_h \in [0, 1]$: Header Agent confidence score.
6. $c_u \in [0, 1]$: URL Agent confidence score ($0.0$ if no URLs present).
7. $c_t \in [0, 1]$: Text Agent confidence score.
8. $c_a \in [0, 1]$: Attachment Agent confidence score ($0.0$ if no attachments present).
9. $m_u \in \{0, 1\}$: Missing URL indicator ($1$ if email contains no URLs, $0$ otherwise).
10. $m_a \in \{0, 1\}$: Missing attachment indicator ($1$ if email contains no attachments, $0$ otherwise).

### 3.2 Formal Mathematical Formulation
$$\hat{P}(\text{phishing} \mid \mathbf{x}_{\text{meta}}) = \sigma\left(\mathbf{w}^T \mathbf{x}_{\text{meta}} + b\right) = \frac{1}{1 + e^{-\left(\sum_{i=1}^{10} w_i x_i + b\right)}}$$

### 3.3 Strict Leakage Prevention: Out-of-Fold (OOF) Training Protocol
> **CRITICAL RESTRICTION: No In-Sample Self-Prediction**  
> If the meta-classifier were trained on agent predictions evaluated on the same training data the agents were fitted on, the agents would output over-confident, over-fitted probabilities near $0.0$ and $1.0$. The meta-classifier would learn artificially extreme weights that collapse on unseen test data.

**Approved Protocol: 5-Fold Stratified Cross-Validation on the Training Split (n=600)**:
1. Divide the 600-sample Training Split into 5 stratified folds of 120 emails each.
2. For fold $k \in \{1, \dots, 5\}$:
   - Train the four specialized agents on the remaining 4 folds (480 emails).
   - Generate out-of-fold predictions and confidence vectors for the held-out fold $k$ (120 emails).
3. Concatenate the 5 out-of-fold prediction blocks into a clean $600 \times 10$ training matrix $\mathbf{X}_{\text{OOF}}$.
4. Train the Logistic Regression meta-classifier on $\mathbf{X}_{\text{OOF}}$ using ground-truth labels.
5. Re-train the individual agents on the complete 600-sample Training Split for downstream inference on Validation and Test sets.

### 3.4 Regularization, Loss Function, and Class Weighting
- **Regularization**: L2 (Ridge) penalty to prevent collinearity and over-fitting in the 10-dimensional space.
- **Cost Function with Inverse-Frequency Class Weighting**:
  $$\mathcal{L}(\mathbf{w}, b) = -\sum_{i=1}^{N} \left[ w_{\text{class}} y_i \log(\hat{p}_i) + (1 - y_i) \log(1 - \hat{p}_i) \right] + \frac{\lambda}{2} \|\mathbf{w}\|_2^2$$
  where $w_{\text{phishing}} = \frac{750}{250} = 3.0$ and $w_{\text{ham}} = 1.0$, balancing the loss gradient against the 3:1 majority ham prevalence.
- **Prohibition on Manual Weights**: **Agent weights $\mathbf{w}$ must never be hand-crafted or manually assigned.** All weights must be learned strictly via regularized empirical risk minimization.

### 3.5 Effective Sample Size & Confidence Intervals
- The meta-classifier trains on $N = 600$ out-of-fold instances (450 ham, 150 phishing). With 10 parameters, the ratio of samples to features is $60:1$, comfortably above standard statistical thresholds ($>10:1$).
- **Bootstrap Parameter Confidence Intervals**: 1,000 bootstrap iterations over the training set will compute empirical 95% confidence intervals for each coefficient $w_i$, verifying whether each agent contributes statistically significant predictive power ($p < 0.05$).

---

## 4. Decision Policy, Uncertainty, and Abstention

A single binary threshold (e.g. $0.5$) is unacceptable in security-critical phishing detection, where false positives disrupt business operations and false negatives lead to credential compromise.

### 4.1 Three-Tier Classification with Selective Abstention
The system produces three operational verdicts:

$$\text{Verdict}(P) = \begin{cases} 
\text{\textbf{Likely Phishing}}, & \text{if } P \ge \tau_{\text{high}} \\ 
\text{\textbf{Likely Legitimate}}, & \text{if } P \le \tau_{\text{low}} \\ 
\text{\textbf{Inconclusive (Abstain)}}, & \text{if } \tau_{\text{low}} < P < \tau_{\text{high}} 
\end{cases}$$

```
    0.0 ─────────────── τ_low ─────────────── τ_high ─────────────── 1.0
     [ Likely Legitimate ] [ Inconclusive / Abstain ] [ Likely Phishing ]
```

### 4.2 Threshold Optimization on the Validation Set (n=200)
Thresholds $\tau_{\text{low}}$ and $\tau_{\text{high}}$ are tuned strictly on the held-out Validation Split (never on training or test sets):
- **$\tau_{\text{high}}$ (Phishing Decision Ceiling)**: Set to the lowest probability $P$ on the validation set that guarantees a False Positive Rate $FPR \le 1.0\%$ ($\le 1$ false positive per 100 legitimate emails).
- **$\tau_{\text{low}}$ (Legitimate Decision Floor)**: Set to the highest probability $P$ on the validation set that guarantees a Phishing False Negative Rate $FNR \le 5.0\%$ ($\ge 95\%$ recall on phishing).
- **Abstention Band ($\tau_{\text{low}}, \tau_{\text{high}}$)**: Samples falling in this range are flagged as `Inconclusive` and routed for secondary human review or safe sandboxing.

### 4.3 Probability Calibration
A raw logistic regression score does not inherently represent true empirical posterior probability under class imbalance.
- **Platt Scaling & Isotonic Regression**: Calibrated on the Validation Split using 5-fold cross-validation.
- **Calibration Metrics**:
  - **Expected Calibration Error (ECE)**: Grouping predictions into 10 reliability bins and measuring the weighted difference between average confidence and accuracy. Target: $ECE \le 0.05$.
  - **Brier Score**: Mean squared error between predicted probabilities and binary outcomes: $\text{Brier} = \frac{1}{N} \sum_{i=1}^N (\hat{p}_i - y_i)^2$.

---

## 5. Comprehensive Evaluation Metrics

Standard accuracy is fundamentally misleading on this dataset (75.0% baseline accuracy). Evaluation must prioritize the following formal metric hierarchy:

### 5.1 Primary Security Metrics
1. **Macro-Averaged F1-Score**: Harmonic mean of Precision and Recall calculated per class and averaged unweighted:
   $$\text{Macro-F1} = \frac{F1_{\text{ham}} + F1_{\text{phishing}}}{2}$$
2. **False Positive Rate at Target Recall ($FPR_{R \ge 95\%}$)**: Proportion of legitimate ham falsely classified as phishing when the operating threshold achieves $\ge 95\%$ phishing recall. Primary metric for minimizing user disruption.
3. **Area Under the Precision-Recall Curve (PR-AUC)**: Measures trade-off across all operating thresholds; highly robust to class imbalance.
4. **Coverage & Selective Risk (for Abstention Evaluation)**:
   - **Coverage**: Proportion of non-abstained emails: $\text{Coverage} = \frac{N_{\text{decided}}}{N_{\text{total}}}$.
   - **Selective Risk**: Error rate evaluated strictly on non-abstained samples: $\text{Risk} = \frac{N_{\text{errors on decided}}}{N_{\text{decided}}}$.

### 5.2 Secondary Analytical Metrics
1. **Area Under the ROC Curve (ROC-AUC)**: Global discriminative capability across all thresholds.
2. **Expected Calibration Error (ECE)** and **Brier Score**: Probability calibration reliability.
3. **Confusion Matrix**: Full four-cell count matrix ($TP, FP, TN, FN$) plus abstention counts ($A_{\text{ham}}, A_{\text{phishing}}$).
4. **95% Confidence Intervals**: Bootstrapped (1,000 iterations) for all primary metrics.
