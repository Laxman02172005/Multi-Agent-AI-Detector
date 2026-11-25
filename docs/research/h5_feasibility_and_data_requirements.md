# Hypothesis H5 Feasibility and Additional Data Requirements

**Document**: `docs/research/h5_feasibility_and_data_requirements.md`  
**Task**: 8.4.1 Research Design and Dataset Bias Mitigation  
**Date**: November 12, 2026  
**Status**: APPROVED RESEARCH DESIGN SPECIFICATION  

---

## 1. Hypothesis Definition and Research Context

> **Hypothesis H5**: *"Multi-agent phishing detection degrades significantly less than baseline approaches when phishing emails contain successful authentication claims."*

### Theoretical Foundation
Phishing attacks increasingly leverage legitimate, compromised sending infrastructure (e.g., hijacked Microsoft 365 / Google Workspace accounts, shared marketing relays, or open forwarders) where the sending domain's SPF, DKIM, and DMARC checks **pass cleanly**. 
Traditional perimeter defenses that treat an authentication pass as an authoritative proof of benign intent suffer catastrophic detection degradation on authenticated phishing. 
Hypothesis H5 asserts that a decoupled, multi-modal multi-agent architecture will remain robust because semantic text analysis, URL lexical inspection, and attachment metadata will maintain high detection belief even when header authentication signals benign alignment.

---

## 2. Empirical Findings from Task 8.4 Analysis

The exploratory analysis conducted on the 1,000-email development dataset in Task 8.4 yielded the following exact empirical counts:

| Cohort | Total Emails | SPF Pass Claims | DKIM Pass Claims | DMARC Pass Claims | Multiple Pass Claims | All Three Pass |
|---|---:|---:|---:|---:|---:|---:|
| **ham_easy** (SpamAssassin 2002) | 500 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| **ham_hard** (SpamAssassin 2002) | 250 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| **Total Legitimate Ham** | **750** | **0 (0.0%)** | **0 (0.0%)** | **0 (0.0%)** | **0 (0.0%)** | **0 (0.0%)** |
| **Phishing (2015)** (Nazario) | 188 | 1 (0.5%) | 13 (6.9%) | 0 (0.0%) | 1 (0.5%) | 0 (0.0%) |
| **Phishing (2021)** (Nazario) | 62 | 24 (38.7%) | 18 (29.0%) | 9 (14.5%) | 16 (25.8%) | 8 (12.9%) |
| **Total Phishing** | **250** | **25 (10.0%)** | **31 (12.4%)** | **9 (3.6%)** | **17 (6.8%)** | **8 (3.2%)** |

### Critical Authentication Evidence Invariants:
1. **Claims are Unverified**: All recorded counts represent third-party receiving MTA assertions extracted passively from `Authentication-Results` and `Received-SPF` headers. They do not constitute independently verified cryptographic proofs.
2. **Missing is Not Failure**: 942 SPF, 771 DKIM, and 918 DMARC statuses are explicitly recorded as `missing`, representing absent infrastructure rather than evaluation failures.

---

## 3. Confounding Problem & Feasibility Verdict

### 3.1 The Confounding Barrier
The experimental evaluation of Hypothesis H5 on the current 1,000-email development dataset faces a fatal statistical confounder:
- **100% of emails with successful authentication claims are Phishing.**
- **0% of legitimate ham emails possess any authentication claims.**

If a baseline model (such as Logistic Regression, Random Forest, or a Header-only classifier) is trained on this dataset with authentication features enabled, the optimization gradient will assign a **positive weight** to `dkim=pass` and `spf=pass` as predictive indicators of phishing! 
This completely inverts the real-world semantic meaning of email authentication. 

Furthermore, measuring "detection degradation on authenticated phishing" requires comparing:
$$\Delta R = R(\text{unauthenticated phishing}) - R(\text{authenticated phishing})$$
while simultaneously evaluating the false-positive penalty on authenticated legitimate email:
$$FPR(\text{authenticated legitimate ham})$$
Because the current dataset contains zero authenticated legitimate emails, $FPR(\text{authenticated legitimate ham})$ cannot be evaluated at all.

### 3.2 Formal Feasibility Classification

| Feasibility Classification | Status | Rationale |
|---|:---:|---|
| **FEASIBLE WITH CURRENT DATA** | REJECTED | Rejected due to 0% authenticated ham and severe temporal confounding. |
| **EXPLORATORY ONLY** | **APPROVED** | Current data supports qualitative case tracing and descriptive feature inspection of the 31 DKIM-pass and 25 SPF-pass phishing emails, but cannot support formal hypothesis testing. |
| **NOT TESTABLE WITH CURRENT DATA** | QUALIFIED | H5 as a formal comparative statistical claim is not testable on the dev set alone without supplementary modern legitimate data. |

---

## 4. Specification for Additional Dataset Acquisition

To rigorously test Hypothesis H5 in a future dedicated phase (Task 9+ or external benchmarking), an additional evaluation dataset must be acquired adhering to the following strict specifications:

### 4.1 Required Dataset Attributes
1. **Contemporary Temporal Alignment (2020–2026)**:
   - Both ham and phishing samples must originate from the modern email era where SPF, DKIM, and DMARC are ubiquitously deployed.
2. **Balanced Authentication Ground Truth**:
   - Minimum **500 Contemporary Legitimate Ham Emails** with valid, authentic SPF pass, DKIM pass, and DMARC pass claims from major corporate, academic, and commercial sending domains.
   - Minimum **250 Contemporary Phishing Emails** exhibiting verified SPF pass and DKIM pass claims (compromised accounts, forwarders, or legitimate cloud relays).
3. **Raw RFC 822 / MIME Byte Integrity**:
   - Emails must be preserved as unrendered `.eml` or native MBOX files containing intact `Authentication-Results`, `DKIM-Signature`, `Received-SPF`, and `Received` headers.
4. **Sender Diversity**:
   - Emails must originate from at least 50 distinct parent domains to prevent model memorization of specific domain keys.
5. **Ethical, Legal, and Privacy Standards**:
   - Permissive research licensing (public domain, Creative Commons, or explicit IRB/corporate consent).
   - Strict redacting of personal identifiable information (PII), personal phone numbers, and private credentials.
   - Zero live malware attachments or weaponized links.

---

## 5. Experimental Protocol for H5 Evaluation

When the supplementary contemporary dataset is integrated, Hypothesis H5 will be evaluated under a controlled comparative protocol across three experimental conditions:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Condition 1: Authentication Features Excluded                               │
│ Both baseline and multi-agent systems operate strictly on content/URLs.      │
│ Measures baseline degradation floor.                                        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ Condition 2: Authentication Claims Included as Direct Features               │
│ Baseline models and Header Agent consume SPF/DKIM/DMARC status directly.     │
│ Evaluates whether monolithic models over-rely on authentication pass.        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ Condition 3: Matched Subgroup Stratification                                │
│ Evaluation restricted strictly to emails with SPF=pass AND DKIM=pass:        │
│ (Authenticated Phishing vs Authenticated Legitimate Ham).                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.1 Primary Evaluation Metric: Relative Degradation Gap
The core metric testing H5 is the **Relative Phishing Recall Degradation ($\Delta \text{Degradation}$)**:

$$\Delta \text{Degradation} = \text{Degradation}_{\text{Baseline}} - \text{Degradation}_{\text{MultiAgent}}$$
where:
$$\text{Degradation} = \frac{R(\text{Unauthenticated Phish}) - R(\text{Authenticated Phish})}{R(\text{Unauthenticated Phish})} \times 100\%$$

- **Confirmation Criterion for H5**: Hypothesis H5 is confirmed if and only if:
  1. The Multi-Agent Meta-Classifier demonstrates a statistically significant lower recall degradation ($\Delta \text{Degradation} \ge 10.0\%$, $p < 0.01$).
  2. The Multi-Agent Meta-Classifier maintains a False Positive Rate on authenticated legitimate emails $FPR_{\text{auth\_ham}} \le 1.0\%$.
