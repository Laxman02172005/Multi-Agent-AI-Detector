# Task 8.4: Dataset Quality, Bias, and Research Feasibility Analysis Report

**Project**: Multi-Agent AI Phishing Email Detector  
**Task**: 8.4 Dataset Quality, Bias, and Research Feasibility Analysis  
**Dataset Analyzed**: Approved 1,000-Email Development Dataset (`data/dev/eml/`)  
**Date**: November 12, 2026  
**Status**: COMPLETE (Exhaustive analysis across all 7 analytical domains)  

---

## Executive Summary

A comprehensive, exploratory, read-only analysis of the approved 1,000-email development dataset was performed across seven critical analytical domains. All 1,000 emails were parsed through the project's unified `EmailIngestor` pipeline, yielding 1,000 validated `EmailData` models with zero fatal parsing errors, zero duplicate content digests, and complete field reconciliation.

### Key Analytical Findings:

1. **Dataset Integrity & Parsing Fidelity**:
   - Exactly 1,000 unique EML files on disk (500 `ham_easy`, 250 `ham_hard`, 250 `phishing`).
   - 100% parsing success rate (1,000 / 1,000) with 45 non-fatal warnings (4.5%, primarily undeclared charsets or non-ASCII characters).
   - Zero duplicate SHA-256 hashes.
2. **Authentication Asymmetry & H5 Verdict**:
   - **Severe Temporal Asymmetry**: All 750 legitimate ham emails originate from SpamAssassin (2002–2003) and contain **zero** SPF, DKIM, or DMARC authentication claims.
   - The 250 phishing emails (sourced from Nazario 2015 and 2021) contain 25 SPF pass, 31 DKIM pass, and 9 DMARC pass claims.
   - **Hypothesis H5 Verdict**: Classified as **EXPLORATORY ONLY**. In this dataset, authentication claims correlate exclusively with phishing due to the temporal gap; testing whether multi-agent detection degrades less on authenticated phishing requires a contemporary authenticated legitimate email corpus.
3. **Dataset Shortcuts & Leakage Risks**:
   - **Date Leakage (Critical)**: 100% of dated ham messages originate from 2002, whereas 100% of dated phishing messages originate from 2015 or 2021. Classifiers must not use the `Date` header.
   - **Source/Scanner Leakage (High)**: 249 of 250 phishing emails (99.6%) contain `X-Spam-*` scanner headers injected by spam traps, while 398 of 750 ham emails (53.1%) contain `List-*` mailing list headers. Downstream feature extractors must strip these corpus artifacts.
   - **Formatting Disparity (Medium)**: 99.8% of `easy_ham` is plain-text only, whereas 92.0% of phishing emails contain HTML markup.
4. **Agent Feasibility**:
   - **Header Agent**: Feasible (core RFC 5322 headers possess >95% availability).
   - **URL Agent**: Feasible & High-Impact (87.9% of emails contain URLs; 16,941 total extracted occurrences across HTML hrefs, plain text, and embedded sources).
   - **Text Agent**: Feasible (99.8% body coverage; `cleaned_text` normalizes formatting differences).
   - **Attachment Agent**: Feasible but Sparse (only 5.9% of emails contain attachments; 78 total attachments).
   - **Meta-Classifier & Aggregation Layer**: Feasible (sufficient sample volume for linear meta-classification and confidence calibration).

---

## 1. Dataset Composition and Integrity

The development dataset is strictly structured according to the approved sampling targets:

| Dataset Category | Source Corpus & Archive | Assigned Label | Sample Count | Percentage |
|---|---|---|---:|---:|
| **Easy Ham** | SpamAssassin (`20030228_easy_ham.tar.bz2`) | `ham_easy` | 500 | 50.0% |
| **Hard Ham** | SpamAssassin (`20030228_hard_ham.tar.bz2`) | `ham_hard` | 250 | 25.0% |
| **Phishing (2015)** | Nazario (`phishing-2015.mbox`) | `phishing` | 188 | 18.8% |
| **Phishing (2021)** | Nazario (`phishing-2021.mbox`) | `phishing` | 62 | 6.2% |
| **TOTAL** | — | — | **1,000** | **100.0%** |

### File Size Distribution (Bytes)

| Cohort | Count | Min | 25th Pct | Median | Mean | 75th Pct | 90th Pct | Max | Std Dev |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Overall Dataset** | 1,000 | 493 | 3,150 | 4,753 | 15,416 | 13,640 | 30,769 | 1,424,910 | 57,991 |
| **ham_easy** | 500 | 493 | 1,918 | 3,303 | 4,156 | 4,284 | 5,258 | 202,500 | 10,636 |
| **ham_hard** | 250 | 1,003 | 9,091 | 24,153 | 22,756 | 31,062 | 33,881 | 300,734 | 24,594 |
| **phishing** | 250 | 2,387 | 5,339 | 8,623 | 30,594 | 16,583 | 39,811 | 1,424,910 | 110,095 |

#### Observations:
- `ham_easy` messages are compact (median 3.3 KB), reflecting typical plain-text interpersonal or open-source mailing list correspondence.
- `ham_hard` messages are significantly larger (median 24.2 KB), consisting of complex HTML newsletters, marketing digests, and rich multi-table layouts.
- `phishing` messages exhibit high variance (min 2.4 KB, max 1.42 MB, mean 30.6 KB), driven by embedded HTML forms, base64-encoded image logos, and multi-part MIME structures.

### Integrity & Parsing Metrics:
- **Duplicate SHA-256 Hashes**: 0 (1,000 unique content digests).
- **Successfully Parsed Emails**: 1,000 (100.0%).
- **Fatal / Malformed Ingestion Failures**: 0 (0.0%).
- **Non-Fatal Parsing Warnings**: 45 emails (4.5%), including 25 undeclared charsets, 15 fallback charset decodings, and 7 minor MIME syntax quirks.

---

## 2. Header Availability Analysis

An exhaustive audit of 11 critical RFC 5322 header fields was conducted across all 1,000 emails:

| Header Field | Present | Present % | Missing | Missing % | ham_easy (P/M) | ham_hard (P/M) | phishing (P/M) |
|---|---:|---:|---:|---:|:---:|:---:|:---:|
| **From** | 998 | 99.8% | 2 | 0.2% | 499 / 1 | 249 / 1 | 250 / 0 |
| **To** | 931 | 93.1% | 69 | 6.9% | 465 / 35 | 249 / 1 | 217 / 33 |
| **Cc** | 102 | 10.2% | 898 | 89.8% | 98 / 402 | 4 / 246 | 0 / 250 |
| **Reply-To** | 296 | 29.6% | 704 | 70.4% | 153 / 347 | 87 / 163 | 56 / 194 |
| **Return-Path** | 989 | 98.9% | 11 | 1.1% | 499 / 1 | 240 / 10 | 250 / 0 |
| **Subject** | 997 | 99.7% | 3 | 0.3% | 499 / 1 | 248 / 2 | 250 / 0 |
| **Date** | 998 | 99.8% | 2 | 0.2% | 499 / 1 | 249 / 1 | 250 / 0 |
| **Message-ID** | 959 | 95.9% | 41 | 4.1% | 499 / 1 | 249 / 1 | 211 / 39 |
| **Received** | 968 | 96.8% | 32 | 3.2% | 469 / 31 | 249 / 1 | 250 / 0 |
| **MIME-Version** | 769 | 76.9% | 231 | 23.1% | 309 / 191 | 215 / 35 | 245 / 5 |
| **Content-Type** | 886 | 88.6% | 114 | 11.4% | 417 / 83 | 219 / 31 | 250 / 0 |

### Critical Header Observations:
1. **Core Envelope Fields**: `From`, `Return-Path`, `Subject`, and `Date` are present in >98.9% of emails across all categories.
2. **Missing Message-ID**: 39 phishing emails (15.6%) lack a `Message-ID` header, compared to only 1 in `ham_easy` (0.2%) and 1 in `ham_hard` (0.4%). Automated phishing kits frequently omit `Message-ID` or rely on intermediate relays that fail to inject one.
3. **MIME-Version & Content-Type in Historical Ham**: In `ham_easy`, 191 messages (38.2%) lack `MIME-Version` and 83 (16.6%) lack `Content-Type`. Under RFC 822/2045, messages without `Content-Type` default to `text/plain; charset=us-ascii`. This reflects historical convention rather than malicious intent.
4. **Cc Header Absence in Phishing**: Exactly 0 of the 250 phishing emails contain a `Cc` header, compared to 98 in `ham_easy` (19.6%) and 4 in `ham_hard` (1.6%). Phishing mass-mailings exclusively use direct `To` or blind delivery.
5. **Received Routing Hops**:
   - `ham_easy`: mean 4.96 hops (median 5.0)
   - `ham_hard`: mean 6.00 hops (median 6.0)
   - `phishing`: mean 3.52 hops (median 3.0)
   - Legitimate mailing-list ham traversed multiple institutional forwarders and Mailman list servers, whereas phishing messages were often delivered directly to target traps.

---

## 3. Authentication Evidence Analysis & H5 Feasibility

In accordance with strict boundary guidelines, all authentication claims are parsed passively as received assertions and maintained as `unverified`. Zero external network requests, DNS lookups, or SMTP queries were made.

### Raw Header Presence Counts

| Header | Overall Count | ham_easy (500) | ham_hard (250) | phishing (250) |
|---|---:|:---:|:---:|:---:|
| `Authentication-Results` | 230 | 0 (0.0%) | 0 (0.0%) | 230 (92.0%) |
| `DKIM-Signature` | 53 | 0 (0.0%) | 0 (0.0%) | 53 (21.2%) |
| `Received-SPF` | 22 | 0 (0.0%) | 0 (0.0%) | 22 (8.8%) |
| `ARC-Authentication-Results` | 2 | 0 (0.0%) | 0 (0.0%) | 2 (0.8%) |
| `ARC-Seal` | 2 | 0 (0.0%) | 0 (0.0%) | 2 (0.8%) |
| `ARC-Message-Signature` | 2 | 0 (0.0%) | 0 (0.0%) | 2 (0.8%) |

### Consolidated Authentication Mechanism Statuses

| Mechanism | Status | Overall | ham_easy | ham_hard | phishing (2015) | phishing (2021) |
|---|---|---:|:---:|:---:|:---:|:---:|
| **SPF** | missing | 942 | 500 | 250 | 182 | 10 |
| | neutral | 23 | 0 | 0 | 4 | 19 |
| | softfail | 7 | 0 | 0 | 1 | 6 |
| | **pass** | **25** | **0** | **0** | **1** | **24** |
| | fail | 3 | 0 | 0 | 0 | 3 |
| **DKIM** | missing | 771 | 500 | 250 | 1 | 20 |
| | neutral | 186 | 0 | 0 | 163 | 23 |
| | **pass** | **31** | **0** | **0** | **13** | **18** |
| | fail | 10 | 0 | 0 | 9 | 1 |
| | permerror | 2 | 0 | 0 | 2 | 0 |
| **DMARC** | missing | 918 | 500 | 250 | 147 | 21 |
| | neutral | 66 | 0 | 0 | 41 | 25 |
| | **pass** | **9** | **0** | **0** | **0** | **9** |
| | fail | 7 | 0 | 0 | 0 | 7 |

### Essential Distinctions Maintained:
- **Presence $\neq$ Pass**: 53 emails carry `DKIM-Signature` headers, but only 31 contain receiving MTA claims of `dkim=pass`. Ten carry explicit `dkim=fail` claims, and two experienced `permerror`.
- **Missing $\neq$ Fail**: 942 emails have missing SPF, 771 have missing DKIM, and 918 have missing DMARC. These are explicitly cataloged as neutral `missing` states, preserving the reality that historical or unconfigured senders simply lack authentication infrastructure.

---

### Research Assessment: Hypothesis H5 Feasibility

> **Hypothesis H5**: *"Multi-agent phishing detection degrades less than baseline approaches when phishing emails contain successful authentication claims."*

#### Empirical Evidence in Development Dataset:
- **Phishing with SPF pass claims**: 25 emails (1 from 2015, 24 from 2021).
- **Phishing with DKIM pass claims**: 31 emails (13 from 2015, 18 from 2021).
- **Phishing with DMARC pass claims**: 9 emails (all from 2021).
- **Phishing with multiple successful claims**: 17 emails (SPF pass + DKIM pass).
- **Phishing with all three passing**: 8 emails (SPF pass + DKIM pass + DMARC pass).
- **Legitimate ham emails with successful claims**: **0 emails** (all 750 SA ham messages precede authentication deployment).
- **Verification status**: All claims are receiver-asserted and unverified.

#### Formal Feasibility Verdict: **EXPLORATORY ONLY**

#### Comprehensive Justification:
1. **Severe Temporal Confounder**: In this dataset, authentication claims are 100% exclusive to the phishing class because the legitimate ham corpus is from 2002–2003. Any statistical baseline trained on this data would erroneously learn that `dkim=pass` or `spf=pass` is an indicator of phishing rather than legitimacy.
2. **Asymmetric Degradation Testing**: Hypothesis H5 requires comparing model behavior on authenticated legitimate emails versus authenticated phishing emails. Because there are zero authenticated legitimate emails in the development set, degradation cannot be meaningfully measured without introducing severe label bias.
3. **Statistical Sample Size**: While 31 DKIM pass and 25 SPF pass phishing emails exist, they are concentrated heavily in the 2021 cohort (n=62). This sample size is sufficient for exploratory qualitative case studies and pipeline tracing, but statistically insufficient for formal hypothesis testing with statistical significance.
4. **Recommendation for Later Tasks**: To rigorously evaluate H5 during later benchmarking phases, the project must incorporate a contemporary legitimate email corpus (e.g., from 2020–2024) possessing legitimate, verified SPF/DKIM/DMARC pass claims.

---

## 4. Body and MIME Structure Analysis

| Body Characteristic | Count | Percentage of Dataset |
|---|---:|---:|
| **Plain-Text Body Available** | 774 | 77.4% |
| **HTML Body Available** | 395 | 39.5% |
| **Dual Format (Both Plain & HTML)** | 171 | 17.1% |
| **Empty or Whitespace-Only Body** | 2 | 0.2% |

### Body Composition by Label

| Label | Plain Only | HTML Only | Both Plain & HTML | Empty / Whitespace | Total |
|---|---:|---:|---:|---:|---:|
| **ham_easy** | 499 (99.8%) | 0 (0.0%) | 1 (0.2%) | 0 (0.0%) | 500 |
| **ham_hard** | 86 (34.4%) | 119 (47.6%) | 45 (18.0%) | 0 (0.0%) | 250 |
| **phishing** | 18 (7.2%) | 105 (42.0%) | 125 (50.0%) | 2 (0.8%) | 250 |

### Top-Level Content-Type Distribution

| Content-Type | Total | ham_easy | ham_hard | phishing |
|---|---:|---:|---:|---:|
| `text/plain` | 462 | 400 | 51 | 11 |
| `text/html` | 195 | 0 | 117 | 78 |
| `multipart/alternative` | 163 | 1 | 43 | 119 |
| `missing` | 114 | 83 | 31 | 0 |
| `multipart/mixed` | 42 | 1 | 6 | 35 |
| `multipart/signed` | 16 | 15 | 1 | 0 |
| `multipart/related` | 8 | 0 | 1 | 7 |

### Text Length Distribution (Characters)
- **Plain-Text Bodies** (n=774): Min 21, Median 885, Mean 2,650, Max 202,500 chars.
- **HTML Bodies** (n=395): Min 99, Median 8,896, Mean 14,165, Max 115,627 chars.
- **Cleaned Text** (n=992): Min 21, Median 915, Mean 2,747, Max 202,499 chars.
- **Empty Bodies in Phishing**: Exactly 2 phishing emails contain no readable text body (consisting exclusively of an attachment or broken base64 payload).

---

## 5. URL Distribution & Context Analysis

URLs are the primary attack vector in modern phishing, and the dataset exhibits dense URL availability:

| Metric | Overall Dataset | ham_easy | ham_hard | phishing |
|---|---:|---:|---:|---:|
| **Emails Containing URLs** | 879 (87.9%) | 404 (80.8%) | 241 (96.4%) | 234 (93.6%) |
| **Total Extracted URL Occurrences** | 16,941 | 806 | 15,022 | 1,113 |
| **Unique Normalized URLs** | 11,497 | 647 | 10,034 | 851 |
| **Mean URLs per Email** | 16.94 | 1.61 | 60.09 | 4.45 |
| **Median URLs per Email** | 2.0 | 1.0 | 48.0 | 2.0 |
| **Max URLs in a Single Email** | 3,134 | 13 | 3,134 | 31 |

### Scheme Breakdown:
- `http`: 15,847 (93.5%)
- `https`: 778 (4.6%) — Heavily concentrated in the 2015/2021 phishing cohort.
- `none` (scheme-less www/bare domain): 299 (1.8%)
- `javascript`: 8 (all in phishing or complex HTML)
- `file`: 3
- `ftp`: 2
- `hhttp` (typo-scheme): 2
- `data`: 1
- `callto`: 1

### Extraction Source Context:
- `html_href`: 8,208 (48.4%) — Anchor destinations.
- `plain_text`: 5,460 (32.2%) — Raw text URLs.
- `html_src`: 3,120 (18.4%) — Image sources, web bugs, and scripts.
- `html_other`: 150 (0.9%) — Meta refreshes, form actions.
- `header`: 3 (<0.1%) — URLs extracted from header comments.

#### Important URL Finding:
`ham_hard` contains an immense volume of URLs (mean 60.09 URLs per email, up to 3,134 in automated digest catalogs). Phishing messages, by contrast, maintain focused targeting (mean 4.45 URLs, median 2.0 URLs). Naive feature sets counting raw URL quantities would severely misclassify `ham_hard` as phishing if raw link density were assumed to be malicious.

---

## 6. Attachment Analysis

| Metric | Overall Dataset | ham_easy | ham_hard | phishing |
|---|---:|---:|---:|---:|
| **Emails with Attachments** | 59 (5.9%) | 16 (3.2%) | 5 (2.0%) | 38 (15.2%) |
| **Total Attachment Count** | 78 | 16 | 23 | 39 |
| **Emails with Multiple Attachments** | 3 | 0 | 1 | 2 |

### MIME Content-Type Distribution:
- `image/gif`: 18 (23.1%) — Primarily tracking pixels and spacer images in `ham_hard`.
- `text/html`: 15 (19.2%) — Phishing HTML attachment lures (e.g., offline credential forms).
- `application/pgp-signature`: 14 (17.9%) — OpenPGP cryptographic signature attachments in `ham_easy`.
- `application/octet-stream`: 8 (10.3%) — Phishing payloads.
- `image/png`: 7 (9.0%)
- `application/pdf`: 6 (7.7%) — Phishing invoice / document decoys.
- `application/zip` / `application/x-zip-compressed`: 3 (3.8%) — Phishing archives.
- `application/x-pkcs7-signature`: 2 (2.6%)
- `image/jpeg` / `image/bmp`: 3 (3.8%)
- `text/plain`: 1 (1.3%)
- `video/mng`: 1 (1.3%)

### Attachment File Size Distribution:
- Total measured attachments: 78
- Minimum: 43 bytes (PGP signature block)
- 25th Percentile: 232 bytes
- Median: 4,308 bytes
- Mean: 52,750 bytes
- 75th Percentile: 37,061 bytes
- Maximum: 553,120 bytes (~540 KB)
- Zero attachments exceeded the 25 MB safety ceiling; zero were skipped.

---

## 7. Dataset Bias and Shortcut Analysis

An essential requirement of Task 8.4 is identifying systemic dataset shortcuts that could inflate future model performance artificially without learning generalizable phishing detection:

### 1. Date / Temporal Leakage (Severity: CRITICAL)
- **Empirical Finding**:
  - `ham_easy`: 499 emails from 2002, 1 missing Date header.
  - `ham_hard`: 249 emails from 2002, 1 missing Date header.
  - `phishing`: 188 emails from 2015, 62 emails from 2021.
- **Risk**: A decision stump splitting on `Date < 2010` achieves **100.0% accuracy** on all 998 dated emails.
- **Mitigation**: The `Date` header must be completely excluded from all feature representation layers in subsequent tasks.

### 2. Source-Specific Scanner & Header Leakage (Severity: HIGH)
- **Empirical Finding**:
  - `X-Spam-*` headers: Present in **249 of 250 phishing emails (99.6%)**, but present in only 0 hard_ham and 0 easy_ham (after strip). These headers were injected by the original Nazario honeypot spam filters (SpamAssassin tags like `X-Spam-Status: Yes`, `X-Spam-Flag: YES`).
  - `List-*` headers: Present in **398 of 750 ham emails (53.1%)**, but present in only 5 phishing emails (2.0%).
  - `User-Agent` / `X-Mailer`: Present in 321 ham emails (42.8%), but present in only 41 phishing emails (16.4%).
- **Risk**: A model relying on `X-Spam-*` will achieve 99.6% phishing recall simply by reading the verdict of the 2015/2021 spam filter.
- **Mitigation**: All `X-Spam-*`, `List-*`, `X-Mailman-*`, and synthetic capture headers must be sanitized and purged before feature extraction.

### 3. Message Formatting Leakage (Severity: MEDIUM)
- **Empirical Finding**: `ham_easy` is 99.8% plain text, whereas `phishing` is 92.0% HTML-capable.
- **Risk**: The presence of HTML markup or MIME boundaries could serve as an artificial proxy for phishing.
- **Mitigation**: Feature extractors must evaluate semantic link structures, visual-to-actual discrepancies, and domain reputations rather than the mere presence of HTML tags.

### 4. Label Imbalance (Severity: LOW–MEDIUM)
- **Empirical Finding**: 750 ham (75.0%) vs 250 phishing (25.0%).
- **Implication**: A trivial majority classifier that always predicts "ham" achieves **75.0% accuracy** while offering 0% security utility (0% phishing recall).
- **Mitigation**: Standard accuracy must never be used in isolation. Evaluation must report Precision, Recall, F1-Score, False Positive Rate (FPR at 99% recall), and Area Under the ROC Curve (ROC-AUC).

---

## 8. Research Component Feasibility Assessment

| Research Component | Dataset Feasibility | Key Empirical Evidence | Development Strategy |
|---|:---:|---|---|
| **Header Agent** | **FEASIBLE** | Core headers present in >95% of emails. Rich spoofing indicators (From vs Return-Path mismatch, missing Message-ID). | Must sanitize `X-Spam-*` and `List-*` headers to avoid shortcut learning. |
| **URL Agent** | **FEASIBLE** | 87.9% email coverage; 16,941 URLs; rich distribution of schemes and anchor contexts. | Normalize URLs, separate href from src, ignore raw URL quantity to protect `ham_hard`. |
| **Text Agent** | **FEASIBLE** | 99.8% body availability; cleaned text available across 992 emails; rich vocabulary. | Rely on normalized `cleaned_text` to bridge plain-text and HTML formatting differences. |
| **Attachment Agent** | **FEASIBLE (SPARSE)** | 59 emails (5.9%) carry attachments; covers HTML lures, PDFs, ZIPs, and signatures. | Must handle sparse activations gracefully (default to neutral confidence when absent). |
| **Evidence Aggregation Layer** | **FEASIBLE** | Multi-modal signals are complementary (e.g. Header + URL + Body). | Combine independent agent belief scores without circular feature dependencies. |
| **Logistic Regression Meta-Classifier** | **FEASIBLE** | 1,000 samples provide ample degrees of freedom for a low-dimensional (4–8 weights) linear meta-classifier. | Regularized L2 logistic regression prevents overfitting on the 1,000-sample dev set. |
| **Confidence Calibration** | **FEASIBLE** | 1,000 samples are statistically adequate for Platt scaling or isotonic calibration. | Calibrate probability outputs using stratified k-fold cross-validation. |
| **H5 Authenticated Phishing** | **EXPLORATORY ONLY** | 31 DKIM pass, 25 SPF pass, 9 DMARC pass in phishing; **0** in legitimate ham. | Conduct exploratory case studies in Task 8.4; require contemporary ham for formal validation. |

---

## 9. Limitations and Recommendations

1. **Temporal Horizon Limitation**:
   - The SpamAssassin corpus represents the email ecosystem of 2002–2003, whereas the Nazario corpus represents 2015–2021. This 13-year temporal divide affects authentication headers, cryptographic algorithms, and character set defaults.
   - **Recommendation**: In future project phases (e.g. Task 9 or final evaluation), evaluate on a modern legitimate corpus (e.g., Enron modern rescrape, private contemporary ham, or synthetic benign corporate email) to test real-world DKIM/SPF behavior.
2. **Preprocessing Pipeline Mandate**:
   - Upstream feature extractors must enforce an explicit header blacklist stripping `X-Spam-*`, `List-*`, `X-Mailman-*`, and `Date` before vectorization.
3. **Metric Selection**:
   - Model development must track macro-averaged F1 and False Positive Rate at target Recall ($R \ge 95\%$), avoiding the 75% baseline accuracy trap.

---

## 10. Regression Suite and Deliverables Verification

All existing and new tests pass with zero errors:

- `tests/test_analyze_dev_dataset.py`: **28 passed** in 0.51s.
- `tests/test_convert_mbox_to_eml.py`: **41 passed** in 16.45s.
- `tests/test_verify_raw_datasets.py`: **22 passed** in 3.35s.
- Full repository test suite (`pytest -v`): **441 passed** in 18.91s (0 failures, 0 warnings).
- Git privacy verification: `data/dev/analysis/` is ignored by `.gitignore:50`. No raw or dev data is committed.

### Generated Deliverables Summary:
1. `scripts/analyze_dev_dataset.py`: Automated analysis script.
2. `data/dev/analysis/dataset_composition.json`: Composition and volume metrics.
3. `data/dev/analysis/header_analysis.json`: 11-header presence and missingness.
4. `data/dev/analysis/authentication_analysis.json`: SPF, DKIM, DMARC, ARC, and H5 metrics.
5. `data/dev/analysis/body_analysis.json`: Plain-text, HTML, and MIME structures.
6. `data/dev/analysis/url_analysis.json`: 16,941 URL occurrences and schemes.
7. `data/dev/analysis/attachment_analysis.json`: 78 attachments and MIME types.
8. `data/dev/analysis/dataset_bias_analysis.json`: Date, header, format leakage, and class imbalance.
9. `tests/test_analyze_dev_dataset.py`: 28 automated verification tests.
10. `task8_4_dataset_analysis_report.md`: This comprehensive report.

---

## Strict Stopping Condition

Task 8.4 is complete. In accordance with explicit instructions:
- No machine-learning models were trained.
- No agents or meta-classifiers were built.
- No application schemas or extractors were modified.
- Raw archives and the 1,000 EML files remain untouched.
- Task 8.5 has not been started.
- Stopped and awaiting your explicit approval.
