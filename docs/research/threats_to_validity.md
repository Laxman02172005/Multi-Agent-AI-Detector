# Comprehensive Threats to Validity

**Document**: `docs/research/threats_to_validity.md`  
**Task**: 8.4.1 Research Design and Dataset Bias Mitigation  
**Date**: November 12, 2026  
**Status**: APPROVED RESEARCH DESIGN SPECIFICATION  

---

## 1. Overview and Methodological Taxonomy

To ensure scientific rigor and prevent misleading conclusions, threats to the validity of the Multi-Agent AI Phishing Email Detector are explicitly categorized into:
1. **Observed Problems (Empirical Realities)**: Measurable artifacts, biases, and structural properties quantified directly during the Task 8.4 exploratory analysis of the 1,000-email development dataset.
2. **Potential Risks (Theoretical Vulnerabilities)**: Inherent challenges in phishing detection, adversarial evasion, real-world deployment, and generalization to unseen environments.

---

## 2. Category I: Observed Problems (Empirical Realities in Dev Dataset)

These threats represent confirmed empirical characteristics of the dataset that have been measured and require strict algorithmic or experimental mitigation.

### 2.1 Date & Temporal Leakage (Critical Severity)
- **Observed Evidence**:
  - `ham_easy`: 499 messages dated 2002, 1 missing.
  - `ham_hard`: 249 messages dated 2002, 1 missing.
  - `phishing`: 188 messages dated 2015, 62 messages dated 2021.
- **The Threat**: A trivial feature rule such as $\text{Year} < 2010$ achieves **100.0% classification accuracy** across all 998 dated emails.
- **Impact**: Any model that includes absolute date headers, copyright years, or year tokens will learn historical chronology rather than phishing behavior.
- **Enforced Mitigation**: The `Date` header is completely excluded from Tier 3 model features. Semantic body tokens matching 4-digit years are normalized into generic `<YEAR>` tokens.

### 2.2 Scanner & Honeypot Artifact Leakage (High Severity)
- **Observed Evidence**:
  - `X-Spam-*` headers (`X-Spam-Status`, `X-Spam-Flag`, `X-Spam-Checker-Version`): Present in **249 of 250 phishing emails (99.6%)**, but absent in hard ham.
  - `List-*` headers (`List-Id`, `List-Unsubscribe`): Present in **398 of 750 ham emails (53.1%)**, but present in only 5 phishing emails (2.0%).
- **The Threat**: The Nazario phishing archives were collected from spam traps running SpamAssassin filters that stamped explicit verdict headers (e.g. `X-Spam-Flag: YES`). Conversely, SpamAssassin ham was scraped from open-source mailing lists carrying Mailman headers.
- **Impact**: Models will learn that `X-Spam-*` indicates phishing and `List-*` indicates ham, yielding near 100% recall without inspecting email text or links.
- **Enforced Mitigation**: Strict pre-extraction blacklist stripping all headers matching `(?i)^(x-spam-.*|list-.*|x-mailman-.*|x-loop|precedence)`.

### 2.3 Authentication Temporal Asymmetry (High Severity)
- **Observed Evidence**: 0 of 750 ham emails have SPF, DKIM, or DMARC claims (originating from 2002–2003, before protocol standardization). Phishing emails contain 25 SPF pass, 31 DKIM pass, and 9 DMARC pass claims.
- **The Threat**: Legitimate authentication is 100% confounded with the phishing class in this corpus.
- **Impact**: Unconstrained classifiers learn that valid authentication pass claims predict *phishing*.
- **Enforced Mitigation**: Formal testing of Hypothesis H5 is classified as **Exploratory Only** on this dataset. Authentication features are decoupled from general meta-classification.

### 2.4 Formatting and Layout Disparity (Medium Severity)
- **Observed Evidence**: 99.8% of `easy_ham` is plain text only, whereas 92.0% of phishing emails contain HTML markup.
- **The Threat**: Models might treat the presence of HTML tags, CSS blocks, or multipart MIME boundaries as an artificial proxy for phishing.
- **Enforced Mitigation**: The Text Agent processes normalized `cleaned_text` (all HTML tags stripped and entities decoded) to enforce semantic invariance.

### 2.5 URL Density Explosion in Digest Ham (Medium Severity)
- **Observed Evidence**: `ham_hard` contains an average of 60.09 URLs per email (median 48, maximum 3,134 links in marketing/digest catalogs), compared to 4.45 URLs in phishing.
- **The Threat**: Naive feature representations that associate higher link counts with phishing will generate unacceptable false positive rates on `ham_hard`.
- **Enforced Mitigation**: The URL Agent evaluates domain divergence, anchor mismatch, and suspicious schemes rather than raw link counts.

### 2.6 Attachment Sparsity (Low–Medium Severity)
- **Observed Evidence**: Only 59 of 1,000 emails (5.9%) contain attachments (38 phishing, 16 easy_ham, 5 hard_ham).
- **The Threat**: The Attachment Agent feature space is unpopulated for 94.1% of the dataset.
- **Impact**: If not handled properly, an absent attachment could trigger default predictions that bias the meta-classifier.
- **Enforced Mitigation**: When attachments are absent, the Attachment Agent emits an explicit neutral belief ($p=0.5, c=0.0$) coupled with an active missing indicator ($m_a = 1$).

### 2.7 Label Imbalance Baseline Distortion (Low Severity)
- **Observed Evidence**: 750 ham (75.0%) vs 250 phishing (25.0%).
- **The Threat**: A trivial majority classifier achieves 75.0% accuracy with 0% phishing recall.
- **Enforced Mitigation**: Accuracy is prohibited as an evaluation metric. Macro-F1, Precision-Recall AUC, and FPR at 95% recall are established as primary metrics.

---

## 3. Category II: Potential Risks (Theoretical & Deployment Vulnerabilities)

These threats represent fundamental challenges in cybersecurity detection systems that cannot be fully solved by dataset partitioning and require ongoing defense-in-depth.

### 3.1 Authentication Claim Forgery in Unverified Headers
- **The Risk**: The `Authentication-Results` header is inserted by the recipient's mail transfer agent (MTA). In unverified offline archives or open mail relays, a sophisticated attacker could inject forged `Authentication-Results: dkim=pass` headers into the raw email stream.
- **Mitigation**: The Header Agent verifies whether the `authserv-id` token matches the receiving domain of the outermost `Received` hop, flagging forged internal authentication headers.

### 3.2 Spam vs. Phishing Label Ambiguity
- **The Risk**: Historical corpora frequently blur the distinction between commercial spam (unsolicited marketing, adult offers, Nigerian prince scams) and credential phishing (targeted brand impersonation designed to steal credentials).
- **Impact**: Some Nazario samples are closer to mass-spam than targeted spear-phishing, introducing label noise.
- **Mitigation**: The Text Agent specifically isolates credential-harvesting and wire-fraud semantic intent, avoiding general spam-filtering heuristics.

### 3.3 Adversarial Evasion and Modern Generative AI Phishing
- **The Risk**: Contemporary phishing increasingly uses Large Language Models (LLMs) to generate fluent, context-aware, error-free emails devoid of traditional grammatical errors, artificial urgency tokens, or overt threat words.
- **Impact**: Models trained on historical 2015/2021 phishing corpora may underperform against modern polymorphic or AI-generated lures.
- **Mitigation**: Decoupled multi-agent architecture ensures that even if text semantics appear benign, the URL Agent (anchor mismatches, suspicious domains) and Header Agent (sender alignment) can still trigger detection.

### 3.4 Domain and Sender Memorization (Overfitting)
- **The Risk**: Machine-learning models with high representational capacity (e.g. large n-gram vocabularies or deep embeddings) can memorize specific sender domains or brand keywords present in the training set.
- **Impact**: Models fail when deployed against novel lookalike domains or unfamiliar brands.
- **Mitigation**: Regularized L2 penalty on meta-classifier coefficients; domain features abstracted into structural properties (subdomain depth, entropy, IPv4 format) rather than raw domain strings.

### 3.5 Absence of Live DNS and Network Signals
- **The Risk**: The current research phase strictly enforces offline, read-only processing with zero external network access (no live DNS lookups, no WHOIS age checks, no real-time domain reputation APIs).
- **Impact**: Detection must rely entirely on internal static and lexical properties, foregoing powerful real-time signals (e.g., domain registered 2 hours ago).
- **Mitigation**: Static lexical extraction is maximized (entropy, homoglyphs, anchor mismatch); live lookup capabilities are deferred to future production deployment phases.
