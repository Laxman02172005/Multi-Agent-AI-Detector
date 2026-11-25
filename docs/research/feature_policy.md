# Feature Policy and Artifact Exclusion Framework

**Document**: `docs/research/feature_policy.md`  
**Task**: 8.4.1 Research Design and Dataset Bias Mitigation  
**Date**: November 12, 2026  
**Status**: APPROVED RESEARCH DESIGN SPECIFICATION  

---

## 1. Architectural Principle: Four-Tier Data Separation

To eliminate data leakage and prevent machine-learning models from exploiting dataset collection artifacts, the detection system enforces a strict four-tier separation of email data:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Tier 1: Original Raw Evidence (Immutable Disk Artifacts)                     │
│ Raw RFC 822 / MIME bytes, untouched headers, original encodings.             │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼ (Parsed via EmailIngestor)
┌─────────────────────────────────────────────────────────────────────────────┐
│ Tier 2: Extracted Forensic Metadata (Pydantic EmailData Contracts)           │
│ Parsed headers, decoded body parts, extracted URLs, attachment metadata.    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼ (Filtered by Feature Whitelist)
┌─────────────────────────────────────────────────────────────────────────────┐
│ Tier 3: Approved Model Features (Agent Input Space)                          │
│ Sanitized structural, semantic, and contextual features approved per agent. │
│ Excludes all corpus artifacts, scanner headers, and temporal timestamps.    │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Tier 4: Dataset Provenance & Audit Metadata (Isolated Tracking)             │
│ Dataset label, source archive, MBOX key, sha256, acquisition timestamp.     │
│ Used strictly for stratification, grouped evaluation, and error analysis.   │
│ STRICTLY PROHIBITED FROM ENTERING AGENT OR META-CLASSIFIER FEATURE SPACES.  │
└─────────────────────────────────────────────────────────────────────────────┘
```

1. **Original Raw Evidence**: Preserved in `data/dev/eml/` as byte-for-byte immutable records. Never modified, overwritten, or deleted.
2. **Extracted Forensic Metadata**: Structured representations in `EmailData` models (Task 3–6 contracts) preserving forensic completeness.
3. **Approved Model Features**: Whitelist-restricted feature vectors consumed by specialized agents. Only verified intrinsic properties of the message may enter this tier.
4. **Dataset Provenance Metadata**: Audit metadata (e.g., `source_archive`, `source_year`, `original_mbox_key`, `sample_id`) maintained in separate manifests. **Strictly barred from model training and inference pipelines.**

---

## 2. Feature Policy by Specialized Agent

Each agent in the multi-agent architecture is assigned an explicit, bounded domain of observation. Features outside an agent's approved policy are prohibited.

### 2.1 Header Agent Policy

The Header Agent evaluates RFC 5322 header structural integrity, sender alignment, routing anomalies, and authentication claims.

| Feature Category | Approved Evidence & Extraction Logic | Restrictions & Invariant Rules |
|---|---|---|
| **Identity Alignment** | - Exact string comparison between `From` address domain and `Reply-To` domain.<br>- Exact comparison between `From` address domain and `Return-Path` (envelope-from) domain.<br>- Display-name spoofing indicators (e.g., email address embedded in display name). | - Do not perform external DNS lookups for MX records.<br>- Do not infer legitimacy solely from domain alignment. |
| **Message-ID Integrity** | - Presence vs absence of `Message-ID` (missing in 15.6% of dev phishing).<br>- Message-ID domain alignment with `From` header domain.<br>- Multiple `Message-ID` headers (RFC 5322 section 3.6 violation).<br>- Conformance to standard `<id@host>` syntax. | - Do not use Message-ID as a database primary key.<br>- Do not maintain static whitelists of known Message-ID suffixes. |
| **Routing / Received Hops** | - Total Received header hop count (mean 3.52 in phishing vs 4.96 in ham).<br>- Presence of private IP addresses in external hops.<br>- Non-numeric or malformed Received tokens.<br>- Transit delay between earliest and latest Received hop (internal delta only). | - **Never use absolute timestamps** from Received headers.<br>- Do not execute Geo-IP or ASN queries against IP addresses. |
| **Authentication Claims** | - Boolean presence of `Authentication-Results`, `Received-SPF`, `DKIM-Signature`, `ARC-*`.<br>- Claimed mechanism status parsed passively (`pass`, `fail`, `softfail`, `neutral`, `missing`).<br>- Authserv-ID consistency across multiple Authentication-Results lines. | - **Maintain all claims as `unverified`**.<br>- **`DKIM-Signature` presence $\neq$ DKIM pass**.<br>- **`Authentication-Results` presence $\neq$ verified authentication**.<br>- **Missing authentication $\neq$ authentication failure**.<br>- Zero DNS TXT/cryptographic key fetches. |
| **Structural Anomalies** | - Presence of mandatory RFC 5322 headers (`From`, `Date`, `To`/`Cc`).<br>- Syntactically invalid header foldings or character sets.<br>- Multiple `Subject` or `From` headers. | - Missing `To` or `Cc` is not automatically malicious (BCC delivery is standard). |

### 2.2 URL Agent Policy

The URL Agent analyzes lexical properties, domain composition, URL placement context, and visual-to-actual target discrepancies.

| Feature Category | Approved Evidence & Extraction Logic | Restrictions & Invariant Rules |
|---|---|---|
| **Scheme Analysis** | - Extracted URL scheme: `http`, `https`, `ftp`, `none` (schemeless).<br>- Flagging of suspicious schemes: `javascript`, `data`, `file`, `callto`. | - Do not penalize standard `http` as malicious merely because it lacks TLS (especially in historical corpora). |
| **Lexical & Hostname Properties** | - Hostname format: raw IPv4/IPv6 address vs domain name.<br>- Subdomain depth (number of dots in hostname).<br>- Presence of credentials in URL (`user:pass@host`).<br>- Suspicious TLD categories or multi-part pseudo-TLDs.<br>- Path depth, query string length, presence of tokenized redirects (`?url=`, `?redirect=`).<br>- URL length and Shannon entropy of hostname/path. | - **Zero live network requests**.<br>- **Zero DNS resolution or WHOIS queries**.<br>- **Zero external reputation API lookups**.<br>- Do not treat specific domain names in the dev set as static blacklists. |
| **Contextual Placement & Anchors** | - Extraction context: `html_href`, `html_src`, `plain_text`, `header`.<br>- Visual vs actual target discrepancy: text inside anchor tag is a valid URL pointing to domain $A$, but `href` destination points to domain $B$.<br>- Embedded form actions (`<form action="...">`). | - In plain text, line-wrapped bracketed URLs must be reconstructed safely without mutating text. |
| **URL Density & Distribution** | - Ratio of unique domains to total URLs.<br>- Distribution of links across plain text and HTML. | - **Do not use raw URL count as a positive phishing feature**: Task 8.4 showed `ham_hard` contains a mean of 60.09 URLs (up to 3,134 in digest emails), while phishing averaged 4.45 URLs. |

### 2.3 Text Agent Policy

The Text Agent analyzes the semantic, communicative, and rhetorical properties of the email body text.

| Feature Category | Approved Evidence & Extraction Logic | Restrictions & Invariant Rules |
|---|---|---|
| **Semantic Intent & Tone** | - Presence of artificial urgency, coercive threats, or extreme deadlines ("within 24 hours", "account suspended").<br>- Explicit requests for credentials, passwords, PINs, or multi-factor tokens.<br>- Urgent financial instructions (wire transfers, crypto payments, gift cards).<br>- Authority and brand impersonation phrases (IT Support, Security Team, Financial Dept). | - Exclude all collection-system headers from body text.<br>- Exclude subject lines if they contain injected `X-Spam-*` tags.<br>- Do not learn corpus-specific vocabulary (e.g. open-source Linux terms in SpamAssassin) as proxies for legitimate ham. |
| **Structural Text Properties** | - Presence of generic or missing recipient greetings ("Dear Customer", "Dear Member" vs personalized name).<br>- Discrepancy between stated company in body and sending domain in `From`.<br>- Text formatting entropy and character-set obfuscation (e.g. Cyrillic homoglyphs, zero-width spaces). | - Feature extraction must operate on normalized `cleaned_text` to eliminate raw HTML tag artifacts. |

### 2.4 Attachment Agent Policy

The Attachment Agent inspects safe static metadata for attachments without executing or decompressing file content.

| Feature Category | Approved Evidence & Extraction Logic | Restrictions & Invariant Rules |
|---|---|---|
| **Static Metadata** | - Declared MIME content-type (`application/pdf`, `application/zip`, `text/html`, etc.).<br>- Declared file extension from filename.<br>- Double extensions (e.g. `invoice.pdf.exe`, `document.docx.vbs`).<br>- Dangerous executable extensions (`.exe`, `.scr`, `.bat`, `.vbs`, `.js`, `.hta`, `.cpl`).<br>- HTML attachment lures (offline phishing forms: 15 occurrences in dev phishing).<br>- Size in bytes (measured statically).<br>- Content-Disposition (`attachment` vs `inline`). | - **Never execute attachments**.<br>- **Never open or render attachments**.<br>- **Never unpack compressed archives** (`.zip`, `.gz`, `.tar`).<br>- Do not upload attachments to online sandboxes.<br>- **Zero inference of maliciousness from attachment presence alone** (only 5.9% of dev emails have attachments).<br>- When attachments are absent, output neutral `no_evidence` state. |

---

## 3. Corpus-Artifact Exclusion Policy

The Task 8.4 analysis demonstrated that historical corpora inject substantial artifact headers, scanner verdicts, and temporal cues. The following policy defines their handling across the data pipeline:

| Header / Field Name | Preserve in Raw Evidence? | Allowed as Model Feature? | Operational Rationale & Mitigation |
|---|:---:|:---:|---|
| **`X-Spam-*`**<br>(`X-Spam-Status`, `X-Spam-Flag`, `X-Spam-Checker-Version`, `X-Spam-Level`) | **YES**<br>(Tier 1 & 2) | **NO**<br>(Strictly Excluded) | Present in **99.6% (249/250)** of Nazario phishing emails as honeypot filter tags. If included, models achieve near 100% recall by reading prior spam filter verdicts rather than email properties. |
| **`List-*`**<br>(`List-Id`, `List-Unsubscribe`, `List-Post`, `List-Help`, `List-Archive`) | **YES**<br>(Tier 1 & 2) | **NO**<br>(Strictly Excluded) | Present in **53.1% (398/750)** of SpamAssassin ham emails due to mailing-list origins. A classifier would erroneously treat mailing-list headers as proof of legitimate communication. |
| **`X-Mailman-Version`** | **YES**<br>(Tier 1 & 2) | **NO**<br>(Strictly Excluded) | Artifact of Mailman list server present exclusively in historical ham. |
| **`Date` (Absolute Header)** | **YES**<br>(Tier 1 & 2) | **NO**<br>(Strictly Excluded) | **Critical Leakage Risk**: 100% of dated ham messages are from 2002; 100% of dated phishing messages are from 2015/2021. Splitting on `Date < 2010` gives 100% accuracy. Absolute date must never enter model features. |
| **Received Timestamps (Transit Deltas)** | **YES**<br>(Tier 1 & 2) | **CONDITIONAL**<br>(Relative Delta Only) | The absolute year/date must be stripped. The relative transit duration (difference between hop 1 and hop $N$) is permitted if valid, as it captures routing delay without temporal leakage. |
| **`User-Agent` / `X-Mailer`** | **YES**<br>(Tier 1 & 2) | **NO**<br>(Strictly Excluded) | Present in 42.8% of ham vs 16.4% of phishing, reflecting historical MUAs (Eudora, Mutt, Outlook Express 6) that would serve as artificial shortcuts. |
| **`X-Loop`, `Precedence`** | **YES**<br>(Tier 1 & 2) | **NO**<br>(Strictly Excluded) | Automated mailing list headers characteristic of the SpamAssassin corpus. |
| **`source_dataset`, `source_archive`** | **YES**<br>(Tier 4 Only) | **NO**<br>(Strictly Excluded) | Provenance labels indicating corpus origin (`spamassassin`, `nazario`). Strictly quarantined in audit manifests. |
| **`original_mbox_key`, `sample_id`** | **YES**<br>(Tier 4 Only) | **NO**<br>(Strictly Excluded) | Internal index keys used for provenance tracking only. |

---

## 4. Verification and Preprocessing Workflow

Before feature extraction occurs, each `EmailData` object passes through an approved sanitization filter that:
1. Strips all blacklisted header keys matching `(?i)^(x-spam-.*|list-.*|x-mailman-.*|x-loop|precedence|user-agent|x-mailer)`.
2. Nullifies the absolute timestamp in the `Date` header while preserving a boolean `has_valid_date_header` flag.
3. Verifies that all authentication claims remain tagged with `verification_status = "unverified"`.
4. Emits a sanitized feature view (`SanitizedEmailView`) consumed by the agents.
