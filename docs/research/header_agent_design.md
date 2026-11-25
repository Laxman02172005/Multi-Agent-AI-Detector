# Header Agent: Architecture, Feature Policy, and Data Contract Specification

**Document**: `docs/research/header_agent_design.md`  
**Task**: 8.5.0 — Header Agent: Design and Contract (Task 8.5.0.14 Revisions Applied)  
**Date**: November 12, 2026  
**Status**: DESIGN SPECIFICATION — PENDING IMPLEMENTATION APPROVAL (DESIGN-ONLY)  

---

## Document Revision History and Task 8.5.0.14 Audit Summary

This document represents the audited, canonical design specification for the Header Agent, incorporating corrections from the Task 8.5.0.14 recovery drain correctness, durability separation, recipient-count semantics, nonce consumption, and test-plan consistency audit:

| Technical Audit Item | Prior Status / Limitation (v1.13) | Task 8.5.0.14 Corrective Specification |
|---|---|---|
| **1. Recovery Drain Correctness & Monotonic Timing** | Claimed all assertions expire at an inclusive 360-second boundary; clock source unspecified. | **Strict 361s Drain & Monotonic Source**: Recalculated lifetime ($\Delta t_{\text{max\_age}} = 300\text{s}$, $\Delta t_{\text{future\_max}} = 60\text{s}$). Demonstrated that at exactly 360 seconds post-crash, an assertion issued at maximum future skew ($T_{\text{crash}} + 60\text{s}$) satisfies the inclusive freshness boundary ($T_{\text{assert}} = T_{\text{now}} - 300\text{s}$) and remains fresh. Enforced strictly safe drain threshold $\Delta t_{\text{drain}} \ge 361\text{ seconds}$ (or $T_{\text{elapsed}} > 360\text{s}$) to guarantee $T_{\text{assert}} < T_{\text{now}} - 300\text{s}$. Mandated monotonic clock source (`time.monotonic()`), preventing NTP step adjustments from shortening the drain. |
| **2. Replay-Store Durability & Redis Limitations** | Described `appendfsync always` plus `WAIT` as "absolute replay immunity"; blurred persistence and replication. | **Durability Layer Separation & Zero-Loss Storage**: Disentangled local disk persistence, replication acknowledgement, and durable failover. Clarified that Redis `WAIT` only verifies replica memory, does not prove replica disk flush, and cannot prevent asynchronous failover write loss. Removed "absolute replay immunity" claims. Defined required consensus-backed storage (Raft/Paxos in Etcd, CockroachDB, Spanner, or synchronous PostgreSQL) or strict $\ge 361\text{s}$ recovery drain. Formally retained unresolved deployment dependency. |
| **3. Recipient-Count Semantics & Mixed Lists** | Semantics for malformed or mixed address tokens were unspecified; risk of counting non-mailbox tokens. | **Strict Mailbox Address Counting & Mixed Lists**: Defined `recipient_count_to` and `recipient_count_cc` as counts of successfully parsed RFC 5322 mailbox addresses only. Preserved display fragments (e.g. `undisclosed-recipients:;`, garbage tokens) are strictly excluded from counts. Specified mixed-list behavior (counts valid mailboxes, ignores malformed tokens, logs Tier 2 forensic evidence). Preserved `None` for unavailable/unevaluable counts under current contract. Preserved 45/41/4 feature structure. |
| **4. Nonce Reservation Ordering & Retry Policy** | Nonce consumption on downstream failure and integration retry rules were undocumented. | **DoS Protection, Nonce Consumption & Retries**: Documented that Step 5 (Nonce Reservation) precedes Step 6 (Digest) and Step 7 (Boundary) to shield expensive SHA-256 and regex parsing from DoS. Documented that downstream failures consume the nonce. Enforced that retries must generate a fresh high-entropy nonce and new signature. Documented that nonce reservation is bounded by dynamic TTL ($\le 360$s) and effectively permanent for the assertion's validity lifetime. |
| **5. Test-Plan Consistency & Scenario Reconciliation** | Revision history stated 49 cases/scenarios while table had 50; test execution claims required qualification. | **Strictly Reconciled 50-Scenario Test Plan**: Reconciled counts across all sections: exactly 50 current-contract scenarios in Section 11.1 (Scenarios 1..50) and 3 future-contract scenarios in Section 11.2 (total 53 specified scenarios). Reconciled decision table to exactly 50 defined cases (Cases 1..50). Clarified that test plans specify requirements for future implementation in Tasks 8.5.1 and 8.5.3, distinct from the 441 existing passing ingestion/dataset regression tests. |

---

## 1. Agent Purpose and Boundaries

### 1.1 Purpose
The Header Agent is the specialized component responsible for evaluating the structural integrity, transport routing, sender-envelope consistency, and declared authentication claims of an email's header block. Its primary role is to detect mechanical, administrative, and protocol-level anomalies introduced by threat actors during email spoofing, infrastructure rotation, and relay abuse.

### 1.2 The Three Modeling Layers
To prevent architectural confusion, the detection system explicitly distinguishes three distinct modeling layers:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 1: Header Agent Feature Extraction (Scope of Current Component)       │
│ - Deterministic, passive, stateless transformation of EmailData.            │
│ - Extracts canonical 45 whitelisted Tier 3 features (HeaderFeatures).       │
│ - Generates per-feature availability manifest (HeaderFeatureAvailability).  │
│ - Records bounded, sanitized forensic audit traces (HeaderEvidence).        │
│ - ZERO learned weights, ZERO manual heuristic scores, ZERO network lookups. │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                        ┌──────────────┴──────────────┐
                        ▼                             ▼
┌──────────────────────────────────────────┐ ┌────────────────────────────────┐
│ Layer 2: Optional Header Base Classifier │ │ Layer 3: Hierarchical          │
│ (Experimental Baseline Model 2)          │ │ Multi-Agent Meta-Classifier    │
│ - Supervised model: P(phish | x_header)  │ │ (Core Detection Architecture)  │
│ - Consumes 41 active predictive features │ │ - Logistic Regression on       │
│   (4 features quarantined).              │ │   [p_h, p_u, p_t, p_a, ...]    │
│ - Transformed into:                      │ │ - Synthesizes all 4 agents.    │
│   • 41D for native-NaN tree models       │ │ - Calibrated decision policy.  │
│   • 79D for regularized logistic regress.│ │ - Tuned abstention thresholds. │
│ - Fitted during 5-fold cross-validation  │ │ - NOT hardcoded in extractor.  │
│   on 600-sample Training Split.          │ │                                │
└──────────────────────────────────────────┘ └────────────────────────────────┘
```

1. **Layer 1: Deterministic Feature Extraction (Current Component Scope)**: The Header Agent extracts strictly sanitized, objective structural metrics, availability flags, and forensic evidence from `EmailData`. It executes no statistical models and assigns no arbitrary threat scores.
2. **Layer 2: Optional Header Agent Base Classifier (Baseline 2)**: Defined in `docs/research/experimental_design.md` as an isolated benchmark model ($P(\text{phishing} \mid \mathbf{x}_{\text{header}})$) evaluated to quantify the discriminative signal available in headers alone. It operates on **41 active predictive features** (with 4 features quarantined) and is trained during the experimental modeling phase (Task 8.9), not inside the feature extractor.
3. **Layer 3: Multi-Agent Meta-Classifier (Core Architecture)**: The regularized Logistic Regression meta-classifier that synthesizes probability, decision margin, and missingness vectors emitted across all four specialized agents (Header, URL, Text, Attachment).

### 1.3 Strict Operational Invariants (Non-Goals)
1. **No Independent Phishing Decision**: The Header Agent does not make a final binary phishing/ham determination.
2. **Zero Network / External Lookups**: The agent operates strictly offline. No DNS queries (MX, TXT, A, PTR records), WHOIS queries, external reputation lookups, or threat intelligence API calls are permitted.
3. **No Domain or Semantic Cross-Contamination**:
   - The Header Agent does not inspect body text, linguistic urgency, or natural language semantics (reserved for Text Agent).
   - The Header Agent does not crawl, parse, or evaluate hyperlinks or anchor tags (reserved for URL Agent).
   - The Header Agent does not inspect attachment payloads or filenames (reserved for Attachment Agent).
4. **No Trust Promotion Without Cryptographic Provenance**: Authentication claims and Received hops are treated strictly as unverified receiver-reported assertions in offline analysis. No claim or hop is promoted to `VERIFIED` or `TRUSTED_RECEIVER` without verified external acquisition provenance.
5. **No Static Domain Blacklists/Whitelists**: The agent does not memorize specific sending domains, public email service providers, or server hostnames.

---

## 2. Input Contract and Ingestion Audit

### 2.1 Empirical Audit of Existing Ingestion Contracts
To ensure the Header Agent does not make unsupported assumptions, we audited `app/schemas/email_schema.py`, `app/ingestion/header_extractor.py`, and `app/ingestion/email_ingestor.py` under Python 3.11+:

| Header Field | Actual Ingestion Field | Physical Presence Preserved? | Empty vs Absent Distinguishable? | Unparseable vs Empty Distinguishable? | Status & Ingestion Limitations |
|---|---|:---:|:---:|:---:|---|
| **From** | `headers.from_address: Optional[str]` | **NO** | **NO** (`None` for both) | **YES** (unparseable preserved as raw string) | `_extract_single_address` returns `None` for absent header OR empty header. Physical presence of an empty From header is lost. |
| **To** | `headers.to: list[str]` | **NO** | **NO** (`[]` for both) | **PARTIALLY** (unparseable tokens appended to list) | `_extract_addresses` returns `[]` for absent To OR empty To. Empty group `undisclosed-recipients:;` normalizes to `[]`. |
| **CC** | `headers.cc: list[str]` | **NO** | **NO** (`[]` for both) | **PARTIALLY** (unparseable tokens appended to list) | `_extract_addresses` returns `[]` for absent CC OR empty CC. |
| **Reply-To** | `headers.reply_to: Optional[str]` | **NO** | **NO** (`None` for both) | **YES** (raw string returned if unparseable) | Absent and empty both normalize to `None`. Physical presence lost. |
| **Return-Path**| `headers.return_path: Optional[str]` | **NO** | **NO** (`None` for both) | **YES** (raw string returned if unparseable; `<>` preserved) | Absent and empty both normalize to `None`. Physical presence lost. |
| **Message-ID** | `headers.message_id: Optional[str]` | **YES** | **YES** (`None` vs `""`) | **YES** (stripped raw token preserved) | `None` indicates absent; `""` indicates empty/whitespace-only header. |
| **Subject** | `headers.subject: Optional[str]` | **YES** | **YES** (`None` vs `""`) | N/A (RFC 2047 decoding fallback) | `None` indicates absent; `""` indicates empty header. |
| **MIME-Version**|`headers.mime_version: Optional[str]` | **YES** | **YES** (`None` vs `""`) | N/A (raw string preserved) | `None` indicates absent; `""` indicates empty header. |
| **Content-Type**|`headers.content_type: Optional[str]` | **YES** | **YES** (`None` vs `""`) | N/A (raw media-type string) | `None` indicates absent; `""` indicates empty header. |

### 2.2 Redefinition of Physical Header Presence Under Current Contract
Because `_extract_single_address` and `_extract_addresses` collapse absent and empty headers to `None` or `[]`, the Header Agent **does not claim physical header presence can be determined** for From, Reply-To, Return-Path, To, and CC under the current contract:
1. `from_present`: Redefined as a **normalized-value presence indicator**. Evaluates to `True` if `headers.from_address is not None` and non-empty. Physical presence of an empty From header cannot be determined.
2. `reply_to_present`: Redefined as a **normalized-value presence indicator**. Evaluates to `True` if `headers.reply_to is not None` and non-empty.
3. `return_path_present`: Redefined as a **normalized-value presence indicator**. Evaluates to `True` if `headers.return_path is not None` and non-empty.
4. `message_id_present`: Indicates non-empty normalized Message-ID token presence (`headers.message_id is not None and len(headers.message_id.strip()) > 0`). An empty `Message-ID: \n` yields `headers.message_id == ""`, which evaluates to `message_id_present = False`.
5. `has_subject_header`: Supported physical presence indicator (`headers.subject is not None`).
6. `mime_version_present`: Supported physical presence indicator (`headers.mime_version is not None`).
7. `content_type_present`: Supported physical presence indicator (`headers.content_type is not None`).

### 2.3 Proposed Future Ingestion Extension (Task 8.6+)
To distinguish physical presence, empty headers, and RFC 2822 group syntax across all address fields, we specify the smallest necessary future extension for `EmailHeaders`:

```python
# Proposed Future Extension for EmailHeaders (Task 8.6+)
from_raw: Optional[str] = Field(
    default=None,
    description="Verbatim unparsed From header line. Preserves physical presence, empty headers, and invalid syntax.",
)
to_raw: Optional[str] = Field(
    default=None,
    description="Verbatim unparsed To header line. Preserves physical presence, empty headers, and group syntax.",
)
cc_raw: Optional[str] = Field(
    default=None,
    description="Verbatim unparsed CC header line. Preserves physical presence, empty headers, and invalid syntax.",
)
reply_to_raw: Optional[str] = Field(
    default=None,
    description="Verbatim unparsed Reply-To header line. Preserves physical presence and empty headers.",
)
return_path_raw: Optional[str] = Field(
    default=None,
    description="Verbatim unparsed Return-Path header line. Preserves physical presence, empty headers, and null return-path '<>'.",
)
message_id_raw: Optional[str] = Field(
    default=None,
    description="Verbatim unparsed Message-ID header line. Preserves raw whitespace and unstripped bracket formatting.",
)
```

> [!IMPORTANT]
> **Strict Non-Implementation Invariant**: This extension is **not implemented in this task** and existing schemas must not be modified. Under the current contract, features requiring physical presence of empty address headers (such as `undisclosed_recipients` and `to_empty_or_missing`) evaluate to `None` and are quarantined from the active predictive feature vector.

### 2.4 Quarantined Input Attributes
The following fields of `EmailData` are accessible in the object but **quarantined** from entering the feature extraction pipeline:
- `source_filename`: Quarantined (Tier 4 provenance).
- `ingestion_timestamp`: Quarantined (Tier 4 provenance).
- `plain_text_body`, `html_body`, `cleaned_text`: Quarantined (out of domain).
- `extracted_urls`: Quarantined (out of domain).
- `attachments`: Quarantined (out of domain).
- `headers.date`: **Strictly Quarantined**. Both the absolute timestamp string and any boolean presence flag (`has_date_header`) are prohibited from Tier 3 predictive features to enforce the research temporal leakage policy.

---

## 3. Machine-Auditable Canonical Feature Registry and Missingness Semantics

The table below is the single, authoritative, machine-auditable registry for the Header Agent. It specifies all **45 canonical features** in continuous order from 1 to 45.

### 3.1 Canonical Registry Table

| # | Exact Canonical Feature Identifier | Category | Feature Type | Availability Behavior | Predictive Eligibility Status |
|---|---|:---:|:---:|---|---|
| 1 | `from_present` | A: Identity | `bool` | Always evaluable (`headers.from_address is not None`). Normalized value presence indicator. | Active Tier 3 Predictive Feature |
| 2 | `from_address_count` | A: Identity | `Optional[int]` | Conditionally evaluable (`None` if absent/unparseable; `0` if empty [future]; `N` if parsed) | Active Tier 3 Predictive Feature |
| 3 | `reply_to_present` | A: Identity | `bool` | Always evaluable (`headers.reply_to is not None`). Normalized value presence indicator. | Active Tier 3 Predictive Feature |
| 4 | `return_path_present` | A: Identity | `bool` | Always evaluable (`headers.return_path is not None`). Normalized value presence indicator. | Active Tier 3 Predictive Feature |
| 5 | `from_reply_to_domain_mismatch` | A: Identity | `Optional[bool]` | Conditionally evaluable (`None` if From or Reply-To missing/unparseable) | Active Tier 3 Predictive Feature |
| 6 | `from_return_path_domain_mismatch` | A: Identity | `Optional[bool]` | Conditionally evaluable (`None` if From or Return-Path missing/unparseable) | Active Tier 3 Predictive Feature |
| 7 | `display_name_contains_email` | A: Identity | `bool` | Always evaluable (`False` if display name absent or contains no email) | Active Tier 3 Predictive Feature |
| 8 | `display_name_domain_mismatch` | A: Identity | `Optional[bool]` | Conditionally evaluable (`None` if display name has no email or domain unparseable) | Active Tier 3 Predictive Feature |
| 9 | `recipient_count_to` | A: Identity | `Optional[int]` | Conditionally evaluable (`None` if absent, empty, or containing zero valid mailbox addresses under current contract; `N` if $\ge 1$ mailbox addresses successfully parsed). Counts valid RFC 5322 mailbox addresses only; excludes malformed display tokens. | Active Tier 3 Predictive Feature |
| 10 | `recipient_count_cc` | A: Identity | `Optional[int]` | Conditionally evaluable (`None` if absent, empty, or containing zero valid mailbox addresses under current contract; `N` if $\ge 1$ mailbox addresses successfully parsed). Counts valid RFC 5322 mailbox addresses only; excludes malformed display tokens. | Active Tier 3 Predictive Feature |
| 11 | `undisclosed_recipients` | A: Identity | `Optional[bool]` | Conditionally evaluable (`None` under current contract; requires proposed `to_raw`) | **Inactive / Quarantined Pending Ingestion Extension** |
| 12 | `to_empty_or_missing` | A: Identity | `Optional[bool]` | Conditionally evaluable (`None` under current contract; requires proposed `to_raw`) | **Inactive / Quarantined Pending Ingestion Extension** |
| 13 | `from_syntax_valid` | A: Identity | `Optional[bool]` | Conditionally evaluable (`None` if From absent; `False` if unparseable/invalid; `True` if valid) | Active Tier 3 Predictive Feature |
| 14 | `received_hop_count` | B: Routing | `int` | Always evaluable (`0` if no Received headers) | Active Tier 3 Predictive Feature |
| 15 | `has_private_ip_in_external_hop` | B: Routing | `bool` | Always evaluable (`False` if $< 2$ hops or no RFC 1918/4193 in hops 1..N) | Active Tier 3 Predictive Feature |
| 16 | `has_loopback_ip_in_external_hop` | B: Routing | `bool` | Always evaluable (`False` if $< 2$ hops or no loopback in hops 1..N) | Active Tier 3 Predictive Feature |
| 17 | `has_link_local_ip_in_external_hop` | B: Routing | `bool` | Always evaluable (`False` if $< 2$ hops or no link-local in hops 1..N) | Active Tier 3 Predictive Feature |
| 18 | `has_special_ip_in_external_hop` | B: Routing | `bool` | Always evaluable (`False` if $< 2$ hops or no CGNAT/doc/multicast/reserved in hops 1..N) | Active Tier 3 Predictive Feature |
| 19 | `received_syntax_malformed_count` | B: Routing | `int` | Always evaluable (`0` if all hops valid or no hops) | Active Tier 3 Predictive Feature |
| 20 | `missing_received_headers` | B: Routing | `bool` | Always evaluable (`True` if `received_hop_count == 0`) | Active Tier 3 Predictive Feature |
| 21 | `transit_delay_seconds` | B: Routing | `Optional[float]` | Conditionally evaluable (`None` if $< 2$ hops or timestamps unparseable/invalid) | **Exploratory / Quarantined from Primary Predictive Vector** |
| 22 | `transit_delay_unavailable` | B: Routing | `bool` | Always evaluable (`True` if `transit_delay_seconds` is `None`) | **Exploratory / Quarantined from Primary Predictive Vector** |
| 23 | `hop_count_anomaly` | B: Routing | `bool` | Always evaluable (`True` if `received_hop_count == 0` or `> 15`) | Active Tier 3 Predictive Feature |
| 24 | `spf_status` | C: Auth | `AuthStatus` | Always evaluable (`AuthStatus.MISSING` if no reported claim found) | Active Tier 3 Predictive Feature |
| 25 | `dkim_status` | C: Auth | `AuthStatus` | Always evaluable (`AuthStatus.MISSING` if no reported claim found) | Active Tier 3 Predictive Feature |
| 26 | `dmarc_status` | C: Auth | `AuthStatus` | Always evaluable (`AuthStatus.MISSING` if no reported claim found) | Active Tier 3 Predictive Feature |
| 27 | `spf_claim_count` | C: Auth | `int` | Always evaluable (`0` if no claims found) | Active Tier 3 Predictive Feature |
| 28 | `dkim_claim_count` | C: Auth | `int` | Always evaluable (`0` if no claims found) | Active Tier 3 Predictive Feature |
| 29 | `dmarc_claim_count` | C: Auth | `int` | Always evaluable (`0` if no claims found) | Active Tier 3 Predictive Feature |
| 30 | `has_conflicting_spf` | C: Auth | `bool` | Always evaluable (`False` if $< 2$ claims or claims agree) | Active Tier 3 Predictive Feature |
| 31 | `has_conflicting_dkim` | C: Auth | `bool` | Always evaluable (`False` if $< 2$ claims or claims agree) | Active Tier 3 Predictive Feature |
| 32 | `has_conflicting_dmarc` | C: Auth | `bool` | Always evaluable (`False` if $< 2$ claims or claims agree) | Active Tier 3 Predictive Feature |
| 33 | `dkim_signature_header_present` | C: Auth | `bool` | Always evaluable (`True` if `len(headers.dkim_signature) > 0`) | Active Tier 3 Predictive Feature |
| 34 | `dkim_signature_present_without_pass`| C: Auth | `bool` | Always evaluable (`True` if sig present and reported `dkim_status != PASS`) | Active Tier 3 Predictive Feature |
| 35 | `authserv_id_count` | C: Auth | `int` | Always evaluable (`0` if no authserv-id extracted) | Active Tier 3 Predictive Feature |
| 36 | `authserv_id_inconsistent` | C: Auth | `bool` | Always evaluable (`False` if $< 2$ distinct authserv-ids) | Active Tier 3 Predictive Feature |
| 37 | `message_id_present` | D: Metadata | `bool` | Always evaluable (`False` if message_id is absent or whitespace-only) | Active Tier 3 Predictive Feature |
| 38 | `message_id_valid_syntax` | D: Metadata | `Optional[bool]` | Conditionally evaluable (`None` if Message-ID is absent or empty) | Active Tier 3 Predictive Feature |
| 39 | `message_id_domain_mismatch` | D: Metadata | `Optional[bool]` | Conditionally evaluable (`None` if Message-ID or From domain missing/unparseable) | Active Tier 3 Predictive Feature |
| 40 | `mime_version_present` | D: Metadata | `bool` | Always evaluable (`headers.mime_version is not None`) | Active Tier 3 Predictive Feature |
| 41 | `mime_version_valid` | D: Metadata | `Optional[bool]` | Conditionally evaluable (`None` if MIME-Version is absent) | Active Tier 3 Predictive Feature |
| 42 | `has_subject_header` | D: Metadata | `bool` | Always evaluable (`headers.subject is not None`) | Active Tier 3 Predictive Feature |
| 43 | `subject_length` | D: Metadata | `int` | Always evaluable (`0` if Subject is absent or empty) | Active Tier 3 Predictive Feature |
| 44 | `content_type_present` | D: Metadata | `bool` | Always evaluable (`headers.content_type is not None`) | Active Tier 3 Predictive Feature |
| 45 | `content_type_is_multipart` | D: Metadata | `Optional[bool]` | Conditionally evaluable (`None` if Content-Type is absent) | Active Tier 3 Predictive Feature |

### 3.2 Category Breakdown and Predictive Vector Dimensionality
- **Total Canonical Schema Features**: **45 features** (Categories: A=13, B=10, C=13, D=9).
- **Quarantined / Inactive Features**: **4 features**:
  - Feature 11 (`undisclosed_recipients`): Quarantined pending ingestion extension (`to_raw`).
  - Feature 12 (`to_empty_or_missing`): Quarantined pending ingestion extension (`to_raw`).
  - Feature 21 (`transit_delay_seconds`): Exploratory / quarantined pending empirical clock-skew study.
  - Feature 22 (`transit_delay_unavailable`): Exploratory / quarantined pending empirical clock-skew study.
- **Active Primary Predictive Feature Vector ($\mathbf{x}_{\text{header}}$)**: Exactly **41 features** (Categories: A=11, B=8, C=13, D=9).

---

### 3.3 Four Address States: Current Contract vs Proposed Future Contract

To ensure that downstream models do not conflate parsing errors or absent headers with valid zero counts or negative evidence, the agent formally distinguishes four mutually exclusive states for address fields (`From`, `To`, `CC`):

```
State 1: Header Absent entirely.
State 2: Header Present physically, but contains zero address tokens (empty header).
State 3: Header Present, but content is unparseable or malformed.
State 4: Header Present and successfully parsed into >= 1 valid mailbox addresses.
```

#### Detailed Contract Semantics Comparison

| Address State | Ingestion Field Representation (Current Contract) | Current Contract Output Semantics | Proposed Future Ingestion Representation (`raw` fields) | Future Contract Output Semantics |
|---|---|---|---|---|
| **State 1: Absent** | `from_address: None`<br>`to: []`<br>`cc: []` | `from_present = False`<br>`from_address_count = None`<br>`from_syntax_valid = None`<br>`recipient_count_to = None`<br>`to_empty_or_missing = None` | `from_raw: None`<br>`to_raw: None`<br>`cc_raw: None` | `from_present = False`<br>`from_address_count = None`<br>`recipient_count_to = None`<br>`to_empty_or_missing = None` |
| **State 2: Present but Empty** (e.g. `To: \s*`) | `from_address: None`<br>`to: []`<br>`cc: []`<br>*(Indistinguishable from Absent)* | **Quarantined**: Evaluates to `None` with `avail_* = False` to prevent false positive zero assertions. | `from_raw: ""` / `"   "`<br>`to_raw: ""` / `"   "`<br>`cc_raw: ""` / `"   "` | `from_present = True`<br>`from_address_count = 0`<br>`recipient_count_to = 0`<br>`to_empty_or_missing = True` |
| **State 3: Present with Unparseable Content** (e.g. `From: >>>bad<<<`) | `from_address: ">>>bad<<<"`<br>`to: ['@@@']`<br>`cc: ['???']` | `from_present = True`<br>`from_address_count = None`<br>`from_syntax_valid = False`<br>`recipient_count_to = None`<br>`to_empty_or_missing = None` | `from_raw: ">>>bad<<<"`<br>`to_raw: "@@@"` / `"undisclosed:;"` | `from_present = True`<br>`from_address_count = None`<br>`from_syntax_valid = False`<br>`recipient_count_to = None`<br>`undisclosed_recipients = True` (if group) |
| **State 4: Present and Parsed** (e.g. `From: "Admin" <a@b.com>`) | `from_address: "Admin <a@b.com>"`<br>`to: ['u1 <u@b.com>']` | `from_present = True`<br>`from_address_count = 1`<br>`from_syntax_valid = True`<br>`recipient_count_to = 1`<br>`to_empty_or_missing = None` (quarantined) | `from_raw: "Admin <a@b.com>"`<br>`to_raw: "u1 <u@b.com>"` | `from_present = True`<br>`from_address_count = 1`<br>`recipient_count_to = 1`<br>`to_empty_or_missing = False` |

#### Operational Invariants for To and CC
- **Distinguishable Under Current Contract**: The current contract reliably distinguishes State 4 (valid parsed addresses, `len(headers.to) >= 1`) and certain State 3 unparseable display tokens preserved by `_extract_addresses`.
- **Indistinguishable Under Current Contract**: State 1 (Absent) and State 2 (Empty) both collapse to `headers.to == []` and `headers.cc == []`. RFC 2822 empty group syntax (`undisclosed-recipients:;`) also normalizes to `[]`.
- **Quarantine Decision for Feature 12**: Because `to_empty_or_missing` evaluates only to `None` or `False` under the current contract, it possesses zero independent variance from `recipient_count_to` availability. It is **formally quarantined** from active predictive modeling pending the Task 8.6+ `to_raw` ingestion extension.

#### Recipient-Count Parsing Semantics and Mixed Token Handling
To ensure that recipient counts represent genuine mailboxes rather than malformed header fragments:
1. **Strict Mailbox Address Definition**:
   - `recipient_count_to` and `recipient_count_cc` are strictly defined as the counts of **successfully parsed RFC 5322 mailbox addresses** (`addr-spec` or `name-addr` where an actual email address containing local-part and domain separated by `@` is successfully extracted).
   - Arbitrary preserved display tokens (e.g. `undisclosed-recipients:;`, bare unquoted strings, or malformed fragments preserved by `_extract_addresses` fallback logic) do NOT represent mailbox addresses and are **NEVER counted** toward `recipient_count_to` or `recipient_count_cc`.
2. **Mixed Valid and Invalid Lists**:
   - When an email header contains a mixture of valid mailbox addresses and malformed fragments (e.g. `To: <alice@corp.com>, >>>bad_token<<<, "Bob" <bob@corp.com>`):
     - `recipient_count_to` counts ONLY the successfully parsed valid mailbox addresses ($N_{\text{valid}} = 2$).
     - The malformed token (`>>>bad_token<<<`) is strictly excluded from the count.
     - The malformed token is preserved exclusively as a Tier 2 forensic evidence item (`HeaderEvidenceItem`) with status `UNVERIFIED` for post-detection auditability.
3. **Purely Malformed or Empty Lists**:
   - If the header is absent or empty: `recipient_count_to = None` (with `avail_recipient_count_to = False`).
   - If the header contains ONLY malformed tokens with zero valid mailbox addresses (e.g. `To: >>>bad<<<, @@@`):
     - Under the current contract, absent, empty, and unevaluable counts without valid addresses cannot be verified as true zero recipient counts without `to_raw`. Therefore, `recipient_count_to = None` (with `avail_recipient_count_to = False`), avoiding false positive zero assertions.
     - Under the proposed future contract (`to_raw` available): `recipient_count_to = 0` (or `None` when absent).
4. **Preservation of 45/41/4 Structure**:
   - Quarantined features (11, 12, 21, 22) and the active 41 predictive features remain strictly intact across all modeling layers.

---

## 4. Explicit Prohibited Feature List

In compliance with `docs/research/feature_policy.md` and `docs/research/threats_to_validity.md`, the features listed in the table below are **strictly prohibited from entering the Header Agent feature output**.

### 4.1 Prohibited Features Registry

| Prohibited Feature / Header | Category | Rationale & Threat to Validity | Enforcement & Prevention Mechanism |
|---|---|---|---|
| **`X-Spam-*`** (`X-Spam-Status`, `X-Spam-Flag`, `X-Spam-Checker-Version`, `X-Spam-Level`) | Scanner Verdict Leakage | Present in **99.6% (249/250)** of Nazario phishing emails as spam-trap filter tags. Classifiers memorize prior scanner output rather than email features. | Sanitizer regex `(?i)^x-spam-.*`. Never mapped to `HeaderFeatures`. |
| **`List-*`** (`List-Id`, `List-Unsubscribe`, `List-Post`, `List-Help`, `List-Archive`) | Mailing List Artifact | Present in **53.1% (398/750)** of SpamAssassin ham emails due to open-source mailing list origins. Classifiers treat mailing-list metadata as proof of legitimate ham. | Sanitizer regex `(?i)^list-.*`. Never exposed in agent feature space. |
| **`X-Mailman-Version`** | Mailing List Artifact | Characteristic exclusively of historical GNU Mailman mailing list servers in SpamAssassin. | Sanitizer regex `(?i)^x-mailman-.*`. |
| **`Date` (Absolute Timestamp / Year / Month / Day)** | Temporal Leakage | **100% of dated ham emails are from 2002; 100% of dated phishing emails are from 2015/2021.** Splitting on Year achieves 100% accuracy, creating catastrophic temporal bias. | `headers.date` is completely masked. Absolute dates never enter Tier 3. |
| **`has_date_header` (Date Presence Flag)** | Temporal / Shortcut Leakage | Task 8.5.0.1 independent review finding: Date-presence indicators must remain excluded from Tier 3 predictive features. | **Removed from feature whitelist and schema.** |
| **Received Timestamps (Absolute Dates)** | Temporal Leakage | Historical Received timestamps leak the exact calendar year of collection. | Absolute dates in Received headers are strictly stripped. |
| **Received Hostnames / Domains** (`dogma.slashnull.org`, `smtp.internal`, etc.) | Infrastructure Overfitting | Historical corpora route through specific internal relays. Learning these hostnames memorizes collection traps rather than phishing tactics. | The Received-header parser extracts only hop counts, syntax validity, and IP classifications. **All hostnames and domains are dropped.** |
| **Raw `Message-ID` String** (`<20020812...>`, etc.) | Token Memorization | Unique string identifiers can be memorized as exact sample hashes. | Raw `message_id` string is quarantined. Only syntax validity and domain alignment booleans are emitted. |
| **`User-Agent` / `X-Mailer`** | Client Artifact Leakage | Present in 42.8% of ham vs 16.4% of phishing, reflecting historical MUAs (Eudora, Mutt, Outlook Express 6). | Sanitizer regex `(?i)^(user-agent|x-mailer)`. Barred from agent features. |
| **`X-Loop`, `Precedence`** | Mailing List Artifact | Mailing list loop-prevention and precedence headers. | Sanitizer regex `(?i)^(x-loop|precedence)`. Barred from agent features. |
| **`source_dataset`, `source_archive`, `source_category`** | Dataset Provenance Leakage | Directly encodes ground-truth dataset origin. | Quarantined in Tier 4 audit manifests. Strictly prohibited in agent interfaces. |
| **`source_filename`, `sample_id`** | Identifier Leakage | File system and sample identifiers. | Excluded from `HeaderFeatures`. |
| **Subject Semantic Text / Keywords** | Out-of-Domain Semantic Leakage | Semantic text analysis belongs exclusively to the Text Agent. | Header Agent measures only Subject presence and character length; raw text is never passed to NLP extractors in this agent. |

---

## 5. Authentication Evidence Handling

### 5.1 Preservation of Distinct Receiver-Reported RFC Statuses
The Header Agent is an offline feature extractor; it **does not independently verify SPF DNS records, compute DKIM cryptographic signatures, or validate DMARC alignment**. All authentication statuses represent **receiver-reported claims** extracted verbatim from incoming headers.

The 10-status taxonomy defined in `AuthStatus` is preserved without collapsing:
1. `PASS`: Extracted receiver-reported claim asserting valid authentication (e.g. `spf=pass`, `dkim=pass`).
2. `FAIL`: Extracted receiver-reported claim asserting explicit failure (e.g. `spf=fail`, `dkim=fail`).
3. `SOFTFAIL`: Extracted receiver-reported claim asserting SPF `~all` policy mismatch (RFC 7208).
4. `NEUTRAL`: Extracted receiver-reported claim asserting SPF `?all` policy or neutral outcome.
5. `NONE`: Extracted receiver-reported claim asserting no published policy.
6. `TEMPERROR`: Extracted receiver-reported claim indicating transient DNS timeout or error.
7. `PERMERROR`: Extracted receiver-reported claim indicating permanent DNS syntax or policy record error.
8. `MISSING`: No authentication header exists in the incoming message.
9. `UNAVAILABLE`: An authentication header exists but could not be parsed or omitted the mechanism.
10. `OTHER`: Contradictory, ambiguous, or multi-claim conflicting outcomes across headers.

### 5.2 Granular Distinctions and Research Invariants
- **Unverified Claims by Default**: `Authentication-Results` headers are written by MTAs. In offline archives or untrusted relays, these headers can be injected by attackers. All claims extracted from headers are classified as `verification_status = UNVERIFIED`. The agent never marks a claim `VERIFIED`.
- **`authserv_id` Does Not Imply Trust**: The presence of an `authserv-id` (e.g. `authserv-id=mx.google.com`) proves only that the header declared that token; without an authenticating cryptographic chain to the recipient boundary MTA, it cannot be trusted as genuine.
- **DKIM-Signature Presence $\neq$ DKIM Pass**: The presence of a `DKIM-Signature` header proves only that the sender included a signature header; it does not indicate that the signature verified. A signature without a corresponding `dkim=pass` claim in an authentic `Authentication-Results` header is treated as unverified (`dkim_status = MISSING` or `UNAVAILABLE`).
- **Reported Pass $\neq$ Legitimacy**: Legitimate, authenticated email infrastructure is routinely compromised or abused by attackers. Under no circumstances does the Header Agent equate a reported SPF, DKIM, or DMARC pass with proof of benign ham.
- **No DMARC Inference**: The agent never synthesizes or infers a DMARC pass from individual SPF and DKIM passes. DMARC requires strict domain identifier alignment that can only be evaluated if explicitly verified by the receiver.
- **Distinct Conflict Handling Across All Three Mechanisms**: Contradictory claims are tracked independently for SPF (`has_conflicting_spf`), DKIM (`has_conflicting_dkim`), and DMARC (`has_conflicting_dmarc`). When contradictory claims occur, the mechanism summary status resolves to `AuthStatus.OTHER`.

---

## 6. Received-Header Structural Analysis, Trust Model, and Configuration Contract

### 6.1 Formal Received-Header Threat Model and Ordering Semantics
In email transmission, `Received` headers are prepended sequentially as the message traverses mail transfer agents.

```
[Sender MUA / Threat Actor Bot]
       │
       ▼
[Relay 1: Attacker-Controlled VPS]        ──► Prepends Received: hop 2 (FORGEABLE)
       │
       ▼
[Relay 2: Intermediate Open Relay]        ──► Prepends Received: hop 1 (FORGEABLE)
       │
       ▼
[Recipient Border MTA: Local Gateway]     ──► Prepends Received: hop 0 (CONDITIONALLY TRUSTED)
       │
       ▼
[Offline .eml Storage / File Archive]
```

**Ingestion Ordering vs Chronological Transit**:
- Standard RFC 5322 MTAs prepend Received headers at the top of the header block. In `email_ingestor.py`, `message.get_all("Received")` reads headers top-to-bottom as serialized in the file.
- Thus, index 0 reflects the **top-of-file Received header**, and index $N-1$ reflects the bottom-of-file header.
- **Critical Ordering Caveat**: If an email was created or re-serialized by a non-standard tool or mail exporter, top-of-file order may not represent chronological order. **The implementation must verify physical header ordering against prepended timestamps before relying on index 0 as the outermost border hop.** If ordering is ambiguous, hop-index assumptions fail closed.

---

### 6.2 Authenticated Received-Header Trust Configuration Contract

A caller-supplied boolean inside an unauthenticated request body cannot establish transport trust. A Pydantic model is purely an in-memory data schema and validator; **its type alone does NOT establish authenticity**. Authenticity can only be established by external runtime verification (TLS handshake termination with mutual client verification) or asymmetric cryptographic digital signatures verified against trusted public keys.

#### Enforceable mTLS Runtime Deployment Boundary
To make the mutual TLS boundary enforceable rather than theoretical, the detection architecture specifies strict deployment-level runtime integration requirements:

1. **Termination Component**:
   Mutual TLS is terminated exclusively by an infrastructure-level component (e.g. an ingress reverse proxy such as Envoy or NGINX with `ssl_verify_client on;`, or an ASGI/gRPC server terminating TLS). The application code and Pydantic validators do not terminate TLS.
2. **Identity Extraction**:
   Upon successful TLS handshake verification against the enterprise internal certificate authority, the TLS termination component extracts the validated client identity from the client certificate's Subject Alternative Name (SAN: URI, DNS, or RFC 822 email) or Subject Common Name (CN).
3. **Internal Identity Propagation**:
   The authenticated identity is transferred across the internal boundary to the detector application via secure intra-cluster IPC, Unix domain socket, or cryptographically signed internal gateway tokens (e.g. RFC 7519 JWT or Envoy `x-forwarded-client-cert` verified by internal server middleware).
4. **Server-Controlled Dependency Injection**:
   The detector runtime receives this context via server-controlled dependency injection (e.g. FastAPI `Depends(get_trusted_transport_context)` or ASGI middleware setting `request.state.trusted_transport`).
5. **Strict External Ingress Barrier**:
   - The external ingress layer **strictly strips and rejects** any client-supplied HTTP headers attempting to assert transport authentication (e.g. `X-Client-Identity`, `X-Forwarded-Client-Cert`).
   - Public request JSON schemas (`EmailData`, `AcquisitionProvenanceRecord`) forbid transport context fields (`extra = "forbid"`).
6. **Fallback and Failure Behavior**:
   If `TrustedTransportContext` is missing, unauthenticated (`client_authenticated == False`), or cannot be cryptographically verified by server middleware, transport authentication is absent. The detector automatically falls back to Path B (Signature-based). If Path B is also absent or invalid, evaluation terminates at Step 2 and fails closed to `UNVERIFIED`.
7. **Deployment Requirement Disclaimer**:
   If the specific hosting infrastructure (e.g. Envoy vs NGINX) is not yet finalized in a given deployment, this boundary is explicitly classified as a **deployment-level integration requirement**. Pydantic models alone do not guarantee network-layer security.

```python
class TrustedTransportContext(BaseModel):
    """
    Transport authentication context supplied exclusively by the trusted hosting
    runtime (e.g. reverse proxy, ASGI middleware, or gRPC interceptor).
    
    STRICT SERVER-SIDE BOUNDARY:
    - This model is NOT part of the public request schema or caller-controlled JSON.
    - It is instantiated ONLY by trusted server-side transport middleware terminating mTLS.
    - The detector receives it through a server-side dependency injection boundary.
    - Any caller-supplied transport fields in request bodies or HTTP headers are stripped/rejected.
    """
    client_authenticated: bool = Field(
        default=False,
        description="True ONLY if the hosting transport layer verified mutual TLS (mTLS).",
    )
    client_identity: Optional[str] = Field(
        default=None,
        description="Authenticated client certificate Common Name (CN) or SAN matching integration ID.",
    )

    model_config = {"extra": "forbid"}


#### Authentication Credential Combinations and Path Selection

When processing an incoming `AcquisitionProvenanceRecord` alongside the server-injected `TrustedTransportContext`, the detector evaluates the presence of transport credentials and cryptographic signing parameters (`key_id`, `integration_signature`). The architecture defines exact, deterministic handling across all six possible permutations:

1. **Combination 1: Pure mTLS (Path A)**
   - **Condition**: `TrustedTransportContext.client_authenticated == True`, `record.key_id is None`, `record.integration_signature is None`.
   - **Handling**: Validated under Path A. Evaluates `client_identity == record.acquisition_integration_id`. Canonical 7-field framing construction and cryptographic signature verification are bypassed. Proceeds to Steps 3–8.
2. **Combination 2: Partial Credentials with mTLS (Missing Signature)**
   - **Condition**: `TrustedTransportContext.client_authenticated == True`, `record.key_id is not None`, `record.integration_signature is None`.
   - **Handling**: Malformed credentials. If a key ID is specified, a corresponding digital signature is mandatory. Fails closed at Step 1/2 with audit status `partial_credentials_missing_signature`. The replay store is NOT touched.
3. **Combination 3: Partial Credentials with mTLS (Missing Key ID)**
   - **Condition**: `TrustedTransportContext.client_authenticated == True`, `record.key_id is None`, `record.integration_signature is not None`.
   - **Handling**: Malformed credentials. If a digital signature is provided, the key ID is mandatory to resolve the verification public key. Fails closed at Step 1/2 with audit status `partial_credentials_missing_key_id`. The replay store is NOT touched.
4. **Combination 4: Dual Authentication Mode (mTLS + Cryptographic Signature)**
   - **Condition**: `TrustedTransportContext.client_authenticated == True`, `record.key_id is not None`, `record.integration_signature is not None`.
   - **Handling**: Both transport-level and application-level authentication are evaluated. First, `client_identity == record.acquisition_integration_id` is verified. Second, the public key is resolved via `(integration_id, key_id)` from the keyring, the canonical 7-field framing is constructed and pre-validated, and the Ed25519 signature is verified.
   - **Dual Auth Invariant**: If the signature fails verification, the key is unknown/revoked/expired, or framing validation fails, the request **FAILS CLOSED** with `dual_auth_signature_invalid` (or specific key failure). Providing an invalid cryptographic signature over an authenticated transport channel is treated as a security violation, NOT silently ignored. Both mechanisms must pass.
5. **Combination 5: Pure Path B Signature (No mTLS Context)**
   - **Condition**: `TrustedTransportContext.client_authenticated == False` (or transport context absent), `record.key_id is not None`, `record.integration_signature is not None`.
   - **Handling**: Validated under Path B. Requires full 7-field canonical framing pre-validation, active key lookup in keyring, and valid Ed25519 signature. Proceeds to Steps 3–8 upon successful verification.
6. **Combination 6: Unauthenticated Request (Missing Credentials)**
   - **Condition**: `TrustedTransportContext.client_authenticated == False` (or absent), and either `record.key_id is None` or `record.integration_signature is None`.
   - **Handling**: Lacks both transport authentication and complete cryptographic credentials. Fails closed at Step 2 with `unauthenticated_provenance` (or `partial_credentials_missing_*`). The replay store is NEVER touched.


class SigningKeyRecord(BaseModel):
    """
    Cryptographic public key registration record for an authorized acquisition integration.
    Enables deterministic key resolution, active lifecycle tracking, and seamless rotation.
    """
    key_id: str = Field(
        description="Explicit identifier for the signing key (e.g. 'mta-key-2026a', matching ^[a-zA-Z0-9_\\-\\.]{1,64}$).",
    )
    integration_id: str = Field(
        description="Identifier of the authorized integration owning this key (matches AcquisitionProvenanceRecord).",
    )
    algorithm: Literal["ed25519"] = Field(
        default="ed25519",
        description="Cryptographic signature algorithm. Currently fixed to Ed25519 (RFC 8032).",
    )
    public_key_bytes: bytes = Field(
        description="Raw 32-byte Ed25519 public verification key.",
    )
    status: Literal["active", "revoked", "expired"] = Field(
        default="active",
        description="Key lifecycle status. Only 'active' keys within their validity window can verify signatures.",
    )
    valid_from_utc: str = Field(
        description="ISO 8601 UTC timestamp defining when the key became valid for verification.",
    )
    valid_until_utc: str = Field(
        description="ISO 8601 UTC timestamp defining when the key expires.",
    )

    model_config = {"extra": "forbid"}


class AcquisitionProvenanceRecord(BaseModel):
    """
    Authenticated external record establishing verified acquisition provenance (Model B).
    Supplied by the deployment integration; NEVER derived from .eml content.
    
    CREDENTIAL COMBINATIONS & PATH SELECTION:
    - Path A (Pure mTLS, Combination 1):
      Requires TrustedTransportContext.client_authenticated == True.
      'key_id' and 'integration_signature' are BOTH None.
      Does NOT construct or validate the 7-field canonical signature payload.
      Validates transport identity, digest, authorization, timestamp, nonce, and boundary.
    - Partial Credentials (Combinations 2 & 3):
      Providing one of (key_id, integration_signature) without the other is strictly REJECTED.
    - Dual Authentication Mode (Combination 4):
      mTLS is valid AND both 'key_id' and 'integration_signature' are provided.
      Both mTLS identity and Ed25519 signature must succeed. Bad signature FAILS CLOSED.
    - Path B (Pure Signature, Combination 5):
      Used when mTLS is absent or unauthenticated.
      Requires both 'key_id' and 'integration_signature' to be present and non-empty.
      Requires all 7 canonical framing fields to be valid and non-empty.
      Resolves public key using (integration_id, key_id) from keyring.
      Verifies Ed25519 signature before replay-store reservation.
    - Unauthenticated (Combination 6):
      Lacks mTLS and complete signature credentials; rejected before store access.
    """
    version: Literal["V1"] = Field(
        default="V1",
        description="Provenance contract schema version (fixed literal 'V1').",
    )
    key_id: Optional[str] = Field(
        default=None,
        description="Signing key identifier. Required for Path B (Signature); optional (None) for Path A (mTLS).",
    )
    email_sha256: str = Field(
        description="Hex-encoded SHA-256 digest of the raw acquired email bytes (exact 64 lowercase hex chars).",
    )
    acquisition_integration_id: str = Field(
        description="Identifier of authorized integration asserting capture (e.g. 'postfix-milter-01').",
    )
    assertion_timestamp_utc: str = Field(
        description="ISO 8601 UTC timestamp in format YYYY-MM-DDTHH:MM:SSZ. Enforces lexical & calendar validation.",
    )
    assertion_nonce: str = Field(
        description="High-entropy unique nonce (16-64 chars) for distributed anti-replay protection.",
    )
    boundary_mta_hostname: str = Field(
        description="Local MTA hostname where message capture occurred (max 253 chars lowercase RFC 1123/5890 FQDN).",
    )
    integration_signature: Optional[str] = Field(
        default=None,
        description="Ed25519 signature over canonical framed payload. Required for Path B; optional for Path A.",
    )

    model_config = {"extra": "forbid"}


class ReceivedTrustPolicy(BaseModel):
    """
    Configuration contract for establishing trusted receiving boundaries.
    Supplied externally to the detector during production deployment.
    NOTE: Not present in current EmailData input; distinguishing offline from configured analysis.
    """
    authorized_integration_ids: list[str] = Field(
        default_factory=list,
        description="Whitelisted integration identifiers authorized to assert acquisition provenance.",
    )
    signing_keys: list[SigningKeyRecord] = Field(
        default_factory=list,
        description="Keyring of registered signing keys for authorized integrations.",
    )
    max_assertion_age_seconds: int = Field(
        default=300,
        description="Maximum permissible age of assertion timestamp before failing closed (default 300s).",
    )
    max_future_clock_skew_seconds: int = Field(
        default=60,
        description="Maximum accepted future clock skew between client and detector clocks (default 60s).",
    )
    require_shared_replay_store: bool = Field(
        default=True,
        description="If True, mandates distributed shared store (e.g. Redis). If store unreachable, fails closed.",
    )
    trusted_mta_hostnames: list[str] = Field(
        default_factory=list,
        description="Explicit FQDN hostnames of known local receiving MTAs (e.g. ['mx1.corp.internal']).",
    )
    trusted_ip_cidrs: list[str] = Field(
        default_factory=list,
        description="CIDR address blocks of authorized receiving boundary gateways (e.g. ['198.51.100.0/24']).",
    )
    provenance_record: Optional[AcquisitionProvenanceRecord] = Field(
        default=None,
        description="External authenticated provenance record bound to the specific message.",
    )
    enforce_boundary_check: bool = Field(
        default=False,
        description="Master boundary enforcement toggle. If False, trust promotion is COMPLETELY SUPPRESSED.",
    )
    require_both_checks: bool = Field(
        default=True,
        description="Applies when BOTH hostnames and IPs are configured. If True, both must match. If False, one match suffices if other does not contradict.",
    )

    model_config = {"extra": "forbid"}
```

#### Deterministic Signing-Key Resolution and Lifecycle Invariants
When executing Path B (Signature-based), the detector resolves verification keys deterministically:
1. **Keyring Lookup Tuple**: Keys are indexed by the composite tuple `(integration_id, key_id)`.
2. **Missing Key ID**: If `integration_signature` is present but `key_id` is omitted or empty $\rightarrow$ fail closed (`missing_key_id`).
3. **Unknown Key**: If no key matches `(integration_id, key_id)` in `policy.signing_keys` $\rightarrow$ fail closed (`unknown_key_id`).
4. **Ambiguous Selection**: If multiple entries match `(integration_id, key_id)` with conflicting definitions $\rightarrow$ fail closed (`ambiguous_key_selection`).
5. **Revocation Check**: If matched key has `status == "revoked"` $\rightarrow$ fail closed (`revoked_key_id`).
6. **Expiration Check**: If matched key has `status == "expired"` OR current time is outside `[valid_from_utc, valid_until_utc]` $\rightarrow$ fail closed (`expired_key_id`).
7. **Active Key Qualification**: A key is valid for signature verification if and only if:
   $$\text{status} == \texttt{"active"} \quad \land \quad t_{\text{valid\_from}} \le t_{\text{current}} \le t_{\text{valid\_until}}$$
8. **Multi-Key Rotation Support**: During an active key rotation window, an integration may register multiple `active` keys with distinct `key_id` values (e.g. `mta-key-2026a` and `mta-key-2026b`). The incoming assertion explicitly declares which key signed the message, allowing seamless zero-downtime rotation.

---

### 6.3 Separation of the Eight Sequential Trust Steps

Trust promotion is executed as eight distinct, strictly ordered sequential steps. **Crucially, unauthenticated requests and requests with partial credentials are rejected at Step 1 or Step 2 and NEVER reach the replay store, eliminating nonce-exhaustion denial-of-service**:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Step 1: Validate Record Structure, Calendar Format & Credential Completeness│
│ - Validate required base fields (version, sha256, id, timestamp, nonce, host│
│ - Strict lexical regex format AND semantic UTC calendar check (reject leap). │
│ - Credential Completeness Check:                                            │
│   • Partial missing signature (key_id!=None, sig=None) -> ABORT             │
│   • Partial missing key ID (key_id=None, sig!=None)    -> ABORT             │
│   • Unauthenticated without mTLS (mTLS=False, sig=None)-> ABORT             │
│ └──> If structure/calendar/credentials invalid: ABORT -> UNVERIFIED         │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Step 2: Authenticate Provenance Issuer (Path A, Dual Auth, or Path B)       │
│ - Path A (Pure mTLS): client_authenticated == True, key_id=None, sig=None.  │
│   Assert client_identity == record.acquisition_integration_id.              │
│   (Bypasses 7-field canonical framing and signature verification).          │
│ - Dual Auth Mode: client_authenticated == True, key_id!=None, sig!=None.    │
│   Assert client_identity == integration_id AND verify Ed25519 signature.   │
│   (If signature invalid -> ABORT dual_auth_signature_invalid).              │
│ - Path B (Pure Signature): mTLS absent/False, key_id!=None, sig!=None.      │
│   Resolve key via (integration_id, key_id); verify active status/validity;   │
│   construct canonical 7-field framing and verify Ed25519 signature.         │
│ └──> If issuer auth fails: ABORT -> UNVERIFIED (unauthenticated_provenance) │
│      NOTE: Unauthenticated requests abort HERE. Store is NOT touched!       │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Step 3: Verify Integration Authorization                                    │
│ - Assert record.acquisition_integration_id in policy.authorized_integration│
│ └──> If not authorized: ABORT -> UNVERIFIED (unauthorized_integration_id)   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Step 4: Validate Freshness and Future-Clock-Skew Limits                      │
│ - Let T_now = current UTC time, T_assert = record.assertion_timestamp_utc.  │
│ - Check future skew: T_assert <= T_now + max_future_clock_skew (60s).       │
│ - Check maximum age: T_assert >= T_now - max_assertion_age (300s).          │
│ └──> If future skew exceeded: ABORT -> (future_timestamp_skew_exceeded)     │
│ └──> If assertion expired: ABORT -> (assertion_expired)                     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Step 5: Atomically Reserve Nonce in Distributed Shared Store & Drain Check  │
│ - Check Recovery Drain: If store restarted/failed over within 361s (monoton)│
│   ABORT -> UNVERIFIED (replay_store_recovery_drain).                         │
│ - Compute TTL = max(60, ceil((T_assert + max_age) - T_res)), capped at 360s│
│ - Enforce store properties: atomic check-and-insert, noeviction, durability.│
│ - Atomic check-and-insert: SET replay:{id}:{nonce} {T_res} NX EX {TTL}       │
│ └──> If duplicate exists: ABORT -> UNVERIFIED (replay_detected)             │
│ └──> If store unreachable or uncertain: ABORT -> (replay_store_unavailable) │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Step 6: Verify Raw-Message SHA-256 Binding                                  │
│ - Compute actual_sha256 = hashlib.sha256(raw_email_bytes).hexdigest()       │
│ - Constant-time assert actual_sha256.lower() == record.email_sha256.lower() │
│ └──> If digest mismatch: ABORT -> UNVERIFIED (digest_mismatch)              │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Step 7: Evaluate Received Boundary Consistency (7-Permutation Policy)       │
│ - Assert enforce_boundary_check == True (if False, trust is suppressed).    │
│ - Assert Received ordering chronologically consistent (no timestamp skew).  │
│ - Strict Mode (require_both=True): Host AND IP must both match.             │
│ - Relaxed Mode (require_both=False): One token match suffices ONLY if other │
│   token is missing. If other token CONTRADICTS policy -> FAIL CLOSED!       │
│ └──> If consistency check fails: ABORT -> UNVERIFIED (boundary contradiction│
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Step 8: Promote ONLY Hop 0 to TRUSTED_RECEIVER                              │
│ - ONLY outermost boundary Hop 0 receives TrustLevel.TRUSTED_RECEIVER.       │
│ - Upstream hops (1..N) strictly remain TrustLevel.UNVERIFIED.               │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Nonce Reservation Ordering, Nonce Consumption, and Retry Policy

The sequence of trust decisions places Step 5 (Atomic Nonce Reservation) immediately after Step 4 (Freshness Validation) and prior to Step 6 (SHA-256 Digest Binding) and Step 7 (Received Boundary Evaluation). The security rationale, side effects, and operational policies governing this ordering are:

1. **Denial-of-Service Defense and Resource Shielding**:
   - Computing cryptographic SHA-256 digests over large MIME message bodies (potentially tens of megabytes with attachments) and parsing complex multi-hop Received header chains with regex and IP tokenization are computationally expensive operations.
   - Placing atomic nonce reservation at Step 5 immediately after cheap issuer authentication (Steps 2/3) and timestamp boundary checks (Step 4) ensures that replayed or duplicate assertions are intercepted and terminated **before** the detector expends CPU cycles and memory allocating buffers, hashing email bytes, or traversing Received trees.

2. **Nonce Consumption on Downstream Failure**:
   - Because nonce reservation occurs at Step 5, if an incoming assertion subsequently fails validation at Step 6 (`digest_mismatch`, e.g. payload transit corruption) or Step 7 (`boundary_ip_contradiction`, `boundary_hostname_contradiction`, etc.), the nonce has ALREADY been reserved in the distributed replay store.
   - **The nonce is permanently consumed for that reservation attempt**. The detector never rolls back or deletes a reserved nonce upon downstream failure, as attempting to un-reserve keys introduces race conditions, orphan reservations, and replay attack vectors.

3. **Mandatory Fresh Nonce and Re-Signing on Retry**:
   - Because a consumed nonce cannot be un-reserved, the acquiring integration **CANNOT simply retry sending the identical assertion payload with the same nonce**. Doing so will immediately collide at Step 5 and be rejected with `replay_detected`.
   - **Retry Invariant**: If an integration needs to retry transmission or submit a corrected assertion (e.g. following network data corruption, re-acquiring the raw message bytes, or correcting boundary MTA routing), the integration **MUST generate a completely new assertion with a fresh high-entropy nonce**, compute an updated timestamp, and **re-sign the assertion** (under Path B or Dual Auth Mode). Reusing an existing nonce across transmission attempts is strictly forbidden.

4. **Duration of Nonce Consumption and Expiration**:
   - Nonce keys in the distributed store are not stored indefinitely; they are governed by the dynamic store TTL formula:
     $$\text{TTL}_{\text{seconds}} = \min\Big(360, \; \max\Big(60, \; \lceil (T_{\text{assert}} + 300) - T_{\text{res}} \rceil\Big)\Big) \le 360\text{ seconds}$$
   - When the TTL expires, the key is evicted from the store to reclaim memory.
   - However, after TTL expiration ($t > T_{\text{res}} + \text{TTL}$), the assertion timestamp $T_{\text{assert}}$ is guaranteed to be $> 300\text{ seconds}$ in the past relative to the current wall-clock time ($T_{\text{current}} - T_{\text{assert}} > 300\text{s}$). Any subsequent attempt to present that identical assertion is permanently blocked at Step 4 (`assertion_expired`) **before** the storage engine is queried.
   - Therefore, while the physical storage record expires under the store TTL, nonce consumption for that specific assertion is **effectively permanent for the entire validity lifetime of the assertion**.

#### Replay Protection: Atomicity vs Durability and Operational Storage Guarantees

We strictly distinguish between **in-memory atomicity**, **local disk persistence**, **replication acknowledgement**, and **durable failover guarantees** under realistic distributed storage systems:

1. **Atomicity vs Durability Defined**:
   - **Atomicity (`SET NX EX`)**: Guarantees mutual exclusion in memory across concurrent application worker threads. If two identical requests arrive simultaneously at different detector nodes, exactly one executes the insert and succeeds, while the other receives a collision error. Atomicity prevents concurrent race conditions during normal operation.
   - **Durability**: Guarantees that once a reservation write is acknowledged as successful to the detector, that reservation survives process termination, operating system crashes, physical power outages, and database cluster failovers.

2. **The Crash Loss Window of Redis AOF `appendfsync everysec`**:
   - In standard Redis deployments configured with Append-Only File (AOF) persistence using `appendfsync everysec`, the `fsync()` system call is delegated to a background thread executed once per second.
   - **Crash Loss Window**: If the server experiences a sudden crash (kernel panic, power loss, OOM kill, hardware fault), all writes acknowledged during the preceding 1 second (and up to 2 seconds under high disk write latency) are permanently lost from persistent storage.
   - **Replication Lag Window**: In a Redis Sentinel or Redis Cluster deployment with asynchronous replication, acknowledged writes on the primary node may not have replicated to standby replicas before a failover occurs. When an un-replicated standby is promoted to primary, acknowledged reservations from the failover window vanish.
   - **Replay Attack Window**: A threat actor capturing a valid email assertion could intentionally trigger or wait for a primary crash or cluster failover. Upon failover, the lost reservation allows the identical assertion nonce to be re-reserved, completely bypassing replay protection.

3. **Separation of Durability Layers and Redis Limitations**:
   We explicitly disentangle the three independent layers of storage durability:
   - **Layer 1: Local Disk Persistence**: Configuring Redis with `appendfsync always` forces an `fsync()` to the local operating system filesystem before acknowledging each write. However, this protects only against single-process crashes; it does not protect against host hardware destruction, power loss bypassing volatile drive controller caches, or unrecoverable node corruption.
   - **Layer 2: Replication Acknowledgement (`WAIT`)**: The Redis `WAIT numreplicas timeout` command blocks until the specified number of replicas acknowledge receiving the command in their *replication stream*. Crucially:
     - `WAIT` **only confirms replication to replica memory**, not replica disk flush. It does NOT enforce or verify that replicas have called `fsync()`.
     - `WAIT` does not convert Redis into a linearizable consensus system. If a replica experiences a power loss or kernel panic immediately after failover, un-fsynced reservations in replica memory are lost.
   - **Layer 3: Durable Failover Guarantees**: Failover in Redis Sentinel and Redis Cluster is asynchronous and consensus-based on node heartbeats, not write linearizability. During network partitions or split-brain conditions, Sentinel or Cluster may elect a replica that did not receive the latest acknowledged writes.
   - **Correction**: We strictly **reject the claim that `appendfsync always` plus `WAIT` provides "absolute replay immunity"**. Redis was not architected as a CP consensus engine and cannot guarantee zero acknowledged-write loss across all Byzantine, partition, and power-loss failover scenarios.

4. **Required Operational Storage Guarantees**:
   To guarantee absolute zero acknowledged-write loss without reliance on recovery drains, the selected storage architecture MUST implement a **distributed consensus-backed engine with synchronous quorum write-ahead logging (WAL)**:
   - Consensus-backed engines (e.g. Raft/Paxos in Etcd, CockroachDB, Google Cloud Spanner).
   - Alternatively, multi-node relational databases with synchronous physical replication and quorum commit confirmation (e.g. PostgreSQL with `synchronous_commit = on` and `synchronous_standby_names` configured to quorum `FIRST 1 (...)` or `remote_apply`).
   - If Redis is selected, the operational architecture MUST enforce the strictly safe **361-second recovery drain period** described below to compensate for Redis's failover durability limitations.

5. **Restart, Failover Recovery, and the 361-Second Strictly Safe Recovery Drain**:
   When a storage node restarts after an ungraceful shutdown, undergoes a failover, or completes an unconfirmed replication resynchronization, it cannot prove that zero acknowledged reservations were lost during the crash window:
   - **Recalculation of Maximum Assertion Lifetime**:
     The maximum acceptable assertion parameters are:
     - Maximum assertion age: $\Delta t_{\text{max\_age}} = 300\text{ seconds}$.
     - Maximum future clock skew: $\Delta t_{\text{future\_max}} = 60\text{ seconds}$.
     Suppose a crash occurs at detector time $T_{\text{crash}}$. A client immediately prior to the crash could have generated an assertion whose timestamp was ahead by the maximum allowable future skew:
     $$T_{\text{assert}} = T_{\text{crash}} + \Delta t_{\text{future\_max}} = T_{\text{crash}} + 60\text{s}$$
   - **The Inclusive Freshness Boundary Condition at Exactly 360 Seconds**:
     At exactly 360 seconds post-crash ($T_{\text{now}} = T_{\text{crash}} + 360\text{s}$), the Step 4 maximum age check evaluates:
     $$T_{\text{assert}} \ge T_{\text{now}} - \Delta t_{\text{max\_age}} \iff (T_{\text{crash}} + 60\text{s}) \ge (T_{\text{crash}} + 360\text{s}) - 300\text{s} = T_{\text{crash}} + 60\text{s}$$
     Notice that at exactly 360 seconds, $T_{\text{assert}} == T_{\text{now}} - 300\text{s}$.
     Because the freshness check is **inclusive** ($\ge$), the assertion is **still accepted as valid and fresh at exactly 360 seconds**.
     Therefore, claiming that all pre-crash assertions have expired at an inclusive 360-second boundary is mathematically false.
   - **Strictly Safe Recovery Drain Duration ($\Delta t_{\text{drain}} \ge 361\text{s}$)**:
     To guarantee that every possible pre-crash assertion is strictly expired ($T_{\text{assert}} < T_{\text{now}} - 300\text{s}$), the drain duration must be strictly greater than 360 seconds:
     $$\Delta t_{\text{drain}} \ge 361\text{ seconds} \quad (\text{or } T_{\text{elapsed}} > 360\text{s})$$
     At $T_{\text{now}} \ge T_{\text{crash}} + 361\text{s}$:
     $$T_{\text{now}} - 300\text{s} \ge T_{\text{crash}} + 61\text{s} > T_{\text{crash}} + 60\text{s} = T_{\text{assert}}$$
     Every single assertion issued or acknowledged prior to the crash is guaranteed to fail Step 4 (`assertion_expired`) and will be rejected before the storage engine is queried.
   - **Monotonic Clock Source and Clock Adjustment Invariance**:
     - The recovery drain duration MUST be measured using a **monotonic clock source** (`time.monotonic()` or hardware monotonic timer), NOT wall-clock time (`time.time()`).
     - Monotonic time cannot jump backwards or forwards due to NTP step adjustments, leap-second smearing, or system administrator clock changes. This guarantees that external clock modifications cannot shorten or bypass the drain period.
     - If monotonic continuity is broken (e.g. full system reboot, container restart), the drain timer resets to zero and enforces a full 361-second drain from service startup.
   - **Drain Behavior**: Any incoming request during this 361-second window aborts at Step 5 and fails closed to `UNVERIFIED` with logged audit reason `replay_store_recovery_drain`.

6. **Fail-Closed on Store Uncertainty**:
   - If a connection timeout, Redis cluster redirection, network partition, or ambiguous response occurs during Step 5, the detector **MUST FAIL CLOSED** (`replay_store_unavailable` or `replay_state_uncertain`). Every Received hop remains `UNVERIFIED`.

7. **Explicit Retention of Unresolved Deployment Dependencies**:
   - **Replay store durability and failover guarantees are explicitly retained as an unresolved deployment dependency**.
   - Absolute replay protection cannot be claimed based solely on `SET NX EX`, `noeviction`, AOF `everysec`, or `WAIT`.
   - Until synchronous consensus durability (e.g. Raft/Paxos WAL or synchronous PostgreSQL) or the strictly safe 361-second monotonic post-crash recovery drain is operationalized in the deployment environment, production trust promotion MUST remain disabled or restricted to non-critical monitoring environments.

#### Step 7: Complete Relaxed Boundary Matching Permutations (`require_both_checks=False`)
When evaluating Hop 0 against configured receiving boundaries where both `trusted_mta_hostnames` and `trusted_ip_cidrs` are configured, `require_both_checks=False` permits asymmetric hops where one token is omitted. However, **contradicting checks must NEVER be ignored**. The architecture specifies all seven permutations exhaustively:

| Permutation | Host Token vs Policy | IP Token vs Policy | Hop 0 Outcome | Logged Reason | Architectural Rationale |
|---|---|---|:---:|---|---|
| **1. Both Match** | Matches configured hostnames | Matches configured CIDRs | **TRUSTED_RECEIVER** | `trusted_boundary_matched` | Perfect dual match. |
| **2. Host Match, IP Missing** | Matches configured hostnames | IP token absent in hop | **TRUSTED_RECEIVER** | `trusted_boundary_matched` | Relaxed check: host matches, no IP contradiction. |
| **3. IP Match, Host Missing** | Host token absent in hop | Matches configured CIDRs | **TRUSTED_RECEIVER** | `trusted_boundary_matched` | Relaxed check: IP matches, no host contradiction. |
| **4. Host Match, IP Contradiction** | Matches configured hostnames | IP present, **mismatches** CIDRs | **UNVERIFIED** | `boundary_ip_contradiction` | **Contradiction barrier**: Authorized host cannot excuse an untrusted IP. |
| **5. IP Match, Host Contradiction** | Host present, **mismatches** hostnames | Matches configured CIDRs | **UNVERIFIED** | `boundary_hostname_contradiction` | **Contradiction barrier**: Authorized IP cannot excuse an untrusted hostname. |
| **6. Both Contradict** | Host present, **mismatches** | IP present, **mismatches** | **UNVERIFIED** | `boundary_mismatch` | Both tokens present and neither matches configured policy. |
| **7. Both Missing** | Host token absent in hop | IP token absent in hop | **UNVERIFIED** | `missing_boundary_tokens` | Cannot evaluate boundary without at least one token present. |

---

### 6.4 Canonical Framing, Hostname Normalization, and Strict Parser Specification

Delimiter-based formats (e.g. pipe-delimited strings) are vulnerable to delimiter injection when fields contain delimiter characters. To guarantee mathematical uniqueness and cross-platform verification consistency, we specify **Length-Prefixed Canonical Framing** for **Path B (Signature-based)** authentication. (Path A mTLS-only assertions do not construct or verify this payload).

#### Normalization-Before-Validation Pipeline (Path B)
Fields are processed in three strict, non-overlapping phases:
1. **Phase 1: Normalization**:
   - `version`: Stripped of whitespace $\rightarrow$ `"V1"`.
   - `key_id`: Stripped of leading/trailing whitespace.
   - `email_sha256`: Stripped of whitespace and converted to lowercase hex ASCII.
   - `acquisition_integration_id`: Stripped of leading/trailing whitespace.
   - `assertion_timestamp_utc`: Stripped of whitespace and converted to normalized ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`).
   - `assertion_nonce`: Stripped of leading/trailing whitespace.
   - `boundary_mta_hostname`:
     1. Strip single trailing dot (`.`) if present (e.g. `mx1.corp.example.` $\rightarrow$ `mx1.corp.example`).
     2. IDNA 2008 / UTS #46 Punycode conversion: Convert non-ASCII Unicode characters to ASCII Punycode via `idna.encode(hostname, uts46=True).decode('ascii')`.
     3. Convert all ASCII characters to lowercase (`.lower()`).
2. **Phase 2: Strict Lexical and Semantic Calendar Validation**:
   Validation is performed on the normalized fields. If any field fails validation, processing aborts immediately:
   - Field 1 (`version`): Exactly `"V1"`.
   - Field 2 (`key_id`): Matches `^[a-zA-Z0-9_\-\.]{1,64}$`.
   - Field 3 (`email_sha256`): Exactly 64 lowercase hex ASCII characters matching `^[0-9a-f]{64}$`.
   - Field 4 (`acquisition_integration_id`): Matches `^[a-zA-Z0-9_\-\.]{1,128}$`.
   - Field 5 (`assertion_timestamp_utc`):
     - **Lexical Format**: Exact regex `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`.
     - **Semantic Calendar Validation**: Month must be 01..12; Day must be 01..days_in_month (accounting for leap-year February: 29 days in leap years, 28 in non-leap); Hour must be 00..23; Minute must be 00..59; Second must be 00..59.
     - **Leap Second Policy**: **Leap seconds (second = 60, e.g. `23:59:60Z`) are strictly REJECTED**.
   - Field 6 (`assertion_nonce`): Matches `^[a-zA-Z0-9_\-]{16,64}$`.
   - Field 7 (`boundary_mta_hostname`): Valid RFC 1123/5890 FQDN (1 to 253 characters; contains at least one dot; each label 1 to 63 chars matching `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`).
   - **Non-Empty Invariant**: **No field may be empty** ($L_k \ge 1$ for all $k \in \{1 \dots 7\}$). A length prefix `0:` is invalid and rejected.
3. **Phase 3: Framing-Only Canonical Serialization**:
   Each validated field $F_k$ is encoded into UTF-8 bytes $B_k$. Its length $L_k = \text{len}(B_k)$ is formatted as an ASCII decimal integer without leading zeros, followed by a colon (`:`), the raw bytes $B_k$, and a terminating newline (`\n`).

$$\text{Frame}(F_k) = \text{ASCII}(L_k) \;\|\; \texttt{":"} \;\|\; B_k \;\|\; \texttt{"\n"}$$

$$\text{canonical\_payload} = \texttt{b"HEADER\_PROVENANCE\_V1\n"} \;\|\; \sum_{k=1}^7 \text{Frame}(F_k)$$

```python
def validate_provenance_fields_for_signing(
    key_id: str,
    email_sha256: str,
    integration_id: str,
    timestamp_utc: str,
    nonce: str,
    mta_hostname: str,
) -> tuple[str, str, str, str, str, str, str]:
    """
    Perform strict normalization and multi-tier validation across all canonical framing fields.
    Returns normalized 7-tuple: (version, key_id, email_sha256, integration_id, timestamp_utc, nonce, hostname).
    Raises ValueError or FramingError on any structural, regex, or calendar discrepancy.
    """
    # 1. Normalization
    norm_version = "V1"
    norm_key_id = key_id.strip()
    norm_sha256 = email_sha256.strip().lower()
    norm_integration_id = integration_id.strip()
    norm_timestamp = timestamp_utc.strip()
    norm_nonce = nonce.strip()
    
    raw_host = mta_hostname.strip()
    if raw_host.endswith("."):
        raw_host = raw_host[:-1]
    try:
        norm_hostname = idna.encode(raw_host, uts46=True).decode("ascii").lower()
    except Exception as e:
        raise ValueError(f"Invalid IDNA/UTS46 hostname '{mta_hostname}': {e}")

    # 2. Field 2: key_id validation
    if not re.match(r"^[a-zA-Z0-9_\-\.]{1,64}$", norm_key_id):
        raise ValueError(f"Invalid key_id format: '{norm_key_id}'")

    # 3. Field 3: email_sha256 validation (exact 64 lowercase hex)
    if not re.match(r"^[0-9a-f]{64}$", norm_sha256):
        raise ValueError(f"Invalid email_sha256 format: '{norm_sha256}'")

    # 4. Field 4: integration_id validation
    if not re.match(r"^[a-zA-Z0-9_\-\.]{1,128}$", norm_integration_id):
        raise ValueError(f"Invalid integration_id format: '{norm_integration_id}'")

    # 5. Field 5: assertion_timestamp_utc lexical & semantic calendar validation
    if not re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", norm_timestamp):
        raise ValueError(f"Invalid ISO 8601 UTC timestamp lexical format: '{norm_timestamp}'")
    if norm_timestamp.endswith(":60Z"):
        raise ValueError("Leap seconds (second=60) are strictly rejected.")
    try:
        dt = datetime.fromisoformat(norm_timestamp.replace("Z", "+00:00"))
        if dt.tzinfo != timezone.utc:
            raise ValueError("Timestamp must be UTC.")
    except Exception as e:
        raise ValueError(f"Invalid semantic calendar timestamp '{norm_timestamp}': {e}")

    # 6. Field 6: assertion_nonce validation
    if not re.match(r"^[a-zA-Z0-9_\-]{16,64}$", norm_nonce):
        raise ValueError(f"Invalid assertion_nonce format: '{norm_nonce}'")

    # 7. Field 7: boundary_mta_hostname RFC 1123/5890 FQDN validation
    if len(norm_hostname) < 1 or len(norm_hostname) > 253 or "." not in norm_hostname:
        raise ValueError(f"Invalid boundary_mta_hostname length/structure: '{norm_hostname}'")
    for label in norm_hostname.split("."):
        if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", label):
            raise ValueError(f"Invalid FQDN label in hostname '{norm_hostname}': '{label}'")

    fields = (
        norm_version,
        norm_key_id,
        norm_sha256,
        norm_integration_id,
        norm_timestamp,
        norm_nonce,
        norm_hostname,
    )

    # 8. Non-empty invariant check on all fields
    for idx, f in enumerate(fields, 1):
        if not f:
            raise ValueError(f"Field {idx} cannot be empty in canonical provenance framing.")

    return fields


def serialize_canonical_provenance_payload(
    validated_fields: tuple[str, str, str, str, str, str, str]
) -> bytes:
    """
    Framing-only serializer: Encodes pre-validated canonical fields into length-prefixed bytes.
    PRECONDITION: validated_fields MUST be pre-validated by validate_provenance_fields_for_signing().
    """
    if len(validated_fields) != 7:
        raise ValueError(f"Expected exactly 7 canonical fields, got {len(validated_fields)}")

    parts = [b"HEADER_PROVENANCE_V1\n"]
    for f in validated_fields:
        raw_bytes = f.encode("utf-8")
        parts.append(f"{len(raw_bytes)}:".encode("ascii") + raw_bytes + b"\n")

    return b"".join(parts)
```

#### Strict Canonical Framing Parser Specification (Path B)
The verification parser reads canonical bytes strictly according to declared lengths and verifies structural integrity:
1. **Magic Header**: Read exactly 21 bytes. Verify bytes equal `b"HEADER_PROVENANCE_V1\n"`. If mismatch, raise `FramingError("Invalid magic header")`.
2. **Field Count**: The parser expects exactly 7 fields.
3. **Per-Field Parsing**: For each field $k \in \{1 \dots 7\}$:
   - Read ASCII digits until ASCII `:` (`0x3A`).
   - Disallow leading zeros (e.g. `05:` is rejected) and disallow empty lengths.
   - Enforce maximum length prefix digits ($\le 4$ digits; no field exceeds 253 bytes).
   - Parse integer $L_k$. Enforce $1 \le L_k \le 253$.
   - Read exactly $L_k$ raw bytes. If EOF is reached before $L_k$ bytes, raise `FramingError("Truncated payload")`.
   - Read exactly 1 byte. Must equal ASCII `\n` (`0x0A`). If not `\n`, raise `FramingError("Missing field newline terminator")`.
4. **EOF Verification**: After consuming the 7th field and its newline terminator, verify that no additional bytes remain. If trailing bytes exist, raise `FramingError("Unexpected trailing bytes")`.

#### Production Test Vectors and Negative Framing / Calendar Tests

- **Test Vector 1 (Valid Standard Production Record - Path B Signature)**:
  - version: `"V1"`
  - key_id: `"mta-key-2026a"`
  - email_sha256: `"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`
  - acquisition_integration_id: `"postfix-milter-01"`
  - assertion_timestamp_utc: `"2026-11-12T22:00:00Z"`
  - assertion_nonce: `"c4b8b6e276344a25a86d317498c56fa9"`
  - boundary_mta_hostname: `"mx1.corp.internal"`
  - Exact Serialized Bytes (212 bytes total):
    ```
    HEADER_PROVENANCE_V1\n
    2:V1\n
    12:mta-key-2026a\n
    64:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n
    17:postfix-milter-01\n
    20:2026-11-12T22:00:00Z\n
    32:c4b8b6e276344a25a86d317498c56fa9\n
    17:mx1.corp.internal\n
    ```

- **Test Vector 2 (Valid IDN Unicode Hostname - Path B Signature)**:
  - Input hostname: `"mail.münchen.example."` (trailing dot + German umlaut `ü`).
  - Normalized hostname: `"mail.xn--mnchen-3ya.example"` (Punycode converted via IDNA 2008 / UTS #46).
  - key_id: `"mta-key-2026b"`
  - Exact Serialized Bytes (223 bytes total):
    ```
    HEADER_PROVENANCE_V1\n
    2:V1\n
    12:mta-key-2026b\n
    64:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n
    17:postfix-milter-01\n
    20:2026-11-12T22:00:00Z\n
    32:c4b8b6e276344a25a86d317498c56fa9\n
    28:mail.xn--mnchen-3ya.example\n
    ```

- **Test Vector 3 (Valid Path A mTLS-Only Record)**:
  - Transport context: `client_authenticated=True, client_identity="postfix-milter-01"`.
  - Record: `key_id=None, integration_signature=None`.
  - All other fields present and valid (`email_sha256`, `assertion_timestamp_utc`, `assertion_nonce`, `boundary_mta_hostname`).
  - Result: Step 2 succeeds without constructing or evaluating signature framing.

- **Negative Framing and Calendar Tests (Isolated Negative Cases)**:
  - **Negative Framing 1 (Length Mismatch)**: Payload declares length `10:abc\n` $\rightarrow$ fails with `FramingError("Missing field newline terminator")`.
  - **Negative Framing 2 (Truncated Stream)**: Stream ends mid-field $\rightarrow$ fails with `FramingError("Truncated payload")`.
  - **Negative Framing 3 (Unexpected Trailing Garbage)**: Stream contains extra bytes after 7th field $\rightarrow$ fails with `FramingError("Unexpected trailing bytes")`.
  - **Negative Framing 4 (Empty Field Rejection)**: Payload contains `0:\n` $\rightarrow$ rejected because all fields require $L_k \ge 1$.
  - **Negative Framing 5 (Leading Zero in Prefix)**: Payload contains `02:V1\n` $\rightarrow$ rejected by length prefix parser.
  - **Negative Calendar 1 (Invalid Day/Month)**: Timestamp `2026-99-99T22:00:00Z` $\rightarrow$ fails semantic calendar validation (`malformed_timestamp_calendar`).
  - **Negative Calendar 2 (Invalid February Day)**: Timestamp `2026-02-30T22:00:00Z` $\rightarrow$ fails semantic calendar validation (`malformed_timestamp_calendar`).
  - **Negative Calendar 3 (Invalid Time)**: Timestamp `2026-11-12T25:00:00Z` or `2026-11-12T22:60:00Z` $\rightarrow$ fails semantic calendar validation.
  - **Negative Calendar 4 (Leap Second Rejection)**: Timestamp `2026-11-12T22:00:60Z` $\rightarrow$ strictly rejected (`leap_second_rejected`).

---

### 6.5 Authoritative Defined Decision Cases

The table below specifies the authoritative set of defined deterministic decisions across operational, cryptographic, configuration, and security boundary conditions. Any condition not explicitly matching a promotion case fails closed to `UNVERIFIED`:

| Case # | Configuration / Assertion State | Issuer Auth (Step 2) | Freshness / Skew (Step 4) | Nonce Store (Step 5) | SHA-256 Binding (Step 6) | Boundary Consistency (Step 7) | `enforce_check` | Hop 0 Trust Outcome | Upstream Hops (1..N) | Logged Audit Status |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|---|
| **1** | Offline / No Policy (`policy is None`) | Absent | N/A | Not Touched | N/A | N/A | False | **UNVERIFIED** | **UNVERIFIED** | Default offline analysis. |
| **2** | Policy supplied, record absent | Absent | N/A | Not Touched | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `provenance_missing`. |
| **3** | **Path A (Pure mTLS)**: `key_id=None, sig=None` | **Valid mTLS** | In Window | Reserved | Matched | Matched | True | **TRUSTED_RECEIVER** | **UNVERIFIED** | mTLS success without signature. |
| **4** | **Path B (Pure Signature)**: Valid key & signature | **Valid Sig** | In Window | Reserved | Matched | Matched | True | **TRUSTED_RECEIVER** | **UNVERIFIED** | Cryptographic signature success. |
| **5** | Partial Credentials (mTLS): Missing signature | **Failed** | N/A | **Not Touched** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `partial_credentials_missing_signature`. |
| **6** | Partial Credentials (mTLS): Missing key ID | **Failed** | N/A | **Not Touched** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `partial_credentials_missing_key_id`. |
| **7** | **Dual Auth Mode**: Valid mTLS & valid signature | **Valid Both**| In Window | Reserved | Matched | Matched | True | **TRUSTED_RECEIVER** | **UNVERIFIED** | `dual_auth_success`. |
| **8** | Dual Auth Mode: Valid mTLS but invalid signature | **Failed** | N/A | **Not Touched** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `dual_auth_signature_invalid`. |
| **9** | Unauthenticated provenance (no mTLS, no sig) | **Failed** | N/A | **Not Touched** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `unauthenticated_provenance`. |
| **10**| Path B: Missing `key_id` in signed assertion | **Failed** | N/A | **Not Touched** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `missing_key_id`. |
| **11**| Path B: Unknown `key_id` not found in keyring | **Failed** | N/A | **Not Touched** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `unknown_key_id`. |
| **12**| Path B: Revoked `key_id` in keyring | **Failed** | N/A | **Not Touched** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `revoked_key_id`. |
| **13**| Path B: Expired `key_id` in keyring | **Failed** | N/A | **Not Touched** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `expired_key_id`. |
| **14**| Path B: Ambiguous key selection (conflicts) | **Failed** | N/A | **Not Touched** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `ambiguous_key_selection`. |
| **15**| Path B: Key rotation (matches active key B) | **Valid Sig** | In Window | Reserved | Matched | Matched | True | **TRUSTED_RECEIVER** | **UNVERIFIED** | Rotation success. |
| **16**| Unauthorized integration ID | **Failed** | N/A | **Not Touched** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `unauthorized_integration_id`. |
| **17**| Timestamp calendar failure (`2026-02-30`) | Step 1 Fail | N/A | **Not Touched** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `malformed_timestamp_calendar`. |
| **18**| Timestamp leap second rejection (`22:00:60Z`)| Step 1 Fail | N/A | **Not Touched** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `leap_second_rejected`. |
| **19**| Future timestamp beyond skew limit ($> +60$s) | Valid | **Failed** ($> +60$s) | **Not Touched** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `future_timestamp_skew_exceeded`. |
| **20**| Future timestamp within skew ($\le +60$s) | Valid | **Valid** ($+30$s) | Reserved | Matched | Matched | True | **TRUSTED_RECEIVER** | **UNVERIFIED** | Skew tolerated. |
| **21**| Assertion expired ($> 300$s old) | Valid | **Failed** ($> 300$s) | **Not Touched** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `assertion_expired`. |
| **22**| Replayed nonce in distributed store | Valid | In Window | **Collision** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `replay_detected`. |
| **23**| Distributed replay store outage / timeout | Valid | In Window | **Error** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `replay_store_unavailable`. |
| **24**| Store failover with uncertain reservation | Valid | In Window | **Uncertain** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `replay_state_uncertain`. |
| **25**| Store early memory eviction / lost key | Valid | In Window | **Lost Key** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `replay_store_eviction_loss`. |
| **26**| Replay store post-crash recovery drain ($T \le 361$s monotonic) | Valid | In Window | **Drain Active** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `replay_store_recovery_drain`. |
| **27**| Evicted nonce replayed after TTL expiration | Valid | **Failed** ($> 300$s) | **Not Touched** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `assertion_expired` (Step 4 block). |
| **28**| SHA-256 raw email digest mismatch | Valid | In Window | Reserved | **Mismatch** | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `digest_mismatch`. |
| **29**| Malformed boundary hostname (syntax/IDNA fail) | Valid | In Window | Reserved | Matched | **Malformed** | True | **UNVERIFIED** | **UNVERIFIED** | `invalid_boundary_hostname`. |
| **30**| Malformed canonical framing (length mismatch) | **Failed** | N/A | **Not Touched** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `framing_malformed_prefix`. |
| **31**| Framing contains unexpected trailing bytes | **Failed** | N/A | **Not Touched** | N/A | N/A | True | **UNVERIFIED** | **UNVERIFIED** | `framing_trailing_bytes`. |
| **32**| Ambiguous Received chronological ordering | Valid | In Window | Reserved | Matched | **Skewed** | True | **UNVERIFIED** | **UNVERIFIED** | `ambiguous_received_ordering`. |
| **33**| Malformed boundary hop in email | Valid | In Window | Reserved | Matched | **Malformed** | True | **UNVERIFIED** | **UNVERIFIED** | `malformed_boundary_hop`. |
| **34**| Master enforcement disabled (`enforce=False`) | Valid | In Window | Reserved | Matched | Matched | **False** | **UNVERIFIED** | **UNVERIFIED** | **Trust promotion suppressed**. |
| **35**| Both Configured (`require_both=True`): Both match | Valid | In Window | Reserved | Matched | Host & IP match | True | **TRUSTED_RECEIVER** | **UNVERIFIED** | Strict dual check passed. |
| **36**| Both Configured (`require_both=True`): IP missing | Valid | In Window | Reserved | Matched | Host match, IP missing | True | **UNVERIFIED** | **UNVERIFIED** | `missing_ip_in_hop`. |
| **37**| Both Configured (`require_both=True`): Host missing| Valid | In Window | Reserved | Matched | IP match, Host missing | True | **UNVERIFIED** | **UNVERIFIED** | `missing_hostname_in_hop`. |
| **38**| Both Configured (`require_both=True`): IP mismatch | Valid | In Window | Reserved | Matched | Host match, IP mismatch | True | **UNVERIFIED** | **UNVERIFIED** | `boundary_ip_mismatch`. |
| **39**| Both Configured (`require_both=True`): Host mismatch| Valid | In Window | Reserved | Matched | IP match, Host mismatch | True | **UNVERIFIED** | **UNVERIFIED** | `boundary_hostname_mismatch`. |
| **40**| Relaxed (`require_both=False`, P1): Both match | Valid | In Window | Reserved | Matched | Host & IP match | True | **TRUSTED_RECEIVER** | **UNVERIFIED** | `trusted_boundary_matched`. |
| **41**| Relaxed (`require_both=False`, P2): Host match, IP missing | Valid | In Window | Reserved | Matched | Host match, IP missing | True | **TRUSTED_RECEIVER** | **UNVERIFIED** | `trusted_boundary_matched`. |
| **42**| Relaxed (`require_both=False`, P3): IP match, Host missing | Valid | In Window | Reserved | Matched | IP match, Host missing | True | **TRUSTED_RECEIVER** | **UNVERIFIED** | `trusted_boundary_matched`. |
| **43**| Relaxed (`require_both=False`, P4): Host match, IP mismatch | Valid | In Window | Reserved | Matched | Host match, IP mismatch | True | **UNVERIFIED** | **UNVERIFIED** | `boundary_ip_contradiction`. |
| **44**| Relaxed (`require_both=False`, P5): IP match, Host mismatch | Valid | In Window | Reserved | Matched | IP match, Host mismatch | True | **UNVERIFIED** | **UNVERIFIED** | `boundary_hostname_contradiction`. |
| **45**| Relaxed (`require_both=False`, P6): Both mismatch | Valid | In Window | Reserved | Matched | Both mismatch | True | **UNVERIFIED** | **UNVERIFIED** | `boundary_mismatch`. |
| **46**| Relaxed (`require_both=False`, P7): Both missing | Valid | In Window | Reserved | Matched | Both tokens missing | True | **UNVERIFIED** | **UNVERIFIED** | `missing_boundary_tokens`. |
| **47**| Host-Only Configured: Host matches | Valid | In Window | Reserved | Matched | Host matches | True | **TRUSTED_RECEIVER** | **UNVERIFIED** | Single host check passed. |
| **48**| Host-Only Configured: Host mismatches or missing | Valid | In Window | Reserved | Matched | Host absent/mismatch | True | **UNVERIFIED** | **UNVERIFIED** | `boundary_hostname_mismatch`. |
| **49**| IP-Only Configured: IP matches CIDR | Valid | In Window | Reserved | Matched | IP matches CIDR | True | **TRUSTED_RECEIVER** | **UNVERIFIED** | Single IP check passed. |
| **50**| IP-Only Configured: IP mismatches or missing | Valid | In Window | Reserved | Matched | IP absent/mismatch | True | **UNVERIFIED** | **UNVERIFIED** | `boundary_ip_mismatch`. |

> [!IMPORTANT]
> **Consolidated Authoritative Semantics of `enforce_boundary_check=False`**:
> Disabling boundary checking (`enforce_boundary_check=False`, Case 29) means **trust promotion is completely suppressed**. Every Received hop remains `TrustLevel.UNVERIFIED`. It **never** means "trust hop 0 without verification". This fail-closed invariant guarantees that unverified messages are never promoted when boundary validation is bypassed or unconfigured.

---

### 6.6 Granular IP Address Classification and Feature Mapping
The implementation parses IP literals from bracketed/parenthesized tokens in Received clauses and evaluates them against exact RFC standards using Python's standard library `ipaddress` module.

> [!IMPORTANT]
> **Python Runtime Specification and `ipaddress` Behavior**:
> Supported Runtime: **Python 3.11+**.
> - In Python 3.11+, Carrier-Grade NAT (`100.64.0.0/10`, RFC 6598) returns `is_private=False`, `is_global=False`, and `is_reserved=False`.
> - Python's `is_private` returns `True` for RFC 1918, RFC 4193, loopback, link-local, documentation, and reserved ranges.
> - Therefore, the implementation **does not rely solely on `ip.is_private` or `ip.is_global`**. It evaluates specific network categories in the prioritized order defined below.
> - **Scope Limitation**: The algorithm explicitly identifies standard RFC 6890 special-purpose assignments. It cannot claim exhaustive coverage of all possible future or unclassified IANA allocations without external dynamic updates.

#### IP Classification Algorithm (Python 3.11+)
```python
def classify_ip_address(ip_str: str) -> str:
    """
    Classify an IP string into granular RFC categories in strict priority order.
    Returns: 'loopback', 'link_local', 'multicast', 'cgnat', 'documentation',
             'special_purpose', 'rfc1918', 'rfc4193', or 'global_routable'.
    """
    ip = ipaddress.ip_address(ip_str.strip())
    
    # 1. Loopback (RFC 1122 / RFC 4291)
    if ip.is_loopback:
        return "loopback"
        
    # 2. Link-Local (RFC 3927 / RFC 4291)
    if ip.is_link_local:
        return "link_local"
        
    # 3. Multicast (RFC 5771 / RFC 4291)
    if ip.is_multicast:
        return "multicast"
        
    # 4. Carrier-Grade NAT (RFC 6598 - Distinct from RFC 1918)
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return "cgnat"

    # 5. Documentation Ranges (RFC 5737 / RFC 3849)
    if ip.version == 4:
        if (ip in ipaddress.ip_network("192.0.2.0/24") or        # TEST-NET-1
            ip in ipaddress.ip_network("198.51.100.0/24") or     # TEST-NET-2
            ip in ipaddress.ip_network("203.0.113.0/24")):       # TEST-NET-3
            return "documentation"
    elif ip.version == 6:
        if ip in ipaddress.ip_network("2001:db8::/32"):          # Doc IPv6
            return "documentation"

    # 6. Special-Purpose / Reserved / Unspecified (RFC 6890 / RFC 1112)
    if ip.is_reserved or ip.is_unspecified:
        return "special_purpose"
    if ip.version == 4:
        if (ip in ipaddress.ip_network("0.0.0.0/8") or           # This network
            ip in ipaddress.ip_network("192.0.0.0/24") or        # IETF Protocol
            ip in ipaddress.ip_network("198.18.0.0/15") or       # Benchmark
            ip in ipaddress.ip_network("240.0.0.0/4")):          # Future use
            return "special_purpose"

    # 7. RFC 1918 Private IPv4
    if ip.version == 4:
        if (ip in ipaddress.ip_network("10.0.0.0/8") or
            ip in ipaddress.ip_network("172.16.0.0/12") or
            ip in ipaddress.ip_network("192.168.0.0/16")):
            return "rfc1918"
            
    # 8. RFC 4193 Unique Local IPv6 (ULA)
    if ip.version == 6 and ip in ipaddress.ip_network("fc00::/7"):
        return "rfc4193"
        
    # 9. Global Public Routable (Strict Unicast Fallback)
    if getattr(ip, "is_global", False):
        return "global_routable"
        
    return "special_purpose"
```

#### IP Category-to-Feature Mapping Table

| Classification Category | Representative Test Vectors | Output Feature Triggered | Included in `has_private_ip`? | Included in `has_special_ip`? | Retained in Evidence? |
|---|---|---|:---:|:---:|:---:|
| **`rfc1918`** | `10.0.0.1`, `172.16.0.1`, `192.168.1.1` | `has_private_ip_in_external_hop = True` | **YES** | NO | YES |
| **`rfc4193`** | `fc00::1`, `fd00::1` | `has_private_ip_in_external_hop = True` | **YES** | NO | YES |
| **`loopback`** | `127.0.0.1`, `::1` | `has_loopback_ip_in_external_hop = True` | NO | NO | YES |
| **`link_local`** | `169.254.1.1`, `fe80::1` | `has_link_local_ip_in_external_hop = True` | NO | NO | YES |
| **`cgnat`** | `100.64.0.1` (RFC 6598) | `has_special_ip_in_external_hop = True` | NO | **YES** | YES |
| **`documentation`** | `192.0.2.1`, `2001:db8::1` | `has_special_ip_in_external_hop = True` | NO | **YES** | YES |
| **`multicast`** | `224.0.0.1`, `ff02::1` | `has_special_ip_in_external_hop = True` | NO | **YES** | YES |
| **`special_purpose`** | `0.0.0.0/8`, `192.0.0.1`, `240.0.0.1` | `has_special_ip_in_external_hop = True` | NO | **YES** | YES |
| **`global_routable`** | `8.8.8.8`, `2606:2800:220:1::` | None (no anomaly flag triggered) | NO | NO | NO |

---

## 7. Proposed Pydantic Output Schema

The Header Agent defines its output contracts using Pydantic v2. These models reside in `app/schemas/header_agent_schema.py` and are strictly decoupled from `EmailData`.

```python
"""
header_agent_schema.py
----------------------
Pydantic v2 data contract for Header Agent outputs.

Architecture:
- CANONICAL_HEADER_FEATURE_NAMES: Machine-auditable 45-feature literal type.
- HeaderFeatures: Sanitized Tier 3 feature vector (canonical 45 features).
- HeaderFeatureAvailability: Comprehensive per-feature availability manifest.
- HeaderEvidence: Tier 2 forensic evidence and audit trails (strictly quarantined from ML).
- HeaderRiskAssessment: Optional layer for calibrated base classifier predictions.
- HeaderAgentOutput: Complete serializable agent output container.
"""

from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, Field, model_validator
from app.schemas.email_schema import AuthStatus, VerificationStatus

# Canonical 45-feature registry literal type (strictly continuous 1..45)
CANONICAL_HEADER_FEATURE_NAMES = Literal[
    # Category A: Sender/Recipient Alignment (13)
    "from_present",
    "from_address_count",
    "reply_to_present",
    "return_path_present",
    "from_reply_to_domain_mismatch",
    "from_return_path_domain_mismatch",
    "display_name_contains_email",
    "display_name_domain_mismatch",
    "recipient_count_to",
    "recipient_count_cc",
    "undisclosed_recipients",
    "to_empty_or_missing",
    "from_syntax_valid",
    # Category B: Routing and Transport Structure (10)
    "received_hop_count",
    "has_private_ip_in_external_hop",
    "has_loopback_ip_in_external_hop",
    "has_link_local_ip_in_external_hop",
    "has_special_ip_in_external_hop",
    "received_syntax_malformed_count",
    "missing_received_headers",
    "transit_delay_seconds",
    "transit_delay_unavailable",
    "hop_count_anomaly",
    # Category C: Authentication Claims (13)
    "spf_status",
    "dkim_status",
    "dmarc_status",
    "spf_claim_count",
    "dkim_claim_count",
    "dmarc_claim_count",
    "has_conflicting_spf",
    "has_conflicting_dkim",
    "has_conflicting_dmarc",
    "dkim_signature_header_present",
    "dkim_signature_present_without_pass",
    "authserv_id_count",
    "authserv_id_inconsistent",
    # Category D: RFC 5322 Metadata & Structural Compliance (9)
    "message_id_present",
    "message_id_valid_syntax",
    "message_id_domain_mismatch",
    "mime_version_present",
    "mime_version_valid",
    "has_subject_header",
    "subject_length",
    "content_type_present",
    "content_type_is_multipart",
]


# ---------------------------------------------------------------------------
# 1. Feature Availability / Missingness Manifest
# ---------------------------------------------------------------------------

class HeaderFeatureAvailability(BaseModel):
    """
    Explicit missingness manifest tracking availability across all conditionally
    evaluable features and prerequisite inputs. Downstream models consume these
    flags to prevent confounding missing evidence with negative evidence.
    """
    # Normalized Value Presence Flags
    avail_from_present: bool = Field(description="True if normalized From address value is present.")
    avail_reply_to_present: bool = Field(description="True if normalized Reply-To address value is present.")
    avail_return_path_present: bool = Field(description="True if normalized Return-Path address value is present.")
    avail_to_present: bool = Field(description="True if To recipient list is evaluable (False under current contract if empty).")
    avail_cc_present: bool = Field(description="True if CC recipient list is evaluable (False under current contract if empty).")
    avail_received_hops: bool = Field(description="True if >= 1 Received header is present.")
    avail_auth_claims: bool = Field(description="True if >= 1 authentication claim is extracted.")
    avail_message_id_present: bool = Field(description="True if Message-ID header is present and non-empty.")
    avail_mime_version_present: bool = Field(description="True if MIME-Version header physically exists.")
    avail_subject_present: bool = Field(description="True if Subject header physically exists.")
    avail_content_type_present: bool = Field(description="True if Content-Type header physically exists.")

    # Parsing Success and Syntax Flags
    avail_from_parsed: bool = Field(description="True if From header was successfully parsed into address structure.")
    avail_from_syntax: bool = Field(description="True if From header content was evaluable for RFC 5322 syntax.")
    avail_reply_to_parsed: bool = Field(description="True if Reply-To was successfully parsed.")
    avail_return_path_parsed: bool = Field(description="True if Return-Path was successfully parsed.")
    avail_to_parsed: bool = Field(description="True if To was successfully parsed/evaluated.")
    avail_cc_parsed: bool = Field(description="True if CC was successfully parsed/evaluated.")

    # Conditionally Evaluable Feature Availability
    avail_from_reply_to_domain_mismatch: bool = Field(
        description="True if both From and Reply-To domains available for comparison.",
    )
    avail_from_return_path_domain_mismatch: bool = Field(
        description="True if both From and Return-Path domains available for comparison.",
    )
    avail_display_name_domain_mismatch: bool = Field(
        description="True if display name embeds an email address available for domain comparison.",
    )
    avail_undisclosed_recipients: bool = Field(
        description="True ONLY if raw To header input is available (False under current contract; quarantined).",
    )
    avail_to_empty_or_missing: bool = Field(
        description="True ONLY if raw To header input is available (False under current contract; quarantined).",
    )
    avail_transit_delay: bool = Field(
        description="True if >= 2 Received headers have valid RFC 2822 timestamps (quarantined).",
    )
    avail_spf_status: bool = Field(
        description="True if SPF claim was evaluated (status not in MISSING, UNAVAILABLE).",
    )
    avail_dkim_status: bool = Field(
        description="True if DKIM claim was evaluated (status not in MISSING, UNAVAILABLE).",
    )
    avail_dmarc_status: bool = Field(
        description="True if DMARC claim was evaluated (status not in MISSING, UNAVAILABLE).",
    )
    avail_message_id_valid_syntax: bool = Field(
        description="True if Message-ID is present and evaluable for RFC syntax.",
    )
    avail_message_id_domain_mismatch: bool = Field(
        description="True if both Message-ID and From domains available for comparison.",
    )
    avail_mime_version_valid: bool = Field(
        description="True if MIME-Version header is present and evaluable.",
    )
    avail_content_type_is_multipart: bool = Field(
        description="True if Content-Type header is present and evaluable for multipart.",
    )

    # Descriptive Domain Completeness Summaries [0.0, 1.0] (Descriptive conventions only)
    completeness_identity: float = Field(ge=0.0, le=1.0)
    completeness_routing: float = Field(ge=0.0, le=1.0)
    completeness_auth: float = Field(ge=0.0, le=1.0)
    completeness_metadata: float = Field(ge=0.0, le=1.0)
    completeness_total: float = Field(ge=0.0, le=1.0)

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# 2. Tier 3: Sanitized Predictive Features (Canonical 45 Features)
# ---------------------------------------------------------------------------

class HeaderFeatures(BaseModel):
    """
    Approved, leakage-free feature representation for the Header Agent.
    Strictly forbids raw text, scanner tags, absolute dates, hostnames, and corpus IDs.
    Total features: exactly 45 (41 active predictive, 4 quarantined/inactive).
    """

    # Category A: Sender, Recipient, and Identity Alignment (13 Features)
    from_present: bool = Field(
        description="True if normalized From address is present and non-empty (headers.from_address is not None).",
    )
    from_address_count: Optional[int] = Field(
        default=None,
        ge=0,
        description="Count of mailbox addresses in From; None if absent or unparseable under current contract; 0 if empty.",
    )
    reply_to_present: bool = Field(
        description="True if normalized Reply-To is present and non-empty (headers.reply_to is not None).",
    )
    return_path_present: bool = Field(
        description="True if normalized Return-Path is present and non-empty (headers.return_path is not None).",
    )
    from_reply_to_domain_mismatch: Optional[bool] = Field(
        default=None,
        description="True if From and Reply-To domains differ; None if either absent or unparseable.",
    )
    from_return_path_domain_mismatch: Optional[bool] = Field(
        default=None,
        description="True if From and Return-Path domains differ; None if either absent or unparseable.",
    )
    display_name_contains_email: bool = Field(
        description="True if From display name embeds an RFC 5322 email address string.",
    )
    display_name_domain_mismatch: Optional[bool] = Field(
        default=None,
        description="True if display name embedded domain differs from actual From domain; None if unparseable.",
    )
    recipient_count_to: Optional[int] = Field(
        default=None,
        ge=0,
        description="Address count in To; None if headers.to == [] under current contract; N if parsed >= 1.",
    )
    recipient_count_cc: Optional[int] = Field(
        default=None,
        ge=0,
        description="Address count in CC; None if headers.cc == [] under current contract; N if parsed >= 1.",
    )
    undisclosed_recipients: Optional[bool] = Field(
        default=None,
        description="True if To explicitly contains group syntax tokens; None if raw To is unavailable. Inactive / Quarantined.",
    )
    to_empty_or_missing: Optional[bool] = Field(
        default=None,
        description="True if To physically empty; None if raw To is unavailable. Inactive / Quarantined.",
    )
    from_syntax_valid: Optional[bool] = Field(
        default=None,
        description="True if From conforms to RFC 5322 addr-spec; False if invalid; None if absent.",
    )

    # Category B: Routing and Transport Structure (10 Features)
    received_hop_count: int = Field(ge=0, description="Total count of Received header hops.")
    has_private_ip_in_external_hop: bool = Field(
        description="True if RFC 1918 IPv4 or RFC 4193 IPv6 detected in intermediate transit hops.",
    )
    has_loopback_ip_in_external_hop: bool = Field(
        description="True if loopback IP detected in intermediate transit hops.",
    )
    has_link_local_ip_in_external_hop: bool = Field(
        description="True if link-local IP detected in intermediate transit hops.",
    )
    has_special_ip_in_external_hop: bool = Field(
        description="True if CGNAT, documentation, multicast, or reserved IP detected in intermediate hops.",
    )
    received_syntax_malformed_count: int = Field(
        ge=0,
        description="Count of Received headers failing RFC structural token parsing.",
    )
    missing_received_headers: bool = Field(
        description="True if Received header hop count is zero.",
    )
    transit_delay_seconds: Optional[float] = Field(
        default=None,
        description="Relative seconds elapsed between earliest and latest hop (max 30 days). Exploratory / Quarantined.",
    )
    transit_delay_unavailable: bool = Field(
        description="True if transit delay could not be reliably calculated. Exploratory / Quarantined.",
    )
    hop_count_anomaly: bool = Field(
        description="True if hop count is 0 or exceeds 15 hops.",
    )

    # Category C: Authentication Claims (13 Features)
    spf_status: AuthStatus = Field(description="Consolidated receiver-reported SPF claim status.")
    dkim_status: AuthStatus = Field(description="Consolidated receiver-reported DKIM claim status.")
    dmarc_status: AuthStatus = Field(description="Consolidated receiver-reported DMARC claim status.")
    spf_claim_count: int = Field(ge=0, description="Number of reported SPF claims extracted.")
    dkim_claim_count: int = Field(ge=0, description="Number of reported DKIM claims extracted.")
    dmarc_claim_count: int = Field(ge=0, description="Number of reported DMARC claims extracted.")
    has_conflicting_spf: bool = Field(description="True if multiple SPF claims disagree.")
    has_conflicting_dkim: bool = Field(description="True if multiple DKIM claims disagree.")
    has_conflicting_dmarc: bool = Field(description="True if multiple DMARC claims disagree.")
    dkim_signature_header_present: bool = Field(
        description="True if DKIM-Signature header exists in message.",
    )
    dkim_signature_present_without_pass: bool = Field(
        description="True if DKIM-Signature exists but reported status is not pass.",
    )
    authserv_id_count: int = Field(ge=0, description="Distinct reporting authserv-ids found.")
    authserv_id_inconsistent: bool = Field(
        description="True if multiple Authentication-Results report conflicting authserv-ids.",
    )

    # Category D: RFC 5322 Metadata & Structural Compliance (9 Features)
    message_id_present: bool = Field(description="True if Message-ID header is present and non-empty.")
    message_id_valid_syntax: Optional[bool] = Field(
        default=None,
        description="True if Message-ID conforms to <id-left@id-right>; None if absent or empty.",
    )
    message_id_domain_mismatch: Optional[bool] = Field(
        default=None,
        description="True if Message-ID domain differs from From domain; None if absent or unparseable.",
    )
    mime_version_present: bool = Field(description="True if MIME-Version header is present.")
    mime_version_valid: Optional[bool] = Field(
        default=None,
        description="True if MIME-Version equals '1.0'; None if absent.",
    )
    has_subject_header: bool = Field(description="True if Subject header is present.")
    subject_length: int = Field(ge=0, description="Character length of decoded Subject header.")
    content_type_present: bool = Field(description="True if Content-Type header is present.")
    content_type_is_multipart: Optional[bool] = Field(
        default=None,
        description="True if Content-Type starts with 'multipart/'; None if absent.",
    )

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# 3. Tier 2: Forensic Evidence & Audit Trails (Quarantined from ML)
# ---------------------------------------------------------------------------

class HeaderEvidenceItem(BaseModel):
    """
    Forensic evidence trace linking an observed anomaly or feature value
    to its raw header origin for auditability and explanation.
    """
    feature_name: CANONICAL_HEADER_FEATURE_NAMES = Field(
        description="The canonical 45-feature identifier this evidence supports.",
    )
    header_name: str = Field(
        description="RFC 5322 header name (e.g. 'From', 'Reply-To', 'Received', 'Authentication-Results').",
    )
    header_index: Optional[int] = Field(
        default=None,
        ge=0,
        description="0-indexed position within repeated headers of the same type; 0 for single headers; None if absent.",
    )
    claim_index: Optional[int] = Field(
        default=None,
        ge=0,
        description="0-indexed position of the claim in AuthenticationMetadata.claims; None if not auth evidence.",
    )
    verification_status: VerificationStatus = Field(
        default=VerificationStatus.UNVERIFIED,
        description="Receiver trust verification status (always UNVERIFIED in offline analysis).",
    )
    description: str = Field(
        max_length=500,
        description="Safe, bounded human-readable explanation of the observed evidence.",
    )
    raw_snippet_bounded: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Preprocessed, sanitized verbatim excerpt (max 256 chars, control characters escaped). Display only; not verified evidence.",
    )

    model_config = {"extra": "forbid"}


class HeaderEvidence(BaseModel):
    """Container for audit evidence and forensic traces supporting feature values."""
    evidence_items: list[HeaderEvidenceItem] = Field(
        default_factory=list,
        max_length=100,
        description="Traceable evidence items (validated to max 100).",
    )
    parsed_authserv_ids: list[str] = Field(
        default_factory=list,
        max_length=50,
        description="Distinct authserv-ids found across Authentication-Results (validated to max 50).",
    )
    detected_anomalous_ips: list[str] = Field(
        default_factory=list,
        max_length=50,
        description="Bounded list of anomalous IPs found in transit hops (validated to max 50).",
    )
    observed_anomalies: list[str] = Field(
        default_factory=list,
        max_length=100,
        description="Human-readable anomaly descriptions (validated to max 100).",
    )

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# 4. Optional Agent Risk & Uncertainty Assessment (Populated by Base Classifier)
# ---------------------------------------------------------------------------

class HeaderRiskAssessment(BaseModel):
    """
    Quantified belief, margin, and uncertainty emitted ONLY when a trained
    Header Base Classifier is attached (Layer 2). None during Layer 1 feature extraction.
    """
    calibrated_phishing_probability: float = Field(
        ge=0.0,
        le=1.0,
        description="Calibrated header-based phishing probability p_h in [0.0, 1.0].",
    )
    decision_margin: float = Field(
        ge=0.0,
        le=1.0,
        description="Distance-from-boundary certainty proxy: 2 * abs(p_h - 0.5).",
    )
    calibrated_confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Empirical prediction confidence derived from validation calibration bins. None until operational definition exists.",
    )
    epistemic_uncertainty: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Model uncertainty estimated via ensemble or bootstrap fold variance.",
    )
    aleatoric_uncertainty: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Data ambiguity arising from conflicting claims or missing headers.",
    )
    abstain: bool = Field(
        default=False,
        description="True if validation-tuned abstention policy triggers.",
    )

    @model_validator(mode="after")
    def validate_decision_margin_formula(self) -> "HeaderRiskAssessment":
        """Validate mathematical consistency between probability and decision margin."""
        expected_margin = 2.0 * abs(self.calibrated_phishing_probability - 0.5)
        if abs(self.decision_margin - expected_margin) > 1e-5:
            raise ValueError(
                f"decision_margin ({self.decision_margin}) must equal 2 * |p_h - 0.5| ({expected_margin})"
            )
        return self

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# 5. Top-Level Agent Contract
# ---------------------------------------------------------------------------

class HeaderAgentOutput(BaseModel):
    """
    Complete output payload of the Header Agent.
    Serialized and passed to the Evidence Aggregation Layer.
    """
    agent_name: str = Field(default="HeaderAgent", description="Identifier of the emitting agent.")
    agent_version: str = Field(default="1.0.0", description="Semantic version of agent specification.")
    email_id: str = Field(description="Unique email identifier matching EmailData.email_id.")
    features: HeaderFeatures = Field(description="Sanitized Tier 3 feature vector (canonical 45 features).")
    availability: HeaderFeatureAvailability = Field(description="Per-feature missingness manifest.")
    evidence: HeaderEvidence = Field(description="Tier 2 forensic evidence and audit trails.")
    risk_assessment: Optional[HeaderRiskAssessment] = Field(
        default=None,
        description="Populated only when a trained Layer 2 base model is attached.",
    )
    warnings: list[str] = Field(default_factory=list, description="Non-fatal data quality warnings.")
    limitations: list[str] = Field(
        default_factory=list,
        description="Explicit operational caveats (e.g. offline unverified claims).",
    )

    model_config = {"extra": "forbid"}
```

---

## 8. Model Preprocessing Pipelines and Input Dimensionality

When training and evaluating supervised models in Layer 2 (Experimental Baseline Model 2) and Layer 3 (Meta-Classifier), raw features from `HeaderFeatures` and `HeaderFeatureAvailability` are transformed through strictly isolated preprocessing pipelines.

### 8.1 Active Feature Whitelist Selection
- **Active Predictive Features**: Exactly **41 features** are selected in canonical order:
  - Category A: Features 1..10, 13 (11 features; Features 11 and 12 quarantined).
  - Category B: Features 14..20, 23 (8 features; Features 21 and 22 quarantined).
  - Category C: Features 24..36 (13 features).
  - Category D: Features 37..45 (9 features).
- **Quarantined Features Excluded**:
  - Feature 11 (`undisclosed_recipients`): Quarantined pending `to_raw`.
  - Feature 12 (`to_empty_or_missing`): Quarantined pending `to_raw`.
  - Feature 21 (`transit_delay_seconds`): Quarantined exploratory.
  - Feature 22 (`transit_delay_unavailable`): Quarantined exploratory.

### 8.2 Missingness Mapping Table
Across the 45 canonical features, exactly **14 features** are nullable (`Optional[int]`, `Optional[float]`, or `Optional[bool]`). Three of these are quarantined, leaving exactly **11 active nullable features** that require missingness tracking:

| # | Canonical Feature Identifier | Type | Predictive Status | Missingness Indicator | Training-Fold Imputation Rule (Linear Pipeline) |
|---|---|:---:|:---:|---|---|
| 2 | `from_address_count` | `Optional[int]` | Active | $m_1$: `m_from_address_count` | Imputed to Training-Fold Median |
| 5 | `from_reply_to_domain_mismatch` | `Optional[bool]` | Active | $m_2$: `m_from_reply_to_domain_mismatch` | Imputed to `0.0` (False) |
| 6 | `from_return_path_domain_mismatch` | `Optional[bool]` | Active | $m_3$: `m_from_return_path_domain_mismatch` | Imputed to `0.0` (False) |
| 8 | `display_name_domain_mismatch` | `Optional[bool]` | Active | $m_4$: `m_display_name_domain_mismatch` | Imputed to `0.0` (False) |
| 9 | `recipient_count_to` | `Optional[int]` | Active | $m_5$: `m_recipient_count_to` | Imputed to Training-Fold Median |
| 10 | `recipient_count_cc` | `Optional[int]` | Active | $m_6$: `m_recipient_count_cc` | Imputed to Training-Fold Median |
| 11 | `undisclosed_recipients` | `Optional[bool]` | **Quarantined** | N/A (Excluded from model vector) | Excluded |
| 12 | `to_empty_or_missing` | `Optional[bool]` | **Quarantined** | N/A (Excluded from model vector) | Excluded |
| 13 | `from_syntax_valid` | `Optional[bool]` | Active | $m_7$: `m_from_syntax_valid` | Imputed to `0.0` (False) |
| 21 | `transit_delay_seconds` | `Optional[float]` | **Quarantined** | N/A (Excluded from model vector) | Excluded |
| 38 | `message_id_valid_syntax` | `Optional[bool]` | Active | $m_8$: `m_message_id_valid_syntax` | Imputed to `0.0` (False) |
| 39 | `message_id_domain_mismatch` | `Optional[bool]` | Active | $m_9$: `m_message_id_domain_mismatch` | Imputed to `0.0` (False) |
| 41 | `mime_version_valid` | `Optional[bool]` | Active | $m_{10}$: `m_mime_version_valid` | Imputed to `0.0` (False) |
| 45 | `content_type_is_multipart` | `Optional[bool]` | Active | $m_{11}$: `m_content_type_is_multipart` | Imputed to `0.0` (False) |

---

### 8.3 Tree-Based Model Pipeline (LightGBM / XGBoost / CatBoost)

Tree-based gradient boosted models handle non-linear boundaries and missing values natively. To prevent invalid assumptions regarding categorical ordering:

1. **Continuous Numerical Features (10 features)**:
   - Features: `from_address_count` [2], `recipient_count_to` [9], `recipient_count_cc` [10], `received_hop_count` [14], `received_syntax_malformed_count` [19], `spf_claim_count` [27], `dkim_claim_count` [28], `dmarc_claim_count` [29], `authserv_id_count` [35], `subject_length` [43].
   - Handled as `float64`. Missing values in nullable counts are passed as `np.nan`.
2. **Boolean Features (28 features)**:
   - 20 always evaluable booleans: mapped to `1.0` (`True`) and `0.0` (`False`).
   - 8 conditionally evaluable booleans (5, 6, 8, 13, 38, 39, 41, 45): mapped to `1.0` (`True`), `0.0` (`False`), and `np.nan` (`None`).
3. **Categorical Features (3 features)**:
   - Features: `spf_status` [24], `dkim_status` [25], `dmarc_status` [26].
   - **Nominal Categorical Declaration**: Integer category indices (0..9) are assigned matching `AuthStatus` enum order. **The implementation declares these features as nominal categoricals** (`pandas.Categorical` dtype, or via `categorical_feature` in LightGBM, `enable_categorical=True` in XGBoost, `cat_features` in CatBoost).
   - **Prohibition on Continuous Encoding**: Integer codes are **never passed as continuous numerical values**. Tree algorithms sort histogram bins using Fisher exact or optimal partition algorithms rather than numeric order splits.
4. **Native Missing-Value Handling**:
   - The tree algorithms natively learn optimal branching directions for `np.nan` values during training. No synthetic imputation is performed.
5. **Exact Input Dimensionality**:
   $$\mathbf{x}_{\text{tree}} \in \mathbb{R}^{41}$$
   The input vector comprises exactly **41 dimensions**.

---

### 8.4 Regularized Logistic Regression Pipeline (Layer 2 Base Classifier)

Linear models cannot process `np.nan` or nominal categorical values directly. They require explicit one-hot encoding, imputation, scaling, and missingness indicators:

1. **Numerical Feature Processing (10 features $\rightarrow$ 10 dimensions)**:
   - Missing values in the 3 nullable counts (Features 2, 9, 10) are imputed to the **median** estimated strictly on the training fold (`SimpleImputer(strategy='median')`).
   - All 10 numerical features are standardized using `StandardScaler` ($\frac{x - \mu}{\sigma}$) fitted on the training fold.
2. **Boolean Feature Processing (28 features $\rightarrow$ 28 dimensions)**:
   - The 20 always evaluable booleans map to $1.0$ and $0.0$.
   - The 8 conditionally evaluable booleans are imputed to $0.0$ when `None` (`SimpleImputer(strategy='constant', fill_value=0.0)`).
3. **Categorical Feature Processing (3 features $\rightarrow$ 30 dimensions)**:
   - Features: `spf_status`, `dkim_status`, `dmarc_status`.
   - Each status is encoded via `OneHotEncoder(categories=[AUTH_STATUS_CATEGORIES]*3, drop=None, sparse_output=False)`.
   - Across the 10 exhaustive `AuthStatus` enum values, each feature expands into exactly 10 binary dummy columns ($3 \times 10 = 30$ dimensions).
   - *Reference Category Justification*: With $L_2$ regularization, `drop=None` preserves symmetric shrinkage across all 10 RFC statuses without arbitrary reference baseline bias. (If unregularized or `drop='first'` is configured, it produces $3 \times 9 = 27$ dimensions; `drop=None` is canonical).
4. **Missingness Indicator Processing (11 nullable features $\rightarrow$ 11 dimensions)**:
   - For all 11 active nullable features (Features 2, 5, 6, 8, 9, 10, 13, 38, 39, 41, 45), binary missingness flags are constructed:
     $$m_j = \begin{cases} 1.0, & \text{if feature } j \text{ was } \text{None} \\ 0.0, & \text{if feature } j \text{ was observed} \end{cases}$$
   - These 11 indicators form vector $\mathbf{m} \in \{0, 1\}^{11}$.
5. **Exact Mathematical Input Dimensionality**:
   $$\mathbf{x}_{\text{linear}} \in \mathbb{R}^{79} = \left[ \mathbf{x}_{\text{num}} \in \mathbb{R}^{10} \;\|\; \mathbf{x}_{\text{bool}} \in \mathbb{R}^{28} \;\|\; \mathbf{x}_{\text{auth\_ohe}} \in \{0, 1\}^{30} \;\|\; \mathbf{m} \in \{0, 1\}^{11} \right]$$
   - Total Dimensions: $10 + 28 + 30 + 11 = \mathbf{79}\text{ dimensions}$.
   - **Dimensionality Invariant**: **The linear model input is exactly 79 dimensions (or 76 dimensions under drop='first'). It is never misrepresented as 41-dimensional or 54-dimensional.** The 11 concatenated missingness indicators ensure that an imputed count can never be confounded with a genuine observed zero.

---

### 8.5 Removal of Neural Pipeline
Neural architectures are **formally removed from this specification**. Multi-layer perceptrons with entity embeddings or continuous categorical projections will be designed in a dedicated future deep-learning research task.

---

### 8.6 Cross-Validation Isolation and Preprocessing Invariants
1. **Training-Fold-Only Fitting**:
   - All imputation medians, scalers ($\mu, \sigma$), and encoder category vocabularies must be fitted **strictly on the Training Fold** ($N=480$ per fold in 5-fold CV of the 600-sample training set).
2. **Zero Leakage Invariant**:
   - `fit()` or `fit_transform()` is **strictly prohibited on validation folds, held-out validation splits ($N=200$), and sealed test splits ($N=200$)**.
   - Evaluation splits are transformed exclusively using `pipeline.transform()` with parameters estimated from the training split.
3. **Reproducible Parameter Persistence**:
   - Preprocessing transformers are serialized alongside the trained model artifacts in `results/models/` to ensure exact reproduction during inference.

---

## 9. Confidence, Margin, Uncertainty, and Calibration Design

In accordance with the review findings, the Header Agent strictly decouples descriptive data availability from statistical prediction confidence, decision margin, and epistemic uncertainty.

### 9.1 Decoupling the Four Concepts
To eliminate ambiguity across the literature and modeling layers, the system formally distinguishes four separate quantities:

1. **Calibrated Phishing Probability ($p_h \in [0.0, 1.0]$)**: The posterior probability estimate $P(\text{phishing} \mid \mathbf{x}_{\text{header}})$ emitted by the Layer 2 base classifier after Platt scaling or isotonic regression on out-of-fold training predictions.
2. **Decision Margin ($m_h \in [0.0, 1.0]$)**: A deterministic geometric certainty proxy defined strictly as:
   $$m_h = 2 \cdot |p_h - 0.5|$$
   It measures the distance of the model's posterior probability from the neutral decision threshold ($0.5$). **It is a decision margin or certainty proxy, NOT prediction confidence.**
3. **Empirical Calibration Quality (e.g. ECE, Brier Score)**: A global statistical metric evaluated over a validation split (reliability diagram, Expected Calibration Error) assessing how closely predicted probabilities reflect empirical frequencies.
4. **Prediction Confidence (`calibrated_confidence`)**: An individual sample's empirical confidence score (e.g., bin-wise empirical accuracy or conformal prediction score).

> [!IMPORTANT]
> **Operational Status of `calibrated_confidence`**: `calibrated_confidence` is kept **strictly unavailable (`None`)** until a precise empirical definition and estimation procedure are approved. The Pydantic validator strictly verifies that `decision_margin == 2 * abs(p_h - 0.5)`.

### 9.2 Descriptive Evidence Completeness
Evidence completeness is a non-probabilistic, descriptive summary of available header evidence. It quantifies how much information was present in the email:
$$E_{\text{comp}} = \frac{1}{4} \left( C_{\text{identity}} + C_{\text{routing}} + C_{\text{auth}} + C_{\text{metadata}} \right)$$

where:
- $C_{\text{identity}} = \frac{1}{3} \left( \mathbb{I}(\text{avail\_from\_parsed}) + \mathbb{I}(\text{avail\_reply\_to\_parsed}) + \mathbb{I}(\text{avail\_return\_path\_parsed}) \right)$
- $C_{\text{routing}} = \begin{cases} 1.0, & \text{if } \text{received\_hop\_count} \ge 2 \text{ and } \text{avail\_transit\_delay} \\ 0.6, & \text{if } \text{received\_hop\_count} \ge 1 \\ 0.0, & \text{if } \text{received\_hop\_count} == 0 \end{cases}$
- $C_{\text{auth}} = \frac{1}{3} \left( \mathbb{I}(\text{avail\_spf\_status}) + \mathbb{I}(\text{avail\_dkim\_status}) + \mathbb{I}(\text{avail\_dmarc\_status}) \right)$
- $C_{\text{metadata}} = \frac{1}{3} \left( \mathbb{I}(\text{avail\_message\_id\_present}) + \mathbb{I}(\text{avail\_mime\_version\_present}) + \mathbb{I}(\text{avail\_content\_type\_present}) \right)$

> [!NOTE]
> **Descriptive Design Convention**: The equal weighting across the four domains and the specific step constants ($1.0, 0.6, 0.0$) in $C_{\text{routing}}$ are **descriptive design conventions** selected to represent data coverage density across standard RFC 5322 metadata blocks. **They do not constitute statistical confidence, probability calibration, or detection reliability.**

### 9.3 Calibration Protocol and Sample-Size Limitations
1. **Leakage-Safe Calibration Protocol**:
   - The base estimator is trained using 5-fold cross-validation on the 600-sample Training Split.
   - Out-of-fold probability predictions on the Training Split are used to fit the calibration model (Platt Scaling or Isotonic Regression).
   - The fitted calibrator is evaluated on the held-out 200-sample Validation Split.
   - **The 200-sample Test Split remains completely quarantined in the sealed vault until final research benchmark reporting.**
2. **No Mathematical ECE Guarantee**:
   - Platt Scaling and Isotonic Regression **do not mathematically guarantee an Expected Calibration Error $\text{ECE} \le 0.05$**.
   - An ECE $\le 0.05$ is an **empirical target**, not an assured outcome.
   - On a finite validation sample size ($N = 200$, containing 150 ham and 50 phishing), bin-wise reliability diagram estimates carry inherent sampling variance.
   - If class balance or sample density within extreme bins is insufficient, empirical calibration may underperform; the system does not promise calibration success without empirical verification.

### 9.4 Uncertainty Formulation ($u_h$)
Uncertainty is partitioned into:
1. **Epistemic Uncertainty (Model Uncertainty)**: Quantified empirically via bootstrap fold variance or ensemble variance across cross-validation models:
   $$\sigma^2_{\text{epistemic}} = \frac{1}{K} \sum_{k=1}^K \left( \hat{p}_k - \bar{p} \right)^2$$
2. **Aleatoric Uncertainty (Data Ambiguity)**: Arises from incomplete evidence (low $E_{\text{comp}}$) and contradictory claims (`has_conflicting_spf`, `has_conflicting_dkim`, `authserv_id_inconsistent`).
3. **No Trivial Identity Claim**: We reject the unsupported claim that $u_h \equiv 1.0 - c_h$ represents an empirical measurement of uncertainty without an underlying statistical estimator.

---

## 10. Evidence Provenance and Sanitization Strategy

To provide defensible forensic explanations without contaminating the ML feature space, the Header Agent enforces strict tier separation:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Tier 2: Forensic Traceability (Human Review / Incident Response)            │
│ HeaderEvidenceItem:                                                         │
│   ├── feature_name: "from_reply_to_domain_mismatch" (Canonical)             │
│   ├── header_name: "Reply-To"                                               │
│   ├── header_index: 0                                                       │
│   ├── claim_index: None                                                     │
│   ├── verification_status: UNVERIFIED                                       │
│   ├── description: "Reply-To domain differs from From address domain"        │
│   └── raw_snippet_bounded: "Reply-To: <collector@attacker-drop.com>"       │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ (Strict Separation Barrier)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Tier 3: Sanitized Machine-Learning Feature Vector                           │
│ HeaderFeatures:                                                             │
│   ├── from_reply_to_domain_mismatch: True                                   │
│   └── (all raw strings, hostnames, and snippets strictly excluded)          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 10.1 Transformation vs Validation for Evidence Snippets
To eliminate ambiguity between sanitization and schema enforcement:
1. **Transformation / Sanitization Step (Pre-Instantiation Function)**:
   Raw header excerpts are passed through a deterministic preprocessing function `sanitize_evidence_snippet(raw_text: str) -> str` prior to Pydantic instantiation:
   - Control Character Escaping: Replaces newline (`\n`), carriage return (`\r`), tab (`\t`), and non-printable characters (ASCII 0–31, 127) with visible escape sequences (`\\n`, `\\r`, `\\t`, `\\xNN`).
   - UTF-8-Safe Bounding: If the escaped string exceeds 256 characters, it is truncated to 253 characters and appended with `...`, ensuring no multi-byte UTF-8 code point is severed.
2. **Pydantic Validation Step (Schema Invariant)**:
   - `Field(max_length=256)` verifies that the resulting string does not exceed 256 characters, raising a `ValidationError` on violations. **It acts strictly as a validator, not a mutator.**
   - Collection size limits (`max_length=100`, `max_length=50`) validate list capacities.
3. **Quarantine from Machine-Learning Vectors**: Evidence snippets are stored exclusively inside `HeaderEvidenceItem` in Tier 2. No string or snippet can enter `HeaderFeatures`.
4. **Display-Only Disclaimer**: Stored snippets are strictly for post-detection forensic display and incident response. Sanitizing a snippet does not authenticate it or make it verified evidence.

---

## 11. Testing Plan

A comprehensive test suite (`tests/test_header_agent.py`) will be implemented covering **50 dedicated validation scenarios** under the current ingestion contract (plus 3 future-contract scenarios, totaling 53 specified scenarios), explicitly separated into current-contract tests and future-contract tests. 

> [!NOTE]
> **Specification vs Execution Status**: In compliance with the design-only scope of Task 8.5.0, these 50 test scenarios define the formal architectural specification for future test implementation in Tasks 8.5.1 and 8.5.3. They are not claimed as executed application tests; the existing passing test suite comprises the 441 ingestion, schema, and dataset tests verified via `pytest`.

### 11.1 Current-Contract Test Scenarios (Executable Under Existing Ingestion)

| # | Test Case Identifier | Test Scenario & Input Condition | Expected Behavior & Assertions |
|---|---|---|---|
| 1 | `test_canonical_registry_integrity` | Compare `HeaderFeatures.model_fields` to Canonical Registry table. | Exactly 45 fields match names, types, and continuous order (1..45) bit-for-bit. |
| 2 | `test_predictive_feature_counts` | Count active vs quarantined features in `HeaderFeatures`. | Exactly 41 active predictive features, 4 quarantined features (11, 12, 21, 22). |
| 3 | `test_date_presence_leakage_prevention` | Email containing `Date: Mon, 12 Aug 2002 10:00:00 -0400`. | Neither absolute date nor `has_date_header` exists in `HeaderFeatures`. |
| 4 | `test_missing_headers_graceful` | Email with completely empty header dictionary. | Executes without exception; outputs `from_present=False`, `from_address_count=None`, `received_hop_count=0`, `missing_received_headers=True`, `risk_assessment=None`. |
| 5 | `test_from_current_contract_states` | Test From under current contract: (a) absent, (b) unparseable `From: >>>bad<<<`, (c) valid `From: <a@b.com>`. | (a) `present=False, count=None, syntax=None`; (b) `present=True, count=None, syntax=False, avail_from_parsed=False`; (c) `present=True, count=1, syntax=True`. |
| 6 | `test_to_quarantined_under_current_contract`| Test To under current contract: (a) empty list `headers.to = []`, (b) unparseable tokens only `['>>>bad<<<']`. | In both cases: `recipient_count_to = None`, `to_empty_or_missing = None`, `avail_to_empty_or_missing = False`. Excluded from model input. |
| 7 | `test_cc_current_contract_states` | Test CC under current contract: (a) empty list `headers.cc = []`, (b) populated with valid addresses, (c) mixed valid and malformed tokens. | (a) `recipient_count_cc = None`, `avail_cc_parsed = False`; (b) `recipient_count_cc = N_valid`, `avail_cc_parsed = True`; (c) `recipient_count_cc = N_valid` (excluding malformed tokens). |
| 8 | `test_display_name_spoofing` | `From: "HelpDesk <admin@paypal.com>" <attacker@phish.net>`. | `display_name_contains_email=True`, `display_name_domain_mismatch=True`. |
| 9 | `test_from_reply_to_mismatch` | `From: <security@bank.com>`, `Reply-To: <collector@drop.com>`. | `from_reply_to_domain_mismatch=True`. |
| 10 | `test_from_return_path_mismatch`| `From: <legit@corp.com>`, `Return-Path: <bounce@spammer.org>`. | `from_return_path_domain_mismatch=True`. |
| 11 | `test_undisclosed_recipients_inactive_status`| Email lacking proposed `to_raw` ingestion extension. | `avail_undisclosed_recipients=False`, `undisclosed_recipients=None` (quarantined). |
| 12 | `test_spf_softfail_distinction` | `Received-SPF: softfail ... ~all`. | Reported status preserved as `AuthStatus.SOFTFAIL` (not collapsed into FAIL or PASS). |
| 13 | `test_auth_missing_vs_fail` | Email lacking any `Authentication-Results` or `Received-SPF`. | `spf_status == AuthStatus.MISSING` (missing is NOT treated as failure). |
| 14 | `test_auth_pass_unverified` | Email with explicit `Authentication-Results: spf=pass; dkim=pass`. | Reported statuses are `PASS`, but all claims retain `verification_status = UNVERIFIED`. |
| 15 | `test_conflicting_spf_claims` | Two `Authentication-Results` lines: one `spf=pass`, one `spf=fail`. | `has_conflicting_spf=True`, `spf_status == AuthStatus.OTHER`. |
| 16 | `test_conflicting_dmarc_claims` | Multiple `Authentication-Results` reporting contradictory DMARC. | `has_conflicting_dmarc=True`, `dmarc_status == AuthStatus.OTHER`. |
| 17 | `test_dkim_sig_without_pass` | `DKIM-Signature` header present but no `dkim=pass` claim. | `dkim_signature_header_present=True`, `dkim_signature_present_without_pass=True`, `dkim_status == AuthStatus.MISSING`. |
| 18 | `test_cgnat_distinct_from_rfc1918` | Received hop containing `100.64.1.1` (CGNAT RFC 6598). | Classified as `has_special_ip_in_external_hop=True`, NOT `has_private_ip_in_external_hop`. |
| 19 | `test_multicast_and_doc_ip_mapping`| Hops with `224.0.0.1` (multicast) and `192.0.2.1` (documentation). | Both trigger `has_special_ip_in_external_hop=True`; neither triggers private IP flag. |
| 20 | `test_global_routability_fallback` | Hop containing public IP `8.8.8.8` or `2606:2800:220:1::`. | Classified as global routable; does NOT trigger private or special IP flags. |
| 21 | `test_received_missing_trust_policy`| Offline email evaluated with `policy = None`. | Hop 0 is NOT trusted; all hops remain `UNVERIFIED`; no exception raised (Case 1). |
| 22 | `test_received_transport_mtls_match`| Trusted transport context contains verified client identity matching authorized ID. | Step 2 succeeds via Path A (Pure mTLS); `key_id=None, sig=None`; Hop 0 promoted to `TRUSTED_RECEIVER` (Case 3). |
| 23 | `test_received_signature_path_b_match`| In absence of mTLS context, record contains valid Ed25519 signature over 7-field canonical framing. | Step 2 succeeds via Path B (Signature); signature verified against keyring; Hop 0 promoted (Case 4). |
| 24 | `test_received_partial_credentials_missing_sig_rejected`| Transport context valid, but assertion provides `key_id!=None` with `integration_signature=None`. | Step 1/2 rejects; logs `partial_credentials_missing_signature`; store NOT touched (Case 5). |
| 25 | `test_received_partial_credentials_missing_key_id_rejected`| Transport context valid, but assertion provides `key_id=None` with `integration_signature!=None`. | Step 1/2 rejects; logs `partial_credentials_missing_key_id`; store NOT touched (Case 6). |
| 26 | `test_received_dual_auth_mode_success`| Transport context valid AND valid Ed25519 signature provided. | Evaluates both mTLS identity and signature; both succeed; Hop 0 promoted (Case 7). |
| 27 | `test_received_dual_auth_mode_invalid_sig_rejected`| Transport context valid, but Ed25519 signature is corrupt or invalid. | Fails closed; logs `dual_auth_signature_invalid`; store NOT touched (Case 8). |
| 28 | `test_received_unauthenticated_request_no_nonce_reservation`| Unauthenticated assertion presents arbitrary nonce. | Step 2 rejects request (`unauthenticated_provenance`); replay store is NOT touched (Case 9). |
| 29 | `test_received_signature_missing_key_id_rejected`| Signed assertion omits `key_id` under Path B. | Step 2 rejects immediately; logs `missing_key_id`; fails closed (Case 10). |
| 30 | `test_received_signature_unknown_key_id_rejected`| Signed assertion specifies unknown `key_id`. | Step 2 rejects immediately; logs `unknown_key_id`; fails closed (Case 11). |
| 31 | `test_received_signature_revoked_key_id_rejected`| Signed assertion specifies key marked `status="revoked"`. | Step 2 rejects immediately; logs `revoked_key_id`; fails closed (Case 12). |
| 32 | `test_received_signature_expired_key_id_rejected`| Signed assertion specifies key with `status="expired"` or past validity window. | Step 2 rejects immediately; logs `expired_key_id`; fails closed (Case 13). |
| 33 | `test_received_signature_ambiguous_key_selection_rejected`| Keyring contains duplicate conflicting definitions for `(integration_id, key_id)`. | Step 2 aborts; logs `ambiguous_key_selection`; fails closed (Case 14). |
| 34 | `test_received_signature_key_rotation_multi_active_keys`| Two active keys in keyring; incoming assertion signs under new key B. | Deterministic lookup resolves key B; Step 2 succeeds; Hop 0 promoted (Case 15). |
| 35 | `test_received_unauthorized_integration_id_rejected`| Integration ID authenticated but not in `policy.authorized_integration_ids`. | Step 3 aborts; logs `unauthorized_integration_id`; store NOT touched (Case 16). |
| 36 | `test_received_timestamp_semantic_calendar_invalid`| Assertions with invalid calendar dates: (a) `2026-99-99T22:00:00Z`, (b) `2026-02-30T22:00:00Z`, (c) `2026-11-12T25:00:00Z`. | Step 1 aborts; logs `malformed_timestamp_calendar`; store NOT touched (Case 17). |
| 37 | `test_received_timestamp_leap_second_rejected`| Assertion with leap second timestamp `2026-11-12T22:00:60Z`. | Step 1 aborts; logs `leap_second_rejected`; store NOT touched (Case 18). |
| 38 | `test_received_future_timestamp_skew_exceeded`| Assertion timestamp is +61 seconds ahead of detector UTC clock. | Step 4 aborts; logs `future_timestamp_skew_exceeded`; store NOT touched (Case 19). |
| 39 | `test_received_future_timestamp_within_skew_accepted`| Assertion timestamp is +30 seconds ahead of detector clock ($\le 60$s limit). | Step 4 succeeds; nonce reserved with computed TTL; Hop 0 promoted (Case 20). |
| 40 | `test_received_assertion_expired_rejected`| Assertion timestamp is 301 seconds old ($> 300$s limit). | Step 4 rejects timestamp as `assertion_expired` before store lookup (Case 21). |
| 41 | `test_received_concurrent_replay_collision`| Two concurrent requests with identical nonce arrive across workers. | Atomic `SET NX` permits exactly one winner; second collides and is rejected (`replay_detected`, Case 22). |
| 42 | `test_received_replay_store_failure_fail_closed`| Distributed replay store (e.g. Redis) unreachable. | Fails closed; logs `replay_store_unavailable`; all hops remain `UNVERIFIED` (Case 23). |
| 43 | `test_received_replay_store_failover_uncertainty_fail_closed`| Redis cluster failover or replication partition leaves reservation unconfirmed. | Fails closed; logs `replay_state_uncertain`; all hops remain `UNVERIFIED` (Case 24). |
| 44 | `test_received_replay_store_eviction_loss_fail_closed`| Early memory eviction detected on storage engine under memory pressure. | Fails closed; logs `replay_store_eviction_loss`; all hops remain `UNVERIFIED` (Case 25). |
| 45 | `test_received_replay_store_recovery_drain_active`| Store restarted or failed over within the last 361 seconds (measured via monotonic clock). | Step 5 aborts; logs `replay_store_recovery_drain`; trust promotion disabled (Case 26). |
| 46 | `test_received_relaxed_boundary_contradiction_ip_fails_closed`| `require_both_checks=False`: Host matches policy, but IP is present and contradicts configured CIDRs. | Fails closed to `UNVERIFIED`; logs `boundary_ip_contradiction` (Case 43). |
| 47 | `test_received_relaxed_boundary_contradiction_host_fails_closed`| `require_both_checks=False`: IP matches policy CIDR, but Host is present and contradicts configured hostnames. | Fails closed to `UNVERIFIED`; logs `boundary_hostname_contradiction` (Case 44). |
| 48 | `test_received_relaxed_boundary_both_missing_fails_closed`| `require_both_checks=False`: Both host and IP tokens are omitted from hop. | Fails closed to `UNVERIFIED`; logs `missing_boundary_tokens` (Case 46). |
| 49 | `test_canonical_framing_parser_strict_rejection`| Malformed framing payloads (bad length prefix, leading zeros, truncated stream, trailing bytes). | Strict parser raises `FramingError`; Step 2 rejects; logs `framing_malformed_prefix` / `framing_trailing_bytes` (Cases 30, 31). |
| 50 | `test_model_vector_dimensionality`| Verify pipeline outputs: 41 active features selected; 41D tree input; 79D linear input. | Tree vector = 41D; Linear vector = 79D ($10\text{ num} + 28\text{ bool} + 30\text{ auth OHE} + 11\text{ missingness}$). |

### 11.2 Future-Contract Test Scenarios (Conditional on Task 8.6 Ingestion Extension)
- `test_from_raw_empty_presence`: Email containing `From: \n`. Requires `from_raw`. Verifies `from_present = True, from_address_count = 0`.
- `test_to_raw_empty_group`: Email containing `To: undisclosed-recipients:;`. Requires `to_raw`. Verifies `undisclosed_recipients = True`.
- `test_to_raw_empty_recipient`: Email containing `To: \n`. Requires `to_raw`. Verifies `recipient_count_to = 0, to_empty_or_missing = True`.

---

## 12. Known Limitations

1. **Passive Offline Operation**:
   - Because live DNS and MX lookups are prohibited, the agent cannot verify whether the sending domain currently publishes an MX record, domain registration age, or live SPF/DKIM DNS TXT records.
2. **Unverified Upstream MTA Chains**:
   - In arbitrary offline `.eml` analysis without an established receiving boundary, no Received header is guaranteed authentic. Intermediate Received headers and `Authentication-Results` can be synthesized by threat actors.
3. **Corpus Temporal Confounding (Hypothesis H5)**:
   - In the 1,000-email development dataset, legitimate ham (2002) lacks SPF/DKIM/DMARC headers, while modern phishing (2015/2021) contains genuine authenticated passes. To prevent models from learning that `dkim=pass` indicates phishing, the Header Agent outputs authentication features objectively as categorical facts without hardcoded bias.
4. **Current Ingestion Contract Limitations**:
   - `EmailHeaders` exposes single strings for `From`, `Subject`, and `Message-ID`. Detecting multiple From, Subject, or Message-ID headers requires an ingestion contract update.
   - `EmailHeaders` normalizes absent and empty address headers identically (`None` or `[]`). Physical presence of empty headers cannot be evaluated until `from_raw`, `to_raw`, `cc_raw`, `reply_to_raw`, and `return_path_raw` are added in Task 8.6+.
   - `undisclosed_recipients` and `to_empty_or_missing` are quarantined because `undisclosed-recipients:;` and empty To both normalize to `[]`.
5. **Replay Store Operational Dependencies and Durability Limitations**:
   - Durable anti-replay protection is strictly conditional on deployment-level storage properties:
     - **Atomicity vs Durability**: `SET NX EX` provides atomic mutual exclusion in memory across application workers, but does NOT guarantee persistent durability against power failure, kernel crash, or cluster failover.
     - **AOF 1-Second Loss Window**: Redis AOF with `appendfsync everysec` incurs an asynchronous 1-second write-loss window during sudden server crashes.
     - **Separation of Durability Layers**: Redis `WAIT` only confirms replication to replica *memory*, not replica disk flush. In asynchronous failovers, acknowledged reservations can vanish. `appendfsync always` plus `WAIT` does NOT provide absolute replay immunity across all partition and failover scenarios.
     - **Required Consensus Durability**: True zero acknowledged-write loss requires a distributed consensus-backed storage system (e.g., Raft/Paxos in Etcd, CockroachDB, Spanner, or multi-node PostgreSQL with synchronous physical replication and `synchronous_commit = on / remote_apply`).
     - **The 361-Second Strictly Safe Recovery Drain**: Upon any replay-store restart, crash recovery, or failover, the detector MUST disable trust promotion for at least 361 seconds ($\Delta t_{\text{drain}} \ge 361$s) measured exclusively via a monotonic clock (`time.monotonic()`), guaranteeing that all pre-crash reservations expire by wall-clock freshness ($>300$s old) before trust promotion can resume.
     - **Unresolved Deployment Dependency**: Durability and failover guarantees are classified as an **unresolved deployment dependency**. Until satisfied by production infrastructure, trust promotion must remain disabled or restricted to non-critical monitoring environments.
6. **Clock Synchronization and Monotonicity**:
   - Freshness evaluation relies on local detector and sender clock synchronization via NTP. NTP step adjustments (backward clock jumps) can corrupt freshness windows; deployment requires continuous clock slewing and monotonic intervals.
7. **Infrastructure-Level mTLS Termination**:
   - Mutual TLS authentication cannot be established by application code or Pydantic models alone. It requires deployment-level infrastructure termination (e.g. Envoy, NGINX) with verified client certificate SAN/CN extraction and secure internal propagation.
8. **Keyring Provisioning and Lifecycle Management**:
   - Cryptographic verification requires out-of-band provisioning of authorized integrations and active signing key records. Dynamic revocation relies on updated policy deployment or shared keyring stores.
9. **IDNA 2008 Hostname Processing**:
   - Normalization of internationalized domain names relies on the Unicode Technical Standard #46 / IDNA 2008 algorithm. Malformed IDN sequences that cannot be decoded or encoded to Punycode fail closed.

---

## 13. Corrected Implementation Sequence for Next Tasks

The implementation of the Header Agent is divided into separate, sequentially reviewed tasks. **The next approved task is Task 8.5.1, which is strictly scoped to Pydantic Data Contracts ONLY.**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Task 8.5.1: Header Agent Data Contracts Implementation (NEXT APPROVED TASK) │
│ - Implement app/schemas/header_agent_schema.py containing:                  │
│   ├── CANONICAL_HEADER_FEATURE_NAMES (45-feature literal type)              │
│   ├── HeaderFeatures (45-feature schema model)                              │
│   ├── HeaderFeatureAvailability (complete availability manifest)             │
│   ├── HeaderEvidenceItem and HeaderEvidence (Tier 2 forensic models)        │
│   ├── HeaderRiskAssessment (optional Layer 2 assessment model with validator│
│   └── HeaderAgentOutput (top-level agent contract container)                │
│ - Implement tests/test_header_agent_schema.py verifying:                    │
│   ├── Model instantiation, defaults, and type validation                    │
│   ├── Canonical registry integrity (exact 45 features, continuous 1..45)    │
│   └── Snippet length validation and collection size limits                  │
│ - STRICT BOUNDARY: NO extractors, NO analyzers, NO agent logic, NO ML.      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ (Subject to User Review & Approval)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Task 8.5.2 (Future Task): Header Agent Extraction Analyzers                 │
│ - Implement app/agents/header_agent/identity_analyzer.py (Features 1..13)   │
│ - Implement app/agents/header_agent/routing_analyzer.py (Features 14..23)    │
│ - Implement app/agents/header_agent/auth_analyzer.py (Features 24..36)       │
│ - Implement app/agents/header_agent/metadata_analyzer.py (Features 37..45)   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ (Subject to User Review & Approval)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Task 8.5.3 (Future Task): Header Agent Orchestrator & Integration           │
│ - Implement app/agents/header_agent/header_agent.py                         │
│ - Orchestrate analyzers, sanitization filters, and completeness metrics     │
│ - Comprehensive 50-scenario test suite (tests/test_header_agent.py)         │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 14. Acceptance Criteria Checklist

- [x] **Strict Path A vs Path B separation and credential completeness**: Clearly separated Path A (Pure mTLS, `key_id=None, sig=None`) from Path B (Pure Signature, 7-field framing required). Handled partial credentials (`partial_credentials_missing_signature`, `partial_credentials_missing_key_id`) by failing closed, and defined Dual Authentication Mode requiring both mTLS identity and Ed25519 signature to succeed.
- [x] **Enforceable mTLS runtime deployment architecture**: Documented TLS termination component (Envoy/NGINX), SAN/CN extraction, secure internal propagation, server-side dependency injection, and ingress stripping/rejection of client-supplied headers. Clarified that Pydantic alone does not guarantee transport security.
- [x] **Replay protection operational durability & strictly safe 361s recovery drain**: Differentiated in-memory atomicity (`SET NX EX`), local persistence (`appendfsync always`), replication acknowledgement (`WAIT`), and durable failover. Rejected claims of absolute replay immunity for Redis `WAIT`. Specified consensus-backed storage requirements (Raft/Paxos WAL or synchronous PostgreSQL). Proved that assertions do not expire at an inclusive 360s boundary and specified strictly safe monotonic $\ge 361\text{s}$ recovery drain ($T_{\text{drain}} \ge 361$s). Explicitly retained replay durability as an **unresolved deployment dependency**.
- [x] **Recipient-count parsing semantics and mixed token handling**: Defined `recipient_count_to` and `recipient_count_cc` as counts of successfully parsed RFC 5322 mailbox addresses only. Preserved display tokens (e.g. `undisclosed-recipients:;`, malformed fragments) are strictly excluded from counts. Specified mixed-list behavior (counts valid mailboxes, ignores malformed tokens, logs Tier 2 forensic evidence). Preserved `None` for unavailable/unevaluable counts under current contract. Preserved 45/41/4 feature structure.
- [x] **Nonce reservation ordering, consumption, and retry policy**: Documented that Step 5 (Nonce Reservation) precedes Step 6 (Digest) and Step 7 (Boundary) as DoS protection. Documented that downstream failures consume the nonce. Enforced that retries must generate a fresh high-entropy nonce and new signature. Documented bounded TTL expiration.
- [x] **Decoupled pre-serialization validation from framing-only serializer**: Specified `validate_provenance_fields_for_signing(...)` to enforce all 8 structural, regex, IDNA, calendar, and non-empty checks, and explicitly restricted `serialize_canonical_provenance_payload(...)` to framing-only execution.
- [x] **Complete relaxed boundary matching permutations (require_both_checks=False)**: Fully specified all 7 permutations when both hostnames and IP CIDRs are configured. Enforced that contradicting tokens (`boundary_ip_contradiction`, `boundary_hostname_contradiction`) strictly fail closed and are never ignored.
- [x] **Authoritative Defined Decision Cases (Cases 1..50)**: Expanded decision table to 50 defined cases with dedicated rows for partial credentials, dual auth success/failure, recovery drain active ($\le 361$s monotonic), and all 7 relaxed matching permutations.
- [x] **Separated eight distinct sequential trust decisions**: Documented Step 1 (schema, calendar & credential validation) $\rightarrow$ Step 2 (issuer authentication) $\rightarrow$ Step 3 (integration authorization) $\rightarrow$ Step 4 (freshness/skew) $\rightarrow$ Step 5 (atomic nonce reservation & recovery drain) $\rightarrow$ Step 6 (digest binding) $\rightarrow$ Step 7 (boundary consistency) $\rightarrow$ Step 8 (Hop 0 conditional promotion). Prohibited automatic promotion of upstream hops.
- [x] **Corrected model preprocessing and dimensionality**: Preserved canonical 45-feature schema, 41 active predictive features, and 4 quarantined features (11, 12, 21, 22). Preserved 41D tree input vector and 79D regularized logistic regression vector.
- [x] **Reconciled complete document and testing plan**: Reconciled counts across all sections: exactly 50 current-contract scenarios in Section 11.1 (Scenarios 1..50) and 3 future-contract scenarios in Section 11.2 (total 53 specified scenarios). Reconciled decision table to exactly 50 defined cases (Cases 1..50).
- [x] **Remains strictly design-only**: No application code, schemas, tests, datasets, dependencies, or model files modified.
