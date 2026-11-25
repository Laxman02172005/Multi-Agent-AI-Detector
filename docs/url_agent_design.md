# URL Agent Architectural Design Specification

**Document**: `docs/url_agent_design.md`  
**Task**: Task 9.0.10 — Correct IPv6 Registry Entry Count and Multicast Registry Attribution (v1.10)  
**System**: Multi-Agent AI Phishing Email Detector  
**Status**: DRAFT DESIGN SPECIFICATION — REVISION 11 (PENDING INDEPENDENT REVIEW)  
**Version**: 1.10.0  
**Date**: November 15, 2026  

---

## Change Log

### Revision 1.10.0 (Current)

This revision corrects the IANA IPv6 Special-Purpose Address Registry entry count and attribution of IPv6 multicast (`ff00::/8`), while fully preserving multicast classification:

1. **Corrected IPv6 Special-Purpose Registry Accounting (Finding 1 & 3)**:
   - Corrected total registry entry count from 26 to **25 entries**:
     - **Section 9.1.5**: 11 sub-allocations within `2001::/23`.
     - **Section 9.1.6**: 14 allocations outside `2001::/23`.
     - **Total**: Exactly **25 entries** in the authoritative IANA IPv6 Special-Purpose Address Registry.
   - Updated all exhaustiveness statements, change log entries, and Section 16 compliance checklist items to reflect the true count of 25 entries.
2. **Corrected Multicast Registry Attribution (Finding 1 & 4)**:
   - Removed `ff00::/8` from the Section 9.1.6 table of IANA IPv6 Special-Purpose Address Registry allocations.
   - Clarified that `ff00::/8` is not cataloged in the special-purpose unicast registry, but is defined by RFC 4291 and cataloged in the authoritative [IANA IPv6 Address Space Registry](https://www.iana.org/assignments/ipv6-address-space).
3. **Fully Preserved Multicast Classification (Finding 2)**:
   - Preserved `IPV6_MULTICAST = ipaddress.ip_network("ff00::/8")  # Core IPv6 Architecture Multicast (RFC 4291 / IANA IPv6 Address Space)` in Section 9.1.7 pseudocode.
   - Preserved Precedence 3 in `classify_ip_address()`, returning `"multicast"`.
   - Preserved Feature 15 (`has_special_ip_url`) trigger semantics where `multicast` sets `has_special_ip_url = True` (Section 9.1.8).
4. **Document Provenance & Cross-Section Consistency (Finding 4 & 5)**:
   - Added reference to the authoritative IANA IPv6 Address Space registry in Section 9.1.2.
   - Verified that all tables, pseudocode, test matrix, and compliance checklist agree without contradiction.

### Revision 1.9.0 (Prior)

This revision completes the comprehensive audit of the authoritative IANA IPv6 Special-Purpose Address Registry, correcting registry values, adding previously omitted entries, and extending test coverage:

1. **Corrected `100::/64` Authoritative IANA Reachability (Finding 1)**:
   - Corrected authoritative IANA `Globally Reachable` value for `100::/64` (Discard-Only Address Block, RFC 6666) from `True` to **`False`**.
   - Removed the erroneous footnote claiming an IANA `True` value.
   - Clarified that the project's derived classification (`special_purpose`, setting `has_special_ip_url = True`) directly agrees with the authoritative IANA `False` value.
2. **Added Omitted IPv6 Special-Purpose Registry Entries (Finding 2)**:
   - Explicitly added all remaining entries from the IANA IPv6 Special-Purpose Address Registry to Section 9.1.6 and pseudocode:
     - `100:0:0:1::/64`: Dummy IPv6 Prefix (RFC 9780), IANA `Globally Reachable = False` $\to$ mapped to `special_purpose` (`has_special_ip_url = True`). Resides outside `2000::/3` as an independent `/64` subnet under `100::/16`.
     - `2620:4f:8000::/48`: Direct Delegation AS112 Service (RFC 7534), IANA `Globally Reachable = True` $\to$ mapped to `syntactically_global` (`has_special_ip_url = False`). Resides inside `2000::/3` and agrees with the global unicast fallback; explicitly matched in `IPV6_GLOBAL_RANGES`.
3. **Exhaustive IPv6 Registry Accounting (Finding 3)**:
   - Rechecked every current entry in the authoritative IANA IPv6 Special-Purpose Address Registry against the design specification.
   - Evaluated entries across Section 9.1.5 (11 sub-allocations within `2001::/23`) and Section 9.1.6 (subsequently refined in v1.10.0 to exactly 14 allocations outside `2001::/23` and 25 total registry entries by correctly separating multicast).
   - Verified that every applicable prefix is explicitly accounted for in pseudocode and longest-prefix precedence rules.
4. **Extended Test Matrix to 37 Categories (Finding 4)**:
   - Added Group 36: Discard-Only and Dummy IPv6 Blocks (`100::1` and `100:0:0:1::1` $\to$ `special_purpose`).
   - Added Group 37: Direct Delegation AS112 Service (`2620:4f:8000::1` $\to$ `syntactically_global`).
   - Retained all existing tests for `3fff::1`, `5f00::1`, `64:ff9b::1`, `64:ff9b:1::1`, `192.0.0.1`, `192.0.0.8`, and `192.0.0.0/29`.
5. **Harmonized Claims Across Entire Document (Finding 5)**:
   - Ensured tables, pseudocode, Section 12 test matrix, Section 14 roadmap, and Section 16 compliance checklist are 100% consistent.

### Revision 1.8.0 (Prior)

This revision resolves all v1.7.0 technical review findings, completing IPv6 classification coverage, eliminating parent-prefix contradictions, auditing IPv4 `192.0.0.0/24` sub-allocations, aligning feature registry identifiers, and clarifying IANA terminology:

1. **Resolved Parent-Prefix Contradiction (Finding 1)**:
   - Corrected Section 9.1.3 and Section 16: parent `2001::/23` is recorded strictly with authoritative IANA `Globally Reachable = False` (with footnote: *"Unless allowed by a more-specific allocation"*).
   - Preserved TEREDO `2001::/32` as IANA `Globally Reachable = N/A` and 6to4 `2002::/16` as IANA `Globally Reachable = N/A`.
   - Updated the taxonomy and compliance checklist so parent `/23` is never described as `N/A`.
2. **Complete IPv6 Classification Outside `2001::/23` (Finding 2)**:
   - Audited all relevant entries in the bundled IANA IPv6 Special-Purpose Address Registry against the `2000::/3` global unicast fallback:
     - `3fff::/20`: Documentation (RFC 9637), IANA `Globally Reachable = False` $\to$ mapped to `documentation` (`has_special_ip_url = True`). Explicitly prioritized before `2000::/3` fallback to prevent misclassifying documentation addresses as global.
     - `5f00::/16`: Segment Routing (SRv6) SIDs (RFC 8986, RFC 9602), IANA `Globally Reachable = False` $\to$ mapped to `special_purpose` (`has_special_ip_url = True`).
     - `64:ff9b::/96`: IPv4-IPv6 Translation Well-Known Prefix (RFC 6052), IANA `Globally Reachable = True` $\to$ mapped to `syntactically_global` (`has_special_ip_url = False`). Correctly classified as global despite residing outside `2000::/3`.
     - `64:ff9b:1::/48`: Local-Use IPv4/IPv6 Translation (RFC 8215), IANA `Globally Reachable = False` $\to$ mapped to `special_purpose` (`has_special_ip_url = True`).
     - Preserved explicit handling of `100::/64` (RFC 6666 Discard-Only), `2001:db8::/32` (RFC 3849 Documentation), `2002::/16` (RFC 3056 6to4), `fc00::/7` (RFC 4193 ULA), and `fe80::/10` (RFC 4291 Link-Local).
   - Structured explicit network sets and longest-prefix precedence order in Section 9.1.6 and 9.1.7 pseudocode.
3. **Audited IPv4 `192.0.0.0/24` Exhaustive Coverage (Finding 3)**:
   - Updated Section 9.1.4 table to exhaustively record all sub-allocations in `192.0.0.0/24`:
     - Included `192.0.0.0/29` (IPv4 Service Continuity Prefix, RFC 7335, IANA False) $\to$ `special_purpose`.
     - Included `192.0.0.8/32` (IPv4 Dummy Address, RFC 7600, IANA False) $\to$ `special_purpose`.
     - Retained `192.0.0.9/32` & `192.0.0.10/32` (PCP/TURN Anycast, IANA True) $\to$ `syntactically_global`.
     - Retained `192.0.0.170/32` & `192.0.0.171/32` (NAT64 Discovery, IANA False) $\to$ `special_purpose`.
     - Retained remainder `192.0.0.0/24` (IETF Protocol Assignments, IANA False) $\to$ `special_purpose`.
   - Explicitly clarified that the table is **exhaustive** for all allocations within `192.0.0.0/24` in the authoritative IANA IPv4 Special-Purpose Address Registry as of the October 9, 2025 release.
4. **Fixed Feature Registry Inconsistency (Finding 4)**:
   - Reaffirmed exact canonical feature definitions matching Section 5:
     - Feature 4: `http_url_count` (`int`, Quarantined due to historical temporal confounding).
     - Feature 12: `has_ip_literal_url` (`bool`, Active for IPv4 and IPv6 host literals).
   - Confirmed zero occurrences of incorrect identifier `has_ip_in_path_url`.
   - Added explicit verification items in the Section 16 compliance checklist.
5. **Clarified IANA Terminology & Reachability Semantics (Finding 5)**:
   - Replaced wording equating `Globally Reachable = True` with guaranteed public Internet routing.
   - Clarified that IANA's field defines forwarding suitability beyond an administrative domain (RFC 6890/8190) and does not guarantee BGP announcement, active IP assignment, or live endpoint availability.
   - Reaffirmed that `syntactically_global` is a static structural category denoting absence of designated special reservations, not an empirical reachability test.
6. **Extended Test Matrix to 35 Categories (Finding 6)**:
   - Expanded Section 12 test matrix from 31 to 35 test groups:
     - Added Group 28 explicit tests for `192.0.0.1`, `192.0.0.8`, and representative host `192.0.0.2` inside `192.0.0.0/29`.
     - Added Group 32: IPv6 Documentation range within `2000::/3` (`3fff::1`).
     - Added Group 33: IPv6 Special-Purpose outside `2000::/3` (`5f00::1`).
     - Added Group 34: IPv4-IPv6 Translation Prefixes (`64:ff9b::1` vs `64:ff9b:1::1`).
     - Added Group 35: Longest-Prefix Priority Overrides Verification across IPv4 and IPv6.

### Revision 1.7.0 (Prior)

This revision corrects all IANA data inaccuracies based on the current authoritative IANA IPv4 and IPv6 Special-Purpose Address Registries:

1. **Authoritative IANA IPv6 Registry Classifications within `2001::/23` (Finding 1)**:
   - Corrected IANA `Globally Reachable` values and derived classifications:
     - `2001:20::/28`: ORCHIDv2 (RFC 7343) has authoritative IANA `Globally Reachable = True` $\to$ mapped to `syntactically_global`.
     - `2001:30::/28`: Drone Remote ID Protocol Entity Tags (RFC 9374) has authoritative IANA `Globally Reachable = True` $\to$ mapped to `syntactically_global`.
     - `2001:10::/28`: Deprecated Sub-TLA allocation (RFC 4843, RFC 7343, termination date 2014-03) has `[Blank]` reachability fields in the source registry. Not represented as explicit IANA False; mapped to `special_purpose` under conservative project policy.
     - `2001::/23`: Parent IETF Protocol Assignments block (RFC 2928) has authoritative IANA `Globally Reachable = False` with explicit footnote: *"Unless allowed by a more-specific allocation"*.
     - `2001::/32`: TEREDO (RFC 4380, RFC 8190) has authoritative IANA `Globally Reachable = N/A` $\to$ mapped to `special_purpose` under conservative project policy.
     - Preserved existing True classifications for `2001:1::1/128` (PCP Anycast), `2001:1::2/128` (TURN Anycast), `2001:1::3/128` (DNS-SD SRP Anycast), `2001:3::/32` (AMT), and `2001:4:112::/48` (AS112-v6).
   - Separated authoritative IANA source values from project-derived classifications into distinct table columns (Section 9.1.5).
   - Explicitly defined the treatment of IANA `Globally Reachable = True`, `False`, `N/A`, and `[Blank]`.
2. **Corrected RFC Attribution & Registry Provenance (Findings 2 & 3)**:
   - Recorded official IANA source URLs:
     - IPv4 Registry: `https://www.iana.org/assignments/iana-ipv4-special-registry`
     - IPv6 Registry: `https://www.iana.org/assignments/iana-ipv6-special-registry`
   - Documented exact source update and project capture dates:
     - **IANA Source Registry Last Updated Date**: **2025-10-09** for both IPv4 and IPv6 registries.
     - **Project Snapshot Capture Date**: **November 15, 2026** (bundled, frozen snapshot for deterministic offline verification).
   - Reaffirmed RFC attribution: `2001:1::3/128` is DNS-SD Service Registration Protocol Anycast (RFC 9665); `2001::/32` is TEREDO (RFC 4380, RFC 8190); `2001:30::/28` is Drone Remote ID (RFC 9374).
3. **Extended IPv4 and IPv6 Boundary Tests (Findings 3 & 4)**:
   - Added explicit IPv4 test cases for NAT64/DNS64 Discovery addresses `192.0.0.170` and `192.0.0.171` (RFC 7050, RFC 8880; IANA Globally Reachable = False) verifying classification as `special_purpose` (`has_special_ip_url=True`).
   - Retained IPv4 positive exceptions (`192.0.0.9`, `192.0.0.10` $\to$ `syntactically_global`) and negative siblings (`192.0.0.1`, `192.0.0.8`, `192.0.0.11` $\to$ `special_purpose`).
   - Added explicit IPv6 test cases: `2001:20::1` (IANA True $\to$ `syntactically_global`), `2001:30::1` (IANA True $\to$ `syntactically_global`), `2001:10::1` (IANA blank/expired $\to$ `special_purpose`), `2001::1` (TEREDO N/A $\to$ `special_purpose`), and `2001:1ff::1` (parent `/23` remainder False $\to$ `special_purpose`).
4. **Preserved Invariants & Constraints (Finding 5)**:
   - Continuous canonical 39-feature registry preserved (36 active, 3 quarantined).
   - IPv4-mapped IPv6 unwrapping (`::ffff:0:0/96`) preserved.
   - Occurrence-based sender alignment ratios ($N_{\text{resolvable}}$ and $N_{\text{match}}$) preserved.
   - Corrected `has_sender_domain_mismatch_url` semantics ($N_{\text{match}} < N_{\text{resolvable}}$) preserved.
   - Link-local policy preserved (`link_local` in per-URL analysis & Tier 2 evidence; does not trigger `has_private_ip_url` or `has_special_ip_url`).
   - Offline runtime requirement (zero network calls) preserved.
   - Evidence ordering `(url_index, feature_name, finding_id)` and caps preserved.
   - Distinction between static classification and actual Internet reachability maintained.

### Revision 1.6.0 (Prior)

Resolved v1.5.0 audit findings (complete sub-allocation coverage in `2001::/23`, corrected RFC 9665 attribution, dual-date registry provenance).

### Revision 1.5.0 (Prior)

Resolved v1.4.0 audit findings (IP range exceptions for `192.0.0.9`/`10`, corrected sender mismatch semantics `N_match < N_resolvable`, IANA snapshot recording).

### Revision 1.4.0 (Prior)

Resolved v1.3.0 audit findings (deterministic IP classification without dynamic `ip.is_global`, occurrence-based sender alignment counting, link-local ML limitation documented).

### Revision 1.3.0 (Prior)

Resolved v1.2.0 audit findings (IPv4-mapped IPv6 unwrap, link-local vs private IP semantics, malformed port conditions, heterogeneous domain counting, external link ratio).

### Revision 1.2.0 (Prior)

Resolved v1.1.0 audit findings (hostname-only Punycode, $\mathcal{O}(N)$ memory documentation, `DomainResolutionStatus` enum, quarantined `has_brand_in_path`, removed probability notation).

### Revision 1.1.0 (Prior)

Resolved v1.0.0 audit findings (Punycode bypass, PSL snapshot strategy, form action quarantine, port semantics, IP classification, evidence capping).

### Revision 1.0.0 (Initial)

Initial URL Agent design specification.

---

## 1. Purpose and Scope

### 1.1 Purpose
The **URL Agent** is the second specialized analytical agent in the Multi-Agent AI Phishing Email Detector architecture, following the completed **Header Agent MVP** (Task 8.5.1). 

The agent performs **strictly deterministic, passive, and offline forensic analysis** of all Uniform Resource Locators (URLs) extracted from email bodies and headers during ingestion. It extracts structural, lexical, obfuscation, and contextual indicators, providing:
1. A sanitized, fixed-length Tier 3 feature vector (`UrlFeatures`) for downstream machine learning.
2. An explicit missingness manifest (`UrlFeatureAvailability`) tracking data presence.
3. A traceable Tier 2 forensic evidence audit trail (`UrlEvidence`) with bounded snippets.

### 1.2 Bounded Scope
- **In-Scope**:
  - Structural syntax validation of URL components and permissive `urlsplit` exception handling.
  - Scheme categorization (`https`, `http`, suspicious schemes `javascript:`, `data:`, `file:`).
  - Explicit port parsing and default mapping (HTTP 80, HTTPS 443, FTP 21, SSH 22).
  - Authority and userinfo credentials inspection (`user:pass@` and `@` symbol obfuscation).
  - Hostname structural analysis (IPv4/IPv6 literals, version-independent explicit RFC IP classification with longest-prefix exception matching and IPv4-mapped IPv6 unwrapping, IDNA Punycode `xn--` detection in hostname only, subdomain depth, PSL registered domain extraction with explicit resolution status, Shannon entropy).
  - Lexical path and query string analysis (path depth, executable extensions, query length, open-redirect parameter tokens).
  - Obfuscation analysis (percent-encoding density, double percent-encoding `%25`, hex/octal IP representations).
  - Contextual alignment (visual anchor text vs destination target mismatch, From header registered domain vs URL registered domain alignment based on occurrence counts).
  - Full email-level aggregation across all extracted URLs.
  - Deterministic audit logging of traceable Tier 2 forensic evidence items.
- **Out-of-Scope (Strictly Prohibited)**:
  - Network connectivity of any kind (TCP sockets, HTTP/HTTPS requests, SSL handshake validation).
  - DNS resolution (no A, AAAA, CNAME, or MX lookups).
  - WHOIS queries, domain registration age lookups, or registrar queries.
  - Active redirection following (the agent identifies redirect *parameters*, but never follows links).
  - Live external reputation feeds, blacklists, Google Safe Browsing, or VirusTotal.
  - Modifying existing `EmailData`, `ExtractedURL`, or ingestion modules.

---

## 2. Integration with Existing Ingestion Architecture

### 2.1 Multi-Agent Pipeline Topology

The detection system operates as a hierarchical multi-agent pipeline:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. Raw RFC 822 Email File (.eml)                                            │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼ (BytesParser Policy)
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. Unified Ingestion Coordinator: ingest_email() (app/ingestion/)          │
│    ├── header_extractor.py     ──► headers: EmailHeaders                    │
│    │                           ──► authentication: AuthenticationMetadata   │
│    ├── body_extractor.py       ──► plain_text_body, html_body, cleaned_text │
│    ├── url_extractor.py        ──► extracted_urls: list[ExtractedURL]       │
│    └── attachment_extractor.py ──► attachments: list[AttachmentMetadata]    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼ (Emits Validated EmailData Contract)
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. Shared Pydantic Contract: EmailData (app/schemas/email_schema.py)        │
└──────────────┬───────────────────────────────────────────────┬──────────────┘
               │                                               │
               ▼                                               ▼
┌──────────────────────────────┐               ┌──────────────────────────────┐
│ Header Agent (Task 8.5.1)    │               │ URL Agent (Task 9 - Design)  │
│ analyze_headers(email_data)  │               │ analyze_urls(email_data)     │
│ ──► HeaderAgentResult        │               │ ──► UrlAgentResult           │
└──────────────┬───────────────┘               └───────────────┬──────────────┘
               │                                               │
               └───────────────────────┬───────────────────────┘
                                       │ (Emits structural features,
                                       │  availability flags, evidence,
                                       │  missingness indicators)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. Evidence Aggregation Layer & Meta-Classifier (Task 12)                   │
│    Synthesizes low-dimensional meta-features via calibrated Ridge/Stacking  │
└─────────────────────────────────────────────────────────────────────────────┘
```

> [!NOTE]
> Layer 1 agents (Header Agent, URL Agent) emit deterministic structural features and availability flags. They do **not** emit calibrated probability scores. The Meta-Classifier (Layer 3, Task 12) is the first stage that may produce probability estimates. The missingness indicator $m_u$ enables the meta-model to adjust its prior odds when URL input is absent.

### 2.2 Reusable Ingestion Fields from `ExtractedURL`

The existing ingestion module `app/ingestion/url_extractor.py` extracts URLs from plain text, HTML markup, and headers, deduplicating them on `(normalized_url, source, anchor_text)` and populating `EmailData.extracted_urls`.

Each `ExtractedURL` object contains:
- `original_url: str`: Verbatim string as extracted from text or markup.
- `normalized_url: Optional[str]`: Unescaped, lowercase scheme, IDNA/Punycode normalized hostname, normalized default path (`/`), preserved query.
- `source: URLSource`: Contextual origin (`PLAIN_TEXT`, `HTML_HREF`, `HTML_SRC`, `HTML_OTHER`, `HEADER`).
- `anchor_text: Optional[str]`: Visible text inside `<a>` tag or image `alt` text.
- `scheme: Optional[str]`: Extracted scheme (e.g. `http`, `https`, `javascript`, `data`, `file`).
- `hostname: Optional[str]`: Extracted and IDNA-normalized hostname or IP address (Punycode-encoded if internationalized).
- `path: Optional[str]`: Path string.
- `query: Optional[str]`: Query string without leading `?`.

> [!IMPORTANT]
> The ingestion pipeline (`url_extractor.py` line 152–159) converts Unicode hostnames to Punycode ASCII via `.encode("idna").decode("ascii")`. Therefore, `ExtractedURL.hostname` already contains Punycode labels (e.g., `xn--e1afmkfd.xn--p1ai`), while `original_url` retains the raw Unicode representation. This asymmetry is critical for correct Punycode detection logic (see Feature 16).

### 2.3 Information Unavailable in `ExtractedURL` (Analyzed Statically by URL Agent)

`ExtractedURL` provides component splitting, but leaves security-critical structural properties unparsed:
1. **Explicit Port Parsing**: `ExtractedURL` does not expose an explicit `port: Optional[int]` field.
2. **Authority / Userinfo Credentials**: Does not expose `username` or `password` fields.
3. **Fragment Component**: The fragment (`#...`) is not stored as an independent field on `ExtractedURL`.
4. **Granular IP Classification**: `hostname` is a raw string; no IP literal verification or RFC category tagging (RFC 1918, RFC 4193, CGNAT, loopback, link-local) is performed during ingestion.
5. **Registered Domain Decomposition**: Does not parse the Public Suffix List (PSL) registered domain (e.g. distinguishing `evil.co.uk` from subdomains `login.bank.evil.co.uk`).
6. **Visual vs. Actual Anchor Discrepancy**: The ingestion pipeline does not evaluate whether anchor text contains a deceptive URL that mismatches the target domain.
7. **Obfuscation Metrics**: Percent-encoding frequency, double-encoding, and Shannon entropy are not computed.
8. **Shortener & Redirect Identification**: No matching against shortener registries or query parameter inspection is performed during ingestion.
9. **Multi-URL Aggregation**: `EmailData` contains an unbounded list of URLs; downstream ML models require a fixed-length feature vector.

---

## 3. Input Contract & Field Availability Audit

### 3.1 Input Contract Definition
The URL Agent takes the validated `EmailData` instance as its sole input:
```python
def analyze_urls(email_data: EmailData) -> UrlAgentResult:
```
The agent accesses:
- `email_data.email_id: str`
- `email_data.extracted_urls: list[ExtractedURL]`
- `email_data.headers.from_address: Optional[str]` (for sender domain alignment comparison)

### 3.2 Handling the No-URL State ($m_u = 1$)
In the 1,000-email development corpus, exactly **121 emails (12.1%) contain zero URLs**. 
- The agent must not raise an exception, abort processing, or fabricate synthetic URL features.
- When `len(email_data.extracted_urls) == 0`:
  - `total_url_count = 0`
  - `unique_url_count = 0`
  - `has_urls = False`
  - All conditional counts are set to `0`
  - All nullable features (`Optional[float]`, `Optional[bool]`) are set to `None`
  - All availability flags (`avail_*`) evaluate to `False`
  - Descriptive URL completeness evaluates to `0.0`
  - **No probability score is emitted by Layer 1**.
  - In the future Meta-Classifier (Layer 3), missing URL input is handled via an explicit indicator $m_u = 1$, allowing the meta-model to adjust its prior odds without requiring a fabricated probability.

---

## 4. Deterministic URL Analysis Pipeline

The URL Agent processes an email through a seven-stage deterministic pipeline:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Stage 1: Input Validation & Nullity Check                                   │
│ Verify EmailData, check len(extracted_urls). If 0, return No-URL Result.    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Stage 2: Per-URL Structural & Lexical Parsing (UrlAnalysisItem)             │
│ For each ExtractedURL:                                                      │
│   ├── Component extraction: scheme, userinfo, hostname, port, path, query    │
│   ├── Structural syntax validation (5 distinct conditions; Section 5.7)      │
│   ├── Explicit RFC IP evaluation: classify_ip_address() with longest-prefix  │
│   │   exception matching and IPv4-mapped IPv6 unwrap (Section 9.1)           │
│   ├── Hostname breakdown: IDNA Punycode detection (hostname-only),          │
│   │   PSL registered domain with DomainResolutionStatus                     │
│   ├── Obfuscation detection: percent-encoding, @ symbol, hex/octal IP forms │
│   └── Lexical metrics: character length, path depth, Shannon entropy        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Stage 3: Contextual & Anchor Discrepancy Evaluation                         │
│   ├── Visual anchor analysis: does anchor_text embed a deceptive URL/domain?│
│   ├── Destination comparison: anchor domain != destination domain?          │
│   ├── URL shortener identification: offline versioned registry lookup       │
│   └── Open redirect parameter detection: ?url=, ?redirect=, etc.            │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Stage 4: Sender Domain Cross-Alignment                                      │
│   └── Compare extracted URL PSL domains against From header PSL domain      │
│       based on all extracted URL occurrences (Section 5.8)                  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Stage 5: Multi-URL Aggregation (UrlFeatures - 39 Canonical Features)        │
│   ├── Stream over 100% of URLs in single linear O(N) pass                   │
│   ├── Maintain uniqueness tracking sets (see Section 12.1 for memory)       │
│   ├── Worst-case anomaly boolean propagation (any URL triggers flag)        │
│   ├── Bounded maximums (max length, max depth, max entropy)                 │
│   └── Distribution metrics (unique URLs, heterogeneous domains, shorteners) │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Stage 6: Forensic Evidence Generation & Bounded Sanitization (UrlEvidence)  │
│   ├── Sort evidence deterministically by (url_index, feature_name,          │
│   │   finding_id) — consistent across all references                        │
│   ├── Cap evidence at 100 items; record omitted_evidence_count              │
│   └── Link anomalies to source URLs with sanitized raw_snippet (max 256 ch) │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Stage 7: Availability Manifest & Output Construction (UrlAgentResult)       │
│   └── Compile UrlFeatureAvailability, descriptive completeness, and result. │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Canonical URL Feature Registry (39 Features)

The URL Agent defines an auditable, continuous registry of **exactly 39 canonical features** indexed 1..39 across 4 categories:
- **Category A**: URL Structural Properties (Features 1..11, 10 Active, 1 Quarantined)
- **Category B**: Hostname & Domain Composition (Features 12..21, 10 Active)
- **Category C**: Obfuscation, Encodings & Deception (Features 22..30, 8 Active, 1 Quarantined)
- **Category D**: Contextual Alignment & Behavioral Indicators (Features 31..39, 8 Active, 1 Quarantined)

### 5.1 Category A: URL Structural Properties (11 Features)

| # | Feature Name | Type | Status | Extraction Logic & Description | Missingness Rule | Potential False-Positive Scenarios |
|---|---|:---:|:---:|---|---|---|
| **1** | `total_url_count` | `int` | **Active** | `len(email_data.extracted_urls)`. Total count of URL occurrences in email. | Always evaluable (`0` if no URLs). | **Mailing lists / digests**: Task 8.4 showed `hard_ham` contains up to 3,134 URLs. Must never be used as a positive phishing signal. |
| **2** | `unique_url_count` | `int` | **Active** | Count of distinct normalized URLs across the email (see Section 5.6 for deduplication identity). | Always evaluable (`0` if no URLs). | Repetitive footer links in corporate marketing emails. |
| **3** | `has_urls` | `bool` | **Active** | `bool(total_url_count > 0)`. Primary presence indicator. | Always evaluable. | Plain-text notifications with no links. |
| **4** | `http_url_count` | `int` | **Quarantined** | Count of URLs with `scheme == 'http'`. | Always evaluable (`0` if no URLs). | **Historical Confounding**: 2002 SpamAssassin ham links are predominantly HTTP. Quarantined from primary feature vector. |
| **5** | `https_url_count` | `int` | **Active** | Count of URLs with `scheme == 'https'`. | Always evaluable (`0` if no URLs). | Modern phishing sites routinely deploy free TLS certificates. |
| **6** | `suspicious_scheme_count` | `int` | **Active** | Count of URLs with `scheme in ('javascript', 'data', 'file', 'vbscript', 'callto')`. | Always evaluable (`0` if no URLs). | Benign tracking pixels or local file links in corporate internal archives. |
| **7** | `has_suspicious_scheme` | `bool` | **Active** | `bool(suspicious_scheme_count > 0)`. True if any non-web protocol is used. | Always evaluable. | Rare benign inline HTML data URIs for small icons. |
| **8** | `has_non_default_port` | `bool` | **Active** | True if any URL specifies an explicit port other than its scheme default (HTTP 80, HTTPS 443, FTP 21, SSH 22). | Always evaluable (`False` if no URLs). | Corporate development servers, webmin interfaces, or internal portals (e.g. `:8080`, `:8443`). |
| **9** | `max_url_length` | `int` | **Active** | Maximum `len(original_url)` across all URLs. (Bounded `ge=0`). | Always evaluable (`0` if no URLs). | Legitimate tracking links with extensive UTM query parameters, affiliate links, or OAuth state tokens. |
| **10** | `max_path_depth` | `int` | **Active** | Maximum number of `/` segments in URL path (excluding leading slash). | Always evaluable (`0` if no URLs). | Deeply nested legitimate content management system (CMS) paths or documentation links. |
| **11** | `has_executable_file_in_path` | `bool` | **Active** | True if URL path terminates with `.exe`, `.scr`, `.bat`, `.vbs`, `.cpl`, `.msi`, `.apk`, `.cmd`. | Always evaluable (`False` if no URLs). | Direct links to legitimate software downloads (e.g. open-source utility installers). |

> [!WARNING]
> **Feature 5 (`https_url_count`) — Temporal Confounding Caveat**: HTTPS prevalence strongly correlates with corpus era. In the 2002 SpamAssassin corpus, HTTPS was rare across all emails; in the 2015/2021 Nazario phishing sets, HTTPS is common. This feature may encode a temporal artifact similar to `http_url_count` (Feature 4). It is retained as active for now but requires careful evaluation during model training. If cross-validation reveals that `https_url_count` primarily encodes corpus era rather than phishing signal, it should be quarantined.

### 5.2 Category B: Hostname & Domain Composition (10 Features)

| # | Feature Name | Type | Status | Extraction Logic & Description | Missingness Rule | Potential False-Positive Scenarios |
|---|---|:---:|:---:|---|---|---|
| **12** | `has_ip_literal_url` | `bool` | **Active** | True if any URL hostname parses as an IPv4 or IPv6 address literal via `ipaddress.ip_address()`. | Always evaluable (`False` if no URLs). | Internal network printers, router management links, or university lab documentation. |
| **13** | `has_private_ip_url` | `bool` | **Active** | True if any URL hostname is an RFC 1918 IPv4 or RFC 4193 IPv6 private address (including unwrapped IPv4-mapped IPv6). Link-local addresses (RFC 3927/4291) do not trigger this feature (see Section 9.1). | Always evaluable (`False` if no URLs). | Internal enterprise intranet communications (e.g. `http://192.168.1.10/wiki`). |
| **14** | `has_loopback_ip_url` | `bool` | **Active** | True if any URL hostname is a loopback address (`127.0.0.1`, `::1`, or mapped `::ffff:127.0.0.1`). | Always evaluable (`False` if no URLs). | Developer emails, debugging logs, or local software testing guides. |
| **15** | `has_special_ip_url` | `bool` | **Active** | True if any URL IP is classified as `cgnat`, `documentation`, `multicast`, or `special_purpose` (see Section 9.1). Link-local, loopback, and RFC 1918/4193 are handled by dedicated features or per-URL analysis. | Always evaluable (`False` if no URLs). | Technical documentation or networking tutorial emails using RFC 5737 test addresses. |
| **16** | `has_punycode_url` | `bool` | **Active** | True if any URL's hostname contains internationalized encoding. Detection is hostname-only (see Section 5.5). | Always evaluable (`False` if no URLs). | Legitimate internationalized domain names (IDN) for non-Latin script organizations (e.g. Arabic, Cyrillic, Chinese). |
| **17** | `max_subdomain_depth` | `int` | **Active** | Maximum number of dot-separated labels in hostname preceding the PSL registered domain. Only computed for URLs with `DomainResolutionStatus` of `EXACT_MATCH`, `WILDCARD_MATCH`, or `EXCEPTION_MATCH`. | Always evaluable (`0` if no URLs or no resolvable domains). | Legitimate cloud services (e.g. `bucket.s3.dualstack.eu-west-1.amazonaws.com`). |
| **18** | `has_excessive_subdomains` | `bool` | **Active** | Operational threshold flag: `bool(max_subdomain_depth >= 3)`. | Always evaluable (`False` if no URLs). | Multi-tenant SaaS platforms or complex regional corporate hosting hierarchies. |
| **19** | `max_hostname_entropy` | `Optional[float]` | **Active** | Maximum Shannon entropy of hostname string: $-\sum p_i \log_2 p_i$. | None if no URLs. | Legitimate content delivery networks (CDNs) with hashed hostnames (e.g. `a7f9b2c.cloudfront.net`). |
| **20** | `unique_domain_count` | `int` | **Active** | Count of distinct heterogeneous domain identities across all extracted URLs (PSL registered domains, normalized IP literals, and FQDNs for unknown suffixes; see Section 5.6 for heterogeneous identity rules and caveats). | Always evaluable (`0` if no URLs). | Newsletters, tech digest emails, and aggregators linking to dozens of distinct sources. |
| **21** | `unique_fqdn_count` | `int` | **Active** | Count of distinct fully qualified hostnames across all extracted URLs. FQDNs are compared case-insensitively after lowercasing. IP literals are excluded from FQDN counts. | Always evaluable (`0` if no URLs). | Multiple subdomains of a single legitimate provider. |

### 5.3 Category C: Obfuscation, Encodings & Deception (9 Features)

| # | Feature Name | Type | Status | Extraction Logic & Description | Missingness Rule | Potential False-Positive Scenarios |
|---|---|:---:|:---:|---|---|---|
| **22** | `has_at_symbol_in_url` | `bool` | **Active** | True if authority segment contains `@` preceding the host (e.g. `http://bank.com@attacker.com/`). | Always evaluable (`False` if no URLs). | Rare legacy FTP URLs with anonymous user credentials (`ftp://anonymous@ftp.example.com`). |
| **23** | `has_embedded_credentials` | `bool` | **Active** | True if authority segment explicitly embeds user credentials (`username:password@`). | Always evaluable (`False` if no URLs). | Internal developer documentation or legacy staging server links. |
| **24** | `has_percent_encoding` | `bool` | **Active** | True if URL contains valid percent-encoded characters (`%[0-9a-fA-F]{2}`). | Always evaluable (`False` if no URLs). | Standard encoding for spaces (`%20`), reserved query characters (`%26`, `%3D`), or UTF-8 parameters. |
| **25** | `has_double_percent_encoding` | `bool` | **Active** | True if URL contains `%25` followed by 2 hex digits (`%25[0-9a-fA-F]{2}`). | Always evaluable (`False` if no URLs). | Web proxies, SAML RelayState parameters, and search engine cache links. |
| **26** | `max_percent_encoded_count` | `int` | **Active** | Maximum count of percent-encoded triplets (`%xx`) in a single URL. | Always evaluable (`0` if no URLs). | Complex federated identity tokens (SAML / OAuth) encoded inside query parameters. |
| **27** | `has_brand_in_path` | `bool` | **Quarantined** | True if path/query embeds a known brand token while the PSL registered domain differs. | **Quarantined** (`None`). | News articles discussing a brand (e.g. `http://tech-news.com/article/paypal-update`). |
| **28** | `has_non_ascii_url` | `bool` | **Active** | True if `original_url` contains characters outside ASCII range 32..126. | Always evaluable (`False` if no URLs). | International web links in non-English legitimate communication. |
| **29** | `has_unusual_ip_format` | `bool` | **Active** | True if IP is encoded in integer, octal (`0177.0.0.1`), or hexadecimal (`0x7f.1`) notation. | Always evaluable (`False` if no URLs). | Rare legacy diagnostic software manuals. |
| **30** | `malformed_url_count` | `int` | **Active** | Count of URLs failing structural syntax validation across 5 failure conditions (see Section 5.7). | Always evaluable (`0` if no URLs). | Broken formatting produced by buggy email client line-wrapping. |

### 5.4 Category D: Contextual Alignment & Behavioral Indicators (9 Features)

| # | Feature Name | Type | Status | Extraction Logic & Description | Missingness Rule | Potential False-Positive Scenarios |
|---|---|:---:|:---:|---|---|---|
| **31** | `has_url_shortener` | `bool` | **Active** | True if any URL domain matches an entry in the offline versioned shortener registry (see Section 9.2). | Always evaluable (`False` if no URLs). | Legitimate marketing campaigns, SMS-to-email notifications, Twitter/social digests. |
| **32** | `url_shortener_count` | `int` | **Active** | Total count of URLs matching offline shortener registry. | Always evaluable (`0` if no URLs). | Marketing newsletters using custom branded shorteners. |
| **33** | `has_redirect_parameter` | `bool` | **Active** | True if query string contains known redirect keys: `url=`, `redirect=`, `dest=`, `target=`, `goto=`, etc. | Always evaluable (`False` if no URLs). | Legitimate single-sign-on (SSO), OAuth `redirect_uri=`, and email tracking unsubscribe links. |
| **34** | `has_anchor_url_mismatch` | `bool` | **Active** | True if anchor text displays a URL/domain whose PSL domain mismatches `href` target PSL domain. When either anchor or target has `DomainResolutionStatus` outside `{EXACT_MATCH, WILDCARD_MATCH, EXCEPTION_MATCH}`, falls back to case-insensitive FQDN comparison. | Always evaluable (`False` if no URLs). | Click-tracking redirectors in legitimate corporate marketing platforms (SendGrid, Mailchimp). |
| **35** | `anchor_url_mismatch_count` | `int` | **Active** | Count of HTML hyperlinks with deceptive anchor text. | Always evaluable (`0` if no URLs). | Multiple tracked links in legitimate marketing newsletters. |
| **36** | `has_sender_domain_mismatch_url` | `Optional[bool]` | **Active** | `True` if $N_{\text{match}} < N_{\text{resolvable}}$ (at least one resolvable URL occurrence mismatches From PSL domain). `False` if $N_{\text{match}} == N_{\text{resolvable}}$ (every resolvable URL occurrence matches). `None` if no URLs, `from_address` unparseable/unresolvable, or $N_{\text{resolvable}} = 0$. Evaluated across all extracted URL occurrences (Section 5.8). | `None` if preconditions unmet. | Corporate emails with third-party footer links (social media icons, unsubscribe handlers). |
| **37** | `sender_domain_matching_url_ratio` | `Optional[float]` | **Active** | $\frac{N_{\text{match}}}{N_{\text{resolvable}}}$ evaluated across all extracted URL occurrences (Section 5.8). Range [0.0, 1.0]. | `None` if no URLs, `from_address` unparseable/unresolvable, or $N_{\text{resolvable}} = 0$. | Newsletters linking exclusively to partner resources. |
| **38** | `external_link_ratio` | `Optional[float]` | **Active** | Ratio of resolvable external non-sender URL occurrences to total resolvable URL occurrences: $\frac{N_{\text{resolvable}} - N_{\text{match}}}{N_{\text{resolvable}}} = 1.0 - \text{sender\_domain\_matching\_url\_ratio}$. Excludes IP literals, unknown suffixes, and malformed hostnames (Section 5.8). Range [0.0, 1.0]. | `None` if `sender_domain_matching_url_ratio` is `None`. | Educational digests or curated industry reading lists. |
| **39** | `has_form_action_url` | `Optional[bool]` | **Quarantined** | True if URL originated from `<form action="...">`. | **Quarantined** (`None`). | **Unsupported by Ingestion**: `URLSource.HTML_OTHER` conflates `<form action>` with `<link href>`. |

### 5.5 Punycode Detection Algorithm (Feature 16 — Hostname-Only)

Feature 16 (`has_punycode_url`) uses a two-pronged, hostname-only detection algorithm:

**Prong 1 — Normalized Hostname Inspection**:
- For each `ExtractedURL`, inspect `ExtractedURL.hostname`.
- If `hostname` is `None` or empty, skip this URL (contributes `False`).
- Split hostname by `.` into labels.
- If any label starts with `xn--` (case-insensitive), this URL has Punycode.

**Prong 2 — Raw Hostname Inspection**:
- Extract the raw hostname from `ExtractedURL.original_url` using `urllib.parse.urlsplit(original_url).hostname`.
- If extraction fails or hostname is `None`, skip (contributes `False`).
- If any character in the raw hostname satisfies `ord(c) > 127`, this URL has internationalized encoding.

**Critical constraint**: Non-ASCII characters in the **path**, **query**, or **fragment** of `original_url` do **not** trigger `has_punycode_url`. Only hostname-portion characters are inspected. Non-ASCII in path/query is captured separately by Feature 28 (`has_non_ascii_url`).

**Aggregate**: `has_punycode_url = True` if any URL satisfies either prong. `False` otherwise.

### 5.6 URL and Domain Deduplication Identity Semantics

Exact unique URL and domain counting requires retaining sets of previously observed identities during the aggregation pass.

#### 5.6.1 Unique URL Identity (`unique_url_count`, Feature 2)
- Identity key = `normalized_url` if present and non-empty, else `original_url.strip()`.
- Two `ExtractedURL` instances with identical identity keys are counted as one unique URL regardless of differing `source` or `anchor_text`.

#### 5.6.2 Heterogeneous Unique Domain Identity (`unique_domain_count`, Feature 20)
`unique_domain_count` measures the count of distinct **heterogeneous domain-level identities** across all extracted URLs. Because the input may contain a mixture of public internet domains, raw IP literals, and unrecognized domain suffixes, the agent constructs identity keys from three heterogeneous sources:
1. **PSL-Resolved Registered Domains**: For URLs whose `DomainResolutionStatus` is `EXACT_MATCH`, `WILDCARD_MATCH`, or `EXCEPTION_MATCH`, the identity key is the lowercased PSL registered domain (e.g., `paypal.com` for `login.paypal.com`, or `bbc.co.uk` for `news.bbc.co.uk`).
2. **Normalized IP Literals**: For URLs whose hostname parses as an IPv4 or IPv6 address literal (`IP_LITERAL`), the identity key is the canonical string representation produced by `ipaddress.ip_address(host)` (e.g., `192.168.1.1` or `2001:db8::1`). Port numbers and paths do not alter the IP identity key.
3. **Full Hostnames for Unknown Suffixes**: For URLs whose `DomainResolutionStatus` is `UNKNOWN_SUFFIX` (valid hostname structure, but the suffix is absent from the bundled PSL snapshot, such as internal enterprise TLDs `.corp`, `.lan`, `.local`), the identity key is the lowercased full FQDN hostname (e.g., `wiki.corp.internal`).
4. **Excluded Categories**: URLs with `INVALID_HOSTNAME` or `NO_HOSTNAME` (such as `data:`, `javascript:`, or `file:` schemes) are excluded from domain counts entirely.

> [!IMPORTANT]
> **Operational Caveat on Heterogeneous Domain Counting**: Hostnames with unknown suffixes are **NOT** PSL-registered domains. Because the agent cannot safely determine where the organizational boundary lies without an authoritative suffix rule, it falls back to the full FQDN. Consequently, two different subdomains of an unknown suffix (e.g., `auth.internal.corp` and `mail.internal.corp`) are counted as **two distinct domain identities**. This design choice prevents speculative boundary guessing while providing a consistent, deterministic count.

#### 5.6.3 Unique FQDN Identity (`unique_fqdn_count`, Feature 21)
- Identity key = lowercased hostname string from `ExtractedURL.hostname`.
- IP literals are excluded from FQDN counts.
- URLs with `None` or empty hostname are excluded.

### 5.7 Malformed URL Validation (Feature 30 — Structural Syntax Validation)

`malformed_url_count` (Feature 30) counts URLs that fail **structural syntax validation**. This is explicitly labelled as structural syntax validation, not strict RFC 3986 conformance, because `urllib.parse.urlsplit` is intentionally permissive.

A URL increments `malformed_url_count` if any of the following five conditions is detected:

1. **`urlsplit` parsing exception**: Calling `urllib.parse.urlsplit(original_url)` raises a `ValueError` (e.g., unclosed IPv6 bracket notation `http://[::1/path`).
2. **Malformed port exception via `SplitResult.port`**: Accessing the `.port` property on a successful `urlsplit` result raises a `ValueError`. In Python's standard library, this occurs when the port string is non-numeric (e.g., `http://example.com:abc/path`) or exceeds the standard integer range (e.g., `http://example.com:99999/path`).
3. **Invalid integer port value**: The port is successfully parsed as an integer, but falls outside the valid TCP/UDP port range 1–65535 (specifically port 0: `http://example.com:0/path`).
4. **Missing authority for web schemes**: The URL specifies a network-based web scheme (`http`, `https`, `ftp`), but the authority/hostname component is `None` or an empty string (e.g., `http:///path/only`).
5. **Invalid percent-encoding sequences**: The URL string contains a `%` character that is not followed by exactly 2 hexadecimal digits (`[0-9a-fA-F]`), indicating a broken percent-escape sequence (e.g., `http://example.com/%GG/path` or a trailing `%`).

```python
def validate_url_syntax(url_str: str) -> tuple[bool, list[str]]:
    """
    Validate URL structural syntax across 5 distinct failure conditions.
    Returns: (is_malformed: bool, failure_reasons: list[str])
    """
    reasons = []
    
    # Condition 1: urlsplit parsing exception
    try:
        parts = urllib.parse.urlsplit(url_str)
    except ValueError as e:
        reasons.append(f"urlsplit_exception: {e}")
        return True, reasons  # Cannot proceed with further component checks

    # Condition 2 & 3: Port validation
    try:
        port = parts.port
        if port is not None and port < 1:
            reasons.append(f"invalid_port_range: port {port} outside 1-65535")
    except ValueError as e:
        reasons.append(f"malformed_port_syntax: {e}")

    # Condition 4: Missing authority for web schemes
    if parts.scheme in ("http", "https", "ftp"):
        if not parts.hostname:
            reasons.append(f"missing_authority_for_scheme: scheme '{parts.scheme}' requires non-empty host")

    # Condition 5: Invalid percent-encoding
    if "%" in url_str:
        # Match '%' NOT followed by two hex digits
        if re.search(r"%(?![0-9a-fA-F]{2})", url_str):
            reasons.append("invalid_percent_encoding_sequence")

    is_malformed = len(reasons) > 0
    return is_malformed, reasons
```

> [!IMPORTANT]
> **Single Bounded Increment Guarantee**: Each URL increments `malformed_url_count` **at most once**, even if multiple failure conditions are simultaneously present (e.g., a URL with both an out-of-range port and a broken percent-escape increments the count by 1). However, the Tier 2 evidence collection logs each distinct failure reason for full forensic traceability.

### 5.8 Sender Domain Alignment — Precise Ratio Semantics (Features 36–38)

The sender domain alignment features compare extracted URL domains against the sender's From header domain. Both sides use PSL registered domain resolution.

#### 5.8.1 Occurrence-Based Counting Semantics
For the MVP, all sender alignment calculations are strictly **occurrence-based**:
- $N_{\text{resolvable}}$: Count of **all extracted URL occurrences** across `email_data.extracted_urls` whose `DomainResolutionStatus` is strictly in `{EXACT_MATCH, WILDCARD_MATCH, EXCEPTION_MATCH}`.
- $N_{\text{match}}$: Count of **all extracted URL occurrences** within $N_{\text{resolvable}}$ whose PSL registered domain matches the From PSL registered domain (case-insensitive).
- **Repeated Occurrences**: Each URL occurrence contributes independently. If an identical sender-domain link appears 3 times in an email (e.g. navigation header, main body button, and unsubscribe footer), it increments $N_{\text{match}}$ by 3 and $N_{\text{resolvable}}$ by 3. This reflects the link volume distribution encountered by the recipient rather than collapsed unique destinations.
- **Excluded Categories**: URLs whose resolution status is `UNKNOWN_SUFFIX`, `IP_LITERAL`, `INVALID_HOSTNAME`, or `NO_HOSTNAME` are **excluded from both numerator and denominator**.

#### 5.8.2 Mathematical Formulation

$$\text{sender\_domain\_matching\_url\_ratio} = \begin{cases} 
\text{None}, & \text{if } N_{\text{resolvable}} = 0 \lor \text{from\_domain is unresolvable} \\
\frac{N_{\text{match}}}{N_{\text{resolvable}}}, & \text{if } N_{\text{resolvable}} > 0 \land \text{from\_domain is resolvable}
\end{cases}$$

$$\text{external\_link\_ratio} = \begin{cases} 
\text{None}, & \text{if } \text{sender\_domain\_matching\_url\_ratio is None} \\
\frac{N_{\text{resolvable}} - N_{\text{match}}}{N_{\text{resolvable}}} = 1.0 - \text{sender\_domain\_matching\_url\_ratio}, & \text{otherwise}
\end{cases}$$

$$\text{has\_sender\_domain\_mismatch\_url} = \begin{cases} 
\text{None}, & \text{if } N_{\text{resolvable}} = 0 \lor \text{from\_domain is unresolvable} \\
\mathbf{True}, & \text{if } N_{\text{match}} < N_{\text{resolvable}} \\
\mathbf{False}, & \text{if } N_{\text{match}} = N_{\text{resolvable}}
\end{cases}$$

> [!NOTE]
> **Design Rationale for `has_sender_domain_mismatch_url` Semantics**: In earlier drafts (v1.1–v1.4), this feature was formulated as `True` if $N_{\text{match}} == 0$. That represented an "all URLs mismatch" condition. The updated definition `N_match < N_resolvable` aligns directly with the feature's name: it evaluates to `True` whenever at least one resolvable URL points to a domain outside the sender's registered domain (i.e. the email *has a sender-domain mismatch URL*). If all resolvable links match the sender ($N_{\text{match}} == N_{\text{resolvable}}$), it evaluates to `False`.

#### 5.8.3 Worked Examples

**Example 1: Repeated Sender Occurrences with One Mismatching Link**
- Header `From: billing@company.com` (PSL domain: `company.com`)
- Occurrence 1: `https://company.com/invoice/1` (PSL: `company.com` $\to$ match)
- Occurrence 2: `https://company.com/invoice/1` (PSL: `company.com` $\to$ match)
- Occurrence 3: `https://company.com/portal` (PSL: `company.com` $\to$ match)
- Occurrence 4: `https://external.org/test` (PSL: `external.org` $\to$ mismatch)
- **Results**:
  - $N_{\text{resolvable}} = 4$
  - $N_{\text{match}} = 3$
  - `sender_domain_matching_url_ratio = 3 / 4 = 0.75`
  - `external_link_ratio = (4 - 3) / 4 = 1.0 - 0.75 = 0.25`
  - `has_sender_domain_mismatch_url = True` (because $N_{\text{match}} < N_{\text{resolvable}}$, i.e. $3 < 4$)

**Example 2: All Resolvable Links Match Sender Domain**
- Header `From: billing@company.com` (PSL domain: `company.com`)
- Occurrence 1: `https://company.com/invoice/1` (PSL: `company.com` $\to$ match)
- Occurrence 2: `https://company.com/invoice/1` (PSL: `company.com` $\to$ match)
- Occurrence 3: `https://company.com/portal` (PSL: `company.com` $\to$ match)
- Occurrence 4: `https://company.com/help` (PSL: `company.com` $\to$ match)
- **Results**:
  - $N_{\text{resolvable}} = 4$
  - $N_{\text{match}} = 4$
  - `sender_domain_matching_url_ratio = 4 / 4 = 1.0`
  - `external_link_ratio = (4 - 4) / 4 = 0.0`
  - `has_sender_domain_mismatch_url = False` (because $N_{\text{match}} == N_{\text{resolvable}}$, i.e. $4 == 4$)

> [!CAUTION]
> **Explicit Caveat on External Resolvable Link Ratio**: `external_link_ratio` measures the proportion of external domains **strictly among resolvable URLs**. It does not measure the proportion of external links across all raw URLs. For example, if an email has 10 URLs where 5 are IP literals (`http://192.168.1.1/`) and 5 point to the sender's domain (`https://company.com/`):
> - $N_{\text{resolvable}} = 5$ (the 5 IP literals are excluded because IP addresses are not registered domains).
> - $N_{\text{match}} = 5$.
> - `sender_domain_matching_url_ratio = 5 / 5 = 1.0`.
> - `external_link_ratio = 1.0 - 1.0 = 0.0`.
> - `has_sender_domain_mismatch_url = False`.
>
> The non-resolvable IP links are not lost; they are independently captured by Category B features (`has_ip_literal_url`, `has_private_ip_url`). Downstream models must consume both feature categories together.

### 5.9 Feature Disposition Summary

| Status | Feature Identifiers | Count | Rationale |
|---|---|:---:|---|
| **Active — Eligible for Experimental Evaluation** | 1–3, 5–26, 28–38 | **36** | Structurally supported and deterministic under offline execution. Requires experimental evaluation before deployment claims. |
| **Quarantined** | 4 (`http_url_count`) | **1** | Severe temporal confounding (2002 SpamAssassin ham links are predominantly HTTP). |
| **Quarantined** | 27 (`has_brand_in_path`) | **1** | Requires a curated, versioned brand registry with documented matching algorithm, authority-vs-path comparison rules, and false-positive analysis before activation. |
| **Quarantined** | 39 (`has_form_action_url`) | **1** | Ingestion contract limitation: `URLSource.HTML_OTHER` conflates forms and links. |
| **Renamed** | Feature 8 (formerly `has_non_standard_port`) | — | Renamed to `has_non_default_port` to clarify scheme-default mapping. |
| **Renamed** | Feature 24 (formerly `has_hex_encoded_url`) | — | Renamed to `has_percent_encoding` to match RFC 3986 terminology. |
| **Added** | Feature 2 (`unique_url_count`) | — | Distinguishes total extracted occurrences from distinct normalized URLs. |
| **Total Features** | Continuous 1..39 | **39** | Audited canonical feature registry (36 active, 3 quarantined). |

> [!IMPORTANT]
> **Quarantine Requirements for `has_brand_in_path` (Feature 27)**: This feature remains quarantined until the following prerequisites are met:
> 1. A curated brand registry with explicit provenance and versioning (e.g., `BRAND-REGISTRY-v1-2026-11`).
> 2. A documented matching algorithm specifying exact string comparison, case normalization, and token boundary rules.
> 3. Authority-vs-path comparison rules: the feature must only fire when the brand token appears in the path/query and the URL's PSL registered domain does NOT match the brand's known domain.
> 4. False-positive analysis demonstrating acceptable precision on the development corpus.

---

## 6. Tier 2 Forensic Evidence & Audit Model

### 6.1 Principles of Forensic Evidence
1. **Traceable Origin**: Every evidence item records the exact `url_index` in `EmailData.extracted_urls` and source context.
2. **Deterministic Ordering**: Evidence items are sorted deterministically by `(url_index, feature_name, finding_id)` — this ordering is consistent across the pipeline diagram (Section 4 Stage 6), this section, and the output contract.
3. **Capped Collection with Accounting**: Maximum 100 evidence items are returned (`max_length=100`). If more are generated, `omitted_evidence_count` records the exact number omitted.
4. **Aggregate Coverage Guarantee**: Capping evidence items does NOT cap feature extraction; aggregate feature calculations (e.g. `total_url_count`, `unique_domain_count`, `has_ip_literal_url`) stream over 100% of URLs in the email.
5. **Sanitized Verbatim Snippets**: Raw URL excerpts are truncated to a maximum of 256 characters (`max_length=256`), with all non-printable ASCII and control characters (`\r`, `\n`, `\t`) strictly escaped.
6. **No Automatic Phishing Verdicts**: An observed anomaly (such as an IP literal or anchor mismatch) constitutes *evidence requiring investigation*, never an automated guilty verdict.
7. **Transparent Benign Explanations**: Every evidence item includes standard operational limitations and benign contexts where the pattern legitimately appears.

### 6.2 Proposed Evidence Data Contracts

```python
class UrlEvidenceItem(BaseModel):
    """
    Forensic trace linking an observed URL anomaly or characteristic
    to its specific source URL in EmailData.extracted_urls.
    """
    finding_id: str = Field(description="Unique finding identifier (e.g. 'url_ev_001').")
    feature_name: CANONICAL_URL_FEATURE_NAMES = Field(description="The canonical 39-feature identifier.")
    category: str = Field(description="Category A, B, C, or D.")
    url_index: int = Field(ge=0, description="0-indexed position within EmailData.extracted_urls.")
    source: URLSource = Field(description="Extraction source location (HTML_HREF, PLAIN_TEXT, etc.).")
    observed_value: str = Field(max_length=256, description="Specific anomalous value observed.")
    description: str = Field(max_length=500, description="Human-readable explanation of why this observation matters.")
    limitations_and_benign_explanations: str = Field(
        max_length=500,
        description="Plausible benign reasons for this pattern (e.g. tracking links, intranet servers).",
    )
    raw_snippet_bounded: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Sanitized verbatim URL or anchor excerpt (max 256 chars, control characters escaped).",
    )

    model_config = {"extra": "forbid"}


class UrlEvidence(BaseModel):
    """Container for audit evidence and forensic traces supporting URL feature values."""
    evidence_items: list[UrlEvidenceItem] = Field(
        default_factory=list,
        max_length=100,
        description="Traceable forensic evidence items (validated to max 100).",
    )
    omitted_evidence_count: int = Field(
        default=0,
        ge=0,
        description="Number of evidence items omitted due to the 100-item safety cap.",
    )
    detected_anomalous_hostnames: list[str] = Field(
        default_factory=list,
        max_length=50,
        description="Bounded list of anomalous hostnames (IPs, Punycode, malformed) found across URLs.",
    )
    detected_shorteners: list[str] = Field(
        default_factory=list,
        max_length=50,
        description="Distinct shortener domains detected (max 50).",
    )
    observed_anomalies: list[str] = Field(
        default_factory=list,
        max_length=100,
        description="High-level human-readable anomaly summary descriptions (max 100).",
    )

    model_config = {"extra": "forbid"}
```

---

## 7. Proposed Pydantic Output Contracts

### 7.1 Per-URL Analysis Container (`UrlAnalysisItem`)
To support forensic drilling and transparency in the dashboard, the agent maintains an internal per-URL breakdown before aggregation:

```python
class UrlAnalysisItem(BaseModel):
    """Granular static inspection record for a single extracted URL."""
    url_index: int = Field(ge=0)
    original_url_snippet: str = Field(max_length=256)
    source: URLSource
    anchor_text_snippet: Optional[str] = Field(default=None, max_length=128)
    scheme: Optional[str]
    hostname: Optional[str]
    registered_domain: Optional[str]
    domain_resolution_status: Optional[str]  # DomainResolutionStatus value
    port: Optional[int]
    path: Optional[str]
    has_ip_hostname: bool
    ip_classification: Optional[str]  # 'rfc1918', 'rfc4193', 'syntactically_global', 'loopback', 'link_local', etc.
    is_punycode: bool
    is_url_shortener: bool
    has_redirect_parameter: bool
    has_anchor_mismatch: bool
    hostname_entropy: Optional[float]
    url_length: int
    is_malformed: bool  # True if this URL failed structural syntax validation
    malformed_reasons: list[str] = Field(default_factory=list)

    model_config = {"extra": "forbid"}
```

### 7.2 Top-Level Agent Contract (`UrlAgentResult`)

Aligned with project standards (no probability scores in Layer 1):

```python
class UrlAgentResult(BaseModel):
    """
    Complete output payload of the URL Agent.
    Serialized and passed to the Evidence Aggregation Layer.
    """
    email_id: str = Field(description="Unique email identifier matching EmailData.email_id.")
    agent_name: str = Field(default="url_agent", description="Identifier of the emitting agent.")
    agent_version: str = Field(default="0.1.0", description="Semantic version of agent specification.")
    status: str = Field(default="success", description="Execution outcome: 'success', 'partial', or 'error'.")
    processing_time_ms: float = Field(ge=0.0, default=0.0, description="Elapsed processing time in milliseconds.")
    total_urls_extracted: int = Field(ge=0, description="Count of URLs analyzed from email_data.extracted_urls.")
    features: UrlFeatures = Field(description="Sanitized Tier 3 feature vector (canonical 39 features).")
    availability: UrlFeatureAvailability = Field(description="Per-feature missingness manifest.")
    evidence: UrlEvidence = Field(description="Tier 2 forensic evidence and audit trails.")
    per_url_analyses: list[UrlAnalysisItem] = Field(
        default_factory=list,
        max_length=200,
        description="Per-URL granular inspection records (capped at 200 for digest safety).",
    )
    warnings: list[str] = Field(default_factory=list, description="Non-fatal data quality warnings.")
    limitations: list[str] = Field(
        default_factory=list,
        description="Explicit operational caveats (e.g. offline analysis limitations).",
    )

    model_config = {"extra": "forbid"}
```

---

## 8. Public Suffix List (PSL) Resolution & Domain Decomposition

### 8.1 PSL Snapshot Strategy

The URL Agent uses a bundled, immutable static snapshot of the Mozilla Public Suffix List for registered domain decomposition. This ensures:
- **Zero network activity** at runtime.
- **Deterministic behavior** across all environments.
- **Reproducible analysis** results.

**Snapshot Provenance**:
- **Source**: Mozilla Public Suffix List (https://publicsuffix.org/list/)
- **License**: Mozilla Public License 2.0 (MPL-2.0)
- **Version Tag**: `PSL-Snapshot-2026-11`
- **Integrity**: SHA-256 hash of the snapshot file recorded in a companion `.sha256` file
- **Location**: `app/data/public_suffix_list.dat`
- **Companion**: `app/data/public_suffix_list.sha256`

**Offline Developer Update Procedure**:
A developer script (`scripts/update_psl_snapshot.py`) performs the following:
1. Downloads the latest PSL from `https://publicsuffix.org/list/public_suffix_list.dat`.
2. Computes and records the SHA-256 hash.
3. Updates the version tag with a date-stamped identifier.
4. Runs the full test suite to verify no regressions.
5. Commits both files with a descriptive message.

This script is run manually by developers and is never invoked at runtime.

### 8.2 Domain Resolution Status

Every hostname processed through PSL resolution produces an explicit `DomainResolutionStatus`:

```python
class DomainResolutionStatus(str, Enum):
    """Explicit outcome of PSL-based registered domain resolution."""
    EXACT_MATCH = "exact_match"          # Hostname suffix exactly matches a PSL rule
    WILDCARD_MATCH = "wildcard_match"    # Hostname suffix matches a PSL wildcard rule (e.g. *.ck)
    EXCEPTION_MATCH = "exception_match"  # Hostname matches a PSL exception rule (e.g. !www.ck)
    UNKNOWN_SUFFIX = "unknown_suffix"    # Hostname has a valid structure but suffix is not in PSL snapshot
    INVALID_HOSTNAME = "invalid_hostname"  # Hostname fails structural validation (empty, whitespace-only, etc.)
    IP_LITERAL = "ip_literal"            # Hostname is an IPv4 or IPv6 address literal
    NO_HOSTNAME = "no_hostname"          # URL has no hostname component (e.g. data: URIs, mailto:)
```

**Resolution behavior by status**:

| Status | `registered_domain` | `subdomain_depth` | Sender Alignment ($N_{\text{resolvable}}$) | Anchor Mismatch | `unique_domain_count` Key |
|---|---|---|---|---|---|
| `EXACT_MATCH` | PSL-resolved domain | Computed from labels | Included | Uses PSL domain comparison | Lowercased PSL domain |
| `WILDCARD_MATCH` | PSL-resolved domain | Computed from labels | Included | Uses PSL domain comparison | Lowercased PSL domain |
| `EXCEPTION_MATCH` | PSL-resolved domain | Computed from labels | Included | Uses PSL domain comparison | Lowercased PSL domain |
| `UNKNOWN_SUFFIX` | `None` | `None` | **Excluded** | Falls back to FQDN comparison | Lowercased full FQDN |
| `INVALID_HOSTNAME` | `None` | `None` | **Excluded** | Not evaluated | **Excluded** (no domain key) |
| `IP_LITERAL` | `None` | `None` | **Excluded** | Uses IP string comparison | Normalized IP string |
| `NO_HOSTNAME` | `None` | `None` | **Excluded** | Not evaluated | **Excluded** (no domain key) |

> [!CAUTION]
> The v1.1.0 "deterministic right-split fallback" for unknown suffixes has been removed. Right-splitting (e.g., treating the rightmost two labels as the registered domain) produces incorrect results for multi-part country-code TLDs such as `.co.uk`, `.com.au`, `.co.jp`. When the PSL snapshot does not contain a suffix, the status is explicitly `UNKNOWN_SUFFIX`, and `registered_domain` is `None`. This avoids silent misclassification at the cost of reduced granularity for unrecognized TLDs.

---

## 9. Security Invariants and Scope Limitations

| Security Invariant | Operational Rule | Failure / Edge-Case Handling |
|---|---|---|
| **Zero Network Activity** | The agent must never call `socket.gethostbyname`, `urllib.request`, `requests`, `aiohttp`, or `dns.resolver`. | Enforced by design; no networking libraries are imported. Tests will verify execution within a network-isolated sandbox. |
| **Static vs. Dynamic Distinction** | The agent flags *lexical indicators of potential redirection* (e.g. `?url=http://...`); it **never claims a URL actually redirects** because no server response has been retrieved. | Finding descriptions explicitly use bounded terminology: `"URL query string contains redirect parameter 'url'; actual redirection not verified offline."` |
| **No Domain Reputation Blacklists** | The agent never labels a domain as malicious based on hardcoded domain lists from the training corpus. | Registries are limited strictly to protocol standards (PSL) and well-known shortener service definitions (versioned, with provenance). |
| **Safe Parsing of Malformed URLs** | URLs with unescaped brackets, invalid ports, or illegal characters must not cause unhandled exceptions. | Caught via `validate_url_syntax()` and `urllib.parse.urlsplit` try-except blocks; malformed URLs increment `malformed_url_count` at most once and generate Tier 2 evidence items. |
| **Digest Bomb Protection** | Emails with thousands of URLs (e.g. SpamAssassin `hard_ham` digests with 3,134 URLs) must not exhaust system memory. | Per-URL detailed inspection records (`per_url_analyses`) are capped at the first 200 URLs; aggregate counts (`total_url_count`, `unique_domain_count`) process all URLs. Note: uniqueness tracking sets grow with N (see Section 12.1). |

### 9.1 Exact, Version-Independent IP Classification Semantics

#### 9.1.1 Supported Python Runtime & Version Considerations
- **Supported Project Runtime**: **Python 3.11, 3.12, and 3.13** (Reference verification baseline: **Python 3.13.2**).
- **Runtime Dependency Realities**: The Python standard library `ipaddress` module has exhibited version-specific changes across point releases:
  - In Python 3.10 and earlier, `IPv4Address.is_private` mistakenly treated `100.64.0.0/10` (CGNAT) as private (resolved in Python 3.11 via bpo-61602).
  - In Python 3.11 through 3.13, `is_global` evaluates a composite expression (`not (is_private or is_reserved or is_loopback or is_link_local or is_multicast or is_unspecified)`), but internal classification of ranges like `192.0.0.0/24`, `198.18.0.0/15`, `2001:2::/48`, and 6to4 have shifted between CPython versions.
  - Future Python releases (Python 3.14+) may alter `is_global` or `is_reserved` definitions as IANA updates its registries.
- **Mandatory Policy**: **Do not rely dynamically on `ip.is_global` as a classification fallback.** The URL Agent implements an explicit, versioned table of network ranges with longest-prefix exception matching to guarantee 100% identical classification across all supported Python releases.

#### 9.1.2 Registry Provenance & Dual-Date Recording (Finding 2 & 3)
The classification table is constructed from the authoritative IANA Special-Purpose Address Registries:
- **IPv4 Registry**: `https://www.iana.org/assignments/iana-ipv4-special-registry`
  - *Source Registry Last Updated*: **2025-10-09**
  - *Project Snapshot Capture Date*: **November 15, 2026**
- **IPv6 Special-Purpose Registry**: `https://www.iana.org/assignments/iana-ipv6-special-registry`
  - *Source Registry Last Updated*: **2025-10-09**
  - *Project Snapshot Capture Date*: **November 15, 2026**
- **IPv6 Address Space Registry (Core Multicast Attribution)**: `https://www.iana.org/assignments/ipv6-address-space`
  - *Governing Standard*: RFC 4291 (IP Version 6 Addressing Architecture)

> [!NOTE]
> The project retrieval/snapshot date (**November 15, 2026**) records when the static rules were verified and frozen in the repository. The source registry publication date (**October 9, 2025**) represents the upstream IANA release date. Neither date should be confused with individual RFC publication or deprecation dates (e.g. 2014-03 termination for `2001:10::/28`, or August 2024 publication for RFC 9665).

#### 9.1.3 IANA Source Values vs. Project-Derived Classification Taxonomy (Findings 1 & 5)
To ensure analytical clarity and rigorous provenance, authoritative IANA registry values are kept strictly distinct from the URL Agent's derived classifications:
- **IANA Registry Values**: The IANA registries record administrative allocations and define `"Globally Reachable"` as `True`, `False`, `N/A`, or `[Blank]` (e.g. expired allocations).
  - **Administrative Scope vs. Internet Routability (Finding 5)**: The IANA `"Globally Reachable"` field describes whether an address is suitable for forwarding across the public Internet and beyond a specified administrative domain (per RFC 6890 and RFC 8190). It does **not** provide any guarantee of actual public BGP route announcements, active host allocation, operational routing policies, or live endpoint reachability.
- **Project Derived Classification**:
  - **`syntactically_global`**: Mapped from IANA allocations with explicit `Globally Reachable: True` (such as `192.0.0.9`, `192.0.0.10`, `2001:1::1..3`, `2001:20::/28`, `2001:30::/28`, and `64:ff9b::/96`). This classification indicates only that an IP address has the syntactic format of a global unicast address outside reserved or special-purpose ranges. It is a static structural property, not an empirical reachability test, and does **not** trigger anomaly alerts (`has_special_ip_url = False`).
  - **`special_purpose`**: Mapped from:
    1. IANA allocations with explicit `Globally Reachable: False` (such as parent `2001::/23`, Benchmarking `2001:2::/48`, SRv6 `5f00::/16`, Local Translation `64:ff9b:1::/48`, NAT64 Discovery `192.0.0.170/32`, Service Continuity `192.0.0.0/29`, and Dummy Address `192.0.0.8/32`).
    2. Allocations with `Globally Reachable: N/A` (such as TEREDO `2001::/32` and 6to4 `2002::/16`).
    3. Allocations with `[Blank]` reachability (such as expired deprecated prefix `2001:10::/28`).
  - **Conservative Fail-Closed Rule**: Under the URL Agent's offline static forensic policy, an IP address is classified as `syntactically_global` **only** if the authoritative IANA registry explicitly certifies `Globally Reachable: True`. All unassigned, ambiguous (`N/A`), deprecated (`[Blank]`), or non-global (`False`) allocations default to `special_purpose` to ensure full forensic visibility.

#### 9.1.4 Authoritative Allocations within `192.0.0.0/24` (IPv4)

Within the `192.0.0.0/24` block (RFC 6890, IETF Protocol Assignments), the URL Agent evaluates addresses in longest-prefix priority order against the following exhaustive table:

| Prefix | Allocation Name | RFC Attribution | IANA Globally Reachable | Project Classification | Policy Rationale |
|---|---|:---:|:---:|:---:|---|
| `192.0.0.0/29` | IPv4 Service Continuity Prefix | RFC 7335 | **False** | `special_purpose` | IANA Explicit False; DS-Lite / NAT444 transition |
| `192.0.0.8/32` | IPv4 Dummy Address | RFC 7600 | **False** | `special_purpose` | IANA Explicit False; dummy routing target |
| `192.0.0.9/32` | Port Control Protocol (PCP) Anycast | RFC 7723 | **True** | `syntactically_global` | More-specific override (IANA True) |
| `192.0.0.10/32` | TURN Anycast | RFC 8155 | **True** | `syntactically_global` | More-specific override (IANA True) |
| `192.0.0.170/32` | NAT64/DNS64 Discovery | RFC 7050, RFC 8880 | **False** | `special_purpose` | IANA Explicit False; local discovery only |
| `192.0.0.171/32` | NAT64/DNS64 Discovery | RFC 7050, RFC 8880 | **False** | `special_purpose` | IANA Explicit False; local discovery only |
| `192.0.0.0/24` (remainder) | IETF Protocol Assignments | RFC 6890 | **False** | `special_purpose` | Parent prefix default for unallocated protocol space |

> [!NOTE]
> **Exhaustiveness Statement**: This table is **exhaustive** for all sub-allocations within `192.0.0.0/24` recorded in the authoritative IANA IPv4 Special-Purpose Address Registry as of the October 9, 2025 release (snapshot captured November 15, 2026).

#### 9.1.5 Authoritative Allocations within `2001::/23` (IPv6)

The `2001::/23` block (`2001:0000::/23` through `2001:01ff:ffff:ffff:ffff:ffff:ffff:ffff`) is allocated to the IETF for protocol assignments (RFC 2928). The URL Agent resolves addresses in this block using longest-prefix matching against the following authoritative table:

| Prefix | Allocation Name | RFC Attribution | IANA Globally Reachable | Project Classification | Policy Rationale |
|---|---|:---:|:---:|:---:|---|
| `2001:1::1/128` | Port Control Protocol (PCP) Anycast | RFC 7723 | **True** | `syntactically_global` | More-specific override (IANA True) |
| `2001:1::2/128` | TURN Anycast | RFC 8155 | **True** | `syntactically_global` | More-specific override (IANA True) |
| `2001:1::3/128` | DNS-SD Service Registration Protocol Anycast | RFC 9665 | **True** | `syntactically_global` | More-specific override (RFC 9665, IANA True) |
| `2001:3::/32` | Automatic Multicast Tunneling (AMT) | RFC 7450 | **True** | `syntactically_global` | More-specific override (IANA True) |
| `2001:4:112::/48` | AS112-v6 | RFC 7535 | **True** | `syntactically_global` | More-specific override (IANA True) |
| `2001:20::/28` | ORCHIDv2 | RFC 7343 | **True** | `syntactically_global` | More-specific override (IANA True) |
| `2001:30::/28` | Drone Remote ID Protocol Entity Tags | RFC 9374 | **True** | `syntactically_global` | More-specific override (IANA True) |
| `2001::/32` | TEREDO | RFC 4380, RFC 8190 | **N/A** | `special_purpose` | Conservative policy: encapsulation tunneling |
| `2001:2::/48` | Benchmarking | RFC 5180 | **False** | `special_purpose` | IANA Explicit False; benchmark testing |
| `2001:10::/28` | Deprecated (Sub-TLA) | RFC 4843, RFC 7343 | **[Blank]** (Term. 2014-03) | `special_purpose` | Conservative policy: expired/deprecated allocation |
| `2001::/23` (remainder) | IETF Protocol Assignments | RFC 2928 | **False**<sup>*</sup> | `special_purpose` | Parent prefix default for unallocated space |

*Footnote: IANA IPv6 Special-Purpose Address Registry records Globally Reachable: False for parent prefix `2001::/23`, with footnote: "Unless allowed by a more-specific allocation."*

#### 9.1.6 Authoritative IPv6 Special-Purpose Allocations Outside `2001::/23`

The URL Agent evaluates IPv6 allocations outside `2001::/23` against the authoritative IANA IPv6 Special-Purpose Address Registry:

| Prefix | Allocation Name | RFC Attribution | Authoritative IANA Globally Reachable | Project Classification | Interaction with Global Unicast Fallback (`2000::/3`) |
|---|---|:---:|:---:|:---:|---|
| `::1/128` | Loopback Address | RFC 4291 | **False** | `loopback` | Outside `2000::/3`; Precedence 1 loopback match |
| `::/128` | Unspecified Address | RFC 4291 | **False** | `special_purpose` | Outside `2000::/3`; Precedence 6 special match |
| `::ffff:0:0/96` | IPv4-mapped Address | RFC 4291 | **False** | *(Unwrapped)* | Unwrapped to IPv4 prior to evaluation |
| `64:ff9b::/96` | IPv4-IPv6 Translation (Well-Known) | RFC 6052 | **True** | `syntactically_global` | Outside `2000::/3`; explicit Precedence 7 global match |
| `64:ff9b:1::/48` | IPv4-IPv6 Translation (Local-Use) | RFC 8215 | **False** | `special_purpose` | Outside `2000::/3`; Precedence 6 special match |
| `100::/64` | Discard-Only Address Block | RFC 6666 | **False** | `special_purpose` | Outside `2000::/3`; project classification agrees with IANA False (packets discarded) |
| `100:0:0:1::/64` | Dummy IPv6 Prefix | RFC 9780 | **False** | `special_purpose` | Outside `2000::/3`; distinct /64 subnet under 100::/16; project classification agrees with IANA False |
| `2001:db8::/32` | Documentation Prefix | RFC 3849 | **False** | `documentation` | Subnet of `2000::/3`; Precedence 4 doc override |
| `2002::/16` | 6to4 Anycast / Transition | RFC 3056, RFC 7526 | **N/A** | `special_purpose` | Subnet of `2000::/3`; Precedence 6 special override |
| `2620:4f:8000::/48` | Direct Delegation AS112 Service | RFC 7534 | **True** | `syntactically_global` | Subnet of `2000::/3`; explicit Precedence 7 global match; agrees with `2000::/3` fallback |
| `3fff::/20` | Documentation Prefix | RFC 9637 | **False** | `documentation` | Subnet of `2000::/3`; Precedence 4 doc override |
| `5f00::/16` | Segment Routing (SRv6) SIDs | RFC 8986, RFC 9602 | **False** | `special_purpose` | Outside `2000::/3`; Precedence 6 special match |
| `fc00::/7` | Unique Local Unicast (ULA) | RFC 4193 | **False** | `rfc4193` | Outside `2000::/3`; Precedence 8 ULA match |
| `fe80::/10` | Link-Local Unicast | RFC 4291 | **False** | `link_local` | Outside `2000::/3`; Precedence 2 link-local match |

> [!NOTE]
> **Exhaustiveness Statement**: The tables in Section 9.1.5 (11 sub-allocations within `2001::/23`) and Section 9.1.6 (14 allocations outside `2001::/23`) collectively provide an **exhaustive accounting of all 25 entries** recorded in the authoritative IANA IPv6 Special-Purpose Address Registry as of the October 9, 2025 release (snapshot captured November 15, 2026). Every registered prefix is evaluated explicitly in pseudocode and mapped according to authoritative IANA reachability facts and documented conservative project policy.

> [!NOTE]
> **Independent Multicast Allocation Attribution (RFC 4291)**: `ff00::/8` is the fundamental IPv6 multicast block defined in RFC 4291 and cataloged in the [IANA IPv6 Address Space Registry](https://www.iana.org/assignments/ipv6-address-space). It is not cataloged in the IANA IPv6 Special-Purpose Address Registry (which tracks unicast protocol assignments). Multicast classification is preserved independently in Precedence 3 of `classify_ip_address()` (`IPV6_MULTICAST = ipaddress.ip_network("ff00::/8")  # Core IPv6 Architecture Multicast (RFC 4291 / IANA IPv6 Address Space)`), and sets `has_special_ip_url = True` (Section 9.1.8), but is categorized based on core IPv6 architectural standards rather than special-purpose unicast registry membership.

> [!CRITICAL]
> **Prevention of `2000::/3` Misclassification**: Both `2001:db8::/32` (RFC 3849) and `3fff::/20` (RFC 9637) are documentation prefixes that reside structurally within the `2000::/3` Global Unicast block. Furthermore, `2002::/16` (6to4) also resides within `2000::/3`. Under no circumstances may an address be classified as `syntactically_global` merely because it falls within `2000::/3`. The evaluation logic enforces that Documentation (`IPV6_DOC_RANGES`) and Special-Purpose (`IPV6_SPECIAL_RANGES`) take strict precedence before the `2000::/3` unicast fallback is reached. Conversely, `64:ff9b::/96` (RFC 6052) resides outside `2000::/3` but has authoritative IANA `Globally Reachable = True`; it is explicitly matched as `syntactically_global` before the non-global fallback. Similarly, `2620:4f:8000::/48` (RFC 7534) is an explicit IANA `Globally Reachable = True` allocation that resides inside `2000::/3` and is explicitly matched in `IPV6_GLOBAL_RANGES`.

#### 9.1.7 Deterministic IP Classification Implementation

```python
# Explicit, version-independent network range definitions (IANA Snapshot: 2026-11, Source: 2025-10-09)

# IPv4 More-Specific Globally Reachable Exceptions (longest-prefix overrides within 192.0.0.0/24)
IPV4_GLOBAL_EXCEPTIONS = [
    ipaddress.ip_network("192.0.0.9/32"),   # Port Control Protocol (PCP) Anycast (RFC 7723) - IANA True
    ipaddress.ip_network("192.0.0.10/32"),  # TURN Anycast (RFC 8155) - IANA True
]

# IPv6 More-Specific Globally Reachable Overrides within 2001::/23 (IANA Globally Reachable = True)
IPV6_2001_GLOBAL_OVERRIDES = [
    ipaddress.ip_network("2001:1::1/128"),   # Port Control Protocol Anycast (RFC 7723)
    ipaddress.ip_network("2001:1::2/128"),   # TURN Anycast (RFC 8155)
    ipaddress.ip_network("2001:1::3/128"),   # DNS-SD SRP Anycast (RFC 9665)
    ipaddress.ip_network("2001:3::/32"),     # Automatic Multicast Tunneling (AMT) (RFC 7450)
    ipaddress.ip_network("2001:4:112::/48"), # AS112-v6 (RFC 7535)
    ipaddress.ip_network("2001:20::/28"),    # ORCHIDv2 (RFC 7343) - IANA True
    ipaddress.ip_network("2001:30::/28"),    # Drone Remote ID (RFC 9374) - IANA True
]

# IPv6 More-Specific Special-Purpose Overrides within 2001::/23 (IANA False, N/A, or Blank)
IPV6_2001_SPECIAL_OVERRIDES = [
    ipaddress.ip_network("2001::/32"),       # TEREDO (RFC 4380, RFC 8190) - IANA N/A
    ipaddress.ip_network("2001:2::/48"),     # Benchmarking (RFC 5180) - IANA False
    ipaddress.ip_network("2001:10::/28"),    # Deprecated Sub-TLA (RFC 4843) - IANA [Blank], Term. 2014-03
]

# IPv4 standard network blocks
IPV4_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")
IPV4_LINK_LOCAL = ipaddress.ip_network("169.254.0.0/16")
IPV4_MULTICAST = ipaddress.ip_network("224.0.0.0/4")
IPV4_CGNAT = ipaddress.ip_network("100.64.0.0/10")
IPV4_DOC_RANGES = [
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3 (RFC 5737)
]
IPV4_SPECIAL_RANGES = [
    ipaddress.ip_network("0.0.0.0/8"),       # "This host on this network" (RFC 1122)
    ipaddress.ip_network("192.0.0.0/24"),     # IETF Protocol Assignments (RFC 6890, includes 192.0.0.0/29, .8, .170, .171)
    ipaddress.ip_network("192.88.99.0/24"),   # 6to4 Relay Anycast (RFC 7526)
    ipaddress.ip_network("198.18.0.0/15"),    # Device Benchmark Testing (RFC 2544)
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved for Future Use (RFC 1112 / RFC 919)
]
IPV4_RFC1918_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# IPv6 standard network blocks
IPV6_LINK_LOCAL = ipaddress.ip_network("fe80::/10")
IPV6_MULTICAST = ipaddress.ip_network("ff00::/8")  # Core IPv6 Architecture Multicast (RFC 4291 / IANA IPv6 Address Space)
IPV6_DOC_RANGES = [
    ipaddress.ip_network("2001:db8::/32"),   # Documentation (RFC 3849) - IANA False
    ipaddress.ip_network("3fff::/20"),       # Documentation (RFC 9637) - IANA False
]
IPV6_2001_PARENT = ipaddress.ip_network("2001::/23")

# IPv6 Explicit Globally Reachable Allocations (IANA Globally Reachable = True)
IPV6_GLOBAL_RANGES = [
    ipaddress.ip_network("64:ff9b::/96"),      # IPv4/IPv6 Translation Well-Known Prefix (RFC 6052) - IANA True (outside 2000::/3)
    ipaddress.ip_network("2620:4f:8000::/48"), # Direct Delegation AS112 Service (RFC 7534) - IANA True (inside 2000::/3)
]

# IPv6 special-purpose ranges outside 2001::/23
IPV6_SPECIAL_RANGES = [
    ipaddress.ip_network("64:ff9b:1::/48"),  # Local-Use IPv4/IPv6 Translation (RFC 8215) - IANA False
    ipaddress.ip_network("100::/64"),        # Discard-Only Prefix (RFC 6666) - IANA False
    ipaddress.ip_network("100:0:0:1::/64"),  # Dummy IPv6 Prefix (RFC 9780) - IANA False
    ipaddress.ip_network("2002::/16"),       # 6to4 (RFC 3056) - IANA N/A
    ipaddress.ip_network("5f00::/16"),       # Segment Routing SRv6 SIDs (RFC 8986, RFC 9602) - IANA False
]
IPV6_RFC4193_ULA = ipaddress.ip_network("fc00::/7")
IPV6_GLOBAL_UNICAST_BLOCK = ipaddress.ip_network("2000::/3")


def classify_ip_address(ip_str: str) -> str:
    """
    Classify an IP string into granular RFC categories in strict priority order
    using explicit, version-independent network range definitions and longest-prefix
    matching for sub-allocation overrides.
    Returns: 'loopback', 'link_local', 'multicast', 'cgnat', 'documentation',
             'special_purpose', 'rfc1918', 'rfc4193', or 'syntactically_global'.
    """
    ip = ipaddress.ip_address(ip_str.strip())
    
    # 0. IPv4-Mapped IPv6 unwrap (RFC 4291 ::ffff:0:0/96)
    if getattr(ip, "ipv4_mapped", None) is not None:
        ip = ip.ipv4_mapped

    if ip.version == 4:
        # Precedence 1: More-specific globally reachable exceptions within broad special ranges
        if any(ip in net for net in IPV4_GLOBAL_EXCEPTIONS):
            return "syntactically_global"

        # Precedence 2: Loopback (RFC 1122)
        if ip in IPV4_LOOPBACK:
            return "loopback"
        # Precedence 3: Link-Local (RFC 3927)
        if ip in IPV4_LINK_LOCAL:
            return "link_local"
        # Precedence 4: Multicast (RFC 5771)
        if ip in IPV4_MULTICAST:
            return "multicast"
        # Precedence 5: CGNAT (RFC 6598)
        if ip in IPV4_CGNAT:
            return "cgnat"
        # Precedence 6: Documentation (RFC 5737)
        if any(ip in net for net in IPV4_DOC_RANGES):
            return "documentation"
        # Precedence 7: Special-Purpose / Reserved / Benchmark (RFC 6890 / 2544 / 1112)
        if any(ip in net for net in IPV4_SPECIAL_RANGES):
            return "special_purpose"
        # Precedence 8: RFC 1918 Private IPv4
        if any(ip in net for net in IPV4_RFC1918_RANGES):
            return "rfc1918"
        # Precedence 9: Deterministic Syntactically Global Fallback
        # Any IPv4 address outside all explicit special/private ranges is syntactically global
        return "syntactically_global"

    else:  # IPv6
        # Precedence 1: Loopback (RFC 4291)
        if ip == ipaddress.ip_address("::1"):
            return "loopback"
        # Precedence 2: Link-Local (RFC 4291)
        if ip in IPV6_LINK_LOCAL:
            return "link_local"
        # Precedence 3: Multicast (RFC 4291 - IANA IPv6 Address Space, independent of special-purpose registry)
        if ip in IPV6_MULTICAST:
            return "multicast"
        # Precedence 4: Documentation (RFC 3849 & RFC 9637 - overrides 2000::/3)
        if any(ip in net for net in IPV6_DOC_RANGES):
            return "documentation"

        # Precedence 5: 2001::/23 Longest-Prefix Matching
        # Overrides: True -> syntactically_global; False/NA/Blank -> special_purpose
        if any(ip in net for net in IPV6_2001_GLOBAL_OVERRIDES):
            return "syntactically_global"
        if any(ip in net for net in IPV6_2001_SPECIAL_OVERRIDES):
            return "special_purpose"
        if ip in IPV6_2001_PARENT:
            return "special_purpose"

        # Precedence 6: Special-Purpose / Unspecified / 6to4 / Discard / Dummy / SRv6 (RFC 4291 / 8215 / 6666 / 9780 / 3056 / 8986)
        if ip == ipaddress.ip_address("::") or any(ip in net for net in IPV6_SPECIAL_RANGES):
            return "special_purpose"
        # Precedence 7: Explicit Globally Reachable Allocations (64:ff9b::/96 & 2620:4f:8000::/48) - IANA True
        if any(ip in net for net in IPV6_GLOBAL_RANGES):
            return "syntactically_global"
        # Precedence 8: RFC 4193 Unique Local IPv6 (ULA)
        if ip in IPV6_RFC4193_ULA:
            return "rfc4193"
        # Precedence 9: Deterministic Global Unicast Fallback
        # Global unicast allocation block (2000::/3) not covered by prior doc/special ranges
        if ip in IPV6_GLOBAL_UNICAST_BLOCK:
            return "syntactically_global"
        # Precedence 10: Any other IPv6 address (unallocated/reserved prefixes) defaults to special_purpose
        return "special_purpose"
```

> [!IMPORTANT]
> **No Claim of Actual Internet Routability**: In offline static analysis, `syntactically_global` indicates only that the address falls outside designated private or special-purpose reservations. It does **not** prove that the address is routed in public BGP tables, assigned to an active host, or reachable across the Internet.

#### 9.1.8 Link-Local vs. Private IP Trigger Semantics & Downstream Impact
The interaction between IP categories and canonical features is strictly partitioned:
- **`has_private_ip_url` (Feature 13)**: Triggered **strictly** by `rfc1918` and `rfc4193` categories. Link-local addresses (RFC 3927 / RFC 4291) do **NOT** trigger this feature.
- **`has_loopback_ip_url` (Feature 14)**: Triggered strictly by `loopback` category (`127.0.0.1`, `::1`, `::ffff:127.0.0.1`).
- **`has_special_ip_url` (Feature 15)**: Triggered strictly by `cgnat`, `documentation`, `multicast`, and `special_purpose`. Link-local addresses do **NOT** trigger this feature.
- **`link_local` Semantics**: Classified as `'link_local'` in per-URL analysis (`UrlAnalysisItem.ip_classification = 'link_local'`) and generates a Tier 2 forensic evidence trace (`UrlEvidenceItem`).
- **Downstream ML Limitation**: Because the 39-feature canonical registry does not contain a dedicated `has_link_local_ip_url` boolean feature, the Tier 3 feature vector (`UrlFeatures`) passed to downstream ML classifiers does not directly encode the presence of link-local IPs. Link-local URLs in email are exceedingly rare outside simulated lab environments; their visibility is intentionally isolated to per-URL forensic inspection and audit evidence in the MVP.
- **`syntactically_global`**: Public unicast addresses do not set anomaly flags.

### 9.2 URL Shortener Registry

The URL Agent maintains an offline, versioned registry of known URL shortener domains.

**Registry Metadata**:
- **Version Tag**: `SHORTENER-REGISTRY-v1-2026-11`
- **Provenance**: Curated from IETF references, industry security reports, and publicly documented shortener services.
- **Integrity**: SHA-256 hash of the registry file recorded in a companion `.sha256` file.
- **Location**: `app/data/url_shorteners.txt` (one domain per line, lowercased, no scheme prefix)
- **Companion**: `app/data/url_shorteners.sha256`

**Offline Developer Update Procedure**:
A developer script (`scripts/update_shortener_registry.py`) performs the following:
1. Accepts additions/removals via a curated source list.
2. Sorts entries, deduplicates, and validates domain syntax.
3. Computes and records the SHA-256 hash.
4. Updates the version tag.
5. Runs the full test suite to verify no regressions.

> [!NOTE]
> **No Malicious Intent Implied**: Presence in this registry does not indicate malicious intent. URL shorteners are widely used in legitimate communications (marketing, SMS notifications, social media). The registry enables structural detection of shortened URLs as an analytical signal, not as a verdict.

---

## 10. Missingness, Availability Manifest, and Completeness

### 10.1 Availability Manifest (`UrlFeatureAvailability`)
Downstream models consume `UrlFeatureAvailability` flags to differentiate between observed negative evidence and missing evidence:

```python
class UrlFeatureAvailability(BaseModel):
    """
    Explicit missingness manifest tracking availability across all conditionally
    evaluable URL features and prerequisite inputs.
    """
    avail_has_urls: bool = Field(description="True if email contains >= 1 extracted URL.")
    avail_structure_features: bool = Field(description="True if URLs exist and structure was parsed.")
    avail_hostname_features: bool = Field(description="True if URLs have non-empty hostnames.")
    avail_entropy_features: bool = Field(description="True if hostnames are present to compute entropy.")
    avail_sender_alignment: bool = Field(description="True if both URLs and From header domain exist.")
    avail_anchor_text_analysis: bool = Field(description="True if >= 1 HTML link with anchor text exists.")

    # Descriptive Domain Completeness Summaries [0.0, 1.0]
    completeness_structure: float = Field(ge=0.0, le=1.0)
    completeness_hostname: float = Field(ge=0.0, le=1.0)
    completeness_obfuscation: float = Field(ge=0.0, le=1.0)
    completeness_context: float = Field(ge=0.0, le=1.0)
    completeness_total: float = Field(ge=0.0, le=1.0)

    model_config = {"extra": "forbid"}
```

### 10.2 Descriptive Evidence Completeness ($E_{\text{comp\_url}}$)
Descriptive evidence completeness for URLs quantifies coverage across the 4 URL feature domains:
$$E_{\text{comp\_url}} = \begin{cases} 
0.0, & \text{if } \text{total\_url\_count} == 0 \\
\frac{1}{4} \left( C_{\text{struct}} + C_{\text{host}} + C_{\text{obfus}} + C_{\text{context}} \right), & \text{if } \text{total\_url\_count} \ge 1
\end{cases}$$
where:
- $C_{\text{struct}} = 1.0$ (always fully evaluable when URLs exist).
- $C_{\text{host}} = 1.0$ if all URLs possess valid hostnames, else $0.5$.
- $C_{\text{obfus}} = 1.0$ (fully evaluable offline).
- $C_{\text{context}} = \frac{1}{2} \left( \mathbb{I}(\text{avail\_sender\_alignment}) + \mathbb{I}(\text{avail\_anchor\_text\_analysis}) \right)$.

---

## 11. False-Positive Analysis and Mitigation Strategies

Phishing detection models frequently suffer false-positive spikes when encountering legitimate corporate communications. The URL Agent design explicitly addresses these known scenarios:

### 11.1 Legitimate Marketing Tracking & Click-Redirectors
- **The Issue**: Legitimate email service providers (SendGrid, Mailchimp, Marketo, HubSpot) rewrite all hyperlinks into tracking domains (e.g. `http://em.company.com/ls/click?upn=...`) that mismatch the anchor text.
- **Mitigation**:
  - The agent emits `has_anchor_url_mismatch = True` as an objective structural finding.
  - The finding is explicitly annotated in `limitations_and_benign_explanations`: `"Legitimate corporate newsletters and ESPs (SendGrid, Mailchimp) routinely rewrite anchor links for engagement tracking."`
  - Downstream meta-classifiers are trained with out-of-fold regularized weights that learn not to treat tracking mismatches alone as definitive proof of phishing.

### 11.2 Corporate Intranet & Development Links
- **The Issue**: System administrator emails and developer notifications frequently include RFC 1918 private IPs (`http://192.168.1.50/status`) or non-default ports (`http://jira.internal:8080/browse`).
- **Mitigation**:
  - `has_private_ip_url` and `has_non_default_port` are flagged, but categorized as internal indicators.
  - In Tier 2 evidence: `"Private IP addresses are standard in internal enterprise communications but indicate potential abuse if arriving from external senders."`

### 11.3 Legitimate URL Shorteners
- **The Issue**: Legitimate services (e.g. SMS-to-email notifications, Twitter digests) use `bit.ly` or `t.co`.
- **Mitigation**:
  - The feature is named `has_url_shortener`, **not** `has_malicious_shortener`.
  - The agent never marks a shortener as malicious without auxiliary evidence.

### 11.4 Complex Cloud Hostnames (Subdomain Depth)
- **The Issue**: AWS S3, Azure Blob, and GCP buckets often contain 4–6 dot-separated labels (e.g. `my-corp-data.s3-accelerate.dualstack.us-east-1.amazonaws.com`).
- **Mitigation**:
  - Registered domain parsing (extracting `amazonaws.com` via PSL) ensures that subdomain depth is calculated relative to the effective TLD, and is documented as common in cloud infrastructure.

---

## 12. Testing Strategy & Test Matrix

The URL Agent test suite will be implemented in `tests/test_url_agent.py` and `tests/test_url_agent_schema.py`. The suite requires zero network calls and executes deterministically across **37 core test categories**:

| Test Group | Scenario / Target | Expected Behavioral Outcome |
|---|---|---|
| **1. Clean HTTPS URLs** | Single standard HTTPS URL (`https://example.com/about`). | `total_url_count=1`, `unique_url_count=1`, `has_urls=True`, `https_url_count=1`, `has_ip_literal_url=False`, zero anomalies. |
| **2. HTTP Scheme URLs** | Legacy HTTP URL (`http://example.com/`). | `http_url_count=1` (quarantined), `https_url_count=0`. |
| **3. IP Address Literals** | URL using IPv4 host (`http://192.168.1.1/login`). | `has_ip_literal_url=True`, `has_private_ip_url=True`. Hostname classified as `rfc1918`. |
| **4. Special / Loopback IPs** | URLs with `127.0.0.1`, `100.64.0.1` (CGNAT), `192.0.2.1`. | `has_loopback_ip_url=True`, `has_special_ip_url=True`. |
| **5. IDNA Punycode** | Internationalized domain (`http://xn--e1afmkfd.xn--p1ai/` and raw Unicode host). | `has_punycode_url=True`, detected via hostname-only inspection. Path Unicode does not trigger. |
| **6. Excessive Subdomains** | Subdomain nesting $\ge 3$ (`http://a.b.c.d.evil.com/`). | `max_subdomain_depth=4`, `has_excessive_subdomains=True`. |
| **7. Embedded Credentials** | URL with userinfo (`http://user:pass@example.com/`). | `has_embedded_credentials=True`, `has_at_symbol_in_url=True`. |
| **8. '@' Symbol Deception** | Authority confusion (`http://google.com@evil.com/path`). | `has_at_symbol_in_url=True`, evidence highlights target host is `evil.com`. |
| **9. Percent-Encoding** | Excessive encoding (`http://example.com/%20%2F%7E`). | `has_percent_encoding=True`, `max_percent_encoded_count=3`. |
| **10. Double Encoding** | URL containing `%2520` or `%252F`. | `has_double_percent_encoding=True`. |
| **11. URL Shorteners** | Hostname `bit.ly` or `tinyurl.com`. | `has_url_shortener=True`, `url_shortener_count=1`. |
| **12. Open Redirect Parameters** | Query containing `?url=http://...` or `?redirect=...`. | `has_redirect_parameter=True`, evidence notes parameter name. |
| **13. Anchor Mismatch** | Visible text `https://paypal.com` pointing to `https://evil.com`. | `has_anchor_url_mismatch=True`, `anchor_url_mismatch_count=1`. |
| **14. Malformed Port — Non-numeric** | URL with `:abc` (`http://example.com:abc/path`). | `malformed_url_count=1`, `SplitResult.port` raises `ValueError`, handled safely without crash. |
| **15. Malformed Port — Out of Range** | URL with port 99999 (`http://example.com:99999/path`). | `malformed_url_count=1`, `SplitResult.port` raises `ValueError`, evidence records failure. |
| **16. Malformed Port — Port 0** | URL with port 0 (`http://example.com:0/path`). | `malformed_url_count=1`, rejected because port 0 is outside 1–65535 range. |
| **17. Malformed IPv6 Brackets** | URL with unclosed bracket (`http://[::1/path`). | `malformed_url_count=1`, `urlsplit` raises `ValueError`, handled safely. |
| **18. Valid Non-Default Port** | URL with port 8080 (`http://example.com:8080/path`). | `malformed_url_count=0`, `has_non_default_port=True`. Port is valid. |
| **19. Simultaneous Malformed Conditions** | URL with out-of-range port and bad percent escape (`http://example.com:99999/%GG/path`). | Increments `malformed_url_count` by **exactly 1**; evidence lists both failure conditions. |
| **20. IPv4-Mapped IPv6 — Private** | URL with `http://[::ffff:192.168.1.1]/`. | Unwraps to `192.168.1.1`, classified as `rfc1918`, `has_private_ip_url=True`. |
| **21. IPv4-Mapped IPv6 — Loopback** | URL with `http://[::ffff:127.0.0.1]/`. | Unwraps to `127.0.0.1`, classified as `loopback`, `has_loopback_ip_url=True`. |
| **22. IPv4-Mapped IPv6 — Public** | URL with `http://[::ffff:93.184.216.34]/`. | Unwraps to `93.184.216.34`, classified as `syntactically_global`, no anomaly flag. |
| **23. Link-Local IP Literals** | URLs with `169.254.1.1` and `fe80::1`. | Classified as `link_local`. `has_private_ip_url=False`, `has_special_ip_url=False`. Evidence logged. |
| **24. Boundary Special-Purpose IPv4** | URLs with `198.18.0.1` (benchmark), `192.0.0.1` (protocol), `192.88.99.1` (6to4), `240.0.0.1` (reserved). | Classified as `special_purpose`. `has_special_ip_url=True`. Verified across Python releases. |
| **25. Heterogeneous Unique Domains** | Mixed URLs: PSL domain, IP literal, unknown suffix FQDN. | `unique_domain_count` correctly tallies distinct heterogeneous identities (Section 5.6). |
| **26. Sender Alignment — Mixed Occurrences** | Email with 3 occurrences of `https://company.com/login` and 1 occurrence of `https://external.org/test`. From: `user@company.com`. | $N_{\text{resolvable}}=4, N_{\text{match}}=3 \implies \text{sender\_ratio}=0.75, \text{external\_ratio}=0.25, \text{has\_sender\_domain\_mismatch\_url}=\mathbf{True}$. |
| **27. Sender Alignment — All Occurrences Match** | Email with 4 occurrences of sender-domain URLs (`https://company.com/...`). From: `user@company.com`. | $N_{\text{resolvable}}=4, N_{\text{match}}=4 \implies \text{sender\_ratio}=1.0, \text{external\_ratio}=0.0, \text{has\_sender\_domain\_mismatch\_url}=\mathbf{False}$. |
| **28. IPv4 Exceptions & Exhaustive 192.0.0.0/24 Allocations** | URLs with `192.0.0.9`, `192.0.0.10` (exceptions) vs `192.0.0.1` and `192.0.0.2` (in `192.0.0.0/29`), `192.0.0.8` (dummy), and `192.0.0.170`, `192.0.0.171` (discovery). | Exception addresses classified as `syntactically_global`, `has_special_ip_url=False`. Service continuity, dummy, discovery, and siblings classified as `special_purpose`, `has_special_ip_url=True`. |
| **29. IPv6 `2001::/23` Sub-Allocations** | URLs with `2001:1::1`, `2001:1::2`, `2001:1::3` (RFC 9665), `2001:3::1` (AMT), `2001:4:112::1` (AS112), `2001:20::1` (ORCHIDv2), `2001:30::1` (Drone ID) vs `2001::1` (Teredo), `2001:2::1` (benchmark), `2001:10::1` (deprecated), `2001:1ff::1` (unassigned). | IANA True allocations classified as `syntactically_global`, `has_special_ip_url=False`. IANA False/NA/Blank allocations classified as `special_purpose`, `has_special_ip_url=True`. |
| **30. External Link Ratio with IP Literals** | Email with 1 sender-matching URL and 1 IP literal URL. | $N_{\text{resolvable}}=1, N_{\text{match}}=1 \implies \text{external\_link\_ratio}=0.0, \text{has\_sender\_domain\_mismatch\_url}=\mathbf{False}$. IP excluded from ratio. |
| **31. IPv6 Documentation Range** | URL with `http://[2001:db8::1]/path`. | Classified as `documentation` (RFC 3849, outside `2001::/23`). `has_special_ip_url=True`. |
| **32. IPv6 Documentation in 2000::/3** | URL with `http://[3fff::1]/path`. | Classified as `documentation` (RFC 9637, sub-network of `2000::/3`). `has_special_ip_url=True`. Verifies documentation overrides `2000::/3` global fallback. |
| **33. Segment Routing SRv6 Prefix** | URL with `http://[5f00::1]/path`. | Classified as `special_purpose` (RFC 8986, RFC 9602, outside `2000::/3`). `has_special_ip_url=True`. |
| **34. IPv4-IPv6 Translation Prefixes** | URLs with `64:ff9b::1` (RFC 6052) and `64:ff9b:1::1` (RFC 8215). | `64:ff9b::1` classified as `syntactically_global` (`has_special_ip_url=False`) consistent with IANA True. `64:ff9b:1::1` classified as `special_purpose` (`has_special_ip_url=True`) consistent with IANA False. |
| **35. Longest-Prefix Override Priority** | Multi-URL test with `192.0.0.9` (override) vs `192.0.0.1` (parent), `2001:1::1` (override) vs `2001:1ff::1` (parent), `3fff::1` (override) vs `2607:f8b0:4005:805::200e` (fallback). | Validates that more-specific sub-allocations consistently override parent ranges across both IPv4 and IPv6. |
| **36. Discard-Only & Dummy IPv6 Blocks** | URLs with `http://[100::1]/path` (RFC 6666) and `http://[100:0:0:1::1]/path` (RFC 9780). | Both classified as `special_purpose`, `has_special_ip_url=True`. Confirms agreement with authoritative IANA Globally Reachable: False. |
| **37. Direct Delegation AS112 Service** | URL with `http://[2620:4f:8000::1]/path` (RFC 7534). | Classified as `syntactically_global`, `has_special_ip_url=False`. Validates explicit match in `IPV6_GLOBAL_RANGES` and alignment with `2000::/3` global fallback without triggering false-positive alerts. |

### 12.1 Algorithmic Complexity Bounds

To remain environment-independent, performance targets are specified as algorithmic bounds:

- **Time Complexity**: $\mathcal{O}(N \cdot L)$ where $N$ is the URL count and $L$ is the maximum URL character length. Processing operates in a single sequential streaming pass.
- **Working Memory**: $\mathcal{O}(N)$ for uniqueness tracking sets (set of normalized URL identity keys, set of domain identity keys, set of FQDN identity keys). In the worst case where every URL is unique, these sets grow linearly with the number of URLs. For the development corpus maximum of 3,134 URLs per email, this remains well within practical memory limits.
- **Output Storage**: Bounded by constant caps — 200 `UrlAnalysisItem` records, 100 evidence items, and 50 anomalous hostnames — preventing unbounded output growth regardless of input size.

---

## 13. Dataset, Confounding, and Evaluation Considerations

### 13.1 Dataset Profile Review (Task 8.4 Findings)
The development dataset contains 1,000 emails:
- **750 Ham**: 500 `easy_ham` and 250 `hard_ham` from SpamAssassin (2002–2003).
- **250 Phishing**: 188 from Nazario 2015, 62 from Nazario 2021.
- **URL Distribution**:
  - Exactly **879 emails (87.9%) contain $\ge 1$ URLs**.
  - Exactly **121 emails (12.1%) contain NO URLs** (78 ham, 43 phishing).
  - Phishing emails average **4.45 URLs** (median 2.0).
  - Ham emails average **15.22 URLs** (with `hard_ham` averaging **60.09 URLs** and reaching a maximum of **3,134 URLs**).

### 13.2 Critical Confounding Hazards & Feature Evaluation Considerations

Quarantining raw hostnames and URLs from the feature space prevents trivial memorization of domain names. **However, it does not eliminate dataset leakage.** Derived structural features can still encode severe source and temporal artifacts:

1. **URL Density Inversion Hazard**:
   - In academic literature, models often assume *more URLs = more spam*.
   - In our real-world dataset, legitimate mailing lists average **60.09 URLs**, whereas phishing averages **4.45 URLs**.
   - A model could achieve high accuracy by learning that having *fewer* URLs implies phishing, which would fail catastrophically on short personal emails.
   - **Mitigation**: `total_url_count` is evaluated with constrained regularization to prevent negative correlation exploitation.
2. **Temporal TLS Confounding (HTTP vs. HTTPS)**:
   - In 2002 (SpamAssassin), the web was overwhelmingly unencrypted HTTP.
   - In 2015/2021 (Nazario), phishing kits routinely used HTTPS.
   - A naive model would learn that `http == ham` and `https == phishing`.
   - **Mandatory Policy**: `http_url_count` is quarantined from the primary feature set. `https_url_count` is retained as active but carries an explicit confounding caveat (see Feature 5 warning) and requires careful evaluation during model training.
3. **Dead Domain Limitation**:
   - Over 95% of phishing domains in historical corpora (2002–2021) are inactive or expired.
   - This is a key reason why **offline static analysis avoids introducing temporal bias from expired domains**, though it is not the only valid evaluation approach. Live-infrastructure analysis may be appropriate for contemporary threat detection where domain availability is relevant.

---

## 14. Incremental Implementation Plan (Upcoming Task 9.1+)

Implementation will proceed in four isolated phases:

1. **Phase 1: Schema Implementation (`app/schemas/url_agent_schema.py`)**:
   - Define `CANONICAL_URL_FEATURE_NAMES` literal (1..39).
   - Define `DomainResolutionStatus` enum.
   - Define `UrlFeatures`, `UrlFeatureAvailability`, `UrlEvidenceItem`, `UrlEvidence`, `UrlAnalysisItem`, and `UrlAgentResult`.
   - Re-export via `app/schemas/__init__.py`.
   - Implement `tests/test_url_agent_schema.py`.
2. **Phase 2: Core URL Agent Implementation (`app/agents/url_agent.py`)**:
   - Implement offline URL shortener registry with version verification.
   - Implement bundled PSL snapshot parser with `DomainResolutionStatus`.
   - Implement deterministic static component analyzers:
     - Hostname-only Punycode detection.
     - Hostname Shannon entropy.
     - Deterministic, version-independent IP classification using explicit network tables with longest-prefix exception overrides for IPv4 (`192.0.0.9`, `192.0.0.10`) and IPv6 (`2001:1::1..3`, `2001:3::/32`, `2001:4:112::/48`, `2001:20::/28`, `2001:30::/28`) and IPv4-mapped unwrapping.
     - Anchor text mismatch evaluation with PSL/FQDN comparison.
     - Query string open redirect parameter detection.
   - Implement malformed URL structural syntax validation (`validate_url_syntax`) covering all 5 conditions with single increment guarantee.
   - Implement occurrence-based sender domain cross-alignment calculations ($N_{\text{match}} / N_{\text{resolvable}}$) and mismatch evaluation ($N_{\text{match}} < N_{\text{resolvable}}$).
   - Implement multi-URL aggregation logic with heterogeneous domain uniqueness tracking and descriptive completeness.
   - Re-export via `app/agents/__init__.py`.
3. **Phase 3: Comprehensive Test Suite (`tests/test_url_agent.py`)**:
   - Implement test fixtures covering all 37 test matrix scenarios.
   - Include IP range exception tests for IPv4 and IPv6 `2001::/23` sub-allocations (positive overrides vs negative sibling addresses).
   - Include IPv4-mapped IPv6 address tests (private, loopback, public).
   - Include boundary special-purpose IP range tests (RFC 2544, RFC 6890, 6to4, RFC 1112, etc.).
   - Include link-local address tests (confirming `has_private_ip_url=False`, `has_special_ip_url=False`).
   - Include malformed port tests (non-numeric, port 0, port 99999, bad IPv6 brackets, simultaneous failures).
   - Include occurrence-based sender alignment tests (3 sender occurrences + 1 external occurrence $\to$ 0.75 / 0.25 / True; 4 sender occurrences $\to$ 1.0 / 0.0 / False).
   - Include heterogeneous domain counting tests and resolvable external link ratio tests.
   - Verify deterministic repeated execution.
   - Run complete workspace test suite (510+ tests) to guarantee zero regression.
4. **Phase 4: Dashboard Integration & Documentation**:
   - Add URL Agent tab to `scripts/header_agent_dashboard.py`.
   - Update `README.md` and documentation manifests.

---

## 15. Unresolved Design Decisions & Discussion Points

1. **Brand-in-Path Matching Scope (Quarantined — Feature 27)**:
   - *Status*: Quarantined pending resolution of prerequisites (see Section 5.9).
   - *Option A*: Maintain a concise, curated, versioned list of the top 30 targeted brands with documented matching algorithm.
   - *Option B*: Defer brand matching entirely to the Text Agent.
   - *Decision required before unquarantining*.
2. **Backward-Compatible Schema Proposal for HTML Form Actions**:
   - To unquarantine Feature 39 (`has_form_action_url`) in future tasks, propose extending `URLSource` in `app/schemas/email_schema.py`:
     ```python
     class URLSource(str, Enum):
         PLAIN_TEXT = "plain_text"
         HTML_HREF = "html_href"
         HTML_SRC = "html_src"
         HTML_OTHER = "html_other"
         HTML_FORM_ACTION = "html_form_action"  # Proposed extension
         HEADER = "header"
     ```
   - This cleanly separates `<form action>` targets from generic HTML links without breaking existing contracts.
3. **PSL Snapshot Currency**:
   - The bundled PSL snapshot may become stale as new TLDs are delegated. The `UNKNOWN_SUFFIX` status provides graceful degradation, but developers should periodically refresh the snapshot using the update script.

---

## 16. Compliance Checklist & Invariant Review

- [x] **Zero implementation code written**: Design-only specification.
- [x] **Zero schema modifications**: Existing schemas (`email_schema.py`, `header_agent_schema.py`) untouched.
- [x] **Zero ingestion modifications**: `url_extractor.py` and `email_ingestor.py` untouched.
- [x] **Zero network activity**: Strictly passive, offline, deterministic specification.
- [x] **Authoritative IANA IPv6 allocation coverage in 2001::/23**: Implemented longest-prefix overrides for all `Globally Reachable: True` sub-allocations (`2001:1::1..3`, `2001:3::/32`, `2001:4:112::/48`, `2001:20::/28`, `2001:30::/28`) and documented conservative policy for `False/NA/Blank` allocations (`2001::/32`, `2001:2::/48`, `2001:10::/28`).
- [x] **Parent prefix reachability accurately distinguished**: Parent `2001::/23` documented as IANA `Globally Reachable: False` with footnote ("Unless allowed by a more-specific allocation"), distinct from `2001::/32` (TEREDO) and `2002::/16` (6to4) which have IANA `Globally Reachable: N/A`. Parent `/23` is never described as N/A.
- [x] **Exhaustive IPv6 registry audit (all 25 entries)**: Tables in Section 9.1.5 (11 sub-allocations within `2001::/23`) and Section 9.1.6 (14 allocations outside `2001::/23`) provide an exhaustive accounting of all 25 entries in the authoritative IANA IPv6 Special-Purpose Address Registry. Every entry is accounted for in pseudocode and longest-prefix precedence rules.
- [x] **Independent multicast architectural attribution**: `ff00::/8` is accurately attributed to RFC 4291 and the IANA IPv6 Address Space registry (rather than the special-purpose registry). Multicast classification is preserved in Precedence 3 and sets `has_special_ip_url`.
- [x] **Corrected 100::/64 reachability**: Corrected authoritative IANA Globally Reachable value for `100::/64` (RFC 6666) from True to False. Erroneous footnote removed. Project classification (`special_purpose`) directly agrees with IANA False.
- [x] **Omitted IPv6 entries added**: Explicitly evaluated and tested `100:0:0:1::/64` (Dummy IPv6 Prefix, RFC 9780, IANA False $\to$ `special_purpose`) and `2620:4f:8000::/48` (Direct Delegation AS112 Service, RFC 7534, IANA True $\to$ `syntactically_global`).
- [x] **Dual-date registry provenance**: Documented IANA Source Registry Last Updated date (2025-10-09) and Project Snapshot Capture date (2026-11-15).
- [x] **Treatment of Globally Reachable = True, False, N/A, [Blank] defined**: Explicit True $\to$ `syntactically_global`; False/NA/Blank $\to$ `special_purpose` under conservative security policy.
- [x] **Correct RFC attribution**: Attributed `2001:1::3` to RFC 9665, `2001:20::/28` to RFC 7343, `2001:30::/28` to RFC 9374, `192.0.0.170/171` to RFC 7050/8880, `192.0.0.0/29` to RFC 7335, `192.0.0.8` to RFC 7600, `3fff::/20` to RFC 9637, `5f00::/16` to RFC 8986/9602, `64:ff9b::/96` to RFC 6052, `64:ff9b:1::/48` to RFC 8215.
- [x] **IPv4-mapped IPv6 classification**: Detects `ip.ipv4_mapped` and unwrap-classifies before rule evaluation. Test cases: `::ffff:192.168.1.1` $\to$ `rfc1918`, `::ffff:127.0.0.1` $\to$ `loopback`, `::ffff:93.184.216.34` $\to$ `syntactically_global`.
- [x] **Link-local policy preserved**: `has_private_ip_url` strictly RFC 1918/4193; link-local does not trigger Feature 13 or 15; preserved in per-URL analysis and forensic evidence; downstream ML limitation explicitly documented.
- [x] **Correct sender mismatch semantics**: `has_sender_domain_mismatch_url` evaluates to `True` when $N_{\text{match}} < N_{\text{resolvable}}$ and `False` when $N_{\text{match}} == N_{\text{resolvable}}$; test cases for both mixed and all-matching link sets documented.
- [x] **Occurrence-based sender alignment semantics**: $N_{\text{resolvable}}$ and $N_{\text{match}}$ count all extracted URL occurrences; repeated occurrence weighting documented.
- [x] **Malformed port and syntax validation formalized**: Five distinct conditions (`urlsplit` exception, `parts.port` `ValueError`, port 0, missing web authority, bad percent-escape); single increment guarantee; dedicated test cases added.
- [x] **Heterogeneous domain identity semantics explicit**: `unique_domain_count` (Feature 20) documented as heterogeneous domain identities (PSL registered domains, IP literals, unknown-suffix FQDNs). Operational caveats documented.
- [x] **External resolvable link ratio semantics explicit**: $\frac{N_{\text{resolvable}} - N_{\text{match}}}{N_{\text{resolvable}}}$ with explicit exclusions (IP literals, unknown suffixes, invalid hostnames) and caveats documented.
- [x] **Punycode detection corrected**: Hostname-only inspection. Non-ASCII in path/query does not trigger `has_punycode_url`.
- [x] **PSL resolution status explicit**: `DomainResolutionStatus` enum replaces silent right-split fallback.
- [x] **Form action quarantined**: Feature 39 quarantined due to `URLSource.HTML_OTHER` conflation.
- [x] **Brand-in-path quarantined**: Feature 27 quarantined pending curated brand registry prerequisites.
- [x] **Probability references removed**: No $p_h, p_u, c_h, c_u$ in pipeline diagram or contracts. Layer 1 emits features, not probabilities.
- [x] **Evidence ordering unified**: `(url_index, feature_name, finding_id)` consistent throughout.
- [x] **Predictive claims reassessed**: "Active — Eligible for Experimental Evaluation" replaces "Active Predictive". No "leakage-safe" claims. `https_url_count` confounding caveat documented.
- [x] **Exact IP semantics defined**: "Syntactically global unicast" used instead of claiming routability.
- [x] **Port feature renamed**: `has_non_default_port` with scheme-default mapping.
- [x] **Deterministic evidence limits**: Sorted by `(url_index, feature_name, finding_id)`, with `omitted_evidence_count`.
- [x] **Complexity documented accurately**: Working memory $\mathcal{O}(N)$ for uniqueness sets; output bounded by caps.
- [x] **Performance bounds**: Specified as environment-independent $\mathcal{O}(N \cdot L)$ time complexity.
