# Header Agent MVP — Demonstration Guide and Architecture

## 1. Overview

The **Header Agent** is the first operational specialist agent in the **Multi-Agent AI Phishing Email Detector** system. It operates strictly deterministically, passively, and offline to analyze email headers and authentication metadata extracted from raw RFC 822 email messages (`.eml`).

```
┌─────────────────┐       ┌─────────────────┐       ┌────────────────────────┐
│  Raw .eml File  │ ────> │  ingest_email() │ ────> │       EmailData        │
│  (RFC 822)      │       │ (email_ingestor)│       │ (Shared Data Contract) │
└─────────────────┘       └─────────────────┘       └────────────────────────┘
                                                                 │
                                                                 ▼
                                                    ┌────────────────────────┐
                                                    │    analyze_headers()   │
                                                    │     (Header Agent)     │
                                                    └────────────────────────┘
                                                                 │
                                                                 ▼
                                                    ┌────────────────────────┐
                                                    │   HeaderAgentResult    │
                                                    │ - Tier 3 (45 Features) │
                                                    │ - Availability Manifest│
                                                    │ - Completeness Metrics │
                                                    │ - Tier 2 Audit Evidence│
                                                    └────────────────────────┘
```

---

## 2. Key Architecture Invariants

1. **Deterministic & Offline**:
   - Zero network requests, socket connections, or DNS queries.
   - Zero external reputation lookups or WHOIS queries.
   - Zero learned weights or arbitrary heuristic scoring formulas.
2. **Leakage-Safe Feature Space**:
   - Predictive features (`HeaderFeatures`) are strictly sanitized.
   - Forbids raw subject text, sender names, absolute dates, server hostnames, scanner tags, and corpus IDs.
3. **Canonical Feature Registry**:
   - Exactly **45 canonical features** continuously ordered 1..45 across 4 categories:
     - **Category A (13)**: Sender, Recipient, and Identity Alignment.
     - **Category B (10)**: Routing and Transport Structure.
     - **Category C (13)**: Authentication Claims.
     - **Category D (9)**: RFC 5322 Metadata & Structural Compliance.
   - **41 active predictive features**; **4 quarantined features** (Features 11, 12, 21, 22).
4. **Missingness Manifest & Completeness**:
   - Downstream models consume `HeaderFeatureAvailability` to prevent confounding missing headers with negative evidence.
   - Descriptive domain completeness metrics ($C_{\text{identity}}$, $C_{\text{routing}}$, $C_{\text{auth}}$, $C_{\text{metadata}}$, $E_{\text{comp}}$) quantify information coverage.
5. **Tier 2 Forensic Traceability**:
   - Bounded verbatim excerpts (`raw_snippet_bounded`, max 256 characters) with escaped control characters.
   - Traceable link to original header and claim index for human incident responders.

---

## 3. Running the Header Agent Demo

### Prerequisites
Run with Python 3.11+:

```powershell
cd phishing-detector
```

### CLI Command Options

1. **Standard Audit Report (Formatted Terminal Summary)**:
   ```powershell
   python scripts/demo_header_agent.py data/samples/synthetic_demo.eml
   ```

2. **Save Structured JSON Report to File**:
   ```powershell
   python scripts/demo_header_agent.py data/samples/synthetic_demo.eml -o report.json
   ```

3. **Output Raw JSON Only (Pipeable / Machine-Readable)**:
   ```powershell
   python scripts/demo_header_agent.py data/samples/synthetic_demo.eml --json-only
   ```

---

## 4. Synthetic Phishing Scenario Walkthrough

The included synthetic demo email (`data/samples/synthetic_demo.eml`) illustrates common advanced phishing techniques:

- **From / Reply-To Domain Mismatch**:
  From domain is `example-bank.com`, but Reply-To directs replies to `scam-credential-collector.xyz`.
- **From / Return-Path Domain Mismatch**:
  Bounces route to `unrelated-relay.net`.
- **Display Name Spoofing**:
  From display name embeds `"Security Notification <security@example-bank.com>"`.
- **Private IP in External Transit Hop**:
  External transit hop 1 contains private IP `192.168.1.45` (RFC 1918).
- **Authentication Failures & DKIM Inconsistency**:
  SPF status is `fail`, DKIM status is `fail`, and DMARC status is `fail`.
  `DKIM-Signature` header physically exists, triggering `dkim_signature_present_without_pass = True`.
- **Message-ID Domain Mismatch**:
  Message-ID domain `unrelated-relay.net` mismatches From domain `example-bank.com`.

### Sample Terminal Audit Output

```
================================================================================
  MULTI-AGENT AI PHISHING EMAIL DETECTOR — HEADER AGENT MVP AUDIT
================================================================================
  Source File      : synthetic_demo.eml
  Internal Email ID: email_bfd473e761824a4193cba3a808f660bc
  Agent Name/Ver   : header_agent v0.1.0
  Execution Status : SUCCESS
  Processing Time  : 5.638 ms
--------------------------------------------------------------------------------
  [1] IDENTITY & ADDRESS ALIGNMENT (Category A)
      From Header Present         : [YES/TRUE]
      From Valid Syntax (RFC 5322): [YES/TRUE]
      From Address Count          : 1
      Reply-To Header Present     : [YES/TRUE]
      Return-Path Header Present  : [YES/TRUE]
      From/Reply-To Mismatch      : [YES/TRUE]
      From/Return-Path Mismatch   : [YES/TRUE]
      Display Name Contains Email : [YES/TRUE]
      Display Name Domain Mismatch: [NO/FALSE]
      To Mailbox Count            : 1
      CC Mailbox Count            : None

  [2] ROUTING & TRANSPORT STRUCTURE (Category B)
      Total Received Hops         : 2
      Missing Received Headers    : [NO/FALSE]
      Hop Count Anomaly (>15 or 0): [NO/FALSE]
      Malformed Received Clauses  : 0
      Private IP in External Hop  : [YES/TRUE]
      Loopback IP in External Hop : [NO/FALSE]
      Link-Local IP in External   : [NO/FALSE]
      Special IP in External Hop  : [NO/FALSE]

  [3] AUTHENTICATION CLAIMS (Category C - Unverified Receiver Reports)
      Consolidated SPF Status     : fail
      Consolidated DKIM Status    : fail
      Consolidated DMARC Status   : fail
      DKIM-Signature Present      : [YES/TRUE]
      DKIM-Sig Present W/O Pass   : [YES/TRUE]
      Conflicting Claims (SPF/D/DM: False / False / False
      Reporting MTAs (Authserv-IDs: ['mx.google.com'] (Count: 1)
      Inconsistent Authserv-IDs   : [NO/FALSE]

  [4] RFC 5322 METADATA COMPLIANCE (Category D)
      Message-ID Present          : [YES/TRUE]
      Message-ID Valid Syntax     : [YES/TRUE]
      Message-ID Domain Mismatch  : [YES/TRUE]
      MIME-Version Present / Valid: True / True
      Subject Present / Char Len  : True / 68
      Content-Type Multipart      : [YES/TRUE]

  [5] DESCRIPTIVE EVIDENCE COMPLETENESS (Section 9.2)
      Identity Completeness       : 100.0%
      Routing Completeness        : 60.0%
      Authentication Completeness : 100.0%
      Metadata Completeness       : 100.0%
      OVERALL TOTAL COMPLETENESS  : 90.0%
--------------------------------------------------------------------------------
  [6] OBSERVED ANOMALIES & AUDIT EVIDENCE
      [1] From/Reply-To domain mismatch: 'example-bank.com' vs 'scam-credential-collector.xyz'
      [2] From/Return-Path domain mismatch: 'example-bank.com' vs 'unrelated-relay.net'
      [3] Private IP '192.168.1.45' (rfc1918) detected in external transit hop 1
      [4] DKIM-Signature header present without pass (status: fail)
      [5] Message-ID domain mismatch: 'unrelated-relay.net' vs 'example-bank.com'
      Anomalous IPs detected in transit: ['192.168.1.45']

      Forensic Evidence Items (6 recorded):
        1. [from_reply_to_domain_mismatch] Reply-To: Reply-To domain 'scam-credential-collector.xyz' mismatches From domain 'example-bank.com'
           Snippet: Account Resolution <harvest@scam-credential-collector.xyz>
        2. [from_return_path_domain_mismatch] Return-Path: Return-Path domain 'unrelated-relay.net' mismatches From domain 'example-bank.com'
           Snippet: bounce@unrelated-relay.net
        3. [display_name_contains_email] From: From display name embeds email address with domain 'example-bank.com'
           Snippet: Security Notification <security@example-bank.com> <alerts@example-bank.com>
        4. [has_private_ip_in_external_hop] Received: External transit hop 1 contains private IP '192.168.1.45' (rfc1918)
           Snippet: from internal.spoofed.lan (gateway.local [192.168.1.45]) by mail.example-bank.com; Wed, 11 Nov 2026 14:32:10 +0000
        5. [dkim_signature_present_without_pass] DKIM-Signature: DKIM-Signature header present but DKIM authentication status is 'fail'
           Snippet: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example-bank.com; s=k1; h=from:to:subject:date:message-id; bh=synthetic_hash_dummy=; b=synthetic_sig_dummy=
================================================================================
```

---

## 5. Python API Usage

```python
from app.ingestion.email_ingestor import ingest_email
from app.agents import analyze_headers
from pathlib import Path

# 1. Read raw email bytes
raw_bytes = Path("data/samples/synthetic_demo.eml").read_bytes()

# 2. Ingest email into validated EmailData contract
email_data = ingest_email(raw_bytes, source_filename="synthetic_demo.eml")

# 3. Analyze headers
result = analyze_headers(email_data)

# 4. Access outputs
print(f"Status: {result.status}")
print(f"Processing time: {result.processing_time_ms} ms")
print(f"SPF Status: {result.features.spf_status}")
print(f"Reply-To Mismatch: {result.features.from_reply_to_domain_mismatch}")
print(f"Observed Anomalies: {result.evidence.observed_anomalies}")

# 5. Export JSON
json_report = result.model_dump_json(indent=2)
```

