#!/usr/bin/env python3
"""
demo_header_agent.py
--------------------
Demonstration script for the Header Agent MVP.

Accepts an RFC 822 .eml file, runs it through the ingestion pipeline (ingest_email),
executes the Header Agent (analyze_headers), and displays both a human-readable
forensic audit report and the serialized HeaderAgentResult JSON.

Usage:
    python scripts/demo_header_agent.py <path_to_email.eml> [--output <output.json>] [--json-only]
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agents import analyze_headers
from app.ingestion.email_ingestor import ingest_email


def format_status(val: bool | None) -> str:
    if val is True:
        return "[YES/TRUE]"
    elif val is False:
        return "[NO/FALSE]"
    return "[N/A]"


def run_demo(eml_path: str, output_path: str | None = None, json_only: bool = False) -> int:
    path = Path(eml_path)
    if not path.is_file():
        print(f"Error: Email file not found at '{eml_path}'", file=sys.stderr)
        return 1

    try:
        raw_eml_bytes = path.read_bytes()
    except Exception as e:
        print(f"Error reading file '{eml_path}': {e}", file=sys.stderr)
        return 1

    # Ingestion step
    try:
        email_data = ingest_email(raw_eml_bytes, source_filename=path.name)
    except Exception as e:
        print(f"Ingestion Error: {e}", file=sys.stderr)
        return 1

    # Header Agent Analysis step
    try:
        result = analyze_headers(email_data)
    except Exception as e:
        print(f"Header Agent Analysis Error: {e}", file=sys.stderr)
        return 1

    json_str = result.model_dump_json(indent=2)

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json_str, encoding="utf-8")
        print(f"[+] Structured JSON report saved to: {output_path}")

    if json_only:
        print(json_str)
        return 0

    feat = result.features
    avail = result.availability
    ev = result.evidence

    # Printable Terminal Summary
    divider = "=" * 80
    subdivider = "-" * 80

    print(divider)
    print(f"  MULTI-AGENT AI PHISHING EMAIL DETECTOR — HEADER AGENT MVP AUDIT")
    print(divider)
    print(f"  Source File      : {email_data.source_filename}")
    print(f"  Internal Email ID: {email_data.email_id}")
    print(f"  Agent Name/Ver   : {result.agent_name} v{result.agent_version}")
    print(f"  Execution Status : {result.status.upper()}")
    print(f"  Processing Time  : {result.processing_time_ms:.3f} ms")
    print(subdivider)

    print("  [1] IDENTITY & ADDRESS ALIGNMENT (Category A)")
    print(f"      From Header Present         : {format_status(feat.from_present)}")
    print(f"      From Valid Syntax (RFC 5322): {format_status(feat.from_syntax_valid)}")
    print(f"      From Address Count          : {feat.from_address_count}")
    print(f"      Reply-To Header Present     : {format_status(feat.reply_to_present)}")
    print(f"      Return-Path Header Present  : {format_status(feat.return_path_present)}")
    print(f"      From/Reply-To Mismatch      : {format_status(feat.from_reply_to_domain_mismatch)}")
    print(f"      From/Return-Path Mismatch   : {format_status(feat.from_return_path_domain_mismatch)}")
    print(f"      Display Name Contains Email : {format_status(feat.display_name_contains_email)}")
    print(f"      Display Name Domain Mismatch: {format_status(feat.display_name_domain_mismatch)}")
    print(f"      To Mailbox Count            : {feat.recipient_count_to}")
    print(f"      CC Mailbox Count            : {feat.recipient_count_cc}")

    print("\n  [2] ROUTING & TRANSPORT STRUCTURE (Category B)")
    print(f"      Total Received Hops         : {feat.received_hop_count}")
    print(f"      Missing Received Headers    : {format_status(feat.missing_received_headers)}")
    print(f"      Hop Count Anomaly (>15 or 0): {format_status(feat.hop_count_anomaly)}")
    print(f"      Malformed Received Clauses  : {feat.received_syntax_malformed_count}")
    print(f"      Private IP in External Hop  : {format_status(feat.has_private_ip_in_external_hop)}")
    print(f"      Loopback IP in External Hop : {format_status(feat.has_loopback_ip_in_external_hop)}")
    print(f"      Link-Local IP in External   : {format_status(feat.has_link_local_ip_in_external_hop)}")
    print(f"      Special IP in External Hop  : {format_status(feat.has_special_ip_in_external_hop)}")

    print("\n  [3] AUTHENTICATION CLAIMS (Category C - Unverified Receiver Reports)")
    print(f"      Consolidated SPF Status     : {feat.spf_status.value}")
    print(f"      Consolidated DKIM Status    : {feat.dkim_status.value}")
    print(f"      Consolidated DMARC Status   : {feat.dmarc_status.value}")
    print(f"      DKIM-Signature Present      : {format_status(feat.dkim_signature_header_present)}")
    print(f"      DKIM-Sig Present W/O Pass   : {format_status(feat.dkim_signature_present_without_pass)}")
    print(f"      Conflicting Claims (SPF/D/DM: {feat.has_conflicting_spf} / {feat.has_conflicting_dkim} / {feat.has_conflicting_dmarc}")
    print(f"      Reporting MTAs (Authserv-IDs: {ev.parsed_authserv_ids} (Count: {feat.authserv_id_count})")
    print(f"      Inconsistent Authserv-IDs   : {format_status(feat.authserv_id_inconsistent)}")

    print("\n  [4] RFC 5322 METADATA COMPLIANCE (Category D)")
    print(f"      Message-ID Present          : {format_status(feat.message_id_present)}")
    print(f"      Message-ID Valid Syntax     : {format_status(feat.message_id_valid_syntax)}")
    print(f"      Message-ID Domain Mismatch  : {format_status(feat.message_id_domain_mismatch)}")
    print(f"      MIME-Version Present / Valid: {feat.mime_version_present} / {feat.mime_version_valid}")
    print(f"      Subject Present / Char Len  : {feat.has_subject_header} / {feat.subject_length}")
    print(f"      Content-Type Multipart      : {format_status(feat.content_type_is_multipart)}")

    print("\n  [5] DESCRIPTIVE EVIDENCE COMPLETENESS (Section 9.2)")
    print(f"      Identity Completeness       : {avail.completeness_identity * 100:.1f}%")
    print(f"      Routing Completeness        : {avail.completeness_routing * 100:.1f}%")
    print(f"      Authentication Completeness : {avail.completeness_auth * 100:.1f}%")
    print(f"      Metadata Completeness       : {avail.completeness_metadata * 100:.1f}%")
    print(f"      OVERALL TOTAL COMPLETENESS  : {avail.completeness_total * 100:.1f}%")

    print(subdivider)
    print("  [6] OBSERVED ANOMALIES & AUDIT EVIDENCE")
    if ev.observed_anomalies:
        for idx, anom in enumerate(ev.observed_anomalies, 1):
            print(f"      [{idx}] {anom}")
    else:
        print("      (No structural or alignment anomalies observed)")

    if ev.detected_anomalous_ips:
        print(f"      Anomalous IPs detected in transit: {ev.detected_anomalous_ips}")

    if ev.evidence_items:
        print(f"\n      Forensic Evidence Items ({len(ev.evidence_items)} recorded):")
        for i, item in enumerate(ev.evidence_items[:5], 1):
            print(f"        {i}. [{item.feature_name}] {item.header_name}: {item.description}")
            if item.raw_snippet_bounded:
                print(f"           Snippet: {item.raw_snippet_bounded}")
        if len(ev.evidence_items) > 5:
            print(f"        ... ({len(ev.evidence_items) - 5} more evidence items truncated for display)")

    if result.warnings:
        print(f"\n  [7] NON-FATAL WARNINGS ({len(result.warnings)}):")
        for w in result.warnings:
            print(f"      - {w}")

    print(divider)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Header Agent MVP analysis on an RFC 822 email file (.eml)."
    )
    parser.add_argument("eml", help="Path to input .eml file.")
    parser.add_argument("-o", "--output", help="Optional path to write full JSON report.")
    parser.add_argument("--json-only", action="store_true", help="Print only raw JSON output.")

    args = parser.parse_args()
    sys.exit(run_demo(args.eml, output_path=args.output, json_only=args.json_only))


if __name__ == "__main__":
    main()

