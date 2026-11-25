#!/usr/bin/env python3
"""
header_agent_dashboard.py
-------------------------
Interactive Streamlit Dashboard for the Multi-Agent AI Phishing Email Detector.

College Project Live Demonstration — Layer 1 Deterministic Header Agent MVP.
Features:
- Upload raw RFC 822 email (.eml) or load synthetic phishing demo email.
- Runs ingest_email() and analyze_headers() pipeline.
- Visualizes actual Pydantic outputs across 4 categories:
    A. Sender Identity & Address Alignment
    B. Routing & Transport Structure
    C. Authentication Claims (Unverified Receiver Reports)
    D. RFC 5322 Metadata & Compliance
- Displays Tier 2 Forensic Evidence Traces and Observed Anomalies.
- Interactive Feature Explorer across all 45 canonical features and availability flags.
- Downloadable and inspectable serialized HeaderAgentResult JSON report.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

import streamlit as st

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.agents import analyze_headers, classify_ip_address, extract_ips_from_hop
from app.ingestion.email_ingestor import IngestionError, ingest_email
from app.schemas.email_schema import AuthStatus, VerificationStatus
from app.schemas.header_agent_schema import (
    CANONICAL_HEADER_FEATURE_LIST,
    HeaderAgentResult,
)

# ---------------------------------------------------------------------------
# Page Configuration & Cybersecurity Dark Theme Styling
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="PhishGuard AI — Header Agent Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
    /* Dark Navy Cybersecurity Theme */
    .stApp {
        background-color: #0d131f;
        color: #e2e8f0;
        font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #111827;
        border-right: 1px solid #1f2937;
    }
    
    /* Headers */
    h1, h2, h3, h4 {
        color: #f8fafc !important;
        font-weight: 600;
    }
    
    /* Metric Cards */
    div[data-testid="stMetric"] {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 12px 16px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    div[data-testid="stMetricValue"] {
        color: #38bdf8 !important;
        font-size: 1.6rem !important;
        font-weight: 700;
    }
    div[data-testid="stMetricLabel"] {
        color: #94a3b8 !important;
        font-size: 0.85rem !important;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    /* Custom Status Badges */
    .badge-pass {
        background-color: #064e3b;
        color: #34d399;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.82rem;
        font-weight: 600;
        border: 1px solid #059669;
        display: inline-block;
    }
    .badge-fail {
        background-color: #7f1d1d;
        color: #fca5a5;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.82rem;
        font-weight: 600;
        border: 1px solid #dc2626;
        display: inline-block;
    }
    .badge-warn {
        background-color: #78350f;
        color: #fcd34d;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.82rem;
        font-weight: 600;
        border: 1px solid #d97706;
        display: inline-block;
    }
    .badge-neutral {
        background-color: #334155;
        color: #cbd5e1;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.82rem;
        font-weight: 500;
        border: 1px solid #475569;
        display: inline-block;
    }
    
    /* Section Container Cards */
    .dashboard-card {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 20px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    
    /* Tables */
    .styled-table {
        width: 100%;
        border-collapse: collapse;
        margin: 10px 0;
        font-size: 0.88rem;
    }
    .styled-table th {
        background-color: #0f172a;
        color: #94a3b8;
        padding: 10px 12px;
        text-align: left;
        border-bottom: 2px solid #334155;
        font-weight: 600;
    }
    .styled-table td {
        padding: 10px 12px;
        border-bottom: 1px solid #1e293b;
        color: #e2e8f0;
    }
    .styled-table tr:hover {
        background-color: #1e293b;
    }
    
    /* Code snippet bounding */
    .snippet-box {
        background-color: #0f172a;
        border: 1px solid #334155;
        border-radius: 4px;
        padding: 6px 10px;
        font-family: 'Consolas', monospace;
        font-size: 0.82rem;
        color: #cbd5e1;
        word-break: break-all;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Sidebar Navigation & Platform Status
# ---------------------------------------------------------------------------

def render_sidebar():
    with st.sidebar:
        st.markdown("## 🛡️ PhishGuard AI")
        st.markdown(
            "**Multi-Agent AI Phishing Email Detector**\n\n"
            "*A modular security platform combining specialized forensic AI agents.*"
        )
        st.divider()

        st.markdown("### Agent Roster Status")
        st.markdown(
            """
            - 🟢 **Header Agent** — `v0.1.0 (Active MVP)`
              *Deterministic RFC 5322 metadata, routing, & auth analyzer.*
            - ⏳ **URL Agent** — *Under Development*
              *Lexical, redirect, domain age, and typosquatting analysis.*
            - ⏳ **Text Agent** — *Under Development*
              *Semantic intent, psychological urgency, & credential harvesting detection.*
            - ⏳ **Attachment Agent** — *Under Development*
              *MIME mismatches, nested archive inspection, & malicious headers.*
            - ⏳ **Meta-Classifier** — *Under Development*
              *Stacking & logistic regression multi-agent evidence fusion.*
            """
        )
        st.divider()

        st.markdown("### Operational Invariants")
        st.markdown(
            """
            - **Strictly Offline**: Zero network, DNS, or reputation requests.
            - **Leakage-Safe**: Raw text and hostnames strictly excluded from ML vector.
            - **Zero Trust Authentication**: SPF/DKIM/DMARC remain unverified receiver claims.
            - **Zero Fallback Fabrication**: Absent fields normalize to missing (`None`).
            """
        )
        st.divider()
        st.caption("College Final Year Project Live Demonstration")


# ---------------------------------------------------------------------------
# Core Analysis Execution Helper
# ---------------------------------------------------------------------------

def execute_pipeline(raw_bytes: bytes, filename: str) -> tuple[Optional[Any], Optional[HeaderAgentResult], Optional[str]]:
    """
    Executes the ingestion and Header Agent pipeline.
    Returns (email_data, header_result, error_message).
    """
    if not raw_bytes or not raw_bytes.strip():
        return None, None, "Uploaded email file is empty. Please provide a valid RFC 822 .eml file."

    if len(raw_bytes) > 52_428_800:
        return None, None, "Uploaded file exceeds the maximum safety size limit of 50 MB."

    try:
        email_data = ingest_email(raw_bytes, source_filename=filename)
    except IngestionError as exc:
        return None, None, f"Ingestion Error: {exc}"
    except Exception as exc:
        return None, None, f"Email Parsing Error: {exc}"

    try:
        header_result = analyze_headers(email_data)
    except Exception as exc:
        return email_data, None, f"Header Agent Execution Error: {exc}"

    return email_data, header_result, None


# ---------------------------------------------------------------------------
# UI Component Renderers
# ---------------------------------------------------------------------------

def render_overview(res: HeaderAgentResult, email_data: Any):
    st.markdown("### A. Analysis Overview")
    
    # 5 Key Metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Agent Status", res.status.upper())
    with col2:
        st.metric("Processing Time", f"{res.processing_time_ms:.2f} ms")
    with col3:
        # Count available active predictive features (excluding quarantined 11, 12, 21, 22)
        active_features = [
            f for i, f in enumerate(CANONICAL_HEADER_FEATURE_LIST)
            if i not in (10, 11, 20, 21)
        ]
        non_null_active = sum(
            1 for f in active_features if getattr(res.features, f) is not None
        )
        st.metric("Active Features", f"{non_null_active} / 41")
    with col4:
        st.metric("Evidence Traces", len(res.evidence.evidence_items))
    with col5:
        st.metric("Total Completeness", f"{res.availability.completeness_total * 100:.1f}%")

    # Completeness Breakdown
    with st.expander("📊 Descriptive Evidence Completeness Breakdown (RFC 5322 Metadata Coverage)", expanded=False):
        st.caption(
            "Descriptive completeness quantifies information presence across the four RFC 5322 header domains. "
            "It is a structural data coverage metric, not a statistical confidence or probability estimate."
        )
        c_col1, c_col2, c_col3, c_col4 = st.columns(4)
        with c_col1:
            st.write(f"**Identity Coverage**: {res.availability.completeness_identity * 100:.1f}%")
            st.progress(res.availability.completeness_identity)
        with c_col2:
            st.write(f"**Routing Coverage**: {res.availability.completeness_routing * 100:.1f}%")
            st.progress(res.availability.completeness_routing)
        with c_col3:
            st.write(f"**Auth Coverage**: {res.availability.completeness_auth * 100:.1f}%")
            st.progress(res.availability.completeness_auth)
        with c_col4:
            st.write(f"**Metadata Coverage**: {res.availability.completeness_metadata * 100:.1f}%")
            st.progress(res.availability.completeness_metadata)


def render_identity_analysis(res: HeaderAgentResult, email_data: Any):
    st.markdown("### B. Sender & Recipient Identity Analysis")
    feat = res.features

    c1, c2 = st.columns([3, 2])
    with c1:
        st.markdown(
            f"""
            <div class="dashboard-card">
                <h4>Address Fields</h4>
                <p><strong>From:</strong> <code>{email_data.headers.from_address or '(Absent)'}</code></p>
                <p><strong>Reply-To:</strong> <code>{email_data.headers.reply_to or '(None / Absent)'}</code></p>
                <p><strong>Return-Path:</strong> <code>{email_data.headers.return_path or '(None / Absent)'}</code></p>
                <p><strong>To Recipients:</strong> <code>{email_data.headers.to or '[]'}</code> (Mailboxes: <strong>{feat.recipient_count_to if feat.recipient_count_to is not None else 'N/A'}</strong>)</p>
                <p><strong>CC Recipients:</strong> <code>{email_data.headers.cc or '[]'}</code> (Mailboxes: <strong>{feat.recipient_count_cc if feat.recipient_count_cc is not None else 'N/A'}</strong>)</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c2:
        # Badges for alignment checks
        syntax_badge = (
            '<span class="badge-pass">RFC 5322 Valid</span>'
            if feat.from_syntax_valid is True
            else ('<span class="badge-fail">Syntax Malformed</span>' if feat.from_syntax_valid is False else '<span class="badge-neutral">From Absent</span>')
        )
        reply_mismatch_badge = (
            '<span class="badge-fail">Domain Mismatch Detected</span>'
            if feat.from_reply_to_domain_mismatch is True
            else ('<span class="badge-pass">Domains Match</span>' if feat.from_reply_to_domain_mismatch is False else '<span class="badge-neutral">Unavailable (No Reply-To)</span>')
        )
        return_mismatch_badge = (
            '<span class="badge-fail">Domain Mismatch Detected</span>'
            if feat.from_return_path_domain_mismatch is True
            else ('<span class="badge-pass">Domains Match</span>' if feat.from_return_path_domain_mismatch is False else '<span class="badge-neutral">Unavailable (No Return-Path)</span>')
        )
        spoofing_badge = (
            '<span class="badge-fail">Embedded Address Mismatch</span>'
            if feat.display_name_domain_mismatch is True
            else ('<span class="badge-warn">Display Name Embeds Email</span>' if feat.display_name_contains_email else '<span class="badge-pass">No Spoofed Email</span>')
        )

        st.markdown(
            f"""
            <div class="dashboard-card">
                <h4>Identity Integrity Checks</h4>
                <p>From Syntax Check: {syntax_badge}</p>
                <p>From vs Reply-To: {reply_mismatch_badge}</p>
                <p>From vs Return-Path: {return_mismatch_badge}</p>
                <p>Display Name Spoofing: {spoofing_badge}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_routing_analysis(res: HeaderAgentResult, email_data: Any):
    st.markdown("### C. Routing & Transport Analysis")
    feat = res.features

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Received Hops", feat.received_hop_count)
    with col2:
        st.metric("Missing Received Hops", "YES (Anomaly)" if feat.missing_received_headers else "NO")
    with col3:
        st.metric("Hop Anomaly (>15 or 0)", "YES" if feat.hop_count_anomaly else "NO")
    with col4:
        st.metric("Malformed Clauses", feat.received_syntax_malformed_count)

    # Hop Details Table
    if email_data.headers.received:
        st.markdown("#### Transit Hops Inspection")
        hop_rows = []
        for idx, hop_str in enumerate(email_data.headers.received):
            hop_ips = extract_ips_from_hop(hop_str)
            hop_role = "Hop 0 (Receiver Ingress)" if idx == 0 else f"Hop {idx} (External Transit)"
            
            ip_details = []
            for ip_val in hop_ips:
                cat = classify_ip_address(ip_val)
                if cat in ("rfc1918", "rfc4193"):
                    ip_details.append(f"<code>{ip_val}</code> <span class='badge-fail'>{cat.upper()}</span>")
                elif cat in ("loopback", "link_local"):
                    ip_details.append(f"<code>{ip_val}</code> <span class='badge-fail'>{cat.upper()}</span>")
                elif cat in ("cgnat", "documentation", "special_purpose"):
                    ip_details.append(f"<code>{ip_val}</code> <span class='badge-warn'>{cat.upper()}</span>")
                else:
                    ip_details.append(f"<code>{ip_val}</code> <span class='badge-pass'>{cat.upper()}</span>")

            ip_summary = "<br>".join(ip_details) if ip_details else "<span class='badge-neutral'>No IP Extracted</span>"
            hop_snippet = hop_str[:120] + "..." if len(hop_str) > 120 else hop_str
            hop_rows.append(f"<tr><td><strong>{hop_role}</strong></td><td>{ip_summary}</td><td><span class='snippet-box'>{hop_snippet}</span></td></tr>")

        st.markdown(
            f"""
            <table class="styled-table">
                <thead>
                    <tr>
                        <th style="width: 25%;">Hop Role</th>
                        <th style="width: 25%;">Extracted IPs & Classification</th>
                        <th style="width: 50%;">Raw Clause Snippet</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(hop_rows)}
                </tbody>
            </table>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.warning("⚠️ No Received headers present in this email message.")


def render_auth_analysis(res: HeaderAgentResult, email_data: Any):
    st.markdown("### D. Authentication Claims Analysis")
    feat = res.features

    st.info(
        "ℹ️ **Receiver-Reported Claims Notice**: All authentication statuses are passive receiver claims "
        "extracted verbatim from Authentication-Results and Received-SPF headers. In offline analysis, "
        "claims remain strictly **VerificationStatus.UNVERIFIED**. A 'PASS' status does not prove legitimacy "
        "without trusted boundary validation.",
        icon="ℹ️",
    )

    def auth_badge(status: AuthStatus) -> str:
        if status == AuthStatus.PASS:
            return '<span class="badge-pass">PASS (Unverified)</span>'
        elif status in (AuthStatus.FAIL, AuthStatus.PERMERROR):
            return f'<span class="badge-fail">{status.value.upper()}</span>'
        elif status in (AuthStatus.SOFTFAIL, AuthStatus.TEMPERROR, AuthStatus.NEUTRAL):
            return f'<span class="badge-warn">{status.value.upper()}</span>'
        else:
            return f'<span class="badge-neutral">{status.value.upper()}</span>'

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            f"""
            <div class="dashboard-card">
                <h4>SPF Claim</h4>
                <p>Status: {auth_badge(feat.spf_status)}</p>
                <p>Extracted Claims: <strong>{feat.spf_claim_count}</strong></p>
                <p>Conflicting Claims: <strong>{'YES' if feat.has_conflicting_spf else 'NO'}</strong></p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"""
            <div class="dashboard-card">
                <h4>DKIM Claim</h4>
                <p>Status: {auth_badge(feat.dkim_status)}</p>
                <p>Extracted Claims: <strong>{feat.dkim_claim_count}</strong></p>
                <p>Conflicting Claims: <strong>{'YES' if feat.has_conflicting_dkim else 'NO'}</strong></p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f"""
            <div class="dashboard-card">
                <h4>DMARC Claim</h4>
                <p>Status: {auth_badge(feat.dmarc_status)}</p>
                <p>Extracted Claims: <strong>{feat.dmarc_claim_count}</strong></p>
                <p>Conflicting Claims: <strong>{'YES' if feat.has_conflicting_dmarc else 'NO'}</strong></p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # DKIM Signature Header & MTA consistency
    dkim_sig_badge = (
        '<span class="badge-fail">Anomaly: Header Present Without Pass</span>'
        if feat.dkim_signature_present_without_pass
        else ('<span class="badge-pass">Present</span>' if feat.dkim_signature_header_present else '<span class="badge-neutral">Absent</span>')
    )
    authserv_badge = (
        '<span class="badge-warn">Inconsistent Reporting MTAs</span>'
        if feat.authserv_id_inconsistent
        else '<span class="badge-pass">Consistent</span>'
    )

    st.markdown(
        f"""
        <div class="dashboard-card">
            <h4>Authentication Header Consistency</h4>
            <p><strong>DKIM-Signature Header:</strong> {dkim_sig_badge}</p>
            <p><strong>Reporting MTAs (authserv-ids):</strong> <code>{res.evidence.parsed_authserv_ids or 'None'}</code> (Count: {feat.authserv_id_count}) — {authserv_badge}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metadata_analysis(res: HeaderAgentResult, email_data: Any):
    st.markdown("### E. RFC 5322 Metadata & Structure Analysis")
    feat = res.features

    col1, col2 = st.columns(2)
    with col1:
        msg_id_badge = (
            '<span class="badge-pass">RFC Syntax Valid</span>'
            if feat.message_id_valid_syntax is True
            else ('<span class="badge-fail">Syntax Malformed</span>' if feat.message_id_valid_syntax is False else '<span class="badge-neutral">Absent</span>')
        )
        msg_id_mismatch_badge = (
            '<span class="badge-fail">Mismatch with From Domain</span>'
            if feat.message_id_domain_mismatch is True
            else ('<span class="badge-pass">Matches From Domain</span>' if feat.message_id_domain_mismatch is False else '<span class="badge-neutral">Unavailable</span>')
        )
        st.markdown(
            f"""
            <div class="dashboard-card">
                <h4>Message-ID Header</h4>
                <p>Raw Value: <code>{email_data.headers.message_id or '(Absent)'}</code></p>
                <p>Syntax Check: {msg_id_badge}</p>
                <p>Domain Alignment: {msg_id_mismatch_badge}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        mime_badge = (
            '<span class="badge-pass">Standard 1.0</span>'
            if feat.mime_version_valid is True
            else ('<span class="badge-fail">Non-Standard</span>' if feat.mime_version_valid is False else '<span class="badge-neutral">Absent</span>')
        )
        content_type_badge = (
            '<span class="badge-pass">Multipart</span>'
            if feat.content_type_is_multipart is True
            else ('<span class="badge-neutral">Singlepart</span>' if feat.content_type_is_multipart is False else '<span class="badge-neutral">Absent</span>')
        )
        st.markdown(
            f"""
            <div class="dashboard-card">
                <h4>MIME & Content-Type</h4>
                <p>MIME-Version: <code>{email_data.headers.mime_version or '(Absent)'}</code> — {mime_badge}</p>
                <p>Subject Length: <strong>{feat.subject_length}</strong> characters (Present: <strong>{'YES' if feat.has_subject_header else 'NO'}</strong>)</p>
                <p>Content-Type: <code>{email_data.headers.content_type or '(Absent)'}</code> — {content_type_badge}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_evidence_and_anomalies(res: HeaderAgentResult):
    st.markdown("### F. Forensic Evidence & Audit Trail")

    ev = res.evidence
    if ev.observed_anomalies:
        st.markdown("#### 🚨 Observed Structural & Alignment Anomalies")
        for idx, anom in enumerate(ev.observed_anomalies, 1):
            st.error(f"**Anomaly {idx}**: {anom}", icon="🚨")
    else:
        st.success("✅ **Header Agent Audit Clean**: No structural or alignment anomalies observed.", icon="✅")

    if ev.detected_anomalous_ips:
        st.warning(f"⚠️ **Anomalous IPs In Transit Hops**: {ev.detected_anomalous_ips}", icon="⚠️")

    if ev.evidence_items:
        st.markdown(f"#### 🔍 Forensic Evidence Items ({len(ev.evidence_items)} Traced)")
        table_rows = []
        for i, item in enumerate(ev.evidence_items, 1):
            snippet_html = f"<span class='snippet-box'>{item.raw_snippet_bounded}</span>" if item.raw_snippet_bounded else "<em>(None)</em>"
            table_rows.append(
                f"""
                <tr>
                    <td><strong>{i}</strong></td>
                    <td><code>{item.feature_name}</code></td>
                    <td>{item.header_name}</td>
                    <td>{item.description}</td>
                    <td><span class="badge-neutral">{item.verification_status.value.upper()}</span></td>
                    <td>{snippet_html}</td>
                </tr>
                """
            )
        st.markdown(
            f"""
            <table class="styled-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Feature Name</th>
                        <th>Header</th>
                        <th>Description</th>
                        <th>Verification Status</th>
                        <th>Sanitized Snippet</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(table_rows)}
                </tbody>
            </table>
            """,
            unsafe_allow_html=True,
        )

    if res.warnings:
        st.markdown("#### ⚠️ Non-Fatal Parser & Header Warnings")
        for w in res.warnings:
            st.warning(w, icon="⚠️")


def render_feature_explorer(res: HeaderAgentResult):
    st.markdown("### G. Feature Explorer (All 45 Canonical Features)")
    
    tab1, tab2 = st.tabs(["📋 Canonical 45-Feature Vector", "🔍 Missingness & Availability Manifest"])
    
    with tab1:
        st.caption("Machine-auditable continuous 45-feature registry in exact canonical order.")
        
        # Categorize
        cat_map = {}
        for i, f_name in enumerate(CANONICAL_HEADER_FEATURE_LIST):
            if i < 13:
                cat = "Category A: Identity Alignment"
            elif i < 23:
                cat = "Category B: Routing Structure"
            elif i < 36:
                cat = "Category C: Authentication Claims"
            else:
                cat = "Category D: Metadata Compliance"
            cat_map[f_name] = (i + 1, cat)

        features_dict = res.features.model_dump()
        table_data = []
        for f_name in CANONICAL_HEADER_FEATURE_LIST:
            f_num, cat = cat_map[f_name]
            val = features_dict.get(f_name)
            
            # Quarantined status
            if f_num in (11, 12, 21, 22):
                status_str = "Quarantined / Inactive"
            else:
                status_str = "Active Predictive"

            table_data.append({
                "#": f_num,
                "Feature Identifier": f_name,
                "Category": cat,
                "Extracted Value": str(val) if val is not None else "None (Unavailable)",
                "Status": status_str,
            })
            
        st.dataframe(table_data, use_container_width=True, height=450)

    with tab2:
        st.caption("Per-feature availability flags tracked to prevent missingness confounding in downstream models.")
        avail_dict = res.availability.model_dump()
        avail_items = [
            {"Availability Flag": k, "Value": "Available (True)" if v is True else ("Unavailable (False)" if v is False else str(v))}
            for k, v in avail_dict.items()
        ]
        st.dataframe(avail_items, use_container_width=True, height=450)


def render_json_report(res: HeaderAgentResult):
    st.markdown("### H. Serialized JSON Report (HeaderAgentResult)")
    json_bytes = res.model_dump_json(indent=2).encode("utf-8")
    
    st.download_button(
        label="📥 Download JSON Report",
        data=json_bytes,
        file_name=f"header_agent_report_{res.email_id}.json",
        mime="application/json",
        use_container_width=True,
    )

    with st.expander("👁️ View Full Serialized HeaderAgentResult JSON", expanded=False):
        st.json(json.loads(res.model_dump_json()))


# ---------------------------------------------------------------------------
# Main Application Flow
# ---------------------------------------------------------------------------

def main():
    render_sidebar()

    st.title("Multi-Agent AI Phishing Email Detector")
    st.markdown(
        "**Intelligent email security analysis using specialized AI agents.**\n\n"
        "*Upload an RFC 822 email (`.eml`) file below to execute Layer 1 deterministic header analysis.*"
    )
    st.divider()

    # Session State Management for Sample Loading
    if "raw_eml_bytes" not in st.session_state:
        st.session_state.raw_eml_bytes = None
    if "eml_filename" not in st.session_state:
        st.session_state.eml_filename = None

    # Upload Section
    c_upload, c_sample = st.columns([3, 2])
    with c_upload:
        uploaded_file = st.file_uploader(
            "Upload Email File (.eml)",
            type=["eml"],
            help="Select an RFC 822 email message file (.eml format, max 50 MB).",
        )
        if uploaded_file is not None:
            st.session_state.raw_eml_bytes = uploaded_file.getvalue()
            st.session_state.eml_filename = uploaded_file.name

    with c_sample:
        st.markdown("**Or Test With a Pre-Configured Sample:**")
        sample_path = PROJECT_ROOT / "data" / "samples" / "synthetic_demo.eml"
        if sample_path.exists():
            if st.button("🧪 Load Synthetic Phishing Demo Email", use_container_width=True):
                st.session_state.raw_eml_bytes = sample_path.read_bytes()
                st.session_state.eml_filename = "synthetic_demo.eml"
                st.success("Loaded 'synthetic_demo.eml' (Credential Harvesting & Spoofing Scenario)")
        else:
            st.caption("No sample email found in `data/samples/`.")

    # Status & Analysis Trigger
    if st.session_state.raw_eml_bytes is not None:
        file_size_kb = len(st.session_state.raw_eml_bytes) / 1024.0
        st.markdown(
            f"**Selected Email:** ` {st.session_state.eml_filename} ` "
            f"*(Size: {file_size_kb:.2f} KB / {len(st.session_state.raw_eml_bytes)} bytes)*"
        )
        
        analyze_clicked = st.button("🔍 Analyze Email Headers", type="primary", use_container_width=True)

        # Trigger analysis automatically if button clicked or if already in state
        if analyze_clicked or "last_analyzed_file" in st.session_state and st.session_state.last_analyzed_file == st.session_state.eml_filename:
            st.session_state.last_analyzed_file = st.session_state.eml_filename
            with st.spinner("Analyzing email headers and authentication claims..."):
                email_data, result, err = execute_pipeline(
                    st.session_state.raw_eml_bytes, st.session_state.eml_filename
                )

            if err:
                st.error(f"❌ {err}")
            elif result is not None:
                st.divider()
                render_overview(result, email_data)
                st.divider()
                render_identity_analysis(result, email_data)
                st.divider()
                render_routing_analysis(result, email_data)
                st.divider()
                render_auth_analysis(result, email_data)
                st.divider()
                render_metadata_analysis(result, email_data)
                st.divider()
                render_evidence_and_anomalies(result)
                st.divider()
                render_feature_explorer(result)
                st.divider()
                render_json_report(result)
    else:
        st.info("👆 Please upload an `.eml` file or click **'Load Synthetic Phishing Demo Email'** to begin analysis.")


if __name__ == "__main__":
    main()

