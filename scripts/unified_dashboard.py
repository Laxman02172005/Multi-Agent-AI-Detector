#!/usr/bin/env python3
"""
scripts/unified_dashboard.py
-----------------------------
Phishing Email Checker — Clean, user-friendly SOC & end-user dashboard.

Three input modes:
  1. Upload a mail file (.eml, .msg, .mbox, .txt)
  2. Connect Gmail via IMAP (imaplib, SSL, password never persisted to disk)
  3. Paste raw email text or try a built-in sample

Backend: PhishingDetectorPipeline (100% passive, offline ML engine).
Strict dependencies: Python stdlib + packages in requirements.txt only.
"""
from __future__ import annotations

import email as email_lib
import email.policy
import imaplib
import io
import json
import mailbox
import os
from pathlib import Path
import sys
from typing import Optional

import streamlit as st

# ── Project root ──────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.pipeline.orchestrator import PhishingDetectorPipeline, PipelineInitializationError
from app.schemas.meta_classifier_schema import DecisionThresholds, Verdict
from app.schemas.pipeline_schema import PhishingAnalysisReport

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Phishing Email Checker",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────────────────────────────────────────────────────────
# CSS — Clean, minimal, human-friendly dark theme
# ─────────────────────────────────────────────────────────────────────────────
CSS = """
<style>
/* ── Resets ─────────────────────────────────────────────────────────────── */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 0 2rem 3rem 2rem !important; max-width: 1100px; }
html, body, [class*="css"] {
    font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
}
.stApp { background: #0C1017; color: #CBD5E1; }

/* ── Top bar ─────────────────────────────────────────────────────────────── */
.top-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 0 14px 0;
    border-bottom: 1px solid #1E293B;
    margin-bottom: 28px;
}
.top-bar-title {
    font-size: 1.25rem;
    font-weight: 800;
    color: #F1F5F9;
    letter-spacing: 0.01em;
}
.top-bar-title span { color: #38BDF8; }
.mode-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}
.mode-offline { background: rgba(56,189,248,0.10); border: 1px solid #0369A1; color: #38BDF8; }
.mode-gmail   { background: rgba(234,88,12,0.12);  border: 1px solid #C2410C; color: #FB923C; }

/* ── Input tabs ──────────────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {
    gap: 0;
    background: #111827;
    border: 1px solid #1E293B;
    border-radius: 10px 10px 0 0;
    padding: 0;
}
.stTabs [data-baseweb="tab"] {
    padding: 11px 22px;
    font-size: 0.85rem;
    font-weight: 600;
    color: #64748B !important;
    border-bottom: 2px solid transparent;
    border-radius: 0;
}
.stTabs [aria-selected="true"] {
    color: #F1F5F9 !important;
    border-bottom: 2px solid #38BDF8 !important;
    background: transparent !important;
}
.stTabs [data-baseweb="tab-panel"] {
    background: #111827;
    border: 1px solid #1E293B;
    border-top: none;
    border-radius: 0 0 10px 10px;
    padding: 20px 24px 24px 24px;
}

/* ── Buttons ─────────────────────────────────────────────────────────────── */
.stButton > button {
    border-radius: 8px !important;
    font-weight: 600 !important;
    font-size: 0.88rem !important;
    transition: all 0.15s ease;
}

/* ── Sample chips ────────────────────────────────────────────────────────── */
.sample-chip-safe {
    display:inline-block; padding:7px 16px; border-radius:20px;
    background:rgba(16,185,129,0.12); border:1px solid #047857;
    color:#34D399; font-size:0.82rem; font-weight:700; cursor:pointer;
}
.sample-chip-phish {
    display:inline-block; padding:7px 16px; border-radius:20px;
    background:rgba(239,68,68,0.12); border:1px solid #B91C1C;
    color:#FCA5A5; font-size:0.82rem; font-weight:700; cursor:pointer;
}

/* ── Verdict banner ──────────────────────────────────────────────────────── */
.verdict-wrap {
    border-radius: 14px;
    padding: 28px 32px;
    margin: 24px 0 20px 0;
    display: flex;
    align-items: flex-start;
    gap: 24px;
}
.verdict-safe    { background: linear-gradient(130deg,#061710,#092B1C); border: 1.5px solid #047857; }
.verdict-phish   { background: linear-gradient(130deg,#180808,#2A0C0C); border: 1.5px solid #B91C1C; }
.verdict-abstain { background: linear-gradient(130deg,#17120A,#261C0A); border: 1.5px solid #B45309; }
.verdict-icon   { font-size: 2.8rem; line-height: 1; flex-shrink: 0; }
.verdict-label  { font-size: 1.55rem; font-weight: 800; letter-spacing: 0.01em; margin-bottom: 6px; }
.verdict-plain  { font-size: 0.95rem; color: #94A3B8; line-height: 1.65; }
.verdict-score  {
    margin-left: auto; text-align: right; flex-shrink: 0;
    display: flex; flex-direction: column; align-items: flex-end; gap: 4px;
}
.score-num  { font-size: 2.6rem; font-weight: 800; letter-spacing: -0.03em; line-height: 1; }
.score-lbl  { font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.1em; color: #64748B; }

/* ── KPI strip ────────────────────────────────────────────────────────────── */
.kpi-row { display: flex; gap: 10px; margin: 0 0 20px 0; flex-wrap: wrap; }
.kpi-card {
    flex: 1 1 130px;
    background: #111827;
    border: 1px solid #1E293B;
    border-radius: 10px;
    padding: 14px 16px;
    min-width: 110px;
}
.kpi-lbl {
    font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.12em;
    color: #475569; margin-bottom: 5px;
}
.kpi-val {
    font-size: clamp(0.95rem, 1.3vw, 1.2rem);
    font-weight: 800; color: #E2E8F0;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}

/* ── Modality check row ──────────────────────────────────────────────────── */
.check-grid { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px; }
.check-card {
    flex: 1 1 200px;
    background: #111827;
    border: 1px solid #1E293B;
    border-radius: 10px;
    padding: 16px 18px;
}
.check-card-name {
    font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.1em;
    color: #475569; margin-bottom: 4px;
}
.check-card-label { font-size: 0.95rem; font-weight: 700; color: #E2E8F0; margin-bottom: 8px; }
.check-bar-bg { background: #1E293B; border-radius: 4px; height: 5px; overflow: hidden; }
.check-bar-fill { height: 5px; border-radius: 4px; }
.check-status { font-size: 0.75rem; margin-top: 6px; }
.ok  { color: #34D399; } .warn { color: #FCD34D; } .bad { color: #F87171; } .dim { color: #64748B; }

/* ── Evidence cards ──────────────────────────────────────────────────────── */
.ev { background:#0D1117; border:1px solid #1E293B; border-left:3px solid #334155;
    border-radius:7px; padding:12px 16px; margin-bottom:9px; }
.ev-crit { border-left-color:#EF4444; } .ev-high { border-left-color:#F97316; }
.ev-med  { border-left-color:#EAB308; } .ev-low  { border-left-color:#3B82F6; }
.ev-info { border-left-color:#334155; }
.ev-top  { display:flex; justify-content:space-between; align-items:center; margin-bottom:5px; }
.ev-name { font-weight:700; color:#E2E8F0; font-size:0.86rem; }
.ev-badges { display:flex; gap:5px; }
.ev-pill { font-size:0.63rem; padding:2px 7px; border-radius:3px; font-weight:700; }
.sev-crit{background:rgba(239,68,68,.2);color:#F87171;}
.sev-high{background:rgba(249,115,22,.2);color:#FDBA74;}
.sev-med {background:rgba(234,179,8,.2); color:#FCD34D;}
.sev-low {background:rgba(59,130,246,.2);color:#93C5FD;}
.sev-info{background:rgba(100,116,139,.2);color:#94A3B8;}
.mod-pill{background:rgba(56,189,248,.12);color:#38BDF8;}
.ev-desc { font-size:0.83rem; color:#94A3B8; }
.ev-snip { font-family:monospace; font-size:0.77rem; color:#64748B;
    background:#0A0D14; border-radius:4px; padding:6px 10px; margin-top:7px;
    white-space:pre-wrap; word-break:break-all; }

/* ── Attribution ─────────────────────────────────────────────────────────── */
.attr-row { display:flex; align-items:center; gap:10px; margin-bottom:8px; font-size:0.84rem; }
.attr-lbl { flex:0 0 210px; color:#CBD5E1; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.attr-bar-bg { flex:1; background:#1E293B; border-radius:3px; height:7px; overflow:hidden; }
.attr-phish  { background:linear-gradient(90deg,#991B1B,#EF4444); height:7px; border-radius:3px; }
.attr-legit  { background:linear-gradient(90deg,#047857,#10B981); height:7px; border-radius:3px; float:right; }
.attr-score  { flex:0 0 56px; text-align:right; font-weight:700; font-family:monospace; }

/* ── Gmail form ──────────────────────────────────────────────────────────── */
.gmail-info {
    background:#111827; border:1px solid #1E293B; border-radius:10px;
    padding:16px 18px; font-size:0.84rem; color:#94A3B8; margin-bottom:16px;
    line-height:1.7;
}
.gmail-info b { color:#E2E8F0; }

/* ── Misc ────────────────────────────────────────────────────────────────── */
.section-label {
    font-size:0.68rem; text-transform:uppercase; letter-spacing:0.14em;
    color:#475569; margin-bottom:10px;
}
.helper-text { font-size:0.82rem; color:#64748B; margin-top:4px; }
div[data-testid="stMetric"] { background:#111827; border:1px solid #1E293B; border-radius:9px; padding:12px 16px; }
div[data-testid="stMetricValue"] { color:#38BDF8 !important; font-weight:800 !important; }
div[data-testid="stMetricLabel"] { color:#64748B !important; font-size:0.72rem !important;
    text-transform:uppercase; letter-spacing:0.08em; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS — built-in sample emails
# ─────────────────────────────────────────────────────────────────────────────
_DEV_EML = PROJECT_ROOT / "data" / "dev" / "eml"
_SAMPLES  = PROJECT_ROOT / "data" / "samples"

SAFE_SAMPLE    = _DEV_EML / "ham_easy"  / "easy_ham_000001_9f8b61b0348d.eml"
PHISH_SAMPLE   = _DEV_EML / "phishing"  / "nazario_2015_000001_5784bb2ec05f.eml"
SYNTH_SAMPLE   = _SAMPLES  / "synthetic_demo.eml"


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE — cached by model dir only; thresholds injected per-request
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_resource(show_spinner=False)
def _load_pipeline(model_dir: str) -> Optional[PhishingDetectorPipeline]:
    try:
        return PhishingDetectorPipeline(model_path=model_dir)
    except Exception:
        return None


def _run_analysis(
    pipeline: PhishingDetectorPipeline,
    raw_bytes: bytes,
    abstain_low: float,
    abstain_high: float,
) -> PhishingAnalysisReport:
    pipeline.thresholds = DecisionThresholds(
        abstain_low=abstain_low, abstain_high=abstain_high
    )
    return pipeline.analyze_raw_email(raw_bytes)


# ─────────────────────────────────────────────────────────────────────────────
# MBOX HELPER — let user pick a message from an .mbox archive
# ─────────────────────────────────────────────────────────────────────────────
def _pick_from_mbox(mbox_bytes: bytes) -> Optional[bytes]:
    """Parse an mbox file and return the user-selected raw message bytes."""
    import tempfile, os as _os
    with tempfile.NamedTemporaryFile(delete=False, suffix=".mbox") as tf:
        tf.write(mbox_bytes)
        tmp_path = tf.name
    try:
        mbox = mailbox.mbox(tmp_path)
        messages = list(mbox)
        if not messages:
            st.warning("No messages found in the .mbox file.")
            return None
        # Build human-readable labels
        labels = []
        for i, msg in enumerate(messages):
            subj = msg.get("Subject", "(no subject)") or "(no subject)"
            frm  = msg.get("From", "") or ""
            labels.append(f"[{i+1}] {subj[:55]} — {frm[:30]}")
        idx = st.selectbox(
            f"📬 Mailbox contains **{len(messages)}** messages — pick one to scan:",
            range(len(messages)),
            format_func=lambda i: labels[i],
        )
        raw = messages[idx].as_bytes()
        return raw
    except Exception as ex:
        st.error(f"Could not parse .mbox file: {ex}")
        return None
    finally:
        try:
            _os.unlink(tmp_path)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# MSG HELPER — best-effort extraction of .msg (Outlook) files via stdlib
# ─────────────────────────────────────────────────────────────────────────────
def _msg_to_rfc822(msg_bytes: bytes) -> bytes:
    """
    Best-effort .msg → RFC 822 fallback using stdlib only.
    Reads visible ASCII headers and body from the raw binary blob.
    """
    try:
        text = msg_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = msg_bytes.decode("latin-1", errors="replace")
    # Heuristic: try to extract something useful
    lines = []
    for line in text.splitlines():
        printable = "".join(c for c in line if c.isprintable() or c in "\t ")
        if printable.strip():
            lines.append(printable)
    fallback = "\r\n".join(lines[:200])
    return f"Subject: (Extracted from .msg)\r\n\r\n{fallback}".encode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# GMAIL IMAP HELPER
# ─────────────────────────────────────────────────────────────────────────────
def _fetch_gmail_messages(address: str, app_password: str, folder: str, limit: int) -> list[dict]:
    """
    Fetch up to `limit` recent messages from Gmail via IMAP+SSL.
    Returns list of dicts: {uid, subject, from_, raw_bytes}.
    Password is NEVER written to disk.
    """
    messages = []
    try:
        imap = imaplib.IMAP4_SSL("imap.gmail.com", 993)
        imap.login(address, app_password)
        imap.select(folder, readonly=True)
        _, data = imap.search(None, "ALL")
        uids = data[0].split()[-limit:]  # most recent N
        for uid in reversed(uids):
            _, raw = imap.fetch(uid, "(RFC822)")
            if raw and raw[0]:
                raw_bytes = raw[0][1]
                msg = email_lib.message_from_bytes(raw_bytes, policy=email_lib.policy.default)
                messages.append({
                    "uid": uid.decode(),
                    "subject": str(msg.get("Subject", "(no subject)"))[:80],
                    "from_": str(msg.get("From", ""))[:60],
                    "raw_bytes": raw_bytes,
                })
        imap.logout()
    except imaplib.IMAP4.error as e:
        raise RuntimeError(f"IMAP login failed: {e}") from e
    except Exception as e:
        raise RuntimeError(f"Gmail fetch error: {e}") from e
    return messages


# ─────────────────────────────────────────────────────────────────────────────
# VERDICT RENDERING HELPERS
# ─────────────────────────────────────────────────────────────────────────────
_SEV_CSS  = {"critical":"sev-crit","high":"sev-high","medium":"sev-med",
             "low":"sev-low","info":"sev-info"}
_EV_CLS   = {"critical":"ev-crit","high":"ev-high","medium":"ev-med",
             "low":"ev-low","info":"ev-info"}


def _bar_fill(value: float) -> str:
    pct = max(0, min(1, value)) * 100
    color = "#10B981" if pct >= 75 else "#EAB308" if pct >= 45 else "#EF4444"
    return (f'<div class="check-bar-bg">'
            f'<div class="check-bar-fill" style="width:{pct:.1f}%;background:{color};"></div>'
            f'</div>')


def _status_cls(status: str) -> str:
    return {"available":"ok","empty":"dim","degraded":"warn","failed":"bad"}.get(status.lower(), "dim")


def _status_label(status: str) -> str:
    return {"available":"✓ Available","empty":"○ Empty","degraded":"⚠ Degraded",
            "failed":"✖ Failed"}.get(status.lower(), status)


def _attr_bar(score: float, max_abs: float, is_phish: bool) -> str:
    pct = min(100.0, abs(score) / max(max_abs, 1e-9) * 100)
    cls = "attr-phish" if is_phish else "attr-legit"
    return f'<div class="attr-bar-bg"><div class="{cls}" style="width:{pct:.1f}%"></div></div>'


# ─────────────────────────────────────────────────────────────────────────────
# RENDER VERDICT PANEL
# ─────────────────────────────────────────────────────────────────────────────
def _render_verdict(report: PhishingAnalysisReport) -> None:
    v   = report.verdict_result
    agg = report.aggregated_evidence

    prob = v.calibrated_probability
    prob_str = f"{prob:.0%}" if prob is not None else "N/A"
    conf_str = f"{v.confidence:.0%}"
    lat_str  = f"{report.total_processing_time_ms:.0f} ms"

    # ── Big banner ──
    if v.verdict == Verdict.PHISHING:
        css, icon = "verdict-phish", "🚨"
        label     = "Likely Phishing"
        plain     = (
            "This email shows signs of a phishing attempt — "
            "suspicious links, misleading sender identity, or deceptive content were detected. "
            "Do not click links or download attachments."
        )
        score_color = "#EF4444"
    elif v.verdict == Verdict.LEGITIMATE:
        css, icon = "verdict-safe", "✅"
        label     = "Safe Email"
        plain     = (
            "No strong indicators of phishing were found. "
            "Authentication checks, link destinations, and message content appear normal."
        )
        score_color = "#10B981"
    else:
        reason  = v.abstention_reason.value.replace("_", " ").title()
        css, icon = "verdict-abstain", "⚠"
        label   = "Needs Review"
        plain   = (
            f"The result is inconclusive ({reason}). "
            "The email's signals are ambiguous — treat with caution and review manually before acting."
        )
        score_color = "#F59E0B"

    st.markdown(
        f"""<div class="verdict-wrap {css}">
            <div class="verdict-icon">{icon}</div>
            <div style="flex:1;">
                <div class="verdict-label" style="color:{score_color};">{label}</div>
                <div class="verdict-plain">{plain}</div>
            </div>
            <div class="verdict-score">
                <div class="score-lbl">Phishing risk</div>
                <div class="score-num" style="color:{score_color};">{prob_str}</div>
                <div style="font-size:0.76rem;color:#64748B;margin-top:2px;">confidence&nbsp;{conf_str}</div>
            </div>
        </div>""",
        unsafe_allow_html=True,
    )

    # ── KPI strip ──
    kpis = [
        ("Verdict",      label),
        ("Phishing risk", prob_str),
        ("Confidence",   conf_str),
        ("Completeness", f"{agg.overall_completeness:.0%}"),
        ("Latency",      lat_str),
        ("Email ID",     report.email_id[-16:]),
    ]
    cols = st.columns(len(kpis))
    for col, (lbl, val) in zip(cols, kpis):
        col.markdown(
            f'<div class="kpi-card"><div class="kpi-lbl">{lbl}</div>'
            f'<div class="kpi-val">{val}</div></div>',
            unsafe_allow_html=True,
        )

    # ── What was checked ──
    st.markdown('<div class="section-label" style="margin-top:20px;">WHAT WE CHECKED</div>',
                unsafe_allow_html=True)
    mods = {
        "header":     ("📋 Sender & Headers",    "Return path, auth claims, routing hops"),
        "url":        ("🔗 Links",                "Destination domains, redirects, anchor text"),
        "text":       ("💬 Message Text",         "Urgency cues, credential lures, hidden content"),
        "attachment": ("📎 Attachments",          "Executable files, macro documents"),
    }
    mcols = st.columns(4)
    for col, (mkey, (mlabel, mdesc)) in zip(mcols, mods.items()):
        health = agg.modality_health.get(mkey)
        with col:
            if health:
                sc  = _status_cls(health.status.value)
                sl  = _status_label(health.status.value)
                bar = _bar_fill(health.completeness)
                st.markdown(
                    f"""<div class="check-card">
                        <div class="check-card-name">CHECKED</div>
                        <div class="check-card-label">{mlabel}</div>
                        {bar}
                        <div class="check-status">
                            <span class="{sc}">{sl}</span>
                            &nbsp;·&nbsp;
                            <span style="color:#475569;font-size:0.72rem;">{health.completeness:.0%}</span>
                        </div>
                        <div style="font-size:0.72rem;color:#334155;margin-top:6px;">{mdesc}</div>
                    </div>""",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"""<div class="check-card">
                        <div class="check-card-name">CHECKED</div>
                        <div class="check-card-label">{mlabel}</div>
                        <div class="check-status bad">✖ Not evaluated</div>
                        <div style="font-size:0.72rem;color:#334155;margin-top:6px;">{mdesc}</div>
                    </div>""",
                    unsafe_allow_html=True,
                )

    # ── Deep-dive tabs ──
    st.markdown("<br>", unsafe_allow_html=True)
    dt1, dt2, dt3 = st.tabs([
        "🔍 Why this verdict",
        "📋 Forensic evidence",
        "⚙ Technical / Analyst details",
    ])

    # TAB 1: Why ──────────────────────────────────────────────────────────────
    with dt1:
        phish_c = v.top_phishing_contributors
        legit_c = v.top_legitimate_contributors
        c1, c2  = st.columns(2)

        def _attr_col(col, contribs, title: str, is_phish: bool):
            with col:
                st.markdown(f'<div class="section-label">{title}</div>', unsafe_allow_html=True)
                if not contribs:
                    st.caption("No strong contributors found.")
                    return
                max_abs = max(abs(c.contribution_score) for c in contribs) or 1.0
                for c in contribs:
                    short = c.feature_name
                    for pfx in ("header_","url_","text_","attachment_"):
                        if short.startswith(pfx):
                            short = short[len(pfx):]; break
                    sign  = "+" if c.contribution_score >= 0 else ""
                    color = "#EF4444" if is_phish else "#10B981"
                    bar   = _attr_bar(c.contribution_score, max_abs, is_phish)
                    st.markdown(
                        f"""<div class="attr-row">
                            <div class="attr-lbl" title="{c.feature_name}">
                                <span style="font-size:0.6rem;color:#334155;text-transform:uppercase;
                                    letter-spacing:.06em;margin-right:4px;">{c.modality[:3]}</span>{short}
                            </div>
                            {bar}
                            <div class="attr-score" style="color:{color};">{sign}{c.contribution_score:.3f}</div>
                        </div>""",
                        unsafe_allow_html=True,
                    )

        _attr_col(c1, phish_c, "🚨 PHISHING SIGNALS", True)
        _attr_col(c2, legit_c, "✅ SAFE SIGNALS", False)
        st.caption(
            "Each bar shows the signed log-odds contribution  `w·x̃`  of a feature. "
            "Longer red bars = stronger phishing evidence; longer green bars = safer signals."
        )

    # TAB 2: Forensic evidence ────────────────────────────────────────────────
    with dt2:
        evidence = agg.unified_evidence
        if not evidence:
            st.info("No significant anomalies recorded for this email.")
        else:
            fc1, fc2 = st.columns([2, 2])
            with fc1:
                sel_sevs = st.multiselect(
                    "Severity", ["critical","high","medium","low","info"],
                    default=["critical","high","medium"],
                    label_visibility="collapsed",
                )
            with fc2:
                sel_mods = st.multiselect(
                    "Modality", ["header","url","text","attachment"],
                    default=["header","url","text","attachment"],
                    label_visibility="collapsed",
                )
            filtered = [e for e in evidence
                        if e.severity in sel_sevs and e.source_modality in sel_mods]
            st.caption(f"Showing **{len(filtered)}** of {len(evidence)} observations "
                       + (f"({agg.omitted_evidence_count} omitted by cap)" if agg.omitted_evidence_count else ""))
            for ev in filtered:
                sev_cls = _SEV_CSS.get(ev.severity, "sev-info")
                ev_cls  = _EV_CLS.get(ev.severity, "ev-info")
                snip    = (f'<div class="ev-snip">{ev.snippet_bounded[:300]}</div>'
                           if ev.snippet_bounded else "")
                st.markdown(
                    f"""<div class="ev {ev_cls}">
                        <div class="ev-top">
                            <div class="ev-name">{ev.feature_name}</div>
                            <div class="ev-badges">
                                <span class="ev-pill {sev_cls}">{ev.severity.upper()}</span>
                                <span class="ev-pill mod-pill">{ev.source_modality.upper()}</span>
                            </div>
                        </div>
                        <div class="ev-desc">{ev.description}</div>
                        {snip}
                    </div>""",
                    unsafe_allow_html=True,
                )

    # TAB 3: Technical / Analyst ──────────────────────────────────────────────
    with dt3:
        vec = agg.feature_vector
        with st.expander("🎚 Adjust abstention thresholds", expanded=False):
            st.caption(
                "These thresholds define the uncertainty band. Emails with risk probability "
                "between τ_low and τ_high are marked **Needs Review** instead of a forced verdict."
            )
            new_low  = st.slider("τ_low  (Legitimate ceiling)", 0.05, 0.45,
                                 st.session_state.get("abstain_low", 0.25), 0.05)
            new_high = st.slider("τ_high (Phishing floor)",     0.55, 0.95,
                                 st.session_state.get("abstain_high", 0.60), 0.05)
            st.session_state["abstain_low"]   = new_low
            st.session_state["abstain_high"]  = new_high
            if st.button("Re-analyze with new thresholds"):
                st.session_state["rerun_thresholds"] = True
                st.rerun()

        with st.expander("🧬 132-Feature meta-vector", expanded=False):
            search_f = st.text_input("Search features", placeholder="e.g. dkim, entropy, url…",
                                     label_visibility="collapsed")
            rows = []
            for idx, fname in enumerate(vec.feature_names):
                if search_f and search_f.lower() not in fname.lower():
                    continue
                rows.append({
                    "#": idx + 1,
                    "Modality": fname.split("_",1)[0].upper(),
                    "Feature":  fname,
                    "Value":    round(vec.feature_values.get(fname, 0.0), 4),
                    "Missing":  bool(vec.missingness_mask.get(fname, 0)),
                })
            st.dataframe(rows, use_container_width=True, height=360,
                column_config={
                    "#":        st.column_config.NumberColumn(width="small"),
                    "Modality": st.column_config.TextColumn(width="small"),
                    "Feature":  st.column_config.TextColumn(width="large"),
                    "Value":    st.column_config.NumberColumn(format="%.4f", width="small"),
                    "Missing":  st.column_config.CheckboxColumn(width="small"),
                })

        with st.expander("📄 Agent errors", expanded=bool(report.agent_errors)):
            if report.agent_errors:
                for mod, err in report.agent_errors.items():
                    st.error(f"**{mod.upper()}**: {err}")
            else:
                st.success("All 4 specialist agents completed without errors.")

        with st.expander("💾 Export full report (JSON)", expanded=False):
            json_str = report.model_dump_json(indent=2)
            st.download_button(
                "⬇ Download PhishingAnalysisReport.json",
                data=json_str,
                file_name=f"phish_report_{report.email_id}.json",
                mime="application/json",
                use_container_width=True,
            )
            st.caption(f"Full Pydantic v2 audit report · {len(json_str):,} bytes · Email ID: `{report.email_id}`")
            st.json(json.loads(json_str), expanded=False)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    # ── Defaults in session state ──
    if "abstain_low"  not in st.session_state: st.session_state["abstain_low"]  = 0.25
    if "abstain_high" not in st.session_state: st.session_state["abstain_high"] = 0.60
    if "gmail_messages" not in st.session_state: st.session_state["gmail_messages"] = []
    if "gmail_connected" not in st.session_state: st.session_state["gmail_connected"] = False

    # ── Model path ──
    model_name = "meta_classifier_real_v1"
    model_path = PROJECT_ROOT / "models" / model_name
    if not model_path.exists():
        model_path = PROJECT_ROOT / "models" / "meta_classifier_v1"

    pipeline = _load_pipeline(str(model_path))

    # ── Top bar ──
    gmail_on = st.session_state["gmail_connected"]
    mode_cls = "mode-gmail" if gmail_on else "mode-offline"
    mode_lbl = "Gmail Connected" if gmail_on else "Offline ML Engine"
    mode_dot = "🔵" if gmail_on else "⚫"

    st.markdown(
        f"""<div class="top-bar">
            <div class="top-bar-title">🛡 <span>Phishing</span> Email Checker</div>
            <div>
                <span class="mode-badge {mode_cls}">{mode_dot}&nbsp;{mode_lbl}</span>
            </div>
        </div>""",
        unsafe_allow_html=True,
    )

    if pipeline is None:
        st.error(
            "**Model not loaded.** Run `python scripts/train_and_evaluate.py` "
            "to train and save a model bundle first.",
            icon="🔴",
        )
        st.stop()

    # ── Input tabs ──
    raw_bytes: Optional[bytes] = None

    tab_upload, tab_gmail, tab_paste = st.tabs([
        "📂 Upload Mail File",
        "📧 Connect Gmail",
        "✏ Paste / Try Sample",
    ])

    # ─── Tab 1: File upload ──────────────────────────────────────────────────
    with tab_upload:
        uploaded = st.file_uploader(
            "Drag & drop an email file here",
            type=["eml", "msg", "mbox", "txt"],
            label_visibility="collapsed",
        )
        if uploaded:
            suffix = Path(uploaded.name).suffix.lower()
            file_bytes = uploaded.read()

            if suffix == ".mbox":
                st.info(f"📬 `{uploaded.name}` — select which message to scan:")
                raw_bytes = _pick_from_mbox(file_bytes)
            elif suffix == ".msg":
                st.warning(
                    "`.msg` (Outlook) files use a proprietary binary format. "
                    "Extracting readable text as a best-effort fallback."
                )
                raw_bytes = _msg_to_rfc822(file_bytes)
            else:
                raw_bytes = file_bytes
                st.success(f"✓ Loaded `{uploaded.name}` ({len(file_bytes):,} bytes)")

    # ─── Tab 2: Gmail IMAP ───────────────────────────────────────────────────
    with tab_gmail:
        st.markdown(
            '<div class="gmail-info">'
            '<b>How it works:</b> Enter your Gmail address and an '
            '<a href="https://support.google.com/accounts/answer/185833" '
            'target="_blank" style="color:#38BDF8;">App Password</a> '
            '(not your main Gmail password). We fetch your most recent emails '
            '<b>directly into memory</b> over encrypted IMAP — nothing is stored to disk. '
            'Scanning runs 100% locally on your machine.'
            '<br><br>'
            '<b>Prerequisite:</b> Enable 2-Step Verification and generate an App Password at '
            'Google Account → Security → App Passwords.'
            '</div>',
            unsafe_allow_html=True,
        )
        gmail_addr = st.text_input("Gmail address", placeholder="you@gmail.com")
        gmail_pass = st.text_input("App Password", type="password",
                                   placeholder="xxxx xxxx xxxx xxxx",
                                   help="16-character App Password from Google Account → Security")
        gmail_folder = st.selectbox("Folder", ["INBOX", "[Gmail]/Spam", "[Gmail]/All Mail"], index=0)
        gmail_limit  = st.slider("Fetch how many recent emails?", 3, 20, 5)

        if st.button("🔗 Connect & Fetch", type="primary", disabled=not gmail_addr or not gmail_pass):
            with st.spinner("Connecting to Gmail via IMAP SSL…"):
                try:
                    msgs = _fetch_gmail_messages(gmail_addr, gmail_pass, gmail_folder, gmail_limit)
                    st.session_state["gmail_messages"]  = msgs
                    st.session_state["gmail_connected"] = True
                    st.success(f"✓ Fetched {len(msgs)} emails from {gmail_folder}")
                    st.rerun()
                except RuntimeError as e:
                    st.error(str(e))

        if st.session_state["gmail_messages"]:
            msgs = st.session_state["gmail_messages"]
            choices = [f"[{i+1}] {m['subject']} — {m['from_']}" for i, m in enumerate(msgs)]
            sel_idx = st.selectbox("Select email to scan", range(len(msgs)),
                                   format_func=lambda i: choices[i])
            if st.button("🔍 Scan this email", type="primary"):
                raw_bytes = msgs[sel_idx]["raw_bytes"]
            if st.button("🔌 Disconnect", type="secondary"):
                st.session_state["gmail_messages"]  = []
                st.session_state["gmail_connected"] = False
                st.rerun()

    # ─── Tab 3: Paste / sample ───────────────────────────────────────────────
    with tab_paste:
        st.markdown('<div class="section-label">QUICK SAMPLES</div>', unsafe_allow_html=True)
        sc1, sc2, _ = st.columns([1, 1, 3])
        with sc1:
            if st.button("✅ Try Safe Email", use_container_width=True):
                p = SAFE_SAMPLE if SAFE_SAMPLE.exists() else SYNTH_SAMPLE
                raw_bytes = p.read_bytes() if p.exists() else None
                if not raw_bytes:
                    st.warning("Sample file not found.")
        with sc2:
            if st.button("🚨 Try Phishing Email", use_container_width=True):
                p = PHISH_SAMPLE if PHISH_SAMPLE.exists() else SYNTH_SAMPLE
                raw_bytes = p.read_bytes() if p.exists() else None
                if not raw_bytes:
                    st.warning("Sample file not found.")

        st.markdown('<br><div class="section-label">OR PASTE RAW EMAIL TEXT</div>',
                    unsafe_allow_html=True)
        raw_text = st.text_area(
            "Paste raw email here",
            height=160,
            placeholder="From: sender@example.com\nTo: you@example.com\nSubject: ...\n\nEmail body...",
            label_visibility="collapsed",
        )
        if st.button("🔍 Analyze Pasted Email", type="primary",
                     disabled=not raw_text.strip()):
            raw_bytes = raw_text.encode("utf-8", errors="replace")

    # ─────────────────────────────────────────────────────────────────────────
    # Idle state
    # ─────────────────────────────────────────────────────────────────────────
    if raw_bytes is None and not st.session_state.get("rerun_thresholds"):
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(
            '<div style="text-align:center;padding:48px 0;color:#334155;">'
            '<div style="font-size:3rem;margin-bottom:12px;">🛡</div>'
            '<div style="font-size:1.05rem;font-weight:700;color:#475569;margin-bottom:6px;">'
            'Upload, connect, or paste an email above to begin</div>'
            '<div style="font-size:0.85rem;color:#334155;">'
            'All analysis runs locally — no data leaves your machine.</div>'
            '</div>',
            unsafe_allow_html=True,
        )
        return

    # ─────────────────────────────────────────────────────────────────────────
    # Analysis
    # ─────────────────────────────────────────────────────────────────────────
    if raw_bytes is None and "last_report" in st.session_state:
        # threshold rerun — reuse previous bytes
        raw_bytes = st.session_state.get("last_raw_bytes")

    st.session_state["rerun_thresholds"] = False

    if not raw_bytes:
        return

    st.session_state["last_raw_bytes"] = raw_bytes

    with st.spinner("Analyzing across all specialist agents…"):
        try:
            report: PhishingAnalysisReport = _run_analysis(
                pipeline,
                raw_bytes,
                st.session_state["abstain_low"],
                st.session_state["abstain_high"],
            )
        except Exception as e:
            st.error(f"**Analysis error:** {e}", icon="🔴")
            st.exception(e)
            return

    st.session_state["last_report"] = report
    _render_verdict(report)


if __name__ == "__main__":
    main()
