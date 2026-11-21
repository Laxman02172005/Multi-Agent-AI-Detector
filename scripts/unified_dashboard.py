#!/usr/bin/env python3
"""
scripts/unified_dashboard.py
-----------------------------
Phishing Email Checker — Clean, user-friendly SOC & end-user dashboard.

Four input modes:
  1. Upload a mail file (.eml, .msg, .mbox, .txt)
  2. Connect Gmail via real OAuth 2.0 (InstalledAppFlow, gmail.readonly scope)
  3. Connect Gmail via IMAP + App Password (legacy fallback)
  4. Paste raw email text or try a built-in sample

Backend: PhishingDetectorPipeline (100% passive, offline ML engine).
Google OAuth: google-auth-oauthlib + google-api-python-client (optional dep).
Strict dependencies: Python stdlib + packages in requirements.txt only.
"""
from __future__ import annotations

import base64
import email as email_lib
import email.policy
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

# ── Optional Google OAuth imports ─────────────────────────────────────────────
try:
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    _GOOGLE_AVAILABLE = True
except ImportError:
    _GOOGLE_AVAILABLE = False

# Gmail read-only scope
_GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

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

/* ── Google Sign-in button ───────────────────────────────────────────────── */
.google-btn-wrap {
    display: flex;
    justify-content: flex-start;
    margin: 12px 0 20px 0;
}
.google-signin-btn {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    padding: 11px 20px;
    background: #FFFFFF;
    color: #3C4043;
    border: 1px solid #DADCE0;
    border-radius: 8px;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    text-decoration: none;
    transition: box-shadow 0.15s;
}
.google-signin-btn:hover { box-shadow: 0 1px 6px rgba(0,0,0,0.3); }
.google-logo {
    font-size: 1.1rem;
}

/* ── Connected account chip ──────────────────────────────────────────────── */
.account-chip {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: rgba(16,185,129,0.10);
    border: 1px solid #047857;
    border-radius: 24px;
    padding: 7px 14px;
    font-size: 0.84rem;
    color: #34D399;
    font-weight: 600;
    margin-bottom: 16px;
}

/* ── Info boxes ──────────────────────────────────────────────────────────── */
.info-box {
    background:#111827; border:1px solid #1E293B; border-radius:10px;
    padding:16px 18px; font-size:0.84rem; color:#94A3B8; margin-bottom:16px;
    line-height:1.7;
}
.info-box b { color:#E2E8F0; }
.info-box a { color:#38BDF8; }

/* ── Setup steps ─────────────────────────────────────────────────────────── */
.setup-step {
    display: flex;
    gap: 12px;
    align-items: flex-start;
    margin-bottom: 10px;
    font-size: 0.84rem;
    color: #94A3B8;
}
.step-num {
    flex-shrink: 0;
    width: 22px; height: 22px;
    background: #1E293B; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.72rem; font-weight: 800; color: #38BDF8;
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
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".mbox") as tf:
        tf.write(mbox_bytes)
        tmp_path = tf.name
    try:
        mbox = mailbox.mbox(tmp_path)
        messages = list(mbox)
        if not messages:
            st.warning("No messages found in the .mbox file.")
            return None
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
        return messages[idx].as_bytes()
    except Exception as ex:
        st.error(f"Could not parse .mbox file: {ex}")
        return None
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# MSG HELPER — best-effort extraction of .msg (Outlook) files via stdlib
# ─────────────────────────────────────────────────────────────────────────────
def _msg_to_rfc822(msg_bytes: bytes) -> bytes:
    try:
        text = msg_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = msg_bytes.decode("latin-1", errors="replace")
    lines = []
    for line in text.splitlines():
        printable = "".join(c for c in line if c.isprintable() or c in "\t ")
        if printable.strip():
            lines.append(printable)
    fallback = "\r\n".join(lines[:200])
    return f"Subject: (Extracted from .msg)\r\n\r\n{fallback}".encode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# GOOGLE OAUTH 2.0 HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _record_oauth_error(context: str, exc: Exception) -> None:
    """Store the last OAuth/Gmail API exception in session state with traceback."""
    import traceback
    st.session_state["oauth_last_error"] = {
        "context": context,
        "message": str(exc) or type(exc).__name__,
        "type": type(exc).__name__,
        "traceback": traceback.format_exc(),
    }


def _clear_oauth_error() -> None:
    """Clear any stored OAuth error."""
    st.session_state.pop("oauth_last_error", None)


def _normalize_oauth_config(cfg: dict) -> dict:
    """
    Ensure client config conforms to Desktop InstalledAppFlow format.
    Adapts 'web', 'installed', or flat client_id/secret dictionaries.
    """
    if "installed" in cfg:
        inst = dict(cfg["installed"])
        if "redirect_uris" not in inst or not inst["redirect_uris"]:
            inst["redirect_uris"] = ["http://localhost"]
        return {"installed": inst}
    if "web" in cfg:
        web = dict(cfg["web"])
        return {
            "installed": {
                "client_id": web.get("client_id", ""),
                "client_secret": web.get("client_secret", ""),
                "auth_uri": web.get("auth_uri", "https://accounts.google.com/o/oauth2/auth"),
                "token_uri": web.get("token_uri", "https://oauth2.googleapis.com/token"),
                "auth_provider_x509_cert_url": web.get("auth_provider_x509_cert_url", "https://www.googleapis.com/oauth2/v1/certs"),
                "redirect_uris": ["http://localhost"],
                "project_id": web.get("project_id", "phishing-detector"),
            }
        }
    if "client_id" in cfg and "client_secret" in cfg:
        return {
            "installed": {
                "client_id": cfg["client_id"],
                "client_secret": cfg["client_secret"],
                "auth_uri": cfg.get("auth_uri", "https://accounts.google.com/o/oauth2/auth"),
                "token_uri": cfg.get("token_uri", "https://oauth2.googleapis.com/token"),
                "auth_provider_x509_cert_url": cfg.get("auth_provider_x509_cert_url", "https://www.googleapis.com/oauth2/v1/certs"),
                "redirect_uris": ["http://localhost"],
                "project_id": cfg.get("project_id", "phishing-detector"),
            }
        }
    return cfg


def _find_token_json() -> Optional[Path]:
    """Search for token.json in standard locations."""
    candidates = [
        PROJECT_ROOT / "token.json",
        PROJECT_ROOT / "secrets" / "token.json",
        Path(os.environ.get("GOOGLE_TOKEN_PATH", "__nonexistent__")),
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def _get_oauth_client_config() -> tuple[Optional[dict], Optional[str], list[str]]:
    """
    Search for OAuth 2.0 client configuration in:
      1. Session state uploaded config
      2. credentials.json or secrets/credentials.json
      3. GOOGLE_CREDENTIALS_PATH env var
      4. GOOGLE_CREDENTIALS_JSON env var (raw JSON string or file path)
      5. GOOGLE_CLIENT_ID & GOOGLE_CLIENT_SECRET env vars

    Returns:
      (normalized_config_dict_or_None, source_label_or_None, checked_sources_list)
    """
    checked = [
        "In-memory uploaded file",
        "credentials.json",
        "secrets/credentials.json",
        "env:GOOGLE_CREDENTIALS_PATH",
        "env:GOOGLE_CREDENTIALS_JSON",
        "env:GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET",
    ]

    # 1. In-memory session upload
    if "uploaded_credentials_dict" in st.session_state:
        cfg = st.session_state["uploaded_credentials_dict"]
        return _normalize_oauth_config(cfg), "Uploaded credentials.json", checked

    # 2. Local standard file paths
    for p in [PROJECT_ROOT / "credentials.json", PROJECT_ROOT / "secrets" / "credentials.json"]:
        if p.exists():
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
                return _normalize_oauth_config(raw), str(p.relative_to(PROJECT_ROOT) if p.is_relative_to(PROJECT_ROOT) else p.name), checked
            except Exception:
                pass

    # 3. Explicit path from env
    env_path = os.environ.get("GOOGLE_CREDENTIALS_PATH")
    if env_path and Path(env_path).exists():
        try:
            raw = json.loads(Path(env_path).read_text(encoding="utf-8"))
            return _normalize_oauth_config(raw), f"env:GOOGLE_CREDENTIALS_PATH ({Path(env_path).name})", checked
        except Exception:
            pass

    # 4. JSON blob or file path in env
    env_json = os.environ.get("GOOGLE_CREDENTIALS_JSON")
    if env_json:
        trimmed = env_json.strip()
        if trimmed.startswith("{"):
            try:
                raw = json.loads(trimmed)
                return _normalize_oauth_config(raw), "env:GOOGLE_CREDENTIALS_JSON (inline)", checked
            except Exception:
                pass
        elif Path(trimmed).exists():
            try:
                raw = json.loads(Path(trimmed).read_text(encoding="utf-8"))
                return _normalize_oauth_config(raw), f"env:GOOGLE_CREDENTIALS_JSON ({Path(trimmed).name})", checked
            except Exception:
                pass

    # 5. Direct Client ID & Secret in env
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    if client_id and client_secret:
        project_id = os.environ.get("GOOGLE_PROJECT_ID", "phishing-detector")
        raw = {
            "installed": {
                "client_id": client_id.strip(),
                "project_id": project_id.strip(),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_secret": client_secret.strip(),
                "redirect_uris": ["http://localhost"],
            }
        }
        return raw, "env:GOOGLE_CLIENT_ID", checked

    return None, None, checked


def _oauth_credentials_from_session() -> Optional["Credentials"]:
    """Reconstruct a Credentials object from session state or token.json."""
    if not _GOOGLE_AVAILABLE:
        return None
    token_dict = st.session_state.get("oauth_token_dict")
    if token_dict:
        try:
            creds = Credentials(
                token=token_dict.get("token"),
                refresh_token=token_dict.get("refresh_token"),
                token_uri=token_dict.get("token_uri", "https://oauth2.googleapis.com/token"),
                client_id=token_dict.get("client_id"),
                client_secret=token_dict.get("client_secret"),
                scopes=token_dict.get("scopes"),
            )
            if creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    _store_creds_in_session(creds)
                except Exception as ref_exc:
                    _record_oauth_error("Token Refresh Failed", ref_exc)
                    return None
            return creds if creds.valid else None
        except Exception as exc:
            _record_oauth_error("Failed to parse session credentials", exc)
            return None

    # Fallback: check token.json on disk if present
    token_path = _find_token_json()
    if token_path and token_path.exists():
        try:
            creds = Credentials.from_authorized_user_file(str(token_path), _GMAIL_SCOPES)
            if creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    token_path.write_text(creds.to_json(), encoding="utf-8")
                except Exception as ref_exc:
                    _record_oauth_error("Disk Token Refresh Failed", ref_exc)
                    return None
            if creds.valid:
                _store_creds_in_session(creds, save_token_file=False)
                if "oauth_gmail_email" not in st.session_state:
                    st.session_state["oauth_gmail_email"] = _get_gmail_user_email(creds)
                    st.session_state["gmail_connected"] = True
                return creds
        except Exception as exc:
            _record_oauth_error("Failed to load token.json", exc)
            return None
    return None


def _store_creds_in_session(creds: "Credentials", save_token_file: bool = True) -> None:
    """Persist credentials in session state and optionally to token.json."""
    st.session_state["oauth_token_dict"] = {
        "token":         creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri":     creds.token_uri,
        "client_id":     creds.client_id,
        "client_secret": creds.client_secret,
        "scopes":        list(creds.scopes or []),
    }
    if save_token_file:
        for p in [PROJECT_ROOT / "token.json", PROJECT_ROOT / "secrets" / "token.json"]:
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(creds.to_json(), encoding="utf-8")
                break
            except Exception:
                pass


def _run_oauth_flow(client_config: dict | Path, remember: bool = True) -> Optional["Credentials"]:
    """
    Launch InstalledAppFlow (opens browser). Returns Credentials or None.
    Tokens are stored in session state (and optionally token.json if writable).
    """
    if not _GOOGLE_AVAILABLE:
        _record_oauth_error("Dependency Missing", RuntimeError("Google OAuth libraries not installed."))
        return None
    try:
        if isinstance(client_config, Path):
            raw = json.loads(client_config.read_text(encoding="utf-8"))
            cfg = _normalize_oauth_config(raw)
        else:
            cfg = _normalize_oauth_config(client_config)

        flow = InstalledAppFlow.from_client_config(cfg, _GMAIL_SCOPES)
        port = int(os.environ.get("GOOGLE_OAUTH_PORT", "0"))
        creds = flow.run_local_server(
            port=port,
            open_browser=True,
            prompt="consent",
            access_type="offline",
        )
        _store_creds_in_session(creds, save_token_file=remember)
        _clear_oauth_error()
        return creds
    except Exception as exc:
        _record_oauth_error("OAuth Sign-in Failed", exc)
        return None


def _gmail_service_from_creds(creds: "Credentials"):
    """Build a Gmail API service object."""
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def _fetch_gmail_messages_oauth(
    creds: "Credentials",
    query: str,
    limit: int,
) -> list[dict]:
    """
    Fetch up to `limit` messages via Gmail REST API (format=raw → base64url bytes).
    Returns list of dicts: {id, subject, from_, date, raw_bytes}.
    """
    try:
        service = _gmail_service_from_creds(creds)
        results = (
            service.users()
            .messages()
            .list(userId="me", q=query or "", maxResults=limit)
            .execute()
        )
        message_refs = results.get("messages", [])
        messages = []
        for ref in message_refs:
            msg_data = (
                service.users()
                .messages()
                .get(userId="me", id=ref["id"], format="raw")
                .execute()
            )
            raw_b64 = msg_data.get("raw", "")
            padded = raw_b64 + "=" * (-len(raw_b64) % 4)
            raw_bytes = base64.urlsafe_b64decode(padded)
            parsed = email_lib.message_from_bytes(raw_bytes, policy=email_lib.policy.default)
            messages.append({
                "id":        ref["id"],
                "subject":   str(parsed.get("Subject", "(no subject)"))[:80],
                "from_":     str(parsed.get("From", "(unknown sender)"))[:60],
                "date":      str(parsed.get("Date", ""))[:40],
                "raw_bytes": raw_bytes,
            })
        _clear_oauth_error()
        return messages
    except Exception as exc:
        _record_oauth_error("Gmail API Fetch Error", exc)
        raise


def _get_gmail_user_email(creds: "Credentials") -> str:
    """Return the signed-in Gmail address (profile lookup)."""
    try:
        service = _gmail_service_from_creds(creds)
        profile = service.users().getProfile(userId="me").execute()
        return profile.get("emailAddress", "Connected Account")
    except Exception as exc:
        _record_oauth_error("User Profile Retrieval Error", exc)
        return "Connected Account"
    except Exception:
        return "Connected"


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
# GMAIL OAUTH TAB — UI helper
# ─────────────────────────────────────────────────────────────────────────────
def _render_gmail_oauth_tab() -> Optional[bytes]:
    """
    Renders the Gmail OAuth 2.0 tab ("Continue with Google").
    Returns raw_bytes of the selected message if the user clicks "Scan Selected Email", else None.
    """
    raw_bytes: Optional[bytes] = None

    # Check OAuth client config and library status
    config, source_label, checked_sources = _get_oauth_client_config()
    creds = _oauth_credentials_from_session()
    gmail_email = st.session_state.get("oauth_gmail_email", "")
    is_signed_in = bool(creds and creds.valid)

    # ── Diagnostic Status Line ────────────────────────────────────────────────
    cfg_icon = "🟢" if config is not None else "🔴"
    cfg_text = f"Yes ({source_label})" if config is not None else "No (not found)"
    libs_icon = "🟢" if _GOOGLE_AVAILABLE else "🔴"
    libs_text = "Installed" if _GOOGLE_AVAILABLE else "Missing (google-auth-oauthlib)"
    auth_icon = "🟢" if is_signed_in else "⚪"
    auth_text = f"Signed in as {gmail_email}" if is_signed_in else "Not signed in"

    st.markdown(
        f"""<div style="display:flex;flex-wrap:wrap;gap:18px;background:#0D1117;border:1px solid #1E293B;border-radius:8px;padding:9px 16px;margin-bottom:18px;font-size:0.80rem;color:#94A3B8;">
            <div><b>OAuth Config:</b> {cfg_icon} <span style="color:#CBD5E1;">{cfg_text}</span></div>
            <div><b>Google Libraries:</b> {libs_icon} <span style="color:#CBD5E1;">{libs_text}</span></div>
            <div><b>Auth Status:</b> {auth_icon} <span style="color:#CBD5E1;">{auth_text}</span></div>
        </div>""",
        unsafe_allow_html=True,
    )

    # ── Surface Stored Error (if any) ─────────────────────────────────────────
    last_err = st.session_state.get("oauth_last_error")
    if last_err:
        st.error(f"**{last_err['context']}:** {last_err['message']}", icon="⚠️")
        err_msg_lower = last_err["message"].lower()
        if "access_denied" in err_msg_lower or "403" in err_msg_lower:
            st.info("💡 **OAuth Permission Note:** If your Google Cloud project is in 'Testing' mode, ensure your Google email is added under **Test users** (Google Cloud Console → APIs & Services → OAuth consent screen).")
        elif "disabled" in err_msg_lower or "has not been used" in err_msg_lower:
            st.info("💡 **Gmail API Note:** Enable the Gmail API in your Google Cloud project at **APIs & Services → Library → Gmail API → Enable**.")
        elif "client secrets must be for a web or installed app" in err_msg_lower:
            st.info("💡 **Format Note:** Ensure your credentials JSON was downloaded from an OAuth 2.0 Client ID (Desktop app or Web app).")

        with st.expander("🔍 Diagnostic Details & Traceback", expanded=False):
            st.code(last_err["traceback"], language="python")
        if st.button("Dismiss Error", key="btn_dismiss_oauth_err"):
            _clear_oauth_error()
            st.rerun()

    if not _GOOGLE_AVAILABLE:
        st.warning("Google API libraries not installed. Run: pip install google-auth-oauthlib google-auth-httplib2 google-api-python-client")
        return None

    # ── CASE 1: Signed In ─────────────────────────────────────────────────────
    if is_signed_in and creds:
        st.markdown(
            f'<div class="account-chip">Connected as <b>{gmail_email}</b></div>',
            unsafe_allow_html=True,
        )

        # Auto-fetch recent emails if not loaded yet
        if "oauth_messages" not in st.session_state or st.session_state["oauth_messages"] is None:
            with st.spinner("Loading recent emails..."):
                try:
                    st.session_state["oauth_messages"] = _fetch_gmail_messages_oauth(creds, "", 10)
                except Exception as exc:
                    st.error(f"Error fetching emails: {exc}")
                    st.session_state["oauth_messages"] = []

        col_q, col_n = st.columns([3, 1])
        with col_q:
            query = st.text_input(
                "Filter",
                value=st.session_state.get("oauth_query", ""),
                placeholder="Search filter (e.g. is:unread, invoice, from:service)",
                label_visibility="collapsed",
            )
        with col_n:
            limit = st.number_input(
                "Count",
                min_value=1,
                max_value=30,
                value=st.session_state.get("oauth_limit", 10),
                step=1,
                label_visibility="collapsed",
            )

        btn_col1, btn_col2 = st.columns([2, 2])
        with btn_col1:
            if st.button("Refresh Emails", type="primary", use_container_width=True):
                st.session_state["oauth_query"] = query
                st.session_state["oauth_limit"] = int(limit)
                with st.spinner("Fetching emails..."):
                    try:
                        st.session_state["oauth_messages"] = _fetch_gmail_messages_oauth(creds, query, int(limit))
                        _clear_oauth_error()
                    except Exception as exc:
                        st.error(f"Error fetching emails: {exc}")
                        st.session_state["oauth_messages"] = []
                st.rerun()

        with btn_col2:
            if st.button("Disconnect / Sign Out", type="secondary", use_container_width=True):
                for k in ("oauth_token_dict", "oauth_gmail_email", "oauth_messages", "oauth_query", "oauth_limit"):
                    st.session_state.pop(k, None)
                st.session_state["gmail_connected"] = False
                _clear_oauth_error()
                token_p = _find_token_json()
                if token_p and token_p.exists():
                    try:
                        token_p.unlink()
                    except Exception:
                        pass
                st.rerun()

        msgs = st.session_state.get("oauth_messages", [])
        if msgs:
            choices = [
                f"[{i+1}] {m['subject']} — {m['from_']} ({m['date']})"
                for i, m in enumerate(msgs)
            ]
            sel_idx = st.selectbox(
                f"Select an email to analyze ({len(msgs)} loaded):",
                range(len(msgs)),
                format_func=lambda i: choices[i],
            )
            if st.button("Scan Selected Email", type="primary", use_container_width=False):
                raw_bytes = msgs[sel_idx]["raw_bytes"]
        else:
            st.info("No emails found for this query.")

        return raw_bytes

    # ── CASE 2: Not Signed In ─────────────────────────────────────────────────
    st.markdown(
        '<div style="font-size:0.92rem;color:#94A3B8;margin-bottom:14px;line-height:1.6;">'
        'Sign in securely to scan emails directly from your Gmail inbox. '
        'All processing is passive and local — emails are examined in memory on your machine and never stored or sent externally.'
        '</div>',
        unsafe_allow_html=True,
    )

    if st.button("Continue with Google", type="primary"):
        if config is not None:
            with st.spinner("Opening Google sign-in in your browser..."):
                new_creds = _run_oauth_flow(config, remember=True)
                if new_creds and new_creds.valid:
                    email_addr = _get_gmail_user_email(new_creds)
                    st.session_state["oauth_gmail_email"] = email_addr
                    st.session_state["gmail_connected"] = True
                    _clear_oauth_error()
                    try:
                        st.session_state["oauth_messages"] = _fetch_gmail_messages_oauth(new_creds, "", 10)
                    except Exception:
                        st.session_state["oauth_messages"] = []
                    st.rerun()
        else:
            _record_oauth_error(
                "OAuth Setup Required",
                FileNotFoundError(
                    f"No OAuth client configuration found. Checked: {', '.join(checked_sources)}. "
                    "Please upload credentials.json below or set GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET environment variables."
                )
            )
            st.session_state["prompt_creds_upload"] = True
            st.rerun()

    # If no config exists, show a single-line compact note and minimal file uploader
    if config is None or st.session_state.get("prompt_creds_upload"):
        st.markdown(
            '<div style="font-size:0.83rem;color:#64748B;margin-top:16px;margin-bottom:6px;">'
            'No credentials.json detected. Upload your OAuth client credentials file to continue:'
            '</div>',
            unsafe_allow_html=True,
        )
        uploaded_json = st.file_uploader(
            "Upload credentials.json",
            type=["json"],
            label_visibility="collapsed",
            key="oauth_creds_file_uploader",
        )
        if uploaded_json is not None:
            try:
                data = json.loads(uploaded_json.read().decode("utf-8"))
                normalized = _normalize_oauth_config(data)
                st.session_state["uploaded_credentials_dict"] = normalized
                st.session_state.pop("prompt_creds_upload", None)
                _clear_oauth_error()
                st.success("Credentials loaded. Click Continue with Google above to sign in.")
                st.rerun()
            except Exception as exc:
                _record_oauth_error("Invalid Credentials JSON", exc)
                st.rerun()

    return raw_bytes


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    # ── Defaults in session state ──
    if "abstain_low"  not in st.session_state: st.session_state["abstain_low"]  = 0.25
    if "abstain_high" not in st.session_state: st.session_state["abstain_high"] = 0.60
    if "gmail_connected" not in st.session_state: st.session_state["gmail_connected"] = False

    # ── Model path ──
    model_name = "meta_classifier_real_v1"
    model_path = PROJECT_ROOT / "models" / model_name
    if not model_path.exists():
        model_path = PROJECT_ROOT / "models" / "meta_classifier_v1"

    pipeline = _load_pipeline(str(model_path))

    # ── Top bar ──
    gmail_on = st.session_state.get("gmail_connected", False)
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

    # ─── Tab 2: Gmail OAuth 2.0 ──────────────────────────────────────────────
    with tab_gmail:
        raw_bytes_from_gmail = _render_gmail_oauth_tab()
        if raw_bytes_from_gmail:
            raw_bytes = raw_bytes_from_gmail

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
