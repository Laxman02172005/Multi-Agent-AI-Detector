"""
AEGIS — Multi-Agent Phishing Defense API
FastAPI backend wrapping PhishingDetectorPipeline.

Endpoints:
  GET  /api/health                      – model status, SHA-256 verification, Gmail config & session status
  POST /api/preview/file                – parse & preview uploaded .eml / .txt / .mbox without scanning
  POST /api/preview/raw                 – parse & preview pasted raw email text without scanning
  POST /api/scan/file                   – scan uploaded .eml / .txt / .mbox file
  POST /api/scan/raw                    – scan raw/plain-text email body
  GET  /api/samples                     – list built-in demo corpus samples
  GET  /api/samples/{sample_id}/preview – preview a built-in demo sample before scanning
  POST /api/scan/sample/{sample_id}     – scan a built-in demo sample

  GET  /api/auth/google                 – start Gmail OAuth 2.0 web flow
  GET  /api/auth/callback               – OAuth 2.0 redirect callback
  POST /api/auth/logout                 – clear Gmail session cookie
  GET  /api/gmail/messages              – list recent Gmail inbox messages
  GET  /api/gmail/messages/{msg_id}     – preview complete Gmail email (From, To, Date, Subject, body, attachments)
  POST /api/gmail/scan/{message_id}     – fetch raw RFC 822 payload & scan through PhishingDetectorPipeline
"""

from __future__ import annotations

import base64
import email as stdlib_email
import email.header
import email.policy
import hashlib
import json
import os
import threading
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from fastapi import Cookie, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from app.pipeline.orchestrator import PhishingDetectorPipeline
from app.schemas.meta_classifier_schema import DecisionThresholds

# ── Constants ─────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_NAME = "meta_classifier_real_v1"
MODEL_DIR = BASE_DIR / "models" / MODEL_NAME
JOBLIB_PATH = MODEL_DIR / f"{MODEL_NAME}.joblib"
METADATA_PATH = MODEL_DIR / f"{MODEL_NAME}_metadata.json"

CREDS_PATHS = [
    BASE_DIR / "credentials.json",
    BASE_DIR / "secrets" / "credentials.json",
]
GMAIL_SCOPE = ["https://www.googleapis.com/auth/gmail.readonly"]
FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "http://localhost:5173")
OAUTH_REDIRECT_URI = os.environ.get(
    "OAUTH_REDIRECT_URI", "http://localhost:8000/api/auth/callback"
)

# In-memory OAuth session store: {session_id: google.oauth2.credentials.Credentials}
_oauth_sessions: dict[str, Any] = {}
_pipeline_lock = threading.Lock()


def _try_import_google():
    try:
        from google_auth_oauthlib.flow import Flow
        from googleapiclient.discovery import build as google_build
        return Flow, google_build
    except ImportError:
        return None, None


# ── Lifespan – load model once ────────────────────────────────────────────────
pipeline: Optional[PhishingDetectorPipeline] = None
_model_sha256: Optional[str] = None
_model_load_error: Optional[str] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pipeline, _model_sha256, _model_load_error
    try:
        pipeline = PhishingDetectorPipeline(
            model_path=str(MODEL_DIR),
            model_name=MODEL_NAME,
        )
        if JOBLIB_PATH.exists():
            _model_sha256 = hashlib.sha256(JOBLIB_PATH.read_bytes()).hexdigest()
    except Exception as exc:  # noqa: BLE001
        _model_load_error = str(exc)
    yield


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="AEGIS Phishing Defense API", version="2.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN, "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_pipeline() -> PhishingDetectorPipeline:
    if pipeline is None:
        detail = f"Model failed to load: {_model_load_error}" if _model_load_error else "Model not loaded."
        raise HTTPException(status_code=503, detail=detail)
    return pipeline


def _sha256_verified() -> bool:
    if _model_sha256 is None:
        return False
    try:
        meta = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
        stored = meta.get("model_sha256")
        if stored:
            return stored.lower() == _model_sha256.lower()
    except Exception:  # noqa: BLE001
        pass
    return False


def _gmail_configured() -> bool:
    for p in CREDS_PATHS:
        if p.exists():
            return True
    for key in ("GOOGLE_CLIENT_ID", "GOOGLE_CREDENTIALS_JSON"):
        if os.environ.get(key):
            return True
    return False


def _load_oauth_client_config() -> dict | None:
    for p in CREDS_PATHS:
        if p.exists():
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
                if "web" in raw or "installed" in raw:
                    return raw
                return {
                    "web": {
                        **raw,
                        "token_uri": raw.get("token_uri", "https://oauth2.googleapis.com/token"),
                    }
                }
            except Exception:  # noqa: BLE001
                pass
    blob = os.environ.get("GOOGLE_CREDENTIALS_JSON", "")
    if blob:
        try:
            return json.loads(blob)
        except Exception:  # noqa: BLE001
            pass
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "")
    if client_id and client_secret:
        return {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [OAUTH_REDIRECT_URI],
            }
        }
    return None


def _decode_base64url(raw_b64: str) -> bytes:
    """Decode Gmail base64url string safely with proper '=' padding."""
    if not raw_b64:
        raise ValueError("Empty raw email payload returned by Gmail API.")
    padded = raw_b64 + "=" * (-len(raw_b64) % 4)
    return base64.urlsafe_b64decode(padded)


def _extract_first_from_mbox(raw_bytes: bytes) -> bytes:
    """Extract the first RFC 5322 email message from an mbox archive."""
    text = raw_bytes.decode("utf-8", errors="replace")
    normalized = text.replace("\r\n", "\n")
    msgs = normalized.split("\nFrom ")
    first = msgs[0] if msgs else normalized
    if first.startswith("From ") and "\n" in first:
        first = first[first.index("\n") + 1:]
    return first.encode("utf-8")


def _scan_raw_bytes(
    raw_bytes: bytes,
    abstain_low: float,
    abstain_high: float,
    file_name: Optional[str] = None,
) -> dict:
    """Scan raw RFC 5322 bytes through PhishingDetectorPipeline with threshold validation."""
    pl = _require_pipeline()
    if not (0.0 < abstain_low < abstain_high < 1.0):
        raise HTTPException(
            status_code=422,
            detail=f"Thresholds must satisfy 0.0 < abstain_low < abstain_high < 1.0 (got {abstain_low}, {abstain_high}).",
        )
    thresholds = DecisionThresholds(abstain_low=abstain_low, abstain_high=abstain_high)
    with _pipeline_lock:
        pl.thresholds = thresholds
        report = pl.analyze_raw_email(raw_bytes, file_name=file_name)
    return json.loads(report.model_dump_json())


def _decode_header_str(value: Optional[str]) -> str:
    """Decode RFC 2047 encoded headers cleanly into Unicode text."""
    if not value:
        return ""
    try:
        return str(stdlib_email.header.make_header(stdlib_email.header.decode_header(value)))
    except Exception:  # noqa: BLE001
        return str(value)


def _decode_email_body(msg: stdlib_email.message.Message) -> str:
    """Extract readable plain-text body (with HTML text fallback) from a parsed email."""
    plain_parts: list[str] = []
    html_parts: list[str] = []

    def _extract_part_text(part: stdlib_email.message.Message) -> Optional[str]:
        payload = part.get_payload(decode=True)
        if not payload:
            return None
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            disp = (part.get_content_disposition() or "").lower()
            if disp == "attachment":
                continue
            if ct == "text/plain":
                text = _extract_part_text(part)
                if text:
                    plain_parts.append(text)
            elif ct == "text/html":
                html_text = _extract_part_text(part)
                if html_text:
                    try:
                        from bs4 import BeautifulSoup
                        html_parts.append(BeautifulSoup(html_text, "html.parser").get_text(separator="\n"))
                    except Exception:  # noqa: BLE001
                        html_parts.append(html_text)
    else:
        text = _extract_part_text(msg)
        if text:
            if msg.get_content_type() == "text/html":
                try:
                    from bs4 import BeautifulSoup
                    html_parts.append(BeautifulSoup(text, "html.parser").get_text(separator="\n"))
                except Exception:  # noqa: BLE001
                    html_parts.append(text)
            else:
                plain_parts.append(text)

    if plain_parts:
        return "\n\n".join(plain_parts).strip()
    if html_parts:
        return "\n\n".join(html_parts).strip()
    return "(No readable body found)"


def _extract_attachments(msg: stdlib_email.message.Message) -> list[dict]:
    """Return a list of attachment metadata dicts (filename, content_type, size_bytes)."""
    attachments: list[dict] = []
    if msg.is_multipart():
        for part in msg.walk():
            disp = (part.get_content_disposition() or "").lower()
            raw_filename = part.get_filename()
            if disp == "attachment" or raw_filename:
                filename = _decode_header_str(raw_filename) or "unnamed"
                payload = part.get_payload(decode=True)
                size = len(payload) if payload else 0
                attachments.append({
                    "filename": filename,
                    "content_type": part.get_content_type(),
                    "size_bytes": size,
                })
    return attachments


def _build_preview_payload(
    raw_bytes: bytes,
    item_id: str,
    snippet: str = "",
) -> dict[str, Any]:
    """Parse raw RFC 5322 email bytes into a structured preview dict."""
    msg = stdlib_email.message_from_bytes(raw_bytes, policy=email.policy.compat32)
    return {
        "id": item_id,
        "subject": _decode_header_str(msg.get("Subject")) or "(no subject)",
        "from": _decode_header_str(msg.get("From")),
        "to": _decode_header_str(msg.get("To")),
        "date": _decode_header_str(msg.get("Date")),
        "reply_to": _decode_header_str(msg.get("Reply-To")),
        "snippet": snippet,
        "body_text": _decode_email_body(msg),
        "attachments": _extract_attachments(msg),
        "raw_size_bytes": len(raw_bytes),
    }


SAMPLE_REGISTRY: dict[str, Path] = {
    "ham_000001": BASE_DIR / "data/dev/eml/ham_easy/easy_ham_000001_9f8b61b0348d.eml",
    "ham_000002": BASE_DIR / "data/dev/eml/ham_easy/easy_ham_000002_b6a4d0a4dc3d.eml",
    "phishing_000001": BASE_DIR / "data/dev/eml/phishing/nazario_2015_000001_5784bb2ec05f.eml",
    "phishing_000002": BASE_DIR / "data/dev/eml/phishing/nazario_2015_000002_17c70a61319f.eml",
    "synthetic": BASE_DIR / "data/samples/synthetic_demo.eml",
}


# ── Request Models ────────────────────────────────────────────────────────────

class RawScanRequest(BaseModel):
    text: str = Field(min_length=1)
    abstain_low: float = Field(default=0.35, gt=0.0, lt=1.0)
    abstain_high: float = Field(default=0.65, gt=0.0, lt=1.0)


class RawPreviewRequest(BaseModel):
    text: str = Field(min_length=1)


class SampleScanRequest(BaseModel):
    abstain_low: float = Field(default=0.35, gt=0.0, lt=1.0)
    abstain_high: float = Field(default=0.65, gt=0.0, lt=1.0)


# ══════════════════════════════════════════════════════════════════════════════
# Routes — Health
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/health")
def health(aegis_session: Optional[str] = Cookie(None)):
    return {
        "status": "ok" if pipeline is not None else "degraded",
        "model_name": MODEL_NAME,
        "model_loaded": pipeline is not None,
        "model_load_error": _model_load_error,
        "sha256": _model_sha256,
        "sha256_verified": _sha256_verified(),
        "gmail_configured": _gmail_configured(),
        "gmail_connected": bool(aegis_session and aegis_session in _oauth_sessions),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Routes — Preview & Scan (Files / Raw Text)
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/preview/file")
async def preview_file(file: UploadFile = File(...)):
    raw_bytes = await file.read()
    filename = file.filename or "uploaded_email"
    if filename.lower().endswith(".mbox"):
        try:
            raw_bytes = _extract_first_from_mbox(raw_bytes)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=422, detail=f"mbox parse error: {exc}")
    preview = _build_preview_payload(raw_bytes, item_id=filename)
    if preview["subject"] == "(no subject)" and not preview["from"]:
        preview["subject"] = filename
    return preview


@app.post("/api/preview/raw")
async def preview_raw(body: RawPreviewRequest):
    raw_bytes = body.text.encode("utf-8")
    return _build_preview_payload(raw_bytes, item_id="pasted_email")


@app.post("/api/scan/file")
async def scan_file(
    file: UploadFile = File(...),
    abstain_low: float = Query(0.35, gt=0.0, lt=1.0),
    abstain_high: float = Query(0.65, gt=0.0, lt=1.0),
):
    _require_pipeline()
    raw_bytes = await file.read()
    filename = file.filename or ""

    if filename.lower().endswith(".mbox"):
        try:
            raw_bytes = _extract_first_from_mbox(raw_bytes)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=422, detail=f"mbox parse error: {exc}")

    try:
        result = _scan_raw_bytes(raw_bytes, abstain_low, abstain_high, file_name=filename or None)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=str(exc))
    return JSONResponse(content=result)


@app.post("/api/scan/raw")
async def scan_raw(body: RawScanRequest):
    _require_pipeline()
    raw_bytes = body.text.encode("utf-8")
    try:
        result = _scan_raw_bytes(raw_bytes, body.abstain_low, body.abstain_high)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=str(exc))
    return JSONResponse(content=result)


# ══════════════════════════════════════════════════════════════════════════════
# Routes — Built-In Demo Samples
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/samples")
def list_samples():
    samples = []
    for sid, path in SAMPLE_REGISTRY.items():
        label = "phishing" if "phishing" in sid else ("synthetic" if "synthetic" in sid else "legitimate")
        subject = from_addr = ""
        if path.exists():
            try:
                raw = path.read_bytes()
                msg = stdlib_email.message_from_bytes(raw, policy=email.policy.compat32)
                subject = _decode_header_str(msg.get("Subject")) or "(no subject)"
                from_addr = _decode_header_str(msg.get("From"))
            except Exception:  # noqa: BLE001
                pass

        samples.append({
            "id": sid,
            "label": label,
            "filename": path.name,
            "exists": path.exists(),
            "subject": subject,
            "from": from_addr,
        })
    return samples


@app.get("/api/samples/{sample_id}/preview")
def preview_sample(sample_id: str):
    path = SAMPLE_REGISTRY.get(sample_id)
    if not path or not path.exists():
        raise HTTPException(status_code=404, detail=f"Sample '{sample_id}' not found.")
    raw = path.read_bytes()
    return _build_preview_payload(raw, item_id=sample_id)


@app.post("/api/scan/sample/{sample_id}")
async def scan_sample(sample_id: str, body: SampleScanRequest = SampleScanRequest()):
    _require_pipeline()
    path = SAMPLE_REGISTRY.get(sample_id)
    if not path:
        raise HTTPException(status_code=404, detail=f"Sample '{sample_id}' not found.")
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Sample file missing on disk: {path.name}")
    raw_bytes = path.read_bytes()
    try:
        result = _scan_raw_bytes(raw_bytes, body.abstain_low, body.abstain_high, file_name=path.name)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=str(exc))
    return JSONResponse(content=result)


# ══════════════════════════════════════════════════════════════════════════════
# Routes — Gmail OAuth 2.0 Web Flow
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/auth/google")
async def auth_google():
    Flow, _ = _try_import_google()
    if Flow is None:
        raise HTTPException(status_code=501, detail="google-auth-oauthlib not installed.")
    config = _load_oauth_client_config()
    if config is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "No OAuth client credentials found. "
                "Place credentials.json in the project root or set GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET."
            ),
        )
    flow = Flow.from_client_config(config, scopes=GMAIL_SCOPE, redirect_uri=OAUTH_REDIRECT_URI)
    auth_url, state = flow.authorization_url(prompt="consent", access_type="offline")
    _oauth_sessions[f"pending:{state}"] = flow
    return RedirectResponse(url=auth_url)


@app.get("/api/auth/callback")
async def auth_callback(
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
):
    if error:
        return RedirectResponse(url=f"{FRONTEND_ORIGIN}/?gmail_error={error}")
    Flow, _ = _try_import_google()
    if Flow is None:
        raise HTTPException(status_code=501, detail="google-auth-oauthlib not installed.")
    if not code or not state:
        return RedirectResponse(url=f"{FRONTEND_ORIGIN}/?gmail_error=missing_oauth_params")

    flow = _oauth_sessions.pop(f"pending:{state}", None)
    if flow is None:
        return RedirectResponse(url=f"{FRONTEND_ORIGIN}/?gmail_error=invalid_oauth_state")
    try:
        flow.fetch_token(code=code)
        credentials = flow.credentials
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"OAuth token exchange failed: {exc}")

    session_id = str(uuid.uuid4())
    _oauth_sessions[session_id] = credentials
    response = RedirectResponse(url=f"{FRONTEND_ORIGIN}/?gmail=connected")
    response.set_cookie("aegis_session", session_id, httponly=True, samesite="lax", max_age=3600)
    return response


@app.post("/api/auth/logout")
async def auth_logout(aegis_session: Optional[str] = Cookie(None)):
    if aegis_session and aegis_session in _oauth_sessions:
        _oauth_sessions.pop(aegis_session, None)
    response = JSONResponse(content={"status": "logged_out"})
    response.delete_cookie("aegis_session")
    return response


def _get_gmail_service(session_id: Optional[str]):
    _, google_build = _try_import_google()
    if google_build is None:
        raise HTTPException(status_code=501, detail="google-api-python-client not installed.")
    if not session_id or session_id not in _oauth_sessions:
        raise HTTPException(status_code=401, detail="Not authenticated with Gmail. Sign in first.")
    creds = _oauth_sessions[session_id]
    return google_build("gmail", "v1", credentials=creds)


@app.get("/api/gmail/messages")
async def gmail_messages(
    aegis_session: Optional[str] = Cookie(None),
    max_results: int = Query(20, ge=1, le=50),
):
    service = _get_gmail_service(aegis_session)
    try:
        results = (
            service.users().messages()
            .list(userId="me", maxResults=max_results, labelIds=["INBOX"])
            .execute()
        )
        messages = results.get("messages", [])
        items = []
        for m in messages[:max_results]:
            meta = (
                service.users().messages()
                .get(
                    userId="me",
                    id=m["id"],
                    format="metadata",
                    metadataHeaders=["Subject", "From", "To", "Date"],
                )
                .execute()
            )
            headers = {h["name"]: h["value"] for h in meta.get("payload", {}).get("headers", [])}
            items.append({
                "id": m["id"],
                "subject": headers.get("Subject", "(no subject)"),
                "from": headers.get("From", ""),
                "to": headers.get("To", ""),
                "date": headers.get("Date", ""),
                "snippet": meta.get("snippet", ""),
            })
        return items
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Gmail API error: {exc}")


@app.get("/api/gmail/messages/{message_id}")
async def gmail_message_preview(
    message_id: str,
    aegis_session: Optional[str] = Cookie(None),
):
    """Fetch complete email details (From, To, Date, Subject, snippet, body_text, attachments) before scanning."""
    service = _get_gmail_service(aegis_session)
    try:
        raw_msg = (
            service.users().messages()
            .get(userId="me", id=message_id, format="raw")
            .execute()
        )
        raw_bytes = _decode_base64url(raw_msg.get("raw", ""))
        return _build_preview_payload(
            raw_bytes,
            item_id=message_id,
            snippet=raw_msg.get("snippet", ""),
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Gmail preview error: {exc}")


@app.post("/api/gmail/scan/{message_id}")
async def gmail_scan(
    message_id: str,
    body: SampleScanRequest = SampleScanRequest(),
    aegis_session: Optional[str] = Cookie(None),
):
    _require_pipeline()
    service = _get_gmail_service(aegis_session)
    try:
        msg = (
            service.users().messages()
            .get(userId="me", id=message_id, format="raw")
            .execute()
        )
        raw_bytes = _decode_base64url(msg.get("raw", ""))
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Gmail fetch error: {exc}")
    try:
        result = _scan_raw_bytes(raw_bytes, body.abstain_low, body.abstain_high, file_name=f"gmail_{message_id}.eml")
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=str(exc))
    return JSONResponse(content=result)
