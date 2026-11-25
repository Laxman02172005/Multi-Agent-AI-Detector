"""
email_ingestor.py
-----------------
Unified email ingestion coordinator for the Multi-Agent AI Phishing Email Detector.

This module provides the central entry point for ingesting raw RFC822 email files
as bytes, orchestrating the extraction of headers, authentication metadata,
body content, URLs, and attachments over a single parsed MIME Message object,
and returning a validated EmailData model.

Coordinator Design & Guarantees:
---------------------------------
1. Input Contract:
   - Accepts raw email content as `bytes` exclusively.
   - Rejects non-bytes inputs (strings, bytearrays, etc.) with `InvalidInputTypeError`.
   - Rejects empty or whitespace-only bytes with `EmptyEmailError`.
2. Strict Resource Boundaries:
   - Enforces `MAX_RAW_EMAIL_SIZE_BYTES = 52_428_800` (50 MB).
   - Rejects oversized input before invoking the MIME parser with `OversizedEmailError`.
   - Never parses, slices, or decodes oversized input.
3. Parsing Policy:
   - Uses Python's standard-library `BytesParser(policy=policy.default)`.
   - Parses the input exactly once, reusing the same `email.message.Message`
     across all extractors.
   - Detects and records parser defects (`message.defects`) without treating
     non-fatal syntax quirks as fatal errors.
4. Internal Email ID:
   - Uses caller-supplied ID if provided and non-empty.
   - Rejects whitespace-only IDs with `ValueError`.
   - Generates a globally unique UUID4 identifier `email_<uuid hex>` by default.
   - Does not use untrusted `Message-ID` headers as internal primary keys.
5. Passive & Secure Operation:
   - Zero network requests, socket connections, or DNS queries.
   - Zero external URL fetching or reputation checks.
   - Zero attachment execution, archive unpacking, or filesystem writes.
   - Zero phishing classification, risk scoring, or confidence weighting.
6. Error Handling:
   - Clear exception hierarchy rooted at `IngestionError`.
   - Unexpected extractor exceptions are preserved via exception chaining (`raise ... from exc`).
   - `MemoryError` is never masked or relabeled as `MalformedEmailError`.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from email import policy
from email.message import Message
from email.parser import BytesParser
from typing import Optional

from app.ingestion.attachment_extractor import extract_attachments
from app.ingestion.body_extractor import extract_body
from app.ingestion.header_extractor import extract_authentication, extract_headers
from app.ingestion.url_extractor import extract_urls
from app.schemas.email_schema import AttachmentStatus, EmailData


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum permitted raw RFC822 input size: 50 MB (52,428,800 bytes)
MAX_RAW_EMAIL_SIZE_BYTES: int = 50 * 1024 * 1024


# ---------------------------------------------------------------------------
# Exception Hierarchy
# ---------------------------------------------------------------------------

class IngestionError(Exception):
    """Base exception for all unrecoverable email ingestion errors."""


class InvalidInputTypeError(IngestionError, TypeError):
    """Raised when raw_eml is not bytes."""


class EmptyEmailError(IngestionError, ValueError):
    """Raised when raw_eml is empty or contains only whitespace."""


class OversizedEmailError(IngestionError, ValueError):
    """Raised when raw_eml exceeds MAX_RAW_EMAIL_SIZE_BYTES."""


class MalformedEmailError(IngestionError, ValueError):
    """Raised when the raw email cannot be parsed into an email Message."""


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _collect_parser_defects(message: Message) -> list[str]:
    """
    Recursively collect parser defects from the message and all subparts.

    Returns descriptive warning strings formatted as 'MIME defect: <DefectName>'.
    """
    warnings: list[str] = []
    seen_defect_ids: set[int] = set()

    try:
        parts = list(message.walk())
    except Exception:
        parts = [message]

    for part in parts:
        for defect in getattr(part, "defects", []):
            if id(defect) not in seen_defect_ids:
                seen_defect_ids.add(id(defect))
                defect_name = defect.__class__.__name__
                line = getattr(defect, "line", None)
                line_info = f" at line {line}" if line is not None else ""
                warnings.append(f"MIME defect: {defect_name}{line_info}")

    return warnings


# ---------------------------------------------------------------------------
# Public Ingestion Coordinator API
# ---------------------------------------------------------------------------

def ingest_email(
    raw_eml: bytes,
    *,
    source_filename: str = "raw_email.eml",
    email_id: str | None = None,
) -> EmailData:
    """
    Coordinate the ingestion of a raw RFC822 email message into an EmailData instance.

    Parameters:
        raw_eml:
            Raw RFC822 email message content as `bytes`.
        source_filename:
            Name of the source email file (default: "raw_email.eml").
            Must not be empty or whitespace-only.
        email_id:
            Optional caller-supplied unique identifier for this email.
            If omitted, a random UUID4-based identifier (`email_<uuid_hex>`) is generated.
            Must not be whitespace-only.

    Returns:
        EmailData:
            Validated Pydantic model populated with headers, authentication metadata,
            body content, extracted URLs, attachments, and parsing warnings.

    Raises:
        InvalidInputTypeError:
            If raw_eml is not `bytes` (e.g. `str`, `bytearray`, `None`).
        EmptyEmailError:
            If raw_eml is empty or contains only whitespace.
        OversizedEmailError:
            If raw_eml exceeds `MAX_RAW_EMAIL_SIZE_BYTES` (50 MB).
        MalformedEmailError:
            If the message cannot be parsed into an email Message.
        IngestionError:
            If an unexpected extractor exception occurs during pipeline execution.
        ValueError:
            If caller supplies an empty or whitespace-only email_id or source_filename.
    """
    # -----------------------------------------------------------------------
    # Step 1: Input Validation
    # -----------------------------------------------------------------------
    if not isinstance(raw_eml, bytes) or isinstance(raw_eml, bytearray):
        raise InvalidInputTypeError(
            f"raw_eml must be bytes, got {type(raw_eml).__name__}"
        )

    # Empty or whitespace-only check
    if len(raw_eml) == 0 or not raw_eml.strip():
        raise EmptyEmailError("raw_eml is empty or whitespace-only.")

    # -----------------------------------------------------------------------
    # Step 2: Raw Size Enforcement (before MIME parsing)
    # -----------------------------------------------------------------------
    if len(raw_eml) > MAX_RAW_EMAIL_SIZE_BYTES:
        raise OversizedEmailError(
            f"Raw email size ({len(raw_eml)} bytes) exceeds maximum limit "
            f"of {MAX_RAW_EMAIL_SIZE_BYTES} bytes (50 MB)."
        )

    # -----------------------------------------------------------------------
    # Step 3: Single-Pass MIME Parsing
    # -----------------------------------------------------------------------
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_eml)
    except MemoryError:
        # Do not catch MemoryError and relabel it as MalformedEmailError
        raise
    except Exception as exc:
        raise MalformedEmailError(f"Failed to parse RFC822 message: {exc}") from exc

    if message is None:
        raise MalformedEmailError("BytesParser returned None for raw email input.")

    # -----------------------------------------------------------------------
    # Step 4: Parser Defect Collection
    # -----------------------------------------------------------------------
    parsing_warnings = _collect_parser_defects(message)

    # -----------------------------------------------------------------------
    # Step 5: Extract Headers & Authentication Metadata
    # -----------------------------------------------------------------------
    try:
        headers = extract_headers(message)
    except Exception as exc:
        raise IngestionError(f"Header extraction failed: {exc}") from exc

    try:
        authentication = extract_authentication(message)
    except Exception as exc:
        raise IngestionError(f"Authentication extraction failed: {exc}") from exc

    # -----------------------------------------------------------------------
    # Step 6: Extract Body Content
    # -----------------------------------------------------------------------
    try:
        body_content = extract_body(message)
    except Exception as exc:
        raise IngestionError(f"Body extraction failed: {exc}") from exc

    parsing_warnings.extend(body_content.parsing_warnings)

    # -----------------------------------------------------------------------
    # Step 7: Resolve Identifiers & Ingestion Timestamp
    # -----------------------------------------------------------------------
    if email_id is not None:
        if not isinstance(email_id, str) or not email_id.strip():
            raise ValueError("email_id must not be empty or whitespace.")
        resolved_email_id = email_id.strip()
    else:
        resolved_email_id = f"email_{uuid.uuid4().hex}"

    if not isinstance(source_filename, str) or not source_filename.strip():
        raise ValueError("source_filename must not be empty or whitespace.")
    resolved_source_filename = source_filename.strip()

    ingestion_timestamp = datetime.now(timezone.utc)

    # -----------------------------------------------------------------------
    # Step 8: Stage EmailData for URL Extraction
    # -----------------------------------------------------------------------
    staged_email_data = EmailData(
        email_id=resolved_email_id,
        source_filename=resolved_source_filename,
        headers=headers,
        authentication=authentication,
        plain_text_body=body_content.plain_text_body,
        html_body=body_content.html_body,
        cleaned_text=body_content.cleaned_text,
        extracted_urls=[],
        attachments=[],
        parsing_warnings=parsing_warnings,
        ingestion_timestamp=ingestion_timestamp,
    )

    # -----------------------------------------------------------------------
    # Step 9: Extract URLs
    # -----------------------------------------------------------------------
    try:
        extracted_urls = extract_urls(staged_email_data)
    except Exception as exc:
        raise IngestionError(f"URL extraction failed: {exc}") from exc

    # -----------------------------------------------------------------------
    # Step 10: Extract Attachments
    # -----------------------------------------------------------------------
    try:
        attachments = extract_attachments(message)
    except Exception as exc:
        raise IngestionError(f"Attachment extraction failed: {exc}") from exc

    # Propagate attachment skip/error warnings into parsing_warnings
    for att in attachments:
        if att.status == AttachmentStatus.SKIPPED and att.skip_reason:
            att_name = att.filename or att.raw_filename or "unnamed"
            parsing_warnings.append(
                f"Attachment '{att_name}' skipped: {att.skip_reason}"
            )
        elif att.status == AttachmentStatus.ERROR and att.skip_reason:
            att_name = att.filename or att.raw_filename or "unnamed"
            parsing_warnings.append(
                f"Attachment '{att_name}' error: {att.skip_reason}"
            )

    # -----------------------------------------------------------------------
    # Step 11: Final EmailData Construction & Validation
    # -----------------------------------------------------------------------
    return EmailData(
        email_id=resolved_email_id,
        source_filename=resolved_source_filename,
        headers=headers,
        authentication=authentication,
        plain_text_body=body_content.plain_text_body,
        html_body=body_content.html_body,
        cleaned_text=body_content.cleaned_text,
        extracted_urls=extracted_urls,
        attachments=attachments,
        parsing_warnings=parsing_warnings,
        ingestion_timestamp=ingestion_timestamp,
    )
