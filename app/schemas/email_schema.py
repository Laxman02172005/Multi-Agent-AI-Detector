"""
email_schema.py
---------------
Pydantic v2 data contracts for the Multi-Agent AI Phishing Email Detector.

These schemas are the shared communication contract used by every component
in the pipeline:
  - Email ingestion
  - Header Agent
  - URL Agent
  - Text Agent
  - Attachment Agent
  - Evidence Aggregation Layer
  - Logistic Regression Meta-Classifier

Rules enforced here:
  - No phishing-classification fields (confidence scores, risk labels, etc.)
  - Missing authentication data must never be inferred or treated as failure.
  - All optional information is properly represented as Optional[...].
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AuthMechanism(str, Enum):
    """Supported email authentication mechanisms."""
    SPF = "SPF"
    DKIM = "DKIM"
    DMARC = "DMARC"


class AuthStatus(str, Enum):
    """
    Possible authentication result statuses.

    Important: 'missing' and 'unavailable' are distinct neutral states.
    Neither implies a failure — they indicate that the information was
    absent or could not be retrieved. Do NOT infer authentication results.
    """
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    MISSING = "missing"
    UNAVAILABLE = "unavailable"
    NEUTRAL = "neutral"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    OTHER = "other"


class AuthProvenance(str, Enum):
    """Source header from which authentication evidence was extracted."""
    AUTHENTICATION_RESULTS_HEADER = "authentication_results_header"
    RECEIVED_SPF_HEADER = "received_spf_header"
    UNAVAILABLE = "unavailable"


class VerificationStatus(str, Enum):
    """Verification state of an authentication claim against receiver trust policy."""
    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    UNKNOWN = "unknown"


class URLSource(str, Enum):
    """Where a URL was found within the email."""
    PLAIN_TEXT = "plain_text"
    HTML_HREF = "html_href"
    HTML_SRC = "html_src"
    HTML_OTHER = "html_other"
    HEADER = "header"


class AttachmentDisposition(str, Enum):
    """MIME content-disposition of an attachment."""
    ATTACHMENT = "attachment"
    INLINE = "inline"
    UNKNOWN = "unknown"


class AttachmentStatus(str, Enum):
    """Processing outcome for an attachment."""
    PROCESSED = "processed"
    SKIPPED = "skipped"
    ERROR = "error"


# ---------------------------------------------------------------------------
# A. EmailHeaders
# ---------------------------------------------------------------------------

class EmailHeaders(BaseModel):
    """
    Raw email header fields preserved exactly as received.

    All fields are optional because headers may be absent in legitimate
    emails (e.g., BCC is stripped by MTAs before delivery, Reply-To is
    rarely set, etc.). Lists default to empty to avoid None-checks.
    """

    from_address: Optional[str] = Field(
        default=None,
        description="Value of the 'From' header.",
    )
    to: list[str] = Field(
        default_factory=list,
        description="Values of the 'To' header (may contain multiple addresses).",
    )
    cc: list[str] = Field(
        default_factory=list,
        description="Values of the 'CC' header.",
    )
    bcc: list[str] = Field(
        default_factory=list,
        description="Values of the 'BCC' header (usually absent post-delivery).",
    )
    reply_to: Optional[str] = Field(
        default=None,
        description="Value of the 'Reply-To' header.",
    )
    return_path: Optional[str] = Field(
        default=None,
        description="Value of the 'Return-Path' header.",
    )
    subject: Optional[str] = Field(
        default=None,
        description="Value of the 'Subject' header.",
    )
    date: Optional[str] = Field(
        default=None,
        description="Value of the 'Date' header (preserved as raw string).",
    )
    message_id: Optional[str] = Field(
        default=None,
        description="Value of the 'Message-ID' header.",
    )
    received: list[str] = Field(
        default_factory=list,
        description="All 'Received' header values in order (oldest last).",
    )
    authentication_results: list[str] = Field(
        default_factory=list,
        description="All 'Authentication-Results' header values.",
    )
    received_spf: list[str] = Field(
        default_factory=list,
        description="All 'Received-SPF' header values.",
    )
    dkim_signature: list[str] = Field(
        default_factory=list,
        description="All 'DKIM-Signature' header values.",
    )
    mime_version: Optional[str] = Field(
        default=None,
        description="Value of the 'MIME-Version' header.",
    )
    content_type: Optional[str] = Field(
        default=None,
        description="Value of the top-level 'Content-Type' header.",
    )

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# B. AuthenticationResult
# ---------------------------------------------------------------------------

class AuthenticationResult(BaseModel):
    """
    Result of a single email authentication check (SPF, DKIM, or DMARC).

    Design note:
        'missing'/'unavailable' statuses are explicit neutral states.
        They MUST NOT be treated as equivalent to 'fail'.
        Agents must never infer authentication results from absence of data.
        'verification_status' defaults to 'unverified' — claims are reported
        as stated in headers until verified against receiver policy by Header Agent.
    """

    mechanism: AuthMechanism = Field(
        description="The authentication mechanism this result belongs to.",
    )
    status: AuthStatus = Field(
        description=(
            "Outcome of the check. Use 'missing' when the header was absent, "
            "'unavailable' when the check could not be performed."
        ),
    )
    raw_value: Optional[str] = Field(
        default=None,
        description="The original header value, preserved verbatim.",
    )
    provenance: AuthProvenance = Field(
        default=AuthProvenance.UNAVAILABLE,
        description="The header source from which this authentication result was extracted.",
    )
    verification_status: VerificationStatus = Field(
        default=VerificationStatus.UNVERIFIED,
        description="Whether this authentication claim has been verified by a trusted receiver.",
    )
    authserv_id: Optional[str] = Field(
        default=None,
        description="The authserv-id of the reporting MTA from Authentication-Results, if present.",
    )

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# C. AuthenticationClaim and AuthenticationMetadata
# ---------------------------------------------------------------------------

class AuthenticationClaim(BaseModel):
    """
    An individual authentication claim issued by a specific mail server or header.

    Unlike summary fields, an AuthenticationClaim preserves the 1:1 relationship
    between an evaluation outcome (pass, fail, etc.) and the specific header
    and reporting authserv-id that produced it.
    """

    mechanism: AuthMechanism = Field(
        description="The authentication mechanism (SPF, DKIM, or DMARC).",
    )
    status: AuthStatus = Field(
        description="Reported authentication outcome for this claim.",
    )
    authserv_id: Optional[str] = Field(
        default=None,
        description="The authserv-id of the reporting MTA from Authentication-Results, if present.",
    )
    raw_value: Optional[str] = Field(
        default=None,
        description="The specific mechanism result fragment (e.g. 'spf=pass').",
    )
    header_raw: Optional[str] = Field(
        default=None,
        description="The original full header line from which this claim was extracted.",
    )
    header_index: int = Field(
        ge=0,
        description="Non-negative integer identifying the original header's position among headers of the same type.",
    )
    provenance: AuthProvenance = Field(
        description="The header source from which this authentication claim was extracted.",
    )
    verification_status: VerificationStatus = Field(
        default=VerificationStatus.UNVERIFIED,
        description="Whether this authentication claim has been verified by a trusted receiver.",
    )

    model_config = {"extra": "forbid"}


class AuthenticationMetadata(BaseModel):
    """
    Container for SPF, DKIM, and DMARC authentication results.

    All three summary sub-results must always be present so that downstream
    consumers can rely on a consistent structure. When information is
    unavailable, use AuthStatus.UNAVAILABLE or AuthStatus.MISSING.
    The 'claims' list preserves every individual authentication claim and its
    associated reporting MTA provenance without loss of granularity.
    """

    spf: AuthenticationResult = Field(
        description="Consolidated SPF authentication summary result.",
    )
    dkim: AuthenticationResult = Field(
        description="Consolidated DKIM authentication summary result.",
    )
    dmarc: AuthenticationResult = Field(
        description="Consolidated DMARC authentication summary result.",
    )
    claims: list[AuthenticationClaim] = Field(
        default_factory=list,
        description="All individual authentication claims extracted from headers.",
    )

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# D. ExtractedURL
# ---------------------------------------------------------------------------

class ExtractedURL(BaseModel):
    """
    A URL extracted from the email body or HTML markup.

    'source' indicates where the URL was found so that agents can weight
    URLs differently depending on context (e.g., obfuscated href vs.
    plain-text mention).
    """

    original_url: str = Field(
        description="The URL exactly as it appeared in the email.",
    )
    normalized_url: Optional[str] = Field(
        default=None,
        description="Canonicalized / decoded version of the URL (optional).",
    )
    source: URLSource = Field(
        description="Where the URL was found in the email.",
    )
    anchor_text: Optional[str] = Field(
        default=None,
        description="The visible link text when the URL was in an HTML anchor.",
    )
    scheme: Optional[str] = Field(
        default=None,
        description="Extracted URL scheme (e.g. 'http', 'https', 'javascript', 'data', 'file').",
    )
    hostname: Optional[str] = Field(
        default=None,
        description="Extracted and normalized hostname or IP address.",
    )
    path: Optional[str] = Field(
        default=None,
        description="Path component of the URL.",
    )
    query: Optional[str] = Field(
        default=None,
        description="Query string component of the URL (without leading '?').",
    )

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# E. AttachmentMetadata
# ---------------------------------------------------------------------------

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class AttachmentMetadata(BaseModel):
    """
    Metadata describing a single email attachment.

    Design notes:
        - 'size_bytes' is validated to be non-negative.
        - 'sha256' must be exactly 64 hex characters when provided.
        - Skipped attachments MUST carry a 'skip_reason' so the reason
          is never silently lost.
    """

    filename: Optional[str] = Field(
        default=None,
        description="Original filename as declared in the MIME part.",
    )
    content_type: Optional[str] = Field(
        default=None,
        description="MIME content type of the attachment.",
    )
    extension: Optional[str] = Field(
        default=None,
        description="File extension derived from the filename (without leading dot).",
    )
    size_bytes: Optional[int] = Field(
        default=None,
        ge=0,
        description="Size of the attachment in bytes if measured. Must be non-negative when present.",
    )
    sha256: Optional[str] = Field(
        default=None,
        description="SHA-256 hex digest of the attachment content (64 hex chars).",
    )
    disposition: AttachmentDisposition = Field(
        description="MIME content-disposition value.",
    )
    status: AttachmentStatus = Field(
        description="Processing outcome for this attachment.",
    )
    skip_reason: Optional[str] = Field(
        default=None,
        description=(
            "Human-readable reason the attachment was skipped. "
            "Required when status is 'skipped'."
        ),
    )
    content_id: Optional[str] = Field(
        default=None,
        description="MIME Content-ID header value if present (e.g. for inline parts).",
    )
    raw_filename: Optional[str] = Field(
        default=None,
        description="Original unsanitised filename preserved verbatim from headers.",
    )

    @property
    def skipped(self) -> bool:
        """Convenience property indicating whether this attachment was skipped."""
        return self.status == AttachmentStatus.SKIPPED

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: Optional[str]) -> Optional[str]:
        """SHA-256 must be exactly 64 hexadecimal characters when present."""
        if value is not None and not _SHA256_RE.match(value):
            raise ValueError(
                f"sha256 must be exactly 64 hexadecimal characters, got {len(value)} chars: {value!r}"
            )
        return value

    @model_validator(mode="after")
    def validate_skip_reason_present_when_skipped(self) -> "AttachmentMetadata":
        """Skipped attachments must carry the reason they were skipped."""
        if self.status == AttachmentStatus.SKIPPED and not self.skip_reason:
            raise ValueError(
                "skip_reason must be provided when attachment status is 'skipped'."
            )
        return self

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# F. BodyContent
# ---------------------------------------------------------------------------

class BodyContent(BaseModel):
    """
    Extracted plain-text, HTML, and sanitised readable text from an email body.

    Produced by the body extraction module (Task 4) and used downstream by
    Text Agent, URL Agent, and the Evidence Aggregation Layer.
    """

    plain_text_body: Optional[str] = Field(
        default=None,
        description="Plain-text part of the email body, preserved as decoded text.",
    )
    html_body: Optional[str] = Field(
        default=None,
        description="HTML part of the email body, preserved as decoded HTML markup.",
    )
    cleaned_text: Optional[str] = Field(
        default=None,
        description="Sanitised, readable text derived from plain-text or HTML for NLP analysis.",
    )
    parsing_warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal warnings encountered during body extraction (e.g. unknown charsets).",
    )

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# G. EmailData  (main model)
# ---------------------------------------------------------------------------

class EmailData(BaseModel):
    """
    Top-level data contract for a parsed email.

    This is the single shared structure passed between every component
    in the pipeline. No phishing-classification data lives here — agents
    emit their own result types and the aggregation layer combines them.
    """

    email_id: str = Field(
        description="Unique identifier for this email (must not be empty).",
    )
    source_filename: str = Field(
        description="Name of the .eml (or other) file this email was read from.",
    )
    headers: EmailHeaders = Field(
        description="Parsed email headers.",
    )
    authentication: AuthenticationMetadata = Field(
        description="SPF / DKIM / DMARC authentication results.",
    )
    plain_text_body: Optional[str] = Field(
        default=None,
        description="Plain-text part of the email body.",
    )
    html_body: Optional[str] = Field(
        default=None,
        description="HTML part of the email body.",
    )
    cleaned_text: Optional[str] = Field(
        default=None,
        description="Sanitised / stripped version of the body text for NLP use.",
    )
    extracted_urls: list[ExtractedURL] = Field(
        default_factory=list,
        description="All URLs extracted from plain-text and HTML bodies.",
    )
    attachments: list[AttachmentMetadata] = Field(
        default_factory=list,
        description="Metadata for every attachment found in the email.",
    )
    parsing_warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal issues encountered during parsing.",
    )
    ingestion_timestamp: datetime = Field(
        description="UTC timestamp when this email was ingested by the pipeline.",
    )

    # ------------------------------------------------------------------
    # Field-level validators
    # ------------------------------------------------------------------

    @field_validator("email_id")
    @classmethod
    def email_id_not_empty(cls, value: str) -> str:
        """Email ID must be a non-empty string."""
        if not value.strip():
            raise ValueError("email_id must not be empty or whitespace.")
        return value

    @field_validator("source_filename")
    @classmethod
    def source_filename_not_empty(cls, value: str) -> str:
        """Source filename must be a non-empty string."""
        if not value.strip():
            raise ValueError("source_filename must not be empty or whitespace.")
        return value

    model_config = {"extra": "forbid"}
