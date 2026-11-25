"""
tests/test_email_ingestor.py
----------------------------
Comprehensive pytest test suite for the unified email ingestion coordinator
(app.ingestion.email_ingestor.ingest_email).

Covers all 23 scenarios specified in Task 7.1:
  1.  Normal plain-text email
  2.  HTML email containing URLs
  3.  Multipart alternative email
  4.  Multipart mixed email with multiple attachments
  5.  Authentication-Results and Received-SPF headers
  6.  Missing optional headers
  7.  Body-only email
  8.  Empty input (b"" and whitespace bytes)
  9.  Invalid input types (str, bytearray, int, None, dict)
  10. Exactly 50 MB raw input boundary check
  11. Raw input exceeding 50 MB
  12. Oversized input rejected before MIME parser is called
  13. Malformed MIME boundaries and parser defect capture
  14. Unknown charset warning propagation
  15. Skipped attachment warning propagation
  16. Caller-supplied email ID
  17. Generated UUID4 email ID format
  18. Duplicate Message-ID headers produce distinct internal IDs
  19. Whitespace-only caller-supplied ID rejected
  20. Complete EmailData schema validation (extra fields forbidden)
  21. JSON serialization and deserialization round trip
  22. Extractor exceptions are not silently swallowed (raise ... from exc)
  23. Exactly same parsed Message instance passed to all extractors
"""

from __future__ import annotations

import json
from email.message import Message
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from app.ingestion.email_ingestor import (
    MAX_RAW_EMAIL_SIZE_BYTES,
    EmptyEmailError,
    IngestionError,
    InvalidInputTypeError,
    MalformedEmailError,
    OversizedEmailError,
    ingest_email,
)
from app.schemas.email_schema import (
    AttachmentDisposition,
    AttachmentStatus,
    AuthMechanism,
    AuthStatus,
    EmailData,
    URLSource,
)


# ---------------------------------------------------------------------------
# Test Fixtures & Sample Messages
# ---------------------------------------------------------------------------

@pytest.fixture
def normal_plain_text_bytes() -> bytes:
    return (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Subject: Meeting Reminder\r\n"
        b"Date: Wed, 11 Nov 2026 10:00:00 +0000\r\n"
        b"Message-ID: <reminder-12345@example.com>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Hi Team,\r\n"
        b"Please remember tomorrow's meeting at 10 AM.\r\n"
    )


@pytest.fixture
def html_with_urls_bytes() -> bytes:
    return (
        b"From: newsletter@example.com\r\n"
        b"To: user@example.com\r\n"
        b"Subject: Weekly Updates\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b"<html><body>\r\n"
        b"<p>Welcome to our newsletter!</p>\r\n"
        b'<p><a href="https://example.com/login">Sign in to your portal</a></p>\r\n'
        b'<img src="https://example.com/logo.png" alt="Company Logo">\r\n'
        b"</body></html>\r\n"
    )


@pytest.fixture
def multipart_alternative_bytes() -> bytes:
    return (
        b"From: support@example.com\r\n"
        b"To: user@example.com\r\n"
        b"Subject: Account Verification\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/alternative; boundary="ALT_BOUND"\r\n'
        b"\r\n"
        b"--ALT_BOUND\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Please verify your account here: https://example.com/verify\r\n"
        b"\r\n"
        b"--ALT_BOUND\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b'<html><body><p>Please <a href="https://example.com/verify">verify</a> your account.</p></body></html>\r\n'
        b"--ALT_BOUND--\r\n"
    )


@pytest.fixture
def multipart_mixed_with_attachments_bytes() -> bytes:
    return (
        b"From: billing@example.com\r\n"
        b"To: accounts@example.com\r\n"
        b"Subject: Invoice #8841\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="MIXED_BOUND"\r\n'
        b"\r\n"
        b"--MIXED_BOUND\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Attached is the invoice PDF and signature.\r\n"
        b"\r\n"
        b"--MIXED_BOUND\r\n"
        b"Content-Type: application/pdf\r\n"
        b'Content-Disposition: attachment; filename="invoice_8841.pdf"\r\n'
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"JVBERi0xLjQKJcTl8uXr...\r\n"
        b"\r\n"
        b"--MIXED_BOUND\r\n"
        b"Content-Type: text/plain\r\n"
        b'Content-Disposition: attachment; filename="notes.txt"\r\n'
        b"\r\n"
        b"Payment due in 30 days.\r\n"
        b"--MIXED_BOUND--\r\n"
    )


# ---------------------------------------------------------------------------
# 1. Normal Plain-Text Email
# ---------------------------------------------------------------------------

def test_normal_plain_text_email(normal_plain_text_bytes):
    """Scenario 1: Happy path single-part plain-text email."""
    result = ingest_email(normal_plain_text_bytes, source_filename="reminder.eml")

    assert isinstance(result, EmailData)
    assert result.source_filename == "reminder.eml"
    assert result.email_id.startswith("email_")
    assert result.headers.from_address == "sender@example.com"
    assert result.headers.to == ["recipient@example.com"]
    assert result.headers.subject == "Meeting Reminder"
    assert result.headers.message_id == "<reminder-12345@example.com>"
    assert result.plain_text_body is not None
    assert "tomorrow's meeting" in result.plain_text_body
    assert result.html_body is None
    assert result.cleaned_text is not None
    assert "tomorrow's meeting" in result.cleaned_text
    assert result.extracted_urls == []
    assert result.attachments == []
    assert result.ingestion_timestamp is not None


# ---------------------------------------------------------------------------
# 2. HTML Email Containing URLs
# ---------------------------------------------------------------------------

def test_html_email_containing_urls(html_with_urls_bytes):
    """Scenario 2: HTML email with multiple URLs extracted."""
    result = ingest_email(html_with_urls_bytes)

    assert isinstance(result, EmailData)
    assert result.html_body is not None
    assert len(result.extracted_urls) == 2

    # Verify link with visible anchor text
    login_url = next(u for u in result.extracted_urls if u.source == URLSource.HTML_HREF)
    assert login_url.original_url == "https://example.com/login"
    assert login_url.anchor_text == "Sign in to your portal"

    # Verify image source URL
    img_url = next(u for u in result.extracted_urls if u.source == URLSource.HTML_SRC)
    assert img_url.original_url == "https://example.com/logo.png"


# ---------------------------------------------------------------------------
# 3. Multipart Alternative Email
# ---------------------------------------------------------------------------

def test_multipart_alternative_email(multipart_alternative_bytes):
    """Scenario 3: Multipart alternative with plain-text and HTML bodies."""
    result = ingest_email(multipart_alternative_bytes)

    assert result.plain_text_body is not None
    assert "Please verify your account" in result.plain_text_body
    assert result.html_body is not None
    assert "<a href=" in result.html_body
    # Precedence rule: cleaned_text should come from plain_text_body
    assert result.cleaned_text == "Please verify your account here: https://example.com/verify"
    assert len(result.extracted_urls) >= 1


# ---------------------------------------------------------------------------
# 4. Multipart Mixed Email with Multiple Attachments
# ---------------------------------------------------------------------------

def test_multipart_mixed_email_with_multiple_attachments(multipart_mixed_with_attachments_bytes):
    """Scenario 4: Multipart mixed email with multiple attachments."""
    result = ingest_email(multipart_mixed_with_attachments_bytes)

    assert len(result.attachments) == 2
    pdf_att = result.attachments[0]
    assert pdf_att.filename == "invoice_8841.pdf"
    assert pdf_att.content_type == "application/pdf"
    assert pdf_att.extension == "pdf"
    assert pdf_att.status == AttachmentStatus.PROCESSED
    assert pdf_att.sha256 is not None
    assert len(pdf_att.sha256) == 64

    txt_att = result.attachments[1]
    assert txt_att.filename == "notes.txt"
    assert txt_att.status == AttachmentStatus.PROCESSED
    assert txt_att.sha256 is not None


# ---------------------------------------------------------------------------
# 5. Authentication Headers
# ---------------------------------------------------------------------------

def test_authentication_results_and_received_spf_headers():
    """Scenario 5: Authentication-Results and Received-SPF parsed into AuthenticationMetadata."""
    raw = (
        b"From: bank@secure.com\r\n"
        b"To: client@example.com\r\n"
        b"Subject: Security Notice\r\n"
        b"Authentication-Results: mx.google.com; spf=pass dkim=pass dmarc=pass\r\n"
        b"Received-SPF: pass (google.com: domain of bank@secure.com designates 1.2.3.4)\r\n"
        b"\r\n"
        b"Security notice body.\r\n"
    )
    result = ingest_email(raw)

    assert result.authentication.spf.status == AuthStatus.PASS
    assert result.authentication.dkim.status == AuthStatus.PASS
    assert result.authentication.dmarc.status == AuthStatus.PASS
    assert len(result.authentication.claims) >= 3


# ---------------------------------------------------------------------------
# 6. Missing Optional Headers
# ---------------------------------------------------------------------------

def test_missing_optional_headers():
    """Scenario 6: Missing headers do not crash; represented as None or []."""
    raw = b"Subject: Lone Subject\r\n\r\nBody with no from or to."
    result = ingest_email(raw)

    assert result.headers.subject == "Lone Subject"
    assert result.headers.from_address is None
    assert result.headers.to == []
    assert result.headers.date is None
    assert result.headers.message_id is None
    assert result.plain_text_body == "Body with no from or to."


# ---------------------------------------------------------------------------
# 7. Body-Only Email
# ---------------------------------------------------------------------------

def test_body_only_email():
    """Scenario 7: Body-only email without any headers is ingested cleanly."""
    raw = b"\r\nJust a raw body line with no headers whatsoever."
    result = ingest_email(raw)

    assert result.headers.from_address is None
    assert result.headers.subject is None
    assert result.plain_text_body == "Just a raw body line with no headers whatsoever."
    assert result.cleaned_text == "Just a raw body line with no headers whatsoever."


# ---------------------------------------------------------------------------
# 8. Empty Input
# ---------------------------------------------------------------------------

def test_empty_input_rejected():
    """Scenario 8: Empty bytes or whitespace bytes raise EmptyEmailError."""
    with pytest.raises(EmptyEmailError):
        ingest_email(b"")

    with pytest.raises(EmptyEmailError):
        ingest_email(b"   \r\n\t  ")


# ---------------------------------------------------------------------------
# 9. Invalid Input Types
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("invalid_input", [
    "From: a@b.com\r\n\r\nHello",  # string
    bytearray(b"From: a@b.com\r\n\r\nHello"),  # bytearray
    None,
    12345,
    ["From: a@b.com"],
    {"raw": b"bytes"},
])
def test_invalid_input_types_rejected(invalid_input):
    """Scenario 9: Non-bytes types raise InvalidInputTypeError."""
    with pytest.raises(InvalidInputTypeError):
        ingest_email(invalid_input)


# ---------------------------------------------------------------------------
# 10. Exactly 50 MB Raw Input Boundary
# ---------------------------------------------------------------------------

def test_exactly_50mb_raw_input(monkeypatch):
    """Scenario 10: Exactly 50 MB (52,428,800 bytes) does not trigger OversizedEmailError."""
    # Mock BytesParser to avoid allocating 50 MB parsed tree in memory
    mock_parser = MagicMock()
    mock_msg = Message()
    mock_msg.set_payload("Mocked 50MB payload")
    mock_parser.return_value.parsebytes.return_value = mock_msg

    import app.ingestion.email_ingestor as mod
    monkeypatch.setattr(mod, "BytesParser", mock_parser)

    # Use a mock/zero-copy byte object of exact size
    class MockBytes(bytes):
        def __len__(self):
            return MAX_RAW_EMAIL_SIZE_BYTES
        def strip(self):
            return b"content"

    mock_raw = MockBytes(b"dummy")
    result = ingest_email(mock_raw)
    assert isinstance(result, EmailData)
    assert mock_parser.return_value.parsebytes.called


# ---------------------------------------------------------------------------
# 11. Raw Input Exceeding 50 MB
# ---------------------------------------------------------------------------

def test_raw_input_exceeding_50mb():
    """Scenario 11: Input exceeding 50 MB raises OversizedEmailError."""
    class MockOversizedBytes(bytes):
        def __len__(self):
            return MAX_RAW_EMAIL_SIZE_BYTES + 1
        def strip(self):
            return b"content"

    oversized = MockOversizedBytes(b"dummy")
    with pytest.raises(OversizedEmailError) as exc_info:
        ingest_email(oversized)

    assert "exceeds maximum limit" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 12. Oversized Input Rejected Before Parser Called
# ---------------------------------------------------------------------------

def test_oversized_input_rejected_before_parser_called(monkeypatch):
    """Scenario 12: Confirm BytesParser is never called for oversized input."""
    mock_parser = MagicMock()
    import app.ingestion.email_ingestor as mod
    monkeypatch.setattr(mod, "BytesParser", mock_parser)

    class MockOversizedBytes(bytes):
        def __len__(self):
            return MAX_RAW_EMAIL_SIZE_BYTES + 1024
        def strip(self):
            return b"content"

    with pytest.raises(OversizedEmailError):
        ingest_email(MockOversizedBytes(b"dummy"))

    assert not mock_parser.called


# ---------------------------------------------------------------------------
# 13. Malformed MIME Boundaries & Parser Defects
# ---------------------------------------------------------------------------

def test_malformed_mime_boundaries_and_parser_defects():
    """Scenario 13: Missing boundaries produce non-fatal parser defects in parsing_warnings."""
    malformed_raw = (
        b"From: test@example.com\r\n"
        b"Subject: Malformed Boundary\r\n"
        b'Content-Type: multipart/mixed; boundary="MISSING_BOUNDARY"\r\n'
        b"\r\n"
        b"This content does not include the declared boundary delimiter.\r\n"
    )
    result = ingest_email(malformed_raw)

    assert isinstance(result, EmailData)
    # Parser defect should be captured
    defect_warnings = [w for w in result.parsing_warnings if "MIME defect:" in w]
    assert len(defect_warnings) > 0


# ---------------------------------------------------------------------------
# 14. Unknown Charset Warning Propagation
# ---------------------------------------------------------------------------

def test_unknown_charset_warning_propagation():
    """Scenario 14: Unknown charset warnings from body_extractor are propagated."""
    raw = (
        b"From: test@example.com\r\n"
        b"Content-Type: text/plain; charset=non-existent-charset-12345\r\n"
        b"\r\n"
        b"Hello world\r\n"
    )
    result = ingest_email(raw)

    assert "Hello world" in result.plain_text_body
    charset_warnings = [w for w in result.parsing_warnings if "character encoding" in w.lower()]
    assert len(charset_warnings) > 0


# ---------------------------------------------------------------------------
# 15. Skipped Attachment Warning Propagation
# ---------------------------------------------------------------------------

def test_skipped_attachment_warning_propagation():
    """Scenario 15: Skipped oversized attachment produces a warning in parsing_warnings."""
    # Attachment of 26 MB raw string exceeding 25 MB limit
    oversized_raw = "A" * (26 * 1024 * 1024)
    raw = (
        b"From: test@example.com\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="BOUND"\r\n'
        b"\r\n"
        b"--BOUND\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Body text\r\n"
        b"--BOUND\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="huge.bin"\r\n'
        b"Content-Transfer-Encoding: 7bit\r\n"
        b"\r\n"
        + oversized_raw.encode("ascii")
        + b"\r\n--BOUND--\r\n"
    )
    result = ingest_email(raw)

    assert len(result.attachments) == 1
    assert result.attachments[0].status == AttachmentStatus.SKIPPED
    assert result.attachments[0].sha256 is None

    # Warning should be propagated into EmailData.parsing_warnings
    skip_warnings = [w for w in result.parsing_warnings if "skipped:" in w.lower()]
    assert len(skip_warnings) > 0


# ---------------------------------------------------------------------------
# 16. Caller-Supplied Email ID
# ---------------------------------------------------------------------------

def test_caller_supplied_email_id(normal_plain_text_bytes):
    """Scenario 16: Caller-supplied non-empty email_id is respected."""
    result = ingest_email(normal_plain_text_bytes, email_id="audit-id-2026-99")
    assert result.email_id == "audit-id-2026-99"


# ---------------------------------------------------------------------------
# 17. Generated UUID4 Email ID
# ---------------------------------------------------------------------------

def test_generated_uuid4_email_id(normal_plain_text_bytes):
    """Scenario 17: Generated email ID follows the 'email_<32 hex>' pattern."""
    result = ingest_email(normal_plain_text_bytes)
    assert result.email_id.startswith("email_")
    hex_part = result.email_id[len("email_"):]
    assert len(hex_part) == 32
    int(hex_part, 16)  # Verifies valid hex


# ---------------------------------------------------------------------------
# 18. Duplicate Message-ID Headers Produce Distinct Internal IDs
# ---------------------------------------------------------------------------

def test_duplicate_message_id_produces_distinct_internal_ids(normal_plain_text_bytes):
    """Scenario 18: Multiple ingestions of the same email yield unique email_id values."""
    res1 = ingest_email(normal_plain_text_bytes)
    res2 = ingest_email(normal_plain_text_bytes)

    assert res1.email_id != res2.email_id
    # But original Message-ID is preserved identically
    assert res1.headers.message_id == res2.headers.message_id == "<reminder-12345@example.com>"


# ---------------------------------------------------------------------------
# 19. Whitespace-Only Caller-Supplied ID
# ---------------------------------------------------------------------------

def test_whitespace_only_caller_supplied_id(normal_plain_text_bytes):
    """Scenario 19: Whitespace-only caller-supplied ID raises ValueError."""
    with pytest.raises(ValueError):
        ingest_email(normal_plain_text_bytes, email_id="   ")

    with pytest.raises(ValueError):
        ingest_email(normal_plain_text_bytes, email_id="\t\n")

    with pytest.raises(ValueError):
        ingest_email(normal_plain_text_bytes, source_filename="   ")


# ---------------------------------------------------------------------------
# 20. Complete EmailData Validation
# ---------------------------------------------------------------------------

def test_complete_email_data_validation(normal_plain_text_bytes):
    """Scenario 20: Validated EmailData strictly forbids extra fields."""
    result = ingest_email(normal_plain_text_bytes)

    # Attempting to assign unknown field should fail on strict Pydantic model
    dumped = result.model_dump()
    dumped["confidence"] = 0.99
    with pytest.raises(ValidationError):
        EmailData(**dumped)


# ---------------------------------------------------------------------------
# 21. JSON Serialization & Deserialization Round Trip
# ---------------------------------------------------------------------------

def test_json_serialization_round_trip(multipart_mixed_with_attachments_bytes):
    """Scenario 21: Full model_dump_json() and model_validate_json() round trip."""
    original = ingest_email(multipart_mixed_with_attachments_bytes, source_filename="mixed.eml")
    json_str = original.model_dump_json()

    # Verify JSON parsable
    parsed = json.loads(json_str)
    assert parsed["email_id"] == original.email_id
    assert parsed["source_filename"] == "mixed.eml"

    # Verify model_validate_json produces equivalent model
    restored = EmailData.model_validate_json(json_str)
    assert restored.email_id == original.email_id
    assert restored.source_filename == original.source_filename
    assert len(restored.attachments) == len(original.attachments)
    assert restored.headers.subject == original.headers.subject


# ---------------------------------------------------------------------------
# 22. Extractor Exceptions Are Not Silently Swallowed
# ---------------------------------------------------------------------------

def test_extractor_exceptions_are_not_silently_swallowed(normal_plain_text_bytes, monkeypatch):
    """Scenario 22: Unhandled extractor failures are wrapped in IngestionError with cause preserved."""
    import app.ingestion.email_ingestor as mod

    def failing_extract_headers(msg):
        raise RuntimeError("Header parser internal fault")

    monkeypatch.setattr(mod, "extract_headers", failing_extract_headers)

    with pytest.raises(IngestionError) as exc_info:
        ingest_email(normal_plain_text_bytes)

    assert "Header extraction failed" in str(exc_info.value)
    assert isinstance(exc_info.value.__cause__, RuntimeError)


# ---------------------------------------------------------------------------
# 23. Same Parsed Message Object Passed to All Extractors
# ---------------------------------------------------------------------------

def test_same_parsed_message_object_passed_to_all_extractors(normal_plain_text_bytes, monkeypatch):
    """Scenario 23: Verify exactly one parsed Message is shared across extractors."""
    import app.ingestion.email_ingestor as mod

    orig_headers = mod.extract_headers
    orig_auth = mod.extract_authentication
    orig_body = mod.extract_body
    orig_att = mod.extract_attachments

    seen_messages = []

    def spy_headers(msg):
        seen_messages.append(("headers", id(msg)))
        return orig_headers(msg)

    def spy_auth(msg):
        seen_messages.append(("auth", id(msg)))
        return orig_auth(msg)

    def spy_body(msg):
        seen_messages.append(("body", id(msg)))
        return orig_body(msg)

    def spy_att(msg):
        seen_messages.append(("att", id(msg)))
        return orig_att(msg)

    monkeypatch.setattr(mod, "extract_headers", spy_headers)
    monkeypatch.setattr(mod, "extract_authentication", spy_auth)
    monkeypatch.setattr(mod, "extract_body", spy_body)
    monkeypatch.setattr(mod, "extract_attachments", spy_att)

    ingest_email(normal_plain_text_bytes)

    assert len(seen_messages) == 4
    first_id = seen_messages[0][1]
    for name, msg_id in seen_messages:
        assert msg_id == first_id, f"Extractor '{name}' received a different Message instance!"
