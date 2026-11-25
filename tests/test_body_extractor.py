"""
tests/test_body_extractor.py
----------------------------
Pytest test suite for app/ingestion/body_extractor.py.

Tests cover all 20 required scenarios:
1. Plain-text only email
2. HTML only email
3. Multipart/alternative with both plain-text and HTML
4. Multipart/mixed containing body and an attachment (ensure attachment is excluded)
5. Multipart/related with HTML and inline image (ensure image is excluded)
6. Nested multipart (multipart/mixed containing multipart/alternative + attachment)
7. Email with no body parts
8. Empty body content
9. UTF-8 encoded body with non-ASCII / Unicode characters
10. ISO-8859-1 encoded body
11. Quoted-printable transfer encoding
12. Base64 transfer encoding
13. Unknown or invalid charset fallback handling
14. Malformed HTML handling
15. HTML containing <script> and <style> tags (verify removed from cleaned_text)
16. Text attachment excluded (e.g. text/plain with filename="log.txt" or Content-Disposition: attachment)
17. Preservation of original HTML in html_body
18. Cleaned text whitespace normalization
19. Pydantic BodyContent validation
20. Backward compatibility with EmailData schema
"""

from __future__ import annotations

import base64
import email
import json
import quopri
from datetime import datetime, timezone
from email.message import EmailMessage, Message
from email.mime.application import MIMEApplication
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import pytest
from pydantic import ValidationError

from app.ingestion.body_extractor import extract_body
from app.schemas import (
    AuthenticationMetadata,
    AuthenticationResult,
    AuthMechanism,
    AuthProvenance,
    AuthStatus,
    BodyContent,
    EmailData,
    EmailHeaders,
    VerificationStatus,
)


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def _dummy_authentication() -> AuthenticationMetadata:
    return AuthenticationMetadata(
        spf=AuthenticationResult(
            mechanism=AuthMechanism.SPF,
            status=AuthStatus.PASS,
            provenance=AuthProvenance.AUTHENTICATION_RESULTS_HEADER,
            verification_status=VerificationStatus.UNVERIFIED,
        ),
        dkim=AuthenticationResult(
            mechanism=AuthMechanism.DKIM,
            status=AuthStatus.PASS,
            provenance=AuthProvenance.AUTHENTICATION_RESULTS_HEADER,
            verification_status=VerificationStatus.UNVERIFIED,
        ),
        dmarc=AuthenticationResult(
            mechanism=AuthMechanism.DMARC,
            status=AuthStatus.PASS,
            provenance=AuthProvenance.AUTHENTICATION_RESULTS_HEADER,
            verification_status=VerificationStatus.UNVERIFIED,
        ),
        claims=[],
    )


# ---------------------------------------------------------------------------
# 1. Plain-text only email
# ---------------------------------------------------------------------------

class TestPlainTextOnlyEmail:
    """Scenario 1: Single-part plain-text email."""

    def test_plain_text_extracted(self):
        msg = MIMEText("Hello, this is a plain text email.\nSecond line here.", "plain", "utf-8")
        result = extract_body(msg)

        assert isinstance(result, BodyContent)
        assert result.plain_text_body == "Hello, this is a plain text email.\nSecond line here."
        assert result.html_body is None
        assert result.cleaned_text == "Hello, this is a plain text email.\nSecond line here."
        assert result.parsing_warnings == []

    def test_plain_text_via_message_from_string(self):
        raw = (
            "From: alice@example.com\n"
            "To: bob@example.com\n"
            "Subject: Test Plain\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "Line one of email body.\n"
            "Line two of email body."
        )
        msg = email.message_from_string(raw)
        result = extract_body(msg)

        assert result.plain_text_body == "Line one of email body.\nLine two of email body."
        assert result.html_body is None
        assert result.cleaned_text == "Line one of email body.\nLine two of email body."
        assert result.parsing_warnings == []


# ---------------------------------------------------------------------------
# 2. HTML only email
# ---------------------------------------------------------------------------

class TestHtmlOnlyEmail:
    """Scenario 2: Single-part HTML email."""

    def test_html_extracted(self):
        raw_html = (
            "<html><body>"
            "<h1>Urgent Notice</h1>"
            "<p>Please click <a href='https://example.com/login'>here</a> to verify.</p>"
            "</body></html>"
        )
        msg = MIMEText(raw_html, "html", "utf-8")
        result = extract_body(msg)

        assert isinstance(result, BodyContent)
        assert result.plain_text_body is None
        assert result.html_body == raw_html
        assert "Urgent Notice" in result.cleaned_text
        assert "Please click here to verify." in result.cleaned_text
        assert result.parsing_warnings == []


# ---------------------------------------------------------------------------
# 3. Multipart/alternative with both plain-text and HTML
# ---------------------------------------------------------------------------

class TestMultipartAlternative:
    """Scenario 3: Multipart/alternative with both plain-text and HTML."""

    def test_both_bodies_preserved_plain_precedence_for_cleaned(self):
        msg = MIMEMultipart("alternative")
        plain = "Plain text alternative content."
        html = "<p>HTML <b>alternative</b> content.</p>"

        part1 = MIMEText(plain, "plain", "utf-8")
        part2 = MIMEText(html, "html", "utf-8")
        msg.attach(part1)
        msg.attach(part2)

        result = extract_body(msg)

        assert result.plain_text_body == plain
        assert result.html_body == html
        # Precedence: non-empty plain text is used for cleaned_text
        assert result.cleaned_text == "Plain text alternative content."
        assert result.parsing_warnings == []

    def test_empty_plain_text_falls_back_to_html_for_cleaned(self):
        msg = MIMEMultipart("alternative")
        part1 = MIMEText("   ", "plain", "utf-8")
        part2 = MIMEText("<p>Actual rich content.</p>", "html", "utf-8")
        msg.attach(part1)
        msg.attach(part2)

        result = extract_body(msg)

        assert result.plain_text_body == "   "
        assert result.html_body == "<p>Actual rich content.</p>"
        assert result.cleaned_text == "Actual rich content."


# ---------------------------------------------------------------------------
# 4. Multipart/mixed containing body and an attachment
# ---------------------------------------------------------------------------

class TestMultipartMixedWithAttachment:
    """Scenario 4: Multipart/mixed containing body and attachment."""

    def test_attachment_excluded_from_body(self):
        msg = MIMEMultipart("mixed")
        body_part = MIMEText("This is the legitimate email body text.", "plain", "utf-8")
        msg.attach(body_part)

        pdf_bytes = b"%PDF-1.4 fake invoice content 123456789"
        attachment = MIMEApplication(pdf_bytes, _subtype="pdf")
        attachment.add_header("Content-Disposition", "attachment", filename="invoice_2026.pdf")
        msg.attach(attachment)

        result = extract_body(msg)

        assert result.plain_text_body == "This is the legitimate email body text."
        assert result.html_body is None
        assert result.cleaned_text == "This is the legitimate email body text."
        assert "invoice_2026.pdf" not in result.cleaned_text
        assert "%PDF" not in result.cleaned_text
        assert result.parsing_warnings == []


# ---------------------------------------------------------------------------
# 5. Multipart/related with HTML and inline image
# ---------------------------------------------------------------------------

class TestMultipartRelatedWithInlineImage:
    """Scenario 5: Multipart/related with HTML and inline image."""

    def test_inline_image_excluded_from_body(self):
        msg = MIMEMultipart("related")
        html_content = (
            "<html><body>"
            "<p>Check our company logo below:</p>"
            "<img src='cid:logo@company.com'>"
            "</body></html>"
        )
        html_part = MIMEText(html_content, "html", "utf-8")
        msg.attach(html_part)

        # 1x1 transparent PNG bytes
        png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
        img_part = MIMEImage(png_bytes, _subtype="png")
        img_part.add_header("Content-ID", "<logo@company.com>")
        img_part.add_header("Content-Disposition", "inline", filename="logo.png")
        msg.attach(img_part)

        result = extract_body(msg)

        assert result.plain_text_body is None
        assert result.html_body == html_content
        assert "Check our company logo below:" in result.cleaned_text
        assert "PNG" not in result.cleaned_text
        assert "logo.png" not in result.cleaned_text
        assert result.parsing_warnings == []


# ---------------------------------------------------------------------------
# 6. Nested multipart (multipart/mixed containing multipart/alternative + attachment)
# ---------------------------------------------------------------------------

class TestNestedMultipart:
    """Scenario 6: Nested multipart structure."""

    def test_nested_alternative_and_attachment(self):
        root = MIMEMultipart("mixed")

        # Inner alternative container
        alt_container = MIMEMultipart("alternative")
        plain_part = MIMEText("Plain version of nested email.", "plain", "utf-8")
        html_part = MIMEText("<p>HTML version of <i>nested</i> email.</p>", "html", "utf-8")
        alt_container.attach(plain_part)
        alt_container.attach(html_part)
        root.attach(alt_container)

        # Attachment
        att = MIMEApplication(b"binary payload", _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename="payload.bin")
        root.attach(att)

        result = extract_body(root)

        assert result.plain_text_body == "Plain version of nested email."
        assert result.html_body == "<p>HTML version of <i>nested</i> email.</p>"
        assert result.cleaned_text == "Plain version of nested email."
        assert "payload.bin" not in result.cleaned_text
        assert "binary payload" not in result.cleaned_text


# ---------------------------------------------------------------------------
# 7. Email with no body parts
# ---------------------------------------------------------------------------

class TestNoBodyParts:
    """Scenario 7: Email with no body parts."""

    def test_headers_only_message(self):
        msg = Message()
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg["Subject"] = "Headers Only"

        result = extract_body(msg)

        assert result.plain_text_body is None
        assert result.html_body is None
        assert result.cleaned_text is None
        assert result.parsing_warnings == []

    def test_multipart_with_only_attachment(self):
        msg = MIMEMultipart("mixed")
        att = MIMEApplication(b"file content", _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename="only_file.dat")
        msg.attach(att)

        result = extract_body(msg)

        assert result.plain_text_body is None
        assert result.html_body is None
        assert result.cleaned_text is None
        assert result.parsing_warnings == []


# ---------------------------------------------------------------------------
# 8. Empty body content
# ---------------------------------------------------------------------------

class TestEmptyBodyContent:
    """Scenario 8: Empty body content."""

    def test_empty_string_plain_text(self):
        msg = MIMEText("", "plain", "utf-8")
        result = extract_body(msg)

        assert result.plain_text_body == ""
        assert result.html_body is None
        assert result.cleaned_text == ""
        assert result.parsing_warnings == []

    def test_empty_html_body(self):
        msg = MIMEText("<html><body></body></html>", "html", "utf-8")
        result = extract_body(msg)

        assert result.plain_text_body is None
        assert result.html_body == "<html><body></body></html>"
        assert result.cleaned_text == ""
        assert result.parsing_warnings == []


# ---------------------------------------------------------------------------
# 9. UTF-8 encoded body with non-ASCII / Unicode characters
# ---------------------------------------------------------------------------

class TestUtf8EncodedBody:
    """Scenario 9: UTF-8 encoded body with diverse Unicode characters."""

    def test_unicode_plain_text(self):
        content = "Bonjour le monde! Привет мир! こんにちは世界! 🚀🔒 Verify: £100 / €50"
        msg = MIMEText(content, "plain", "utf-8")
        result = extract_body(msg)

        assert result.plain_text_body == content
        assert result.cleaned_text == content
        assert "🚀" in result.cleaned_text
        assert "Привет" in result.cleaned_text
        assert "こんにちは" in result.cleaned_text
        assert result.parsing_warnings == []

    def test_unicode_html_body(self):
        content = "<p>Accents: résumé, naïve, façade. Japanese: こんにちは.</p>"
        msg = MIMEText(content, "html", "utf-8")
        result = extract_body(msg)

        assert result.html_body == content
        assert "Accents: résumé, naïve, façade. Japanese: こんにちは." in result.cleaned_text


# ---------------------------------------------------------------------------
# 10. ISO-8859-1 encoded body
# ---------------------------------------------------------------------------

class TestIso88591EncodedBody:
    """Scenario 10: ISO-8859-1 encoded email body."""

    def test_iso_8859_1_decoding(self):
        # "Café et thé à l'hôtel" in ISO-8859-1 bytes
        text = "Café et thé à l'hôtel"
        msg = MIMEText(text, "plain", "iso-8859-1")
        result = extract_body(msg)

        assert result.plain_text_body == text
        assert result.cleaned_text == text
        assert result.parsing_warnings == []


# ---------------------------------------------------------------------------
# 11. Quoted-printable transfer encoding
# ---------------------------------------------------------------------------

class TestQuotedPrintableEncoding:
    """Scenario 11: Quoted-printable transfer encoding."""

    def test_quoted_printable_decoded(self):
        raw = (
            "From: test@example.com\n"
            "To: dest@example.com\n"
            "Subject: QP Test\n"
            "MIME-Version: 1.0\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "Content-Transfer-Encoding: quoted-printable\n"
            "\n"
            "This is a quoted-printable message with soft=\n"
            " line breaks and special characters like =3D and =C3=A9."
        )
        msg = email.message_from_string(raw)
        result = extract_body(msg)

        assert result.plain_text_body is not None
        assert "soft line breaks" in result.plain_text_body
        assert "=" in result.plain_text_body
        assert "é" in result.plain_text_body
        assert result.parsing_warnings == []


# ---------------------------------------------------------------------------
# 12. Base64 transfer encoding
# ---------------------------------------------------------------------------

class TestBase64TransferEncoding:
    """Scenario 12: Base64 transfer encoding."""

    def test_base64_plain_text(self):
        original_text = "Secure password reset request for your banking account."
        b64_payload = base64.b64encode(original_text.encode("utf-8")).decode("ascii")

        raw = (
            "From: security@bank.com\n"
            "To: victim@example.com\n"
            "Subject: Security Alert\n"
            "MIME-Version: 1.0\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "Content-Transfer-Encoding: base64\n"
            "\n"
            f"{b64_payload}"
        )
        msg = email.message_from_string(raw)
        result = extract_body(msg)

        assert result.plain_text_body == original_text
        assert result.cleaned_text == original_text
        assert result.parsing_warnings == []


# ---------------------------------------------------------------------------
# 13. Unknown or invalid charset fallback handling
# ---------------------------------------------------------------------------

class TestUnknownCharsetFallback:
    """Scenario 13: Unknown or invalid charset fallback handling."""

    def test_unknown_charset_does_not_crash_and_warns(self):
        raw = (
            "From: test@example.com\n"
            "To: dest@example.com\n"
            "Subject: Unknown Charset\n"
            "Content-Type: text/plain; charset=unknown-custom-encoding-xyz\n"
            "\n"
            "This is plain text with an unknown declared charset."
        )
        msg = email.message_from_string(raw)
        result = extract_body(msg)

        assert result.plain_text_body is not None
        assert "unknown declared charset" in result.plain_text_body
        assert any("Unknown or unsupported character encoding" in w for w in result.parsing_warnings)

    def test_malformed_bytes_fallback_with_replacement(self):
        # Raw bytes that violate UTF-8 specification
        msg = Message()
        msg["Content-Type"] = "text/plain; charset=utf-8"
        msg.set_payload(b"Invalid \xff\xfe UTF-8 bytes")

        result = extract_body(msg)

        assert result.plain_text_body is not None
        assert "Invalid" in result.plain_text_body
        assert any("Failed to decode payload" in w for w in result.parsing_warnings)


# ---------------------------------------------------------------------------
# 14. Malformed HTML handling
# ---------------------------------------------------------------------------

class TestMalformedHtmlHandling:
    """Scenario 14: Malformed HTML handling."""

    def test_unclosed_tags_and_broken_markup(self):
        broken_html = (
            "<div><p>Paragraph 1 without closing tag"
            "<p>Paragraph 2 with <b>unclosed bold"
            "<a href='http://phish.com'>Phishing link"
            "<table border=1><tr><td>Cell 1<td>Cell 2</table>"
        )
        msg = MIMEText(broken_html, "html", "utf-8")
        result = extract_body(msg)

        assert result.html_body == broken_html
        assert "Paragraph 1 without closing tag" in result.cleaned_text
        assert "Paragraph 2 with unclosed bold" in result.cleaned_text
        assert "Phishing link" in result.cleaned_text
        assert "Cell 1" in result.cleaned_text


# ---------------------------------------------------------------------------
# 15. HTML containing <script> and <style> tags
# ---------------------------------------------------------------------------

class TestScriptAndStyleRemoval:
    """Scenario 15: HTML containing <script> and <style> tags."""

    def test_script_and_style_tags_removed_from_cleaned_text(self):
        html_markup = (
            "<html><head>"
            "<style>body { font-size: 14px; color: red; }</style>"
            "<script type='text/javascript'>alert('XSS execution');</script>"
            "</head><body>"
            "<noscript>Please enable JavaScript to view this site.</noscript>"
            "<p>Visible content for the recipient.</p>"
            "<script>window.location='http://evil.com';</script>"
            "</body></html>"
        )
        msg = MIMEText(html_markup, "html", "utf-8")
        result = extract_body(msg)

        # Original preserved in html_body
        assert "<style>" in result.html_body
        assert "<script" in result.html_body

        # Removed from cleaned_text
        assert "alert('XSS execution')" not in result.cleaned_text
        assert "font-size: 14px" not in result.cleaned_text
        assert "window.location" not in result.cleaned_text
        assert "Please enable JavaScript" not in result.cleaned_text
        assert result.cleaned_text == "Visible content for the recipient."


# ---------------------------------------------------------------------------
# 16. Text attachment excluded
# ---------------------------------------------------------------------------

class TestTextAttachmentExcluded:
    """Scenario 16: Text attachments excluded from body."""

    def test_text_attachment_with_filename_excluded(self):
        msg = MIMEMultipart("mixed")
        body_part = MIMEText("Legitimate body text.", "plain", "utf-8")
        msg.attach(body_part)

        # Text attachment with filename parameter
        att_part = MIMEText("ERROR 2026-11-11: Server failure stacktrace...", "plain", "utf-8")
        att_part.add_header("Content-Disposition", "attachment", filename="server.log")
        msg.attach(att_part)

        result = extract_body(msg)

        assert result.plain_text_body == "Legitimate body text."
        assert "ERROR 2026-11-11" not in result.plain_text_body
        assert "server.log" not in result.cleaned_text

    def test_text_with_name_in_content_type_excluded(self):
        msg = MIMEMultipart("mixed")
        body_part = MIMEText("Body message.", "plain", "utf-8")
        msg.attach(body_part)

        att_part = MIMEText("Secret data in attachment", "plain", "utf-8")
        att_part.set_param("name", "passwords.txt", header="Content-Type")
        msg.attach(att_part)

        result = extract_body(msg)

        assert result.plain_text_body == "Body message."
        assert "Secret data in attachment" not in result.plain_text_body


# ---------------------------------------------------------------------------
# 17. Preservation of original HTML in html_body
# ---------------------------------------------------------------------------

class TestOriginalHtmlPreservation:
    """Scenario 17: Preservation of original HTML in html_body."""

    def test_html_body_is_unmodified_verbatim(self):
        raw_html = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<style>.urgent { color: red; }</style>"
            "</head><body><p class='urgent'>Action required <a href='https://bank.com'>now</a>.</p>"
            "<!-- comment preserved --></body></html>"
        )
        msg = MIMEText(raw_html, "html", "utf-8")
        result = extract_body(msg)

        assert result.html_body == raw_html
        assert "<!-- comment preserved -->" in result.html_body
        assert "class='urgent'" in result.html_body


# ---------------------------------------------------------------------------
# 18. Cleaned text whitespace normalization
# ---------------------------------------------------------------------------

class TestWhitespaceNormalization:
    """Scenario 18: Cleaned text whitespace normalization."""

    def test_whitespace_normalization_in_plain_text(self):
        raw_text = (
            "   Paragraph 1     with   many    internal   spaces.   \n"
            "\n"
            "\n"
            "\n"
            "   Paragraph 2   after many blank lines.   \n"
            "\n"
            "   Paragraph 3.   "
        )
        msg = MIMEText(raw_text, "plain", "utf-8")
        result = extract_body(msg)

        expected = (
            "Paragraph 1 with many internal spaces.\n"
            "\n"
            "Paragraph 2 after many blank lines.\n"
            "\n"
            "Paragraph 3."
        )
        assert result.cleaned_text == expected

    def test_html_paragraph_and_break_preservation(self):
        html = (
            "<p>First paragraph.</p>"
            "<p>Second paragraph with<br>a line break.</p>"
        )
        msg = MIMEText(html, "html", "utf-8")
        result = extract_body(msg)

        expected = (
            "First paragraph.\n"
            "\n"
            "Second paragraph with\n"
            "a line break."
        )
        assert result.cleaned_text == expected


# ---------------------------------------------------------------------------
# 19. Pydantic BodyContent validation
# ---------------------------------------------------------------------------

class TestBodyContentValidation:
    """Scenario 19: Pydantic BodyContent schema validation."""

    def test_valid_body_content_model(self):
        bc = BodyContent(
            plain_text_body="Hello",
            html_body="<p>Hello</p>",
            cleaned_text="Hello",
            parsing_warnings=["test warning"],
        )
        assert bc.plain_text_body == "Hello"
        assert bc.html_body == "<p>Hello</p>"
        assert bc.cleaned_text == "Hello"
        assert bc.parsing_warnings == ["test warning"]

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            BodyContent(
                plain_text_body="Hello",
                unexpected_field="disallowed",  # type: ignore[call-arg]
            )

    def test_json_round_trip(self):
        bc = BodyContent(
            plain_text_body="Plain",
            html_body="<b>HTML</b>",
            cleaned_text="HTML",
            parsing_warnings=[],
        )
        dumped_json = bc.model_dump_json()
        restored = BodyContent.model_validate_json(dumped_json)
        assert restored == bc


# ---------------------------------------------------------------------------
# 20. Backward compatibility with EmailData schema
# ---------------------------------------------------------------------------

class TestEmailDataBackwardCompatibility:
    """Scenario 20: Backward compatibility with EmailData schema."""

    def test_extracted_body_integrates_into_email_data(self):
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText("Plain text message body.", "plain", "utf-8"))
        msg.attach(MIMEText("<p>HTML message body.</p>", "html", "utf-8"))

        body_content = extract_body(msg)

        email_data = EmailData(
            email_id="msg-2026-task4-001",
            source_filename="sample_email.eml",
            headers=EmailHeaders(
                from_address="sender@example.com",
                to=["recipient@example.com"],
                subject="Task 4 Verification",
            ),
            authentication=_dummy_authentication(),
            plain_text_body=body_content.plain_text_body,
            html_body=body_content.html_body,
            cleaned_text=body_content.cleaned_text,
            parsing_warnings=body_content.parsing_warnings,
            ingestion_timestamp=datetime.now(timezone.utc),
        )

        assert email_data.plain_text_body == "Plain text message body."
        assert email_data.html_body == "<p>HTML message body.</p>"
        assert email_data.cleaned_text == "Plain text message body."
        assert email_data.parsing_warnings == []

        # Round trip serialization
        json_data = email_data.model_dump_json()
        loaded = EmailData.model_validate_json(json_data)
        assert loaded.email_id == email_data.email_id
        assert loaded.cleaned_text == email_data.cleaned_text
