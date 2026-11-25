"""
test_attachment_extractor.py
----------------------------
Comprehensive pytest suite for the Email Attachment Extraction Module (Task 6).

Scenarios covered:
 1. Ordinary PDF attachment.
 2. ZIP attachment.
 3. Executable attachment.
 4. Image attachment.
 5. Inline image.
 6. Text attachment.
 7. Attachment without filename.
 8. Filename without Content-Disposition.
 9. Nested multipart attachments.
10. Multiple attachments.
11. Duplicate filenames.
12. Path traversal filename (e.g. ../../malicious.exe).
13. Windows-style path filename (e.g. C:\\Users\\Public\\malicious.exe).
14. Unicode filename (non-ASCII characters).
15. Encoded filename (RFC 2047 and RFC 2231).
16. Empty filename (filename="").
17. Missing filename (no filename declared).
18. Correct size calculation (matches byte count).
19. Correct SHA-256 calculation (matches independent hashlib computation).
20. Malformed transfer encoding (malformed base64).
21. Empty attachment (0-byte payload).
22. Attachment larger than 25 MB (skipped, not hashed, reason preserved).
23. More than 50 attachments (safe limit, remaining attachments skipped, none dropped).
24. Malformed MIME structures (resilience, no unhandled exceptions).
25. Non-attachment body text must NOT be classified as an attachment.
26. Misleading / double extensions (e.g. invoice.pdf.exe).
27. Extremely long filename (>255 characters truncated safely).
28. Filename with null bytes and control characters stripped.
29. Standalone single-part attachment message (not multipart).
30. Standalone single-part plain text email (no attachments).
31. Pydantic validation (AttachmentMetadata extra='forbid', sha256 validation).
32. Integration into EmailData schema and JSON round-trip serialization.
33. Convenience property 'skipped' on AttachmentMetadata.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from email.message import Message
from email.mime.application import MIMEApplication
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import email

import quopri

import pytest
from pydantic import ValidationError

from app.ingestion.attachment_extractor import (
    DEFAULT_QP_CHUNK_SIZE,
    MAX_ATTACHMENT_COUNT,
    MAX_ATTACHMENT_SIZE_BYTES,
    _bounded_decode_quoted_printable,
    extract_attachments,
)
from app.schemas.email_schema import (
    AttachmentDisposition,
    AttachmentMetadata,
    AttachmentStatus,
    AuthenticationMetadata,
    AuthenticationResult,
    AuthMechanism,
    AuthStatus,
    EmailData,
    EmailHeaders,
)


# ---------------------------------------------------------------------------
# 1. Ordinary PDF attachment
# ---------------------------------------------------------------------------

class TestOrdinaryPdfAttachment:
    """Scenario 1: Standard PDF attachment with Content-Disposition."""

    def test_pdf_attachment_extracted(self):
        msg = MIMEMultipart("mixed")
        body = MIMEText("Please find the attached invoice.", "plain", "utf-8")
        msg.attach(body)

        pdf_bytes = b"%PDF-1.5 test invoice content for audit verification"
        att = MIMEApplication(pdf_bytes, _subtype="pdf")
        att.add_header("Content-Disposition", "attachment", filename="invoice_2026.pdf")
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        assert meta.filename == "invoice_2026.pdf"
        assert meta.raw_filename == "invoice_2026.pdf"
        assert meta.extension == "pdf"
        assert meta.content_type == "application/pdf"
        assert meta.disposition == AttachmentDisposition.ATTACHMENT
        assert meta.status == AttachmentStatus.PROCESSED
        assert meta.size_bytes == len(pdf_bytes)
        assert meta.sha256 == hashlib.sha256(pdf_bytes).hexdigest()
        assert meta.skipped is False


# ---------------------------------------------------------------------------
# 2. ZIP attachment
# ---------------------------------------------------------------------------

class TestZipAttachment:
    """Scenario 2: ZIP archive attachment."""

    def test_zip_attachment_extracted(self):
        msg = MIMEMultipart("mixed")
        zip_bytes = b"PK\x03\x04\x14\x00fake zip archive payload data"
        att = MIMEApplication(zip_bytes, _subtype="zip")
        att.add_header("Content-Disposition", "attachment", filename="archive.zip")
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        assert meta.filename == "archive.zip"
        assert meta.extension == "zip"
        assert meta.content_type == "application/zip"
        assert meta.disposition == AttachmentDisposition.ATTACHMENT
        assert meta.status == AttachmentStatus.PROCESSED
        assert meta.size_bytes == len(zip_bytes)
        assert meta.sha256 == hashlib.sha256(zip_bytes).hexdigest()


# ---------------------------------------------------------------------------
# 3. Executable attachment
# ---------------------------------------------------------------------------

class TestExecutableAttachment:
    """Scenario 3: Executable attachment (extracted safely without execution)."""

    def test_executable_attachment_extracted_safely(self):
        msg = MIMEMultipart("mixed")
        exe_bytes = b"MZ\x90\x00\x03\x00\x00\x00Fake Windows Executable binary content"
        att = MIMEApplication(exe_bytes, _subtype="x-dosexec")
        att.add_header("Content-Disposition", "attachment", filename="installer.exe")
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        assert meta.filename == "installer.exe"
        assert meta.extension == "exe"
        assert meta.content_type == "application/x-dosexec"
        assert meta.disposition == AttachmentDisposition.ATTACHMENT
        assert meta.status == AttachmentStatus.PROCESSED
        assert meta.size_bytes == len(exe_bytes)
        assert meta.sha256 == hashlib.sha256(exe_bytes).hexdigest()


# ---------------------------------------------------------------------------
# 4. Image attachment
# ---------------------------------------------------------------------------

class TestImageAttachment:
    """Scenario 4: Regular image attachment."""

    def test_image_attachment_extracted(self):
        msg = MIMEMultipart("mixed")
        img_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRfake png photo bytes"
        att = MIMEImage(img_bytes, _subtype="png")
        att.add_header("Content-Disposition", "attachment", filename="photo.png")
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        assert meta.filename == "photo.png"
        assert meta.extension == "png"
        assert meta.content_type == "image/png"
        assert meta.disposition == AttachmentDisposition.ATTACHMENT
        assert meta.status == AttachmentStatus.PROCESSED
        assert meta.size_bytes == len(img_bytes)
        assert meta.sha256 == hashlib.sha256(img_bytes).hexdigest()


# ---------------------------------------------------------------------------
# 5. Inline image
# ---------------------------------------------------------------------------

class TestInlineImage:
    """Scenario 5: Inline image with Content-ID and inline disposition."""

    def test_inline_image_extracted(self):
        msg = MIMEMultipart("related")
        html = MIMEText('<p>Company logo: <img src="cid:logo123@domain"></p>', "html", "utf-8")
        msg.attach(html)

        img_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIFfake jpeg banner bytes"
        att = MIMEImage(img_bytes, _subtype="jpeg")
        att.add_header("Content-Disposition", "inline", filename="banner.jpg")
        att.add_header("Content-ID", "<logo123@domain>")
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        assert meta.filename == "banner.jpg"
        assert meta.extension == "jpg"
        assert meta.content_type == "image/jpeg"
        assert meta.disposition == AttachmentDisposition.INLINE
        assert meta.content_id == "logo123@domain"
        assert meta.status == AttachmentStatus.PROCESSED
        assert meta.size_bytes == len(img_bytes)
        assert meta.sha256 == hashlib.sha256(img_bytes).hexdigest()


# ---------------------------------------------------------------------------
# 6. Text attachment
# ---------------------------------------------------------------------------

class TestTextAttachment:
    """Scenario 6: Text file attachment (e.g. server log)."""

    def test_text_attachment_with_disposition(self):
        msg = MIMEMultipart("mixed")
        body = MIMEText("See error log attached.", "plain", "utf-8")
        msg.attach(body)

        log_content = "FATAL: 2026-11-11 Out of memory error in worker thread."
        att = MIMEText(log_content, "plain", "utf-8")
        att.add_header("Content-Disposition", "attachment", filename="crash.log")
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        assert meta.filename == "crash.log"
        assert meta.extension == "log"
        assert meta.content_type == "text/plain"
        assert meta.disposition == AttachmentDisposition.ATTACHMENT
        assert meta.status == AttachmentStatus.PROCESSED
        assert meta.size_bytes == len(log_content.encode("utf-8"))
        assert meta.sha256 == hashlib.sha256(log_content.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 7. Attachment without filename
# ---------------------------------------------------------------------------

class TestAttachmentWithoutFilename:
    """Scenario 7: Attachment lacking any filename parameter."""

    def test_binary_part_without_filename(self):
        msg = MIMEMultipart("mixed")
        pdf_bytes = b"%PDF-1.4 unnamed pdf payload"
        att = MIMEApplication(pdf_bytes, _subtype="pdf")
        att.add_header("Content-Disposition", "attachment")  # no filename param
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        assert meta.filename is None
        assert meta.raw_filename is None
        assert meta.extension is None
        assert meta.content_type == "application/pdf"
        assert meta.disposition == AttachmentDisposition.ATTACHMENT
        assert meta.status == AttachmentStatus.PROCESSED
        assert meta.size_bytes == len(pdf_bytes)
        assert meta.sha256 == hashlib.sha256(pdf_bytes).hexdigest()

    def test_unnamed_non_text_part_without_content_disposition(self):
        msg = MIMEMultipart("mixed")
        raw_bytes = b"\x00\x01\x02\x03\x04raw binary stream"
        att = MIMEApplication(raw_bytes, _subtype="octet-stream")
        # No Content-Disposition header at all
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        assert meta.filename is None
        assert meta.extension is None
        assert meta.content_type == "application/octet-stream"
        assert meta.disposition == AttachmentDisposition.UNKNOWN
        assert meta.status == AttachmentStatus.PROCESSED
        assert meta.size_bytes == len(raw_bytes)


# ---------------------------------------------------------------------------
# 8. Filename without Content-Disposition
# ---------------------------------------------------------------------------

class TestFilenameWithoutContentDisposition:
    """Scenario 8: Filename declared in Content-Type name parameter, no Content-Disposition."""

    def test_filename_in_content_type(self):
        msg = MIMEMultipart("mixed")
        data = b"secret,values,in,csv\n1,2,3,4"
        att = MIMEApplication(data, _subtype="csv")
        # Set name parameter on Content-Type, omit Content-Disposition
        att.set_param("name", "financial_records.csv")
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        assert meta.filename == "financial_records.csv"
        assert meta.extension == "csv"
        assert meta.content_type == "application/csv"
        assert meta.disposition == AttachmentDisposition.UNKNOWN
        assert meta.status == AttachmentStatus.PROCESSED
        assert meta.size_bytes == len(data)
        assert meta.sha256 == hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# 9. Nested multipart attachments
# ---------------------------------------------------------------------------

class TestNestedMultipartAttachments:
    """Scenario 9: Arbitrarily nested multipart hierarchies."""

    def test_nested_multipart_mixed_related_alternative(self):
        root = MIMEMultipart("mixed")

        # Nested related
        related = MIMEMultipart("related")
        alt = MIMEMultipart("alternative")
        alt.attach(MIMEText("Plain text body", "plain", "utf-8"))
        alt.attach(MIMEText("<p>HTML body</p>", "html", "utf-8"))
        related.attach(alt)

        # Inline image inside related
        inline_img = MIMEImage(b"png data", _subtype="png")
        inline_img.add_header("Content-Disposition", "inline", filename="logo.png")
        inline_img.add_header("Content-ID", "<logo@corp>")
        related.attach(inline_img)
        root.attach(related)

        # PDF attachment at root mixed level
        pdf = MIMEApplication(b"pdf data", _subtype="pdf")
        pdf.add_header("Content-Disposition", "attachment", filename="doc.pdf")
        root.attach(pdf)

        results = extract_attachments(root)

        assert len(results) == 2
        # Inline image
        assert results[0].filename == "logo.png"
        assert results[0].disposition == AttachmentDisposition.INLINE
        assert results[0].content_id == "logo@corp"
        # PDF attachment
        assert results[1].filename == "doc.pdf"
        assert results[1].disposition == AttachmentDisposition.ATTACHMENT


# ---------------------------------------------------------------------------
# 10. Multiple attachments
# ---------------------------------------------------------------------------

class TestMultipleAttachments:
    """Scenario 10: Multiple distinct attachments in a single email."""

    def test_five_attachments_extracted_in_order(self):
        msg = MIMEMultipart("mixed")
        msg.attach(MIMEText("Email with five attachments", "plain", "utf-8"))

        expected_filenames = ["file1.pdf", "file2.docx", "file3.zip", "file4.png", "file5.xlsx"]
        for fn in expected_filenames:
            part = MIMEApplication(f"content of {fn}".encode("utf-8"), _subtype="octet-stream")
            part.add_header("Content-Disposition", "attachment", filename=fn)
            msg.attach(part)

        results = extract_attachments(msg)

        assert len(results) == 5
        assert [r.filename for r in results] == expected_filenames
        for r in results:
            assert r.status == AttachmentStatus.PROCESSED
            assert r.sha256 is not None


# ---------------------------------------------------------------------------
# 11. Duplicate filenames
# ---------------------------------------------------------------------------

class TestDuplicateFilenames:
    """Scenario 11: Duplicate filenames must not overwrite or discard records."""

    def test_duplicate_filenames_both_retained(self):
        msg = MIMEMultipart("mixed")
        data1 = b"First invoice version"
        data2 = b"Second revised invoice version"

        att1 = MIMEApplication(data1, _subtype="pdf")
        att1.add_header("Content-Disposition", "attachment", filename="invoice.pdf")
        msg.attach(att1)

        att2 = MIMEApplication(data2, _subtype="pdf")
        att2.add_header("Content-Disposition", "attachment", filename="invoice.pdf")
        msg.attach(att2)

        results = extract_attachments(msg)

        assert len(results) == 2
        assert results[0].filename == "invoice.pdf"
        assert results[1].filename == "invoice.pdf"
        assert results[0].size_bytes == len(data1)
        assert results[1].size_bytes == len(data2)
        assert results[0].sha256 != results[1].sha256


# ---------------------------------------------------------------------------
# 12. Path traversal filename
# ---------------------------------------------------------------------------

class TestPathTraversalFilename:
    """Scenario 12: Path traversal filename (../../malicious.exe)."""

    def test_path_traversal_sanitized_and_evidence_preserved(self):
        msg = MIMEMultipart("mixed")
        att = MIMEApplication(b"payload", _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename="../../etc/passwd.exe")
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        # Display filename sanitized
        assert meta.filename == "passwd.exe"
        assert meta.extension == "exe"
        assert "/" not in meta.filename
        assert ".." not in meta.filename
        # Original evidence preserved
        assert meta.raw_filename == "../../etc/passwd.exe"

    def test_deep_path_traversal(self):
        msg = MIMEMultipart("mixed")
        att = MIMEApplication(b"payload", _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename="../../../../trojan.bin")
        msg.attach(att)

        results = extract_attachments(msg)
        assert results[0].filename == "trojan.bin"
        assert results[0].raw_filename == "../../../../trojan.bin"


# ---------------------------------------------------------------------------
# 13. Windows-style path filename
# ---------------------------------------------------------------------------

class TestWindowsStylePathFilename:
    """Scenario 13: Windows absolute and backslash paths."""

    def test_windows_absolute_path_sanitized(self):
        msg = MIMEMultipart("mixed")
        att = MIMEApplication(b"payload", _subtype="octet-stream")
        att.add_header(
            "Content-Disposition",
            "attachment",
            filename=r"C:\Users\Public\Downloads\malicious.exe",
        )
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        assert meta.filename == "malicious.exe"
        assert meta.extension == "exe"
        assert "\\" not in meta.filename
        assert ":" not in meta.filename
        assert meta.raw_filename == r"C:\Users\Public\Downloads\malicious.exe"

    def test_windows_traversal_path(self):
        msg = MIMEMultipart("mixed")
        att = MIMEApplication(b"payload", _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename=r"..\..\malware.bat")
        msg.attach(att)

        results = extract_attachments(msg)
        assert results[0].filename == "malware.bat"
        assert results[0].extension == "bat"


# ---------------------------------------------------------------------------
# 14. Unicode filename
# ---------------------------------------------------------------------------

class TestUnicodeFilename:
    """Scenario 14: Unicode filename preservation."""

    def test_unicode_cyrillic_and_accented_filenames(self):
        msg = MIMEMultipart("mixed")

        # Cyrillic
        att1 = MIMEApplication(b"pdf1", _subtype="pdf")
        att1.add_header("Content-Disposition", "attachment", filename="документ_2026.pdf")
        msg.attach(att1)

        # Accented French
        att2 = MIMEApplication(b"pdf2", _subtype="pdf")
        att2.add_header("Content-Disposition", "attachment", filename="résumé_officiel.pdf")
        msg.attach(att2)

        results = extract_attachments(msg)

        assert len(results) == 2
        assert results[0].filename == "документ_2026.pdf"
        assert results[0].extension == "pdf"
        assert results[1].filename == "résumé_officiel.pdf"
        assert results[1].extension == "pdf"


# ---------------------------------------------------------------------------
# 15. Encoded filename
# ---------------------------------------------------------------------------

class TestEncodedFilename:
    """Scenario 15: RFC 2047 and RFC 2231 encoded filenames."""

    def test_rfc2047_base64_encoded_filename(self):
        # =?UTF-8?B?aW52b2ljZS5wZGY=?= -> invoice.pdf
        raw_msg = (
            "From: sender@example.com\n"
            "To: recipient@example.com\n"
            "Subject: Test\n"
            "MIME-Version: 1.0\n"
            'Content-Type: multipart/mixed; boundary="BOUNDARY"\n\n'
            "--BOUNDARY\n"
            'Content-Type: application/pdf\n'
            'Content-Disposition: attachment; filename="=?UTF-8?B?aW52b2ljZS5wZGY=?="\n'
            "Content-Transfer-Encoding: base64\n\n"
            "cGRmIGRhdGE=\n"
            "--BOUNDARY--\n"
        )
        parsed = email.message_from_string(raw_msg)
        results = extract_attachments(parsed)

        assert len(results) == 1
        assert results[0].filename == "invoice.pdf"
        assert results[0].extension == "pdf"

    def test_rfc2231_percent_encoded_filename(self):
        raw_msg = (
            "From: sender@example.com\n"
            "To: recipient@example.com\n"
            "Subject: Test\n"
            "MIME-Version: 1.0\n"
            'Content-Type: multipart/mixed; boundary="BOUNDARY"\n\n'
            "--BOUNDARY\n"
            "Content-Type: application/pdf\n"
            "Content-Disposition: attachment; filename*=utf-8''annual%20report.pdf\n\n"
            "pdf bytes\n"
            "--BOUNDARY--\n"
        )
        parsed = email.message_from_string(raw_msg)
        results = extract_attachments(parsed)

        assert len(results) == 1
        assert results[0].filename == "annual report.pdf"
        assert results[0].extension == "pdf"


# ---------------------------------------------------------------------------
# 16. Empty filename
# ---------------------------------------------------------------------------

class TestEmptyFilename:
    """Scenario 16: Empty filename string (filename="")."""

    def test_empty_string_filename(self):
        msg = MIMEMultipart("mixed")
        att = MIMEApplication(b"content", _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename="")
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        assert meta.filename is None
        assert meta.extension is None
        assert meta.raw_filename == ""
        assert meta.status == AttachmentStatus.PROCESSED


# ---------------------------------------------------------------------------
# 17. Missing filename
# ---------------------------------------------------------------------------

class TestMissingFilename:
    """Scenario 17: Missing filename parameter on attachment."""

    def test_missing_filename(self):
        msg = MIMEMultipart("mixed")
        att = MIMEApplication(b"content", _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment")
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        assert meta.filename is None
        assert meta.raw_filename is None
        assert meta.extension is None


# ---------------------------------------------------------------------------
# 18. Correct size calculation
# ---------------------------------------------------------------------------

class TestCorrectSizeCalculation:
    """Scenario 18: Exact byte size calculation matching raw attachment length."""

    def test_exact_byte_sizes(self):
        msg = MIMEMultipart("mixed")

        # 1 byte
        att1 = MIMEApplication(b"X", _subtype="octet-stream")
        att1.add_header("Content-Disposition", "attachment", filename="1byte.bin")
        msg.attach(att1)

        # 4096 bytes
        data_4k = b"A" * 4096
        att2 = MIMEApplication(data_4k, _subtype="octet-stream")
        att2.add_header("Content-Disposition", "attachment", filename="4k.bin")
        msg.attach(att2)

        results = extract_attachments(msg)

        assert len(results) == 2
        assert results[0].size_bytes == 1
        assert results[1].size_bytes == 4096


# ---------------------------------------------------------------------------
# 19. Correct SHA-256 calculation
# ---------------------------------------------------------------------------

class TestCorrectSha256Calculation:
    """Scenario 19: SHA-256 hash matches independent hashlib computation."""

    def test_sha256_computation_exact_match(self):
        msg = MIMEMultipart("mixed")
        test_payload = b"Specific known test vector for cryptographic hashing verification 2026."
        expected_hash = hashlib.sha256(test_payload).hexdigest()

        att = MIMEApplication(test_payload, _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename="hash_test.dat")
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        assert results[0].sha256 == expected_hash
        assert len(results[0].sha256) == 64


# ---------------------------------------------------------------------------
# 20. Malformed base64
# ---------------------------------------------------------------------------

class TestMalformedBase64:
    """Scenario 20: Malformed transfer encoding does not crash the parser."""

    def test_malformed_base64_payload_handled_safely(self):
        raw_msg = (
            "From: sender@example.com\n"
            "To: recipient@example.com\n"
            "Subject: Malformed base64\n"
            "MIME-Version: 1.0\n"
            'Content-Type: multipart/mixed; boundary="B"\n\n'
            "--B\n"
            "Content-Type: application/octet-stream\n"
            'Content-Disposition: attachment; filename="corrupt.bin"\n'
            "Content-Transfer-Encoding: base64\n\n"
            "===INVALID_BASE64_BYTES!!!###\n"
            "--B--\n"
        )
        parsed = email.message_from_string(raw_msg)
        results = extract_attachments(parsed)

        # Must not crash, must return the attachment record
        assert len(results) == 1
        assert results[0].filename == "corrupt.bin"
        assert results[0].status in (AttachmentStatus.PROCESSED, AttachmentStatus.ERROR)


# ---------------------------------------------------------------------------
# 21. Empty attachment
# ---------------------------------------------------------------------------

class TestEmptyAttachment:
    """Scenario 21: Empty attachment (0 bytes payload)."""

    def test_zero_byte_attachment(self):
        msg = MIMEMultipart("mixed")
        att = MIMEApplication(b"", _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename="empty.txt")
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        assert meta.filename == "empty.txt"
        assert meta.size_bytes == 0
        expected_empty_hash = hashlib.sha256(b"").hexdigest()
        assert meta.sha256 == expected_empty_hash
        assert meta.status == AttachmentStatus.PROCESSED


# ---------------------------------------------------------------------------
# 22. Attachment larger than 25 MB
# ---------------------------------------------------------------------------

class TestAttachmentLargerThan25MB:
    """Scenario 22: Attachment exceeding 25 MB size limit."""

    def test_attachment_over_25mb_skipped_and_not_hashed(self):
        msg = MIMEMultipart("mixed")
        # 25 MB + 1024 bytes
        large_size = MAX_ATTACHMENT_SIZE_BYTES + 1024
        large_bytes = b"A" * large_size

        att = MIMEApplication(large_bytes, _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename="huge_database.dump")
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        assert meta.filename == "huge_database.dump"
        assert meta.status == AttachmentStatus.SKIPPED
        assert meta.skipped is True
        assert meta.sha256 is None  # MUST NOT hash
        assert meta.size_bytes == large_size  # Metadata preserved
        assert meta.skip_reason is not None
        assert "exceeds" in meta.skip_reason.lower()


# ---------------------------------------------------------------------------
# 23. More than 50 attachments
# ---------------------------------------------------------------------------

class TestMoreThan50Attachments:
    """Scenario 23: Messages with more than 50 attachments."""

    def test_attachment_count_limit_safely_enforced(self):
        msg = MIMEMultipart("mixed")

        # Create 55 attachments
        total_attachments = 55
        for i in range(1, total_attachments + 1):
            part = MIMEApplication(f"data {i}".encode("utf-8"), _subtype="octet-stream")
            part.add_header("Content-Disposition", "attachment", filename=f"file_{i:02d}.dat")
            msg.attach(part)

        results = extract_attachments(msg)

        # None are silently omitted
        assert len(results) == total_attachments

        # First 50 are processed
        for idx in range(MAX_ATTACHMENT_COUNT):
            assert results[idx].status == AttachmentStatus.PROCESSED
            assert results[idx].sha256 is not None
            assert results[idx].skipped is False

        # 51 through 55 are marked skipped
        for idx in range(MAX_ATTACHMENT_COUNT, total_attachments):
            assert results[idx].status == AttachmentStatus.SKIPPED
            assert results[idx].skipped is True
            assert results[idx].sha256 is None
            assert results[idx].size_bytes is None  # Size was not measured
            assert results[idx].skip_reason is not None
            assert "attachment count" in results[idx].skip_reason.lower()
            assert "exceeded" in results[idx].skip_reason.lower()


# ---------------------------------------------------------------------------
# 24. Malformed MIME structures
# ---------------------------------------------------------------------------

class TestMalformedMimeStructures:
    """Scenario 24: Resilient handling of malformed MIME messages."""

    def test_non_message_input_returns_empty_list(self):
        assert extract_attachments(None) == []  # type: ignore[arg-type]
        assert extract_attachments("string instead of message") == []  # type: ignore[arg-type]

    def test_broken_mime_boundary_string(self):
        broken_raw = (
            "Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\n\n"
            "--BOUNDARY\n"
            "Content-Type: application/pdf\n"
            "Content-Disposition: attachment; filename=\"file.pdf\"\n\n"
            "pdf bytes\n"
            "--DIFFERENT_UNEXPECTED_BOUNDARY--\n"
        )
        msg = email.message_from_string(broken_raw)
        results = extract_attachments(msg)
        # Does not raise unhandled exception
        assert isinstance(results, list)


# ---------------------------------------------------------------------------
# 25. Non-attachment body text must NOT be classified as an attachment
# ---------------------------------------------------------------------------

class TestNonAttachmentBodyNotClassified:
    """Scenario 25: Plain-text and HTML email bodies are NOT attachments."""

    def test_multipart_alternative_bodies_not_attachments(self):
        msg = MIMEMultipart("alternative")
        plain = MIMEText("This is the main plain text email body.", "plain", "utf-8")
        html = MIMEText("<p>This is the main HTML email body.</p>", "html", "utf-8")
        msg.attach(plain)
        msg.attach(html)

        results = extract_attachments(msg)
        assert results == []

    def test_inline_plain_text_without_filename_not_attachment(self):
        msg = MIMEMultipart("mixed")
        body = MIMEText("Ordinary email body with inline disposition.", "plain", "utf-8")
        body.add_header("Content-Disposition", "inline")
        msg.attach(body)

        results = extract_attachments(msg)
        assert results == []

    def test_single_part_text_email_not_attachment(self):
        msg = MIMEText("Single part plain text message.", "plain", "utf-8")
        results = extract_attachments(msg)
        assert results == []


# ---------------------------------------------------------------------------
# 26. Misleading and double extensions
# ---------------------------------------------------------------------------

class TestMisleadingExtensions:
    """Scenario 26: Double extensions (e.g. document.pdf.exe)."""

    def test_double_extension_handled_correctly(self):
        msg = MIMEMultipart("mixed")
        att = MIMEApplication(b"payload", _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename="document.pdf.exe")
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        assert meta.filename == "document.pdf.exe"
        # Extension is the final extension (exe)
        assert meta.extension == "exe"


# ---------------------------------------------------------------------------
# 27. Extremely long filenames
# ---------------------------------------------------------------------------

class TestExtremelyLongFilename:
    """Scenario 27: Filenames exceeding 255 characters are truncated safely."""

    def test_long_filename_truncated_safely(self):
        msg = MIMEMultipart("mixed")
        long_stem = "a" * 300
        raw_name = f"{long_stem}.docx"
        att = MIMEApplication(b"doc bytes", _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename=raw_name)
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        assert len(meta.filename) <= 255
        assert meta.extension == "docx"
        assert meta.filename.endswith(".docx")
        # Raw evidence preserved
        assert meta.raw_filename == raw_name


# ---------------------------------------------------------------------------
# 28. Filename with null bytes and control characters
# ---------------------------------------------------------------------------

class TestFilenameControlCharacters:
    """Scenario 28: Null bytes and control characters stripped from filename."""

    def test_null_bytes_stripped(self):
        msg = MIMEMultipart("mixed")
        att = MIMEApplication(b"content", _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename="invoice\x00_test.pdf")
        msg.attach(att)

        results = extract_attachments(msg)

        assert len(results) == 1
        meta = results[0]
        assert "\x00" not in meta.filename
        assert meta.filename == "invoice_test.pdf"
        assert meta.extension == "pdf"


# ---------------------------------------------------------------------------
# 29. Standalone single-part attachment email
# ---------------------------------------------------------------------------

class TestStandaloneSinglePartAttachment:
    """Scenario 29: Standalone single-part attachment message (not multipart)."""

    def test_single_part_pdf_attachment(self):
        pdf_bytes = b"%PDF-1.4 standalone file"
        msg = MIMEApplication(pdf_bytes, _subtype="pdf")
        msg.add_header("Content-Disposition", "attachment", filename="standalone.pdf")

        results = extract_attachments(msg)

        assert len(results) == 1
        assert results[0].filename == "standalone.pdf"
        assert results[0].extension == "pdf"
        assert results[0].size_bytes == len(pdf_bytes)
        assert results[0].sha256 == hashlib.sha256(pdf_bytes).hexdigest()


# ---------------------------------------------------------------------------
# 30. Pydantic validation & forbidden extra fields
# ---------------------------------------------------------------------------

class TestPydanticAttachmentValidation:
    """Scenario 30: AttachmentMetadata schema validation."""

    def test_extra_fields_forbidden_on_attachment_metadata(self):
        with pytest.raises(ValidationError):
            AttachmentMetadata(
                filename="doc.pdf",
                size_bytes=100,
                disposition=AttachmentDisposition.ATTACHMENT,
                status=AttachmentStatus.PROCESSED,
                malware_verdict="clean",  # type: ignore[call-arg]
            )

    def test_invalid_sha256_rejected(self):
        with pytest.raises(ValidationError):
            AttachmentMetadata(
                filename="doc.pdf",
                size_bytes=100,
                sha256="not_a_valid_hex_hash",
                disposition=AttachmentDisposition.ATTACHMENT,
                status=AttachmentStatus.PROCESSED,
            )

    def test_skipped_without_reason_rejected(self):
        with pytest.raises(ValidationError):
            AttachmentMetadata(
                filename="doc.pdf",
                size_bytes=100,
                disposition=AttachmentDisposition.ATTACHMENT,
                status=AttachmentStatus.SKIPPED,
                # skip_reason missing
            )


# ---------------------------------------------------------------------------
# 31. Integration into EmailData schema & JSON round-trip
# ---------------------------------------------------------------------------

class TestEmailDataIntegration:
    """Scenario 31: Extracted attachments integrate cleanly into EmailData."""

    def test_email_data_with_extracted_attachments_round_trip(self):
        msg = MIMEMultipart("mixed")
        body = MIMEText("Here is the document.", "plain", "utf-8")
        msg.attach(body)
        pdf_bytes = b"%PDF-1.4 sample payload"
        att = MIMEApplication(pdf_bytes, _subtype="pdf")
        att.add_header("Content-Disposition", "attachment", filename="report.pdf")
        msg.attach(att)

        extracted_atts = extract_attachments(msg)

        email_data = EmailData(
            email_id="msg-999",
            source_filename="test.eml",
            headers=EmailHeaders(
                from_address="sender@example.com",
                to=["user@example.com"],
                subject="Test document",
            ),
            authentication=AuthenticationMetadata(
                spf=AuthenticationResult(mechanism=AuthMechanism.SPF, status=AuthStatus.PASS),
                dkim=AuthenticationResult(mechanism=AuthMechanism.DKIM, status=AuthStatus.PASS),
                dmarc=AuthenticationResult(mechanism=AuthMechanism.DMARC, status=AuthStatus.MISSING),
            ),
            plain_text_body="Here is the document.",
            attachments=extracted_atts,
            ingestion_timestamp=datetime.now(timezone.utc),
        )

        # JSON Serialization
        json_output = email_data.model_dump_json()
        parsed = json.loads(json_output)

        assert len(parsed["attachments"]) == 1
        assert parsed["attachments"][0]["filename"] == "report.pdf"
        assert parsed["attachments"][0]["size_bytes"] == len(pdf_bytes)
        assert parsed["attachments"][0]["sha256"] == hashlib.sha256(pdf_bytes).hexdigest()

        # Deserialization
        restored = EmailData.model_validate_json(json_output)
        assert len(restored.attachments) == 1
        assert restored.attachments[0].filename == "report.pdf"
        assert restored.attachments[0].sha256 == email_data.attachments[0].sha256


# ---------------------------------------------------------------------------
# Task 6.1 — Strict Limits and Accurate Metadata Verification
# ---------------------------------------------------------------------------

class TestTask61StrictLimitsAndMetadata:
    """
    Focused verification of Task 6.1 requirements:
      1. Empty attachment has size_bytes=0.
      2. Normal attachment has its exact decoded size.
      3. Oversized attachment has a meaningful skip_reason and no hash.
      4. Attachment beyond the 50-item limit has size_bytes=None.
      5. Attachment beyond the limit is not decoded or hashed.
      6. Existing AttachmentMetadata instances with integer size remain valid.
      7. Size limit is enforced before unnecessary full decoding wherever possible.
      8. Existing SHA-256 values remain unchanged for accepted attachments.
      9. Malformed transfer encodings remain safely handled.
    """

    def test_empty_attachment_size_zero(self):
        """1. Empty attachment has size_bytes=0."""
        msg = MIMEMultipart("mixed")
        att = MIMEApplication(b"", _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename="zero.dat")
        msg.attach(att)

        results = extract_attachments(msg)
        assert len(results) == 1
        assert results[0].size_bytes == 0
        assert results[0].sha256 == hashlib.sha256(b"").hexdigest()
        assert results[0].status == AttachmentStatus.PROCESSED

    def test_normal_attachment_exact_decoded_size(self):
        """2. Normal attachment has its exact decoded size."""
        msg = MIMEMultipart("mixed")
        payload = b"Exact test payload containing 45 bytes of data!"
        att = MIMEApplication(payload, _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename="payload.bin")
        msg.attach(att)

        results = extract_attachments(msg)
        assert len(results) == 1
        assert results[0].size_bytes == len(payload)
        assert results[0].sha256 == hashlib.sha256(payload).hexdigest()
        assert results[0].status == AttachmentStatus.PROCESSED

    def test_oversized_attachment_skip_reason_and_no_hash(self):
        """3. Oversized attachment has a meaningful skip_reason and no hash."""
        msg = MIMEMultipart("mixed")
        oversized_len = MAX_ATTACHMENT_SIZE_BYTES + 4096
        att = MIMEApplication(b"X" * oversized_len, _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename="oversized.bin")
        msg.attach(att)

        results = extract_attachments(msg)
        assert len(results) == 1
        meta = results[0]
        assert meta.status == AttachmentStatus.SKIPPED
        assert meta.sha256 is None
        assert meta.size_bytes == oversized_len
        assert meta.skip_reason is not None
        assert "exceeds" in meta.skip_reason.lower()
        assert "25 mb" in meta.skip_reason.lower() or str(MAX_ATTACHMENT_SIZE_BYTES) in meta.skip_reason

    def test_attachment_beyond_50_limit_size_none(self):
        """4. Attachment beyond the 50-item limit has size_bytes=None."""
        msg = MIMEMultipart("mixed")
        for i in range(1, 53):
            att = MIMEApplication(b"item", _subtype="octet-stream")
            att.add_header("Content-Disposition", "attachment", filename=f"att_{i}.bin")
            msg.attach(att)

        results = extract_attachments(msg)
        assert len(results) == 52

        # 1..50 have measured size_bytes
        for i in range(50):
            assert results[i].size_bytes == 4
            assert results[i].status == AttachmentStatus.PROCESSED

        # 51 and 52 have size_bytes=None because size was not measured
        assert results[50].size_bytes is None
        assert results[50].status == AttachmentStatus.SKIPPED
        assert results[50].sha256 is None
        assert results[51].size_bytes is None
        assert results[51].status == AttachmentStatus.SKIPPED
        assert results[51].sha256 is None

    def test_attachment_beyond_limit_not_decoded_or_hashed(self):
        """5. Attachment beyond the limit is not decoded or hashed."""
        msg = MIMEMultipart("mixed")
        for i in range(1, 51):
            att = MIMEApplication(b"ok", _subtype="octet-stream")
            att.add_header("Content-Disposition", "attachment", filename=f"ok_{i}.bin")
            msg.attach(att)

        # 51st attachment with deliberately malformed base64 that would error if decoded
        raw_broken = MIMEApplication(b"", _subtype="octet-stream")
        raw_broken["Content-Transfer-Encoding"] = "base64"
        raw_broken.set_payload("===BrokenBase64ThatShouldNeverBeDecoded===")
        raw_broken.add_header("Content-Disposition", "attachment", filename="skip_me.bin")
        msg.attach(raw_broken)

        results = extract_attachments(msg)
        assert len(results) == 51
        att51 = results[50]
        # Should be SKIPPED due to count limit, NOT ERROR from decoding broken base64!
        assert att51.status == AttachmentStatus.SKIPPED
        assert att51.size_bytes is None
        assert att51.sha256 is None
        assert "count" in att51.skip_reason.lower()

    def test_existing_attachment_metadata_with_int_size_valid(self):
        """6. Existing AttachmentMetadata instances with integer size remain valid."""
        # Positive integer
        att_int = AttachmentMetadata(
            filename="test.pdf",
            size_bytes=2048,
            disposition=AttachmentDisposition.ATTACHMENT,
            status=AttachmentStatus.PROCESSED,
        )
        assert att_int.size_bytes == 2048

        # Zero integer
        att_zero = AttachmentMetadata(
            filename="empty.txt",
            size_bytes=0,
            disposition=AttachmentDisposition.ATTACHMENT,
            status=AttachmentStatus.PROCESSED,
        )
        assert att_zero.size_bytes == 0

        # None size (unmeasured)
        att_none = AttachmentMetadata(
            filename="unmeasured.dat",
            size_bytes=None,
            disposition=AttachmentDisposition.ATTACHMENT,
            status=AttachmentStatus.SKIPPED,
            skip_reason="Exceeded count limit",
        )
        assert att_none.size_bytes is None

        # Negative integer must still raise ValidationError
        with pytest.raises(ValidationError):
            AttachmentMetadata(
                filename="invalid.dat",
                size_bytes=-5,
                disposition=AttachmentDisposition.ATTACHMENT,
                status=AttachmentStatus.PROCESSED,
            )

    def test_size_limit_enforced_before_full_decoding_base64(self):
        """7. Size limit is enforced before unnecessary full decoding for base64."""
        # 26 MB base64 string
        line_b64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk+\n"
        # Each line has 86 chars including newline (84 clean b64 chars = 63 bytes)
        # 420,000 lines * 63 bytes = 26,460,000 bytes (>25 MB)
        b64_oversized = line_b64 * 420000

        msg = MIMEMultipart("mixed")
        att = MIMEApplication(b"", _subtype="octet-stream")
        att["Content-Transfer-Encoding"] = "base64"
        att.set_payload(b64_oversized)
        att.add_header("Content-Disposition", "attachment", filename="large_b64.iso")
        msg.attach(att)

        results = extract_attachments(msg)
        assert len(results) == 1
        meta = results[0]
        assert meta.status == AttachmentStatus.SKIPPED
        assert meta.sha256 is None
        assert meta.size_bytes is not None
        assert meta.size_bytes > MAX_ATTACHMENT_SIZE_BYTES
        assert "exceeds" in meta.skip_reason.lower()

    def test_existing_sha256_values_remain_unchanged(self):
        """8. Existing SHA-256 values remain unchanged for accepted attachments."""
        msg = MIMEMultipart("mixed")
        known_data = b"The quick brown fox jumps over the lazy dog"
        expected_hash = hashlib.sha256(known_data).hexdigest()

        att = MIMEApplication(known_data, _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename="fox.txt")
        msg.attach(att)

        results = extract_attachments(msg)
        assert len(results) == 1
        assert results[0].sha256 == expected_hash
        assert results[0].size_bytes == len(known_data)
        assert results[0].status == AttachmentStatus.PROCESSED

    def test_malformed_transfer_encodings_safely_handled(self):
        """9. Malformed transfer encodings remain safely handled."""
        msg = MIMEMultipart("mixed")
        att = MIMEApplication(b"", _subtype="octet-stream")
        att["Content-Transfer-Encoding"] = "base64"
        att.set_payload("!@#$%^&*()_+NonValidBase64Chars")
        att.add_header("Content-Disposition", "attachment", filename="corrupt.bin")
        msg.attach(att)

        # Must not raise unhandled exception
        results = extract_attachments(msg)
        assert len(results) == 1
        assert results[0].filename == "corrupt.bin"
        assert results[0].status in (AttachmentStatus.PROCESSED, AttachmentStatus.ERROR)


# ---------------------------------------------------------------------------
# Task 6.2 — Bounded Quoted-Printable Decoding by Bytes Verification
# ---------------------------------------------------------------------------

class TestTask62BoundedQuotedPrintableDecoding:
    """
    Focused verification of Task 6.2 requirements:
      1. Single encoded line exceeding 25 MB without newlines.
      2. Single line that decodes to more than 25 MB.
      3. Escape sequence split across internal processing chunks.
      4. Soft line break split across processing chunks.
      5. Many short lines whose combined decoded size exceeds 25 MB.
      6. Exactly 25 MB decoded.
      7. Exactly 25 MB plus one byte.
      8. Ordinary valid quoted-printable content.
      9. Malformed escape sequences.
      10. Empty quoted-printable content.
      11. Instrumentation: verifies input chunks never exceed bounded chunk size.
    """

    def test_single_encoded_line_exceeding_25mb_without_newlines(self):
        """1. A single encoded line exceeding 25 MB without newlines."""
        # 27 MB raw encoded line of '=20' (decodes to 9 MB, <= 25 MB limit)
        raw_line_27mb = "=20" * (9 * 1024 * 1024)
        res, sz = _bounded_decode_quoted_printable(raw_line_27mb, MAX_ATTACHMENT_SIZE_BYTES)
        assert res is not None
        assert sz == 9 * 1024 * 1024
        assert len(res) == 9 * 1024 * 1024

    def test_single_line_decoding_to_more_than_25mb(self):
        """2. A single line that decodes to more than 25 MB."""
        raw_line_over = "A" * (MAX_ATTACHMENT_SIZE_BYTES + 2048)
        res, sz = _bounded_decode_quoted_printable(raw_line_over, MAX_ATTACHMENT_SIZE_BYTES)
        assert res is None
        assert sz > MAX_ATTACHMENT_SIZE_BYTES

        # End-to-end extraction test
        msg = MIMEMultipart("mixed")
        att = MIMEApplication(b"", _subtype="octet-stream")
        del att["Content-Transfer-Encoding"]
        att["Content-Transfer-Encoding"] = "quoted-printable"
        att.set_payload(raw_line_over)
        att.add_header("Content-Disposition", "attachment", filename="single_line_over.bin")
        msg.attach(att)

        results = extract_attachments(msg)
        assert len(results) == 1
        meta = results[0]
        assert meta.status == AttachmentStatus.SKIPPED
        assert meta.sha256 is None
        assert meta.size_bytes is not None
        assert meta.size_bytes > MAX_ATTACHMENT_SIZE_BYTES
        assert "exceeds" in meta.skip_reason.lower()

    def test_escape_sequence_split_across_chunks(self):
        """3. An escape sequence split across internal processing chunks."""
        # Force a small chunk size of 5 so '=3D' and '=20' are split across chunks
        split_seq = "header=3Dbody=20end"
        expected = quopri.decodestring(split_seq.encode("ascii"))
        res, sz = _bounded_decode_quoted_printable(
            split_seq, MAX_ATTACHMENT_SIZE_BYTES, chunk_size=5
        )
        assert res == expected
        assert sz == len(expected)

    def test_soft_line_break_split_across_chunks(self):
        """4. A soft line break split across processing chunks."""
        # Test soft line breaks '=\r\n' and '=\n' across chunk boundaries 4..10
        raw_text = "line_one=\r\nline_two=\nline_three"
        expected = quopri.decodestring(raw_text.encode("ascii"))
        for csz in range(4, 11):
            res, sz = _bounded_decode_quoted_printable(
                raw_text, MAX_ATTACHMENT_SIZE_BYTES, chunk_size=csz
            )
            assert res == expected, f"Failed at chunk_size={csz}"
            assert sz == len(expected)

    def test_many_short_lines_combined_exceeding_25mb(self):
        """5. Many short lines whose combined decoded size exceeds 25 MB."""
        raw_lines = "Short line of data.\n" * 1500000  # ~30 MB
        res, sz = _bounded_decode_quoted_printable(raw_lines, MAX_ATTACHMENT_SIZE_BYTES)
        assert res is None
        assert sz > MAX_ATTACHMENT_SIZE_BYTES

    def test_exactly_25mb_decoded(self):
        """6. Exactly 25 MB decoded."""
        exact_str = "K" * MAX_ATTACHMENT_SIZE_BYTES
        res, sz = _bounded_decode_quoted_printable(exact_str, MAX_ATTACHMENT_SIZE_BYTES)
        assert res is not None
        assert sz == MAX_ATTACHMENT_SIZE_BYTES
        assert len(res) == MAX_ATTACHMENT_SIZE_BYTES

    def test_exactly_25mb_plus_one_byte(self):
        """7. Exactly 25 MB plus one byte."""
        over_one_str = "K" * (MAX_ATTACHMENT_SIZE_BYTES + 1)
        res, sz = _bounded_decode_quoted_printable(over_one_str, MAX_ATTACHMENT_SIZE_BYTES)
        assert res is None
        assert sz == MAX_ATTACHMENT_SIZE_BYTES + 1

    def test_ordinary_valid_quoted_printable_content(self):
        """8. Ordinary valid quoted-printable content."""
        qp_content = (
            "From: security@example.com\r\n"
            "Subject: Verification=20Required\r\n"
            "Status: =3D=3D=3D=20Active=20=3D=3D=3D\r\n"
            "Message: Soft line break=\r\n continued here.\r\n"
        )
        expected = quopri.decodestring(qp_content.encode("ascii"))
        res, sz = _bounded_decode_quoted_printable(qp_content, MAX_ATTACHMENT_SIZE_BYTES)
        assert res == expected
        assert sz == len(expected)

    def test_malformed_escape_sequences(self):
        """9. Malformed escape sequences handled safely."""
        malformed = "Bad=ZZEscape=1\nTrailing=\nInvalid=G9"
        expected = quopri.decodestring(malformed.encode("ascii"))
        res, sz = _bounded_decode_quoted_printable(malformed, MAX_ATTACHMENT_SIZE_BYTES)
        assert res == expected
        assert sz == len(expected)

    def test_empty_quoted_printable_content(self):
        """10. Empty quoted-printable content."""
        res, sz = _bounded_decode_quoted_printable("", MAX_ATTACHMENT_SIZE_BYTES)
        assert res == b""
        assert sz == 0

    def test_instrumented_chunk_size_bounded(self, monkeypatch):
        """11. Verify that quopri.decodestring never receives an unbounded input chunk."""
        max_chunk_observed = 0
        original_decodestring = quopri.decodestring

        def instrumented_decodestring(s):
            nonlocal max_chunk_observed
            if len(s) > max_chunk_observed:
                max_chunk_observed = len(s)
            return original_decodestring(s)

        monkeypatch.setattr(quopri, "decodestring", instrumented_decodestring)

        # 500 KB line without any newlines
        long_line = "A" * 500000
        res, sz = _bounded_decode_quoted_printable(
            long_line, MAX_ATTACHMENT_SIZE_BYTES, chunk_size=DEFAULT_QP_CHUNK_SIZE
        )
        assert res is not None
        assert sz == 500000
        # The maximum chunk processed must never exceed chunk_size + 2 (carryover)
        assert max_chunk_observed <= DEFAULT_QP_CHUNK_SIZE + 2
        assert max_chunk_observed < 70000
