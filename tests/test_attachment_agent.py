"""
tests/test_attachment_agent.py
------------------------------
Comprehensive test suite for the Attachment Specialist Agent:
- app.agents.attachment_agent.analyze_attachments
- app.agents.attachment_agent.create_no_attachment_result
- app.agents.attachment_agent.AttachmentAgentProcessingError
- app.agents.attachment_agent.ValidatedAttachmentRecord
- Executable, macro, and script detection
- HTML smuggling, double extension, and RLO spoofing
- MIME type conflict and archive/container classification
- Volumetric anomalies (zero-byte, oversized, skipped)
- Capacity caps (50 analysis items, 100 evidence items)
- Boundary validation, caller contracts, and fail-closed error handling
- End-to-end integration with email_ingestor
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
from unittest.mock import patch

import pytest

from app.agents.attachment_agent import (
    AttachmentAgentProcessingError,
    ValidatedAttachmentRecord,
    analyze_attachments,
    create_no_attachment_result,
)
from app.ingestion.email_ingestor import ingest_email
from app.schemas.attachment_agent_schema import AttachmentAgentResult
from app.schemas.email_schema import (
    AttachmentDisposition,
    AttachmentMetadata,
    AttachmentStatus,
    AuthenticationClaim,
    AuthenticationMetadata,
    AuthenticationResult,
    AuthMechanism,
    AuthProvenance,
    AuthStatus,
    EmailData,
    EmailHeaders,
)


def _make_attachment(
    filename: str = "report.pdf",
    content_type: str = "application/pdf",
    extension: Optional[str] = "pdf",
    size_bytes: int = 25000,
    disposition: AttachmentDisposition = AttachmentDisposition.ATTACHMENT,
    status: AttachmentStatus = AttachmentStatus.PROCESSED,
    skip_reason: Optional[str] = None,
    raw_filename: Optional[str] = None,
) -> AttachmentMetadata:
    return AttachmentMetadata(
        filename=filename,
        content_type=content_type,
        extension=extension,
        size_bytes=size_bytes,
        disposition=disposition,
        status=status,
        skip_reason=skip_reason,
        raw_filename=raw_filename,
    )


def _make_test_email(
    attachments: Optional[List[AttachmentMetadata]] = None,
    email_id: str = "test-email-att-001",
) -> EmailData:
    headers = EmailHeaders(
        from_address="sender@example.com",
        to=["recipient@example.com"],
        subject="Test Attachments",
        date="Wed, 20 Nov 2026 12:00:00 +0000",
        message_id="<msg-001@example.com>",
    )
    auth = AuthenticationMetadata(
        spf=AuthenticationResult(mechanism=AuthMechanism.SPF, status=AuthStatus.MISSING, provenance=AuthProvenance.UNAVAILABLE),
        dkim=AuthenticationResult(mechanism=AuthMechanism.DKIM, status=AuthStatus.MISSING, provenance=AuthProvenance.UNAVAILABLE),
        dmarc=AuthenticationResult(mechanism=AuthMechanism.DMARC, status=AuthStatus.MISSING, provenance=AuthProvenance.UNAVAILABLE),
        claims=[],
    )
    return EmailData(
        email_id=email_id,
        source_filename="test.eml",
        headers=headers,
        authentication=auth,
        plain_text_body="See attached document.",
        html_body=None,
        cleaned_text="See attached document.",
        extracted_urls=[],
        attachments=attachments if attachments is not None else [],
        ingestion_timestamp=datetime.now(timezone.utc),
    )


# ===========================================================================
# 1. No-Attachment Scenarios (State 1)
# ===========================================================================

class TestNoAttachmentScenarios:
    def test_state_1_empty_attachments(self) -> None:
        email = _make_test_email(attachments=[])
        result = analyze_attachments(email)

        assert isinstance(result, AttachmentAgentResult)
        assert result.status == "success"
        assert result.email_id == "test-email-att-001"
        assert result.total_attachments_evaluated == 0
        assert result.features.has_attachments is False
        assert result.features.total_attachment_count == 0
        assert result.features.has_executable_attachment is False
        assert result.features.has_macro_enabled_attachment is False
        assert result.features.total_attachment_size_bytes == 0

        assert result.availability.avail_has_attachments is False
        assert result.availability.completeness_total == 0.0
        assert result.evidence.evidence_items == []
        assert result.analysis_items == []

    def test_state_1_internal_crash_safety(self) -> None:
        email = _make_test_email(attachments=[])
        with patch("app.agents.attachment_agent.create_no_attachment_result", side_effect=RuntimeError("Simulated crash")):
            with pytest.raises(AttachmentAgentProcessingError) as exc_info:
                analyze_attachments(email)
            err = exc_info.value
            assert err.email_id == "test-email-att-001"
            assert isinstance(err.original_exception, RuntimeError)
            assert err.__cause__ is err.original_exception


# ===========================================================================
# 2. Benign Attachment Scenarios
# ===========================================================================

class TestBenignAttachments:
    def test_clean_pdf_and_xlsx(self) -> None:
        att1 = _make_attachment(filename="quarterly_report.pdf", content_type="application/pdf", extension="pdf", size_bytes=50000)
        att2 = _make_attachment(filename="budget_2026.xlsx", content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", extension="xlsx", size_bytes=75000)

        email = _make_test_email([att1, att2])
        result = analyze_attachments(email)

        assert result.status == "success"
        assert result.total_attachments_evaluated == 2
        assert result.features.has_attachments is True
        assert result.features.total_attachment_count == 2
        assert result.features.total_attachment_size_bytes == 125000
        assert result.features.max_attachment_size_bytes == 75000

        # Risk features should all be False/0
        assert result.features.has_executable_attachment is False
        assert result.features.executable_attachment_count == 0
        assert result.features.has_macro_enabled_attachment is False
        assert result.features.has_html_smuggling_attachment is False
        assert result.features.has_double_extension is False
        assert result.features.has_rlo_spoofing is False
        assert result.features.has_mime_mismatch is False
        assert result.features.has_archive_attachment is False
        assert result.features.has_oversized_attachment is False
        assert result.features.has_zero_byte_attachment is False

        assert result.availability.avail_has_attachments is True
        assert result.availability.completeness_total == 1.0
        assert len(result.analysis_items) == 2


# ===========================================================================
# 3. High-Risk Executable, Script & Macro Detection
# ===========================================================================

class TestHighRiskFiles:
    def test_executable_extensions(self) -> None:
        exec_files = [
            _make_attachment(filename="malware.exe", content_type="application/x-msdownload", extension="exe"),
            _make_attachment(filename="dropper.scr", content_type="application/octet-stream", extension="scr"),
            _make_attachment(filename="payload.js", content_type="application/javascript", extension="js"),
            _make_attachment(filename="script.vbs", content_type="application/x-vbs", extension="vbs"),
            _make_attachment(filename="launcher.bat", content_type="application/x-bat", extension="bat"),
        ]
        email = _make_test_email(exec_files)
        result = analyze_attachments(email)

        assert result.features.has_executable_attachment is True
        assert result.features.executable_attachment_count == 5
        assert any(item.feature_name == "has_executable_attachment" for item in result.evidence.evidence_items)

    def test_macro_enabled_office(self) -> None:
        macro_files = [
            _make_attachment(filename="invoice.docm", content_type="application/vnd.ms-word.document.macroEnabled.12", extension="docm"),
            _make_attachment(filename="ledger.xlsm", content_type="application/vnd.ms-excel.sheet.macroEnabled.12", extension="xlsm"),
            _make_attachment(filename="briefing.pptm", content_type="application/vnd.ms-powerpoint.presentation.macroEnabled.12", extension="pptm"),
        ]
        email = _make_test_email(macro_files)
        result = analyze_attachments(email)

        assert result.features.has_macro_enabled_attachment is True
        assert result.features.macro_enabled_count == 3
        assert any(item.feature_name == "has_macro_enabled_attachment" for item in result.evidence.evidence_items)

    def test_html_smuggling_vectors(self) -> None:
        smuggle_files = [
            _make_attachment(filename="document_viewer.html", content_type="text/html", extension="html"),
            _make_attachment(filename="logo_vector.svg", content_type="image/svg+xml", extension="svg"),
        ]
        email = _make_test_email(smuggle_files)
        result = analyze_attachments(email)

        assert result.features.has_html_smuggling_attachment is True
        assert result.features.html_smuggling_count == 2


# ===========================================================================
# 4. Deceptive Spoofing (Double Extension & RLO)
# ===========================================================================

class TestSpoofingAndEvasion:
    def test_double_extension_spoofing(self) -> None:
        att = _make_attachment(
            filename="urgent_invoice.pdf.exe",
            content_type="application/octet-stream",
            extension="exe",
        )
        email = _make_test_email([att])
        result = analyze_attachments(email)

        assert result.features.has_double_extension is True
        assert result.features.double_extension_count == 1
        assert any(item.feature_name == "has_double_extension" for item in result.evidence.evidence_items)

    def test_rlo_character_spoofing(self) -> None:
        # Right-to-Left Override (U+202E) turns "tax_doc[RLO]exe.pdf" visually into "tax_docfdp.exe"
        rlo_filename = "tax_doc\u202Eexe.pdf"
        att = _make_attachment(
            filename=rlo_filename,
            raw_filename=rlo_filename,
            content_type="application/octet-stream",
            extension="pdf",
        )
        email = _make_test_email([att])
        result = analyze_attachments(email)

        assert result.features.has_rlo_spoofing is True
        assert result.features.rlo_spoofing_count == 1
        assert any(item.feature_name == "has_rlo_spoofing" for item in result.evidence.evidence_items)

    def test_mime_type_mismatch(self) -> None:
        # Declares image/jpeg or application/pdf, but extension is exe
        att = _make_attachment(
            filename="scan_document.exe",
            content_type="application/pdf",
            extension="exe",
        )
        email = _make_test_email([att])
        result = analyze_attachments(email)

        assert result.features.has_mime_mismatch is True
        assert result.features.mime_mismatch_count == 1


# ===========================================================================
# 5. Archive and Container Formats
# ===========================================================================

class TestArchivesAndContainers:
    def test_archive_and_disk_images(self) -> None:
        att1 = _make_attachment(filename="payload.zip", content_type="application/zip", extension="zip")
        att2 = _make_attachment(filename="system_image.iso", content_type="application/octet-stream", extension="iso")

        email = _make_test_email([att1, att2])
        result = analyze_attachments(email)

        assert result.features.has_archive_attachment is True
        assert result.features.archive_attachment_count == 1
        assert result.features.has_disk_image is True

    def test_encrypted_archive(self) -> None:
        att = _make_attachment(
            filename="secure_financials.zip",
            content_type="application/zip",
            extension="zip",
            skip_reason="Password encrypted archive payload",
        )
        email = _make_test_email([att])
        result = analyze_attachments(email)

        assert result.features.has_encrypted_archive is True


# ===========================================================================
# 6. Volumetric and Size Properties
# ===========================================================================

class TestVolumetricProperties:
    def test_zero_byte_attachment(self) -> None:
        att = _make_attachment(filename="empty.txt", size_bytes=0)
        email = _make_test_email([att])
        result = analyze_attachments(email)

        assert result.features.has_zero_byte_attachment is True

    def test_oversized_attachment(self) -> None:
        att = _make_attachment(filename="massive_database.dump", size_bytes=15 * 1024 * 1024)
        email = _make_test_email([att])
        result = analyze_attachments(email)

        assert result.features.has_oversized_attachment is True

    def test_skipped_attachment(self) -> None:
        att = _make_attachment(
            filename="skipped_huge.zip",
            status=AttachmentStatus.SKIPPED,
            skip_reason="Exceeded 25 MB limit",
        )
        email = _make_test_email([att])
        result = analyze_attachments(email)

        assert result.features.has_skipped_attachments is True
        assert result.features.skipped_attachment_count == 1

    def test_analysis_items_cap_50(self) -> None:
        # Create 60 attachments
        many_atts = [
            _make_attachment(filename=f"file_{i}.txt", size_bytes=100)
            for i in range(60)
        ]
        email = _make_test_email(many_atts)
        result = analyze_attachments(email)

        assert result.features.total_attachment_count == 60
        assert len(result.analysis_items) == 50
        assert any("capped to first 50" in w for w in result.warnings)


# ===========================================================================
# 7. Boundary Validation, Caller Contracts & Exception Handling
# ===========================================================================

class TestBoundaryValidationAndContracts:
    def test_reject_unrelated_types(self) -> None:
        with pytest.raises(TypeError):
            analyze_attachments(None)  # type: ignore

        with pytest.raises(TypeError):
            analyze_attachments("string")  # type: ignore

        with pytest.raises(TypeError):
            analyze_attachments({"email_id": "test"})  # type: ignore

    def test_reject_blank_or_whitespace_email_id(self) -> None:
        for bad_id in ["", "   ", "\t\n"]:
            ed = EmailData.model_construct(email_id=bad_id, attachments=[])
            with pytest.raises(ValueError):
                analyze_attachments(ed)

    def test_preserves_exact_email_id(self) -> None:
        exact_id = "  exact-att-id-001  "
        email = _make_test_email(email_id=exact_id)
        result = analyze_attachments(email)
        assert result.email_id == exact_id

    def test_reject_non_list_attachments(self) -> None:
        for bad_atts in [("tuple",), "string", 12345, {"dict": "val"}]:
            ed = EmailData.model_construct(email_id="msg-001", attachments=bad_atts)
            with pytest.raises(TypeError):
                analyze_attachments(ed)

    def test_reject_non_attachment_metadata_items(self) -> None:
        ed = EmailData.model_construct(email_id="msg-001", attachments=["not_metadata"])
        with pytest.raises(TypeError):
            analyze_attachments(ed)

    def test_corrupted_attachment_fields_fail_fast(self) -> None:
        bad_att1 = AttachmentMetadata.model_construct(filename=123, content_type="text/plain")
        ed1 = EmailData.model_construct(email_id="msg-001", attachments=[bad_att1])
        with pytest.raises(TypeError):
            analyze_attachments(ed1)

        bad_att2 = AttachmentMetadata.model_construct(filename="ok.txt", content_type="text/plain", size_bytes=-10)
        ed2 = EmailData.model_construct(email_id="msg-001", attachments=[bad_att2])
        with pytest.raises(ValueError):
            analyze_attachments(ed2)

    def test_internal_pipeline_crash_fail_closed(self) -> None:
        att = _make_attachment()
        email = _make_test_email([att])
        with patch("app.agents.attachment_agent.execute_attachment_analysis_pipeline", side_effect=RuntimeError("Pipeline crash")):
            with pytest.raises(AttachmentAgentProcessingError) as exc_info:
                analyze_attachments(email)
            err = exc_info.value
            assert err.email_id == "test-email-att-001"
            assert err.total_attachments_evaluated == 1
            assert isinstance(err.original_exception, RuntimeError)
            assert "Pipeline crash" in err.traceback_str


# ===========================================================================
# 8. End-to-End Ingestion Integration
# ===========================================================================

class TestEndToEndIntegration:
    def test_ingest_email_to_analyze_attachments_roundtrip(self) -> None:
        raw_eml = (
            b"From: billing@external-vendor.com\r\n"
            b"To: victim@company.com\r\n"
            b"Subject: Invoice Attached\r\n"
            b"Date: Wed, 20 Nov 2026 12:00:00 +0000\r\n"
            b"Message-ID: <att-integration-001@example.com>\r\n"
            b"MIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="BOUNDARY123"\r\n\r\n'
            b"--BOUNDARY123\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Please see attached invoice.\r\n\r\n"
            b"--BOUNDARY123\r\n"
            b'Content-Type: application/pdf; name="invoice_1092.exe"\r\n'
            b'Content-Disposition: attachment; filename="invoice_1092.exe"\r\n'
            b"Content-Transfer-Encoding: base64\r\n\r\n"
            b"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n"
            b"--BOUNDARY123--\r\n"
        )
        email_data = ingest_email(raw_eml, source_filename="sample_attachment_phish.eml")
        assert len(email_data.attachments) >= 1

        result = analyze_attachments(email_data)
        assert result.status == "success"
        assert result.features.has_attachments is True
        assert result.features.has_executable_attachment is True
        assert result.features.has_mime_mismatch is True

        # Validation roundtrip
        dumped = result.model_dump()
        reconstructed = AttachmentAgentResult.model_validate(dumped)
        assert reconstructed.email_id == result.email_id
        assert reconstructed.features.has_attachments is True
        assert reconstructed.features.total_attachment_count == result.features.total_attachment_count
