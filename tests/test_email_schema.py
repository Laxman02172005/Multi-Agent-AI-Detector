"""
tests/test_email_schema.py
--------------------------
Pytest test suite for the EmailData Pydantic schemas.

Covers:
  1.  Valid EmailData creation (happy path)
  2.  Missing optional headers
  3.  Missing authentication information (status = 'missing')
  4.  Authentication pass
  5.  Authentication fail
  6.  Invalid authentication status
  7.  Invalid SHA-256 (wrong length / non-hex)
  8.  Negative attachment size
  9.  Empty email_id
  10. Empty source_filename
  11. URL source validation
  12. JSON serialisation (model_dump_json)
  13. Nested model validation (headers + auth always required)
  14. Skipped attachment must include skip_reason
  15. AuthStatus.MISSING is not treated as failure
"""

import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas import (
    AttachmentDisposition,
    AttachmentMetadata,
    AttachmentStatus,
    AuthenticationMetadata,
    AuthenticationResult,
    AuthMechanism,
    AuthStatus,
    EmailData,
    EmailHeaders,
    ExtractedURL,
    URLSource,
)

# ---------------------------------------------------------------------------
# Shared helpers / fixtures
# ---------------------------------------------------------------------------

def _make_auth_metadata(
    spf_status: AuthStatus = AuthStatus.PASS,
    dkim_status: AuthStatus = AuthStatus.PASS,
    dmarc_status: AuthStatus = AuthStatus.PASS,
) -> AuthenticationMetadata:
    """Return a fully populated AuthenticationMetadata for a given set of statuses."""
    return AuthenticationMetadata(
        spf=AuthenticationResult(
            mechanism=AuthMechanism.SPF,
            status=spf_status,
            raw_value="spf=pass" if spf_status == AuthStatus.PASS else None,
        ),
        dkim=AuthenticationResult(
            mechanism=AuthMechanism.DKIM,
            status=dkim_status,
            raw_value="dkim=pass" if dkim_status == AuthStatus.PASS else None,
        ),
        dmarc=AuthenticationResult(
            mechanism=AuthMechanism.DMARC,
            status=dmarc_status,
            raw_value=None,
        ),
    )


def _make_minimal_email_data(**overrides) -> dict:
    """Return a minimal valid EmailData payload dict (keyword overrides applied)."""
    base = {
        "email_id": "email-001",
        "source_filename": "sample.eml",
        "headers": {
            "from_address": "security@example.com",
            "to": ["user@example.net"],
            "subject": "Account notification",
            "received": [],
        },
        "authentication": {
            "spf": {
                "mechanism": "SPF",
                "status": "pass",
                "raw_value": "spf=pass",
            },
            "dkim": {
                "mechanism": "DKIM",
                "status": "pass",
                "raw_value": "dkim=pass",
            },
            "dmarc": {
                "mechanism": "DMARC",
                "status": "missing",
                "raw_value": None,
            },
        },
        "plain_text_body": "Please review your account.",
        "html_body": None,
        "cleaned_text": "Please review your account.",
        "extracted_urls": [],
        "attachments": [],
        "parsing_warnings": [],
        "ingestion_timestamp": "2026-11-10T10:00:00Z",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# 1. Valid EmailData creation
# ---------------------------------------------------------------------------

class TestValidEmailDataCreation:
    def test_valid_email_data_from_dict(self):
        """A fully populated, valid EmailData must parse without errors."""
        data = EmailData(**_make_minimal_email_data())
        assert data.email_id == "email-001"
        assert data.source_filename == "sample.eml"
        assert data.headers.from_address == "security@example.com"
        assert data.headers.to == ["user@example.net"]
        assert data.authentication.spf.status == AuthStatus.PASS
        assert data.authentication.dmarc.status == AuthStatus.MISSING

    def test_ingestion_timestamp_parsed_to_datetime(self):
        """ingestion_timestamp must be a datetime after parsing."""
        data = EmailData(**_make_minimal_email_data())
        assert isinstance(data.ingestion_timestamp, datetime)

    def test_all_optional_list_fields_default_to_empty_list(self):
        """List fields with defaults should start empty when omitted."""
        data = EmailData(**_make_minimal_email_data())
        assert data.extracted_urls == []
        assert data.attachments == []
        assert data.parsing_warnings == []


# ---------------------------------------------------------------------------
# 2. Missing optional headers
# ---------------------------------------------------------------------------

class TestMissingOptionalHeaders:
    def test_headers_with_only_to_field(self):
        """EmailHeaders must accept when most optional fields are absent."""
        headers = EmailHeaders(to=["a@b.com"])
        assert headers.from_address is None
        assert headers.reply_to is None
        assert headers.subject is None
        assert headers.cc == []
        assert headers.bcc == []

    def test_completely_empty_headers(self):
        """EmailHeaders must be constructable with no arguments at all."""
        headers = EmailHeaders()
        assert headers.from_address is None
        assert headers.to == []

    def test_email_data_with_minimal_headers_dict(self):
        """EmailData must accept headers dict containing only 'to'."""
        payload = _make_minimal_email_data()
        payload["headers"] = {"to": ["user@example.net"]}
        data = EmailData(**payload)
        assert data.headers.from_address is None
        assert data.headers.subject is None


# ---------------------------------------------------------------------------
# 3. Missing authentication information
# ---------------------------------------------------------------------------

class TestMissingAuthenticationInformation:
    def test_auth_status_missing_is_valid(self):
        """AuthStatus.MISSING must be a valid, accepted value."""
        result = AuthenticationResult(
            mechanism=AuthMechanism.DMARC,
            status=AuthStatus.MISSING,
            raw_value=None,
        )
        assert result.status == AuthStatus.MISSING

    def test_auth_status_unavailable_is_valid(self):
        """AuthStatus.UNAVAILABLE must be accepted without raising."""
        result = AuthenticationResult(
            mechanism=AuthMechanism.SPF,
            status=AuthStatus.UNAVAILABLE,
        )
        assert result.status == AuthStatus.UNAVAILABLE

    def test_all_three_mechanisms_can_be_missing(self):
        """All three auth mechanisms may simultaneously carry status 'missing'."""
        auth = _make_auth_metadata(
            spf_status=AuthStatus.MISSING,
            dkim_status=AuthStatus.MISSING,
            dmarc_status=AuthStatus.MISSING,
        )
        assert auth.spf.status == AuthStatus.MISSING
        assert auth.dkim.status == AuthStatus.MISSING
        assert auth.dmarc.status == AuthStatus.MISSING


# ---------------------------------------------------------------------------
# 4. Authentication pass
# ---------------------------------------------------------------------------

class TestAuthenticationPass:
    def test_spf_pass(self):
        result = AuthenticationResult(
            mechanism=AuthMechanism.SPF, status=AuthStatus.PASS, raw_value="spf=pass"
        )
        assert result.status == AuthStatus.PASS

    def test_dkim_pass(self):
        result = AuthenticationResult(
            mechanism=AuthMechanism.DKIM, status=AuthStatus.PASS, raw_value="dkim=pass"
        )
        assert result.status == AuthStatus.PASS

    def test_dmarc_pass(self):
        result = AuthenticationResult(
            mechanism=AuthMechanism.DMARC, status=AuthStatus.PASS, raw_value="dmarc=pass"
        )
        assert result.status == AuthStatus.PASS

    def test_all_pass_accepted_in_email_data(self):
        """EmailData with all-pass auth must validate without errors."""
        payload = _make_minimal_email_data()
        for key in ("spf", "dkim", "dmarc"):
            payload["authentication"][key]["status"] = "pass"
        data = EmailData(**payload)
        assert data.authentication.spf.status == AuthStatus.PASS
        assert data.authentication.dkim.status == AuthStatus.PASS
        assert data.authentication.dmarc.status == AuthStatus.PASS


# ---------------------------------------------------------------------------
# 5. Authentication fail
# ---------------------------------------------------------------------------

class TestAuthenticationFail:
    def test_spf_fail(self):
        result = AuthenticationResult(
            mechanism=AuthMechanism.SPF, status=AuthStatus.FAIL, raw_value="spf=fail"
        )
        assert result.status == AuthStatus.FAIL

    def test_dkim_fail(self):
        result = AuthenticationResult(
            mechanism=AuthMechanism.DKIM, status=AuthStatus.FAIL
        )
        assert result.status == AuthStatus.FAIL

    def test_dmarc_fail(self):
        result = AuthenticationResult(
            mechanism=AuthMechanism.DMARC, status=AuthStatus.FAIL
        )
        assert result.status == AuthStatus.FAIL

    def test_temperror_and_permerror_are_valid(self):
        """temperror and permerror are distinct from fail and must be accepted."""
        r1 = AuthenticationResult(mechanism=AuthMechanism.SPF, status=AuthStatus.TEMPERROR)
        r2 = AuthenticationResult(mechanism=AuthMechanism.DKIM, status=AuthStatus.PERMERROR)
        assert r1.status == AuthStatus.TEMPERROR
        assert r2.status == AuthStatus.PERMERROR


# ---------------------------------------------------------------------------
# 6. Invalid authentication status
# ---------------------------------------------------------------------------

class TestInvalidAuthenticationStatus:
    def test_unknown_status_string_raises(self):
        """An unrecognised auth status value must raise a ValidationError."""
        with pytest.raises(ValidationError):
            AuthenticationResult(
                mechanism=AuthMechanism.SPF,
                status="unknown_status",  # type: ignore[arg-type]
            )

    def test_empty_string_status_raises(self):
        with pytest.raises(ValidationError):
            AuthenticationResult(
                mechanism=AuthMechanism.SPF,
                status="",  # type: ignore[arg-type]
            )

    def test_integer_status_raises(self):
        with pytest.raises(ValidationError):
            AuthenticationResult(
                mechanism=AuthMechanism.SPF,
                status=1,  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# 7. Invalid SHA-256
# ---------------------------------------------------------------------------

class TestInvalidSHA256:
    VALID_SHA256 = "a" * 64

    def test_valid_sha256_accepted(self):
        att = AttachmentMetadata(
            size_bytes=100,
            sha256=self.VALID_SHA256,
            disposition=AttachmentDisposition.ATTACHMENT,
            status=AttachmentStatus.PROCESSED,
        )
        assert att.sha256 == self.VALID_SHA256

    def test_sha256_too_short_raises(self):
        with pytest.raises(ValidationError):
            AttachmentMetadata(
                size_bytes=100,
                sha256="abc123",
                disposition=AttachmentDisposition.ATTACHMENT,
                status=AttachmentStatus.PROCESSED,
            )

    def test_sha256_too_long_raises(self):
        with pytest.raises(ValidationError):
            AttachmentMetadata(
                size_bytes=100,
                sha256="a" * 65,
                disposition=AttachmentDisposition.ATTACHMENT,
                status=AttachmentStatus.PROCESSED,
            )

    def test_sha256_non_hex_raises(self):
        with pytest.raises(ValidationError):
            AttachmentMetadata(
                size_bytes=100,
                sha256="g" * 64,  # 'g' is not a hex character
                disposition=AttachmentDisposition.ATTACHMENT,
                status=AttachmentStatus.PROCESSED,
            )

    def test_sha256_none_accepted(self):
        """sha256 is optional; None must not raise."""
        att = AttachmentMetadata(
            size_bytes=0,
            sha256=None,
            disposition=AttachmentDisposition.INLINE,
            status=AttachmentStatus.PROCESSED,
        )
        assert att.sha256 is None


# ---------------------------------------------------------------------------
# 8. Negative attachment size
# ---------------------------------------------------------------------------

class TestNegativeAttachmentSize:
    def test_zero_size_allowed(self):
        att = AttachmentMetadata(
            size_bytes=0,
            disposition=AttachmentDisposition.ATTACHMENT,
            status=AttachmentStatus.PROCESSED,
        )
        assert att.size_bytes == 0

    def test_positive_size_allowed(self):
        att = AttachmentMetadata(
            size_bytes=1024,
            disposition=AttachmentDisposition.ATTACHMENT,
            status=AttachmentStatus.PROCESSED,
        )
        assert att.size_bytes == 1024

    def test_negative_size_raises(self):
        with pytest.raises(ValidationError):
            AttachmentMetadata(
                size_bytes=-1,
                disposition=AttachmentDisposition.ATTACHMENT,
                status=AttachmentStatus.PROCESSED,
            )


# ---------------------------------------------------------------------------
# 9. Empty email_id
# ---------------------------------------------------------------------------

class TestEmptyEmailId:
    def test_empty_string_email_id_raises(self):
        payload = _make_minimal_email_data(email_id="")
        with pytest.raises(ValidationError):
            EmailData(**payload)

    def test_whitespace_only_email_id_raises(self):
        payload = _make_minimal_email_data(email_id="   ")
        with pytest.raises(ValidationError):
            EmailData(**payload)

    def test_valid_email_id_accepted(self):
        payload = _make_minimal_email_data(email_id="email-999")
        data = EmailData(**payload)
        assert data.email_id == "email-999"


# ---------------------------------------------------------------------------
# 10. Empty source_filename
# ---------------------------------------------------------------------------

class TestEmptySourceFilename:
    def test_empty_string_filename_raises(self):
        payload = _make_minimal_email_data(source_filename="")
        with pytest.raises(ValidationError):
            EmailData(**payload)

    def test_whitespace_only_filename_raises(self):
        payload = _make_minimal_email_data(source_filename="\t\n")
        with pytest.raises(ValidationError):
            EmailData(**payload)

    def test_valid_filename_accepted(self):
        payload = _make_minimal_email_data(source_filename="inbox_001.eml")
        data = EmailData(**payload)
        assert data.source_filename == "inbox_001.eml"


# ---------------------------------------------------------------------------
# 11. URL source validation
# ---------------------------------------------------------------------------

class TestURLSourceValidation:
    def test_plain_text_source_valid(self):
        url = ExtractedURL(original_url="http://example.com", source=URLSource.PLAIN_TEXT)
        assert url.source == URLSource.PLAIN_TEXT

    def test_html_href_source_valid(self):
        url = ExtractedURL(
            original_url="http://example.com",
            source=URLSource.HTML_HREF,
            anchor_text="Click here",
        )
        assert url.source == URLSource.HTML_HREF

    def test_html_src_source_valid(self):
        url = ExtractedURL(
            original_url="http://cdn.example.com/img.png",
            source=URLSource.HTML_SRC,
        )
        assert url.source == URLSource.HTML_SRC

    def test_invalid_source_raises(self):
        with pytest.raises(ValidationError):
            ExtractedURL(
                original_url="http://example.com",
                source="javascript_href",  # type: ignore[arg-type]
            )

    def test_url_in_email_data(self):
        """ExtractedURL instances must round-trip correctly within EmailData."""
        payload = _make_minimal_email_data()
        payload["extracted_urls"] = [
            {
                "original_url": "http://phishing.example/login",
                "normalized_url": "http://phishing.example/login",
                "source": "html_href",
                "anchor_text": "Verify your account",
            }
        ]
        data = EmailData(**payload)
        assert len(data.extracted_urls) == 1
        assert data.extracted_urls[0].source == URLSource.HTML_HREF


# ---------------------------------------------------------------------------
# 12. JSON serialisation
# ---------------------------------------------------------------------------

class TestJSONSerialisation:
    def test_model_dump_json_produces_valid_json(self):
        data = EmailData(**_make_minimal_email_data())
        json_str = data.model_dump_json()
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)
        assert parsed["email_id"] == "email-001"

    def test_serialised_json_preserves_nested_structure(self):
        data = EmailData(**_make_minimal_email_data())
        parsed = json.loads(data.model_dump_json())
        # Nested headers
        assert "headers" in parsed
        assert parsed["headers"]["from_address"] == "security@example.com"
        # Nested authentication
        assert "authentication" in parsed
        assert parsed["authentication"]["spf"]["status"] == "pass"
        assert parsed["authentication"]["dmarc"]["status"] == "missing"

    def test_model_dump_produces_dict(self):
        data = EmailData(**_make_minimal_email_data())
        d = data.model_dump()
        assert isinstance(d, dict)
        assert isinstance(d["authentication"], dict)
        assert isinstance(d["headers"], dict)

    def test_serialised_json_round_trips(self):
        """Parse → serialise → re-parse must yield identical objects."""
        original = EmailData(**_make_minimal_email_data())
        json_str = original.model_dump_json()
        restored = EmailData.model_validate_json(json_str)
        assert original.email_id == restored.email_id
        assert original.authentication.spf.status == restored.authentication.spf.status


# ---------------------------------------------------------------------------
# 13. Nested model validation
# ---------------------------------------------------------------------------

class TestNestedModelValidation:
    def test_headers_field_is_required(self):
        """EmailData must reject a payload where 'headers' is absent."""
        payload = _make_minimal_email_data()
        del payload["headers"]
        with pytest.raises(ValidationError):
            EmailData(**payload)

    def test_authentication_field_is_required(self):
        """EmailData must reject a payload where 'authentication' is absent."""
        payload = _make_minimal_email_data()
        del payload["authentication"]
        with pytest.raises(ValidationError):
            EmailData(**payload)

    def test_authentication_spf_required(self):
        """AuthenticationMetadata must require 'spf'."""
        payload = _make_minimal_email_data()
        del payload["authentication"]["spf"]
        with pytest.raises(ValidationError):
            EmailData(**payload)

    def test_authentication_dkim_required(self):
        """AuthenticationMetadata must require 'dkim'."""
        payload = _make_minimal_email_data()
        del payload["authentication"]["dkim"]
        with pytest.raises(ValidationError):
            EmailData(**payload)

    def test_authentication_dmarc_required(self):
        """AuthenticationMetadata must require 'dmarc'."""
        payload = _make_minimal_email_data()
        del payload["authentication"]["dmarc"]
        with pytest.raises(ValidationError):
            EmailData(**payload)

    def test_extra_fields_on_email_data_rejected(self):
        """EmailData must reject unknown extra fields (extra='forbid')."""
        payload = _make_minimal_email_data()
        payload["confidence_score"] = 0.99  # must NOT be in EmailData
        with pytest.raises(ValidationError):
            EmailData(**payload)

    def test_attachment_metadata_validates_inside_email_data(self):
        """Invalid attachment inside EmailData must surface as ValidationError."""
        payload = _make_minimal_email_data()
        payload["attachments"] = [
            {
                "size_bytes": -5,  # invalid
                "disposition": "attachment",
                "status": "processed",
            }
        ]
        with pytest.raises(ValidationError):
            EmailData(**payload)


# ---------------------------------------------------------------------------
# 14. Skipped attachment must include skip_reason
# ---------------------------------------------------------------------------

class TestSkippedAttachmentSkipReason:
    def test_skipped_without_reason_raises(self):
        with pytest.raises(ValidationError):
            AttachmentMetadata(
                size_bytes=0,
                disposition=AttachmentDisposition.ATTACHMENT,
                status=AttachmentStatus.SKIPPED,
                # skip_reason intentionally omitted
            )

    def test_skipped_with_reason_accepted(self):
        att = AttachmentMetadata(
            size_bytes=0,
            disposition=AttachmentDisposition.ATTACHMENT,
            status=AttachmentStatus.SKIPPED,
            skip_reason="Attachment exceeds size limit of 10 MB.",
        )
        assert att.skip_reason == "Attachment exceeds size limit of 10 MB."

    def test_processed_without_skip_reason_accepted(self):
        att = AttachmentMetadata(
            size_bytes=512,
            disposition=AttachmentDisposition.ATTACHMENT,
            status=AttachmentStatus.PROCESSED,
        )
        assert att.skip_reason is None


# ---------------------------------------------------------------------------
# 15. AuthStatus.MISSING is not failure
# ---------------------------------------------------------------------------

class TestMissingIsNotFailure:
    def test_missing_is_distinct_from_fail(self):
        assert AuthStatus.MISSING != AuthStatus.FAIL

    def test_unavailable_is_distinct_from_fail(self):
        assert AuthStatus.UNAVAILABLE != AuthStatus.FAIL

    def test_missing_status_string_value(self):
        assert AuthStatus.MISSING.value == "missing"

    def test_unavailable_status_string_value(self):
        assert AuthStatus.UNAVAILABLE.value == "unavailable"

    def test_email_data_with_all_missing_auth_is_valid(self):
        """An email where all auth checks are 'missing' must still parse successfully."""
        payload = _make_minimal_email_data()
        for key in ("spf", "dkim", "dmarc"):
            payload["authentication"][key]["status"] = "missing"
            payload["authentication"][key]["raw_value"] = None
        data = EmailData(**payload)
        assert data.authentication.spf.status == AuthStatus.MISSING
        assert data.authentication.dkim.status == AuthStatus.MISSING
        assert data.authentication.dmarc.status == AuthStatus.MISSING
