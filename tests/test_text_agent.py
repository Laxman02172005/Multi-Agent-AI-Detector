"""
tests/test_text_agent.py
------------------------
Comprehensive test suite for the Text/Body Specialist Agent:
- app.agents.text_agent.analyze_text
- app.agents.text_agent.create_no_body_result
- app.agents.text_agent.TextAgentProcessingError
- app.agents.text_agent.ValidatedTextRecord
- Intent, lure, and urgency extraction
- Obfuscation, zero-width chars, hidden text, and mismatch detection
- Readability, lexical statistics, and generic greetings
- Boundary validation, caller contracts, and fail-closed error handling
- End-to-end integration with email_ingestor
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from unittest.mock import patch

import pytest

from app.agents.text_agent import (
    TextAgentProcessingError,
    ValidatedTextRecord,
    analyze_text,
    create_no_body_result,
)
from app.ingestion.email_ingestor import ingest_email
from app.schemas.email_schema import (
    AuthenticationClaim,
    AuthenticationMetadata,
    AuthenticationResult,
    AuthMechanism,
    AuthProvenance,
    AuthStatus,
    EmailData,
    EmailHeaders,
)
from app.schemas.text_agent_schema import TextAgentResult


def _make_test_email(
    plain_text_body: Optional[str] = None,
    html_body: Optional[str] = None,
    cleaned_text: Optional[str] = None,
    email_id: str = "test-email-text-001",
) -> EmailData:
    headers = EmailHeaders(
        from_address="sender@example.com",
        to=["recipient@example.com"],
        subject="Test Subject",
        date="Wed, 20 Nov 2026 12:00:00 +0000",
        message_id="<msg-001@example.com>",
    )
    auth = AuthenticationMetadata(
        spf=AuthenticationResult(mechanism=AuthMechanism.SPF, status=AuthStatus.MISSING, provenance=AuthProvenance.UNAVAILABLE),
        dkim=AuthenticationResult(mechanism=AuthMechanism.DKIM, status=AuthStatus.MISSING, provenance=AuthProvenance.UNAVAILABLE),
        dmarc=AuthenticationResult(mechanism=AuthMechanism.DMARC, status=AuthStatus.MISSING, provenance=AuthProvenance.UNAVAILABLE),
        claims=[],
    )
    # Default cleaned_text to plain_text_body if not explicitly provided
    if cleaned_text is None and plain_text_body is not None:
        cleaned_text = plain_text_body.strip()

    return EmailData(
        email_id=email_id,
        source_filename="test.eml",
        headers=headers,
        authentication=auth,
        plain_text_body=plain_text_body,
        html_body=html_body,
        cleaned_text=cleaned_text,
        extracted_urls=[],
        attachments=[],
        ingestion_timestamp=datetime.now(timezone.utc),
    )


# ===========================================================================
# 1. No-Body Scenarios (State 1)
# ===========================================================================

class TestNoBodyScenarios:
    def test_state_1_completely_empty_body(self) -> None:
        email = _make_test_email(plain_text_body=None, html_body=None, cleaned_text=None)
        result = analyze_text(email)

        assert isinstance(result, TextAgentResult)
        assert result.status == "success"
        assert result.email_id == "test-email-text-001"
        assert result.features.has_body is False
        assert result.features.has_plain_text is False
        assert result.features.has_html is False
        assert result.features.word_count == 0
        assert result.features.character_count == 0
        assert result.features.html_to_text_ratio is None
        assert result.features.body_entropy is None
        assert result.features.urgency_cue_count == 0
        assert result.features.has_urgency_cues is False

        assert result.availability.avail_has_body is False
        assert result.availability.completeness_total == 0.0
        assert result.evidence.evidence_items == []
        assert result.evidence.omitted_evidence_count == 0

    def test_state_1_whitespace_only_body(self) -> None:
        email = _make_test_email(plain_text_body="   \n\t  ", html_body="", cleaned_text="   ")
        result = analyze_text(email)
        assert result.status == "success"
        assert result.features.has_body is False
        assert result.availability.avail_has_body is False

    def test_state_1_internal_crash_safety(self) -> None:
        email = _make_test_email()
        with patch("app.agents.text_agent.create_no_body_result", side_effect=RuntimeError("Simulated crash")):
            with pytest.raises(TextAgentProcessingError) as exc_info:
                analyze_text(email)
            err = exc_info.value
            assert err.email_id == "test-email-text-001"
            assert isinstance(err.original_exception, RuntimeError)
            assert err.__cause__ is err.original_exception


# ===========================================================================
# 2. Benign Body Scenarios
# ===========================================================================

class TestBenignBodyScenarios:
    def test_clean_meeting_notes(self) -> None:
        body = (
            "Hi team,\n\n"
            "Here are the notes from our morning standup. We discussed the quarterly goals "
            "and finalized the roadmap for next sprint. Let me know if you have questions.\n\n"
            "Best regards,\nAlice"
        )
        email = _make_test_email(plain_text_body=body, cleaned_text=body)
        result = analyze_text(email)

        assert result.status == "success"
        assert result.features.has_body is True
        assert result.features.has_plain_text is True
        assert result.features.has_html is False
        assert result.features.word_count > 25
        assert result.features.character_count > 100
        assert result.features.body_entropy is not None and result.features.body_entropy > 3.0

        # Phishing cues should all be False/0
        assert result.features.has_urgency_cues is False
        assert result.features.urgency_cue_count == 0
        assert result.features.has_credential_lures is False
        assert result.features.has_financial_lures is False
        assert result.features.has_action_lures is False
        assert result.features.has_threat_cues is False
        assert result.features.has_reward_cues is False
        assert result.features.generic_greeting_present is False
        assert result.features.has_hidden_text is False
        assert result.features.has_zero_width_chars is False
        assert result.features.has_excessive_capitalization is False
        assert result.features.has_excessive_punctuation is False

        assert result.availability.avail_has_body is True
        assert result.availability.completeness_total == 1.0


# ===========================================================================
# 3. Urgency, Lure & Intent Detection
# ===========================================================================

class TestIntentAndLures:
    def test_urgency_cues(self) -> None:
        body = "Immediate action required! Your account will be suspended within 24 hours. Act now, this is your final notice."
        email = _make_test_email(plain_text_body=body)
        result = analyze_text(email)

        assert result.features.has_urgency_cues is True
        assert result.features.urgency_cue_count >= 3

    def test_credential_and_financial_lures(self) -> None:
        body = (
            "Please verify your password immediately to confirm your identity. "
            "An overdue invoice of $4,500 requires direct wire transfer to our bank account."
        )
        email = _make_test_email(plain_text_body=body)
        result = analyze_text(email)

        assert result.features.has_credential_lures is True
        assert result.features.credential_lure_count >= 1
        assert result.features.has_financial_lures is True
        assert result.features.financial_lure_count >= 2

    def test_action_and_threat_cues(self) -> None:
        body = (
            "Click here to open the attachment. Failure to respond will result in "
            "legal action by law enforcement and your account will be permanently closed."
        )
        email = _make_test_email(plain_text_body=body)
        result = analyze_text(email)

        assert result.features.has_action_lures is True
        assert result.features.has_threat_cues is True
        assert result.features.threat_cue_count >= 2

    def test_reward_cues(self) -> None:
        body = "Congratulations! You have won the sweepstakes lottery. Claim your cash prize and refund now."
        email = _make_test_email(plain_text_body=body)
        result = analyze_text(email)

        assert result.features.has_reward_cues is True
        assert result.features.reward_cue_count >= 2

    def test_generic_greeting(self) -> None:
        body = "Dear Valued Customer,\n\nWe noticed suspicious activity on your card."
        email = _make_test_email(plain_text_body=body)
        result = analyze_text(email)

        assert result.features.generic_greeting_present is True


# ===========================================================================
# 4. Obfuscation, Zero-Width Chars & Text Mismatch
# ===========================================================================

class TestObfuscationDetection:
    def test_hidden_text_css(self) -> None:
        html_content = (
            "<html><body>"
            "<p>Please review your bill.</p>"
            "<div style='display: none;'>hidden keywords to bypass security filters</div>"
            "<span style='font-size: 0px;'>stealth text</span>"
            "</body></html>"
        )
        email = _make_test_email(html_body=html_content, cleaned_text="Please review your bill.")
        result = analyze_text(email)

        assert result.features.has_hidden_text is True
        assert result.features.hidden_text_count >= 2
        assert any(item.feature_name == "has_hidden_text" for item in result.evidence.evidence_items)

    def test_zero_width_characters(self) -> None:
        # Embed zero-width space (U+200B) inside the word 'password'
        body = "Please update your pass\u200Bword immediately."
        email = _make_test_email(plain_text_body=body)
        result = analyze_text(email)

        assert result.features.has_zero_width_chars is True
        assert result.features.zero_width_char_count == 1
        assert any(item.feature_name == "has_zero_width_chars" for item in result.evidence.evidence_items)

    def test_excessive_capitalization(self) -> None:
        body = "URGENT SECURITY ALERT! YOU MUST ACT IMMEDIATELY TO VERIFY YOUR IDENTITY!"
        email = _make_test_email(plain_text_body=body)
        result = analyze_text(email)

        assert result.features.has_excessive_capitalization is True
        assert result.features.capitalization_ratio > 0.70

    def test_excessive_punctuation(self) -> None:
        body = "Is this really your account??? Please respond immediately!!!!"
        email = _make_test_email(plain_text_body=body)
        result = analyze_text(email)

        assert result.features.has_excessive_punctuation is True
        assert result.features.excessive_punctuation_count >= 2

    def test_plain_html_divergence_mismatch(self) -> None:
        plain = "Here is the delicious chocolate chip cookie recipe we discussed earlier today with sugar and flour."
        html = (
            "<html><body>"
            "<h1>URGENT BANKING SECURITY NOTICE</h1>"
            "<p>Your bank credentials have been compromised. Click here to verify account and reset password.</p>"
            "</body></html>"
        )
        cleaned_html = "URGENT BANKING SECURITY NOTICE. Your bank credentials have been compromised. Click here to verify account and reset password."

        email = _make_test_email(plain_text_body=plain, html_body=html, cleaned_text=cleaned_html)
        result = analyze_text(email)

        assert result.features.has_plain_html_mismatch is True
        assert any(item.feature_name == "has_plain_html_mismatch" for item in result.evidence.evidence_items)


# ===========================================================================
# 5. Boundary Validation, Caller Contracts & Exception Handling
# ===========================================================================

class TestBoundaryValidationAndContracts:
    def test_reject_unrelated_types(self) -> None:
        with pytest.raises(TypeError):
            analyze_text(None)  # type: ignore

        with pytest.raises(TypeError):
            analyze_text("some string")  # type: ignore

        with pytest.raises(TypeError):
            analyze_text({"email_id": "test"})  # type: ignore

    def test_reject_blank_or_whitespace_email_id(self) -> None:
        for bad_id in ["", "   ", "\t\n"]:
            ed = EmailData.model_construct(email_id=bad_id)
            with pytest.raises(ValueError):
                analyze_text(ed)

    def test_preserves_exact_email_id(self) -> None:
        exact_id = "  email-with-boundary-spaces  "
        email = _make_test_email(plain_text_body="Hello world", email_id=exact_id)
        result = analyze_text(email)
        assert result.email_id == exact_id

    def test_corrupted_body_types_fail_fast(self) -> None:
        ed = EmailData.model_construct(email_id="msg-001", plain_text_body=12345)
        with pytest.raises(TypeError):
            analyze_text(ed)

    def test_internal_pipeline_crash_fail_closed(self) -> None:
        email = _make_test_email(plain_text_body="Some normal body text")
        with patch("app.agents.text_agent.execute_text_analysis_pipeline", side_effect=RuntimeError("Pipeline internal error")):
            with pytest.raises(TextAgentProcessingError) as exc_info:
                analyze_text(email)
            err = exc_info.value
            assert err.email_id == "test-email-text-001"
            assert isinstance(err.original_exception, RuntimeError)
            assert "Pipeline internal error" in err.traceback_str


# ===========================================================================
# 6. End-to-End Ingestion Integration
# ===========================================================================

class TestEndToEndIntegration:
    def test_ingest_email_to_analyze_text_roundtrip(self) -> None:
        raw_eml = (
            b"From: security@payroll-alert.com\r\n"
            b"To: employee@company.com\r\n"
            b"Subject: Immediate action: Wire transfer invoice\r\n"
            b"Date: Wed, 20 Nov 2026 12:00:00 +0000\r\n"
            b"Message-ID: <text-integration-001@example.com>\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Dear Valued Customer,\r\n\r\n"
            b"Your account will be suspended immediately unless you verify your password.\r\n"
            b"Please click here to confirm your wire transfer invoice.\r\n"
        )
        email_data = ingest_email(raw_eml, source_filename="sample_phish_body.eml")
        result = analyze_text(email_data)

        assert result.status == "success"
        assert result.features.has_body is True
        assert result.features.has_urgency_cues is True
        assert result.features.has_credential_lures is True
        assert result.features.has_financial_lures is True
        assert result.features.has_action_lures is True
        assert result.features.generic_greeting_present is True

        # Validation roundtrip
        dumped = result.model_dump()
        reconstructed = TextAgentResult.model_validate(dumped)
        assert reconstructed.email_id == result.email_id
        assert reconstructed.features.has_body == result.features.has_body
