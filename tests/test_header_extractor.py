"""
tests/test_header_extractor.py
-------------------------------
Pytest test suite for app/ingestion/header_extractor.py.

Tests are organised into logical groups matching the task specification.
Synthetic email.message.Message objects are constructed directly (no .eml
files required) so the tests are self-contained and deterministic.

Coverage
--------
1.  Normal email headers
2.  Missing optional headers
3.  Multiple recipients (To / Cc / Bcc)
4.  RFC-2047-encoded subject
5.  Multiple Received headers
6.  Multiple Authentication-Results headers
7.  Multiple Received-SPF headers
8.  Missing SPF, DKIM, and DMARC (status = missing)
9.  SPF pass
10. SPF fail
11. DKIM pass
12. DKIM fail
13. DMARC pass
14. DMARC fail
15. DKIM-Signature present without DKIM authentication result
16. Conflicting authentication results
17. Malformed authentication headers
18. Invalid / missing sender address
19. Repeated headers
20. Empty email message
21. Output validates against existing Pydantic models
22. Security invariants (missing ≠ fail, DKIM-Sig ≠ pass, raw evidence kept)
23. Demonstration scenarios A–E
"""

from __future__ import annotations

import email
import json
import warnings
from email.message import Message

import pytest

from app.ingestion.header_extractor import extract_authentication, extract_headers
from app.schemas import (
    AuthenticationClaim,
    AuthenticationMetadata,
    AuthenticationResult,
    AuthMechanism,
    AuthProvenance,
    AuthStatus,
    EmailData,
    EmailHeaders,
    VerificationStatus,
)


# ---------------------------------------------------------------------------
# Shared builders
# ---------------------------------------------------------------------------

def _make_message(**headers: str) -> Message:
    """
    Build an ``email.message.Message`` from keyword arguments.

    Each keyword becomes a header name (underscores replaced by hyphens when
    the header name requires them — callers pass the exact name as a string
    via ``**{...}`` when needed).

    Example::

        _make_message(**{
            "From": "alice@example.com",
            "Subject": "Hello",
        })
    """
    msg = Message()
    for name, value in headers.items():
        msg[name] = value
    return msg


def _make_message_multi(header_pairs: list[tuple[str, str]]) -> Message:
    """
    Build a Message from an ordered list of (name, value) tuples,
    preserving duplicates (e.g. multiple Received headers).
    """
    msg = Message()
    for name, value in header_pairs:
        msg[name] = value
    return msg


# ---------------------------------------------------------------------------
# 1. Normal email headers
# ---------------------------------------------------------------------------

class TestNormalEmailHeaders:
    def _normal_message(self) -> Message:
        return _make_message_multi([
            ("From", "Alice Sender <alice@example.com>"),
            ("To", "Bob Recipient <bob@example.net>"),
            ("Cc", "carol@example.org"),
            ("Subject", "Account notification"),
            ("Date", "Tue, 10 Nov 2026 10:00:00 +0000"),
            ("Message-ID", "<msg001@example.com>"),
            ("MIME-Version", "1.0"),
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Received", "from mail.example.com by mx.example.net"),
        ])

    def test_from_address_extracted(self):
        msg = self._normal_message()
        headers = extract_headers(msg)
        assert headers.from_address is not None
        assert "alice@example.com" in headers.from_address

    def test_to_extracted(self):
        headers = extract_headers(self._normal_message())
        assert len(headers.to) == 1
        assert "bob@example.net" in headers.to[0]

    def test_cc_extracted(self):
        headers = extract_headers(self._normal_message())
        assert len(headers.cc) == 1
        assert "carol@example.org" in headers.cc[0]

    def test_subject_extracted(self):
        headers = extract_headers(self._normal_message())
        assert headers.subject == "Account notification"

    def test_date_extracted(self):
        headers = extract_headers(self._normal_message())
        assert headers.date is not None
        assert "2026" in headers.date

    def test_message_id_extracted(self):
        headers = extract_headers(self._normal_message())
        assert headers.message_id is not None
        assert "msg001" in headers.message_id

    def test_mime_version_extracted(self):
        headers = extract_headers(self._normal_message())
        assert headers.mime_version == "1.0"

    def test_content_type_extracted(self):
        headers = extract_headers(self._normal_message())
        assert headers.content_type is not None
        assert "text/plain" in headers.content_type

    def test_received_extracted(self):
        headers = extract_headers(self._normal_message())
        assert len(headers.received) == 1

    def test_output_is_email_headers_instance(self):
        headers = extract_headers(self._normal_message())
        assert isinstance(headers, EmailHeaders)

    def test_output_validates_as_pydantic_model(self):
        headers = extract_headers(self._normal_message())
        # Re-validate through model (must not raise)
        EmailHeaders.model_validate(headers.model_dump())


# ---------------------------------------------------------------------------
# 2. Missing optional headers
# ---------------------------------------------------------------------------

class TestMissingOptionalHeaders:
    def test_empty_message_returns_empty_headers(self):
        msg = Message()
        headers = extract_headers(msg)
        assert headers.from_address is None
        assert headers.to == []
        assert headers.cc == []
        assert headers.bcc == []
        assert headers.reply_to is None
        assert headers.return_path is None
        assert headers.subject is None
        assert headers.date is None
        assert headers.message_id is None
        assert headers.mime_version is None
        assert headers.content_type is None

    def test_missing_reply_to_is_none(self):
        msg = _make_message(**{"From": "a@b.com"})
        headers = extract_headers(msg)
        assert headers.reply_to is None

    def test_missing_bcc_is_empty_list(self):
        msg = _make_message(**{"From": "a@b.com", "To": "b@c.com"})
        headers = extract_headers(msg)
        assert headers.bcc == []

    def test_missing_received_is_empty_list(self):
        msg = _make_message(**{"From": "a@b.com"})
        headers = extract_headers(msg)
        assert headers.received == []

    def test_missing_dkim_signature_is_empty_list(self):
        msg = _make_message(**{"From": "a@b.com"})
        headers = extract_headers(msg)
        assert headers.dkim_signature == []

    def test_missing_authentication_results_is_empty_list(self):
        msg = _make_message(**{"From": "a@b.com"})
        headers = extract_headers(msg)
        assert headers.authentication_results == []


# ---------------------------------------------------------------------------
# 3. Multiple recipients
# ---------------------------------------------------------------------------

class TestMultipleRecipients:
    def test_multiple_to_addresses(self):
        msg = _make_message(**{
            "From": "sender@example.com",
            "To": "alice@example.com, bob@example.net, carol@example.org",
        })
        headers = extract_headers(msg)
        assert len(headers.to) == 3

    def test_multiple_cc_addresses(self):
        msg = _make_message(**{
            "Cc": "x@a.com, y@b.com",
        })
        headers = extract_headers(msg)
        assert len(headers.cc) == 2

    def test_bcc_present(self):
        msg = _make_message(**{
            "Bcc": "hidden@example.com",
        })
        headers = extract_headers(msg)
        assert len(headers.bcc) == 1
        assert "hidden@example.com" in headers.bcc[0]

    def test_to_with_display_names(self):
        msg = _make_message(**{
            "To": '"Alice" <alice@a.com>, "Bob" <bob@b.com>',
        })
        headers = extract_headers(msg)
        assert len(headers.to) == 2
        assert any("alice@a.com" in addr for addr in headers.to)
        assert any("bob@b.com" in addr for addr in headers.to)


# ---------------------------------------------------------------------------
# 4. Encoded subject
# ---------------------------------------------------------------------------

class TestEncodedSubject:
    def test_base64_encoded_subject_decoded(self):
        # =?UTF-8?B?SGVsbG8gV29ybGQ=?= decodes to "Hello World"
        msg = _make_message(**{"Subject": "=?UTF-8?B?SGVsbG8gV29ybGQ=?="})
        headers = extract_headers(msg)
        assert headers.subject == "Hello World"

    def test_qp_encoded_subject_decoded(self):
        # =?UTF-8?Q?Test_=E2=82=AC_Subject?= decodes to "Test € Subject"
        msg = _make_message(**{"Subject": "=?UTF-8?Q?Test_=E2=82=AC_Subject?="})
        headers = extract_headers(msg)
        assert "Test" in headers.subject
        # The euro sign should be present after decoding
        assert "€" in headers.subject or "Subject" in headers.subject

    def test_plain_subject_unchanged(self):
        msg = _make_message(**{"Subject": "Plain subject line"})
        headers = extract_headers(msg)
        assert headers.subject == "Plain subject line"

    def test_missing_subject_is_none(self):
        msg = Message()
        headers = extract_headers(msg)
        assert headers.subject is None


# ---------------------------------------------------------------------------
# 5. Multiple Received headers
# ---------------------------------------------------------------------------

class TestMultipleReceivedHeaders:
    def test_three_received_headers_all_preserved(self):
        msg = _make_message_multi([
            ("Received", "from mx1.example.com by final.example.net; Tue, 10 Nov 2026 10:00:00 +0000"),
            ("Received", "from smtp.relay.com by mx1.example.com; Tue, 10 Nov 2026 09:59:50 +0000"),
            ("Received", "from sender.example.com by smtp.relay.com; Tue, 10 Nov 2026 09:59:40 +0000"),
        ])
        headers = extract_headers(msg)
        assert len(headers.received) == 3

    def test_received_order_preserved(self):
        """Received headers must come back in the same order Message.get_all returns them."""
        pairs = [
            ("Received", "hop-1"),
            ("Received", "hop-2"),
            ("Received", "hop-3"),
        ]
        msg = _make_message_multi(pairs)
        headers = extract_headers(msg)
        assert headers.received == ["hop-1", "hop-2", "hop-3"]


# ---------------------------------------------------------------------------
# 6. Multiple Authentication-Results headers
# ---------------------------------------------------------------------------

class TestMultipleAuthenticationResultsHeaders:
    def test_two_auth_results_both_preserved(self):
        msg = _make_message_multi([
            ("Authentication-Results", "mx.example.com; spf=pass"),
            ("Authentication-Results", "mx.relay.net; dkim=pass header.d=example.com"),
        ])
        headers = extract_headers(msg)
        assert len(headers.authentication_results) == 2

    def test_raw_ar_values_verbatim(self):
        ar1 = "mx.example.com; spf=pass smtp.mailfrom=example.com"
        ar2 = "mx.relay.net; dkim=pass header.d=example.com; dmarc=pass"
        msg = _make_message_multi([
            ("Authentication-Results", ar1),
            ("Authentication-Results", ar2),
        ])
        headers = extract_headers(msg)
        assert ar1 in headers.authentication_results
        assert ar2 in headers.authentication_results


# ---------------------------------------------------------------------------
# 7. Multiple Received-SPF headers
# ---------------------------------------------------------------------------

class TestMultipleReceivedSPFHeaders:
    def test_two_received_spf_both_preserved(self):
        msg = _make_message_multi([
            ("Received-SPF", "pass (domain of example.com designates 1.2.3.4 as permitted)"),
            ("Received-SPF", "none (domain of relay.net: no SPF record)"),
        ])
        headers = extract_headers(msg)
        assert len(headers.received_spf) == 2


# ---------------------------------------------------------------------------
# 8. Missing SPF, DKIM, DMARC
# ---------------------------------------------------------------------------

class TestMissingAuthentication:
    def test_all_missing_when_no_auth_headers(self):
        msg = _make_message(**{"From": "a@b.com", "To": "c@d.com"})
        auth = extract_authentication(msg)
        assert auth.spf.status == AuthStatus.MISSING
        assert auth.dkim.status == AuthStatus.MISSING
        assert auth.dmarc.status == AuthStatus.MISSING

    def test_missing_status_not_fail(self):
        msg = Message()
        auth = extract_authentication(msg)
        assert auth.spf.status != AuthStatus.FAIL
        assert auth.dkim.status != AuthStatus.FAIL
        assert auth.dmarc.status != AuthStatus.FAIL

    def test_missing_raw_value_is_none(self):
        msg = Message()
        auth = extract_authentication(msg)
        assert auth.spf.raw_value is None
        assert auth.dkim.raw_value is None
        assert auth.dmarc.raw_value is None

    def test_output_is_authentication_metadata_instance(self):
        msg = Message()
        auth = extract_authentication(msg)
        assert isinstance(auth, AuthenticationMetadata)

    def test_mechanisms_correct(self):
        msg = Message()
        auth = extract_authentication(msg)
        assert auth.spf.mechanism == AuthMechanism.SPF
        assert auth.dkim.mechanism == AuthMechanism.DKIM
        assert auth.dmarc.mechanism == AuthMechanism.DMARC


# ---------------------------------------------------------------------------
# 9. SPF pass
# ---------------------------------------------------------------------------

class TestSPFPass:
    def test_spf_pass_from_auth_results(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; spf=pass smtp.mailfrom=example.com",
        })
        auth = extract_authentication(msg)
        assert auth.spf.status == AuthStatus.PASS

    def test_spf_pass_raw_value_preserved(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; spf=pass smtp.mailfrom=example.com",
        })
        auth = extract_authentication(msg)
        assert auth.spf.raw_value is not None
        assert "spf=pass" in auth.spf.raw_value.lower()

    def test_spf_pass_from_received_spf(self):
        """SPF pass from Received-SPF when no Authentication-Results header."""
        msg = _make_message(**{
            "Received-SPF": "pass (domain of example.com designates 1.2.3.4 as permitted sender)",
        })
        auth = extract_authentication(msg)
        assert auth.spf.status == AuthStatus.PASS

    def test_spf_pass_mechanism_is_spf(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; spf=pass",
        })
        auth = extract_authentication(msg)
        assert auth.spf.mechanism == AuthMechanism.SPF


# ---------------------------------------------------------------------------
# 10. SPF fail
# ---------------------------------------------------------------------------

class TestSPFFail:
    def test_spf_fail_from_auth_results(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; spf=fail (not authorised)",
        })
        auth = extract_authentication(msg)
        assert auth.spf.status == AuthStatus.FAIL

    def test_spf_fail_from_received_spf(self):
        msg = _make_message(**{
            "Received-SPF": "fail (domain of example.com does not designate 5.6.7.8)",
        })
        auth = extract_authentication(msg)
        assert auth.spf.status == AuthStatus.FAIL

    def test_spf_fail_raw_value_preserved(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; spf=fail smtp.mailfrom=attacker.com",
        })
        auth = extract_authentication(msg)
        assert auth.spf.raw_value is not None
        assert "spf=fail" in auth.spf.raw_value.lower()

    def test_spf_fail_is_not_missing(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; spf=fail",
        })
        auth = extract_authentication(msg)
        assert auth.spf.status != AuthStatus.MISSING


# ---------------------------------------------------------------------------
# 11. DKIM pass
# ---------------------------------------------------------------------------

class TestDKIMPass:
    def test_dkim_pass_from_auth_results(self):
        msg = _make_message(**{
            "Authentication-Results": (
                "mx.example.net; spf=pass; dkim=pass header.d=example.com; dmarc=pass"
            ),
        })
        auth = extract_authentication(msg)
        assert auth.dkim.status == AuthStatus.PASS

    def test_dkim_pass_raw_value_contains_fragment(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; dkim=pass header.d=example.com",
        })
        auth = extract_authentication(msg)
        assert auth.dkim.raw_value is not None
        assert "dkim=pass" in auth.dkim.raw_value.lower()

    def test_dkim_mechanism_is_dkim(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; dkim=pass",
        })
        auth = extract_authentication(msg)
        assert auth.dkim.mechanism == AuthMechanism.DKIM


# ---------------------------------------------------------------------------
# 12. DKIM fail
# ---------------------------------------------------------------------------

class TestDKIMFail:
    def test_dkim_fail_from_auth_results(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; dkim=fail (bad signature)",
        })
        auth = extract_authentication(msg)
        assert auth.dkim.status == AuthStatus.FAIL

    def test_dkim_fail_raw_value_preserved(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; dkim=fail",
        })
        auth = extract_authentication(msg)
        assert auth.dkim.raw_value is not None
        assert "dkim=fail" in auth.dkim.raw_value.lower()

    def test_dkim_temperror(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; dkim=temperror",
        })
        auth = extract_authentication(msg)
        assert auth.dkim.status == AuthStatus.TEMPERROR


# ---------------------------------------------------------------------------
# 13. DMARC pass
# ---------------------------------------------------------------------------

class TestDMARCPass:
    def test_dmarc_pass_from_auth_results(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; spf=pass; dkim=pass; dmarc=pass",
        })
        auth = extract_authentication(msg)
        assert auth.dmarc.status == AuthStatus.PASS

    def test_dmarc_pass_raw_value_preserved(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; dmarc=pass",
        })
        auth = extract_authentication(msg)
        assert auth.dmarc.raw_value is not None
        assert "dmarc=pass" in auth.dmarc.raw_value.lower()

    def test_dmarc_mechanism_is_dmarc(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; dmarc=pass",
        })
        auth = extract_authentication(msg)
        assert auth.dmarc.mechanism == AuthMechanism.DMARC


# ---------------------------------------------------------------------------
# 14. DMARC fail
# ---------------------------------------------------------------------------

class TestDMARCFail:
    def test_dmarc_fail_from_auth_results(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; dmarc=fail",
        })
        auth = extract_authentication(msg)
        assert auth.dmarc.status == AuthStatus.FAIL

    def test_dmarc_fail_raw_value_preserved(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; dmarc=fail (p=reject)",
        })
        auth = extract_authentication(msg)
        assert auth.dmarc.raw_value is not None
        assert "dmarc=fail" in auth.dmarc.raw_value.lower()


# ---------------------------------------------------------------------------
# 15. DKIM-Signature present without DKIM authentication result
# ---------------------------------------------------------------------------

class TestDKIMSignatureWithoutAuthResult:
    """
    Critical security invariant:
    The presence of a DKIM-Signature header MUST NOT produce AuthStatus.PASS.
    """

    def test_dkim_signature_header_does_not_produce_pass(self):
        msg = _make_message(**{
            "DKIM-Signature": (
                "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; "
                "s=default; h=from:to:subject; bh=abc123; b=XYZ..."
            ),
        })
        auth = extract_authentication(msg)
        assert auth.dkim.status != AuthStatus.PASS

    def test_dkim_signature_present_but_status_is_missing(self):
        msg = _make_message(**{
            "DKIM-Signature": "v=1; a=rsa-sha256; d=example.com; s=default;",
        })
        auth = extract_authentication(msg)
        # No Authentication-Results → status must be missing
        assert auth.dkim.status == AuthStatus.MISSING

    def test_dkim_signature_header_captured_in_email_headers(self):
        sig = "v=1; a=rsa-sha256; d=example.com; s=default; b=FAKE=="
        msg = _make_message(**{"DKIM-Signature": sig})
        headers = extract_headers(msg)
        assert len(headers.dkim_signature) == 1
        assert headers.dkim_signature[0] == sig

    def test_dkim_signature_in_headers_and_fail_in_auth_results(self):
        """Signature present + Authentication-Results says fail → still fail."""
        msg = _make_message_multi([
            ("DKIM-Signature", "v=1; a=rsa-sha256; d=example.com; s=default;"),
            ("Authentication-Results", "mx.example.net; dkim=fail (signature mismatch)"),
        ])
        auth = extract_authentication(msg)
        assert auth.dkim.status == AuthStatus.FAIL


# ---------------------------------------------------------------------------
# 16. Conflicting authentication results
# ---------------------------------------------------------------------------

class TestConflictingAuthenticationResults:
    """
    When multiple Authentication-Results headers carry conflicting results for
    the same mechanism, the extractor MUST NOT silently pick the most favourable
    result.  It signals ambiguity with AuthStatus.OTHER.
    """

    def test_conflicting_spf_produces_other(self):
        msg = _make_message_multi([
            ("Authentication-Results", "mx.inner.example.com; spf=pass"),
            ("Authentication-Results", "mx.outer.example.com; spf=fail"),
        ])
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            auth = extract_authentication(msg)
        assert auth.spf.status == AuthStatus.OTHER

    def test_conflicting_dkim_produces_other(self):
        msg = _make_message_multi([
            ("Authentication-Results", "mx.a.example.com; dkim=pass"),
            ("Authentication-Results", "mx.b.example.com; dkim=fail"),
        ])
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            auth = extract_authentication(msg)
        assert auth.dkim.status == AuthStatus.OTHER

    def test_conflicting_dmarc_produces_other(self):
        msg = _make_message_multi([
            ("Authentication-Results", "mx.a.com; dmarc=pass"),
            ("Authentication-Results", "mx.b.com; dmarc=fail"),
        ])
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            auth = extract_authentication(msg)
        assert auth.dmarc.status == AuthStatus.OTHER

    def test_conflict_does_not_produce_pass(self):
        """Conflicting evidence must NEVER silently become a pass result."""
        msg = _make_message_multi([
            ("Authentication-Results", "mx.a.com; spf=pass"),
            ("Authentication-Results", "mx.b.com; spf=fail"),
        ])
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            auth = extract_authentication(msg)
        assert auth.spf.status != AuthStatus.PASS

    def test_duplicate_identical_results_not_conflict(self):
        """Two headers reporting the same result should NOT be flagged as conflicting."""
        msg = _make_message_multi([
            ("Authentication-Results", "mx.a.com; spf=pass"),
            ("Authentication-Results", "mx.b.com; spf=pass"),
        ])
        auth = extract_authentication(msg)
        assert auth.spf.status == AuthStatus.PASS

    def test_conflict_raw_value_contains_evidence(self):
        """Raw value must preserve evidence from both conflicting results."""
        msg = _make_message_multi([
            ("Authentication-Results", "mx.a.com; spf=pass"),
            ("Authentication-Results", "mx.b.com; spf=fail"),
        ])
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            auth = extract_authentication(msg)
        assert auth.spf.raw_value is not None
        assert "spf=pass" in auth.spf.raw_value.lower()
        assert "spf=fail" in auth.spf.raw_value.lower()


# ---------------------------------------------------------------------------
# 17. Malformed authentication headers
# ---------------------------------------------------------------------------

class TestMalformedAuthenticationHeaders:
    def test_garbage_auth_results_gives_missing(self):
        """Completely unparseable Authentication-Results → missing (no match)."""
        msg = _make_message(**{
            "Authentication-Results": ";;;=invalid junk here===",
        })
        auth = extract_authentication(msg)
        # No recognisable mechanism result → missing
        assert auth.spf.status == AuthStatus.MISSING
        assert auth.dkim.status == AuthStatus.MISSING
        assert auth.dmarc.status == AuthStatus.MISSING

    def test_partial_auth_results_extracts_known_parts(self):
        """A malformed header that still contains a recognisable fragment."""
        msg = _make_message(**{
            "Authentication-Results": "GARBAGE; spf=pass; ===BROKEN===",
        })
        auth = extract_authentication(msg)
        assert auth.spf.status == AuthStatus.PASS
        # DKIM/DMARC absent → missing
        assert auth.dkim.status == AuthStatus.MISSING
        assert auth.dmarc.status == AuthStatus.MISSING

    def test_malformed_received_spf_gives_unavailable(self):
        """Received-SPF present but doesn't start with a known keyword."""
        msg = _make_message(**{
            "Received-SPF": "BROKEN HEADER VALUE with no keyword",
        })
        auth = extract_authentication(msg)
        # SPF header present but cannot be reliably parsed
        assert auth.spf.status == AuthStatus.UNAVAILABLE

    def test_does_not_crash_on_empty_auth_results(self):
        """Empty Authentication-Results header must not raise."""
        msg = _make_message(**{"Authentication-Results": ""})
        auth = extract_authentication(msg)
        assert isinstance(auth, AuthenticationMetadata)

    def test_does_not_crash_on_whitespace_auth_results(self):
        msg = _make_message(**{"Authentication-Results": "   "})
        auth = extract_authentication(msg)
        assert isinstance(auth, AuthenticationMetadata)


# ---------------------------------------------------------------------------
# 18. Invalid or missing sender address
# ---------------------------------------------------------------------------

class TestInvalidSenderAddress:
    def test_missing_from_header_is_none(self):
        msg = _make_message(**{"To": "someone@example.com"})
        headers = extract_headers(msg)
        assert headers.from_address is None

    def test_empty_from_header_is_none(self):
        msg = _make_message(**{"From": ""})
        headers = extract_headers(msg)
        assert headers.from_address is None

    def test_malformed_from_header_does_not_crash(self):
        msg = _make_message(**{"From": "not-an-email-address!!!"})
        headers = extract_headers(msg)
        # Must not raise; value may be preserved as-is or None
        assert isinstance(headers, EmailHeaders)

    def test_display_name_only_from_header(self):
        """A From header with a display name but no angle-bracket address."""
        msg = _make_message(**{"From": "No Address Here"})
        headers = extract_headers(msg)
        # Must not crash; from_address may be None or the raw string
        assert isinstance(headers, EmailHeaders)

    def test_valid_from_address_preserved(self):
        msg = _make_message(**{"From": "sender@domain.com"})
        headers = extract_headers(msg)
        assert headers.from_address is not None
        assert "sender@domain.com" in headers.from_address


# ---------------------------------------------------------------------------
# 19. Repeated headers (generic)
# ---------------------------------------------------------------------------

class TestRepeatedHeaders:
    def test_multiple_dkim_signatures_all_captured(self):
        msg = _make_message_multi([
            ("DKIM-Signature", "v=1; d=domain1.com; s=s1; b=AAAA"),
            ("DKIM-Signature", "v=1; d=domain2.com; s=s2; b=BBBB"),
        ])
        headers = extract_headers(msg)
        assert len(headers.dkim_signature) == 2

    def test_multiple_received_spf_all_captured(self):
        msg = _make_message_multi([
            ("Received-SPF", "pass (example.com)"),
            ("Received-SPF", "none (relay.net)"),
        ])
        headers = extract_headers(msg)
        assert len(headers.received_spf) == 2


# ---------------------------------------------------------------------------
# 20. Empty email message
# ---------------------------------------------------------------------------

class TestEmptyEmailMessage:
    def test_extract_headers_on_empty_message(self):
        msg = Message()
        headers = extract_headers(msg)
        assert isinstance(headers, EmailHeaders)
        assert headers.from_address is None
        assert headers.to == []
        assert headers.received == []
        assert headers.authentication_results == []

    def test_extract_authentication_on_empty_message(self):
        msg = Message()
        auth = extract_authentication(msg)
        assert isinstance(auth, AuthenticationMetadata)
        assert auth.spf.status == AuthStatus.MISSING
        assert auth.dkim.status == AuthStatus.MISSING
        assert auth.dmarc.status == AuthStatus.MISSING


# ---------------------------------------------------------------------------
# 21. Output validates against existing Pydantic models
# ---------------------------------------------------------------------------

class TestOutputValidation:
    def test_email_headers_model_dump_json_round_trips(self):
        msg = _make_message_multi([
            ("From", "alice@example.com"),
            ("To", "bob@example.net, carol@example.org"),
            ("Subject", "Test round-trip"),
            ("Authentication-Results", "mx.example.net; spf=pass; dkim=pass; dmarc=pass"),
            ("Received", "from mail.example.com by mx.example.net"),
            ("Received", "from sender.example.com by mail.example.com"),
        ])
        headers = extract_headers(msg)
        json_str = headers.model_dump_json()
        restored = EmailHeaders.model_validate_json(json_str)
        assert restored.from_address == headers.from_address
        assert restored.to == headers.to
        assert restored.received == headers.received
        assert restored.authentication_results == headers.authentication_results

    def test_auth_metadata_model_dump_json_round_trips(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; spf=pass; dkim=pass; dmarc=pass",
        })
        auth = extract_authentication(msg)
        json_str = auth.model_dump_json()
        restored = AuthenticationMetadata.model_validate_json(json_str)
        assert restored.spf.status == auth.spf.status
        assert restored.dkim.status == auth.dkim.status
        assert restored.dmarc.status == auth.dmarc.status

    def test_email_headers_extra_fields_rejected(self):
        """EmailHeaders schema uses extra='forbid'; ensure extractor doesn't add fields."""
        from pydantic import ValidationError
        msg = _make_message(**{"From": "a@b.com"})
        headers = extract_headers(msg)
        d = headers.model_dump()
        d["unexpected_field"] = "oops"
        with pytest.raises(ValidationError):
            EmailHeaders(**d)


# ---------------------------------------------------------------------------
# 22. Security invariants
# ---------------------------------------------------------------------------

class TestSecurityInvariants:
    def test_missing_never_equals_fail(self):
        assert AuthStatus.MISSING != AuthStatus.FAIL

    def test_unavailable_never_equals_fail(self):
        assert AuthStatus.UNAVAILABLE != AuthStatus.FAIL

    def test_dkim_signature_header_alone_never_produces_pass(self):
        for sig in [
            "v=1; a=rsa-sha256; d=example.com; s=default; b=REAL==",
            "v=1; a=ed25519-sha256; d=example.com; s=ed; b=FAKE",
        ]:
            msg = _make_message(**{"DKIM-Signature": sig})
            auth = extract_authentication(msg)
            assert auth.dkim.status != AuthStatus.PASS, (
                f"DKIM-Signature header {sig!r} must not yield DKIM pass"
            )

    def test_raw_spf_evidence_always_preserved_on_pass(self):
        msg = _make_message(**{"Authentication-Results": "mx.example.net; spf=pass"})
        auth = extract_authentication(msg)
        assert auth.spf.raw_value is not None

    def test_raw_dkim_evidence_always_preserved_on_fail(self):
        msg = _make_message(**{"Authentication-Results": "mx.example.net; dkim=fail"})
        auth = extract_authentication(msg)
        assert auth.dkim.raw_value is not None

    def test_conflicting_evidence_not_discarded(self):
        msg = _make_message_multi([
            ("Authentication-Results", "mx.a.com; spf=pass"),
            ("Authentication-Results", "mx.b.com; spf=fail"),
        ])
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            auth = extract_authentication(msg)
        # Raw value must contain BOTH fragments
        assert auth.spf.raw_value is not None
        assert "pass" in auth.spf.raw_value.lower()
        assert "fail" in auth.spf.raw_value.lower()

    def test_no_risk_score_or_classification_in_output(self):
        """The extraction output must not carry any phishing-classification data."""
        msg = _make_message(**{"From": "a@b.com"})
        headers = extract_headers(msg)
        auth = extract_authentication(msg)
        # EmailHeaders must not have extra classification fields
        h_keys = set(headers.model_dump().keys())
        forbidden = {"risk_score", "confidence", "is_phishing", "trust_score", "label"}
        assert not (h_keys & forbidden)
        a_keys = set(auth.model_dump().keys())
        assert not (a_keys & forbidden)


# ---------------------------------------------------------------------------
# 23. Demonstration scenarios A–E
# ---------------------------------------------------------------------------

def _build_scenario_a() -> Message:
    """A. Normal email with all authentication passing."""
    return _make_message_multi([
        ("From", "security@trusted-bank.com"),
        ("To", "customer@example.net"),
        ("Subject", "Your monthly statement is ready"),
        ("Date", "Wed, 11 Nov 2026 09:00:00 +0000"),
        ("Message-ID", "<stmt-nov2026@trusted-bank.com>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
        ("Received", "from smtp.trusted-bank.com by mx.example.net; Wed, 11 Nov 2026 09:00:00 +0000"),
        ("Authentication-Results", "mx.example.net; spf=pass smtp.mailfrom=trusted-bank.com; dkim=pass header.d=trusted-bank.com; dmarc=pass"),
        ("Received-SPF", "pass (domain of trusted-bank.com designates 203.0.113.5 as permitted sender)"),
        ("DKIM-Signature", "v=1; a=rsa-sha256; c=relaxed/relaxed; d=trusted-bank.com; s=mail2026; h=from:to:subject:date; bh=BASE64HASH==; b=VALIDBASE64SIG=="),
    ])


def _build_scenario_b() -> Message:
    """B. Email with authentication failing."""
    return _make_message_multi([
        ("From", "security@trusted-bank.com"),
        ("To", "victim@example.net"),
        ("Subject", "Urgent: Your account has been compromised!"),
        ("Date", "Wed, 11 Nov 2026 10:30:00 +0000"),
        ("Message-ID", "<phish-001@evil-domain.com>"),
        ("Received", "from smtp.evil-domain.com by mx.example.net; Wed, 11 Nov 2026 10:30:00 +0000"),
        ("Authentication-Results", "mx.example.net; spf=fail smtp.mailfrom=evil-domain.com; dkim=fail (bad signature); dmarc=fail"),
        ("Received-SPF", "fail (domain of trusted-bank.com does not designate 198.51.100.7 as permitted sender)"),
    ])


def _build_scenario_c() -> Message:
    """C. Email with missing authentication headers entirely."""
    return _make_message_multi([
        ("From", "newsletter@old-system.example"),
        ("To", "subscriber@example.org"),
        ("Subject", "Monthly digest"),
        ("Date", "Tue, 10 Nov 2026 08:00:00 +0000"),
        ("Message-ID", "<digest-001@old-system.example>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain"),
        ("Received", "from mail.old-system.example by mx.example.org"),
    ])


def _build_scenario_d() -> Message:
    """D. Email with DKIM-Signature present but no DKIM pass result in Authentication-Results."""
    return _make_message_multi([
        ("From", "sender@example.com"),
        ("To", "recipient@example.net"),
        ("Subject", "Signed but not verified"),
        ("Received", "from mail.example.com by mx.example.net"),
        ("DKIM-Signature", "v=1; a=rsa-sha256; d=example.com; s=default; b=PLACEHOLDER=="),
        # No Authentication-Results → no DKIM verification result
    ])


def _build_scenario_e() -> Message:
    """E. Email with conflicting authentication results across two AR headers."""
    return _make_message_multi([
        ("From", "attacker@example.com"),
        ("To", "target@example.net"),
        ("Subject", "Conflicting auth evidence"),
        ("Received", "from inner.relay.example.com by mx.example.net"),
        ("Received", "from smtp.attacker.com by inner.relay.example.com"),
        # First AR header (injected by an internal hop) says pass
        ("Authentication-Results", "inner.relay.example.com; spf=pass; dkim=pass"),
        # Second AR header (added by the border MX) says fail
        ("Authentication-Results", "mx.example.net; spf=fail; dkim=fail; dmarc=fail"),
    ])


class TestDemonstrationScenarios:
    """
    Run all demonstration scenarios through extract_headers + extract_authentication
    and assert the expected behaviours documented in the task spec.
    """

    # --- A: all passing ---

    def test_scenario_a_spf_pass(self):
        auth = extract_authentication(_build_scenario_a())
        assert auth.spf.status == AuthStatus.PASS

    def test_scenario_a_dkim_pass(self):
        auth = extract_authentication(_build_scenario_a())
        assert auth.dkim.status == AuthStatus.PASS

    def test_scenario_a_dmarc_pass(self):
        auth = extract_authentication(_build_scenario_a())
        assert auth.dmarc.status == AuthStatus.PASS

    def test_scenario_a_headers_complete(self):
        headers = extract_headers(_build_scenario_a())
        assert "trusted-bank.com" in (headers.from_address or "")
        assert len(headers.authentication_results) == 1
        assert len(headers.received_spf) == 1
        assert len(headers.dkim_signature) == 1

    # --- B: all failing ---

    def test_scenario_b_spf_fail(self):
        auth = extract_authentication(_build_scenario_b())
        assert auth.spf.status == AuthStatus.FAIL

    def test_scenario_b_dkim_fail(self):
        auth = extract_authentication(_build_scenario_b())
        assert auth.dkim.status == AuthStatus.FAIL

    def test_scenario_b_dmarc_fail(self):
        auth = extract_authentication(_build_scenario_b())
        assert auth.dmarc.status == AuthStatus.FAIL

    # --- C: all missing ---

    def test_scenario_c_spf_missing(self):
        auth = extract_authentication(_build_scenario_c())
        assert auth.spf.status == AuthStatus.MISSING

    def test_scenario_c_dkim_missing(self):
        auth = extract_authentication(_build_scenario_c())
        assert auth.dkim.status == AuthStatus.MISSING

    def test_scenario_c_dmarc_missing(self):
        auth = extract_authentication(_build_scenario_c())
        assert auth.dmarc.status == AuthStatus.MISSING

    def test_scenario_c_missing_not_fail(self):
        auth = extract_authentication(_build_scenario_c())
        assert auth.spf.status != AuthStatus.FAIL
        assert auth.dkim.status != AuthStatus.FAIL
        assert auth.dmarc.status != AuthStatus.FAIL

    # --- D: DKIM-Signature present, no DKIM AR result ---

    def test_scenario_d_dkim_signature_in_headers(self):
        headers = extract_headers(_build_scenario_d())
        assert len(headers.dkim_signature) == 1

    def test_scenario_d_dkim_status_is_missing_not_pass(self):
        auth = extract_authentication(_build_scenario_d())
        assert auth.dkim.status == AuthStatus.MISSING

    def test_scenario_d_dkim_status_is_not_pass(self):
        auth = extract_authentication(_build_scenario_d())
        assert auth.dkim.status != AuthStatus.PASS

    # --- E: conflicting auth results ---

    def test_scenario_e_spf_conflict_produces_other(self):
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            auth = extract_authentication(_build_scenario_e())
        assert auth.spf.status == AuthStatus.OTHER

    def test_scenario_e_dkim_conflict_produces_other(self):
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            auth = extract_authentication(_build_scenario_e())
        assert auth.dkim.status == AuthStatus.OTHER

    def test_scenario_e_conflict_raw_value_has_both_pass_and_fail(self):
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            auth = extract_authentication(_build_scenario_e())
        assert auth.spf.raw_value is not None
        assert "pass" in auth.spf.raw_value.lower()
        assert "fail" in auth.spf.raw_value.lower()

    def test_scenario_e_conflict_does_not_produce_pass(self):
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            auth = extract_authentication(_build_scenario_e())
        assert auth.spf.status != AuthStatus.PASS
        assert auth.dkim.status != AuthStatus.PASS

    def test_scenario_e_all_ar_headers_captured(self):
        headers = extract_headers(_build_scenario_e())
        assert len(headers.authentication_results) == 2


# ---------------------------------------------------------------------------
# Additional edge-case: SPF neutral
# ---------------------------------------------------------------------------

class TestSPFNeutral:
    def test_spf_neutral_from_auth_results(self):
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; spf=neutral",
        })
        auth = extract_authentication(msg)
        assert auth.spf.status == AuthStatus.NEUTRAL

    def test_spf_none_keyword_maps_to_neutral(self):
        """RFC 7208 'none' result means no SPF record — mapped to NEUTRAL."""
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; spf=none",
        })
        auth = extract_authentication(msg)
        assert auth.spf.status == AuthStatus.NEUTRAL


# ---------------------------------------------------------------------------
# Additional edge-case: Return-Path and Reply-To
# ---------------------------------------------------------------------------

class TestReturnPathAndReplyTo:
    def test_return_path_extracted(self):
        msg = _make_message(**{
            "Return-Path": "<bounce@example.com>",
        })
        headers = extract_headers(msg)
        assert headers.return_path is not None
        assert "bounce@example.com" in headers.return_path

    def test_reply_to_extracted(self):
        msg = _make_message(**{
            "Reply-To": "support@helpdesk.example.com",
        })
        headers = extract_headers(msg)
        assert headers.reply_to is not None
        assert "support@helpdesk.example.com" in headers.reply_to

    def test_missing_return_path_is_none(self):
        msg = _make_message(**{"From": "a@b.com"})
        headers = extract_headers(msg)
        assert headers.return_path is None


# ---------------------------------------------------------------------------
# Task 3.1: Provenance and Verification Status Tests
# ---------------------------------------------------------------------------

class TestTask31AuthenticationProvenance:
    """
    Tests for Task 3.1:
    1. Single Authentication-Results header reporting pass.
    2. The same result remains unverified.
    3. SPF softfail is preserved.
    4. DKIM pass remains unverified.
    5. DMARC pass remains unverified.
    6. Received-SPF provenance is recorded.
    7. Missing authentication remains missing.
    8. Conflicting authentication results remain distinguishable.
    9. Existing serialization works.
    10. Existing schema tests still pass.
    """

    def test_single_ar_header_reporting_pass_fields(self):
        """1. Single Authentication-Results header reporting pass extracts mechanism, status, raw_value, authserv_id."""
        msg = _make_message(**{
            "Authentication-Results": "mx.company.com; spf=pass",
        })
        auth = extract_authentication(msg)
        assert auth.spf.mechanism == AuthMechanism.SPF
        assert auth.spf.status == AuthStatus.PASS
        assert auth.spf.raw_value == "spf=pass"
        assert auth.spf.provenance == AuthProvenance.AUTHENTICATION_RESULTS_HEADER
        assert auth.spf.authserv_id == "mx.company.com"

    def test_pass_result_remains_unverified(self):
        """2. The same result remains unverified (never verified automatically)."""
        msg = _make_message(**{
            "Authentication-Results": "mx.company.com; spf=pass",
        })
        auth = extract_authentication(msg)
        assert auth.spf.verification_status == VerificationStatus.UNVERIFIED
        assert auth.spf.verification_status != VerificationStatus.VERIFIED

    def test_spf_softfail_preserved_from_auth_results(self):
        """3a. SPF softfail from Authentication-Results is preserved as AuthStatus.SOFTFAIL (not FAIL)."""
        msg = _make_message(**{
            "Authentication-Results": "mx.example.net; spf=softfail smtp.mailfrom=example.com",
        })
        auth = extract_authentication(msg)
        assert auth.spf.status == AuthStatus.SOFTFAIL
        assert auth.spf.status != AuthStatus.FAIL
        assert "softfail" in auth.spf.raw_value.lower()
        assert auth.spf.provenance == AuthProvenance.AUTHENTICATION_RESULTS_HEADER
        assert auth.spf.verification_status == VerificationStatus.UNVERIFIED
        assert auth.spf.authserv_id == "mx.example.net"

    def test_spf_softfail_preserved_from_received_spf(self):
        """3b. SPF softfail from Received-SPF is preserved as AuthStatus.SOFTFAIL (not FAIL)."""
        msg = _make_message(**{
            "Received-SPF": "softfail (domain of example.com does not designate 1.2.3.4)",
        })
        auth = extract_authentication(msg)
        assert auth.spf.status == AuthStatus.SOFTFAIL
        assert auth.spf.status != AuthStatus.FAIL
        assert "softfail" in auth.spf.raw_value.lower()
        assert auth.spf.provenance == AuthProvenance.RECEIVED_SPF_HEADER
        assert auth.spf.verification_status == VerificationStatus.UNVERIFIED
        assert auth.spf.authserv_id is None

    def test_dkim_pass_remains_unverified(self):
        """4. DKIM pass remains unverified."""
        msg = _make_message(**{
            "Authentication-Results": "mx.company.com; dkim=pass header.d=example.com",
        })
        auth = extract_authentication(msg)
        assert auth.dkim.status == AuthStatus.PASS
        assert auth.dkim.provenance == AuthProvenance.AUTHENTICATION_RESULTS_HEADER
        assert auth.dkim.verification_status == VerificationStatus.UNVERIFIED
        assert auth.dkim.verification_status != VerificationStatus.VERIFIED
        assert auth.dkim.authserv_id == "mx.company.com"

    def test_dmarc_pass_remains_unverified(self):
        """5. DMARC pass remains unverified."""
        msg = _make_message(**{
            "Authentication-Results": "mx.company.com; dmarc=pass header.from=example.com",
        })
        auth = extract_authentication(msg)
        assert auth.dmarc.status == AuthStatus.PASS
        assert auth.dmarc.provenance == AuthProvenance.AUTHENTICATION_RESULTS_HEADER
        assert auth.dmarc.verification_status == VerificationStatus.UNVERIFIED
        assert auth.dmarc.verification_status != VerificationStatus.VERIFIED
        assert auth.dmarc.authserv_id == "mx.company.com"

    def test_received_spf_provenance_recorded(self):
        """6. Received-SPF provenance is recorded as received_spf_header."""
        msg = _make_message(**{
            "Received-SPF": "pass (domain of example.com designates 1.2.3.4 as permitted sender)",
        })
        auth = extract_authentication(msg)
        assert auth.spf.status == AuthStatus.PASS
        assert auth.spf.provenance == AuthProvenance.RECEIVED_SPF_HEADER
        assert auth.spf.verification_status == VerificationStatus.UNVERIFIED
        assert auth.spf.authserv_id is None

    def test_missing_authentication_remains_missing(self):
        """7. Missing authentication remains missing with unavailable provenance."""
        msg = _make_message(**{"From": "a@b.com", "To": "c@d.com"})
        auth = extract_authentication(msg)
        assert auth.spf.status == AuthStatus.MISSING
        assert auth.dkim.status == AuthStatus.MISSING
        assert auth.dmarc.status == AuthStatus.MISSING
        assert auth.spf.provenance == AuthProvenance.UNAVAILABLE
        assert auth.dkim.provenance == AuthProvenance.UNAVAILABLE
        assert auth.dmarc.provenance == AuthProvenance.UNAVAILABLE
        assert auth.spf.verification_status == VerificationStatus.UNVERIFIED
        assert auth.spf.authserv_id is None

    def test_conflicting_authentication_results_distinguishable(self):
        """8. Conflicting authentication results remain distinguishable and unverified."""
        msg = _make_message_multi([
            ("Authentication-Results", "mx.inner.example.com; spf=pass"),
            ("Authentication-Results", "mx.outer.example.com; spf=fail"),
        ])
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            auth = extract_authentication(msg)
        assert auth.spf.status == AuthStatus.OTHER
        assert auth.spf.verification_status == VerificationStatus.UNVERIFIED
        assert "spf=pass" in auth.spf.raw_value
        assert "spf=fail" in auth.spf.raw_value
        assert auth.spf.authserv_id is not None
        assert "mx.inner.example.com" in auth.spf.authserv_id
        assert "mx.outer.example.com" in auth.spf.authserv_id

    def test_serialization_round_trip_with_provenance_and_verification(self):
        """9. Existing serialization works and preserves provenance and verification_status."""
        msg = _make_message(**{
            "Authentication-Results": "mx.company.com; spf=pass; dkim=pass; dmarc=pass",
        })
        auth = extract_authentication(msg)
        json_str = auth.model_dump_json()
        data = json.loads(json_str)

        assert data["spf"]["provenance"] == "authentication_results_header"
        assert data["spf"]["verification_status"] == "unverified"
        assert data["spf"]["authserv_id"] == "mx.company.com"

        restored = AuthenticationMetadata.model_validate_json(json_str)
        assert restored.spf.provenance == AuthProvenance.AUTHENTICATION_RESULTS_HEADER
        assert restored.spf.verification_status == VerificationStatus.UNVERIFIED
        assert restored.spf.authserv_id == "mx.company.com"


# ---------------------------------------------------------------------------
# Task 3.2: Granular Authentication Claims and Provenance Tests
# ---------------------------------------------------------------------------

class TestTask32IndividualClaimsAndProvenance:
    """
    Tests for Task 3.2:
    1. Two headers with conflicting SPF results and different authserv-ids.
    2. Two headers with identical SPF results and different authserv-ids.
    3. Three headers with different SPF statuses.
    4. Multiple mechanisms reported by one server.
    5. Multiple mechanisms reported by different servers.
    6. Duplicate identical headers: no claim is discarded.
    7. Multiple Received-SPF headers.
    8. Correct header indexes.
    9. Correct provenance for each claim.
    10. Every extracted claim remains UNVERIFIED.
    11. JSON serialization and deserialization preserve every claim.
    12. Existing summary fields remain backward-compatible.
    13. Legacy EmailData payloads still validate.
    14. Existing schema and header-extraction tests continue passing.
    """

    def test_conflicting_spf_different_authservs_preserves_both_claims(self):
        """1. Two headers with conflicting SPF results and different authserv-ids."""
        msg = _make_message_multi([
            ("Authentication-Results", "relay1.example.com; spf=pass"),
            ("Authentication-Results", "mx.internal.net; spf=fail"),
        ])
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            auth = extract_authentication(msg)

        assert len(auth.claims) == 2
        claim0, claim1 = auth.claims[0], auth.claims[1]

        assert claim0.authserv_id == "relay1.example.com"
        assert claim0.status == AuthStatus.PASS
        assert claim0.header_index == 0
        assert claim0.raw_value == "spf=pass"
        assert claim0.header_raw == "relay1.example.com; spf=pass"

        assert claim1.authserv_id == "mx.internal.net"
        assert claim1.status == AuthStatus.FAIL
        assert claim1.header_index == 1
        assert claim1.raw_value == "spf=fail"
        assert claim1.header_raw == "mx.internal.net; spf=fail"

        # Summary field remains OTHER
        assert auth.spf.status == AuthStatus.OTHER

    def test_identical_spf_different_authservs_preserves_both_claims(self):
        """2. Two headers with identical SPF results and different authserv-ids."""
        msg = _make_message_multi([
            ("Authentication-Results", "relay1.example.com; spf=pass"),
            ("Authentication-Results", "mx.internal.net; spf=pass"),
        ])
        auth = extract_authentication(msg)

        assert len(auth.claims) == 2
        assert auth.claims[0].authserv_id == "relay1.example.com"
        assert auth.claims[0].status == AuthStatus.PASS
        assert auth.claims[1].authserv_id == "mx.internal.net"
        assert auth.claims[1].status == AuthStatus.PASS

        # Neither server is silently discarded in the claims list
        authservs_in_claims = [c.authserv_id for c in auth.claims]
        assert "relay1.example.com" in authservs_in_claims
        assert "mx.internal.net" in authservs_in_claims

        # Summary retains common status PASS and includes both servers
        assert auth.spf.status == AuthStatus.PASS
        assert "relay1.example.com" in auth.spf.authserv_id
        assert "mx.internal.net" in auth.spf.authserv_id

    def test_three_headers_different_spf_statuses(self):
        """3. Three headers with different SPF statuses."""
        msg = _make_message_multi([
            ("Authentication-Results", "relay1.example.com; spf=pass"),
            ("Authentication-Results", "relay2.example.com; spf=neutral"),
            ("Authentication-Results", "mx.internal.net; spf=fail"),
        ])
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            auth = extract_authentication(msg)

        assert len(auth.claims) == 3
        statuses = [c.status for c in auth.claims]
        assert statuses == [AuthStatus.PASS, AuthStatus.NEUTRAL, AuthStatus.FAIL]
        authservs = [c.authserv_id for c in auth.claims]
        assert authservs == ["relay1.example.com", "relay2.example.com", "mx.internal.net"]

        assert auth.spf.status == AuthStatus.OTHER

    def test_multiple_mechanisms_reported_by_one_server(self):
        """4. Multiple mechanisms reported by one server."""
        header_text = "mx.company.com; spf=pass; dkim=pass; dmarc=pass"
        msg = _make_message(**{"Authentication-Results": header_text})
        auth = extract_authentication(msg)

        assert len(auth.claims) == 3
        mechanisms = {c.mechanism for c in auth.claims}
        assert mechanisms == {AuthMechanism.SPF, AuthMechanism.DKIM, AuthMechanism.DMARC}

        for claim in auth.claims:
            assert claim.authserv_id == "mx.company.com"
            assert claim.header_index == 0
            assert claim.header_raw == header_text
            assert claim.status == AuthStatus.PASS
            assert claim.provenance == AuthProvenance.AUTHENTICATION_RESULTS_HEADER

    def test_multiple_mechanisms_reported_by_different_servers(self):
        """5. Multiple mechanisms reported by different servers."""
        msg = _make_message_multi([
            ("Authentication-Results", "relay1.example.com; dkim=pass"),
            ("Authentication-Results", "mx.internal.net; spf=pass; dmarc=pass"),
        ])
        auth = extract_authentication(msg)

        assert len(auth.claims) == 3
        dkim_claim = [c for c in auth.claims if c.mechanism == AuthMechanism.DKIM][0]
        assert dkim_claim.authserv_id == "relay1.example.com"
        assert dkim_claim.header_index == 0

        spf_claim = [c for c in auth.claims if c.mechanism == AuthMechanism.SPF][0]
        assert spf_claim.authserv_id == "mx.internal.net"
        assert spf_claim.header_index == 1

        dmarc_claim = [c for c in auth.claims if c.mechanism == AuthMechanism.DMARC][0]
        assert dmarc_claim.authserv_id == "mx.internal.net"
        assert dmarc_claim.header_index == 1

    def test_duplicate_identical_headers_no_claim_discarded(self):
        """6. Duplicate identical headers: no claim is discarded."""
        msg = _make_message_multi([
            ("Authentication-Results", "mx.company.com; spf=pass"),
            ("Authentication-Results", "mx.company.com; spf=pass"),
        ])
        auth = extract_authentication(msg)

        assert len(auth.claims) == 2
        assert auth.claims[0].header_index == 0
        assert auth.claims[1].header_index == 1
        assert auth.claims[0].status == AuthStatus.PASS
        assert auth.claims[1].status == AuthStatus.PASS
        assert auth.claims[0].authserv_id == "mx.company.com"
        assert auth.claims[1].authserv_id == "mx.company.com"

    def test_multiple_received_spf_headers(self):
        """7. Multiple Received-SPF headers are all extracted as separate claims."""
        msg = _make_message_multi([
            ("Received-SPF", "pass (domain of example.com designates 1.2.3.4)"),
            ("Received-SPF", "softfail (domain of attacker.com does not designate 5.6.7.8)"),
        ])
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            auth = extract_authentication(msg)

        assert len(auth.claims) == 2
        c0, c1 = auth.claims[0], auth.claims[1]
        assert c0.mechanism == AuthMechanism.SPF
        assert c0.status == AuthStatus.PASS
        assert c0.header_index == 0
        assert c0.provenance == AuthProvenance.RECEIVED_SPF_HEADER
        assert c0.authserv_id is None

        assert c1.mechanism == AuthMechanism.SPF
        assert c1.status == AuthStatus.SOFTFAIL
        assert c1.header_index == 1
        assert c1.provenance == AuthProvenance.RECEIVED_SPF_HEADER
        assert c1.authserv_id is None

    def test_correct_header_indexes_across_types(self):
        """8. Correct header indexes tracked independently per header type."""
        msg = _make_message_multi([
            ("Authentication-Results", "mx1.example.com; dkim=pass"),
            ("Authentication-Results", "mx2.example.com; dkim=fail"),
            ("Received-SPF", "pass (mx1)"),
            ("Received-SPF", "neutral (mx2)"),
        ])
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            auth = extract_authentication(msg)

        ar_claims = [c for c in auth.claims if c.provenance == AuthProvenance.AUTHENTICATION_RESULTS_HEADER]
        assert [c.header_index for c in ar_claims] == [0, 1]

        rspf_claims = [c for c in auth.claims if c.provenance == AuthProvenance.RECEIVED_SPF_HEADER]
        assert [c.header_index for c in rspf_claims] == [0, 1]

    def test_correct_provenance_for_each_claim(self):
        """9. Correct provenance for each claim."""
        msg = _make_message_multi([
            ("Authentication-Results", "mx.example.com; spf=pass"),
            ("Received-SPF", "pass (relay.net)"),
        ])
        auth = extract_authentication(msg)

        assert len(auth.claims) == 2
        assert auth.claims[0].provenance == AuthProvenance.AUTHENTICATION_RESULTS_HEADER
        assert auth.claims[1].provenance == AuthProvenance.RECEIVED_SPF_HEADER

    def test_every_extracted_claim_remains_unverified(self):
        """10. Every extracted claim remains UNVERIFIED (never VERIFIED)."""
        msg = _make_message_multi([
            ("Authentication-Results", "mx.company.com; spf=pass; dkim=pass; dmarc=pass"),
            ("Received-SPF", "pass (server.com)"),
        ])
        auth = extract_authentication(msg)

        assert len(auth.claims) == 4
        for claim in auth.claims:
            assert claim.verification_status == VerificationStatus.UNVERIFIED
            assert claim.verification_status != VerificationStatus.VERIFIED

    def test_json_serialization_preserves_every_claim(self):
        """11. JSON serialization and deserialization preserve every claim and field."""
        msg = _make_message_multi([
            ("Authentication-Results", "relay.com; spf=pass; dkim=pass"),
            ("Received-SPF", "pass (relay.com)"),
        ])
        auth = extract_authentication(msg)

        json_str = auth.model_dump_json(indent=2)
        data = json.loads(json_str)

        assert "claims" in data
        assert len(data["claims"]) == 3
        assert data["claims"][0]["mechanism"] == "SPF"
        assert data["claims"][0]["authserv_id"] == "relay.com"
        assert data["claims"][0]["header_index"] == 0

        restored = AuthenticationMetadata.model_validate_json(json_str)
        assert len(restored.claims) == 3
        assert restored.claims[0] == auth.claims[0]
        assert restored.claims[1] == auth.claims[1]
        assert restored.claims[2] == auth.claims[2]

    def test_existing_summary_fields_remain_backward_compatible(self):
        """12. Existing summary fields remain backward-compatible."""
        msg = _make_message(**{
            "Authentication-Results": "mx.company.com; spf=pass; dkim=pass; dmarc=pass",
        })
        auth = extract_authentication(msg)

        assert isinstance(auth.spf, AuthenticationResult)
        assert isinstance(auth.dkim, AuthenticationResult)
        assert isinstance(auth.dmarc, AuthenticationResult)
        assert auth.spf.status == AuthStatus.PASS
        assert auth.dkim.status == AuthStatus.PASS
        assert auth.dmarc.status == AuthStatus.PASS

    def test_legacy_email_data_payload_validates(self):
        """13. Legacy EmailData payloads without 'claims' still validate cleanly."""
        legacy_payload = {
            "email_id": "legacy-task32-001",
            "source_filename": "legacy.eml",
            "headers": {
                "from_address": "sender@example.com",
                "to": ["receiver@example.com"],
            },
            "authentication": {
                "spf": {"mechanism": "SPF", "status": "pass", "raw_value": "spf=pass"},
                "dkim": {"mechanism": "DKIM", "status": "pass", "raw_value": "dkim=pass"},
                "dmarc": {"mechanism": "DMARC", "status": "missing", "raw_value": None},
            },
            "ingestion_timestamp": "2026-11-11T10:00:00Z",
        }
        data = EmailData(**legacy_payload)
        assert data.authentication.claims == []
        assert data.authentication.spf.status == AuthStatus.PASS

    def test_claim_model_extra_fields_forbidden(self):
        """14. AuthenticationClaim forbids extra unexpected fields."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            AuthenticationClaim(
                mechanism=AuthMechanism.SPF,
                status=AuthStatus.PASS,
                header_index=0,
                provenance=AuthProvenance.AUTHENTICATION_RESULTS_HEADER,
                unexpected_field="disallowed",
            )
