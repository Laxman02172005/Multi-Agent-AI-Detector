"""
tests/test_header_agent.py
--------------------------
Comprehensive unit and integration test suite for the Header Agent MVP:
- app.agents.header_agent.analyze_headers
- app.agents.header_agent.classify_ip_address
- app.agents.header_agent.extract_ips_from_hop
- app.agents.header_agent.sanitize_evidence_snippet
- Ingestion-to-Agent end-to-end pipeline
"""

import json
from datetime import datetime, timezone

import pytest

from app.agents.header_agent import (
    analyze_headers,
    classify_ip_address,
    extract_ips_from_hop,
    is_received_hop_malformed,
    sanitize_evidence_snippet,
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
    VerificationStatus,
)
from app.schemas.header_agent_schema import HeaderAgentResult


# ---------------------------------------------------------------------------
# Test Fixture Helpers
# ---------------------------------------------------------------------------

def _make_email_data(
    headers: EmailHeaders,
    auth: AuthenticationMetadata | None = None,
    email_id: str = "test_email_001",
    warnings: list[str] | None = None,
) -> EmailData:
    if auth is None:
        auth = AuthenticationMetadata(
            spf=AuthenticationResult(
                mechanism=AuthMechanism.SPF,
                status=AuthStatus.MISSING,
                provenance=AuthProvenance.UNAVAILABLE,
            ),
            dkim=AuthenticationResult(
                mechanism=AuthMechanism.DKIM,
                status=AuthStatus.MISSING,
                provenance=AuthProvenance.UNAVAILABLE,
            ),
            dmarc=AuthenticationResult(
                mechanism=AuthMechanism.DMARC,
                status=AuthStatus.MISSING,
                provenance=AuthProvenance.UNAVAILABLE,
            ),
            claims=[],
        )
    return EmailData(
        email_id=email_id,
        source_filename="test.eml",
        headers=headers,
        authentication=auth,
        parsing_warnings=warnings or [],
        ingestion_timestamp=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# 1. IP Classification and Extraction Unit Tests
# ---------------------------------------------------------------------------

class TestIPClassification:
    def test_loopback(self):
        assert classify_ip_address("127.0.0.1") == "loopback"
        assert classify_ip_address("::1") == "loopback"

    def test_link_local(self):
        assert classify_ip_address("169.254.1.1") == "link_local"
        assert classify_ip_address("fe80::1") == "link_local"

    def test_multicast(self):
        assert classify_ip_address("224.0.0.1") == "multicast"
        assert classify_ip_address("ff02::1") == "multicast"

    def test_cgnat(self):
        assert classify_ip_address("100.64.0.1") == "cgnat"
        assert classify_ip_address("100.127.255.254") == "cgnat"

    def test_documentation(self):
        assert classify_ip_address("192.0.2.1") == "documentation"
        assert classify_ip_address("198.51.100.25") == "documentation"
        assert classify_ip_address("203.0.113.1") == "documentation"
        assert classify_ip_address("2001:db8::1") == "documentation"

    def test_special_purpose_and_reserved(self):
        assert classify_ip_address("0.0.0.1") == "special_purpose"
        assert classify_ip_address("240.0.0.1") == "special_purpose"
        assert classify_ip_address("192.0.0.1") == "special_purpose"

    def test_rfc1918(self):
        assert classify_ip_address("10.0.0.1") == "rfc1918"
        assert classify_ip_address("172.16.5.4") == "rfc1918"
        assert classify_ip_address("192.168.1.1") == "rfc1918"

    def test_rfc4193(self):
        assert classify_ip_address("fc00::1") == "rfc4193"
        assert classify_ip_address("fd12:3456:789a::1") == "rfc4193"

    def test_global_routable(self):
        assert classify_ip_address("8.8.8.8") == "global_routable"
        assert classify_ip_address("2606:2800:220:1:248:1893:25c8:1946") == "global_routable"


class TestIPExtractionFromHop:
    def test_bracketed_ipv4(self):
        hop = "from mail.example.com (mail.example.com [192.168.1.1]) by mx.google.com"
        ips = extract_ips_from_hop(hop)
        assert ips == ["192.168.1.1"]

    def test_bracketed_ipv6(self):
        hop = "from mail.example.com ([IPv6:2001:db8::1]) by mx.google.com"
        ips = extract_ips_from_hop(hop)
        assert ips == ["2001:db8::1"]

    def test_parenthesized_ip(self):
        hop = "from mail.example.com (10.0.0.5) by mx.google.com"
        ips = extract_ips_from_hop(hop)
        assert ips == ["10.0.0.5"]


class TestSanitizeSnippet:
    def test_control_character_escaping(self):
        raw = "Line1\r\nLine2\tWith Tabs\x00Null"
        sanitized = sanitize_evidence_snippet(raw)
        assert r"\r" in sanitized
        assert r"\n" in sanitized
        assert r"\t" in sanitized
        assert r"\x00" in sanitized

    def test_length_truncation(self):
        long_str = "A" * 300
        sanitized = sanitize_evidence_snippet(long_str, max_len=256)
        assert len(sanitized) == 256
        assert sanitized.endswith("...")


# ---------------------------------------------------------------------------
# 2. Category A: Identity, Address, and Alignment Tests
# ---------------------------------------------------------------------------

class TestCategoryAFeatures:
    def test_clean_sender_and_recipients(self):
        headers = EmailHeaders(
            from_address="Alice Smith <alice@example.com>",
            reply_to="Alice Smith <alice@example.com>",
            return_path="<alice@example.com>",
            to=["bob@company.com", "carol@company.com"],
            cc=["dave@company.com"],
            subject="Status Update",
        )
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.from_present is True
        assert res.features.from_address_count == 1
        assert res.features.from_syntax_valid is True
        assert res.features.reply_to_present is True
        assert res.features.return_path_present is True
        assert res.features.from_reply_to_domain_mismatch is False
        assert res.features.from_return_path_domain_mismatch is False
        assert res.features.display_name_contains_email is False
        assert res.features.display_name_domain_mismatch is None
        assert res.features.recipient_count_to == 2
        assert res.features.recipient_count_cc == 1
        assert res.features.undisclosed_recipients is None
        assert res.features.to_empty_or_missing is None

    def test_missing_from(self):
        headers = EmailHeaders(from_address=None)
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.from_present is False
        assert res.features.from_address_count is None
        assert res.features.from_syntax_valid is None

    def test_malformed_from_syntax(self):
        headers = EmailHeaders(from_address=">>>bad_sender<<<")
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.from_present is True
        assert res.features.from_address_count is None
        assert res.features.from_syntax_valid is False
        assert any(item.feature_name == "from_syntax_valid" for item in res.evidence.evidence_items)

    def test_from_reply_to_mismatch(self):
        headers = EmailHeaders(
            from_address="Support <support@legitimate-bank.com>",
            reply_to="Attacker <phish@evil-server.org>",
        )
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.from_reply_to_domain_mismatch is True
        assert any(item.feature_name == "from_reply_to_domain_mismatch" for item in res.evidence.evidence_items)
        assert any("From/Reply-To domain mismatch" in a for a in res.evidence.observed_anomalies)

    def test_from_return_path_mismatch(self):
        headers = EmailHeaders(
            from_address="Billing <billing@corp.com>",
            return_path="<bounce@spoofed.net>",
        )
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.from_return_path_domain_mismatch is True
        assert any(item.feature_name == "from_return_path_domain_mismatch" for item in res.evidence.evidence_items)

    def test_display_name_spoofing_detection(self):
        headers = EmailHeaders(
            from_address='"PayPal Support <security@paypal.com>" <attacker@phishing-hub.xyz>',
        )
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.display_name_contains_email is True
        assert res.features.display_name_domain_mismatch is True
        assert any(item.feature_name == "display_name_domain_mismatch" for item in res.evidence.evidence_items)
        assert any("Display name spoofing" in a for a in res.evidence.observed_anomalies)

    def test_display_name_matching_email(self):
        headers = EmailHeaders(
            from_address='"alice@example.com" <alice@example.com>',
        )
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.display_name_contains_email is True
        assert res.features.display_name_domain_mismatch is False

    def test_empty_recipient_lists(self):
        headers = EmailHeaders(from_address="user@example.com", to=[], cc=[])
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.recipient_count_to is None
        assert res.features.recipient_count_cc is None
        assert res.availability.avail_to_present is False
        assert res.availability.avail_cc_present is False

    def test_malformed_recipient_tokens(self):
        headers = EmailHeaders(
            from_address="user@example.com",
            to=["<valid@example.com>", "undisclosed-recipients:;"],
        )
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.recipient_count_to == 1
        assert any("To header contained" in w for w in res.warnings)
        assert any(item.feature_name == "recipient_count_to" for item in res.evidence.evidence_items)

    def test_all_malformed_recipient_tokens(self):
        headers = EmailHeaders(
            from_address="user@example.com",
            to=["undisclosed-recipients:;"],
        )
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.recipient_count_to is None
        assert any("To header contained" in w for w in res.warnings)


# ---------------------------------------------------------------------------
# 3. Category B: Routing and Transport Structure Tests
# ---------------------------------------------------------------------------

class TestCategoryBFeatures:
    def test_missing_received_headers(self):
        headers = EmailHeaders(from_address="user@example.com", received=[])
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.received_hop_count == 0
        assert res.features.missing_received_headers is True
        assert res.features.hop_count_anomaly is True
        assert any(item.feature_name == "missing_received_headers" for item in res.evidence.evidence_items)

    def test_private_ip_in_external_hop(self):
        headers = EmailHeaders(
            from_address="user@example.com",
            received=[
                # Hop 0: internal ingress
                "from mx1.example.com by mx.google.com with ESMTPS id abc [8.8.8.8]; Tue, 10 Nov 2026 10:00:00 +0000",
                # Hop 1: external intermediate hop with RFC 1918 private IP
                "from internal.relay (relay.lan [192.168.1.50]) by mx1.example.com; Tue, 10 Nov 2026 09:59:00 +0000",
            ],
        )
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.received_hop_count == 2
        assert res.features.has_private_ip_in_external_hop is True
        assert "192.168.1.50" in res.evidence.detected_anomalous_ips
        assert any(item.feature_name == "has_private_ip_in_external_hop" for item in res.evidence.evidence_items)

    def test_private_ip_in_hop_0_not_flagged_as_external(self):
        # Ingress hop 0 is internal to receiver infrastructure, not external hop
        headers = EmailHeaders(
            from_address="user@example.com",
            received=[
                "from [10.0.0.1] by mx.local with SMTP; Tue, 10 Nov 2026 10:00:00 +0000",
            ],
        )
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.received_hop_count == 1
        assert res.features.has_private_ip_in_external_hop is False

    def test_cgnat_classified_as_special_not_private(self):
        headers = EmailHeaders(
            from_address="user@example.com",
            received=[
                "from mx.dest.com by dest.com [8.8.8.8]; Tue, 10 Nov 2026 10:00:00 +0000",
                "from isp.gateway (gateway [100.64.1.1]) by mx.dest.com; Tue, 10 Nov 2026 09:59:00 +0000",
            ],
        )
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.has_special_ip_in_external_hop is True
        assert res.features.has_private_ip_in_external_hop is False

    def test_loopback_and_link_local_in_external_hops(self):
        headers = EmailHeaders(
            from_address="user@example.com",
            received=[
                "from mx0 by mx [8.8.8.8]; Tue, 10 Nov 2026 10:00:00 +0000",
                "from loop (loop [127.0.0.1]) by mx0; Tue, 10 Nov 2026 09:58:00 +0000",
                "from link (link [169.254.1.10]) by loop; Tue, 10 Nov 2026 09:57:00 +0000",
            ],
        )
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.has_loopback_ip_in_external_hop is True
        assert res.features.has_link_local_ip_in_external_hop is True

    def test_malformed_received_header_syntax(self):
        headers = EmailHeaders(
            from_address="user@example.com",
            received=[
                "from mail.example.com by mx.google.com; Tue, 10 Nov 2026 10:00:00 +0000",
                "NOT_A_VALID_RECEIVED_HEADER_LINE_WITHOUT_CLAUSES",
            ],
        )
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.received_syntax_malformed_count == 1
        assert any(item.feature_name == "received_syntax_malformed_count" for item in res.evidence.evidence_items)

    def test_excessive_hop_count_anomaly(self):
        hops = [f"from hop{i} by hop{i+1}; Tue, 10 Nov 2026 10:00:00 +0000" for i in range(16)]
        headers = EmailHeaders(from_address="user@example.com", received=hops)
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.received_hop_count == 16
        assert res.features.hop_count_anomaly is True


# ---------------------------------------------------------------------------
# 4. Category C: Authentication Claims Tests
# ---------------------------------------------------------------------------

class TestCategoryCFeatures:
    def test_auth_claims_pass_and_unverified(self):
        auth = AuthenticationMetadata(
            spf=AuthenticationResult(
                mechanism=AuthMechanism.SPF,
                status=AuthStatus.PASS,
                provenance=AuthProvenance.AUTHENTICATION_RESULTS_HEADER,
                authserv_id="mx.google.com",
            ),
            dkim=AuthenticationResult(
                mechanism=AuthMechanism.DKIM,
                status=AuthStatus.PASS,
                provenance=AuthProvenance.AUTHENTICATION_RESULTS_HEADER,
                authserv_id="mx.google.com",
            ),
            dmarc=AuthenticationResult(
                mechanism=AuthMechanism.DMARC,
                status=AuthStatus.PASS,
                provenance=AuthProvenance.AUTHENTICATION_RESULTS_HEADER,
                authserv_id="mx.google.com",
            ),
            claims=[
                AuthenticationClaim(
                    mechanism=AuthMechanism.SPF,
                    status=AuthStatus.PASS,
                    authserv_id="mx.google.com",
                    header_index=0,
                    provenance=AuthProvenance.AUTHENTICATION_RESULTS_HEADER,
                    verification_status=VerificationStatus.UNVERIFIED,
                )
            ],
        )
        headers = EmailHeaders(from_address="user@example.com")
        data = _make_email_data(headers, auth=auth)
        res = analyze_headers(data)

        assert res.features.spf_status == AuthStatus.PASS
        assert res.features.dkim_status == AuthStatus.PASS
        assert res.features.dmarc_status == AuthStatus.PASS
        assert res.features.spf_claim_count == 1
        assert res.features.has_conflicting_spf is False
        assert res.features.authserv_id_count == 1
        assert res.features.authserv_id_inconsistent is False

    def test_conflicting_spf_claims(self):
        auth = AuthenticationMetadata(
            spf=AuthenticationResult(
                mechanism=AuthMechanism.SPF,
                status=AuthStatus.PASS,
                provenance=AuthProvenance.AUTHENTICATION_RESULTS_HEADER,
            ),
            dkim=AuthenticationResult(
                mechanism=AuthMechanism.DKIM,
                status=AuthStatus.MISSING,
                provenance=AuthProvenance.UNAVAILABLE,
            ),
            dmarc=AuthenticationResult(
                mechanism=AuthMechanism.DMARC,
                status=AuthStatus.MISSING,
                provenance=AuthProvenance.UNAVAILABLE,
            ),
            claims=[
                AuthenticationClaim(
                    mechanism=AuthMechanism.SPF,
                    status=AuthStatus.PASS,
                    authserv_id="mx.google.com",
                    header_index=0,
                    provenance=AuthProvenance.AUTHENTICATION_RESULTS_HEADER,
                ),
                AuthenticationClaim(
                    mechanism=AuthMechanism.SPF,
                    status=AuthStatus.FAIL,
                    authserv_id="mx.google.com",
                    header_index=1,
                    provenance=AuthProvenance.RECEIVED_SPF_HEADER,
                ),
            ],
        )
        headers = EmailHeaders(from_address="user@example.com")
        data = _make_email_data(headers, auth=auth)
        res = analyze_headers(data)

        assert res.features.has_conflicting_spf is True
        assert any(item.feature_name == "has_conflicting_spf" for item in res.evidence.evidence_items)

    def test_dkim_signature_without_pass(self):
        auth = AuthenticationMetadata(
            spf=AuthenticationResult(mechanism=AuthMechanism.SPF, status=AuthStatus.MISSING, provenance=AuthProvenance.UNAVAILABLE),
            dkim=AuthenticationResult(mechanism=AuthMechanism.DKIM, status=AuthStatus.FAIL, provenance=AuthProvenance.AUTHENTICATION_RESULTS_HEADER),
            dmarc=AuthenticationResult(mechanism=AuthMechanism.DMARC, status=AuthStatus.MISSING, provenance=AuthProvenance.UNAVAILABLE),
            claims=[],
        )
        headers = EmailHeaders(
            from_address="user@example.com",
            dkim_signature=["v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=k1; ..."],
        )
        data = _make_email_data(headers, auth=auth)
        res = analyze_headers(data)

        assert res.features.dkim_signature_header_present is True
        assert res.features.dkim_signature_present_without_pass is True
        assert any(item.feature_name == "dkim_signature_present_without_pass" for item in res.evidence.evidence_items)

    def test_authserv_id_inconsistent(self):
        auth = AuthenticationMetadata(
            spf=AuthenticationResult(
                mechanism=AuthMechanism.SPF,
                status=AuthStatus.PASS,
                provenance=AuthProvenance.AUTHENTICATION_RESULTS_HEADER,
                authserv_id="mx1.example.com",
            ),
            dkim=AuthenticationResult(
                mechanism=AuthMechanism.DKIM,
                status=AuthStatus.PASS,
                provenance=AuthProvenance.AUTHENTICATION_RESULTS_HEADER,
                authserv_id="mx2.otherhost.org",
            ),
            dmarc=AuthenticationResult(
                mechanism=AuthMechanism.DMARC,
                status=AuthStatus.MISSING,
                provenance=AuthProvenance.UNAVAILABLE,
            ),
            claims=[],
        )
        headers = EmailHeaders(from_address="user@example.com")
        data = _make_email_data(headers, auth=auth)
        res = analyze_headers(data)

        assert res.features.authserv_id_count == 2
        assert res.features.authserv_id_inconsistent is True
        assert "mx1.example.com" in res.evidence.parsed_authserv_ids
        assert "mx2.otherhost.org" in res.evidence.parsed_authserv_ids


# ---------------------------------------------------------------------------
# 5. Category D: RFC 5322 Metadata & Structural Compliance Tests
# ---------------------------------------------------------------------------

class TestCategoryDFeatures:
    def test_clean_metadata(self):
        headers = EmailHeaders(
            from_address="user@example.com",
            message_id="<msg12345@example.com>",
            mime_version="1.0",
            subject="Hello World",
            content_type="multipart/mixed; boundary=frontier",
        )
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.message_id_present is True
        assert res.features.message_id_valid_syntax is True
        assert res.features.message_id_domain_mismatch is False
        assert res.features.mime_version_present is True
        assert res.features.mime_version_valid is True
        assert res.features.has_subject_header is True
        assert res.features.subject_length == 11
        assert res.features.content_type_present is True
        assert res.features.content_type_is_multipart is True

    def test_missing_message_id_and_mime_version(self):
        headers = EmailHeaders(from_address="user@example.com")
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.message_id_present is False
        assert res.features.message_id_valid_syntax is None
        assert res.features.message_id_domain_mismatch is None
        assert res.features.mime_version_present is False
        assert res.features.mime_version_valid is None

    def test_malformed_message_id_syntax(self):
        headers = EmailHeaders(
            from_address="user@example.com",
            message_id="no-brackets-id@example.com",
        )
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.message_id_present is True
        assert res.features.message_id_valid_syntax is False
        assert any(item.feature_name == "message_id_valid_syntax" for item in res.evidence.evidence_items)

    def test_message_id_domain_mismatch(self):
        headers = EmailHeaders(
            from_address="user@legitimate.com",
            message_id="<abc@attacker-relay.org>",
        )
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.message_id_domain_mismatch is True
        assert any(item.feature_name == "message_id_domain_mismatch" for item in res.evidence.evidence_items)

    def test_invalid_mime_version(self):
        headers = EmailHeaders(
            from_address="user@example.com",
            mime_version="2.0",
        )
        data = _make_email_data(headers)
        res = analyze_headers(data)

        assert res.features.mime_version_valid is False
        assert any(item.feature_name == "mime_version_valid" for item in res.evidence.evidence_items)


# ---------------------------------------------------------------------------
# 6. Availability and Completeness Calculations
# ---------------------------------------------------------------------------

class TestAvailabilityAndCompleteness:
    def test_completeness_formula_accuracy(self):
        headers = EmailHeaders(
            from_address="user@example.com",
            reply_to="user@example.com",
            return_path="<user@example.com>",
            received=["from a by b; Tue, 10 Nov 2026 10:00:00 +0000"],
            message_id="<123@example.com>",
            mime_version="1.0",
            content_type="text/plain",
        )
        auth = AuthenticationMetadata(
            spf=AuthenticationResult(mechanism=AuthMechanism.SPF, status=AuthStatus.PASS, provenance=AuthProvenance.AUTHENTICATION_RESULTS_HEADER),
            dkim=AuthenticationResult(mechanism=AuthMechanism.DKIM, status=AuthStatus.PASS, provenance=AuthProvenance.AUTHENTICATION_RESULTS_HEADER),
            dmarc=AuthenticationResult(mechanism=AuthMechanism.DMARC, status=AuthStatus.PASS, provenance=AuthProvenance.AUTHENTICATION_RESULTS_HEADER),
            claims=[],
        )
        data = _make_email_data(headers, auth=auth)
        res = analyze_headers(data)

        # C_identity = (1 + 1 + 1)/3 = 1.0
        assert res.availability.completeness_identity == 1.0
        # C_routing = 0.6 (1 hop >= 1)
        assert res.availability.completeness_routing == 0.6
        # C_auth = (1 + 1 + 1)/3 = 1.0
        assert res.availability.completeness_auth == 1.0
        # C_metadata = (1 + 1 + 1)/3 = 1.0
        assert res.availability.completeness_metadata == 1.0
        # C_total = 0.25 * (1.0 + 0.6 + 1.0 + 1.0) = 0.9
        assert res.availability.completeness_total == 0.9


# ---------------------------------------------------------------------------
# 7. End-to-End Ingestion to Agent Integration
# ---------------------------------------------------------------------------

class TestEndToEndPipeline:
    def test_pipeline_with_raw_eml(self):
        raw_email = (
            b"From: Security Team <security@alerts-service.com>\r\n"
            b"Reply-To: Collector <harvest@external-bad.org>\r\n"
            b"To: Victim <victim@target-corp.com>\r\n"
            b"Subject: Immediate Action Required\r\n"
            b"Date: Wed, 11 Nov 2026 10:00:00 +0000\r\n"
            b"Message-ID: <alert-999@alerts-service.com>\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Received: from mx.target-corp.com by mx.google.com with ESMTPS id xyz [8.8.8.8]; Wed, 11 Nov 2026 10:01:00 +0000\r\n"
            b"Received: from upstream.net (upstream.lan [192.168.10.5]) by mx.target-corp.com; Wed, 11 Nov 2026 10:00:30 +0000\r\n"
            b"Authentication-Results: mx.google.com; spf=fail (google.com: domain does not designate 192.168.10.5)\r\n"
            b"\r\n"
            b"Please click this link to verify your account.\r\n"
        )
        email_data = ingest_email(raw_email, source_filename="sample_phish.eml")
        result = analyze_headers(email_data)

        assert isinstance(result, HeaderAgentResult)
        assert result.status == "success"
        assert result.agent_name == "header_agent"
        assert result.agent_version == "0.1.0"
        assert result.features.from_present is True
        assert result.features.from_reply_to_domain_mismatch is True
        assert result.features.received_hop_count == 2
        assert result.features.has_private_ip_in_external_hop is True
        assert result.features.spf_status == AuthStatus.FAIL
        assert result.processing_time_ms >= 0.0

        # Verify JSON serialization works seamlessly
        json_output = result.model_dump_json(indent=2)
        parsed = json.loads(json_output)
        assert parsed["email_id"] == email_data.email_id
        assert parsed["features"]["has_private_ip_in_external_hop"] is True

    def test_determinism(self):
        raw_email = (
            b"From: user@example.com\r\n"
            b"To: dest@example.com\r\n"
            b"Subject: Test\r\n"
            b"Message-ID: <123@example.com>\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        email_data = ingest_email(raw_email)
        res1 = analyze_headers(email_data)
        res2 = analyze_headers(email_data)

        # Processing time may slightly differ, but features, availability, and evidence must be identical
        assert res1.features.model_dump() == res2.features.model_dump()
        assert res1.availability.model_dump() == res2.availability.model_dump()
        assert res1.evidence.model_dump() == res2.evidence.model_dump()

