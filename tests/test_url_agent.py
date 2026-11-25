"""
tests/test_url_agent.py
-----------------------
Comprehensive unit and integration test suite for the URL Agent Phase B:
- app.agents.url_agent.analyze_urls
- app.agents.url_agent.create_no_url_result
- app.agents.url_agent.ValidatedURLRecord
- app.agents.url_agent.UrlAgentProcessingError
- app.agents.url_agent._get_caller_attribute
- All 14 Test Groups specified in Section 10 of docs/url_agent_phase_b_implementation_plan.md
"""

from __future__ import annotations

import collections
import inspect
import time
from datetime import datetime, timezone
from typing import Any, Optional
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app.agents.url_agent import (
    UrlAgentProcessingError,
    ValidatedURLRecord,
    _get_caller_attribute,
    analyze_urls,
    create_no_url_result,
)
from app.agents.url_components.psl_resolver import (
    DomainResolutionStatus,
    get_psl_trie,
    resolve_domain,
)
from app.agents.url_components.ip_classifier import classify_ip_address
from app.agents.url_components.syntax_validator import validate_url_syntax
from app.agents.url_components.lexical_features import (
    compute_hostname_entropy,
    count_path_segments,
    detect_unusual_ip_format,
    has_executable_file_in_path,
)
from app.agents.url_components.contextual_analyzer import (
    check_anchor_url_mismatch,
    compute_sender_domain_alignment,
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
    ExtractedURL,
    URLSource,
)
from app.schemas.url_agent_schema import (
    ACTIVE_URL_FEATURES,
    CANONICAL_URL_FEATURE_LIST,
    IPClassificationCategory,
    QUARANTINED_URL_FEATURES,
    UrlAgentOutput,
    UrlAgentResult,
    UrlAnalysisItem,
    UrlEvidence,
    UrlEvidenceItem,
    UrlFeatureAvailability,
    UrlFeatures,
)


# ---------------------------------------------------------------------------
# Test Fixture Helpers
# ---------------------------------------------------------------------------

def _make_email_headers(from_address: Optional[str] = "billing@company.com") -> EmailHeaders:
    return EmailHeaders(
        from_address=from_address,
        to=["recipient@example.com"],
        subject="Test Subject",
        date="Wed, 20 Nov 2026 12:00:00 +0000",
        message_id="<msg-001@example.com>",
    )


def _make_auth_metadata() -> AuthenticationMetadata:
    return AuthenticationMetadata(
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


def _make_email_data(
    extracted_urls: list[ExtractedURL] | None = None,
    from_address: Optional[str] = "billing@company.com",
    email_id: str = "test-email-001",
) -> EmailData:
    return EmailData(
        email_id=email_id,
        source_filename="test.eml",
        headers=_make_email_headers(from_address=from_address),
        authentication=_make_auth_metadata(),
        extracted_urls=extracted_urls if extracted_urls is not None else [],
        ingestion_timestamp=datetime.now(timezone.utc),
    )


def _make_url(
    original_url: str,
    source: URLSource = URLSource.PLAIN_TEXT,
    anchor_text: Optional[str] = None,
    normalized_url: Optional[str] = None,
    scheme: Optional[str] = None,
    hostname: Optional[str] = None,
    path: Optional[str] = None,
    query: Optional[str] = None,
) -> ExtractedURL:
    return ExtractedURL(
        original_url=original_url,
        source=source,
        anchor_text=anchor_text,
        normalized_url=normalized_url,
        scheme=scheme,
        hostname=hostname,
        path=path,
        query=query,
    )


# ---------------------------------------------------------------------------
# Pydantic-Compatible Test Instrumentation (Group 11)
# ---------------------------------------------------------------------------

class MonitoredEmailData(EmailData):
    """
    Preserves 100% of Pydantic field definitions, defaults, validators,
    and construction behavior. Intercepts attribute retrieval to verify
    single-access execution without shadowing model fields.
    """
    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        object.__setattr__(self, "_access_counts", collections.defaultdict(int))

    def __getattribute__(self, name: str) -> Any:
        try:
            counts = object.__getattribute__(self, "_access_counts")
        except AttributeError:
            return super().__getattribute__(name)
        if name in ("email_id", "extracted_urls"):
            counts[name] += 1
        return super().__getattribute__(name)


class CrashingEmailData(EmailData):
    """
    Simulates descriptor or attribute access failures on genuine EmailData
    instances without shadowing Pydantic fields or breaking __init__.
    """
    def __init__(self, fail_attr: str, exception_to_raise: Exception, **data: Any) -> None:
        super().__init__(**data)
        object.__setattr__(self, "_fail_attr", fail_attr)
        object.__setattr__(self, "_exc", exception_to_raise)

    def __getattribute__(self, name: str) -> Any:
        try:
            fail_attr = object.__getattribute__(self, "_fail_attr")
        except AttributeError:
            return super().__getattribute__(name)
        if name == fail_attr:
            raise object.__getattribute__(self, "_exc")
        return super().__getattribute__(name)


class PurePropertyAttributeError:
    @property
    def bad_attr(self) -> Any:
        raise AttributeError("property getter raised AttributeError")


class PurePropertyRuntimeError:
    @property
    def bad_attr(self) -> Any:
        raise RuntimeError("property getter raised RuntimeError")


class PureDynamicAttributeError:
    def __getattr__(self, name: str) -> Any:
        exc = AttributeError(f"dynamic attribute error for {name}")
        exc.name = "other_name"
        raise exc


class PurePlainMissing:
    pass


# ===========================================================================
# Group 1: No-URL Scenarios (State 1)
# ===========================================================================

class TestGroup1NoUrlScenarios:
    def test_state_1_clean_execution(self) -> None:
        """Emails with empty extracted_urls qualify for State 1 with verified defaults."""
        email_data = _make_email_data(extracted_urls=[])
        result = analyze_urls(email_data)

        assert isinstance(result, UrlAgentResult)
        assert result.status == "success"
        assert result.total_urls_extracted == 0
        assert result.email_id == "test-email-001"
        assert result.analysis_items == []
        assert result.evidence.evidence_items == []
        assert result.evidence.omitted_evidence_count == 0
        assert result.evidence.detected_anomalous_hostnames == []
        assert result.evidence.detected_shorteners == []
        assert result.evidence.observed_anomalies == []
        assert result.warnings == []

        # Completeness metrics must all be strictly 0.0 (inside result.availability)
        avail = result.availability
        assert avail.avail_has_urls is False
        assert avail.avail_structure_features is False
        assert avail.avail_hostname_features is False
        assert avail.avail_entropy_features is False
        assert avail.avail_sender_alignment is False
        assert avail.avail_anchor_text_analysis is False
        assert avail.completeness_total == 0.0
        assert avail.completeness_structure == 0.0
        assert avail.completeness_obfuscation == 0.0
        assert avail.completeness_context == 0.0
        assert avail.completeness_hostname == 0.0

        # Features: all counts 0, bools False, nullable features None
        feat = result.features
        assert feat.total_url_count == 0
        assert feat.unique_url_count == 0
        assert feat.has_urls is False
        assert feat.http_url_count == 0
        assert feat.https_url_count == 0
        assert feat.suspicious_scheme_count == 0
        assert feat.has_suspicious_scheme is False
        assert feat.has_non_default_port is False
        assert feat.max_url_length == 0
        assert feat.max_path_depth == 0
        assert feat.has_executable_file_in_path is False
        assert feat.has_ip_literal_url is False
        assert feat.has_private_ip_url is False
        assert feat.has_loopback_ip_url is False
        assert feat.has_special_ip_url is False
        assert feat.has_punycode_url is False
        assert feat.max_subdomain_depth == 0
        assert feat.has_excessive_subdomains is False
        assert feat.max_hostname_entropy is None  # Optional float, None when no URLs
        assert feat.unique_domain_count == 0
        assert feat.unique_fqdn_count == 0
        assert feat.has_at_symbol_in_url is False
        assert feat.has_embedded_credentials is False
        assert feat.has_percent_encoding is False
        assert feat.has_double_percent_encoding is False
        assert feat.max_percent_encoded_count == 0
        assert feat.has_brand_in_path is None
        assert feat.has_non_ascii_url is False
        assert feat.has_unusual_ip_format is False
        assert feat.malformed_url_count == 0
        assert feat.has_url_shortener is False
        assert feat.url_shortener_count == 0
        assert feat.has_redirect_parameter is False
        assert feat.has_anchor_url_mismatch is False
        assert feat.anchor_url_mismatch_count == 0
        assert feat.has_sender_domain_mismatch_url is None
        assert feat.sender_domain_matching_url_ratio is None
        assert feat.external_link_ratio is None
        assert feat.has_form_action_url is None

    def test_state_1_internal_crash_safety(self) -> None:
        """Internal failure during create_no_url_result must raise UrlAgentProcessingError."""
        email_data = _make_email_data(extracted_urls=[])

        with patch("app.agents.url_agent.create_no_url_result", side_effect=RuntimeError("Simulated zero-url crash")):
            with pytest.raises(UrlAgentProcessingError) as exc_info:
                analyze_urls(email_data)

            err = exc_info.value
            assert err.email_id == "test-email-001"
            assert err.total_urls_extracted == 0
            assert isinstance(err.original_exception, RuntimeError)
            assert err.__cause__ is err.original_exception
            assert "Simulated zero-url crash" in err.traceback_str


# ===========================================================================
# Group 2: Clean Web URLs
# ===========================================================================

class TestGroup2CleanWebUrls:
    def test_clean_https_url(self) -> None:
        """Standard clean HTTPS URL analysis."""
        url = _make_url("https://example.com/about", source=URLSource.PLAIN_TEXT)
        email_data = _make_email_data([url])
        result = analyze_urls(email_data)

        assert result.status == "success"
        assert result.total_urls_extracted == 1
        assert result.features.total_url_count == 1
        assert result.features.unique_url_count == 1
        assert result.features.https_url_count == 1
        assert result.features.http_url_count == 0
        assert result.features.has_urls is True
        assert result.features.has_ip_literal_url is False
        assert result.features.malformed_url_count == 0

        assert len(result.analysis_items) == 1
        item = result.analysis_items[0]
        assert item.domain_resolution_status == DomainResolutionStatus.EXACT_MATCH
        assert item.registered_domain == "example.com"
        assert item.has_ip_hostname is False
        assert item.is_url_shortener is False


# ===========================================================================
# Group 3: Malformed URLs (All 5 Conditions)
# ===========================================================================

class TestGroup3MalformedUrls:
    def test_condition_1_unclosed_ipv6_bracket(self) -> None:
        """Condition 1: Unclosed IPv6 bracket."""
        url = _make_url("http://[::1/path")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.malformed_url_count == 1
        assert result.analysis_items[0].is_malformed is True

    def test_condition_2_non_numeric_port(self) -> None:
        """Condition 2: Non-numeric port in authority."""
        url = _make_url("http://example.com:abc/path")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.malformed_url_count == 1
        assert result.analysis_items[0].is_malformed is True

    def test_condition_2_out_of_range_port(self) -> None:
        """Condition 2: Out of range port (> 65535)."""
        url = _make_url("http://example.com:99999/path")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.malformed_url_count == 1
        assert result.analysis_items[0].is_malformed is True

    def test_condition_3_port_0(self) -> None:
        """Condition 3: Port 0."""
        url = _make_url("http://example.com:0/path")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.malformed_url_count == 1
        assert result.analysis_items[0].is_malformed is True

    def test_condition_4_missing_authority(self) -> None:
        """Condition 4: Missing authority for web scheme."""
        url = _make_url("http:///path")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.malformed_url_count == 1
        assert result.analysis_items[0].is_malformed is True

    def test_condition_5_broken_percent_escape(self) -> None:
        """Condition 5: Non-hex or truncated percent escape."""
        url1 = _make_url("http://example.com/%GG/path")
        res1 = analyze_urls(_make_email_data([url1]))
        assert res1.features.malformed_url_count == 1
        assert res1.analysis_items[0].is_malformed is True

        url2 = _make_url("http://example.com/%2")
        res2 = analyze_urls(_make_email_data([url2]))
        assert res2.features.malformed_url_count == 1
        assert res2.analysis_items[0].is_malformed is True

    def test_simultaneous_conditions_single_bounded_increment(self) -> None:
        """A URL failing multiple syntax conditions increments malformed_url_count by exactly 1."""
        url = _make_url("http://example.com:99999/%GG/path")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.malformed_url_count == 1
        assert result.analysis_items[0].is_malformed is True


# ===========================================================================
# Group 4: IP Address Literals & Range Precedence
# ===========================================================================

class TestGroup4IpAddressLiterals:
    def test_ipv4_loopback(self) -> None:
        url = _make_url("http://127.0.0.1/test")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_loopback_ip_url is True
        assert result.features.has_ip_literal_url is True
        assert result.features.has_private_ip_url is False

    def test_ipv4_rfc1918_private(self) -> None:
        urls = [
            _make_url("http://192.168.1.1/"),
            _make_url("http://10.0.0.1/"),
            _make_url("http://172.16.0.1/"),
        ]
        result = analyze_urls(_make_email_data(urls))
        assert result.features.has_private_ip_url is True
        assert result.features.has_ip_literal_url is True

    def test_ipv4_cgnat(self) -> None:
        url = _make_url("http://100.64.0.1/")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_special_ip_url is True
        assert result.features.has_private_ip_url is False

    def test_ipv4_documentation(self) -> None:
        url = _make_url("http://192.0.2.1/")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_special_ip_url is True

    def test_ipv4_pcp_anycast_override(self) -> None:
        url = _make_url("http://192.0.0.9/")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_ip_literal_url is True
        assert result.features.has_special_ip_url is False
        assert result.features.has_private_ip_url is False

    def test_ipv4_special_protocol_remainder(self) -> None:
        url = _make_url("http://192.0.0.1/")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_special_ip_url is True

    def test_ipv4_mapped_ipv6_unwrap(self) -> None:
        url = _make_url("http://[::ffff:192.168.1.1]/")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_private_ip_url is True

    def test_ipv6_loopback(self) -> None:
        url = _make_url("http://[::1]/")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_loopback_ip_url is True

    def test_ipv6_multicast(self) -> None:
        url = _make_url("http://[ff02::1]/")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_special_ip_url is True

    def test_ipv6_ula(self) -> None:
        url = _make_url("http://[fc00::1]/")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_private_ip_url is True

    def test_ipv6_2001_overrides(self) -> None:
        global_urls = [
            _make_url("http://[2001:1::1]/"),
            _make_url("http://[2001:20::1]/"),
            _make_url("http://[2001:30::1]/"),
        ]
        res_global = analyze_urls(_make_email_data(global_urls))
        assert res_global.features.has_special_ip_url is False

        special_urls = [
            _make_url("http://[2001::1]/"),
            _make_url("http://[2001:2::1]/"),
            _make_url("http://[2001:10::1]/"),
            _make_url("http://[2001:0100::1]/"),
        ]
        res_special = analyze_urls(_make_email_data(special_urls))
        assert res_special.features.has_special_ip_url is True

    def test_ipv6_outside_2001(self) -> None:
        specials = [
            _make_url("http://[100::1]/"),
            _make_url("http://[100:0:0:1::1]/"),
            _make_url("http://[3fff::1]/"),
            _make_url("http://[2001:db8::1]/"),
            _make_url("http://[5f00::1]/"),
        ]
        res_spec = analyze_urls(_make_email_data(specials))
        assert res_spec.features.has_special_ip_url is True

        globals_v6 = [
            _make_url("http://[64:ff9b::1]/"),
            _make_url("http://[2620:4f:8000::1]/"),
        ]
        res_glob = analyze_urls(_make_email_data(globals_v6))
        assert res_glob.features.has_special_ip_url is False


# ===========================================================================
# Group 5: IDN & Punycode (Two-Pronged Detection)
# ===========================================================================

class TestGroup5IdnPunycode:
    def test_normalized_hostname_punycode_prefix(self) -> None:
        """Prong 1: Normalized hostname containing xn-- prefix."""
        url = _make_url("http://xn--e1afmkfd.xn--p1ai/path")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_punycode_url is True

    def test_raw_hostname_unicode(self) -> None:
        """Prong 2: Raw hostname containing non-ASCII Unicode."""
        url = _make_url("http://bücher.de/path")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_punycode_url is True

    def test_unicode_in_path_or_query_only(self) -> None:
        """Non-ASCII characters strictly in path or query must not trigger punycode."""
        url = _make_url("http://example.com/café?q=naïve")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_punycode_url is False
        assert result.features.has_non_ascii_url is True


# ===========================================================================
# Group 6: Public Suffix List Resolution
# ===========================================================================

class TestGroup6PslResolution:
    def test_exact_match_depth_0(self) -> None:
        url = _make_url("http://example.com/test")
        result = analyze_urls(_make_email_data([url]))
        item = result.analysis_items[0]
        assert item.domain_resolution_status == DomainResolutionStatus.EXACT_MATCH
        assert item.registered_domain == "example.com"
        assert result.features.max_subdomain_depth == 0

        # Direct trie resolution verification
        reg, status, depth = resolve_domain("example.com")
        assert status == DomainResolutionStatus.EXACT_MATCH
        assert reg == "example.com"
        assert depth == 0

    def test_multipart_tld_depth_1(self) -> None:
        url = _make_url("http://news.bbc.co.uk/world")
        result = analyze_urls(_make_email_data([url]))
        item = result.analysis_items[0]
        assert item.domain_resolution_status == DomainResolutionStatus.EXACT_MATCH
        assert item.registered_domain == "bbc.co.uk"
        assert result.features.max_subdomain_depth == 1

        reg, status, depth = resolve_domain("news.bbc.co.uk")
        assert status == DomainResolutionStatus.EXACT_MATCH
        assert reg == "bbc.co.uk"
        assert depth == 1

    def test_wildcard_rule(self) -> None:
        # *.ck wildcard rule: foo.ck IS the TLD-equivalent under *.ck
        # Only bar.foo.ck has foo.ck as registered domain
        url = _make_url("http://bar.foo.ck/home")
        result = analyze_urls(_make_email_data([url]))
        item = result.analysis_items[0]
        assert item.domain_resolution_status == DomainResolutionStatus.WILDCARD_MATCH
        assert item.registered_domain == "bar.foo.ck"

        reg, status, depth = resolve_domain("bar.foo.ck")
        assert status == DomainResolutionStatus.WILDCARD_MATCH
        assert reg == "bar.foo.ck"
        assert depth == 0

    def test_exception_rule(self) -> None:
        url = _make_url("http://www.ck/page")
        result = analyze_urls(_make_email_data([url]))
        item = result.analysis_items[0]
        assert item.domain_resolution_status == DomainResolutionStatus.EXCEPTION_MATCH
        assert item.registered_domain == "www.ck"

        reg, status, depth = resolve_domain("www.ck")
        assert status == DomainResolutionStatus.EXCEPTION_MATCH
        assert reg == "www.ck"
        assert depth == 0

    def test_unknown_suffix(self) -> None:
        url = _make_url("http://server.corp.local/login")
        result = analyze_urls(_make_email_data([url]))
        item = result.analysis_items[0]
        assert item.domain_resolution_status == DomainResolutionStatus.UNKNOWN_SUFFIX
        assert item.registered_domain is None

        reg, status, depth = resolve_domain("server.corp.local")
        assert status == DomainResolutionStatus.UNKNOWN_SUFFIX
        assert reg is None


# ===========================================================================
# Group 7: URL Shorteners
# ===========================================================================

class TestGroup7UrlShorteners:
    def test_known_shorteners_detected(self) -> None:
        urls = [
            _make_url("http://bit.ly/xyz123"),
            _make_url("http://t.co/abc456"),
        ]
        result = analyze_urls(_make_email_data(urls))
        assert result.features.has_url_shortener is True
        assert result.features.url_shortener_count == 2
        assert "bit.ly" in result.evidence.detected_shorteners
        assert "t.co" in result.evidence.detected_shorteners

    def test_regular_domain_not_shortener(self) -> None:
        url = _make_url("http://example.com/path")
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_url_shortener is False
        assert result.features.url_shortener_count == 0
        assert result.evidence.detected_shorteners == []


# ===========================================================================
# Group 8: Sender Domain Alignment
# ===========================================================================

class TestGroup8SenderDomainAlignment:
    def test_mixed_occurrences(self) -> None:
        urls = [
            _make_url("http://company.com/page1"),
            _make_url("http://company.com/page2"),
            _make_url("http://sub.company.com/page3"),
            _make_url("http://external.org/login"),
        ]
        result = analyze_urls(_make_email_data(urls, from_address="billing@company.com"))
        assert result.features.sender_domain_matching_url_ratio == 0.75
        assert result.features.external_link_ratio == 0.25
        assert result.features.has_sender_domain_mismatch_url is True
        assert round(result.features.sender_domain_matching_url_ratio + result.features.external_link_ratio, 6) == 1.0

    def test_all_matching(self) -> None:
        urls = [
            _make_url("http://company.com/page1"),
            _make_url("http://company.com/page2"),
            _make_url("http://company.com/page3"),
            _make_url("http://company.com/page4"),
        ]
        result = analyze_urls(_make_email_data(urls, from_address="billing@company.com"))
        assert result.features.sender_domain_matching_url_ratio == 1.0
        assert result.features.external_link_ratio == 0.0
        assert result.features.has_sender_domain_mismatch_url is False

    def test_excluded_ips_from_resolvable_denominator(self) -> None:
        urls = [
            _make_url("http://192.168.1.1/"),
            _make_url("http://10.0.0.1/"),
            _make_url("http://company.com/page1"),
            _make_url("http://company.com/page2"),
        ]
        result = analyze_urls(_make_email_data(urls, from_address="billing@company.com"))
        assert result.features.sender_domain_matching_url_ratio == 1.0
        assert result.features.external_link_ratio == 0.0
        assert result.features.has_sender_domain_mismatch_url is False

    def test_missing_from_header(self) -> None:
        urls = [_make_url("http://company.com/page")]
        result = analyze_urls(_make_email_data(urls, from_address=None))
        assert result.features.sender_domain_matching_url_ratio is None
        assert result.features.external_link_ratio is None
        assert result.features.has_sender_domain_mismatch_url is None
        assert result.availability.avail_sender_alignment is False

    def test_unresolvable_from_domain(self) -> None:
        urls = [_make_url("http://company.com/page")]
        result = analyze_urls(_make_email_data(urls, from_address="invalid-email-address"))
        assert result.features.sender_domain_matching_url_ratio is None
        assert result.features.external_link_ratio is None
        assert result.features.has_sender_domain_mismatch_url is None
        assert result.availability.avail_sender_alignment is False


# ===========================================================================
# Group 9: Anchor Text Mismatch & Source Qualification
# ===========================================================================

class TestGroup9AnchorTextMismatch:
    def test_deceptive_url_anchor_with_html_href(self) -> None:
        url = _make_url(
            "http://evil.com/login",
            source=URLSource.HTML_HREF,
            anchor_text="https://paypal.com/signin",
        )
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_anchor_url_mismatch is True
        assert result.features.anchor_url_mismatch_count == 1

    def test_descriptive_anchor_with_html_href(self) -> None:
        url = _make_url(
            "http://evil.com/login",
            source=URLSource.HTML_HREF,
            anchor_text="Click Here to Verify Your Account",
        )
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_anchor_url_mismatch is False
        assert result.features.anchor_url_mismatch_count == 0

    def test_html_other_strictly_disqualified(self) -> None:
        url = _make_url(
            "http://evil.com/post",
            source=URLSource.HTML_OTHER,
            anchor_text="https://paypal.com",
        )
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_anchor_url_mismatch is False
        assert result.features.anchor_url_mismatch_count == 0

    def test_html_src_strictly_disqualified(self) -> None:
        url = _make_url(
            "http://evil.com/image.png",
            source=URLSource.HTML_SRC,
            anchor_text="https://paypal.com",
        )
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_anchor_url_mismatch is False
        assert result.features.anchor_url_mismatch_count == 0

    def test_plain_text_strictly_disqualified(self) -> None:
        url = _make_url(
            "http://evil.com/path",
            source=URLSource.PLAIN_TEXT,
            anchor_text="https://paypal.com",
        )
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_anchor_url_mismatch is False

    def test_email_address_anchor_not_mismatch(self) -> None:
        url = _make_url(
            "http://evil.com/contact",
            source=URLSource.HTML_HREF,
            anchor_text="support@paypal.com",
        )
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_anchor_url_mismatch is False
        assert result.features.anchor_url_mismatch_count == 0

    def test_ambiguous_prefix_anchor_not_mismatch(self) -> None:
        url = _make_url(
            "http://evil.com/path",
            source=URLSource.HTML_HREF,
            anchor_text="https://",
        )
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_anchor_url_mismatch is False

    def test_same_registered_domain_not_mismatch(self) -> None:
        url = _make_url(
            "http://login.paypal.com/signin",
            source=URLSource.HTML_HREF,
            anchor_text="https://paypal.com",
        )
        result = analyze_urls(_make_email_data([url]))
        assert result.features.has_anchor_url_mismatch is False


# ===========================================================================
# Group 10: Processing Limits & Caps Verification
# ===========================================================================

class TestGroup10ProcessingLimitsAndCaps:
    def test_large_url_set_500_urls(self) -> None:
        urls = [
            _make_url(f"https://example{i}.com/page")
            for i in range(500)
        ]
        result = analyze_urls(_make_email_data(urls))
        assert len(result.analysis_items) == 200
        assert result.total_urls_extracted == 500
        assert result.features.total_url_count == 500
        assert result.features.https_url_count == 500
        assert any("capped to first 200" in w or "500 URLs" in w for w in result.warnings)

    def test_digest_bomb_3134_urls(self) -> None:
        """In-situ benchmark verification: 3,134 URLs processed within budget."""
        urls = [
            _make_url(f"https://sub{i % 50}.domain{i % 100}.org/path/{i}")
            for i in range(3134)
        ]
        t0 = time.perf_counter()
        result = analyze_urls(_make_email_data(urls))
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        assert len(result.analysis_items) == 200
        assert result.total_urls_extracted == 3134
        assert result.features.total_url_count == 3134
        assert result.status in ("success", "partial")
        # Ensure completion well within the theoretical budget (350 ms)
        assert elapsed_ms < 1000.0

    def test_excessive_evidence_items_capped_to_100(self) -> None:
        # Create 150 IP literal URLs that generate evidence items
        urls = [
            _make_url(f"http://192.168.1.{i % 250 + 1}/test")
            for i in range(150)
        ]
        result = analyze_urls(_make_email_data(urls))
        assert len(result.evidence.evidence_items) == 100
        assert result.evidence.omitted_evidence_count == 50

    def test_excessive_anomalous_hostnames_capped_to_50(self) -> None:
        # Create 60 distinct IP literal URLs
        urls = [
            _make_url(f"http://10.{i}.0.1/")
            for i in range(60)
        ]
        result = analyze_urls(_make_email_data(urls))
        assert len(result.evidence.detected_anomalous_hostnames) == 50

    def test_excessive_shorteners_capped_to_50(self) -> None:
        # 60 shortener URLs
        urls = [
            _make_url(f"http://bit.ly/{i}")
            for i in range(60)
        ]
        result = analyze_urls(_make_email_data(urls))
        assert len(result.evidence.detected_shorteners) <= 50


# ===========================================================================
# Group 11: Pipeline Failure & Error Contract Validation
# ===========================================================================

class TestGroup11PipelineFailureAndErrorContract:
    def test_state_1_verified_absence(self) -> None:
        email_data = _make_email_data(extracted_urls=[])
        result = analyze_urls(email_data)
        assert result.status == "success"
        assert result.total_urls_extracted == 0
        assert result.availability.avail_has_urls is False
        assert result.availability.completeness_total == 0.0

    def test_state_2_successful_execution(self) -> None:
        urls = [_make_url("https://example.com/1"), _make_url("https://example.com/2")]
        result = analyze_urls(_make_email_data(urls))
        assert result.status == "success"
        assert result.total_urls_extracted == 2
        assert result.availability.avail_has_urls is True
        assert result.availability.completeness_structure == 1.0
        assert result.availability.completeness_obfuscation == 1.0
        assert result.availability.completeness_total >= 0.625

    def test_state_3_pipeline_crash_fail_closed(self) -> None:
        urls = [_make_url("https://example.com/1"), _make_url("https://example.com/2")]
        email_data = _make_email_data(urls, email_id="crash-email-999")

        with patch("app.agents.url_agent.execute_url_analysis_pipeline", side_effect=RuntimeError("Pipeline crash")):
            with pytest.raises(UrlAgentProcessingError) as exc_info:
                analyze_urls(email_data)

            err = exc_info.value
            assert err.email_id == "crash-email-999"
            assert err.total_urls_extracted == 2
            assert isinstance(err.original_exception, RuntimeError)
            assert err.__cause__ is err.original_exception
            assert "Pipeline crash" in err.traceback_str

    def test_monitored_email_data_single_access(self) -> None:
        urls = [_make_url("https://example.com/")]
        email_data = MonitoredEmailData(
            email_id="monitored-001",
            source_filename="test.eml",
            headers=_make_email_headers(),
            authentication=_make_auth_metadata(),
            extracted_urls=urls,
            ingestion_timestamp=datetime.now(timezone.utc),
        )
        result = analyze_urls(email_data)
        assert result.status == "success"
        counts = object.__getattribute__(email_data, "_access_counts")
        assert counts["email_id"] == 1
        assert counts["extracted_urls"] == 1

    def test_crashing_email_data_attribute_error_disambiguation(self) -> None:
        urls = [_make_url("https://example.com/")]
        email_data = CrashingEmailData(
            fail_attr="email_id",
            exception_to_raise=AttributeError("Simulated getter crash"),
            email_id="crashing-001",
            source_filename="test.eml",
            headers=_make_email_headers(),
            authentication=_make_auth_metadata(),
            extracted_urls=urls,
            ingestion_timestamp=datetime.now(timezone.utc),
        )
        with pytest.raises(AttributeError) as exc_info:
            analyze_urls(email_data)
        # _get_caller_attribute wraps the error; check the cause contains the original message
        assert exc_info.value.__cause__ is not None
        assert "email_id" in str(exc_info.value)

    def test_crashing_email_data_runtime_error_propagates(self) -> None:
        urls = [_make_url("https://example.com/")]
        email_data = CrashingEmailData(
            fail_attr="extracted_urls",
            exception_to_raise=RuntimeError("Database query failed"),
            email_id="crashing-002",
            source_filename="test.eml",
            headers=_make_email_headers(),
            authentication=_make_auth_metadata(),
            extracted_urls=urls,
            ingestion_timestamp=datetime.now(timezone.utc),
        )
        with pytest.raises(RuntimeError) as exc_info:
            analyze_urls(email_data)
        assert "Database query failed" in str(exc_info.value)

    def test_isolated_get_caller_attribute_helper(self) -> None:
        # Property raising AttributeError
        target1 = PurePropertyAttributeError()
        with pytest.raises(AttributeError) as exc1:
            _get_caller_attribute(target1, "bad_attr")
        assert "property getter raised AttributeError" in str(exc1.value)
        assert exc1.value.__cause__ is not None

        # Property raising RuntimeError
        target2 = PurePropertyRuntimeError()
        with pytest.raises(RuntimeError) as exc2:
            _get_caller_attribute(target2, "bad_attr")
        assert "property getter raised RuntimeError" in str(exc2.value)

        # Dynamic attribute error with exc.name != attr_name
        target3 = PureDynamicAttributeError()
        with pytest.raises(AttributeError) as exc3:
            _get_caller_attribute(target3, "some_attr")
        assert "dynamic attribute error for some_attr" in str(exc3.value)

        # Plain missing attribute
        target4 = PurePlainMissing()
        with pytest.raises(AttributeError) as exc4:
            _get_caller_attribute(target4, "missing_attr")
        assert "missing required attribute 'missing_attr'" in str(exc4.value)

    def test_model_construct_bypasses_caught(self) -> None:
        # email_id is None
        bad_ed1 = EmailData.model_construct(email_id=None, extracted_urls=[])
        with pytest.raises(ValueError):
            analyze_urls(bad_ed1)

        # email_id is empty
        bad_ed2 = EmailData.model_construct(email_id="", extracted_urls=[])
        with pytest.raises(ValueError):
            analyze_urls(bad_ed2)

        # extracted_urls is None
        bad_ed3 = EmailData.model_construct(email_id="msg-001", extracted_urls=None)
        with pytest.raises(TypeError):
            analyze_urls(bad_ed3)

        # extracted_urls is not a list
        bad_ed4 = EmailData.model_construct(email_id="msg-001", extracted_urls="not_a_list")
        with pytest.raises(TypeError):
            analyze_urls(bad_ed4)

        # extracted_urls contains non-ExtractedURL
        bad_ed5 = EmailData.model_construct(email_id="msg-001", extracted_urls=[123])
        with pytest.raises(TypeError):
            analyze_urls(bad_ed5)

    def test_architecture_b_boundary_field_validation(self) -> None:
        # Corrupted original_url
        u1 = ExtractedURL.model_construct(original_url=None, source=URLSource.PLAIN_TEXT)
        with pytest.raises(ValueError):
            analyze_urls(_make_email_data([u1]))

        u2 = ExtractedURL.model_construct(original_url=123, source=URLSource.PLAIN_TEXT)
        with pytest.raises(ValueError):
            analyze_urls(_make_email_data([u2]))

        u3 = ExtractedURL.model_construct(original_url="", source=URLSource.PLAIN_TEXT)
        with pytest.raises(ValueError):
            analyze_urls(_make_email_data([u3]))

        # Corrupted source
        u4 = ExtractedURL.model_construct(original_url="https://example.com", source="invalid_source")
        with pytest.raises(TypeError):
            analyze_urls(_make_email_data([u4]))

        # Corrupted anchor_text
        u5 = ExtractedURL.model_construct(original_url="https://example.com", source=URLSource.HTML_HREF, anchor_text=123)
        with pytest.raises(TypeError):
            analyze_urls(_make_email_data([u5]))

        # Corrupted normalized_url
        u6 = ExtractedURL.model_construct(original_url="https://example.com", source=URLSource.PLAIN_TEXT, normalized_url=123)
        with pytest.raises(TypeError):
            analyze_urls(_make_email_data([u6]))

        # Corrupted scheme
        u7 = ExtractedURL.model_construct(original_url="https://example.com", source=URLSource.PLAIN_TEXT, scheme=123)
        with pytest.raises(TypeError):
            analyze_urls(_make_email_data([u7]))

        # Corrupted hostname
        u8 = ExtractedURL.model_construct(original_url="https://example.com", source=URLSource.PLAIN_TEXT, hostname=123)
        with pytest.raises(TypeError):
            analyze_urls(_make_email_data([u8]))

        # Corrupted path
        u9 = ExtractedURL.model_construct(original_url="https://example.com", source=URLSource.PLAIN_TEXT, path=123)
        with pytest.raises(TypeError):
            analyze_urls(_make_email_data([u9]))

        # Corrupted query
        u10 = ExtractedURL.model_construct(original_url="https://example.com", source=URLSource.PLAIN_TEXT, query=123)
        with pytest.raises(TypeError):
            analyze_urls(_make_email_data([u10]))

        # Legitimate optional None fields accepted cleanly
        u11 = ExtractedURL(
            original_url="https://example.com/ok",
            source=URLSource.PLAIN_TEXT,
            anchor_text=None,
            normalized_url=None,
            scheme=None,
            hostname=None,
            path=None,
            query=None,
        )
        res11 = analyze_urls(_make_email_data([u11]))
        assert res11.status == "success"

        # Absence of raw_item on ValidatedURLRecord
        rec = ValidatedURLRecord(
            original_url="https://example.com",
            source=URLSource.PLAIN_TEXT,
            anchor_text=None,
            normalized_url=None,
            scheme=None,
            hostname=None,
            path=None,
            query=None,
        )
        assert hasattr(rec, "raw_item") is False

    def test_rejection_of_unrelated_types(self) -> None:
        with pytest.raises(TypeError):
            analyze_urls(None)  # type: ignore

        with pytest.raises(TypeError):
            analyze_urls({"email_id": "test"})  # type: ignore

        with pytest.raises(TypeError):
            analyze_urls("string_input")  # type: ignore

        with pytest.raises(TypeError):
            analyze_urls(12345)  # type: ignore

    def test_rejection_of_non_list_extracted_urls(self) -> None:
        for non_list in [
            ("tuple",),
            {"set"},
            (x for x in []),
            "string",
            b"bytes",
            {"dict": "val"},
        ]:
            ed = EmailData.model_construct(email_id="msg-001", extracted_urls=non_list)
            with pytest.raises(TypeError):
                analyze_urls(ed)

    def test_email_id_exact_preservation(self) -> None:
        # Boundary whitespace preserved without stripping
        raw_id = "  msg-boundary-001  "
        url = _make_url("https://example.com/")
        email_data = _make_email_data([url], email_id=raw_id)
        result = analyze_urls(email_data)
        assert result.email_id == raw_id

    def test_blank_or_whitespace_email_id_rejected(self) -> None:
        for blank_id in ["", "   ", "\t\n"]:
            ed = EmailData.model_construct(email_id=blank_id, extracted_urls=[])
            with pytest.raises(ValueError):
                analyze_urls(ed)


# ===========================================================================
# Group 12: Quarantined Feature Verification
# ===========================================================================

class TestGroup12QuarantinedFeatures:
    def test_quarantined_features_semantics(self) -> None:
        urls = [
            _make_url("http://example.com/one"),
            _make_url("http://example.com/two"),
            _make_url("https://example.com/three"),
        ]
        result = analyze_urls(_make_email_data(urls))
        feat = result.features

        # Feature 4 (http_url_count) must be active integer
        assert feat.http_url_count == 2
        assert isinstance(feat.http_url_count, int)

        # Feature 27 (has_brand_in_path) must be None
        assert feat.has_brand_in_path is None

        # Feature 39 (has_form_action_url) must be None
        assert feat.has_form_action_url is None


# ===========================================================================
# Group 13: End-to-End Pipeline Integration
# ===========================================================================

class TestGroup13EndToEndIntegration:
    def test_ingest_email_to_analyze_urls_roundtrip(self) -> None:
        raw_eml = (
            b"From: security@paypal-verify.com\r\n"
            b"To: victim@example.com\r\n"
            b"Subject: Action Required: Verify Account\r\n"
            b"Date: Wed, 20 Nov 2026 12:00:00 +0000\r\n"
            b"Message-ID: <roundtrip-test-001@example.com>\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b"<html><body>"
            b'<a href="http://evil.com/login">https://paypal.com/verify</a><br>'
            b'<a href="http://192.168.1.1/admin">Internal Router</a><br>'
            b'<a href="http://bit.ly/secure-link">Shortened Link</a>'
            b"</body></html>"
        )
        email_data = ingest_email(raw_eml, source_filename="sample_phish.eml")
        assert len(email_data.extracted_urls) >= 3

        result = analyze_urls(email_data)
        assert result.status == "success"
        assert result.total_urls_extracted == len(email_data.extracted_urls)
        assert result.features.has_urls is True
        assert result.features.has_anchor_url_mismatch is True
        assert result.features.has_private_ip_url is True
        assert result.features.has_url_shortener is True

        # Verify full model dump and validation roundtrip
        dumped = result.model_dump()
        reconstructed = UrlAgentResult.model_validate(dumped)
        assert reconstructed.email_id == result.email_id
        assert reconstructed.features.total_url_count == result.features.total_url_count
        assert reconstructed.availability.avail_has_urls == result.availability.avail_has_urls


# ===========================================================================
# Group 14: Full Regression Check
# ===========================================================================

class TestGroup14RegressionCheck:
    def test_schema_and_canonical_invariants(self) -> None:
        """Verify that all canonical feature counts and categories are maintained."""
        assert len(CANONICAL_URL_FEATURE_LIST) == 39
        assert len(ACTIVE_URL_FEATURES) == 36
        assert len(QUARANTINED_URL_FEATURES) == 3
        assert "http_url_count" in QUARANTINED_URL_FEATURES
        assert "has_brand_in_path" in QUARANTINED_URL_FEATURES
        assert "has_form_action_url" in QUARANTINED_URL_FEATURES
