"""
tests/test_url_extractor.py
---------------------------
Pytest test suite for app/ingestion/url_extractor.py.

Covers all 25 specified scenarios:
1. Plain-text HTTP URL
2. Plain-text HTTPS URL
3. Multiple URLs in one message
4. HTML anchor href
5. HTML anchor text differing from href
6. HTML image src
7. Duplicate URL in multiple locations
8. Query parameters and fragments
9. Percent-encoded URLs
10. Unicode domain
11. Punycode domain
12. IP-address-based URL
13. Unusual valid port
14. javascript: scheme
15. data: scheme
16. file: scheme
17. URL with user information
18. Malformed URL
19. URL-like text without a scheme
20. Ordinary email addresses must not be extracted
21. Very long URL
22. URL surrounded by punctuation
23. URL containing HTML entities
24. Empty email body
25. Email with both plain text and HTML representations
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.ingestion.url_extractor import (
    extract_urls,
    extract_urls_from_headers,
    extract_urls_from_html,
    extract_urls_from_text,
)
from app.schemas import (
    AuthenticationMetadata,
    AuthenticationResult,
    AuthMechanism,
    AuthProvenance,
    AuthStatus,
    EmailData,
    EmailHeaders,
    ExtractedURL,
    URLSource,
    VerificationStatus,
)


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def _dummy_auth() -> AuthenticationMetadata:
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


def _make_email_data(
    plain_text_body: str | None = None,
    html_body: str | None = None,
    headers: EmailHeaders | None = None,
) -> EmailData:
    return EmailData(
        email_id="test-msg-001",
        source_filename="test.eml",
        headers=headers or EmailHeaders(),
        authentication=_dummy_auth(),
        plain_text_body=plain_text_body,
        html_body=html_body,
        ingestion_timestamp=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# 1. Plain-text HTTP URL
# ---------------------------------------------------------------------------

class TestPlainTextHttpUrl:
    """Scenario 1: Plain-text HTTP URL."""

    def test_plain_text_http(self):
        email_data = _make_email_data(plain_text_body="Please visit http://example.com/login for access.")
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].original_url == "http://example.com/login"
        assert urls[0].normalized_url == "http://example.com/login"
        assert urls[0].scheme == "http"
        assert urls[0].hostname == "example.com"
        assert urls[0].path == "/login"
        assert urls[0].source == URLSource.PLAIN_TEXT
        assert urls[0].anchor_text is None


# ---------------------------------------------------------------------------
# 2. Plain-text HTTPS URL
# ---------------------------------------------------------------------------

class TestPlainTextHttpsUrl:
    """Scenario 2: Plain-text HTTPS URL."""

    def test_plain_text_https(self):
        email_data = _make_email_data(plain_text_body="Secure link: https://portal.company.com/auth/verify")
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].original_url == "https://portal.company.com/auth/verify"
        assert urls[0].normalized_url == "https://portal.company.com/auth/verify"
        assert urls[0].scheme == "https"
        assert urls[0].hostname == "portal.company.com"
        assert urls[0].path == "/auth/verify"
        assert urls[0].source == URLSource.PLAIN_TEXT


# ---------------------------------------------------------------------------
# 3. Multiple URLs in one message
# ---------------------------------------------------------------------------

class TestMultipleUrlsInOneMessage:
    """Scenario 3: Multiple URLs in one message."""

    def test_multiple_urls_extracted(self):
        body = (
            "Visit https://site1.org/home\n"
            "Also check https://site2.net/faq\n"
            "And backup at http://backup.site3.io/data\n"
        )
        email_data = _make_email_data(plain_text_body=body)
        urls = extract_urls(email_data)

        assert len(urls) == 3
        hostnames = [u.hostname for u in urls]
        assert "site1.org" in hostnames
        assert "site2.net" in hostnames
        assert "backup.site3.io" in hostnames


# ---------------------------------------------------------------------------
# 4. HTML anchor href
# ---------------------------------------------------------------------------

class TestHtmlAnchorHref:
    """Scenario 4: HTML anchor href."""

    def test_html_anchor_extracted(self):
        html_markup = '<p>Click <a href="https://legit-bank.com/signin">here</a> to sign in.</p>'
        email_data = _make_email_data(html_body=html_markup)
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].original_url == "https://legit-bank.com/signin"
        assert urls[0].normalized_url == "https://legit-bank.com/signin"
        assert urls[0].source == URLSource.HTML_HREF
        assert urls[0].anchor_text == "here"
        assert urls[0].hostname == "legit-bank.com"


# ---------------------------------------------------------------------------
# 5. HTML anchor text differing from href
# ---------------------------------------------------------------------------

class TestHtmlAnchorTextDifferingFromHref:
    """Scenario 5: HTML anchor text differing from href (deceptive link)."""

    def test_deceptive_anchor_text_preserved(self):
        html_markup = '<p>Account issue: <a href="http://phishing.attacker.ru/steal">https://www.paypal.com/signin</a></p>'
        email_data = _make_email_data(html_body=html_markup)
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].original_url == "http://phishing.attacker.ru/steal"
        assert urls[0].anchor_text == "https://www.paypal.com/signin"
        assert urls[0].hostname == "phishing.attacker.ru"
        assert urls[0].source == URLSource.HTML_HREF


# ---------------------------------------------------------------------------
# 6. HTML image src
# ---------------------------------------------------------------------------

class TestHtmlImageSrc:
    """Scenario 6: HTML image src."""

    def test_image_src_extracted(self):
        html_markup = '<img src="https://tracker.com/pixel.png" alt="tracker">'
        email_data = _make_email_data(html_body=html_markup)
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].original_url == "https://tracker.com/pixel.png"
        assert urls[0].source == URLSource.HTML_SRC
        assert urls[0].hostname == "tracker.com"
        assert urls[0].anchor_text is None


# ---------------------------------------------------------------------------
# 7. Duplicate URL in multiple locations
# ---------------------------------------------------------------------------

class TestDuplicateUrlDeduplication:
    """Scenario 7: Duplicate URL in multiple locations."""

    def test_different_sources_and_anchor_texts_preserved(self):
        plain = "Check https://example.com/page"
        html = (
            '<p><a href="https://example.com/page">Link A</a></p>'
            '<p><a href="https://example.com/page">Link B</a></p>'
            '<p><a href="https://example.com/page">Link A</a></p>'  # Exact duplicate of first anchor
            '<img src="https://example.com/page">'
        )
        email_data = _make_email_data(plain_text_body=plain, html_body=html)
        urls = extract_urls(email_data)

        # Expected distinct occurrences:
        # 1. Plain text: (https://example.com/page, PLAIN_TEXT, None)
        # 2. HTML href with Link A: (https://example.com/page, HTML_HREF, "Link A")
        # 3. HTML href with Link B: (https://example.com/page, HTML_HREF, "Link B")
        # 4. HTML src: (https://example.com/page, HTML_SRC, None)
        # The repeated "Link A" must be deduplicated!
        assert len(urls) == 4

        sources = [(u.source, u.anchor_text) for u in urls]
        assert (URLSource.PLAIN_TEXT, None) in sources
        assert (URLSource.HTML_HREF, "Link A") in sources
        assert (URLSource.HTML_HREF, "Link B") in sources
        assert (URLSource.HTML_SRC, None) in sources


# ---------------------------------------------------------------------------
# 8. Query parameters and fragments
# ---------------------------------------------------------------------------

class TestQueryParametersAndFragments:
    """Scenario 8: Query parameters and fragments."""

    def test_query_and_fragment_preserved(self):
        raw = "https://shop.com/search?category=shoes&sort=price_asc#page2"
        email_data = _make_email_data(plain_text_body=raw)
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].query == "category=shoes&sort=price_asc"
        assert "#page2" in urls[0].normalized_url
        assert urls[0].hostname == "shop.com"
        assert urls[0].path == "/search"


# ---------------------------------------------------------------------------
# 9. Percent-encoded URLs
# ---------------------------------------------------------------------------

class TestPercentEncodedUrls:
    """Scenario 9: Percent-encoded URLs."""

    def test_percent_encoding_handled(self):
        raw = "http://example.com/path%20with%20spaces/item%2F1?param=%3Fval%26key"
        email_data = _make_email_data(plain_text_body=raw)
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert "%20" in urls[0].normalized_url
        assert urls[0].hostname == "example.com"
        assert "%20with%20spaces" in urls[0].path


# ---------------------------------------------------------------------------
# 10. Unicode domain
# ---------------------------------------------------------------------------

class TestUnicodeDomain:
    """Scenario 10: Unicode domain."""

    def test_unicode_domain_punycode_normalized(self):
        raw = "https://münchen.de/kultur/rathaus"
        email_data = _make_email_data(plain_text_body=raw)
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].original_url == raw
        # IDN punycode for münchen.de is xn--mnchen-3ya.de
        assert urls[0].hostname == "xn--mnchen-3ya.de"
        assert "xn--mnchen-3ya.de" in urls[0].normalized_url


# ---------------------------------------------------------------------------
# 11. Punycode domain
# ---------------------------------------------------------------------------

class TestPunycodeDomain:
    """Scenario 11: Punycode domain."""

    def test_punycode_domain_preserved(self):
        raw = "https://xn--e1afmkfd.xn--p1ai/index.html"
        email_data = _make_email_data(plain_text_body=raw)
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].hostname == "xn--e1afmkfd.xn--p1ai"
        assert urls[0].scheme == "https"


# ---------------------------------------------------------------------------
# 12. IP-address-based URL
# ---------------------------------------------------------------------------

class TestIpAddressBasedUrl:
    """Scenario 12: IP-address-based URL."""

    def test_ipv4_address_url(self):
        raw = "http://192.168.1.100:8080/admin/settings"
        email_data = _make_email_data(plain_text_body=raw)
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].hostname == "192.168.1.100"
        assert urls[0].scheme == "http"
        assert ":8080" in urls[0].normalized_url
        assert urls[0].path == "/admin/settings"


# ---------------------------------------------------------------------------
# 13. Unusual valid port
# ---------------------------------------------------------------------------

class TestUnusualValidPort:
    """Scenario 13: Unusual valid port."""

    def test_unusual_port_preserved(self):
        raw = "https://example.com:2083/cpanel"
        email_data = _make_email_data(plain_text_body=raw)
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].hostname == "example.com"
        assert ":2083" in urls[0].normalized_url
        assert urls[0].path == "/cpanel"


# ---------------------------------------------------------------------------
# 14. javascript: scheme
# ---------------------------------------------------------------------------

class TestJavascriptScheme:
    """Scenario 14: javascript: scheme."""

    def test_javascript_scheme_in_html_href(self):
        html_markup = '<a href="javascript:alert(\'pwned\')">Click to win</a>'
        email_data = _make_email_data(html_body=html_markup)
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].scheme == "javascript"
        assert "alert" in urls[0].original_url
        assert urls[0].hostname is None
        assert urls[0].source == URLSource.HTML_HREF
        assert urls[0].anchor_text == "Click to win"


# ---------------------------------------------------------------------------
# 15. data: scheme
# ---------------------------------------------------------------------------

class TestDataScheme:
    """Scenario 15: data: scheme."""

    def test_data_scheme_extracted(self):
        data_url = "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
        html_markup = f'<a href="{data_url}">Data Document</a>'
        email_data = _make_email_data(html_body=html_markup)
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].scheme == "data"
        assert urls[0].original_url == data_url
        assert urls[0].hostname is None


# ---------------------------------------------------------------------------
# 16. file: scheme
# ---------------------------------------------------------------------------

class TestFileScheme:
    """Scenario 16: file: scheme."""

    def test_file_scheme_extracted(self):
        file_url = "file:///etc/passwd"
        html_markup = f'<a href="{file_url}">Local file</a>'
        email_data = _make_email_data(html_body=html_markup)
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].scheme == "file"
        assert urls[0].original_url == file_url
        assert urls[0].path == "/etc/passwd"


# ---------------------------------------------------------------------------
# 17. URL with user information
# ---------------------------------------------------------------------------

class TestUrlWithUserInfo:
    """Scenario 17: URL with user information."""

    def test_user_info_preserved(self):
        raw = "http://admin:secret123@phish-gateway.com/verify"
        email_data = _make_email_data(plain_text_body=raw)
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert "admin:secret123@" in urls[0].normalized_url
        assert urls[0].hostname == "phish-gateway.com"
        assert urls[0].path == "/verify"


# ---------------------------------------------------------------------------
# 18. Malformed URL
# ---------------------------------------------------------------------------

class TestMalformedUrl:
    """Scenario 18: Malformed URL."""

    def test_malformed_url_does_not_crash(self):
        # Malformed IPv6 literal that raises ValueError in urlsplit
        bad_url = "http://[invalid-ipv6/broken"
        email_data = _make_email_data(plain_text_body=f"Visit {bad_url} now")
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].original_url == bad_url
        assert urls[0].source == URLSource.PLAIN_TEXT


# ---------------------------------------------------------------------------
# 19. URL-like text without a scheme
# ---------------------------------------------------------------------------

class TestUrlLikeTextWithoutScheme:
    """Scenario 19: URL-like text without a scheme."""

    def test_www_prefix_extracted_and_normalized(self):
        email_data = _make_email_data(plain_text_body="Check www.phishing-target.com/login for updates.")
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].original_url == "www.phishing-target.com/login"
        assert urls[0].normalized_url == "http://www.phishing-target.com/login"
        assert urls[0].scheme == "http"
        assert urls[0].hostname == "www.phishing-target.com"
        assert urls[0].path == "/login"


# ---------------------------------------------------------------------------
# 20. Ordinary email addresses must not be extracted
# ---------------------------------------------------------------------------

class TestOrdinaryEmailAddressesNotExtracted:
    """Scenario 20: Ordinary email addresses must not be extracted."""

    def test_email_addresses_in_plain_text_not_extracted(self):
        body = (
            "Contact our support team at support@example.com or security@corp.net.\n"
            "Do not reply to noreply@sub.domain.org."
        )
        email_data = _make_email_data(plain_text_body=body)
        urls = extract_urls(email_data)

        assert len(urls) == 0

    def test_mailto_in_html_not_extracted_as_url(self):
        html_markup = '<a href="mailto:phish-target@victim.org">Email Us</a>'
        email_data = _make_email_data(html_body=html_markup)
        urls = extract_urls(email_data)

        assert len(urls) == 0

    def test_email_addresses_in_headers_not_extracted(self):
        headers = EmailHeaders(
            from_address="John Doe <john.doe@company.com>",
            reply_to="reply@secure.org",
            subject="Standard Subject",
        )
        email_data = _make_email_data(headers=headers)
        urls = extract_urls(email_data)

        assert len(urls) == 0


# ---------------------------------------------------------------------------
# 21. Very long URL
# ---------------------------------------------------------------------------

class TestVeryLongUrl:
    """Scenario 21: Very long URL."""

    def test_very_long_url_processed_safely(self):
        long_query = "a=" + ("x" * 5000)
        long_url = f"https://example.com/api?{long_query}"
        email_data = _make_email_data(plain_text_body=f"Visit {long_url}")
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].hostname == "example.com"
        assert len(urls[0].original_url) > 5000


# ---------------------------------------------------------------------------
# 22. URL surrounded by punctuation
# ---------------------------------------------------------------------------

class TestUrlSurroundedByPunctuation:
    """Scenario 22: URL surrounded by punctuation."""

    def test_punctuation_stripping(self):
        body = (
            "In parens: (https://example.com/one)\n"
            "In brackets: [https://example.com/two]\n"
            "In quotes: \"https://example.com/three\"\n"
            "With trailing period: https://example.com/four.\n"
            "With trailing comma: https://example.com/five,\n"
            "With question mark: https://example.com/six?\n"
            "Wikipedia with balanced parens: https://en.wikipedia.org/wiki/Phishing_(disambiguation)\n"
        )
        email_data = _make_email_data(plain_text_body=body)
        urls = extract_urls(email_data)

        assert len(urls) == 7
        orig_urls = [u.original_url for u in urls]
        assert "https://example.com/one" in orig_urls
        assert "https://example.com/two" in orig_urls
        assert "https://example.com/three" in orig_urls
        assert "https://example.com/four" in orig_urls
        assert "https://example.com/five" in orig_urls
        assert "https://example.com/six" in orig_urls
        assert "https://en.wikipedia.org/wiki/Phishing_(disambiguation)" in orig_urls


# ---------------------------------------------------------------------------
# 23. URL containing HTML entities
# ---------------------------------------------------------------------------

class TestUrlContainingHtmlEntities:
    """Scenario 23: URL containing HTML entities."""

    def test_html_entities_decoded_in_plain_text(self):
        plain_body = "Access token: https://example.com/auth?token=abc&amp;scope=read&amp;id=123"
        email_data = _make_email_data(plain_text_body=plain_body)
        urls = extract_urls(email_data)

        assert len(urls) == 1
        # Original preserves exact text value
        assert "&amp;" in urls[0].original_url
        # Normalized decodes &amp; to &
        assert "&amp;" not in urls[0].normalized_url
        assert urls[0].query == "token=abc&scope=read&id=123"

    def test_html_entities_in_html_anchor(self):
        html_markup = '<a href="https://example.com/auth?token=abc&amp;scope=read">Access</a>'
        email_data = _make_email_data(html_body=html_markup)
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].query == "token=abc&scope=read"


# ---------------------------------------------------------------------------
# 24. Empty email body
# ---------------------------------------------------------------------------

class TestEmptyEmailBody:
    """Scenario 24: Empty email body."""

    def test_none_bodies(self):
        email_data = _make_email_data(plain_text_body=None, html_body=None)
        urls = extract_urls(email_data)
        assert urls == []

    def test_empty_string_bodies(self):
        email_data = _make_email_data(plain_text_body="", html_body="   ")
        urls = extract_urls(email_data)
        assert urls == []


# ---------------------------------------------------------------------------
# 25. Email with both plain text and HTML representations
# ---------------------------------------------------------------------------

class TestEmailWithBothPlainAndHtml:
    """Scenario 25: Email with both plain text and HTML representations."""

    def test_both_representations_extracted_with_correct_sources(self):
        plain = "Plain link: https://plain-only.com/path"
        html = (
            '<p>HTML link: <a href="https://html-only.com/path">Click</a></p>'
            '<img src="https://shared-host.com/pixel.gif">'
        )
        email_data = _make_email_data(plain_text_body=plain, html_body=html)
        urls = extract_urls(email_data)

        assert len(urls) == 3
        source_map = {u.hostname: u.source for u in urls}
        assert source_map["plain-only.com"] == URLSource.PLAIN_TEXT
        assert source_map["html-only.com"] == URLSource.HTML_HREF
        assert source_map["shared-host.com"] == URLSource.HTML_SRC


# ---------------------------------------------------------------------------
# Additional Edge Cases
# ---------------------------------------------------------------------------

class TestAdditionalUrlEdgeCases:
    """Additional edge cases: Header URLs, Line wrapping, Iframe, Form Action."""

    def test_header_url_extracted(self):
        headers = EmailHeaders(
            from_address="Support (https://support-fake.com) <support@legit.com>",
            subject="Urgent: Check https://alert-system.org/verify now",
        )
        email_data = _make_email_data(headers=headers)
        urls = extract_urls(email_data)

        assert len(urls) == 2
        hostnames = [u.hostname for u in urls]
        assert "support-fake.com" in hostnames
        assert "alert-system.org" in hostnames
        for u in urls:
            assert u.source == URLSource.HEADER

    def test_line_wrapped_bracketed_url(self):
        wrapped_text = (
            "Please click: <https://example.com/very/long/\n"
            "resource/path/\n"
            "continuation?param=1>\n"
        )
        email_data = _make_email_data(plain_text_body=wrapped_text)
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].original_url == "https://example.com/very/long/resource/path/continuation?param=1"
        assert urls[0].hostname == "example.com"
        assert urls[0].query == "param=1"

    def test_iframe_and_form_action_extracted(self):
        html_markup = (
            '<iframe src="https://embedded-phish.net/login.html"></iframe>'
            '<form action="https://collector.evil.com/post_creds" method="POST"></form>'
        )
        email_data = _make_email_data(html_body=html_markup)
        urls = extract_urls(email_data)

        assert len(urls) == 2
        hostnames = [u.hostname for u in urls]
        assert "embedded-phish.net" in hostnames
        assert "collector.evil.com" in hostnames


# ---------------------------------------------------------------------------
# Task 5.1: Invalid URL Port Handling
# ---------------------------------------------------------------------------

class TestTask51InvalidUrlPorts:
    """Task 5.1: Safe handling of invalid and boundary URL ports."""

    def test_out_of_range_port_99999(self):
        raw = "https://example.com:99999/login"
        email_data = _make_email_data(plain_text_body=f"Visit {raw}")
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].original_url == raw
        # Must preserve original as evidence, but not misclassify as valid HTTP/HTTPS
        assert urls[0].scheme is None
        assert urls[0].hostname is None

    def test_out_of_range_port_65536(self):
        raw = "https://example.com:65536/"
        email_data = _make_email_data(plain_text_body=f"Visit {raw}")
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].original_url == raw
        assert urls[0].scheme is None
        assert urls[0].hostname is None

    def test_valid_boundary_port_65535(self):
        raw = "https://example.com:65535/"
        email_data = _make_email_data(plain_text_body=f"Visit {raw}")
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].original_url == raw
        assert urls[0].scheme == "https"
        assert urls[0].hostname == "example.com"
        assert urls[0].normalized_url == "https://example.com:65535/"

    def test_valid_standard_port_443(self):
        raw = "https://example.com:443/"
        email_data = _make_email_data(plain_text_body=f"Visit {raw}")
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].original_url == raw
        assert urls[0].scheme == "https"
        assert urls[0].hostname == "example.com"
        assert urls[0].normalized_url == "https://example.com/"

    def test_non_numeric_port_abc(self):
        raw = "https://example.com:abc/"
        email_data = _make_email_data(plain_text_body=f"Visit {raw}")
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].original_url == raw
        assert urls[0].scheme is None
        assert urls[0].hostname is None

    def test_valid_url_without_explicit_port(self):
        raw = "https://example.com/normal"
        email_data = _make_email_data(plain_text_body=f"Visit {raw}")
        urls = extract_urls(email_data)

        assert len(urls) == 1
        assert urls[0].original_url == raw
        assert urls[0].scheme == "https"
        assert urls[0].hostname == "example.com"
        assert urls[0].normalized_url == "https://example.com/normal"
