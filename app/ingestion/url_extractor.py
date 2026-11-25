"""
url_extractor.py
----------------
Modular URL extraction component for the Multi-Agent AI Phishing Email Detector.

Identifies, extracts, normalizes, and categorizes URLs found in email bodies
(plain text and HTML) and relevant email headers, preserving their full structural
context (source location, visible anchor text, scheme, hostname, path, query).

Key Design & Security Rules:
----------------------------
1. Strictly Passive / Non-Executing:
   - Does NOT fetch, open, or resolve URLs.
   - Does NOT issue DNS requests or network calls.
   - Does NOT execute JavaScript or browser automation.
   - Does NOT perform phishing classification or reputation lookups (deferred to URL Agent).

2. Context & Source Preservation:
   - Preserves source location via URLSource (PLAIN_TEXT, HTML_HREF, HTML_SRC, HTML_OTHER, HEADER).
   - Preserves visible anchor text for HTML hyperlinks (crucial for detecting deceptive link text).
   - Preserves the original raw URL string verbatim in `original_url`.

3. Normalization & Structural Metadata:
   - Decodes HTML entities (e.g. &amp; -> &) in normalized URLs.
   - Normalizes schemes to lowercase.
   - Lowercases hostnames and applies Punycode (IDNA) normalization for internationalized domains.
   - Safely parses and preserves unusual valid ports, userinfo, queries, and fragments.
   - Supports suspicious schemes (javascript:, data:, file:) without misclassifying them as web links.
   - Tolerates malformed URL syntax without raising unhandled exceptions.

4. Deduplication Policy:
   - Identical destination URLs with the SAME source and SAME visible anchor text are deduplicated.
   - Distinct occurrences across different sources (e.g. plain text vs. HTML) or with different
     anchor texts (e.g. "Click Here" vs. "https://paypal.com") are strictly preserved.

5. Email Address Protection:
   - Ordinary email addresses (e.g. user@example.com) and mailto: links are NOT extracted as URLs.
"""

from __future__ import annotations

import html
import re
import urllib.parse
from typing import Optional

from bs4 import BeautifulSoup

from app.schemas.email_schema import EmailData, EmailHeaders, ExtractedURL, URLSource


# ---------------------------------------------------------------------------
# Regular Expressions for Plain-Text & Header URL Extraction
# ---------------------------------------------------------------------------

# Matches bracketed URLs <https://...> that might span multiple lines
_BRACKETED_URL_RE = re.compile(
    r"<((?:https?|ftp)://[^>]+)>",
    re.DOTALL | re.IGNORECASE,
)

# Matches URLs starting with http://, https://, ftp:// or www.
# Ensures not preceded by '@' or word characters to avoid matching email addresses
_PLAIN_URL_RE = re.compile(
    r"(?<![@\w])(?:(?:https?|ftp)://|www\.)[^\s<>\"\'`]+",
    re.IGNORECASE,
)

# Trailing characters that may be sentence punctuation rather than part of the URL
_TRAILING_PUNCT = ".,;:!?)]}>'\""


def _strip_punctuation(raw_url: str) -> str:
    """
    Strip surrounding and trailing punctuation while preserving balanced brackets.

    For example:
      '(https://example.com/)' -> 'https://example.com/'
      'https://example.com/path.' -> 'https://example.com/path'
      'https://en.wikipedia.org/wiki/Phishing_(disambiguation)' -> preserved balanced parens
    """
    url = raw_url.lstrip('<([{"\'')
    while url and url[-1] in _TRAILING_PUNCT:
        # If closing bracket, only strip if unbalanced
        if url[-1] == ")" and url.count("(") >= url.count(")"):
            break
        if url[-1] == "]" and url.count("[") >= url.count("]"):
            break
        if url[-1] == "}" and url.count("{") >= url.count("}"):
            break
        url = url[:-1]
    return url


# ---------------------------------------------------------------------------
# Normalization and Structural Property Parsing
# ---------------------------------------------------------------------------

def _normalize_and_parse_url(
    raw_url: str,
) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Parse a raw URL string into structural components and generate a normalized URL.

    Returns:
        (normalized_url, scheme, hostname, path, query)
    """
    if not raw_url:
        return (None, None, None, None, None)

    # 1. Unescape HTML entities
    unescaped = html.unescape(raw_url.strip())

    # 2. Check for special schemes
    lower_raw = unescaped.lower()

    if lower_raw.startswith("javascript:"):
        scheme = "javascript"
        path = unescaped[len("javascript:"):].strip()
        return (unescaped, scheme, None, path if path else None, None)

    if lower_raw.startswith("data:"):
        scheme = "data"
        path = unescaped[len("data:"):].strip()
        return (unescaped, scheme, None, path if path else None, None)

    if lower_raw.startswith("file:"):
        scheme = "file"
        try:
            res = urllib.parse.urlsplit(unescaped)
            return (unescaped, scheme, res.hostname or None, res.path if res.path else None, None)
        except Exception:
            return (unescaped, scheme, None, None, None)

    # 3. Handle scheme-less URLs (e.g. starting with www.)
    has_inferred_scheme = False
    url_to_split = unescaped
    if lower_raw.startswith("www."):
        url_to_split = "http://" + unescaped
        has_inferred_scheme = True

    try:
        split_res = urllib.parse.urlsplit(url_to_split)
        port = split_res.port
    except (ValueError, Exception):
        # Malformed URL syntax (e.g. invalid IPv6 brackets or out-of-range/non-numeric port)
        return (unescaped, None, None, None, None)

    scheme = split_res.scheme.lower() if split_res.scheme else (None if not has_inferred_scheme else "http")
    raw_hostname = split_res.hostname

    # Normalize hostname (lowercase + IDN punycode)
    hostname: Optional[str] = None
    if raw_hostname:
        raw_hostname = raw_hostname.lower()
        try:
            hostname = raw_hostname.encode("idna").decode("ascii")
        except Exception:
            hostname = raw_hostname

    # Normalize path: default to '/' for web schemes if empty
    path = split_res.path
    norm_path = path
    if not path and scheme in ("http", "https"):
        norm_path = "/"

    # Normalize query string
    query = split_res.query if split_res.query else None

    # Reconstruct normalized URL
    netloc_parts: list[str] = []
    if split_res.username:
        if split_res.password:
            netloc_parts.append(f"{split_res.username}:{split_res.password}@")
        else:
            netloc_parts.append(f"{split_res.username}@")

    netloc_parts.append(hostname or "")

    if port:
        # Omit default ports from canonical normalized URL
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            pass
        else:
            netloc_parts.append(f":{port}")

    norm_netloc = "".join(netloc_parts)

    try:
        normalized_url = urllib.parse.urlunsplit((
            scheme or "",
            norm_netloc,
            norm_path,
            split_res.query,
            split_res.fragment,
        ))
    except Exception:
        normalized_url = unescaped

    return (normalized_url, scheme, hostname, path if path else None, query)


def _build_extracted_url(
    original_url: str,
    source: URLSource,
    anchor_text: Optional[str] = None,
) -> ExtractedURL:
    """Construct an ExtractedURL instance with parsed metadata."""
    norm_url, scheme, hostname, path, query = _normalize_and_parse_url(original_url)
    return ExtractedURL(
        original_url=original_url,
        normalized_url=norm_url,
        source=source,
        anchor_text=anchor_text,
        scheme=scheme,
        hostname=hostname,
        path=path,
        query=query,
    )


# ---------------------------------------------------------------------------
# Plain-Text & Header URL Extraction
# ---------------------------------------------------------------------------

def _extract_plain_text_candidates(text: str) -> list[str]:
    """Scan plain text for candidate URL strings without matching email addresses."""
    if not text:
        return []

    candidates: list[str] = []

    # 1. Extract bracketed URLs <https://...> which may span multiple lines
    def _bracket_replacer(match: re.Match) -> str:
        raw_inner = match.group(1)
        cleaned_inner = re.sub(r"\s+", "", raw_inner)
        candidates.append(cleaned_inner)
        return " " * len(match.group(0))

    scrubbed = _BRACKETED_URL_RE.sub(_bracket_replacer, text)

    # 2. Extract standard URLs and www. URLs
    for match in _PLAIN_URL_RE.finditer(scrubbed):
        raw_candidate = match.group(0)
        cleaned = _strip_punctuation(raw_candidate)
        if cleaned:
            # Avoid matching email addresses (contains @ and no /)
            if "@" in cleaned and "/" not in cleaned:
                continue
            candidates.append(cleaned)

    return candidates


def extract_urls_from_text(
    text: Optional[str],
    source: URLSource = URLSource.PLAIN_TEXT,
) -> list[ExtractedURL]:
    """Extract URLs from a plain-text string."""
    if not text:
        return []

    raw_candidates = _extract_plain_text_candidates(text)
    return [_build_extracted_url(cand, source) for cand in raw_candidates]


def extract_urls_from_headers(headers: EmailHeaders) -> list[ExtractedURL]:
    """
    Extract URLs from relevant email header fields (From, Reply-To, Subject, Return-Path).

    Only actual URLs are extracted; ordinary email addresses are strictly excluded.
    """
    header_fields = [
        headers.from_address,
        headers.reply_to,
        headers.subject,
        headers.return_path,
    ]

    urls: list[ExtractedURL] = []
    for field_val in header_fields:
        if field_val:
            for cand in _extract_plain_text_candidates(field_val):
                urls.append(_build_extracted_url(cand, URLSource.HEADER))

    return urls


# ---------------------------------------------------------------------------
# HTML URL Extraction
# ---------------------------------------------------------------------------

def extract_urls_from_html(html_content: Optional[str]) -> list[ExtractedURL]:
    """
    Extract URLs from HTML markup:
      - <a> href attributes (preserving visible anchor text)
      - <img> src attributes
      - <iframe>, <embed>, <audio>, <video>, <source>, <script> src attributes
      - <form> action attributes
      - <link> href attributes
      - Plain-text URLs occurring in visible HTML text outside <a> tags
    """
    if not html_content or not html_content.strip():
        return []

    try:
        soup = BeautifulSoup(html_content, "html.parser")
    except Exception:
        # Fallback to plain text scan if BeautifulSoup fails
        return extract_urls_from_text(html_content, URLSource.HTML_OTHER)

    urls: list[ExtractedURL] = []

    # 1. <a> anchor tags with href
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"].strip()
        if not href or href == "#":
            continue

        lower_href = href.lower()
        if lower_href.startswith("mailto:") or lower_href.startswith("tel:"):
            continue

        # Extract visible anchor text
        anchor_text = a_tag.get_text(separator=" ", strip=True)
        if not anchor_text:
            # Check for inner image alt text
            img = a_tag.find("img")
            if img and img.get("alt"):
                anchor_text = img["alt"].strip()
            else:
                anchor_text = None

        urls.append(_build_extracted_url(href, URLSource.HTML_HREF, anchor_text=anchor_text))

    # 2. <img> image src attributes
    for img_tag in soup.find_all("img", src=True):
        src = img_tag["src"].strip()
        if not src or src.lower().startswith("cid:"):
            continue
        urls.append(_build_extracted_url(src, URLSource.HTML_SRC))

    # 3. <iframe>, <embed>, <audio>, <video>, <source>, <script> src attributes
    for tag_name in ("iframe", "embed", "audio", "video", "source", "script"):
        for tag in soup.find_all(tag_name, src=True):
            src = tag["src"].strip()
            if not src or src.lower().startswith("cid:"):
                continue
            urls.append(_build_extracted_url(src, URLSource.HTML_SRC))

    # 4. <form action="...">
    for form_tag in soup.find_all("form", action=True):
        action = form_tag["action"].strip()
        if action and action != "#":
            urls.append(_build_extracted_url(action, URLSource.HTML_OTHER))

    # 5. <link href="...">
    for link_tag in soup.find_all("link", href=True):
        href = link_tag["href"].strip()
        if href and not href.lower().startswith("mailto:"):
            urls.append(_build_extracted_url(href, URLSource.HTML_OTHER))

    # 6. Unlinked plain URLs appearing in text outside <a> tags
    # Remove existing <a>, <script>, <style> tags to avoid duplicate anchor extractions
    for tag in soup(["a", "script", "style"]):
        tag.decompose()
    remaining_text = soup.get_text()
    for cand in _extract_plain_text_candidates(remaining_text):
        urls.append(_build_extracted_url(cand, URLSource.PLAIN_TEXT))

    return urls


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _deduplicate_urls(urls: list[ExtractedURL]) -> list[ExtractedURL]:
    """
    Deduplicate identical URL occurrences.

    Policy:
      A URL occurrence is keyed on (normalized_url, source, anchor_text).
      - Redundant identical URLs within the same context are eliminated.
      - Distinct occurrences with different sources (e.g. plain text vs HTML)
        or different visible anchor text (e.g. "Click Here" vs "Login") are preserved.
    """
    seen: set[tuple[str, URLSource, Optional[str]]] = set()
    deduped: list[ExtractedURL] = []

    for u in urls:
        url_key = u.normalized_url or u.original_url.strip()
        key = (url_key, u.source, u.anchor_text)
        if key not in seen:
            seen.add(key)
            deduped.append(u)

    return deduped


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_urls(email_data: EmailData) -> list[ExtractedURL]:
    """
    Extract and normalize all URLs from an EmailData instance.

    Scans:
      - Plain-text body (PLAIN_TEXT)
      - HTML body (HTML_HREF, HTML_SRC, HTML_OTHER, and unlinked PLAIN_TEXT)
      - Relevant headers (HEADER)

    Returns:
        list[ExtractedURL]: Deduplicated list of ExtractedURL objects.
    """
    collected: list[ExtractedURL] = []

    # 1. Plain-text body
    if email_data.plain_text_body:
        collected.extend(extract_urls_from_text(email_data.plain_text_body, URLSource.PLAIN_TEXT))

    # 2. HTML body
    if email_data.html_body:
        collected.extend(extract_urls_from_html(email_data.html_body))

    # 3. Relevant headers
    if email_data.headers:
        collected.extend(extract_urls_from_headers(email_data.headers))

    return _deduplicate_urls(collected)
