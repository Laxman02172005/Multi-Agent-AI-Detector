"""
app/agents/text_components/lexical_metrics.py
---------------------------------------------
Lexical statistics, entropy computation, readability features,
and generic greeting detection.
"""

from __future__ import annotations

import collections
import math
import re
from typing import Optional, NamedTuple


GENERIC_GREETING_REGEX = re.compile(
    r"\b("
    r"(?:dear|hello|hi|greetings|attention)\s+"
    r"(?:customer|user|client|member|account\s+holder|valued\s+(?:customer|member|client)|"
    r"sir(?:\/|\s+or\s+)madam|subscriber|taxpayer|citizen|friend|shopper|cardholder)"
    r")\b",
    re.IGNORECASE,
)


class LexicalMetricsResult(NamedTuple):
    has_body: bool
    has_plain_text: bool
    has_html: bool
    word_count: int
    character_count: int
    html_to_text_ratio: Optional[float]
    body_entropy: Optional[float]
    generic_greeting_present: bool


def compute_shannon_entropy(text: str) -> Optional[float]:
    """
    Compute Shannon entropy over character distribution in text.
    Formula: -sum(p_i * log2(p_i))
    Returns None if text is empty.
    """
    if not text:
        return None
    counts = collections.Counter(text)
    total = len(text)
    entropy = -sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values())
    return round(entropy, 4)


def compute_html_to_text_ratio(
    cleaned_text: Optional[str],
    html_body: Optional[str],
) -> Optional[float]:
    """
    Compute ratio of cleaned text length to raw HTML length.
    Returns None if no HTML body is present.
    """
    if not html_body or not html_body.strip():
        return None
    cleaned_len = len((cleaned_text or "").strip())
    html_len = len(html_body.strip())
    if html_len == 0:
        return None
    return round(cleaned_len / html_len, 4)


def detect_generic_greeting(text: str) -> bool:
    """
    Detect non-personalized generic greetings (e.g., 'Dear Customer', 'Hello Member')
    within the first 350 characters of cleaned email body text.
    """
    if not text:
        return False
    lead_text = text[:350]
    return bool(GENERIC_GREETING_REGEX.search(lead_text))


def analyze_lexical_metrics(
    plain_text: Optional[str],
    html_body: Optional[str],
    cleaned_text: Optional[str],
) -> LexicalMetricsResult:
    """Extract all Category C lexical, volumetric, and entropy metrics."""
    has_plain = bool(plain_text and plain_text.strip())
    has_html = bool(html_body and html_body.strip())
    has_body = bool((cleaned_text and cleaned_text.strip()) or has_plain or has_html)

    target_text = (cleaned_text or plain_text or "").strip()
    words = target_text.split() if target_text else []
    word_count = len(words)
    char_count = len(target_text)

    entropy = compute_shannon_entropy(target_text) if target_text else None
    h2t_ratio = compute_html_to_text_ratio(cleaned_text, html_body)
    has_generic = detect_generic_greeting(target_text)

    return LexicalMetricsResult(
        has_body=has_body,
        has_plain_text=has_plain,
        has_html=has_html,
        word_count=word_count,
        character_count=char_count,
        html_to_text_ratio=h2t_ratio,
        body_entropy=entropy,
        generic_greeting_present=has_generic,
    )
