"""
app/agents/text_components/obfuscation_detector.py
--------------------------------------------------
Detection of text and HTML obfuscation, hidden content, zero-width characters,
excessive capitalization/punctuation, and plain-text vs. HTML body divergence.
"""

from __future__ import annotations

import re
from typing import Optional, NamedTuple


ZERO_WIDTH_CHARS = frozenset({
    "\u200B",  # Zero-width space
    "\u200C",  # Zero-width non-joiner
    "\u200D",  # Zero-width joiner
    "\uFEFF",  # Byte order mark / zero-width no-break space
    "\u2060",  # Word joiner
    "\u200E",  # Left-to-right mark
    "\u200F",  # Right-to-left mark
    "\u00AD",  # Soft hyphen
})

HIDDEN_CSS_REGEX = re.compile(
    r"(?:"
    r"display\s*:\s*none|"
    r"visibility\s*:\s*hidden|"
    r"font-size\s*:\s*0(?:px|pt|em|rem)?\b|"
    r"opacity\s*:\s*0(?:\.0+)?\b|"
    r"max-height\s*:\s*0(?:px)?\b|"
    r"height\s*:\s*0(?:px)?\s*;\s*overflow\s*:\s*hidden|"
    r"color\s*:\s*(?:white|#ffffff|#fff|rgba?\([^)]*,\s*0(?:\.0+)?\))"
    r")",
    re.IGNORECASE,
)

EXCESSIVE_PUNCT_REGEX = re.compile(r"[!?]{3,}")


class ObfuscationAnalysisResult(NamedTuple):
    has_hidden_text: bool
    hidden_text_count: int
    has_zero_width_chars: bool
    zero_width_char_count: int
    has_excessive_capitalization: bool
    capitalization_ratio: float
    has_excessive_punctuation: bool
    excessive_punctuation_count: int
    has_plain_html_mismatch: bool
    evidence_snippets: list[str]


def detect_zero_width_characters(text: str) -> tuple[bool, int]:
    """Detect zero-width Unicode characters used for NLP evasion or watermark injection."""
    if not text:
        return False, 0
    count = sum(1 for c in text if c in ZERO_WIDTH_CHARS)
    return count > 0, count


def detect_hidden_text_css(html_body: Optional[str]) -> tuple[bool, int, list[str]]:
    """Detect CSS hiding techniques in raw HTML markup."""
    if not html_body or not html_body.strip():
        return False, 0, []

    matches = HIDDEN_CSS_REGEX.findall(html_body)
    snippets: list[str] = [m.strip() for m in matches[:10]]
    return len(matches) > 0, len(matches), snippets


def compute_capitalization_metrics(text: str) -> tuple[bool, float]:
    """
    Compute ratio of uppercase letters to total alphabetic letters.
    Flags excessive capitalization if alpha count >= 30 and ratio >= 0.30.
    """
    if not text:
        return False, 0.0

    alpha_chars = [c for c in text if c.isalpha()]
    total_alpha = len(alpha_chars)
    if total_alpha == 0:
        return False, 0.0

    upper_count = sum(1 for c in alpha_chars if c.isupper())
    ratio = round(upper_count / total_alpha, 4)
    has_excessive = total_alpha >= 30 and ratio >= 0.30
    return has_excessive, ratio


def detect_excessive_punctuation(text: str) -> tuple[bool, int]:
    """Detect clusters of repeated exclamation or question marks (e.g. '!!!', '???')."""
    if not text:
        return False, 0
    matches = EXCESSIVE_PUNCT_REGEX.findall(text)
    return len(matches) > 0, len(matches)


def detect_plain_html_mismatch(
    plain_text: Optional[str],
    html_body: Optional[str],
    cleaned_text: Optional[str],
) -> bool:
    """
    Detect whether plain-text body significantly conflicts with the HTML body.
    Phishing attacks sometimes place benign text in plain-text and malicious lures in HTML.
    """
    if not plain_text or not plain_text.strip():
        return False
    if not html_body or not html_body.strip():
        return False

    # Extract word tokens from plain text and cleaned HTML text
    plain_words = set(re.findall(r"\b[a-zA-Z]{3,}\b", plain_text.lower()))
    html_words = set(re.findall(r"\b[a-zA-Z]{3,}\b", (cleaned_text or "").lower()))

    if not plain_words or not html_words:
        return False

    # Jaccard similarity over substantive words
    intersection = plain_words.intersection(html_words)
    union = plain_words.union(html_words)
    if not union:
        return False

    jaccard = len(intersection) / len(union)

    # If overlap is under 20% while both parts have substantial content (> 10 words)
    if len(plain_words) >= 10 and len(html_words) >= 10 and jaccard < 0.20:
        return True

    return False


def analyze_obfuscation(
    plain_text: Optional[str],
    html_body: Optional[str],
    cleaned_text: Optional[str],
) -> ObfuscationAnalysisResult:
    """Execute all obfuscation, hidden text, and divergence checks."""
    combined_raw = f"{plain_text or ''}\n{html_body or ''}"
    has_zw, zw_count = detect_zero_width_characters(combined_raw)

    has_hidden, hidden_count, hidden_snippets = detect_hidden_text_css(html_body)

    target_text = cleaned_text or plain_text or ""
    has_caps, caps_ratio = compute_capitalization_metrics(target_text)
    has_punct, punct_count = detect_excessive_punctuation(target_text)

    has_mismatch = detect_plain_html_mismatch(plain_text, html_body, cleaned_text)

    evidence_snippets: list[str] = []
    if has_zw:
        evidence_snippets.append(f"Zero-width characters detected: {zw_count} occurrences.")
    if has_hidden:
        evidence_snippets.append(f"Hidden CSS styling detected: {hidden_count} occurrences ({', '.join(hidden_snippets[:3])}).")
    if has_caps:
        evidence_snippets.append(f"Excessive capitalization ratio: {caps_ratio:.1%}.")
    if has_punct:
        evidence_snippets.append(f"Excessive punctuation clusters: {punct_count} instances.")
    if has_mismatch:
        evidence_snippets.append("Substantive textual divergence detected between plain-text and HTML bodies.")

    return ObfuscationAnalysisResult(
        has_hidden_text=has_hidden,
        hidden_text_count=hidden_count,
        has_zero_width_chars=has_zw,
        zero_width_char_count=zw_count,
        has_excessive_capitalization=has_caps,
        capitalization_ratio=caps_ratio,
        has_excessive_punctuation=has_punct,
        excessive_punctuation_count=punct_count,
        has_plain_html_mismatch=has_mismatch,
        evidence_snippets=evidence_snippets,
    )
