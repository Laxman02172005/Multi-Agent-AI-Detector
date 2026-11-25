"""
lexical_features.py
--------------------
Lexical and structural character-level feature extraction for the URL Agent.

Computes Shannon entropy, path depth, executable file extensions, percent encodings,
embedded credentials, unusual IP notations, and two-pronged Punycode detection.
"""

from __future__ import annotations

import collections
import math
import re
from typing import Optional


# Executable extensions monitored under Feature 11
_EXECUTABLE_EXTENSIONS = (
    ".exe",
    ".scr",
    ".bat",
    ".vbs",
    ".cpl",
    ".msi",
    ".apk",
    ".cmd",
)

# Regex patterns for encodings and authority inspection
_HEX_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_DOUBLE_PERCENT_RE = re.compile(r"%25[0-9a-fA-F]{2}", re.IGNORECASE)

# Hexadecimal IP pattern: e.g. 0x7f.0.0.1 or 0x7f000001
_HEX_IP_RE = re.compile(r"^0x[0-9a-fA-F]+(\.[0-9a-zA-Z.]+)?$", re.IGNORECASE)
# Octal IP pattern: e.g. 0177.0.0.1
_OCTAL_IP_RE = re.compile(r"^0[0-7]+(\.[0-9a-zA-Z.]+)?$")
# Pure integer IP pattern: e.g. 2130706433 (between 1 and 2^32-1)
_INT_IP_RE = re.compile(r"^\d{4,10}$")


def compute_hostname_entropy(hostname: Optional[str]) -> Optional[float]:
    """
    Compute the Shannon entropy of a hostname string:
        H(s) = -sum p_i * log2(p_i)

    Returns None if hostname is None, empty, or whitespace.
    """
    if not hostname:
        return None

    clean = hostname.strip().lower()
    if not clean:
        return None

    total_chars = len(clean)
    counts = collections.Counter(clean)
    entropy = 0.0

    for count in counts.values():
        p_i = count / total_chars
        entropy -= p_i * math.log2(p_i)

    return float(entropy)


def count_path_segments(path_str: Optional[str]) -> int:
    """
    Count the number of non-empty path segments separated by '/'.
    Excludes leading and trailing empty segments.
    """
    if not path_str:
        return 0

    clean_path = path_str.strip()
    segments = [seg for seg in clean_path.split("/") if seg]
    return len(segments)


def has_executable_file_in_path(path_str: Optional[str]) -> bool:
    """
    Check if the path terminates with an executable extension (.exe, .scr, .bat, etc.).
    Case-insensitive.
    """
    if not path_str:
        return False

    clean = path_str.strip().lower()
    # Strip any trailing slashes
    clean = clean.rstrip("/")
    if not clean:
        return False

    # Extract the last segment
    last_segment = clean.split("/")[-1]
    return any(last_segment.endswith(ext) for ext in _EXECUTABLE_EXTENSIONS)


def has_at_symbol_in_url(netloc: Optional[str], raw_url: str) -> bool:
    """
    Check if authority segment contains '@' preceding the host.
    """
    if netloc and "@" in netloc:
        return True

    # Fallback to check raw authority segment if parser stripped it
    parts = raw_url.split("://", 1)
    if len(parts) == 2:
        authority_part = parts[1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        return "@" in authority_part

    return False


def has_embedded_credentials(netloc: Optional[str], raw_url: str) -> bool:
    """
    Check if the URL contains embedded credentials (e.g. username:password@ or username@).
    """
    if netloc and "@" in netloc:
        userinfo = netloc.split("@", 1)[0]
        if userinfo:
            return True

    parts = raw_url.split("://", 1)
    if len(parts) == 2:
        authority_part = parts[1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in authority_part:
            userinfo = authority_part.split("@", 1)[0]
            return bool(userinfo)

    return False


def has_percent_encoding(url_str: str) -> bool:
    """True if URL contains valid percent-encoded triplets (%[0-9a-fA-F]{2})."""
    return bool(_HEX_PERCENT_RE.search(url_str))


def has_double_percent_encoding(url_str: str) -> bool:
    """True if URL contains double percent-encoding: %25[0-9a-fA-F]{2}."""
    return bool(_DOUBLE_PERCENT_RE.search(url_str))


def count_percent_encoded_triplets(url_str: str) -> int:
    """Count total occurrences of valid percent-encoded triplets (%xx) in the URL."""
    return len(_HEX_PERCENT_RE.findall(url_str))


def has_non_ascii_url(original_url: str) -> bool:
    """
    Feature 28: True if original_url contains any character outside ASCII 32..126.
    """
    return any(ord(c) < 32 or ord(c) > 126 for c in original_url)


def detect_unusual_ip_format(host_str: Optional[str], netloc: Optional[str]) -> bool:
    """
    Feature 29: True if authority/host contains IP in hexadecimal, octal, or integer notation.
    """
    candidates = []
    if host_str:
        candidates.append(host_str.strip().strip("[]"))
    if netloc:
        # Strip userinfo and port
        clean_net = netloc.split("@")[-1].split(":")[0].strip().strip("[]")
        candidates.append(clean_net)

    for cand in candidates:
        if not cand:
            continue
        # Check hex notation: 0x7f.0.0.1 or 0x7f000001
        if cand.lower().startswith("0x") or ".0x" in cand.lower():
            return True
        # Check octal notation: 0177.0.0.1 or leading zeros on numeric dot segments
        parts = cand.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            if any(len(p) > 1 and p.startswith("0") for p in parts):
                return True
        # Check pure integer notation (e.g. 2130706433)
        if cand.isdigit() and len(cand) >= 7:
            try:
                val = int(cand)
                if 0 <= val <= 0xFFFFFFFF:
                    return True
            except ValueError:
                pass

    return False


def check_punycode(normalized_hostname: Optional[str], raw_hostname: Optional[str]) -> bool:
    """
    Feature 16: Two-pronged Punycode / IDN detection:
    - Prong 1: Normalized hostname has label starting with 'xn--'.
    - Prong 2: Raw hostname contains character with ord(c) > 127.
    Path and query non-ASCII characters are strictly excluded.
    """
    # Prong 1: xn-- check
    if normalized_hostname:
        labels = normalized_hostname.lower().split(".")
        if any(lbl.startswith("xn--") for lbl in labels):
            return True

    # Prong 2: Raw hostname Unicode check
    if raw_hostname:
        clean_raw = raw_hostname.split(":")[0].strip("[]")
        if any(ord(c) > 127 for c in clean_raw):
            return True

    return False
