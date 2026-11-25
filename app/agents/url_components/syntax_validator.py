"""
syntax_validator.py
--------------------
Safe URL syntax parser and structural validation engine for the URL Agent.

Evaluates the 5 approved structural syntax conditions for Feature 30 (malformed_url_count)
with single bounded increment guarantee and comprehensive diagnostic failure reason reporting.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import List, Tuple


_HEX_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")


def validate_url_syntax(url_str: str) -> Tuple[bool, List[str]]:
    """
    Validate the structural syntax of a URL string across the 5 approved failure conditions:
    1. Parser Exception: urllib.parse.urlsplit raises an exception.
    2. Malformed Port: Accessing split_res.port raises ValueError.
    3. Port 0: split_res.port == 0.
    4. Missing Web Authority: Scheme is 'http' or 'https', but netloc is empty.
    5. Malformed Percent-Escape: URL contains '%' not followed by two hexadecimal digits.

    Returns:
        (is_malformed: bool, failure_reasons: list[str])

    Enforces the single bounded increment guarantee: returns is_malformed=True if
    any condition failed, while accumulating all distinct failure reasons.
    """
    reasons: List[str] = []

    # Condition 1: Parser Exception
    try:
        split_res = urllib.parse.urlsplit(url_str)
    except Exception as exc:
        return True, [f"urlsplit parser exception: {exc}"]

    # Condition 2: Malformed Port Property (non-numeric or > 65535)
    port: int | None = None
    try:
        port = split_res.port
    except ValueError as exc:
        reasons.append(f"Invalid port specification: {exc}")

    # Condition 3: Port 0
    if port == 0:
        reasons.append("Port 0 is invalid for network web traffic")

    # Condition 4: Missing Web Authority for HTTP/HTTPS
    scheme = (split_res.scheme or "").lower()
    if scheme in ("http", "https"):
        if not split_res.netloc:
            reasons.append(f"Missing authority (netloc) for web scheme '{scheme}'")

    # Condition 5: Malformed Percent-Escape Sequences
    # Stripping all valid %[0-9a-fA-F]{2} sequences; if any '%' remains, it is invalid
    cleaned = _HEX_PERCENT_RE.sub("", url_str)
    if "%" in cleaned:
        reasons.append("Malformed percent-escape sequence ('%' not followed by 2 hex digits)")

    is_malformed = len(reasons) > 0
    return is_malformed, reasons
