"""
contextual_analyzer.py
-----------------------
Contextual alignment and behavioral indicators for the URL Agent.

Implements:
- Offline URL shortener detection (Features 31 & 32)
- Open redirect parameter detection (Feature 33)
- Visual anchor text mismatch heuristic (Features 34 & 35)
- From header sender domain alignment (Features 36, 37, 38)
"""

from __future__ import annotations

import email.utils
import functools
import ipaddress
from pathlib import Path
import re
from typing import FrozenSet, Optional, Tuple, List
import urllib.parse

from app.agents.url_components.psl_resolver import resolve_domain
from app.schemas.email_schema import URLSource
from app.schemas.url_agent_schema import DomainResolutionStatus


# Recognized open redirect parameter keys
_REDIRECT_PARAM_KEYS = frozenset({
    "url",
    "redirect",
    "dest",
    "target",
    "goto",
    "r",
    "link",
    "destination",
    "return",
    "next",
    "redir",
    "redirect_url",
    "redirect_uri",
    "return_url",
})


@functools.lru_cache(maxsize=1)
def load_shorteners_set() -> FrozenSet[str]:
    """Load the immutable offline URL shorteners registry from disk."""
    base_dir = Path(__file__).resolve().parent.parent.parent
    shorteners_file = base_dir / "data" / "url_shorteners.txt"
    if not shorteners_file.is_file():
        return frozenset()

    shorteners = set()
    with open(shorteners_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                shorteners.add(line)

    return frozenset(shorteners)


def is_url_shortener(hostname: Optional[str], registered_domain: Optional[str]) -> bool:
    """
    Check if hostname or registered domain matches an entry in the offline shorteners registry.
    """
    shortener_set = load_shorteners_set()
    if not shortener_set:
        return False

    if hostname and hostname.lower() in shortener_set:
        return True
    if registered_domain and registered_domain.lower() in shortener_set:
        return True

    return False


def has_redirect_parameter(query_str: Optional[str]) -> bool:
    """
    Feature 33: True if query string contains known open-redirect parameter keys
    or values that specify external destinations.
    """
    if not query_str:
        return False

    clean_query = query_str.lstrip("?")
    if not clean_query:
        return False

    try:
        pairs = urllib.parse.parse_qsl(clean_query, keep_blank_values=True)
    except Exception:
        # Fallback to simple regex inspection if parse_qsl crashes
        lower_q = clean_query.lower()
        return any(f"{key}=" in lower_q for key in _REDIRECT_PARAM_KEYS)

    for key, val in pairs:
        clean_key = key.lower().strip()
        if clean_key in _REDIRECT_PARAM_KEYS:
            return True
        # Check if value itself looks like an absolute URL redirect destination
        clean_val = val.lower().strip()
        if clean_val.startswith(("http://", "https://", "//")):
            return True

    return False


def check_anchor_url_mismatch(
    source: URLSource,
    anchor_text: Optional[str],
    dest_hostname: Optional[str],
    dest_registered_domain: Optional[str],
    dest_status: DomainResolutionStatus,
) -> Tuple[bool, Optional[str]]:
    """
    Features 34 & 35: Deterministic Visual Anchor-Text URL Detection & Source Qualification.
    Implements the 8-step algorithm in Section 6.2 of the Phase B plan.

    Returns:
        (has_mismatch: bool, anchor_hostname: Optional[str])
    """
    # Step 1: Strict Source Qualification & Preconditions
    if source != URLSource.HTML_HREF:
        return False, None

    if not anchor_text:
        return False, None

    # Strip surrounding whitespace and delimiters: <([{"' and '>)]}"'
    cleaned = anchor_text.strip('<([{"\' >)]}"')
    if not cleaned:
        return False, None

    # Exclude ordinary email addresses (e.g. support@paypal.com)
    if "@" in cleaned:
        return False, None

    # Step 2: Deterministic Classification of Anchor Text Representation
    lower_anchor = cleaned.lower()
    is_url_like = False

    if lower_anchor.startswith(("http://", "https://", "www.")):
        is_url_like = True
    else:
        # Check if it has the syntactic form of an IP literal
        try:
            ipaddress.ip_address(cleaned.split("/")[0].split(":")[0])
            is_url_like = True
        except ValueError:
            # Check if it matches the syntactic form of a domain name:
            # - No whitespace
            # - At least two dot-separated labels
            # - Rightmost label is all ASCII alphabetic with length >= 2
            # - All label characters are [a-zA-Z0-9-]
            if not re.search(r"\s", cleaned):
                host_candidate = cleaned.split("/")[0].split(":")[0].split("?")[0]
                labels = host_candidate.split(".")
                if len(labels) >= 2:
                    tld = labels[-1]
                    if tld.isalpha() and len(tld) >= 2:
                        if all(lbl and all(c.isalnum() or c == "-" for c in lbl) for lbl in labels):
                            # Exclude semantic version strings (e.g. v2.1.0 or 1.0.4)
                            if not (labels[0].startswith("v") and labels[0][1:].isdigit()):
                                is_url_like = True

    if not is_url_like:
        # Natural language descriptive text (e.g. "Click here", "View invoice")
        return False, None

    # Step 3: Displayed Hostname Extraction
    url_to_split = cleaned
    if not lower_anchor.startswith(("http://", "https://")):
        url_to_split = "http://" + cleaned

    try:
        split_res = urllib.parse.urlsplit(url_to_split)
        anchor_host = split_res.hostname
    except Exception:
        return False, None

    if not anchor_host:
        return False, None

    # Step 4: Displayed Hostname Normalization
    anchor_host = anchor_host.strip().rstrip(".").lower()
    try:
        anchor_host = anchor_host.encode("idna").decode("ascii")
    except Exception:
        pass

    if not anchor_host:
        return False, None

    # Step 5: Dual Domain Resolution
    anchor_reg_domain, anchor_status, _ = resolve_domain(anchor_host)

    # Step 6: Identity Comparison Hierarchy
    # 6.3 Both are IP literals
    if anchor_status == DomainResolutionStatus.IP_LITERAL and dest_status == DomainResolutionStatus.IP_LITERAL:
        try:
            ip_anchor = ipaddress.ip_address(anchor_host)
            ip_dest = ipaddress.ip_address(dest_hostname) if dest_hostname else None
            return (ip_anchor != ip_dest), anchor_host
        except Exception:
            return True, anchor_host

    # One is IP literal and other is domain -> Mismatch
    if anchor_status == DomainResolutionStatus.IP_LITERAL or dest_status == DomainResolutionStatus.IP_LITERAL:
        return True, anchor_host

    # 6.1 Both Domains Resolvable via PSL
    resolvable_statuses = {
        DomainResolutionStatus.EXACT_MATCH,
        DomainResolutionStatus.WILDCARD_MATCH,
        DomainResolutionStatus.EXCEPTION_MATCH,
    }
    if anchor_status in resolvable_statuses and dest_status in resolvable_statuses:
        if anchor_reg_domain and dest_registered_domain:
            mismatch = (anchor_reg_domain.lower() != dest_registered_domain.lower())
            return mismatch, anchor_host
        return False, anchor_host

    # 6.2 Unknown Suffix Fallback (compare full FQDNs)
    if anchor_status == DomainResolutionStatus.UNKNOWN_SUFFIX or dest_status == DomainResolutionStatus.UNKNOWN_SUFFIX:
        if dest_hostname:
            mismatch = (anchor_host.lower() != dest_hostname.lower())
            return mismatch, anchor_host
        return False, anchor_host

    # 6.4 Invalid or ambiguous anchor hostname -> do NOT fabricate a mismatch
    return False, anchor_host


def compute_sender_domain_alignment(
    from_address: Optional[str],
    url_target_records: List[Tuple[Optional[str], DomainResolutionStatus]],
) -> Tuple[Optional[bool], Optional[float], Optional[float], bool]:
    """
    Features 36, 37, 38: From Header Sender Domain Alignment.
    
    Arguments:
        from_address: Raw From header value from EmailHeaders.from_address.
        url_target_records: List of (target_registered_domain, target_status) per URL occurrence.

    Returns:
        (has_sender_domain_mismatch_url, sender_domain_matching_url_ratio, external_link_ratio, from_domain_resolvable)
    """
    if not from_address or not from_address.strip():
        return None, None, None, False

    # Extract email address
    _, addr = email.utils.parseaddr(from_address)
    if not addr or "@" not in addr:
        return None, None, None, False

    sender_host = addr.split("@")[-1].strip().lower()
    if not sender_host:
        return None, None, None, False

    sender_reg_domain, sender_status, _ = resolve_domain(sender_host)

    resolvable_statuses = {
        DomainResolutionStatus.EXACT_MATCH,
        DomainResolutionStatus.WILDCARD_MATCH,
        DomainResolutionStatus.EXCEPTION_MATCH,
    }

    if sender_status not in resolvable_statuses or not sender_reg_domain:
        return None, None, None, False

    # Count occurrence-based resolvable URLs
    n_resolvable = 0
    n_match = 0

    for dest_rd, dest_status in url_target_records:
        if dest_status in resolvable_statuses and dest_rd:
            n_resolvable += 1
            if dest_rd.lower() == sender_reg_domain.lower():
                n_match += 1

    if n_resolvable == 0:
        return None, None, None, True

    matching_ratio = float(n_match / n_resolvable)
    external_ratio = float(1.0 - matching_ratio)
    has_mismatch = bool(n_match < n_resolvable)

    return has_mismatch, matching_ratio, external_ratio, True
