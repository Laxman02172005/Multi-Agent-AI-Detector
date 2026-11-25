"""
header_agent.py
---------------
Deterministic Header Agent for the Multi-Agent AI Phishing Email Detector.

This module implements Layer 1 deterministic feature extraction over EmailData
according to docs/research/header_agent_design.md:
- Strictly passive and offline: zero network, socket, or DNS queries.
- Leakage-safe: zero raw text or hostnames in predictive feature space.
- Extracts exactly 45 canonical features (41 active predictive, 4 quarantined).
- Populates explicit per-feature missingness manifest (HeaderFeatureAvailability).
- Populates descriptive domain completeness metrics.
- Populates Tier 2 forensic evidence traces and audit trails with bounded snippets.
"""

from __future__ import annotations

import ipaddress
import re
import time
from email.utils import parseaddr
from typing import Optional, Tuple

from app.schemas.email_schema import (
    AuthenticationMetadata,
    AuthMechanism,
    AuthStatus,
    EmailData,
    VerificationStatus,
)
from app.schemas.header_agent_schema import (
    HeaderAgentResult,
    HeaderEvidence,
    HeaderEvidenceItem,
    HeaderFeatureAvailability,
    HeaderFeatures,
)


# ---------------------------------------------------------------------------
# IP Address Classification Algorithm (Python 3.11+, RFC Standards)
# ---------------------------------------------------------------------------

def classify_ip_address(ip_str: str) -> str:
    """
    Classify an IP string into granular RFC categories in strict priority order.
    Returns: 'loopback', 'link_local', 'multicast', 'cgnat', 'documentation',
             'special_purpose', 'rfc1918', 'rfc4193', or 'global_routable'.
    """
    ip = ipaddress.ip_address(ip_str.strip())

    # 1. Loopback (RFC 1122 / RFC 4291)
    if ip.is_loopback:
        return "loopback"

    # 2. Link-Local (RFC 3927 / RFC 4291)
    if ip.is_link_local:
        return "link_local"

    # 3. Multicast (RFC 5771 / RFC 4291)
    if ip.is_multicast:
        return "multicast"

    # 4. Carrier-Grade NAT (RFC 6598 - Distinct from RFC 1918)
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return "cgnat"

    # 5. Documentation Ranges (RFC 5737 / RFC 3849)
    if ip.version == 4:
        if (
            ip in ipaddress.ip_network("192.0.2.0/24")
            or ip in ipaddress.ip_network("198.51.100.0/24")
            or ip in ipaddress.ip_network("203.0.113.0/24")
        ):
            return "documentation"
    elif ip.version == 6:
        if ip in ipaddress.ip_network("2001:db8::/32"):
            return "documentation"

    # 6. Special-Purpose / Reserved / Unspecified (RFC 6890 / RFC 1112)
    if ip.is_reserved or ip.is_unspecified:
        return "special_purpose"
    if ip.version == 4:
        if (
            ip in ipaddress.ip_network("0.0.0.0/8")
            or ip in ipaddress.ip_network("192.0.0.0/24")
            or ip in ipaddress.ip_network("198.18.0.0/15")
            or ip in ipaddress.ip_network("240.0.0.0/4")
        ):
            return "special_purpose"

    # 7. RFC 1918 Private IPv4
    if ip.version == 4:
        if (
            ip in ipaddress.ip_network("10.0.0.0/8")
            or ip in ipaddress.ip_network("172.16.0.0/12")
            or ip in ipaddress.ip_network("192.168.0.0/16")
        ):
            return "rfc1918"

    # 8. RFC 4193 Unique Local IPv6 (ULA)
    if ip.version == 6 and ip in ipaddress.ip_network("fc00::/7"):
        return "rfc4193"

    # 9. Global Public Routable (Strict Unicast Fallback)
    if getattr(ip, "is_global", False):
        return "global_routable"

    return "special_purpose"


def extract_ips_from_hop(hop_str: str) -> list[str]:
    """
    Extract valid IP address strings from bracketed and parenthesized tokens in a Received header.
    """
    ips: list[str] = []

    # 1. Bracketed tokens: [1.2.3.4] or [IPv6:2001:db8::1]
    for m in re.finditer(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]", hop_str, re.IGNORECASE):
        candidate = m.group(1).strip()
        try:
            ip_obj = ipaddress.ip_address(candidate)
            ips.append(str(ip_obj))
        except ValueError:
            pass

    # 2. Parenthesized tokens: (1.2.3.4) or (mail.example.com [1.2.3.4])
    for m in re.finditer(r"\(([^()]+)\)", hop_str):
        inner = m.group(1).strip()
        for token in inner.split():
            clean = token.strip("[](),;:")
            clean = re.sub(r"^ipv6:\s*", "", clean, flags=re.IGNORECASE)
            try:
                ip_obj = ipaddress.ip_address(clean)
                ips.append(str(ip_obj))
            except ValueError:
                pass

    # Return deduplicated list preserving discovery order
    return list(dict.fromkeys(ips))


def is_received_hop_malformed(hop_str: str) -> bool:
    """
    Check if a Received header fails RFC 5322 structural token parsing.
    """
    s = hop_str.strip()
    if not s:
        return True
    has_clause = bool(re.search(r"\b(from|by|with|id|for)\b", s, re.IGNORECASE))
    if not has_clause and ";" not in s:
        return True
    return False


# ---------------------------------------------------------------------------
# Header Identity & Syntax Helpers
# ---------------------------------------------------------------------------

def extract_email_address_and_domain(raw_header: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Parses a single address header (From, Reply-To, Return-Path).
    Returns (display_name, email_address, domain).
    """
    if not raw_header or not raw_header.strip():
        return None, None, None
    raw_str = raw_header.strip()
    m = re.search(r"^(.*?)\s*<([^<>\s@]+@[^<>\s@]+)>\s*$", raw_str)
    if m and "<" in m.group(1):
        realname = m.group(1).strip()
        addr = m.group(2).strip()
    else:
        realname, addr = parseaddr(raw_str)
        addr = addr.strip()
        if not addr or "@" not in addr:
            if m:
                realname = m.group(1).strip()
                addr = m.group(2).strip()
            else:
                return (realname.strip() if realname else None), None, None

    parts = addr.rsplit("@", 1)
    domain = parts[1].strip().lower() if len(parts) == 2 and parts[1].strip() else None
    return (realname.strip() if realname else None), addr.lower(), domain


def count_valid_recipients(recipient_list: list[str]) -> Tuple[Optional[int], list[str]]:
    """
    Parses recipient list entries (To or CC) and counts valid RFC 5322 mailboxes.
    Returns (valid_count_or_none, malformed_tokens).
    """
    if not recipient_list:
        return None, []

    valid_count = 0
    malformed: list[str] = []
    for token in recipient_list:
        if not token or not token.strip():
            malformed.append(token)
            continue
        name, addr = parseaddr(token.strip())
        addr = addr.strip()
        if addr and "@" in addr:
            domain_part = addr.rsplit("@", 1)[1].strip()
            if domain_part:
                valid_count += 1
            else:
                malformed.append(token)
        else:
            malformed.append(token)

    if valid_count > 0:
        return valid_count, malformed
    else:
        # All tokens were malformed
        return None, malformed


def check_display_name_spoofing(
    display_name: Optional[str], from_domain: Optional[str]
) -> Tuple[bool, Optional[bool], Optional[str]]:
    """
    Checks if From display name contains an embedded email address and whether its domain mismatches From domain.
    Returns (display_name_contains_email, display_name_domain_mismatch, embedded_domain).
    """
    if not display_name:
        return False, None, None
    match = re.search(r"[\w\.-]+@([\w\.-]+\.[a-zA-Z]{2,})", display_name)
    if not match:
        return False, None, None

    embedded_domain = match.group(1).strip().lower()
    if not from_domain:
        return True, None, embedded_domain

    mismatch = (embedded_domain != from_domain.lower())
    return True, mismatch, embedded_domain


def check_message_id(
    message_id: Optional[str], from_domain: Optional[str]
) -> Tuple[bool, Optional[bool], Optional[bool], Optional[str]]:
    """
    Returns (message_id_present, message_id_valid_syntax, message_id_domain_mismatch, msg_id_domain).
    """
    if not message_id or not message_id.strip():
        return False, None, None, None

    msg_id = message_id.strip()
    valid_syntax = bool(re.match(r"^<[^@\s<>]+@[^@\s<>]+>$", msg_id))

    domain = None
    if valid_syntax:
        domain = msg_id[1:-1].split("@")[-1].strip().lower()
    else:
        match = re.search(r"@([^@\s>]+)", msg_id)
        if match:
            domain = match.group(1).strip().rstrip(">").lower()

    if domain and from_domain:
        domain_mismatch = (domain != from_domain.lower())
    else:
        domain_mismatch = None

    return True, valid_syntax, domain_mismatch, domain


def check_mime_version(mime_version: Optional[str]) -> Tuple[bool, Optional[bool]]:
    """
    Returns (mime_version_present, mime_version_valid).
    """
    if mime_version is None:
        return False, None
    s = mime_version.strip()
    if not s:
        return False, None
    clean = re.sub(r"\(.*?\)", "", s).strip()
    is_valid = (clean == "1.0")
    return True, is_valid


def check_content_type(content_type: Optional[str]) -> Tuple[bool, Optional[bool]]:
    """
    Returns (content_type_present, content_type_is_multipart).
    """
    if content_type is None:
        return False, None
    s = content_type.strip()
    if not s:
        return False, None
    is_multipart = s.lower().startswith("multipart/")
    return True, is_multipart


def sanitize_evidence_snippet(raw_str: Optional[str], max_len: int = 256) -> Optional[str]:
    """
    Sanitize raw snippet for display in Tier 2 evidence items:
    - Escapes control characters (\\r, \\n, \\t).
    - Replaces non-printable characters.
    - Truncates to max_len (256 chars) with '...' ellipsis.
    """
    if raw_str is None:
        return None
    s = raw_str.replace("\r", r"\r").replace("\n", r"\n").replace("\t", r"\t")
    clean = "".join(c if (c.isprintable() or c == " ") else f"\\x{ord(c):02x}" for c in s)
    if len(clean) > max_len:
        return clean[: max_len - 3] + "..."
    return clean


# ---------------------------------------------------------------------------
# Public Header Agent API
# ---------------------------------------------------------------------------

def analyze_headers(email_data: EmailData) -> HeaderAgentResult:
    """
    Analyze email headers and authentication metadata from EmailData.
    Produces a leakage-free, validated HeaderAgentResult with Tier 3 features,
    availability manifest, completeness metrics, and Tier 2 forensic evidence.
    """
    start_time = time.perf_counter()

    evidence_items: list[HeaderEvidenceItem] = []
    observed_anomalies: list[str] = []
    warnings: list[str] = list(email_data.parsing_warnings)

    # -----------------------------------------------------------------------
    # Category A: Sender, Recipient, and Identity Alignment
    # -----------------------------------------------------------------------
    from_present = bool(email_data.headers.from_address and email_data.headers.from_address.strip())
    from_name, from_addr, from_domain = extract_email_address_and_domain(email_data.headers.from_address)

    if not from_present:
        from_address_count: Optional[int] = None
        from_syntax_valid: Optional[bool] = None if email_data.headers.from_address is None else False
    else:
        if from_addr is not None:
            from_address_count = 1
            from_syntax_valid = bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", from_addr))
        else:
            from_address_count = None  # unparseable under current contract
            from_syntax_valid = False

    if from_syntax_valid is False and from_present:
        evidence_items.append(
            HeaderEvidenceItem(
                feature_name="from_syntax_valid",
                header_name="From",
                header_index=0,
                description="From address fails RFC 5322 addr-spec syntax validation",
                raw_snippet_bounded=sanitize_evidence_snippet(email_data.headers.from_address),
            )
        )
        observed_anomalies.append("From header syntax is invalid or malformed")

    reply_to_present = bool(email_data.headers.reply_to and email_data.headers.reply_to.strip())
    reply_name, reply_addr, reply_domain = extract_email_address_and_domain(email_data.headers.reply_to)

    if from_domain and reply_domain:
        from_reply_to_domain_mismatch: Optional[bool] = (from_domain != reply_domain)
        if from_reply_to_domain_mismatch:
            evidence_items.append(
                HeaderEvidenceItem(
                    feature_name="from_reply_to_domain_mismatch",
                    header_name="Reply-To",
                    header_index=0,
                    description=f"Reply-To domain '{reply_domain}' mismatches From domain '{from_domain}'",
                    raw_snippet_bounded=sanitize_evidence_snippet(email_data.headers.reply_to),
                )
            )
            observed_anomalies.append(
                f"From/Reply-To domain mismatch: '{from_domain}' vs '{reply_domain}'"
            )
    else:
        from_reply_to_domain_mismatch = None

    return_path_present = bool(email_data.headers.return_path and email_data.headers.return_path.strip())
    ret_name, ret_addr, ret_domain = extract_email_address_and_domain(email_data.headers.return_path)

    if from_domain and ret_domain:
        from_return_path_domain_mismatch: Optional[bool] = (from_domain != ret_domain)
        if from_return_path_domain_mismatch:
            evidence_items.append(
                HeaderEvidenceItem(
                    feature_name="from_return_path_domain_mismatch",
                    header_name="Return-Path",
                    header_index=0,
                    description=f"Return-Path domain '{ret_domain}' mismatches From domain '{from_domain}'",
                    raw_snippet_bounded=sanitize_evidence_snippet(email_data.headers.return_path),
                )
            )
            observed_anomalies.append(
                f"From/Return-Path domain mismatch: '{from_domain}' vs '{ret_domain}'"
            )
    else:
        from_return_path_domain_mismatch = None

    disp_contains_email, disp_domain_mismatch, disp_domain = check_display_name_spoofing(
        from_name, from_domain
    )
    if disp_contains_email and disp_domain_mismatch:
        evidence_items.append(
            HeaderEvidenceItem(
                feature_name="display_name_domain_mismatch",
                header_name="From",
                header_index=0,
                description=(
                    f"From display name embeds address domain '{disp_domain}' "
                    f"which mismatches From domain '{from_domain}'"
                ),
                raw_snippet_bounded=sanitize_evidence_snippet(email_data.headers.from_address),
            )
        )
        observed_anomalies.append(
            f"Display name spoofing: embedded domain '{disp_domain}' mismatches From domain '{from_domain}'"
        )
    elif disp_contains_email:
        evidence_items.append(
            HeaderEvidenceItem(
                feature_name="display_name_contains_email",
                header_name="From",
                header_index=0,
                description=f"From display name embeds email address with domain '{disp_domain}'",
                raw_snippet_bounded=sanitize_evidence_snippet(email_data.headers.from_address),
            )
        )

    recipient_count_to, malformed_to = count_valid_recipients(email_data.headers.to)
    if malformed_to:
        warnings.append(f"To header contained {len(malformed_to)} malformed or non-mailbox tokens")
        for m_tok in malformed_to:
            evidence_items.append(
                HeaderEvidenceItem(
                    feature_name="recipient_count_to",
                    header_name="To",
                    header_index=0,
                    description="Unparseable or non-mailbox recipient token in To header",
                    raw_snippet_bounded=sanitize_evidence_snippet(m_tok),
                )
            )

    recipient_count_cc, malformed_cc = count_valid_recipients(email_data.headers.cc)
    if malformed_cc:
        warnings.append(f"CC header contained {len(malformed_cc)} malformed or non-mailbox tokens")
        for m_tok in malformed_cc:
            evidence_items.append(
                HeaderEvidenceItem(
                    feature_name="recipient_count_cc",
                    header_name="CC",
                    header_index=0,
                    description="Unparseable or non-mailbox recipient token in CC header",
                    raw_snippet_bounded=sanitize_evidence_snippet(m_tok),
                )
            )

    # -----------------------------------------------------------------------
    # Category B: Routing and Transport Structure
    # -----------------------------------------------------------------------
    received_hop_count = len(email_data.headers.received)
    missing_received_headers = (received_hop_count == 0)
    hop_count_anomaly = (received_hop_count == 0 or received_hop_count > 15)

    if missing_received_headers:
        evidence_items.append(
            HeaderEvidenceItem(
                feature_name="missing_received_headers",
                header_name="Received",
                header_index=None,
                description="Zero Received headers present in email",
                raw_snippet_bounded=None,
            )
        )
        observed_anomalies.append("Missing Received headers (hop count is 0)")
    elif received_hop_count > 15:
        evidence_items.append(
            HeaderEvidenceItem(
                feature_name="hop_count_anomaly",
                header_name="Received",
                header_index=0,
                description=f"Excessive Received hop count ({received_hop_count} hops > 15)",
                raw_snippet_bounded=None,
            )
        )
        observed_anomalies.append(f"Excessive transit hops: {received_hop_count} hops")

    malformed_received_count = 0
    has_private_ip = False
    has_loopback_ip = False
    has_link_local_ip = False
    has_special_ip = False
    detected_anomalous_ips: list[str] = []

    for idx, hop_str in enumerate(email_data.headers.received):
        if is_received_hop_malformed(hop_str):
            malformed_received_count += 1
            evidence_items.append(
                HeaderEvidenceItem(
                    feature_name="received_syntax_malformed_count",
                    header_name="Received",
                    header_index=idx,
                    description=f"Received hop {idx} fails RFC structural token parsing",
                    raw_snippet_bounded=sanitize_evidence_snippet(hop_str),
                )
            )

        # External hops are intermediate transit hops (hops 1..N-1)
        if idx >= 1:
            hop_ips = extract_ips_from_hop(hop_str)
            for ip_val in hop_ips:
                category = classify_ip_address(ip_val)
                if category in ("rfc1918", "rfc4193"):
                    has_private_ip = True
                    detected_anomalous_ips.append(ip_val)
                    evidence_items.append(
                        HeaderEvidenceItem(
                            feature_name="has_private_ip_in_external_hop",
                            header_name="Received",
                            header_index=idx,
                            description=f"External transit hop {idx} contains private IP '{ip_val}' ({category})",
                            raw_snippet_bounded=sanitize_evidence_snippet(hop_str),
                        )
                    )
                    observed_anomalies.append(
                        f"Private IP '{ip_val}' ({category}) detected in external transit hop {idx}"
                    )
                elif category == "loopback":
                    has_loopback_ip = True
                    detected_anomalous_ips.append(ip_val)
                    evidence_items.append(
                        HeaderEvidenceItem(
                            feature_name="has_loopback_ip_in_external_hop",
                            header_name="Received",
                            header_index=idx,
                            description=f"External transit hop {idx} contains loopback IP '{ip_val}'",
                            raw_snippet_bounded=sanitize_evidence_snippet(hop_str),
                        )
                    )
                    observed_anomalies.append(
                        f"Loopback IP '{ip_val}' detected in external transit hop {idx}"
                    )
                elif category == "link_local":
                    has_link_local_ip = True
                    detected_anomalous_ips.append(ip_val)
                    evidence_items.append(
                        HeaderEvidenceItem(
                            feature_name="has_link_local_ip_in_external_hop",
                            header_name="Received",
                            header_index=idx,
                            description=f"External transit hop {idx} contains link-local IP '{ip_val}'",
                            raw_snippet_bounded=sanitize_evidence_snippet(hop_str),
                        )
                    )
                    observed_anomalies.append(
                        f"Link-local IP '{ip_val}' detected in external transit hop {idx}"
                    )
                elif category in ("cgnat", "documentation", "multicast", "special_purpose"):
                    has_special_ip = True
                    detected_anomalous_ips.append(ip_val)
                    evidence_items.append(
                        HeaderEvidenceItem(
                            feature_name="has_special_ip_in_external_hop",
                            header_name="Received",
                            header_index=idx,
                            description=f"External transit hop {idx} contains special-purpose IP '{ip_val}' ({category})",
                            raw_snippet_bounded=sanitize_evidence_snippet(hop_str),
                        )
                    )
                    observed_anomalies.append(
                        f"Special IP '{ip_val}' ({category}) detected in external transit hop {idx}"
                    )

    # -----------------------------------------------------------------------
    # Category C: Authentication Claims
    # -----------------------------------------------------------------------
    auth = email_data.authentication
    spf_status = auth.spf.status
    dkim_status = auth.dkim.status
    dmarc_status = auth.dmarc.status

    spf_claims = [c for c in auth.claims if c.mechanism == AuthMechanism.SPF]
    dkim_claims = [c for c in auth.claims if c.mechanism == AuthMechanism.DKIM]
    dmarc_claims = [c for c in auth.claims if c.mechanism == AuthMechanism.DMARC]

    spf_claim_count = len(spf_claims)
    dkim_claim_count = len(dkim_claims)
    dmarc_claim_count = len(dmarc_claims)

    has_conflicting_spf = len({c.status for c in spf_claims}) > 1
    has_conflicting_dkim = len({c.status for c in dkim_claims}) > 1
    has_conflicting_dmarc = len({c.status for c in dmarc_claims}) > 1

    if has_conflicting_spf:
        evidence_items.append(
            HeaderEvidenceItem(
                feature_name="has_conflicting_spf",
                header_name="Authentication-Results",
                description="Conflicting SPF claims reported across authentication headers",
                raw_snippet_bounded=sanitize_evidence_snippet(auth.spf.raw_value),
            )
        )
        observed_anomalies.append("Conflicting SPF authentication claims")

    if has_conflicting_dkim:
        evidence_items.append(
            HeaderEvidenceItem(
                feature_name="has_conflicting_dkim",
                header_name="Authentication-Results",
                description="Conflicting DKIM claims reported across authentication headers",
                raw_snippet_bounded=sanitize_evidence_snippet(auth.dkim.raw_value),
            )
        )
        observed_anomalies.append("Conflicting DKIM authentication claims")

    if has_conflicting_dmarc:
        evidence_items.append(
            HeaderEvidenceItem(
                feature_name="has_conflicting_dmarc",
                header_name="Authentication-Results",
                description="Conflicting DMARC claims reported across authentication headers",
                raw_snippet_bounded=sanitize_evidence_snippet(auth.dmarc.raw_value),
            )
        )
        observed_anomalies.append("Conflicting DMARC authentication claims")

    dkim_sig_present = bool(len(email_data.headers.dkim_signature) > 0)
    dkim_sig_without_pass = bool(dkim_sig_present and dkim_status != AuthStatus.PASS)

    if dkim_sig_without_pass:
        evidence_items.append(
            HeaderEvidenceItem(
                feature_name="dkim_signature_present_without_pass",
                header_name="DKIM-Signature",
                header_index=0,
                description=f"DKIM-Signature header present but DKIM authentication status is '{dkim_status.value}'",
                raw_snippet_bounded=sanitize_evidence_snippet(email_data.headers.dkim_signature[0]),
            )
        )
        observed_anomalies.append(
            f"DKIM-Signature header present without pass (status: {dkim_status.value})"
        )

    authserv_ids: set[str] = set()
    for c in auth.claims:
        if c.authserv_id and c.authserv_id.strip():
            authserv_ids.add(c.authserv_id.strip().lower())
    for res in (auth.spf, auth.dkim, auth.dmarc):
        if res.authserv_id and res.authserv_id.strip():
            authserv_ids.add(res.authserv_id.strip().lower())

    authserv_id_count = len(authserv_ids)
    authserv_id_inconsistent = (authserv_id_count > 1)

    if authserv_id_inconsistent:
        evidence_items.append(
            HeaderEvidenceItem(
                feature_name="authserv_id_inconsistent",
                header_name="Authentication-Results",
                description=f"Multiple distinct authserv-ids found: {sorted(list(authserv_ids))}",
                raw_snippet_bounded=None,
            )
        )
        observed_anomalies.append(
            f"Inconsistent reporting MTAs (authserv-ids): {sorted(list(authserv_ids))}"
        )

    # -----------------------------------------------------------------------
    # Category D: RFC 5322 Metadata & Structural Compliance
    # -----------------------------------------------------------------------
    msg_id_pres, msg_id_valid, msg_id_mismatch, msg_id_domain = check_message_id(
        email_data.headers.message_id, from_domain
    )
    if msg_id_pres and msg_id_valid is False:
        evidence_items.append(
            HeaderEvidenceItem(
                feature_name="message_id_valid_syntax",
                header_name="Message-ID",
                header_index=0,
                description="Message-ID fails RFC 5322 addr-spec syntax format <id-left@id-right>",
                raw_snippet_bounded=sanitize_evidence_snippet(email_data.headers.message_id),
            )
        )
        observed_anomalies.append("Message-ID syntax is malformed")

    if msg_id_mismatch:
        evidence_items.append(
            HeaderEvidenceItem(
                feature_name="message_id_domain_mismatch",
                header_name="Message-ID",
                header_index=0,
                description=f"Message-ID domain '{msg_id_domain}' mismatches From domain '{from_domain}'",
                raw_snippet_bounded=sanitize_evidence_snippet(email_data.headers.message_id),
            )
        )
        observed_anomalies.append(
            f"Message-ID domain mismatch: '{msg_id_domain}' vs '{from_domain}'"
        )

    mime_pres, mime_valid = check_mime_version(email_data.headers.mime_version)
    if mime_pres and mime_valid is False:
        evidence_items.append(
            HeaderEvidenceItem(
                feature_name="mime_version_valid",
                header_name="MIME-Version",
                header_index=0,
                description=f"MIME-Version header value is invalid or non-standard: '{email_data.headers.mime_version}'",
                raw_snippet_bounded=sanitize_evidence_snippet(email_data.headers.mime_version),
            )
        )
        observed_anomalies.append(f"Invalid MIME-Version: '{email_data.headers.mime_version}'")

    has_subject = (email_data.headers.subject is not None)
    subject_length = len(email_data.headers.subject) if email_data.headers.subject else 0

    ct_pres, ct_multipart = check_content_type(email_data.headers.content_type)

    # -----------------------------------------------------------------------
    # Tier 3 Feature Vector (Canonical 45 Features)
    # -----------------------------------------------------------------------
    features = HeaderFeatures(
        # Category A (13)
        from_present=from_present,
        from_address_count=from_address_count,
        reply_to_present=reply_to_present,
        return_path_present=return_path_present,
        from_reply_to_domain_mismatch=from_reply_to_domain_mismatch,
        from_return_path_domain_mismatch=from_return_path_domain_mismatch,
        display_name_contains_email=disp_contains_email,
        display_name_domain_mismatch=disp_domain_mismatch,
        recipient_count_to=recipient_count_to,
        recipient_count_cc=recipient_count_cc,
        undisclosed_recipients=None,  # Quarantined
        to_empty_or_missing=None,     # Quarantined
        from_syntax_valid=from_syntax_valid,
        # Category B (10)
        received_hop_count=received_hop_count,
        has_private_ip_in_external_hop=has_private_ip,
        has_loopback_ip_in_external_hop=has_loopback_ip,
        has_link_local_ip_in_external_hop=has_link_local_ip,
        has_special_ip_in_external_hop=has_special_ip,
        received_syntax_malformed_count=malformed_received_count,
        missing_received_headers=missing_received_headers,
        transit_delay_seconds=None,       # Quarantined
        transit_delay_unavailable=True,   # Quarantined
        hop_count_anomaly=hop_count_anomaly,
        # Category C (13)
        spf_status=spf_status,
        dkim_status=dkim_status,
        dmarc_status=dmarc_status,
        spf_claim_count=spf_claim_count,
        dkim_claim_count=dkim_claim_count,
        dmarc_claim_count=dmarc_claim_count,
        has_conflicting_spf=has_conflicting_spf,
        has_conflicting_dkim=has_conflicting_dkim,
        has_conflicting_dmarc=has_conflicting_dmarc,
        dkim_signature_header_present=dkim_sig_present,
        dkim_signature_present_without_pass=dkim_sig_without_pass,
        authserv_id_count=authserv_id_count,
        authserv_id_inconsistent=authserv_id_inconsistent,
        # Category D (9)
        message_id_present=msg_id_pres,
        message_id_valid_syntax=msg_id_valid,
        message_id_domain_mismatch=msg_id_mismatch,
        mime_version_present=mime_pres,
        mime_version_valid=mime_valid,
        has_subject_header=has_subject,
        subject_length=subject_length,
        content_type_present=ct_pres,
        content_type_is_multipart=ct_multipart,
    )

    # -----------------------------------------------------------------------
    # Availability Manifest & Descriptive Completeness
    # -----------------------------------------------------------------------
    avail_from_parsed = (from_domain is not None)
    avail_reply_to_parsed = (reply_domain is not None)
    avail_return_path_parsed = (ret_domain is not None)
    avail_to_parsed = (recipient_count_to is not None)
    avail_cc_parsed = (recipient_count_cc is not None)

    avail_spf_status = (spf_status not in (AuthStatus.MISSING, AuthStatus.UNAVAILABLE))
    avail_dkim_status = (dkim_status not in (AuthStatus.MISSING, AuthStatus.UNAVAILABLE))
    avail_dmarc_status = (dmarc_status not in (AuthStatus.MISSING, AuthStatus.UNAVAILABLE))

    # Section 9.2 Descriptive Completeness Conventions
    c_identity = (int(avail_from_parsed) + int(avail_reply_to_parsed) + int(avail_return_path_parsed)) / 3.0

    if received_hop_count >= 2 and False:  # avail_transit_delay is quarantined/False
        c_routing = 1.0
    elif received_hop_count >= 1:
        c_routing = 0.6
    else:
        c_routing = 0.0

    c_auth = (int(avail_spf_status) + int(avail_dkim_status) + int(avail_dmarc_status)) / 3.0

    c_metadata = (int(msg_id_pres) + int(mime_pres) + int(ct_pres)) / 3.0

    c_total = 0.25 * (c_identity + c_routing + c_auth + c_metadata)

    availability = HeaderFeatureAvailability(
        avail_from_present=from_present,
        avail_reply_to_present=reply_to_present,
        avail_return_path_present=return_path_present,
        avail_to_present=bool(len(email_data.headers.to) > 0),
        avail_cc_present=bool(len(email_data.headers.cc) > 0),
        avail_received_hops=(received_hop_count > 0),
        avail_auth_claims=bool(len(auth.claims) > 0),
        avail_message_id_present=msg_id_pres,
        avail_mime_version_present=mime_pres,
        avail_subject_present=has_subject,
        avail_content_type_present=ct_pres,
        avail_from_parsed=avail_from_parsed,
        avail_from_syntax=from_present,
        avail_reply_to_parsed=avail_reply_to_parsed,
        avail_return_path_parsed=avail_return_path_parsed,
        avail_to_parsed=avail_to_parsed,
        avail_cc_parsed=avail_cc_parsed,
        avail_from_reply_to_domain_mismatch=bool(from_domain and reply_domain),
        avail_from_return_path_domain_mismatch=bool(from_domain and ret_domain),
        avail_display_name_domain_mismatch=bool(disp_contains_email and from_domain and disp_domain),
        avail_undisclosed_recipients=False,
        avail_to_empty_or_missing=False,
        avail_transit_delay=False,
        avail_spf_status=avail_spf_status,
        avail_dkim_status=avail_dkim_status,
        avail_dmarc_status=avail_dmarc_status,
        avail_message_id_valid_syntax=msg_id_pres,
        avail_message_id_domain_mismatch=bool(msg_id_domain and from_domain),
        avail_mime_version_valid=mime_pres,
        avail_content_type_is_multipart=ct_pres,
        completeness_identity=round(c_identity, 4),
        completeness_routing=round(c_routing, 4),
        completeness_auth=round(c_auth, 4),
        completeness_metadata=round(c_metadata, 4),
        completeness_total=round(c_total, 4),
    )

    # -----------------------------------------------------------------------
    # Tier 2 Forensic Evidence Assembly
    # -----------------------------------------------------------------------
    evidence = HeaderEvidence(
        evidence_items=evidence_items[:100],
        parsed_authserv_ids=sorted(list(authserv_ids))[:50],
        detected_anomalous_ips=list(dict.fromkeys(detected_anomalous_ips))[:50],
        observed_anomalies=list(dict.fromkeys(observed_anomalies))[:100],
    )

    limitations = [
        "Offline analysis mode: receiver trust policy and cryptographic provenance verification are not evaluated.",
        "Authentication claims (SPF, DKIM, DMARC) are unverified receiver reports and remain VerificationStatus.UNVERIFIED.",
        "Features 11 (undisclosed_recipients) and 12 (to_empty_or_missing) are quarantined pending raw-header contract extension.",
        "Features 21 (transit_delay_seconds) and 22 (transit_delay_unavailable) are quarantined exploratory metrics.",
    ]

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    return HeaderAgentResult(
        email_id=email_data.email_id,
        agent_name="header_agent",
        agent_version="0.1.0",
        status="success",
        processing_time_ms=round(elapsed_ms, 3),
        features=features,
        availability=availability,
        evidence=evidence,
        risk_assessment=None,
        warnings=warnings,
        limitations=limitations,
    )

