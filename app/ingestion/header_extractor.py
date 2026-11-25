"""
app/ingestion/header_extractor.py
----------------------------------
Modular email header extraction component.

Extracts header fields and authentication evidence from an already-parsed
``email.message.Message`` object and returns existing Pydantic models.

Public interface
----------------
    extract_headers(message: Message) -> EmailHeaders
    extract_authentication(message: Message) -> AuthenticationMetadata

Design constraints (from task spec)
------------------------------------
* Extraction ONLY — no phishing detection, trust scoring, or classification.
* Missing authentication data → AuthStatus.MISSING  (never AuthStatus.FAIL).
* DKIM-Signature header presence NEVER implies DKIM pass.
* Conflicting Authentication-Results are NOT silently resolved.
* All raw header evidence is preserved verbatim.
* Malformed or missing headers are handled gracefully (no crashes).
"""

from __future__ import annotations

import re
import warnings
from email.header import decode_header, make_header
from email.message import Message
from email.utils import formataddr, getaddresses, parseaddr
from typing import Optional

from app.schemas import (
    AuthenticationClaim,
    AuthenticationMetadata,
    AuthenticationResult,
    AuthMechanism,
    AuthProvenance,
    AuthStatus,
    EmailHeaders,
    VerificationStatus,
)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Matches the keyword result of an auth mechanism in an Authentication-Results
# value, e.g. "spf=pass", "dkim=fail", "dmarc=temperror".
_AUTH_RESULT_PATTERN = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*"
    r"(pass|fail|neutral|temperror|permerror|none|softfail|hardfail|policy|"
    r"nxdomain|signed|unknown|other|missing|unavailable)",
    re.IGNORECASE,
)

# Maps the raw reported keyword to an AuthStatus enum value.
_STATUS_MAP: dict[str, AuthStatus] = {
    "pass":        AuthStatus.PASS,
    "fail":        AuthStatus.FAIL,
    "neutral":     AuthStatus.NEUTRAL,
    "softfail":    AuthStatus.SOFTFAIL,   # SPF softfail is a distinct status (RFC 7208)
    "hardfail":    AuthStatus.FAIL,
    "none":        AuthStatus.NEUTRAL,    # RFC 7208: none means no record found
    "nxdomain":    AuthStatus.FAIL,
    "temperror":   AuthStatus.TEMPERROR,
    "permerror":   AuthStatus.PERMERROR,
    "policy":      AuthStatus.OTHER,
    "signed":      AuthStatus.OTHER,
    "unknown":     AuthStatus.OTHER,
    "other":       AuthStatus.OTHER,
    "missing":     AuthStatus.MISSING,
    "unavailable": AuthStatus.UNAVAILABLE,
}

_AUTHSERV_ID_RE = re.compile(r"^\s*\"?([^\s;\"()]+)\"?", re.ASCII)


def _extract_authserv_id(header_val: str) -> Optional[str]:
    """
    Extract authserv-id from the beginning of an Authentication-Results header.

    Per RFC 8601 section 2.2:
        Authentication-Results: <authserv-id> [version] ; <results>
    """
    if not header_val or not header_val.strip():
        return None
    m = _AUTHSERV_ID_RE.match(header_val)
    if m:
        authserv_id = m.group(1).strip()
        return authserv_id if authserv_id else None
    return None


def _decode_header_value(raw: Optional[str]) -> Optional[str]:
    """
    Decode an RFC 2047-encoded header value (e.g. ``=?UTF-8?B?...?=``).

    Returns the decoded string, or the original value if decoding fails.
    Returns None when ``raw`` is None.
    """
    if raw is None:
        return None
    try:
        return str(make_header(decode_header(raw)))
    except Exception:  # noqa: BLE001
        warnings.warn(
            f"Could not RFC-2047 decode header value: {raw!r}",
            stacklevel=4,
        )
        return raw


def _get_single(message: Message, name: str) -> Optional[str]:
    """Return the first value of *name* header, or None."""
    return message.get(name)


def _get_all(message: Message, name: str) -> list[str]:
    """Return all values of *name* header as a list (empty if absent)."""
    values = message.get_all(name)
    return values if values is not None else []


def _extract_addresses(raw_header: Optional[str]) -> list[str]:
    """
    Parse a potentially multi-address header (To, Cc, Bcc, Reply-To) into a
    list of normalised ``name <addr>`` strings, falling back to the original
    fragment on parse failure.

    Empty or None headers return an empty list.
    """
    if not raw_header or not raw_header.strip():
        return []
    try:
        pairs = getaddresses([raw_header])
        result: list[str] = []
        for display, addr in pairs:
            if addr:
                result.append(f"{display} <{addr}>".strip() if display else addr)
            elif display:
                # Malformed — no angle-bracket address, preserve display text
                result.append(display)
        return result if result else []
    except Exception:  # noqa: BLE001
        warnings.warn(
            f"Could not parse address header: {raw_header!r}",
            stacklevel=4,
        )
        return [raw_header]


def _extract_single_address(raw_header: Optional[str]) -> Optional[str]:
    """
    Parse a single-address header (From, Return-Path) into a normalised
    ``name <addr>`` string.

    Returns None when the header is absent or unparseable.
    """
    if not raw_header or not raw_header.strip():
        return None
    try:
        display, addr = parseaddr(raw_header)
        if addr:
            return formataddr((display, addr)) if display else addr
        # parseaddr found nothing useful — return the raw value as-is
        warnings.warn(
            f"Could not extract a valid address from: {raw_header!r}",
            stacklevel=4,
        )
        return raw_header.strip() or None
    except Exception:  # noqa: BLE001
        warnings.warn(
            f"Could not parse address header: {raw_header!r}",
            stacklevel=4,
        )
        return raw_header


# ---------------------------------------------------------------------------
# Public extraction functions
# ---------------------------------------------------------------------------


def extract_headers(message: Message) -> EmailHeaders:
    """
    Extract email header fields from a parsed ``email.message.Message``.

    Parameters
    ----------
    message:
        A Python standard-library ``email.message.Message`` object (or a
        subclass such as ``email.message.EmailMessage``).

    Returns
    -------
    EmailHeaders
        Populated with the header values found in *message*.  Missing headers
        are represented as ``None`` (optional fields) or ``[]`` (list fields).

    Notes
    -----
    * Encoded subjects (RFC 2047) are decoded.
    * Address fields are normalised but the original parsing is best-effort;
      malformed values are preserved rather than discarded.
    * All Received, Authentication-Results, Received-SPF, and DKIM-Signature
      headers are collected in full — repeated headers are not collapsed.
    """

    # --- From ----------------------------------------------------------------
    raw_from = _get_single(message, "From")
    from_address = _extract_single_address(raw_from)

    # --- To / Cc / Bcc -------------------------------------------------------
    to_raw = _get_single(message, "To")
    to = _extract_addresses(to_raw)

    cc_raw = _get_single(message, "Cc")
    cc = _extract_addresses(cc_raw)

    bcc_raw = _get_single(message, "Bcc")
    bcc = _extract_addresses(bcc_raw)

    # --- Reply-To / Return-Path ----------------------------------------------
    raw_reply_to = _get_single(message, "Reply-To")
    reply_to: Optional[str] = None
    if raw_reply_to:
        addrs = _extract_addresses(raw_reply_to)
        reply_to = addrs[0] if addrs else raw_reply_to.strip() or None

    raw_return_path = _get_single(message, "Return-Path")
    return_path = _extract_single_address(raw_return_path)

    # --- Subject (RFC 2047 decode) -------------------------------------------
    raw_subject = _get_single(message, "Subject")
    subject = _decode_header_value(raw_subject)

    # --- Date / Message-ID ---------------------------------------------------
    date = _get_single(message, "Date")
    message_id = _get_single(message, "Message-ID")
    if message_id:
        # Strip surrounding angle-brackets if present, but preserve the value
        message_id = message_id.strip()

    # --- Repeated headers ----------------------------------------------------
    received = _get_all(message, "Received")
    authentication_results = _get_all(message, "Authentication-Results")
    received_spf = _get_all(message, "Received-SPF")
    dkim_signature = _get_all(message, "DKIM-Signature")

    # --- MIME-Version / Content-Type -----------------------------------------
    mime_version = _get_single(message, "MIME-Version")
    content_type = _get_single(message, "Content-Type")
    if content_type:
        # Preserve only the media-type part (strip parameters like boundary=…)
        # but keep the raw string intact as the schema expects verbatim values.
        # We store the full value; callers may strip parameters themselves.
        content_type = content_type.strip()

    return EmailHeaders(
        from_address=from_address,
        to=to,
        cc=cc,
        bcc=bcc,
        reply_to=reply_to,
        return_path=return_path,
        subject=subject,
        date=date,
        message_id=message_id,
        received=received,
        authentication_results=authentication_results,
        received_spf=received_spf,
        dkim_signature=dkim_signature,
        mime_version=mime_version,
        content_type=content_type,
    )


# ---------------------------------------------------------------------------
# Authentication evidence extraction
# ---------------------------------------------------------------------------


def _aggregate_mechanism_summary(
    mechanism: AuthMechanism,
    mechanism_claims: list[AuthenticationClaim],
) -> AuthenticationResult:
    """
    Aggregate individual claims for a mechanism into a summary AuthenticationResult.

    Expected behavior:
    - No claim: MISSING.
    - One distinct status: retain that status.
    - Multiple contradictory statuses: OTHER.
    - Duplicate agreeing claims: retain the common status while preserving reporting servers.
    """
    if not mechanism_claims:
        return AuthenticationResult(
            mechanism=mechanism,
            status=AuthStatus.MISSING,
            raw_value=None,
            provenance=AuthProvenance.UNAVAILABLE,
            verification_status=VerificationStatus.UNVERIFIED,
            authserv_id=None,
        )

    statuses = [c.status for c in mechanism_claims]
    unique_statuses = list(dict.fromkeys(statuses))
    raw_fragments = [c.raw_value for c in mechanism_claims if c.raw_value]
    authservs = [c.authserv_id for c in mechanism_claims if c.authserv_id]
    unique_authservs = list(dict.fromkeys(authservs))
    primary_provenance = mechanism_claims[0].provenance

    if len(unique_statuses) == 1:
        authserv_id = "; ".join(unique_authservs) if unique_authservs else None
        return AuthenticationResult(
            mechanism=mechanism,
            status=unique_statuses[0],
            raw_value=raw_fragments[0] if raw_fragments else None,
            provenance=primary_provenance,
            verification_status=VerificationStatus.UNVERIFIED,
            authserv_id=authserv_id,
        )

    # Multiple distinct results found — conflicting evidence.
    warnings.warn(
        f"Conflicting {mechanism.value.upper()} results found across headers: "
        f"{raw_fragments}. Statuses: {[s.value for s in statuses]}. "
        f"Reporting summary as AuthStatus.OTHER.",
        stacklevel=3,
    )
    authserv_id = "; ".join(unique_authservs) if unique_authservs else None
    return AuthenticationResult(
        mechanism=mechanism,
        status=AuthStatus.OTHER,
        raw_value="; ".join(raw_fragments) if raw_fragments else None,
        provenance=primary_provenance,
        verification_status=VerificationStatus.UNVERIFIED,
        authserv_id=authserv_id,
    )


def extract_authentication(message: Message) -> AuthenticationMetadata:
    """
    Extract SPF, DKIM, and DMARC authentication evidence from *message*.

    Parameters
    ----------
    message:
        A Python standard-library ``email.message.Message`` object.

    Returns
    -------
    AuthenticationMetadata
        Contains summary fields ``spf``, ``dkim``, ``dmarc``, as well as the
        complete granular ``claims`` collection preserving every individual
        claim, reporting authserv-id, header index, and raw evidence.

    Security notes
    --------------
    * All extracted authentication results and claims are marked
      ``VerificationStatus.UNVERIFIED`` by default. No trusted receiving-server
      configuration exists yet.
    * ``DKIM-Signature`` header presence does NOT produce ``AuthStatus.PASS``.
      DKIM pass requires an explicit ``dkim=pass`` in ``Authentication-Results``.
    * No receiver trust weighting is applied — all ``Authentication-Results``
      and ``Received-SPF`` headers are extracted without discarding duplicate
      or conflicting claims.
    * Conflicting results are NEVER silently resolved in favour of ``pass``.
    """
    all_auth_results = _get_all(message, "Authentication-Results")
    all_received_spf = _get_all(message, "Received-SPF")

    claims: list[AuthenticationClaim] = []

    # 1. Extract every individual claim from every Authentication-Results header
    for idx, ar_value in enumerate(all_auth_results):
        ar_authserv = _extract_authserv_id(ar_value)
        for match in _AUTH_RESULT_PATTERN.finditer(ar_value):
            mech_str = match.group(1).lower()
            if mech_str == "spf":
                mech_enum = AuthMechanism.SPF
            elif mech_str == "dkim":
                mech_enum = AuthMechanism.DKIM
            elif mech_str == "dmarc":
                mech_enum = AuthMechanism.DMARC
            else:
                continue

            raw_keyword = match.group(2).lower()
            status = _STATUS_MAP.get(raw_keyword, AuthStatus.UNAVAILABLE)

            claims.append(
                AuthenticationClaim(
                    mechanism=mech_enum,
                    status=status,
                    authserv_id=ar_authserv,
                    raw_value=match.group(0),
                    header_raw=ar_value,
                    header_index=idx,
                    provenance=AuthProvenance.AUTHENTICATION_RESULTS_HEADER,
                    verification_status=VerificationStatus.UNVERIFIED,
                )
            )

    # 2. Extract every individual claim from every Received-SPF header
    for idx, rspf_value in enumerate(all_received_spf):
        stripped = rspf_value.strip()
        keyword_match = re.match(
            r"^(pass|fail|neutral|softfail|hardfail|none|temperror|permerror)\b",
            stripped,
            re.IGNORECASE,
        )
        if keyword_match:
            raw_keyword = keyword_match.group(1).lower()
            status = _STATUS_MAP.get(raw_keyword, AuthStatus.UNAVAILABLE)
        else:
            status = AuthStatus.UNAVAILABLE

        claims.append(
            AuthenticationClaim(
                mechanism=AuthMechanism.SPF,
                status=status,
                authserv_id=None,
                raw_value=stripped,
                header_raw=rspf_value,
                header_index=idx,
                provenance=AuthProvenance.RECEIVED_SPF_HEADER,
                verification_status=VerificationStatus.UNVERIFIED,
            )
        )

    # 3. Aggregate backward-compatible summary fields
    ar_spf_claims = [
        c for c in claims
        if c.mechanism == AuthMechanism.SPF
        and c.provenance == AuthProvenance.AUTHENTICATION_RESULTS_HEADER
    ]
    rspf_claims = [
        c for c in claims
        if c.mechanism == AuthMechanism.SPF
        and c.provenance == AuthProvenance.RECEIVED_SPF_HEADER
    ]
    dkim_claims = [c for c in claims if c.mechanism == AuthMechanism.DKIM]
    dmarc_claims = [c for c in claims if c.mechanism == AuthMechanism.DMARC]

    # For SPF summary: AR claims take precedence if present; fallback to Received-SPF
    if ar_spf_claims:
        spf_summary = _aggregate_mechanism_summary(AuthMechanism.SPF, ar_spf_claims)
    elif rspf_claims:
        spf_summary = _aggregate_mechanism_summary(AuthMechanism.SPF, rspf_claims)
    else:
        spf_summary = AuthenticationResult(
            mechanism=AuthMechanism.SPF,
            status=AuthStatus.MISSING,
            raw_value=None,
            provenance=AuthProvenance.UNAVAILABLE,
            verification_status=VerificationStatus.UNVERIFIED,
            authserv_id=None,
        )

    dkim_summary = _aggregate_mechanism_summary(AuthMechanism.DKIM, dkim_claims)
    dmarc_summary = _aggregate_mechanism_summary(AuthMechanism.DMARC, dmarc_claims)

    return AuthenticationMetadata(
        spf=spf_summary,
        dkim=dkim_summary,
        dmarc=dmarc_summary,
        claims=claims,
    )
