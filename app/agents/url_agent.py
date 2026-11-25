"""
url_agent.py
-------------
Layer 1 Deterministic URL Feature Extraction Agent for the Multi-Agent AI Phishing Email Detector.

Extracts exactly 39 canonical features across 5 categories in strict compliance with
docs/url_agent_phase_b_implementation_plan.md v2.3.0 and app/schemas/url_agent_schema.py.

Key Architectural Guarantees:
1. Strictly Passive & Offline: Zero network calls, DNS queries, or live HTTP requests.
2. Architecture B Boundary Validation: All 8 ExtractedURL fields evaluated strictly once
   in Step 1 and cached in immutable ValidatedURLRecord instances with raw_item eliminated.
3. Fail-Closed Error Handling: Strict 4-tier failure classification; unrecoverable crashes
   raise UrlAgentProcessingError preserving diagnostic context, original email_id, and
   extraction count, never emitting fabricated default zero results.
4. Single-Access Attribute Retrieval: _get_caller_attribute safely disambiguates missing
   attributes from descriptor getter crashes using static non-evaluating introspection.
5. Invariant Grounding: Section 8.1 availability manifest reads strictly from validated_records.
"""

from __future__ import annotations

from dataclasses import dataclass
import inspect
import ipaddress
import re
import time
import traceback
from typing import Any, List, Optional, Set, Tuple
import urllib.parse

from app.agents.url_components.contextual_analyzer import (
    check_anchor_url_mismatch,
    compute_sender_domain_alignment,
    has_redirect_parameter,
    is_url_shortener,
)
from app.agents.url_components.ip_classifier import classify_ip_address
from app.agents.url_components.lexical_features import (
    check_punycode,
    compute_hostname_entropy,
    count_path_segments,
    count_percent_encoded_triplets,
    detect_unusual_ip_format,
    has_at_symbol_in_url,
    has_double_percent_encoding,
    has_embedded_credentials,
    has_executable_file_in_path,
    has_non_ascii_url,
    has_percent_encoding,
)
from app.agents.url_components.psl_resolver import resolve_domain
from app.agents.url_components.syntax_validator import validate_url_syntax
from app.schemas.email_schema import EmailData, ExtractedURL, URLSource
from app.schemas.url_agent_schema import (
    DomainResolutionStatus,
    UrlAgentResult,
    UrlAnalysisItem,
    UrlEvidence,
    UrlEvidenceItem,
    UrlFeatureAvailability,
    UrlFeatures,
)


_SENTINEL = object()
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def sanitize_snippet(text: Optional[str], max_len: int = 256) -> str:
    """Sanitize and bound raw string excerpts for safe Tier 2 forensic storage."""
    if not text:
        return ""
    clean = _CONTROL_CHARS_RE.sub(" ", text).strip()
    return clean[:max_len]


@dataclass(frozen=True, slots=True)
class ValidatedURLRecord:
    """
    Internal immutable record caching validated ExtractedURL fields for single-access processing.
    raw_item is strictly eliminated to prevent unvalidated property leaks or descriptor calls.
    """
    original_url: str
    source: URLSource
    anchor_text: Optional[str] = None
    normalized_url: Optional[str] = None
    scheme: Optional[str] = None
    hostname: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None


def _get_caller_attribute(target: Any, attr_name: str) -> Any:
    """
    Retrieve a required attribute from a caller input object with single-access
    execution and strict disambiguation between missing attributes and descriptor crashes.
    """
    try:
        return getattr(target, attr_name)
    except AttributeError as exc:
        is_defined = False
        try:
            static_val = inspect.getattr_static(target, attr_name, _SENTINEL)
            if static_val is not _SENTINEL:
                is_defined = True
        except Exception:
            pass

        # Check Python 3.10+ exception metadata (exc.name) if available
        exc_name = getattr(exc, "name", None)
        if not is_defined and exc_name is not None and exc_name != attr_name:
            # The AttributeError was raised for an internal attribute during getter execution
            is_defined = True

        if is_defined:
            raise AttributeError(
                f"Error accessing '{attr_name}' on {type(target).__name__}: "
                f"property or descriptor getter raised AttributeError: {exc}"
            ) from exc

        raise AttributeError(
            f"Invalid input: {type(target).__name__} missing required attribute '{attr_name}'."
        ) from exc


class UrlAgentProcessingError(RuntimeError):
    """
    Raised when the URL Agent encounters an unrecoverable failure during top-level execution.
    Preserves input provenance, original email identity, and diagnostic traceback.
    """

    def __init__(
        self,
        message: str,
        email_id: Optional[str] = None,
        total_urls_extracted: int = 0,
        original_exception: Optional[Exception] = None,
        traceback_str: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.email_id = email_id
        self.total_urls_extracted = total_urls_extracted
        self.original_exception = original_exception
        self.traceback_str = traceback_str


def create_no_url_result(email_id: str) -> UrlAgentResult:
    """
    State 1: Verified Absence of URLs.
    Constructs a schema-valid UrlAgentResult indicating clean, observed absence of URLs.
    """
    return UrlAgentResult(
        email_id=email_id,
        status="success",
        total_urls_extracted=0,
        features=UrlFeatures(),  # Defaults: counts=0, booleans=False, nullable=None
        availability=UrlFeatureAvailability(
            avail_has_urls=False,
            avail_structure_features=False,
            avail_hostname_features=False,
            avail_entropy_features=False,
            avail_sender_alignment=False,
            avail_anchor_text_analysis=False,
            completeness_structure=0.0,
            completeness_hostname=0.0,
            completeness_obfuscation=0.0,
            completeness_context=0.0,
            completeness_total=0.0,
        ),
        evidence=UrlEvidence(
            evidence_items=[],
            omitted_evidence_count=0,
            detected_anomalous_hostnames=[],
            detected_shorteners=[],
            observed_anomalies=[],
        ),
        analysis_items=[],
        warnings=[],
        limitations=[
            "Zero URLs extracted from email; URL modality feature vector reflects observed absence."
        ],
    )


def execute_url_analysis_pipeline(
    email_data: EmailData,
    email_id: str,
    validated_records: List[ValidatedURLRecord],
) -> UrlAgentResult:
    """
    State 2: URLs Present (Success / Partial).
    Executes full deterministic extraction across 100% of URLs in validated_records.
    """
    start_time = time.perf_counter()
    total_urls = len(validated_records)

    analysis_items: List[UrlAnalysisItem] = []
    evidence_items_raw: List[UrlEvidenceItem] = []
    detected_anomalous_hostnames: Set[str] = set()
    detected_shorteners: Set[str] = set()
    observed_anomalies: Set[str] = set()
    warnings: List[str] = []

    # Aggregate metric collectors across 100% of URLs
    unique_url_keys: Set[str] = set()
    unique_domains: Set[str] = set()
    unique_fqdns: Set[str] = set()

    http_count = 0
    https_count = 0
    suspicious_scheme_count = 0
    has_non_default_port = False
    max_url_len = 0
    max_path_depth = 0
    has_executable = False

    has_ip_literal_url = False
    has_private_ip_url = False
    has_loopback_ip_url = False
    has_special_ip_url = False
    has_punycode_url = False
    subdomain_depths: List[int] = []
    hostname_entropies: List[float] = []

    has_at_symbol = False
    has_embedded_creds = False
    has_percent_enc = False
    has_double_percent_enc = False
    max_percent_enc_count = 0
    has_non_ascii = False
    has_unusual_ip = False
    malformed_url_count = 0

    has_shortener = False
    shortener_count = 0
    has_redirect_param = False
    has_anchor_mismatch = False
    anchor_mismatch_count = 0

    target_records_for_sender: List[Tuple[Optional[str], DomainResolutionStatus]] = []

    standard_ports = {
        "http": 80,
        "https": 443,
        "ftp": 21,
        "ssh": 22,
    }

    suspicious_schemes = {"javascript", "data", "file", "vbscript", "callto"}

    # ------------------------------------------------------------------
    # Pass 2: Per-URL Analysis & Extraction
    # ------------------------------------------------------------------
    for idx, rec in enumerate(validated_records):
        url_str = rec.original_url
        max_url_len = max(max_url_len, len(url_str))

        # Identity key for uniqueness (Feature 2)
        key = rec.normalized_url.strip() if rec.normalized_url and rec.normalized_url.strip() else url_str.strip()
        unique_url_keys.add(key)

        # Syntax validation (Feature 30)
        is_malformed, malformed_reasons = validate_url_syntax(url_str)
        if is_malformed:
            malformed_url_count += 1
            observed_anomalies.add("Structurally malformed URL syntax detected")
            for r in malformed_reasons:
                evidence_items_raw.append(
                    UrlEvidenceItem(
                        finding_id=f"malformed_url_{idx}",
                        feature_name="malformed_url_count",
                        category="Category C",
                        url_index=idx,
                        source=rec.source,
                        observed_value=sanitize_snippet(r, 256),
                        description="URL string failed structural syntax validation checks.",
                        limitations_and_benign_explanations="Broken links or malformed copy-paste by benign senders.",
                        raw_snippet_bounded=sanitize_snippet(url_str, 256),
                    )
                )

        # Parse URL safely
        try:
            split_res = urllib.parse.urlsplit(url_str)
            raw_netloc = split_res.netloc
            raw_hostname = split_res.hostname
            raw_path = split_res.path
            raw_query = split_res.query
            parsed_scheme = split_res.scheme.lower() if split_res.scheme else None
        except Exception:
            raw_netloc = None
            raw_hostname = None
            raw_path = None
            raw_query = None
            parsed_scheme = None

        scheme = parsed_scheme or (rec.scheme.lower() if rec.scheme else None)

        # Scheme metrics (Features 4, 5, 6, 7)
        if scheme == "http":
            http_count += 1
        elif scheme == "https":
            https_count += 1
        elif scheme in suspicious_schemes:
            suspicious_scheme_count += 1
            observed_anomalies.add(f"Suspicious URL scheme detected: '{scheme}'")
            evidence_items_raw.append(
                UrlEvidenceItem(
                    finding_id=f"suspicious_scheme_{idx}",
                    feature_name="suspicious_scheme_count",
                    category="Category A",
                    url_index=idx,
                    source=rec.source,
                    observed_value=str(scheme),
                    description=f"URL specifies suspicious non-web protocol scheme '{scheme}'.",
                    limitations_and_benign_explanations="Certain desktop mail clients generate file: or callto: protocol links.",
                    raw_snippet_bounded=sanitize_snippet(url_str, 256),
                )
            )

        # Port validation (Feature 8)
        port: Optional[int] = None
        try:
            if split_res and split_res.port is not None:
                p = split_res.port
                if 1 <= p <= 65535:
                    port = p
                    if scheme and scheme in standard_ports:
                        if port != standard_ports[scheme]:
                            has_non_default_port = True
                    elif scheme:
                        has_non_default_port = True
        except (ValueError, Exception):
            pass

        # Path metrics (Features 10, 11)
        path_str = raw_path or rec.path
        if path_str:
            p_depth = count_path_segments(path_str)
            max_path_depth = max(max_path_depth, p_depth)
            if has_executable_file_in_path(path_str):
                has_executable = True
                observed_anomalies.add("Direct executable file reference in URL path")
                evidence_items_raw.append(
                    UrlEvidenceItem(
                        finding_id=f"executable_path_{idx}",
                        feature_name="has_executable_file_in_path",
                        category="Category A",
                        url_index=idx,
                        source=rec.source,
                        observed_value=sanitize_snippet(path_str.split("/")[-1], 256),
                        description="URL path directly references an executable binary format.",
                        limitations_and_benign_explanations="Legitimate software download repositories.",
                        raw_snippet_bounded=sanitize_snippet(url_str, 256),
                    )
                )

        # Normalization of hostname
        normalized_hostname: Optional[str] = None
        if raw_hostname:
            clean_host = raw_hostname.strip().rstrip(".").lower()
            try:
                normalized_hostname = clean_host.encode("idna").decode("ascii")
            except Exception:
                normalized_hostname = clean_host
        elif rec.hostname:
            normalized_hostname = rec.hostname.strip().rstrip(".").lower()

        # Domain resolution via PSL
        reg_domain, domain_status, depth = resolve_domain(normalized_hostname)
        target_records_for_sender.append((reg_domain, domain_status))

        # Hostname entropy (Feature 19)
        entropy = compute_hostname_entropy(normalized_hostname)
        if entropy is not None:
            hostname_entropies.append(entropy)

        # Punycode check (Feature 16)
        is_puny = check_punycode(normalized_hostname, raw_hostname)
        if is_puny:
            has_punycode_url = True
            if normalized_hostname:
                detected_anomalous_hostnames.add(normalized_hostname)
            observed_anomalies.add("Internationalized domain name (Punycode) detected")
            evidence_items_raw.append(
                UrlEvidenceItem(
                    finding_id=f"punycode_{idx}",
                    feature_name="has_punycode_url",
                    category="Category B",
                    url_index=idx,
                    source=rec.source,
                    observed_value=str(normalized_hostname or raw_hostname),
                    description="Hostname employs Punycode/IDNA representation susceptible to homograph spoofing.",
                    limitations_and_benign_explanations="Legitimate international websites operating under native script domain names.",
                    raw_snippet_bounded=sanitize_snippet(url_str, 256),
                )
            )

        # IP classification (Features 12, 13, 14, 15)
        ip_class = None
        has_ip = False
        if domain_status == DomainResolutionStatus.IP_LITERAL:
            has_ip = True
            has_ip_literal_url = True
            if normalized_hostname:
                detected_anomalous_hostnames.add(normalized_hostname)
            try:
                ip_class = classify_ip_address(normalized_hostname or "")
                if ip_class in ("rfc1918", "rfc4193"):
                    has_private_ip_url = True
                elif ip_class == "loopback":
                    has_loopback_ip_url = True
                elif ip_class in ("cgnat", "documentation", "multicast", "special_purpose"):
                    has_special_ip_url = True
            except Exception:
                ip_class = "special_purpose"
                has_special_ip_url = True

            observed_anomalies.add(f"IP address literal host: {ip_class}")
            evidence_items_raw.append(
                UrlEvidenceItem(
                    finding_id=f"ip_literal_{idx}",
                    feature_name="has_ip_literal_url",
                    category="Category B",
                    url_index=idx,
                    source=rec.source,
                    observed_value=str(normalized_hostname),
                    description=f"URL specifies raw IP address literal ({ip_class}) rather than registered domain name.",
                    limitations_and_benign_explanations="Internal network management consoles or printer portals.",
                    raw_snippet_bounded=sanitize_snippet(url_str, 256),
                )
            )

        # Subdomain depth tracking (Features 17, 18)
        if domain_status in (
            DomainResolutionStatus.EXACT_MATCH,
            DomainResolutionStatus.WILDCARD_MATCH,
            DomainResolutionStatus.EXCEPTION_MATCH,
        ):
            subdomain_depths.append(depth)

        # Domain and FQDN counting (Features 20, 21)
        if domain_status in (
            DomainResolutionStatus.EXACT_MATCH,
            DomainResolutionStatus.WILDCARD_MATCH,
            DomainResolutionStatus.EXCEPTION_MATCH,
        ):
            if reg_domain:
                unique_domains.add(reg_domain.lower())
        elif domain_status == DomainResolutionStatus.IP_LITERAL and normalized_hostname:
            try:
                canonical_ip = str(ipaddress.ip_address(normalized_hostname))
                unique_domains.add(canonical_ip)
            except ValueError:
                unique_domains.add(normalized_hostname)
        elif domain_status == DomainResolutionStatus.UNKNOWN_SUFFIX and normalized_hostname:
            unique_domains.add(normalized_hostname.lower())

        if normalized_hostname and domain_status != DomainResolutionStatus.IP_LITERAL:
            unique_fqdns.add(normalized_hostname.lower())

        # Authority deception & encodings (Features 22, 23, 24, 25, 26, 28, 29)
        if has_at_symbol_in_url(raw_netloc, url_str):
            has_at_symbol = True
        if has_embedded_credentials(raw_netloc, url_str):
            has_embedded_creds = True
            observed_anomalies.add("Embedded credentials present in URL authority")
            evidence_items_raw.append(
                UrlEvidenceItem(
                    finding_id=f"embedded_creds_{idx}",
                    feature_name="has_embedded_credentials",
                    category="Category C",
                    url_index=idx,
                    source=rec.source,
                    observed_value=sanitize_snippet(raw_netloc, 256),
                    description="URL authority explicitly embeds user credentials.",
                    limitations_and_benign_explanations="Legacy authentication formats in corporate environments.",
                    raw_snippet_bounded=sanitize_snippet(url_str, 256),
                )
            )

        if has_percent_encoding(url_str):
            has_percent_enc = True
        if has_double_percent_encoding(url_str):
            has_double_percent_enc = True
        pct_count = count_percent_encoded_triplets(url_str)
        max_percent_enc_count = max(max_percent_enc_count, pct_count)

        if has_non_ascii_url(url_str):
            has_non_ascii = True

        if detect_unusual_ip_format(normalized_hostname, raw_netloc):
            has_unusual_ip = True
            observed_anomalies.add("Unusual IP representation detected (hex, octal, or integer)")

        # URL Shorteners (Features 31, 32)
        is_short = is_url_shortener(normalized_hostname, reg_domain)
        if is_short:
            has_shortener = True
            shortener_count += 1
            if reg_domain:
                detected_shorteners.add(reg_domain.lower())
            elif normalized_hostname:
                detected_shorteners.add(normalized_hostname.lower())
            observed_anomalies.add("URL shortener service detected")
            evidence_items_raw.append(
                UrlEvidenceItem(
                    finding_id=f"shortener_{idx}",
                    feature_name="has_url_shortener",
                    category="Category D",
                    url_index=idx,
                    source=rec.source,
                    observed_value=str(reg_domain or normalized_hostname),
                    description="URL leverages a link shortening domain concealing final destination.",
                    limitations_and_benign_explanations="Marketing campaigns, character-limited messaging platforms.",
                    raw_snippet_bounded=sanitize_snippet(url_str, 256),
                )
            )

        # Redirect parameters (Feature 33)
        query_str = raw_query or rec.query
        has_redir = has_redirect_parameter(query_str)
        if has_redir:
            has_redirect_param = True
            observed_anomalies.add("Open redirect parameter observed in query string")

        # Visual anchor text mismatch (Features 34, 35)
        mismatch, anchor_host = check_anchor_url_mismatch(
            source=rec.source,
            anchor_text=rec.anchor_text,
            dest_hostname=normalized_hostname,
            dest_registered_domain=reg_domain,
            dest_status=domain_status,
        )
        if mismatch:
            has_anchor_mismatch = True
            anchor_mismatch_count += 1
            observed_anomalies.add("Visible anchor text displays conflicting domain identity")
            evidence_items_raw.append(
                UrlEvidenceItem(
                    finding_id=f"anchor_mismatch_{idx}",
                    feature_name="has_anchor_url_mismatch",
                    category="Category D",
                    url_index=idx,
                    source=rec.source,
                    observed_value=f"anchor: '{sanitize_snippet(rec.anchor_text, 80)}' -> dest: '{sanitize_snippet(url_str, 80)}'",
                    description="Visible anchor text displays a domain that mismatches the actual target destination.",
                    limitations_and_benign_explanations="Corporate newsletters and email marketing platforms rewriting links for engagement tracking.",
                    raw_snippet_bounded=sanitize_snippet(url_str, 256),
                )
            )

        # Build UrlAnalysisItem for the first 200 URLs
        if idx < 200:
            analysis_items.append(
                UrlAnalysisItem(
                    url_index=idx,
                    original_url_snippet=sanitize_snippet(url_str, 256),
                    source=rec.source,
                    anchor_text_snippet=sanitize_snippet(rec.anchor_text, 128) if rec.anchor_text else None,
                    scheme=scheme,
                    hostname=normalized_hostname,
                    registered_domain=reg_domain,
                    domain_resolution_status=domain_status,
                    port=port,
                    path=path_str,
                    has_ip_hostname=has_ip,
                    ip_classification=ip_class,
                    is_punycode=is_puny,
                    is_url_shortener=is_short,
                    has_redirect_parameter=has_redir,
                    has_anchor_mismatch=mismatch,
                    hostname_entropy=entropy,
                    url_length=len(url_str),
                    is_malformed=is_malformed,
                    malformed_reasons=malformed_reasons,
                )
            )

    # ------------------------------------------------------------------
    # Pass 3: Full Aggregate Metric Evaluation
    # ------------------------------------------------------------------
    # Sender domain alignment (Features 36, 37, 38)
    from_addr = None
    if email_data.headers and email_data.headers.from_address:
        from_addr = email_data.headers.from_address

    has_sender_mismatch, matching_ratio, ext_ratio, from_resolvable = compute_sender_domain_alignment(
        from_address=from_addr,
        url_target_records=target_records_for_sender,
    )

    max_depth = max(subdomain_depths) if subdomain_depths else 0
    max_entropy = max(hostname_entropies) if hostname_entropies else None

    # Assemble 39 canonical features
    features = UrlFeatures(
        # Category A: Structural Properties
        total_url_count=total_urls,
        unique_url_count=len(unique_url_keys),
        has_urls=True,
        http_url_count=http_count,
        https_url_count=https_count,
        suspicious_scheme_count=suspicious_scheme_count,
        has_suspicious_scheme=bool(suspicious_scheme_count > 0),
        has_non_default_port=has_non_default_port,
        max_url_length=max_url_len,
        max_path_depth=max_path_depth,
        has_executable_file_in_path=has_executable,
        # Category B: Hostname & Domain Composition
        has_ip_literal_url=has_ip_literal_url,
        has_private_ip_url=has_private_ip_url,
        has_loopback_ip_url=has_loopback_ip_url,
        has_special_ip_url=has_special_ip_url,
        has_punycode_url=has_punycode_url,
        max_subdomain_depth=max_depth,
        has_excessive_subdomains=bool(max_depth >= 3),
        max_hostname_entropy=max_entropy,
        unique_domain_count=len(unique_domains),
        unique_fqdn_count=len(unique_fqdns),
        # Category C: Obfuscation & Encodings
        has_at_symbol_in_url=has_at_symbol,
        has_embedded_credentials=has_embedded_creds,
        has_percent_encoding=has_percent_enc,
        has_double_percent_encoding=has_double_percent_enc,
        max_percent_encoded_count=max_percent_enc_count,
        has_brand_in_path=None,  # Quarantined
        has_non_ascii_url=has_non_ascii,
        has_unusual_ip_format=has_unusual_ip,
        malformed_url_count=malformed_url_count,
        # Category D: Contextual Alignment & Behavioral Indicators
        has_url_shortener=has_shortener,
        url_shortener_count=shortener_count,
        has_redirect_parameter=has_redirect_param,
        has_anchor_url_mismatch=has_anchor_mismatch,
        anchor_url_mismatch_count=anchor_mismatch_count,
        has_sender_domain_mismatch_url=has_sender_mismatch,
        sender_domain_matching_url_ratio=matching_ratio,
        external_link_ratio=ext_ratio,
        has_form_action_url=None,  # Quarantined
    )

    # Availability manifest grounded strictly on validated_records (Section 8.1)
    avail_hostname = all(bool(r.hostname) for r in validated_records)
    avail_entropy = any(bool(r.hostname) for r in validated_records)
    avail_sender = bool(from_resolvable and (matching_ratio is not None))
    avail_anchor = any(bool(r.anchor_text) for r in validated_records if r.source == URLSource.HTML_HREF)

    availability = UrlFeatureAvailability(
        avail_has_urls=True,
        avail_structure_features=True,
        avail_hostname_features=avail_hostname,
        avail_entropy_features=avail_entropy,
        avail_sender_alignment=avail_sender,
        avail_anchor_text_analysis=avail_anchor,
    )

    # ------------------------------------------------------------------
    # Capacity Caps Application
    # ------------------------------------------------------------------
    if total_urls > 200:
        warnings.append(
            f"Email contains {total_urls} URLs; granular inspection records capped to first 200 per safety budget."
        )

    evidence_items = evidence_items_raw[:100]
    omitted_evidence = max(0, len(evidence_items_raw) - 100)

    capped_hostnames = sorted(detected_anomalous_hostnames)[:50]
    capped_shorteners = sorted(detected_shorteners)[:50]
    capped_anomalies = sorted(observed_anomalies)[:100]

    evidence = UrlEvidence(
        evidence_items=evidence_items,
        omitted_evidence_count=omitted_evidence,
        detected_anomalous_hostnames=capped_hostnames,
        detected_shorteners=capped_shorteners,
        observed_anomalies=capped_anomalies,
    )

    processing_time_ms = (time.perf_counter() - start_time) * 1000.0

    return UrlAgentResult(
        email_id=email_id,
        status="success",
        processing_time_ms=processing_time_ms,
        total_urls_extracted=total_urls,
        features=features,
        availability=availability,
        evidence=evidence,
        analysis_items=analysis_items,
        warnings=warnings,
        limitations=[
            "URL feature extraction executed purely offline; no live DNS or HTTP fetches performed."
        ],
    )


def analyze_urls(email_data: EmailData) -> UrlAgentResult:
    """
    Analyze all URLs extracted from an email and emit a validated UrlAgentResult.

    Preconditions (Caller Input & Record Contract):
        - email_data must be an EmailData instance or legitimate subclass (raises TypeError).
        - email_data.email_id must be a non-empty, non-whitespace string (raises ValueError/AttributeError).
        - email_data.extracted_urls must be a list of ExtractedURL objects (raises TypeError/AttributeError).
        - For each ExtractedURL item:
            * original_url must be a non-empty, non-whitespace string (raises ValueError/TypeError/AttributeError).
            * source must be a URLSource enum member (raises TypeError/AttributeError).
            * anchor_text must be None or str (raises TypeError/AttributeError).
            * normalized_url must be None or str (raises TypeError/AttributeError).
            * scheme must be None or str (raises TypeError/AttributeError).
            * hostname must be None or str (raises TypeError/AttributeError).
            * path must be None or str (raises TypeError/AttributeError).
            * query must be None or str (raises TypeError/AttributeError).
    """
    # ------------------------------------------------------------------
    # Step 1: Input Precondition Validation & Single-Access Field Caching
    # ------------------------------------------------------------------
    # Runs OUTSIDE the internal processing try block. Input contract violations
    # raise standard exceptions and are strictly NOT wrapped as UrlAgentProcessingError.
    if not isinstance(email_data, EmailData):
        raise TypeError(
            f"Invalid input: analyze_urls requires an EmailData instance or legitimate subclass, "
            f"got {type(email_data).__name__}."
        )

    # 1.1 Single-access email_id retrieval and exact preservation
    raw_id = _get_caller_attribute(email_data, "email_id")
    if not isinstance(raw_id, str) or not raw_id.strip():
        raise ValueError("Cannot process email: email_data.email_id must be a non-empty, non-whitespace string.")
    email_id = raw_id  # Exact original string preserved without alteration

    # 1.2 Single-access extracted_urls retrieval & strict list validation
    raw_urls = _get_caller_attribute(email_data, "extracted_urls")
    if not isinstance(raw_urls, list):
        raise TypeError(
            f"Invalid input: email_data.extracted_urls must be a list of ExtractedURL objects "
            f"(got {type(raw_urls).__name__}). Tuples, sets, generators, strings, bytes, mappings, and non-list types are rejected."
        )

    total_urls = len(raw_urls)

    # 1.3 Strict ExtractedURL boundary validation and single-access field caching (Architecture B)
    validated_records: List[ValidatedURLRecord] = []
    if total_urls > 0:
        for idx, item in enumerate(raw_urls):
            if not isinstance(item, ExtractedURL):
                raise TypeError(
                    f"Invalid input: email_data.extracted_urls[{idx}] must be an ExtractedURL instance "
                    f"or legitimate subclass, got {type(item).__name__}."
                )

            # Single-access retrieval and validation of all 8 consumed fields
            orig_url = _get_caller_attribute(item, "original_url")
            if not isinstance(orig_url, str) or not orig_url.strip():
                raise ValueError(
                    f"Invalid input: email_data.extracted_urls[{idx}].original_url must be a "
                    f"non-empty, non-whitespace string (got {type(orig_url).__name__})."
                )

            src = _get_caller_attribute(item, "source")
            if not isinstance(src, URLSource):
                raise TypeError(
                    f"Invalid input: email_data.extracted_urls[{idx}].source must be a URLSource enum "
                    f"member (got {type(src).__name__})."
                )

            anchor = _get_caller_attribute(item, "anchor_text")
            if anchor is not None and not isinstance(anchor, str):
                raise TypeError(
                    f"Invalid input: email_data.extracted_urls[{idx}].anchor_text must be None or str "
                    f"(got {type(anchor).__name__})."
                )

            norm_url = _get_caller_attribute(item, "normalized_url")
            if norm_url is not None and not isinstance(norm_url, str):
                raise TypeError(
                    f"Invalid input: email_data.extracted_urls[{idx}].normalized_url must be None or str "
                    f"(got {type(norm_url).__name__})."
                )

            scheme = _get_caller_attribute(item, "scheme")
            if scheme is not None and not isinstance(scheme, str):
                raise TypeError(
                    f"Invalid input: email_data.extracted_urls[{idx}].scheme must be None or str "
                    f"(got {type(scheme).__name__})."
                )

            hostname = _get_caller_attribute(item, "hostname")
            if hostname is not None and not isinstance(hostname, str):
                raise TypeError(
                    f"Invalid input: email_data.extracted_urls[{idx}].hostname must be None or str "
                    f"(got {type(hostname).__name__})."
                )

            path = _get_caller_attribute(item, "path")
            if path is not None and not isinstance(path, str):
                raise TypeError(
                    f"Invalid input: email_data.extracted_urls[{idx}].path must be None or str "
                    f"(got {type(path).__name__})."
                )

            query = _get_caller_attribute(item, "query")
            if query is not None and not isinstance(query, str):
                raise TypeError(
                    f"Invalid input: email_data.extracted_urls[{idx}].query must be None or str "
                    f"(got {type(query).__name__})."
                )

            validated_records.append(
                ValidatedURLRecord(
                    original_url=orig_url,
                    source=src,
                    anchor_text=anchor,
                    normalized_url=norm_url,
                    scheme=scheme,
                    hostname=hostname,
                    path=path,
                    query=query,
                )
            )

    # ------------------------------------------------------------------
    # Step 2: Internal Processing Execution (Unified Fail-Closed Protection)
    # ------------------------------------------------------------------
    try:
        if total_urls == 0:
            return create_no_url_result(email_id=email_id)

        return execute_url_analysis_pipeline(
            email_data=email_data,
            email_id=email_id,
            validated_records=validated_records,
        )
    except Exception as exc:
        tb_str = traceback.format_exc()
        raise UrlAgentProcessingError(
            message=f"URL Agent internal processing failed for email {email_id}: {type(exc).__name__}: {exc}",
            email_id=email_id,
            total_urls_extracted=total_urls,
            original_exception=exc,
            traceback_str=tb_str,
        ) from exc
