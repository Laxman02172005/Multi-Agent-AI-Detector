"""
url_agent_schema.py
-------------------
Pydantic v2 data contract for the URL Agent in the Multi-Agent AI Phishing Email Detector.

Architecture:
- DomainResolutionStatus: String enumeration for the 7 approved PSL resolution outcomes.
- IPClassificationCategory: Literal type for the 9 approved RFC IP classification categories.
- CANONICAL_URL_FEATURE_NAMES: Machine-auditable 39-feature literal type (strictly continuous 1..39).
- CANONICAL_URL_FEATURE_LIST: Ordered tuple of all 39 canonical feature names.
- CATEGORY_A_FEATURES .. CATEGORY_D_FEATURES: Approved category partitions (A: 11, B: 10, C: 9, D: 9).
- URL_CATEGORY_IDENTIFIERS: Literal type for the 4 approved category names ("Category A" .. "Category D").
- FEATURE_TO_CATEGORY_MAP: Complete 1-to-1 mapping of all 39 features to approved categories.
- ACTIVE_URL_FEATURES: Immutable set of the 36 active feature names.
- QUARANTINED_URL_FEATURES: Immutable set of the 3 quarantined feature names.
- UrlFeatures: Sanitized Tier 3 feature vector (canonical 39 features, zero raw text/hostnames).
- UrlFeatureAvailability: Comprehensive availability and completeness manifest.
- UrlEvidenceItem: Traceable forensic evidence link for an observed feature or anomaly.
- UrlEvidence: Tier 2 forensic evidence and audit trails (strictly quarantined from ML).
- UrlAnalysisItem: Detailed intermediate inspection record for an individual URL (max 200).
- UrlAgentResult: Complete serializable agent output container (aliased as UrlAgentOutput).

Design Invariants:
- Exactly 39 canonical features (36 active, 3 quarantined: http_url_count, has_brand_in_path, has_form_action_url).
- Strictly passive, offline, and deterministic: zero network calls, socket connections, or DNS queries.
- Zero risk predictions, probabilities, confidence scores, or final phishing verdicts.
- Tier 2 container caps: analysis_items <= 200, evidence_items <= 100, detected_anomalous_hostnames <= 50.
- Aggregate feature extraction operates across ALL extracted URLs without truncation.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Optional, Tuple, get_args

from pydantic import AliasChoices, BaseModel, Field, field_validator, model_validator

from app.schemas.email_schema import URLSource, VerificationStatus


# ---------------------------------------------------------------------------
# 1. Domain Resolution Status & IP Classification Vocabulary (Section 8.2 & 9.1)
# ---------------------------------------------------------------------------

class DomainResolutionStatus(str, Enum):
    """
    Explicit outcome of PSL-based registered domain resolution.
    Strictly enforces the seven approved statuses from v1.10.0 design spec.
    """
    EXACT_MATCH = "exact_match"          # Hostname suffix exactly matches a PSL rule
    WILDCARD_MATCH = "wildcard_match"    # Hostname suffix matches a PSL wildcard rule (e.g. *.ck)
    EXCEPTION_MATCH = "exception_match"  # Hostname matches a PSL exception rule (e.g. !www.ck)
    UNKNOWN_SUFFIX = "unknown_suffix"    # Hostname has a valid structure but suffix is not in PSL snapshot
    INVALID_HOSTNAME = "invalid_hostname"  # Hostname fails structural validation (empty, whitespace-only, etc.)
    IP_LITERAL = "ip_literal"            # Hostname is an IPv4 or IPv6 address literal
    NO_HOSTNAME = "no_hostname"          # URL has no hostname component (e.g. data: URIs, mailto:)


# Approved RFC IP classification categories from Section 9.1
IPClassificationCategory = Literal[
    "loopback",
    "link_local",
    "multicast",
    "cgnat",
    "documentation",
    "special_purpose",
    "rfc1918",
    "rfc4193",
    "syntactically_global",
]

IP_CLASSIFICATION_CATEGORIES: Tuple[str, ...] = get_args(IPClassificationCategory)


# ---------------------------------------------------------------------------
# 2. Canonical 39-Feature Registry Literal and Collections (Section 5 & Plan)
# ---------------------------------------------------------------------------

# Canonical 39-feature registry literal type (strictly continuous 1..39)
CANONICAL_URL_FEATURE_NAMES = Literal[
    # Category A: URL Structural Properties (Features 1..11, 11 Features, 1 Quarantined)
    "total_url_count",
    "unique_url_count",
    "has_urls",
    "http_url_count",
    "https_url_count",
    "suspicious_scheme_count",
    "has_suspicious_scheme",
    "has_non_default_port",
    "max_url_length",
    "max_path_depth",
    "has_executable_file_in_path",
    # Category B: Hostname & Domain Composition (Features 12..21, 10 Features)
    "has_ip_literal_url",
    "has_private_ip_url",
    "has_loopback_ip_url",
    "has_special_ip_url",
    "has_punycode_url",
    "max_subdomain_depth",
    "has_excessive_subdomains",
    "max_hostname_entropy",
    "unique_domain_count",
    "unique_fqdn_count",
    # Category C: Obfuscation, Encodings & Deception (Features 22..30, 9 Features, 1 Quarantined)
    "has_at_symbol_in_url",
    "has_embedded_credentials",
    "has_percent_encoding",
    "has_double_percent_encoding",
    "max_percent_encoded_count",
    "has_brand_in_path",
    "has_non_ascii_url",
    "has_unusual_ip_format",
    "malformed_url_count",
    # Category D: Contextual Alignment & Behavioral Indicators (Features 31..39, 9 Features, 1 Quarantined)
    "has_url_shortener",
    "url_shortener_count",
    "has_redirect_parameter",
    "has_anchor_url_mismatch",
    "anchor_url_mismatch_count",
    "has_sender_domain_mismatch_url",
    "sender_domain_matching_url_ratio",
    "external_link_ratio",
    "has_form_action_url",
]

# Immutable ordered tuple of all 39 canonical feature names in exact 1..39 index order
CANONICAL_URL_FEATURE_LIST: Tuple[str, ...] = get_args(CANONICAL_URL_FEATURE_NAMES)

# Categorical partitions (Approved Design docs/url_agent_design.md v1.10.0 Section 5: A: 11, B: 10, C: 9, D: 9)
CATEGORY_A_FEATURES: Tuple[str, ...] = CANONICAL_URL_FEATURE_LIST[0:11]
CATEGORY_B_FEATURES: Tuple[str, ...] = CANONICAL_URL_FEATURE_LIST[11:21]
CATEGORY_C_FEATURES: Tuple[str, ...] = CANONICAL_URL_FEATURE_LIST[21:30]
CATEGORY_D_FEATURES: Tuple[str, ...] = CANONICAL_URL_FEATURE_LIST[30:39]

# Approved Category Identifiers (4 categories matching Section 5 & Section 10 completeness domains)
URL_CATEGORY_IDENTIFIERS = Literal[
    "Category A",
    "Category B",
    "Category C",
    "Category D",
]

URL_CATEGORY_LIST: Tuple[str, ...] = get_args(URL_CATEGORY_IDENTIFIERS)

# Exact 1-to-1 mapping from canonical feature name to approved category identifier
FEATURE_TO_CATEGORY_MAP: dict[str, str] = {
    # Category A: URL Structural Properties (Features 1..11)
    "total_url_count": "Category A",
    "unique_url_count": "Category A",
    "has_urls": "Category A",
    "http_url_count": "Category A",
    "https_url_count": "Category A",
    "suspicious_scheme_count": "Category A",
    "has_suspicious_scheme": "Category A",
    "has_non_default_port": "Category A",
    "max_url_length": "Category A",
    "max_path_depth": "Category A",
    "has_executable_file_in_path": "Category A",
    # Category B: Hostname & Domain Composition (Features 12..21)
    "has_ip_literal_url": "Category B",
    "has_private_ip_url": "Category B",
    "has_loopback_ip_url": "Category B",
    "has_special_ip_url": "Category B",
    "has_punycode_url": "Category B",
    "max_subdomain_depth": "Category B",
    "has_excessive_subdomains": "Category B",
    "max_hostname_entropy": "Category B",
    "unique_domain_count": "Category B",
    "unique_fqdn_count": "Category B",
    # Category C: Obfuscation, Encodings & Deception (Features 22..30)
    "has_at_symbol_in_url": "Category C",
    "has_embedded_credentials": "Category C",
    "has_percent_encoding": "Category C",
    "has_double_percent_encoding": "Category C",
    "max_percent_encoded_count": "Category C",
    "has_brand_in_path": "Category C",
    "has_non_ascii_url": "Category C",
    "has_unusual_ip_format": "Category C",
    "malformed_url_count": "Category C",
    # Category D: Contextual Alignment & Behavioral Indicators (Features 31..39)
    "has_url_shortener": "Category D",
    "url_shortener_count": "Category D",
    "has_redirect_parameter": "Category D",
    "has_anchor_url_mismatch": "Category D",
    "anchor_url_mismatch_count": "Category D",
    "has_sender_domain_mismatch_url": "Category D",
    "sender_domain_matching_url_ratio": "Category D",
    "external_link_ratio": "Category D",
    "has_form_action_url": "Category D",
}

# Quarantined features (3 features)
QUARANTINED_URL_FEATURES: frozenset[str] = frozenset({
    "http_url_count",       # Feature 4 (Category A) - severe historical temporal confounding (2002 ham)
    "has_brand_in_path",    # Feature 27 (Category C) - requires curated brand registry prerequisites
    "has_form_action_url",  # Feature 39 (Category D) - unsupported by ingestion contract (URLSource conflation)
})

# Active predictive features (36 features)
ACTIVE_URL_FEATURES: frozenset[str] = frozenset(
    name for name in CANONICAL_URL_FEATURE_LIST if name not in QUARANTINED_URL_FEATURES
)


# ---------------------------------------------------------------------------
# 3. Sanitized Tier 3 Feature Vector (Section 5)
# ---------------------------------------------------------------------------

class UrlFeatures(BaseModel):
    """
    Approved, leakage-free feature representation for the URL Agent.
    Strictly forbids raw URLs, hostnames, query strings, anchor snippets, and corpus IDs.
    Total features: exactly 39 (36 active, 3 quarantined/inactive).
    Categorized into 4 approved partitions matching Section 5: A: 11, B: 10, C: 9, D: 9.
    """

    # Category A: URL Structural Properties (11 Features, 1..11, 1 Quarantined)
    total_url_count: int = Field(
        default=0,
        ge=0,
        description="len(email_data.extracted_urls). Total count of URL occurrences in email.",
    )
    unique_url_count: int = Field(
        default=0,
        ge=0,
        description="Count of distinct normalized URLs across the email.",
    )
    has_urls: bool = Field(
        default=False,
        description="bool(total_url_count > 0). Primary presence indicator.",
    )
    http_url_count: int = Field(
        default=0,
        ge=0,
        description="Count of URLs with scheme == 'http'. Quarantined from primary predictive model due to historical temporal confounding.",
    )
    https_url_count: int = Field(
        default=0,
        ge=0,
        description="Count of URLs with scheme == 'https'.",
    )
    suspicious_scheme_count: int = Field(
        default=0,
        ge=0,
        description="Count of URLs with scheme in ('javascript', 'data', 'file', 'vbscript', 'callto').",
    )
    has_suspicious_scheme: bool = Field(
        default=False,
        description="bool(suspicious_scheme_count > 0). True if any non-web protocol is used.",
    )
    has_non_default_port: bool = Field(
        default=False,
        description="True if any URL specifies an explicit port other than its scheme default (HTTP 80, HTTPS 443, FTP 21, SSH 22).",
    )
    max_url_length: int = Field(
        default=0,
        ge=0,
        description="Maximum len(original_url) across all URLs.",
    )
    max_path_depth: int = Field(
        default=0,
        ge=0,
        description="Maximum number of '/' segments in URL path (excluding leading slash).",
    )
    has_executable_file_in_path: bool = Field(
        default=False,
        description="True if URL path terminates with an executable extension (.exe, .scr, .bat, etc.).",
    )

    # Category B: Hostname & Domain Composition (10 Features, 12..21)
    has_ip_literal_url: bool = Field(
        default=False,
        description="True if any URL hostname parses as an IPv4 or IPv6 address literal.",
    )
    has_private_ip_url: bool = Field(
        default=False,
        description="True if any URL hostname is an RFC 1918 IPv4 or RFC 4193 IPv6 private address (including unwrapped IPv4-mapped IPv6).",
    )
    has_loopback_ip_url: bool = Field(
        default=False,
        description="True if any URL hostname is a loopback address (127.0.0.1, ::1, or mapped ::ffff:127.0.0.1).",
    )
    has_special_ip_url: bool = Field(
        default=False,
        description="True if any URL IP is classified as cgnat, documentation, multicast, or special_purpose.",
    )
    has_punycode_url: bool = Field(
        default=False,
        description="True if any URL hostname contains internationalized encoding (hostname-only inspection).",
    )
    max_subdomain_depth: int = Field(
        default=0,
        ge=0,
        description="Maximum number of dot-separated labels in hostname preceding the PSL registered domain.",
    )
    has_excessive_subdomains: bool = Field(
        default=False,
        description="Operational threshold flag: bool(max_subdomain_depth >= 3).",
    )
    max_hostname_entropy: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Maximum Shannon entropy of hostname string: -sum p_i log_2 p_i. None if no URLs.",
    )
    unique_domain_count: int = Field(
        default=0,
        ge=0,
        description="Count of distinct heterogeneous domain identities across all extracted URLs.",
    )
    unique_fqdn_count: int = Field(
        default=0,
        ge=0,
        description="Count of distinct fully qualified hostnames across all extracted URLs (IP literals excluded).",
    )

    # Category C: Obfuscation, Encodings & Deception (9 Features, 22..30, 1 Quarantined)
    has_at_symbol_in_url: bool = Field(
        default=False,
        description="True if authority segment contains '@' preceding the host.",
    )
    has_embedded_credentials: bool = Field(
        default=False,
        description="True if authority segment explicitly embeds user credentials (username:password@).",
    )
    has_percent_encoding: bool = Field(
        default=False,
        description="True if URL contains valid percent-encoded characters (%[0-9a-fA-F]{2}).",
    )
    has_double_percent_encoding: bool = Field(
        default=False,
        description="True if URL contains %25 followed by 2 hex digits (%25[0-9a-fA-F]{2}).",
    )
    max_percent_encoded_count: int = Field(
        default=0,
        ge=0,
        description="Maximum count of percent-encoded triplets (%xx) in a single URL.",
    )
    has_brand_in_path: Optional[bool] = Field(
        default=None,
        description="Quarantined feature; always None pending curated brand registry and matching rules.",
    )
    has_non_ascii_url: bool = Field(
        default=False,
        description="True if original_url contains characters outside ASCII range 32..126.",
    )
    has_unusual_ip_format: bool = Field(
        default=False,
        description="True if IP is encoded in integer, octal (0177.0.0.1), or hexadecimal (0x7f.1) notation.",
    )
    malformed_url_count: int = Field(
        default=0,
        ge=0,
        description="Count of URLs failing structural syntax validation across 5 failure conditions.",
    )

    # Category D: Contextual Alignment & Behavioral Indicators (9 Features, 31..39, 1 Quarantined)
    has_url_shortener: bool = Field(
        default=False,
        description="True if any URL domain matches an entry in the offline versioned shortener registry.",
    )
    url_shortener_count: int = Field(
        default=0,
        ge=0,
        description="Total count of URLs matching offline shortener registry.",
    )
    has_redirect_parameter: bool = Field(
        default=False,
        description="True if query string contains known redirect keys (url=, redirect=, dest=, etc.).",
    )
    has_anchor_url_mismatch: bool = Field(
        default=False,
        description="True if anchor text displays a URL/domain whose PSL domain mismatches href target PSL domain.",
    )
    anchor_url_mismatch_count: int = Field(
        default=0,
        ge=0,
        description="Count of HTML hyperlinks with deceptive anchor text.",
    )
    has_sender_domain_mismatch_url: Optional[bool] = Field(
        default=None,
        description="True if N_match < N_resolvable. False if N_match == N_resolvable > 0. None if no URLs, from_address unparseable/unresolvable, or N_resolvable = 0.",
    )
    sender_domain_matching_url_ratio: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="N_match / N_resolvable evaluated across all extracted URL occurrences. Range [0.0, 1.0]. None if no URLs or N_resolvable = 0.",
    )
    external_link_ratio: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Ratio of resolvable external non-sender URL occurrences to total resolvable URL occurrences: (N_resolvable - N_match) / N_resolvable. None if sender_domain_matching_url_ratio is None.",
    )
    has_form_action_url: Optional[bool] = Field(
        default=None,
        description="Quarantined feature; always None due to ingestion contract conflation.",
    )

    model_config = {"extra": "forbid"}

    # ------------------------------------------------------------------
    # Model-level validation for quarantined semantics & ratios
    # ------------------------------------------------------------------

    @model_validator(mode="after")
    def validate_quarantined_features(self) -> UrlFeatures:
        """Enforce exact quarantined feature semantics (Features 27 and 39 must be None)."""
        if self.has_brand_in_path is not None:
            raise ValueError(
                "has_brand_in_path is a quarantined feature and must be None. "
                f"Got: {self.has_brand_in_path!r}"
            )
        if self.has_form_action_url is not None:
            raise ValueError(
                "has_form_action_url is a quarantined feature and must be None. "
                f"Got: {self.has_form_action_url!r}"
            )
        return self

    @model_validator(mode="after")
    def validate_sender_ratios(self) -> UrlFeatures:
        """
        Validate mathematical consistency and mutual exclusion between
        has_sender_domain_mismatch_url, sender_domain_matching_url_ratio, and external_link_ratio.
        """
        mismatch_flag = self.has_sender_domain_mismatch_url
        ratio_match = self.sender_domain_matching_url_ratio
        ratio_ext = self.external_link_ratio

        # Case 1: When ratio_match is None, ratio_ext must also be None
        if ratio_match is None and ratio_ext is not None:
            raise ValueError("external_link_ratio must be None when sender_domain_matching_url_ratio is None.")
        if ratio_match is not None and ratio_ext is None:
            raise ValueError("external_link_ratio must not be None when sender_domain_matching_url_ratio is populated.")

        # Case 2: When ratios are populated, they must sum to 1.0 (within float epsilon 1e-4)
        if ratio_match is not None and ratio_ext is not None:
            sum_ratios = ratio_match + ratio_ext
            if abs(sum_ratios - 1.0) > 1e-4:
                raise ValueError(
                    f"sender_domain_matching_url_ratio ({ratio_match}) + external_link_ratio ({ratio_ext}) "
                    f"must sum to 1.0; got {sum_ratios:.6f}"
                )

        # Case 3: When sender prerequisite is unavailable (ratios are None), mismatch flag must be None
        if ratio_match is None and mismatch_flag is not None:
            raise ValueError(
                f"has_sender_domain_mismatch_url must be None when sender domain matching ratio is None (got {mismatch_flag!r})."
            )

        # Case 4: When mismatch flag is False (all match), ratio_match must be 1.0
        if mismatch_flag is False:
            if ratio_match is not None and abs(ratio_match - 1.0) > 1e-4:
                raise ValueError(
                    f"has_sender_domain_mismatch_url is False but sender_domain_matching_url_ratio is {ratio_match} (must be 1.0)."
                )

        # Case 5: When mismatch flag is True (at least one mismatch), ratio_match cannot be 1.0
        if mismatch_flag is True:
            if ratio_match is not None and abs(ratio_match - 1.0) < 1e-4:
                raise ValueError(
                    "has_sender_domain_mismatch_url is True but sender_domain_matching_url_ratio is 1.0 "
                    "(mismatch cannot coexist with a 100% matching ratio)."
                )

        return self


# ---------------------------------------------------------------------------
# 4. Feature Availability / Missingness Manifest (Section 10.1)
# ---------------------------------------------------------------------------

class UrlFeatureAvailability(BaseModel):
    """
    Explicit missingness manifest tracking availability across all conditionally
    evaluable URL features and prerequisite inputs. Downstream models consume these
    flags to differentiate between observed negative evidence and missing evidence.
    """
    avail_has_urls: bool = Field(
        default=False,
        description="True if email contains >= 1 extracted URL.",
    )
    avail_structure_features: bool = Field(
        default=False,
        description="True if URLs exist and structure was parsed.",
    )
    avail_hostname_features: bool = Field(
        default=False,
        description="True if URLs have non-empty hostnames.",
    )
    avail_entropy_features: bool = Field(
        default=False,
        description="True if hostnames are present to compute entropy.",
    )
    avail_sender_alignment: bool = Field(
        default=False,
        description="True if both URLs and From header domain exist and are resolvable.",
    )
    avail_anchor_text_analysis: bool = Field(
        default=False,
        description="True if >= 1 HTML link with anchor text exists.",
    )

    # Descriptive Domain Completeness Summaries [0.0, 1.0] (Section 10.2)
    completeness_structure: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Completeness across Category A structural features [0.0, 1.0].",
    )
    completeness_hostname: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Completeness across Category B hostname features [0.0, 1.0].",
    )
    completeness_obfuscation: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Completeness across Category C obfuscation features [0.0, 1.0].",
    )
    completeness_context: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Completeness across Category D contextual features [0.0, 1.0].",
    )
    completeness_total: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Overall descriptive evidence completeness E_comp_url [0.0, 1.0].",
    )

    model_config = {"extra": "forbid"}

    @model_validator(mode="before")
    @classmethod
    def populate_default_completeness_if_unspecified(cls, data: Any) -> Any:
        """
        When completeness values are not explicitly supplied, automatically populate them
        according to the Section 10.2 specifications:
        - If avail_has_urls is False: all completeness values are 0.0.
        - If avail_has_urls is True:
            - C_struct = 1.0 (always fully evaluable when URLs exist)
            - C_host = 1.0 if avail_hostname_features else 0.5
            - C_obfus = 1.0 (fully evaluable offline)
            - C_context = 0.5 * (int(avail_sender_alignment) + int(avail_anchor_text_analysis))
            - E_comp_url = 0.25 * (C_struct + C_host + C_obfus + C_context)
        If any completeness value was explicitly supplied by the caller, it is preserved
        so that subsequent validation can enforce consistency and catch discrepancies.
        """
        if isinstance(data, dict):
            completeness_keys = (
                "completeness_structure",
                "completeness_hostname",
                "completeness_obfuscation",
                "completeness_context",
                "completeness_total",
            )
            if not any(k in data for k in completeness_keys):
                has_urls = bool(data.get("avail_has_urls", False))
                if not has_urls:
                    data["completeness_structure"] = 0.0
                    data["completeness_hostname"] = 0.0
                    data["completeness_obfuscation"] = 0.0
                    data["completeness_context"] = 0.0
                    data["completeness_total"] = 0.0
                else:
                    c_struct = 1.0
                    c_host = 1.0 if bool(data.get("avail_hostname_features", False)) else 0.5
                    c_obfus = 1.0
                    c_context = 0.5 * (
                        float(bool(data.get("avail_sender_alignment", False)))
                        + float(bool(data.get("avail_anchor_text_analysis", False)))
                    )
                    c_total = 0.25 * (c_struct + c_host + c_obfus + c_context)
                    data["completeness_structure"] = c_struct
                    data["completeness_hostname"] = c_host
                    data["completeness_obfuscation"] = c_obfus
                    data["completeness_context"] = c_context
                    data["completeness_total"] = c_total
        return data

    @model_validator(mode="after")
    def validate_completeness_consistency(self) -> UrlFeatureAvailability:
        """
        Validate completeness consistency strictly against Section 10.2 of docs/url_agent_design.md:
        - When avail_has_urls is False: completeness_total and all domain values must be 0.0.
        - When avail_has_urls is True:
            - completeness_structure must be 1.0 (always fully evaluable when URLs exist).
            - completeness_hostname must be 1.0 if all hostnames are valid (avail_hostname_features=True), else 0.5.
            - completeness_obfuscation must be 1.0 (fully evaluable offline).
            - completeness_context must equal 0.5 * (I(avail_sender_alignment) + I(avail_anchor_text_analysis)).
            - completeness_total must equal the arithmetic mean:
                (completeness_structure + completeness_hostname + completeness_obfuscation + completeness_context) / 4.0
              within floating-point tolerance 1e-4.
        """
        tol = 1e-4
        if not self.avail_has_urls:
            # Section 10.2 no-URL rule: E_comp_url = 0.0 if total_url_count == 0
            if abs(self.completeness_total) > tol:
                raise ValueError(
                    f"When avail_has_urls is False, completeness_total must be 0.0 (Section 10.2), got {self.completeness_total}"
                )
            if (
                abs(self.completeness_structure) > tol
                or abs(self.completeness_hostname) > tol
                or abs(self.completeness_obfuscation) > tol
                or abs(self.completeness_context) > tol
            ):
                raise ValueError(
                    f"When avail_has_urls is False, all domain completeness values must be 0.0 (Section 10.2), got "
                    f"structure={self.completeness_structure}, hostname={self.completeness_hostname}, "
                    f"obfuscation={self.completeness_obfuscation}, context={self.completeness_context}"
                )
            return self

        # When avail_has_urls is True:
        # Component 1: C_struct = 1.0 (always fully evaluable when URLs exist)
        if abs(self.completeness_structure - 1.0) > tol:
            raise ValueError(
                f"When URLs exist (avail_has_urls=True), completeness_structure must be 1.0 (Section 10.2), got {self.completeness_structure}"
            )

        # Component 2: C_host = 1.0 if all URLs possess valid hostnames, else 0.5
        expected_host = 1.0 if self.avail_hostname_features else 0.5
        if abs(self.completeness_hostname - expected_host) > tol:
            raise ValueError(
                f"completeness_hostname ({self.completeness_hostname}) must match Section 10.2 definition: "
                f"1.0 if avail_hostname_features is True, else 0.5 (expected {expected_host})"
            )

        # Component 3: C_obfus = 1.0 (fully evaluable offline)
        if abs(self.completeness_obfuscation - 1.0) > tol:
            raise ValueError(
                f"When URLs exist (avail_has_urls=True), completeness_obfuscation must be 1.0 (Section 10.2), got {self.completeness_obfuscation}"
            )

        # Component 4: C_context = 0.5 * (I(avail_sender_alignment) + I(avail_anchor_text_analysis))
        expected_context = 0.5 * (
            float(self.avail_sender_alignment) + float(self.avail_anchor_text_analysis)
        )
        if abs(self.completeness_context - expected_context) > tol:
            raise ValueError(
                f"completeness_context ({self.completeness_context}) must match Section 10.2 definition: "
                f"0.5 * (I(avail_sender_alignment) + I(avail_anchor_text_analysis)) = {expected_context}"
            )

        # Overall total completeness: Arithmetic mean of 4 domain components
        expected_total = (
            self.completeness_structure
            + self.completeness_hostname
            + self.completeness_obfuscation
            + self.completeness_context
        ) / 4.0
        if abs(self.completeness_total - expected_total) > tol:
            raise ValueError(
                f"completeness_total ({self.completeness_total}) must equal arithmetic mean of the four domain "
                f"completeness values ({expected_total:.4f}) within tolerance {tol} (Section 10.2)"
            )

        return self

    def is_feature_available(self, feature_name: CANONICAL_URL_FEATURE_NAMES) -> bool:
        """
        Query the operational availability of any canonical feature name based on manifest state
        and Section 5 missingness rules.

        Distinguishes:
        1. Quarantined features (has_brand_in_path, has_form_action_url): permanently unavailable (False).
        2. Features that evaluate to None when required evidence is missing:
           - max_hostname_entropy: requires URLs and hostnames (avail_has_urls and avail_entropy_features).
           - has_sender_domain_mismatch_url, sender_domain_matching_url_ratio, external_link_ratio:
             require URLs and sender alignment preconditions (avail_has_urls and avail_sender_alignment).
        3. All other 33 features: Always evaluable according to Section 5.
           When evidence is negative or absent (e.g. no URLs, no hostnames, no HTML anchors),
           they evaluate to observed zero (0) or negative (False) values. They are available (True).
        """
        # 1. Quarantined features that are permanently deactivated in Layer 1
        if feature_name in ("has_brand_in_path", "has_form_action_url"):
            return False

        # 2. When no URLs are present in the email:
        if not self.avail_has_urls:
            # Features whose missingness rule in Section 5 specifies None when no URLs exist:
            if feature_name in (
                "max_hostname_entropy",
                "has_sender_domain_mismatch_url",
                "sender_domain_matching_url_ratio",
                "external_link_ratio",
            ):
                return False
            # All other 33 features evaluate to observed 0 or False (available):
            return True

        # 3. Features dependent on sender domain alignment preconditions (evaluate to None if unmet)
        if feature_name in (
            "has_sender_domain_mismatch_url",
            "sender_domain_matching_url_ratio",
            "external_link_ratio",
        ):
            return self.avail_sender_alignment

        # 4. Hostname entropy feature (evaluates to None if hostnames are missing)
        if feature_name == "max_hostname_entropy":
            return self.avail_entropy_features

        # 5. All other 33 features are always evaluable per Section 5 (evaluating to observed int or bool)
        return True


# ---------------------------------------------------------------------------
# 5. Tier 2 Forensic Evidence Containers (Section 7)
# ---------------------------------------------------------------------------

class UrlEvidenceItem(BaseModel):
    """
    Forensic trace linking an observed URL anomaly or characteristic
    to its specific source URL in EmailData.extracted_urls.
    """
    finding_id: str = Field(
        description="Unique finding identifier (e.g. 'url_ev_001').",
    )
    feature_name: CANONICAL_URL_FEATURE_NAMES = Field(
        description="The canonical 39-feature identifier supported by this evidence trace.",
    )
    category: URL_CATEGORY_IDENTIFIERS = Field(
        description="Approved category identifier: 'Category A', 'Category B', 'Category C', or 'Category D'.",
    )
    url_index: int = Field(
        ge=0,
        description="0-indexed position within EmailData.extracted_urls.",
    )
    source: URLSource = Field(
        description="Extraction source location (HTML_HREF, PLAIN_TEXT, etc.).",
    )
    observed_value: str = Field(
        max_length=256,
        description="Specific anomalous value observed (e.g. '192.168.1.1', 'xn--e1afmkfd', ':8080').",
    )
    description: str = Field(
        max_length=500,
        description="Human-readable explanation of why this observation matters.",
    )
    limitations_and_benign_explanations: str = Field(
        max_length=500,
        description="Plausible benign reasons for this pattern (e.g. internal intranet server, tracking link).",
    )
    raw_snippet_bounded: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Sanitized verbatim URL or anchor excerpt (max 256 chars, control characters escaped).",
    )
    verification_status: VerificationStatus = Field(
        default=VerificationStatus.UNVERIFIED,
        description="Trust verification state (always UNVERIFIED in passive offline analysis).",
    )

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def validate_feature_category_match(self) -> UrlEvidenceItem:
        """Ensure the evidence item category strictly matches the canonical feature category."""
        expected = FEATURE_TO_CATEGORY_MAP.get(self.feature_name)
        if expected is not None and self.category != expected:
            raise ValueError(
                f"Feature {self.feature_name!r} belongs to {expected!r}, got category {self.category!r}"
            )
        return self


class UrlEvidence(BaseModel):
    """
    Container for audit evidence and forensic traces supporting URL feature values.
    
    CAP ENFORCEMENT & SAFETY NOTE:
    Pydantic `max_length` validation strictly rejects oversized lists by raising a ValidationError;
    it does NOT silently truncate input lists.
    Phase B (extraction & analysis pipeline) is strictly responsible for applying capacity caps
    (e.g. slicing evidence_items to [:100], detected_anomalous_hostnames to [:50], etc.) BEFORE
    constructing this Pydantic model. Omitted items must be recorded in `omitted_evidence_count`.
    Aggregate feature calculations must ALWAYS account for all extracted URLs and are NEVER
    truncated by forensic evidence caps.
    """
    evidence_items: list[UrlEvidenceItem] = Field(
        default_factory=list,
        max_length=100,
        description="Traceable forensic evidence items (validated to max 100). Phase B must cap to [:100].",
    )
    omitted_evidence_count: int = Field(
        default=0,
        ge=0,
        description="Number of evidence items omitted due to the 100-item safety cap.",
    )
    detected_anomalous_hostnames: list[str] = Field(
        default_factory=list,
        max_length=50,
        description="Bounded list of anomalous hostnames (IP literals, Punycode, malformed) found across URLs (max 50). Phase B must cap to [:50].",
    )
    detected_shorteners: list[str] = Field(
        default_factory=list,
        max_length=50,
        description="Distinct shortener domains detected (max 50). Phase B must cap to [:50].",
    )
    observed_anomalies: list[str] = Field(
        default_factory=list,
        max_length=100,
        description="High-level human-readable anomaly summary descriptions (max 100). Phase B must cap to [:100].",
    )

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# 6. Per-URL Detailed Inspection Record (Section 7.1)
# ---------------------------------------------------------------------------

class UrlAnalysisItem(BaseModel):
    """
    Granular static inspection record for a single extracted URL.
    Maintained in a bounded list (max 200) to support transparency and UI drill-downs.
    """
    url_index: int = Field(
        ge=0,
        description="0-indexed position within EmailData.extracted_urls.",
    )
    original_url_snippet: str = Field(
        max_length=256,
        description="Sanitized excerpt of the original raw URL string (max 256 chars).",
    )
    source: URLSource = Field(
        description="Extraction source (HTML_HREF, PLAIN_TEXT, HTML_SRC, etc.).",
    )
    anchor_text_snippet: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Sanitized snippet of visible anchor text if available (max 128 chars).",
    )
    scheme: Optional[str] = Field(
        default=None,
        description="Extracted lowercase URL scheme (e.g. 'http', 'https', 'javascript').",
    )
    hostname: Optional[str] = Field(
        default=None,
        description="Extracted and normalized hostname or IP address literal.",
    )
    registered_domain: Optional[str] = Field(
        default=None,
        description="PSL registered domain if resolvable.",
    )
    domain_resolution_status: DomainResolutionStatus = Field(
        description="Explicit PSL domain resolution outcome (strictly required; one of the 7 approved DomainResolutionStatus enum values).",
    )
    port: Optional[int] = Field(
        default=None,
        ge=1,
        le=65535,
        description="Explicit port number if valid (1..65535); None if omitted or default.",
    )
    path: Optional[str] = Field(
        default=None,
        description="URL path component.",
    )
    has_ip_hostname: bool = Field(
        default=False,
        description="True if hostname parses as an IPv4 or IPv6 address literal.",
    )
    ip_classification: Optional[IPClassificationCategory] = Field(
        default=None,
        description="Approved RFC IP category ('rfc1918', 'rfc4193', 'syntactically_global', 'loopback', 'link_local', 'cgnat', 'documentation', 'special_purpose'). None if hostname is not an IP literal.",
    )
    is_punycode: bool = Field(
        default=False,
        description="True if hostname contains Punycode/IDNA encoding.",
    )
    is_url_shortener: bool = Field(
        default=False,
        description="True if hostname matches an entry in the offline shortener registry.",
    )
    has_redirect_parameter: bool = Field(
        default=False,
        description="True if query contains redirect parameter keys (url=, redirect=, etc.).",
    )
    has_anchor_mismatch: bool = Field(
        default=False,
        description="True if anchor text domain conflicts with href target domain.",
    )
    hostname_entropy: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Shannon entropy of hostname string.",
    )
    url_length: int = Field(
        default=0,
        ge=0,
        description="Length of original raw URL string.",
    )
    is_malformed: bool = Field(
        default=False,
        description="True if this URL failed structural syntax validation across 5 failure conditions.",
    )
    malformed_reasons: list[str] = Field(
        default_factory=list,
        description="Descriptions of any syntax validation failures encountered.",
    )

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# 7. Top-Level Agent Contract (Section 7.2)
# ---------------------------------------------------------------------------

class UrlAgentResult(BaseModel):
    """
    Complete output payload of the URL Agent.
    Serialized and passed to the Evidence Aggregation Layer.
    Emits strictly measurements and identity alignment indicators; zero risk scores or verdicts.
    """
    email_id: str = Field(
        description="Unique email identifier matching EmailData.email_id.",
    )
    agent_name: str = Field(
        default="url_agent",
        description="Identifier of the emitting agent.",
    )
    agent_version: str = Field(
        default="0.1.0",
        description="Semantic version of agent specification.",
    )
    status: str = Field(
        default="success",
        description="Execution outcome: 'success', 'partial', or 'error'.",
    )
    processing_time_ms: float = Field(
        ge=0.0,
        default=0.0,
        description="Elapsed processing time in milliseconds.",
    )
    total_urls_extracted: int = Field(
        default=0,
        ge=0,
        description="Count of URLs analyzed from email_data.extracted_urls.",
    )
    features: UrlFeatures = Field(
        description="Sanitized Tier 3 feature vector (canonical 39 features).",
    )
    availability: UrlFeatureAvailability = Field(
        description="Per-feature missingness manifest.",
    )
    evidence: UrlEvidence = Field(
        description="Tier 2 forensic evidence and audit trails.",
    )
    analysis_items: list[UrlAnalysisItem] = Field(
        default_factory=list,
        max_length=200,
        description=(
            "Per-URL granular inspection records (validated to max 200 for digest safety). "
            "Pydantic rejects inputs > 200 with ValidationError; it does NOT truncate. "
            "Phase B must cap inspection records to [:200] before constructing this model. "
            "Aggregate feature calculations must always cover all extracted URLs without truncation."
        ),
        validation_alias=AliasChoices("analysis_items", "per_url_analyses"),
        serialization_alias="analysis_items",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal data quality warnings (e.g. URL count capped notice).",
    )
    limitations: list[str] = Field(
        default_factory=list,
        description="Explicit operational caveats (e.g. offline analysis limitations).",
    )

    model_config = {
        "extra": "forbid",
        "populate_by_name": True,
    }

    # ------------------------------------------------------------------
    # Field-level validators
    # ------------------------------------------------------------------

    @field_validator("email_id")
    @classmethod
    def email_id_not_empty(cls, value: str) -> str:
        """Email ID must be a non-empty string."""
        if not value.strip():
            raise ValueError("email_id must not be empty or whitespace.")
        return value

    @field_validator("status")
    @classmethod
    def status_valid(cls, value: str) -> str:
        """Status must be 'success', 'partial', or 'error'."""
        allowed = {"success", "partial", "error"}
        if value not in allowed:
            raise ValueError(f"status must be one of {allowed}, got {value!r}")
        return value

    @property
    def per_url_analyses(self) -> list[UrlAnalysisItem]:
        """Backward-compatibility alias property returning analysis_items."""
        return self.analysis_items


# Architectural alias matching Header Agent conventions
UrlAgentOutput = UrlAgentResult
