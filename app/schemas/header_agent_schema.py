"""
header_agent_schema.py
----------------------
Pydantic v2 data contract for Header Agent outputs.

Architecture:
- CANONICAL_HEADER_FEATURE_NAMES: Machine-auditable 45-feature literal type.
- CANONICAL_HEADER_FEATURE_LIST: Ordered tuple of all 45 canonical feature names.
- HeaderFeatures: Sanitized Tier 3 feature vector (canonical 45 features).
- HeaderFeatureAvailability: Comprehensive per-feature availability manifest.
- HeaderEvidenceItem: Traceable forensic evidence link for an observed feature or anomaly.
- HeaderEvidence: Tier 2 forensic evidence and audit trails (strictly quarantined from ML).
- HeaderRiskAssessment: Optional layer for calibrated base classifier predictions.
- HeaderAgentResult: Complete serializable agent output container (aliased as HeaderAgentOutput).
"""

from __future__ import annotations

from typing import Literal, Optional, Tuple, get_args
from pydantic import BaseModel, Field, model_validator
from app.schemas.email_schema import AuthStatus, VerificationStatus


# Canonical 45-feature registry literal type (strictly continuous 1..45)
CANONICAL_HEADER_FEATURE_NAMES = Literal[
    # Category A: Sender/Recipient Alignment (13)
    "from_present",
    "from_address_count",
    "reply_to_present",
    "return_path_present",
    "from_reply_to_domain_mismatch",
    "from_return_path_domain_mismatch",
    "display_name_contains_email",
    "display_name_domain_mismatch",
    "recipient_count_to",
    "recipient_count_cc",
    "undisclosed_recipients",
    "to_empty_or_missing",
    "from_syntax_valid",
    # Category B: Routing and Transport Structure (10)
    "received_hop_count",
    "has_private_ip_in_external_hop",
    "has_loopback_ip_in_external_hop",
    "has_link_local_ip_in_external_hop",
    "has_special_ip_in_external_hop",
    "received_syntax_malformed_count",
    "missing_received_headers",
    "transit_delay_seconds",
    "transit_delay_unavailable",
    "hop_count_anomaly",
    # Category C: Authentication Claims (13)
    "spf_status",
    "dkim_status",
    "dmarc_status",
    "spf_claim_count",
    "dkim_claim_count",
    "dmarc_claim_count",
    "has_conflicting_spf",
    "has_conflicting_dkim",
    "has_conflicting_dmarc",
    "dkim_signature_header_present",
    "dkim_signature_present_without_pass",
    "authserv_id_count",
    "authserv_id_inconsistent",
    # Category D: RFC 5322 Metadata & Structural Compliance (9)
    "message_id_present",
    "message_id_valid_syntax",
    "message_id_domain_mismatch",
    "mime_version_present",
    "mime_version_valid",
    "has_subject_header",
    "subject_length",
    "content_type_present",
    "content_type_is_multipart",
]

CANONICAL_HEADER_FEATURE_LIST: Tuple[str, ...] = get_args(CANONICAL_HEADER_FEATURE_NAMES)


# ---------------------------------------------------------------------------
# 1. Feature Availability / Missingness Manifest
# ---------------------------------------------------------------------------

class HeaderFeatureAvailability(BaseModel):
    """
    Explicit missingness manifest tracking availability across all conditionally
    evaluable features and prerequisite inputs. Downstream models consume these
    flags to prevent confounding missing evidence with negative evidence.
    """
    # Normalized Value Presence Flags
    avail_from_present: bool = Field(description="True if normalized From address value is present.")
    avail_reply_to_present: bool = Field(description="True if normalized Reply-To address value is present.")
    avail_return_path_present: bool = Field(description="True if normalized Return-Path address value is present.")
    avail_to_present: bool = Field(description="True if To recipient list is evaluable (False under current contract if empty).")
    avail_cc_present: bool = Field(description="True if CC recipient list is evaluable (False under current contract if empty).")
    avail_received_hops: bool = Field(description="True if >= 1 Received header is present.")
    avail_auth_claims: bool = Field(description="True if >= 1 authentication claim is extracted.")
    avail_message_id_present: bool = Field(description="True if Message-ID header is present and non-empty.")
    avail_mime_version_present: bool = Field(description="True if MIME-Version header physically exists.")
    avail_subject_present: bool = Field(description="True if Subject header physically exists.")
    avail_content_type_present: bool = Field(description="True if Content-Type header physically exists.")

    # Parsing Success and Syntax Flags
    avail_from_parsed: bool = Field(description="True if From header was successfully parsed into address structure.")
    avail_from_syntax: bool = Field(description="True if From header content was evaluable for RFC 5322 syntax.")
    avail_reply_to_parsed: bool = Field(description="True if Reply-To was successfully parsed.")
    avail_return_path_parsed: bool = Field(description="True if Return-Path was successfully parsed.")
    avail_to_parsed: bool = Field(description="True if To was successfully parsed/evaluated.")
    avail_cc_parsed: bool = Field(description="True if CC was successfully parsed/evaluated.")

    # Conditionally Evaluable Feature Availability
    avail_from_reply_to_domain_mismatch: bool = Field(
        description="True if both From and Reply-To domains available for comparison.",
    )
    avail_from_return_path_domain_mismatch: bool = Field(
        description="True if both From and Return-Path domains available for comparison.",
    )
    avail_display_name_domain_mismatch: bool = Field(
        description="True if display name embeds an email address available for domain comparison.",
    )
    avail_undisclosed_recipients: bool = Field(
        default=False,
        description="True ONLY if raw To header input is available (False under current contract; quarantined).",
    )
    avail_to_empty_or_missing: bool = Field(
        default=False,
        description="True ONLY if raw To header input is available (False under current contract; quarantined).",
    )
    avail_transit_delay: bool = Field(
        default=False,
        description="True if >= 2 Received headers have valid RFC 2822 timestamps (quarantined).",
    )
    avail_spf_status: bool = Field(
        description="True if SPF claim was evaluated (status not in MISSING, UNAVAILABLE).",
    )
    avail_dkim_status: bool = Field(
        description="True if DKIM claim was evaluated (status not in MISSING, UNAVAILABLE).",
    )
    avail_dmarc_status: bool = Field(
        description="True if DMARC claim was evaluated (status not in MISSING, UNAVAILABLE).",
    )
    avail_message_id_valid_syntax: bool = Field(
        description="True if Message-ID is present and evaluable for RFC syntax.",
    )
    avail_message_id_domain_mismatch: bool = Field(
        description="True if both Message-ID and From domains available for comparison.",
    )
    avail_mime_version_valid: bool = Field(
        description="True if MIME-Version header is present and evaluable.",
    )
    avail_content_type_is_multipart: bool = Field(
        description="True if Content-Type header is present and evaluable for multipart.",
    )

    # Descriptive Domain Completeness Summaries [0.0, 1.0] (Descriptive conventions only)
    completeness_identity: float = Field(ge=0.0, le=1.0)
    completeness_routing: float = Field(ge=0.0, le=1.0)
    completeness_auth: float = Field(ge=0.0, le=1.0)
    completeness_metadata: float = Field(ge=0.0, le=1.0)
    completeness_total: float = Field(ge=0.0, le=1.0)

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# 2. Tier 3: Sanitized Predictive Features (Canonical 45 Features)
# ---------------------------------------------------------------------------

class HeaderFeatures(BaseModel):
    """
    Approved, leakage-free feature representation for the Header Agent.
    Strictly forbids raw text, scanner tags, absolute dates, hostnames, and corpus IDs.
    Total features: exactly 45 (41 active predictive, 4 quarantined/inactive).
    """

    # Category A: Sender, Recipient, and Identity Alignment (13 Features)
    from_present: bool = Field(
        description="True if normalized From address is present and non-empty (headers.from_address is not None).",
    )
    from_address_count: Optional[int] = Field(
        default=None,
        ge=0,
        description="Count of mailbox addresses in From; None if absent or unparseable under current contract; 0 if empty.",
    )
    reply_to_present: bool = Field(
        description="True if normalized Reply-To is present and non-empty (headers.reply_to is not None).",
    )
    return_path_present: bool = Field(
        description="True if normalized Return-Path is present and non-empty (headers.return_path is not None).",
    )
    from_reply_to_domain_mismatch: Optional[bool] = Field(
        default=None,
        description="True if From and Reply-To domains differ; None if either absent or unparseable.",
    )
    from_return_path_domain_mismatch: Optional[bool] = Field(
        default=None,
        description="True if From and Return-Path domains differ; None if either absent or unparseable.",
    )
    display_name_contains_email: bool = Field(
        description="True if From display name embeds an RFC 5322 email address string.",
    )
    display_name_domain_mismatch: Optional[bool] = Field(
        default=None,
        description="True if display name embedded domain differs from actual From domain; None if unparseable.",
    )
    recipient_count_to: Optional[int] = Field(
        default=None,
        ge=0,
        description="Address count in To; None if headers.to == [] under current contract; N if parsed >= 1.",
    )
    recipient_count_cc: Optional[int] = Field(
        default=None,
        ge=0,
        description="Address count in CC; None if headers.cc == [] under current contract; N if parsed >= 1.",
    )
    undisclosed_recipients: Optional[bool] = Field(
        default=None,
        description="True if To explicitly contains group syntax tokens; None if raw To is unavailable. Inactive / Quarantined.",
    )
    to_empty_or_missing: Optional[bool] = Field(
        default=None,
        description="True if To physically empty; None if raw To is unavailable. Inactive / Quarantined.",
    )
    from_syntax_valid: Optional[bool] = Field(
        default=None,
        description="True if From conforms to RFC 5322 addr-spec; False if invalid; None if absent.",
    )

    # Category B: Routing and Transport Structure (10 Features)
    received_hop_count: int = Field(ge=0, description="Total count of Received header hops.")
    has_private_ip_in_external_hop: bool = Field(
        description="True if RFC 1918 IPv4 or RFC 4193 IPv6 detected in intermediate transit hops.",
    )
    has_loopback_ip_in_external_hop: bool = Field(
        description="True if loopback IP detected in intermediate transit hops.",
    )
    has_link_local_ip_in_external_hop: bool = Field(
        description="True if link-local IP detected in intermediate transit hops.",
    )
    has_special_ip_in_external_hop: bool = Field(
        description="True if CGNAT, documentation, multicast, or reserved IP detected in intermediate hops.",
    )
    received_syntax_malformed_count: int = Field(
        ge=0,
        description="Count of Received headers failing RFC structural token parsing.",
    )
    missing_received_headers: bool = Field(
        description="True if Received header hop count is zero.",
    )
    transit_delay_seconds: Optional[float] = Field(
        default=None,
        description="Relative seconds elapsed between earliest and latest hop (max 30 days). Exploratory / Quarantined.",
    )
    transit_delay_unavailable: bool = Field(
        description="True if transit delay could not be reliably calculated. Exploratory / Quarantined.",
    )
    hop_count_anomaly: bool = Field(
        description="True if hop count is 0 or exceeds 15 hops.",
    )

    # Category C: Authentication Claims (13 Features)
    spf_status: AuthStatus = Field(description="Consolidated receiver-reported SPF claim status.")
    dkim_status: AuthStatus = Field(description="Consolidated receiver-reported DKIM claim status.")
    dmarc_status: AuthStatus = Field(description="Consolidated receiver-reported DMARC claim status.")
    spf_claim_count: int = Field(ge=0, description="Number of reported SPF claims extracted.")
    dkim_claim_count: int = Field(ge=0, description="Number of reported DKIM claims extracted.")
    dmarc_claim_count: int = Field(ge=0, description="Number of reported DMARC claims extracted.")
    has_conflicting_spf: bool = Field(description="True if multiple SPF claims disagree.")
    has_conflicting_dkim: bool = Field(description="True if multiple DKIM claims disagree.")
    has_conflicting_dmarc: bool = Field(description="True if multiple DMARC claims disagree.")
    dkim_signature_header_present: bool = Field(
        description="True if DKIM-Signature header exists in message.",
    )
    dkim_signature_present_without_pass: bool = Field(
        description="True if DKIM-Signature exists but reported status is not pass.",
    )
    authserv_id_count: int = Field(ge=0, description="Distinct reporting authserv-ids found.")
    authserv_id_inconsistent: bool = Field(
        description="True if multiple Authentication-Results report conflicting authserv-ids.",
    )

    # Category D: RFC 5322 Metadata & Structural Compliance (9 Features)
    message_id_present: bool = Field(description="True if Message-ID header is present and non-empty.")
    message_id_valid_syntax: Optional[bool] = Field(
        default=None,
        description="True if Message-ID conforms to <id-left@id-right>; None if absent or empty.",
    )
    message_id_domain_mismatch: Optional[bool] = Field(
        default=None,
        description="True if Message-ID domain differs from From domain; None if absent or unparseable.",
    )
    mime_version_present: bool = Field(description="True if MIME-Version header is present.")
    mime_version_valid: Optional[bool] = Field(
        default=None,
        description="True if MIME-Version equals '1.0'; None if absent.",
    )
    has_subject_header: bool = Field(description="True if Subject header is present.")
    subject_length: int = Field(ge=0, description="Character length of decoded Subject header.")
    content_type_present: bool = Field(description="True if Content-Type header is present.")
    content_type_is_multipart: Optional[bool] = Field(
        default=None,
        description="True if Content-Type starts with 'multipart/'; None if absent.",
    )

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# 3. Tier 2: Forensic Evidence & Audit Trails (Quarantined from ML)
# ---------------------------------------------------------------------------

class HeaderEvidenceItem(BaseModel):
    """
    Forensic evidence trace linking an observed anomaly or feature value
    to its raw header origin for auditability and explanation.
    """
    feature_name: CANONICAL_HEADER_FEATURE_NAMES = Field(
        description="The canonical 45-feature identifier this evidence supports.",
    )
    header_name: str = Field(
        description="RFC 5322 header name (e.g. 'From', 'Reply-To', 'Received', 'Authentication-Results').",
    )
    header_index: Optional[int] = Field(
        default=None,
        ge=0,
        description="0-indexed position within repeated headers of the same type; 0 for single headers; None if absent.",
    )
    claim_index: Optional[int] = Field(
        default=None,
        ge=0,
        description="0-indexed position of the claim in AuthenticationMetadata.claims; None if not auth evidence.",
    )
    verification_status: VerificationStatus = Field(
        default=VerificationStatus.UNVERIFIED,
        description="Receiver trust verification status (always UNVERIFIED in offline analysis).",
    )
    description: str = Field(
        max_length=500,
        description="Safe, bounded human-readable explanation of the observed evidence.",
    )
    raw_snippet_bounded: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Preprocessed, sanitized verbatim excerpt (max 256 chars, control characters escaped). Display only; not verified evidence.",
    )

    model_config = {"extra": "forbid"}


class HeaderEvidence(BaseModel):
    """Container for audit evidence and forensic traces supporting feature values."""
    evidence_items: list[HeaderEvidenceItem] = Field(
        default_factory=list,
        max_length=100,
        description="Traceable evidence items (validated to max 100).",
    )
    parsed_authserv_ids: list[str] = Field(
        default_factory=list,
        max_length=50,
        description="Distinct authserv-ids found across Authentication-Results (validated to max 50).",
    )
    detected_anomalous_ips: list[str] = Field(
        default_factory=list,
        max_length=50,
        description="Bounded list of anomalous IPs found in transit hops (validated to max 50).",
    )
    observed_anomalies: list[str] = Field(
        default_factory=list,
        max_length=100,
        description="Human-readable anomaly descriptions (validated to max 100).",
    )

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# 4. Optional Agent Risk & Uncertainty Assessment (Populated by Base Classifier)
# ---------------------------------------------------------------------------

class HeaderRiskAssessment(BaseModel):
    """
    Quantified belief, margin, and uncertainty emitted ONLY when a trained
    Header Base Classifier is attached (Layer 2). None during Layer 1 feature extraction.
    """
    calibrated_phishing_probability: float = Field(
        ge=0.0,
        le=1.0,
        description="Calibrated header-based phishing probability p_h in [0.0, 1.0].",
    )
    decision_margin: float = Field(
        ge=0.0,
        le=1.0,
        description="Distance-from-boundary certainty proxy: 2 * abs(p_h - 0.5).",
    )
    calibrated_confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Empirical prediction confidence derived from validation calibration bins. None until operational definition exists.",
    )
    epistemic_uncertainty: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Model uncertainty estimated via ensemble or bootstrap fold variance.",
    )
    aleatoric_uncertainty: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Data ambiguity arising from conflicting claims or missing headers.",
    )
    abstain: bool = Field(
        default=False,
        description="True if validation-tuned abstention policy triggers.",
    )

    @model_validator(mode="after")
    def validate_decision_margin_formula(self) -> "HeaderRiskAssessment":
        """Validate mathematical consistency between probability and decision margin."""
        expected_margin = 2.0 * abs(self.calibrated_phishing_probability - 0.5)
        if abs(self.decision_margin - expected_margin) > 1e-5:
            raise ValueError(
                f"decision_margin ({self.decision_margin}) must equal 2 * |p_h - 0.5| ({expected_margin})"
            )
        return self

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# 5. Top-Level Agent Contract
# ---------------------------------------------------------------------------

class HeaderAgentResult(BaseModel):
    """
    Complete output payload of the Header Agent.
    Serialized and passed to the Evidence Aggregation Layer.
    """
    email_id: str = Field(description="Unique email identifier matching EmailData.email_id.")
    agent_name: str = Field(default="header_agent", description="Identifier of the emitting agent.")
    agent_version: str = Field(default="0.1.0", description="Semantic version of agent specification.")
    status: str = Field(default="success", description="Execution outcome: 'success', 'partial', or 'error'.")
    processing_time_ms: float = Field(ge=0.0, default=0.0, description="Elapsed processing time in milliseconds.")
    features: HeaderFeatures = Field(description="Sanitized Tier 3 feature vector (canonical 45 features).")
    availability: HeaderFeatureAvailability = Field(description="Per-feature missingness manifest.")
    evidence: HeaderEvidence = Field(description="Tier 2 forensic evidence and audit trails.")
    risk_assessment: Optional[HeaderRiskAssessment] = Field(
        default=None,
        description="Populated only when a trained Layer 2 base model is attached.",
    )
    warnings: list[str] = Field(default_factory=list, description="Non-fatal data quality warnings.")
    limitations: list[str] = Field(
        default_factory=list,
        description="Explicit operational caveats (e.g. offline unverified claims).",
    )

    model_config = {"extra": "forbid"}


# Architectural alias for HeaderAgentResult matching Section 7 of design doc
HeaderAgentOutput = HeaderAgentResult

