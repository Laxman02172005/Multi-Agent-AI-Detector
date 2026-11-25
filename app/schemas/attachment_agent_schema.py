"""
app/schemas/attachment_agent_schema.py
--------------------------------------
Pydantic v2 data contract for the Attachment Specialist Agent.

Architecture & Contracts:
- CANONICAL_ATTACHMENT_FEATURE_NAMES: Literal type defining all 25 canonical attachment features.
- CANONICAL_ATTACHMENT_FEATURE_LIST: Ordered tuple of all 25 canonical feature names.
- FEATURE_TO_CATEGORY_MAP: Mapping of each feature to its approved category.
- AttachmentFeatures: Sanitized Tier 3 feature vector (canonical 25 features).
- AttachmentFeatureAvailability: Availability and completeness manifest.
- AttachmentAnalysisItem: Granular static inspection record for individual attachments (max 50).
- AttachmentEvidenceItem & AttachmentEvidence: Tier 2 forensic evidence container (capped at 100).
- AttachmentAgentResult: Complete serializable agent output container (aliased as AttachmentAgentOutput).
"""

from __future__ import annotations

from typing import Any, Literal, Optional, Tuple, get_args
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# 1. Canonical 25-Feature Registry (Continuous Order)
# ---------------------------------------------------------------------------

CANONICAL_ATTACHMENT_FEATURE_NAMES = Literal[
    # Category A: High-Risk Types & Scripts (6 features)
    "total_attachment_count",
    "has_attachments",
    "has_executable_attachment",
    "executable_attachment_count",
    "has_macro_enabled_attachment",
    "macro_enabled_count",
    # Category B: Evasion, Smuggling & Spoofing (8 features)
    "has_html_smuggling_attachment",
    "html_smuggling_count",
    "has_double_extension",
    "double_extension_count",
    "has_rlo_spoofing",
    "rlo_spoofing_count",
    "has_mime_mismatch",
    "mime_mismatch_count",
    # Category C: Archives & Containers (5 features)
    "has_archive_attachment",
    "archive_attachment_count",
    "has_disk_image",
    "has_encrypted_archive",
    "has_suspicious_archive",
    # Category D: Size & Volumetric Properties (6 features)
    "total_attachment_size_bytes",
    "max_attachment_size_bytes",
    "has_oversized_attachment",
    "has_zero_byte_attachment",
    "has_skipped_attachments",
    "skipped_attachment_count",
]

CANONICAL_ATTACHMENT_FEATURE_LIST: Tuple[str, ...] = get_args(CANONICAL_ATTACHMENT_FEATURE_NAMES)
CANONICAL_ATTACHMENT_FEATURE_NAMES_SET: frozenset[str] = frozenset(CANONICAL_ATTACHMENT_FEATURE_LIST)

CATEGORY_A_ATTACHMENT_FEATURES: Tuple[str, ...] = (
    "total_attachment_count",
    "has_attachments",
    "has_executable_attachment",
    "executable_attachment_count",
    "has_macro_enabled_attachment",
    "macro_enabled_count",
)

CATEGORY_B_ATTACHMENT_FEATURES: Tuple[str, ...] = (
    "has_html_smuggling_attachment",
    "html_smuggling_count",
    "has_double_extension",
    "double_extension_count",
    "has_rlo_spoofing",
    "rlo_spoofing_count",
    "has_mime_mismatch",
    "mime_mismatch_count",
)

CATEGORY_C_ATTACHMENT_FEATURES: Tuple[str, ...] = (
    "has_archive_attachment",
    "archive_attachment_count",
    "has_disk_image",
    "has_encrypted_archive",
    "has_suspicious_archive",
)

CATEGORY_D_ATTACHMENT_FEATURES: Tuple[str, ...] = (
    "total_attachment_size_bytes",
    "max_attachment_size_bytes",
    "has_oversized_attachment",
    "has_zero_byte_attachment",
    "has_skipped_attachments",
    "skipped_attachment_count",
)

ATTACHMENT_FEATURE_TO_CATEGORY_MAP: dict[str, str] = {}
for feat in CATEGORY_A_ATTACHMENT_FEATURES:
    ATTACHMENT_FEATURE_TO_CATEGORY_MAP[feat] = "Category A: High-Risk Types & Scripts"
for feat in CATEGORY_B_ATTACHMENT_FEATURES:
    ATTACHMENT_FEATURE_TO_CATEGORY_MAP[feat] = "Category B: Evasion, Smuggling & Spoofing"
for feat in CATEGORY_C_ATTACHMENT_FEATURES:
    ATTACHMENT_FEATURE_TO_CATEGORY_MAP[feat] = "Category C: Archives & Containers"
for feat in CATEGORY_D_ATTACHMENT_FEATURES:
    ATTACHMENT_FEATURE_TO_CATEGORY_MAP[feat] = "Category D: Size & Volumetric Properties"


# ---------------------------------------------------------------------------
# 2. Sanitized Tier 3 Feature Vector
# ---------------------------------------------------------------------------

class AttachmentFeatures(BaseModel):
    """
    Sanitized Tier 3 feature vector containing the 25 canonical attachment features.
    Zero raw filenames or binary digests are stored here.
    """
    # Category A: High-Risk Types & Scripts
    total_attachment_count: int = Field(default=0, ge=0, description="Total count of attachments found in email.")
    has_attachments: bool = Field(default=False, description="True if one or more attachments were extracted.")
    has_executable_attachment: bool = Field(default=False, description="True if executable binary or script files were detected.")
    executable_attachment_count: int = Field(default=0, ge=0, description="Count of executable attachments (.exe, .scr, .vbs, .js, .bat, etc.).")
    has_macro_enabled_attachment: bool = Field(default=False, description="True if macro-enabled Office files (.docm, .xlsm, etc.) were detected.")
    macro_enabled_count: int = Field(default=0, ge=0, description="Count of macro-enabled Office attachments.")

    # Category B: Evasion, Smuggling & Spoofing
    has_html_smuggling_attachment: bool = Field(default=False, description="True if HTML smuggling vector files (.html, .htm, .svg) were detected.")
    html_smuggling_count: int = Field(default=0, ge=0, description="Count of HTML smuggling candidate attachments.")
    has_double_extension: bool = Field(default=False, description="True if double extension filenames (e.g. invoice.pdf.exe) were detected.")
    double_extension_count: int = Field(default=0, ge=0, description="Count of double extension attachments.")
    has_rlo_spoofing: bool = Field(default=False, description="True if Right-to-Left Override (U+202E) spoofing was detected in filename.")
    rlo_spoofing_count: int = Field(default=0, ge=0, description="Count of attachments containing RLO characters.")
    has_mime_mismatch: bool = Field(default=False, description="True if declared MIME type conflicts with the file extension.")
    mime_mismatch_count: int = Field(default=0, ge=0, description="Count of MIME-type vs extension mismatches.")

    # Category C: Archives & Containers
    has_archive_attachment: bool = Field(default=False, description="True if archive container files (.zip, .rar, .7z, .tar, .gz) were detected.")
    archive_attachment_count: int = Field(default=0, ge=0, description="Count of archive attachments.")
    has_disk_image: bool = Field(default=False, description="True if virtual disk images (.iso, .img, .vhd) were detected.")
    has_encrypted_archive: bool = Field(default=False, description="True if password-protected / encrypted archive was detected.")
    has_suspicious_archive: bool = Field(default=False, description="True if archive exhibits evasion indicators (nested executable, double ext).")

    # Category D: Size & Volumetric Properties
    total_attachment_size_bytes: int = Field(default=0, ge=0, description="Combined byte size across all attachments.")
    max_attachment_size_bytes: int = Field(default=0, ge=0, description="Maximum byte size among all individual attachments.")
    has_oversized_attachment: bool = Field(default=False, description="True if any attachment exceeds large attachment threshold (>10 MB).")
    has_zero_byte_attachment: bool = Field(default=False, description="True if any attachment has size == 0 bytes.")
    has_skipped_attachments: bool = Field(default=False, description="True if any attachment was skipped during extraction (e.g. >25 MB or >50 count).")
    skipped_attachment_count: int = Field(default=0, ge=0, description="Count of attachments skipped by extractor resource guards.")

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# 3. Availability and Completeness Manifest
# ---------------------------------------------------------------------------

class AttachmentFeatureAvailability(BaseModel):
    """
    Tracks availability and completeness metrics across attachment feature subsets.
    """
    avail_has_attachments: bool = Field(default=False, description="True if one or more attachments exist in the email.")
    avail_metadata_features: bool = Field(default=False, description="True if attachment metadata was fully inspectable.")
    avail_mime_classification: bool = Field(default=False, description="True if MIME types could be compared with file extensions.")
    completeness_risk_types: float = Field(default=0.0, ge=0.0, le=1.0, description="Completeness of Category A risk type features.")
    completeness_spoofing: float = Field(default=0.0, ge=0.0, le=1.0, description="Completeness of Category B spoofing/smuggling features.")
    completeness_container: float = Field(default=0.0, ge=0.0, le=1.0, description="Completeness of Category C archive/container features.")
    completeness_total: float = Field(default=0.0, ge=0.0, le=1.0, description="Harmonized total completeness across all categories.")

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# 4. Granular Per-Attachment Inspection Record (Tier 2 Drill-down)
# ---------------------------------------------------------------------------

class AttachmentAnalysisItem(BaseModel):
    """
    Granular static inspection record for a single attachment (max 50).
    """
    attachment_index: int = Field(ge=0, description="0-indexed position within EmailData.attachments.")
    filename_snippet: str = Field(max_length=256, description="Sanitized display filename (max 256 chars).")
    content_type: str = Field(description="Declared or inferred MIME type.")
    extension: Optional[str] = Field(default=None, description="Lowercased file extension without leading dot.")
    size_bytes: int = Field(ge=0, description="Byte size of attachment.")
    is_executable: bool = Field(default=False, description="True if extension is a known executable/script format.")
    is_macro_enabled: bool = Field(default=False, description="True if extension is a macro-enabled Office format.")
    is_html_smuggling: bool = Field(default=False, description="True if extension is an HTML smuggling candidate.")
    has_double_extension: bool = Field(default=False, description="True if filename has deceptive secondary extension.")
    has_rlo_spoofing: bool = Field(default=False, description="True if filename contains U+202E Right-to-Left Override.")
    has_mime_mismatch: bool = Field(default=False, description="True if declared MIME type conflicts with extension.")
    is_archive: bool = Field(default=False, description="True if extension is a known archive/compressed format.")
    is_disk_image: bool = Field(default=False, description="True if extension is a disk image format.")
    is_encrypted: bool = Field(default=False, description="True if archive is password-protected or encrypted.")
    status: str = Field(description="Extraction status string (processed, skipped_oversized, etc.).")

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# 5. Forensic Evidence (Tier 2)
# ---------------------------------------------------------------------------

class AttachmentEvidenceItem(BaseModel):
    """
    Forensic evidence item linking an observed attachment finding to its source.
    """
    finding_id: str = Field(description="Unique finding identifier.")
    feature_name: str = Field(description="Canonical feature name associated with this finding.")
    category: str = Field(description="Feature category partition.")
    attachment_index: int = Field(ge=0, description="Index of affected attachment.")
    observed_value: str = Field(description="Sanitized observed value or metric snippet.")
    description: str = Field(description="Human-readable explanation of why this finding was recorded.")
    snippet_bounded: str = Field(max_length=256, description="Bounded filename or MIME snippet (max 256 chars).")

    model_config = {"extra": "forbid"}


class AttachmentEvidence(BaseModel):
    """
    Container for Tier 2 forensic evidence items supporting attachment features.
    """
    evidence_items: list[AttachmentEvidenceItem] = Field(default_factory=list, max_length=100, description="Forensic evidence items (capped at 100).")
    omitted_evidence_count: int = Field(default=0, ge=0, description="Count of evidence items omitted due to capacity cap.")
    observed_anomalies: list[str] = Field(default_factory=list, max_length=100, description="Distinct anomaly tags observed in attachments.")

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# 6. Top-Level Agent Result
# ---------------------------------------------------------------------------

class AttachmentAgentResult(BaseModel):
    """
    Complete serializable output container for the Attachment Specialist Agent.
    """
    email_id: str = Field(description="Unique email identifier preserved exactly from ingestion.")
    agent_name: str = Field(default="attachment_agent", description="Specialist agent identifier.")
    agent_version: str = Field(default="1.0.0", description="Semantic version of the Attachment Agent.")
    status: Literal["success", "partial", "error"] = Field(default="success", description="Execution status.")
    processing_time_ms: float = Field(default=0.0, ge=0.0, description="Processing duration in milliseconds.")
    total_attachments_evaluated: int = Field(default=0, ge=0, description="Total attachments evaluated.")
    features: AttachmentFeatures = Field(description="Canonical 25-feature vector.")
    availability: AttachmentFeatureAvailability = Field(description="Feature availability and completeness manifest.")
    evidence: AttachmentEvidence = Field(default_factory=AttachmentEvidence, description="Forensic evidence items.")
    analysis_items: list[AttachmentAnalysisItem] = Field(default_factory=list, max_length=50, description="Granular inspection records (capped at 50).")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings encountered during analysis.")
    limitations: list[str] = Field(default_factory=list, description="Methodological boundaries and operating constraints.")

    model_config = {"extra": "forbid"}


# Public alias for consistency across agents
AttachmentAgentOutput = AttachmentAgentResult
