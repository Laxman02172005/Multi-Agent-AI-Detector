"""
app/schemas/aggregator_schema.py
---------------------------------
Pydantic v2 data contract for the Evidence Aggregator (Layer 2) in the
Hierarchical Multi-Agent AI Phishing Email Detector.

Architecture & Contracts:
- ModalityStatus: Enumeration of operational health states for each modality
  (AVAILABLE, EMPTY, DEGRADED, FAILED).
- ModalityHealth: Health, availability, completeness, and missingness metrics
  for a single modality.
- UnifiedEvidenceItem: Tier 2 cross-modality normalized forensic evidence record.
- MetaFeatureVector: Sanitized Tier 3 meta-feature vector containing exactly
  132 active numerical features (ordered, non-quarantined) and corresponding
  missingness mask.
- AggregatedEvidenceResult: Complete serializable output of Layer 2 Evidence
  Aggregation.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Optional, Tuple, get_args
from pydantic import BaseModel, Field, model_validator

from app.schemas.header_agent_schema import CANONICAL_HEADER_FEATURE_LIST
from app.schemas.url_agent_schema import CANONICAL_URL_FEATURE_LIST
from app.schemas.text_agent_schema import CANONICAL_TEXT_FEATURE_LIST
from app.schemas.attachment_agent_schema import CANONICAL_ATTACHMENT_FEATURE_LIST


# ---------------------------------------------------------------------------
# 1. Feature Registry & Quarantined Partitions
# ---------------------------------------------------------------------------

HEADER_QUARANTINED_FEATURES: Tuple[str, ...] = (
    "undisclosed_recipients",
    "to_empty_or_missing",
    "transit_delay_seconds",
    "transit_delay_unavailable",
)

URL_QUARANTINED_FEATURES: Tuple[str, ...] = (
    "has_brand_in_path",
    "has_form_action_url",
)

HEADER_ACTIVE_FEATURES: Tuple[str, ...] = tuple(
    f for f in CANONICAL_HEADER_FEATURE_LIST if f not in HEADER_QUARANTINED_FEATURES
)
URL_ACTIVE_FEATURES: Tuple[str, ...] = tuple(
    f for f in CANONICAL_URL_FEATURE_LIST if f not in URL_QUARANTINED_FEATURES
)
TEXT_ACTIVE_FEATURES: Tuple[str, ...] = tuple(CANONICAL_TEXT_FEATURE_LIST)
ATTACHMENT_ACTIVE_FEATURES: Tuple[str, ...] = tuple(CANONICAL_ATTACHMENT_FEATURE_LIST)

# Ordered full active meta-feature names (41 + 37 + 29 + 25 = 132)
ACTIVE_META_FEATURE_NAMES: Tuple[str, ...] = (
    tuple(f"header_{f}" for f in HEADER_ACTIVE_FEATURES)
    + tuple(f"url_{f}" for f in URL_ACTIVE_FEATURES)
    + tuple(f"text_{f}" for f in TEXT_ACTIVE_FEATURES)
    + tuple(f"attachment_{f}" for f in ATTACHMENT_ACTIVE_FEATURES)
)

QUARANTINED_META_FEATURE_NAMES: Tuple[str, ...] = (
    tuple(f"header_{f}" for f in HEADER_QUARANTINED_FEATURES)
    + tuple(f"url_{f}" for f in URL_QUARANTINED_FEATURES)
)

ACTIVE_META_FEATURE_COUNT: int = len(ACTIVE_META_FEATURE_NAMES)  # 132
QUARANTINED_META_FEATURE_COUNT: int = len(QUARANTINED_META_FEATURE_NAMES)  # 6

MODALITY_NAMES: Tuple[str, ...] = ("header", "url", "text", "attachment")

MODALITY_WEIGHTS: dict[str, float] = {
    "header": 0.35,
    "text": 0.35,
    "url": 0.20,
    "attachment": 0.10,
}


# ---------------------------------------------------------------------------
# 2. Modality Health and Status
# ---------------------------------------------------------------------------

class ModalityStatus(str, Enum):
    """
    Operational status of a Layer 1 specialist modality.
    """
    AVAILABLE = "available"  # Present, successfully extracted, completeness >= 0.60
    EMPTY = "empty"          # Evaluated successfully, but modality has zero items (0 URLs, no body, 0 attachments)
    DEGRADED = "degraded"    # Extracted with partial warnings or low completeness (< 0.60)
    FAILED = "failed"        # Agent result was None or emitted status == "error"


class ModalityHealth(BaseModel):
    """
    Diagnostic health and completeness assessment for an individual specialist modality.
    """
    modality: Literal["header", "url", "text", "attachment"] = Field(
        description="Name of the specialist modality."
    )
    status: ModalityStatus = Field(
        description="Operational health status of the modality."
    )
    completeness: float = Field(
        ge=0.0,
        le=1.0,
        description="Modality-specific completeness score between 0.0 and 1.0.",
    )
    active_feature_count: int = Field(
        ge=0,
        description="Count of active (non-quarantined) features for this modality.",
    )
    missing_feature_count: int = Field(
        ge=0,
        description="Count of missing/imputed features for this modality.",
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Diagnostic error message if modality failed or degraded.",
    )

    model_config = {
        "extra": "forbid",
    }


# ---------------------------------------------------------------------------
# 3. Unified Forensic Evidence Item (Tier 2)
# ---------------------------------------------------------------------------

class UnifiedEvidenceItem(BaseModel):
    """
    Normalized, cross-modality forensic evidence record for explainability and auditing.
    Capped in aggregate container to prevent memory exhaustion on malicious inputs.
    """
    finding_id: str = Field(
        description="Unique identifier for the evidence finding."
    )
    source_modality: Literal["header", "url", "text", "attachment"] = Field(
        description="Specialist modality that produced the finding."
    )
    feature_name: str = Field(
        description="Name of the associated feature or detection trigger."
    )
    category: str = Field(
        description="Category classification within the source modality."
    )
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(
        default="medium",
        description="Severity classification of the observed finding.",
    )
    observed_value: str = Field(
        description="Observed anomaly value or summary."
    )
    description: str = Field(
        description="Human-readable explanation of why this finding indicates risk."
    )
    snippet_bounded: str = Field(
        max_length=256,
        description="Bounded, sanitized snippet of raw evidence text (<= 256 chars).",
    )

    model_config = {
        "extra": "forbid",
    }


# ---------------------------------------------------------------------------
# 4. Meta-Feature Vector (Tier 3)
# ---------------------------------------------------------------------------

class MetaFeatureVector(BaseModel):
    """
    Sanitized Tier 3 feature vector synthesizing all active features across the 4 modalities.
    Zero raw email texts, raw hostnames, or unescaped snippets are stored here.
    """
    feature_names: list[str] = Field(
        description="Strictly ordered list of active meta-feature names (132 features)."
    )
    feature_values: dict[str, float] = Field(
        description="Mapping of feature names to numeric float values (missing features imputed to 0.0)."
    )
    missingness_mask: dict[str, int] = Field(
        description="Binary missingness indicator mapping: 0 for observed/evaluated, 1 for missing/imputed."
    )
    active_feature_count: int = Field(
        default=ACTIVE_META_FEATURE_COUNT,
        description="Total active features (132).",
    )
    quarantined_feature_count: int = Field(
        default=QUARANTINED_META_FEATURE_COUNT,
        description="Total quarantined features excluded from vector (6).",
    )
    missing_feature_count: int = Field(
        ge=0,
        description="Count of missing/imputed features across all modalities.",
    )

    model_config = {
        "extra": "forbid",
    }

    @model_validator(mode="after")
    def validate_vector_consistency(self) -> MetaFeatureVector:
        if len(self.feature_names) != ACTIVE_META_FEATURE_COUNT:
            raise ValueError(
                f"feature_names length ({len(self.feature_names)}) does not match "
                f"expected active count ({ACTIVE_META_FEATURE_COUNT})"
            )
        if len(self.feature_values) != ACTIVE_META_FEATURE_COUNT:
            raise ValueError(
                f"feature_values length ({len(self.feature_values)}) does not match "
                f"expected active count ({ACTIVE_META_FEATURE_COUNT})"
            )
        if len(self.missingness_mask) != ACTIVE_META_FEATURE_COUNT:
            raise ValueError(
                f"missingness_mask length ({len(self.missingness_mask)}) does not match "
                f"expected active count ({ACTIVE_META_FEATURE_COUNT})"
            )
        return self


# ---------------------------------------------------------------------------
# 5. Aggregated Evidence Result Container
# ---------------------------------------------------------------------------

class AggregatedEvidenceResult(BaseModel):
    """
    Complete serializable output of Layer 2 Evidence Aggregator.
    Synthesizes Tier 3 meta-features, modality health manifests, and Tier 2 unified evidence.
    """
    email_id: str = Field(
        description="Identifier of the email under analysis, strictly preserved from ingestion."
    )
    status: Literal["success", "partial", "error"] = Field(
        description="Overall aggregation execution status."
    )
    processing_time_ms: float = Field(
        ge=0.0,
        description="Execution time of Layer 2 aggregation in milliseconds.",
    )
    feature_vector: MetaFeatureVector = Field(
        description="Sanitized Tier 3 meta-feature vector and missingness mask."
    )
    modality_health: dict[str, ModalityHealth] = Field(
        description="Health and completeness metrics for each of the 4 specialist modalities."
    )
    overall_completeness: float = Field(
        ge=0.0,
        le=1.0,
        description="Weighted cross-modality completeness score.",
    )
    abstention_recommended_by_health: bool = Field(
        description="Flag indicating whether Layer 3 meta-classifier should abstain due to severe modality degradation.",
    )
    unified_evidence: list[UnifiedEvidenceItem] = Field(
        default_factory=list,
        max_length=150,
        description="Deterministically ordered, bounded list of unified evidence findings (max 150 items).",
    )
    omitted_evidence_count: int = Field(
        default=0,
        ge=0,
        description="Count of evidence items omitted due to container capacity cap.",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Diagnostic warnings encountered during aggregation.",
    )

    model_config = {
        "extra": "forbid",
    }
