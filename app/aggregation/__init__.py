"""
app/aggregation/__init__.py
---------------------------
Layer 2 Evidence Aggregator public exports.
"""

from app.aggregation.evidence_aggregator import (
    EvidenceAggregationError,
    aggregate_evidence,
)
from app.schemas.aggregator_schema import (
    ACTIVE_META_FEATURE_COUNT,
    ACTIVE_META_FEATURE_NAMES,
    ATTACHMENT_ACTIVE_FEATURES,
    HEADER_ACTIVE_FEATURES,
    HEADER_QUARANTINED_FEATURES,
    MODALITY_NAMES,
    MODALITY_WEIGHTS,
    QUARANTINED_META_FEATURE_COUNT,
    QUARANTINED_META_FEATURE_NAMES,
    TEXT_ACTIVE_FEATURES,
    URL_ACTIVE_FEATURES,
    URL_QUARANTINED_FEATURES,
    AggregatedEvidenceResult,
    MetaFeatureVector,
    ModalityHealth,
    ModalityStatus,
    UnifiedEvidenceItem,
)

__all__ = [
    "aggregate_evidence",
    "EvidenceAggregationError",
    "ACTIVE_META_FEATURE_COUNT",
    "ACTIVE_META_FEATURE_NAMES",
    "ATTACHMENT_ACTIVE_FEATURES",
    "HEADER_ACTIVE_FEATURES",
    "HEADER_QUARANTINED_FEATURES",
    "MODALITY_NAMES",
    "MODALITY_WEIGHTS",
    "QUARANTINED_META_FEATURE_COUNT",
    "QUARANTINED_META_FEATURE_NAMES",
    "TEXT_ACTIVE_FEATURES",
    "URL_ACTIVE_FEATURES",
    "URL_QUARANTINED_FEATURES",
    "AggregatedEvidenceResult",
    "MetaFeatureVector",
    "ModalityHealth",
    "ModalityStatus",
    "UnifiedEvidenceItem",
]
