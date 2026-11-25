"""
app/schemas/meta_classifier_schema.py
-------------------------------------
Pydantic v2 data contract for the Meta-Classifier and Selective Abstention
Policy (Layer 3) in the Hierarchical Multi-Agent AI Phishing Email Detector.

Architecture & Contracts:
- Verdict: Final operational classification decision (PHISHING, LEGITIMATE, ABSTAIN).
- AbstentionReason: Formal justification when verdict is ABSTAIN.
- FeatureContribution: Linear feature attribution explaining local model decision.
- DecisionThresholds: Configurable decision thresholds defining the abstention band.
- MetaClassifierResult: Complete serializable output of Layer 3 Meta-Classifier.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field, model_validator


class Verdict(str, Enum):
    """
    Final operational classification verdict from the Meta-Classifier.
    """
    PHISHING = "phishing"
    LEGITIMATE = "legitimate"
    ABSTAIN = "abstain"


class AbstentionReason(str, Enum):
    """
    Root-cause classification for selective abstention.
    """
    NONE = "none"                                              # Verdict is definitive (PHISHING or LEGITIMATE)
    INSUFFICIENT_MODALITY_HEALTH = "insufficient_modality_health"  # Input modalities failed or degraded below safety floor
    UNCERTAINTY_BAND = "uncertainty_band"                      # Calibrated probability fell within [abstain_low, abstain_high]
    MODEL_DEGRADED = "model_degraded"                          # Meta-model encountered internal integrity degradation


class FeatureContribution(BaseModel):
    """
    Attribution score for a single active feature indicating its signed linear
    influence on the logistic regression log-odds (w_i * x_tilde_i).
    """
    feature_name: str = Field(
        description="Canonical feature name (e.g. 'header_spf_status', 'url_has_ip_literal_url')."
    )
    modality: Literal["header", "url", "text", "attachment"] = Field(
        description="Source specialist modality of this feature."
    )
    feature_value: float = Field(
        description="Observed numeric value of the feature before standardization."
    )
    contribution_score: float = Field(
        description="Signed linear contribution score (w_i * x_tilde_i). Positive pushes towards Phishing, negative towards Legitimate."
    )

    model_config = {
        "extra": "forbid",
    }


class DecisionThresholds(BaseModel):
    """
    Configurable asymmetric classification and abstention thresholds.
    Enforces 0.0 < abstain_low < abstain_high < 1.0.
    """
    abstain_low: float = Field(
        default=0.35,
        gt=0.0,
        lt=1.0,
        description="Lower threshold below which an email is classified as LEGITIMATE.",
    )
    abstain_high: float = Field(
        default=0.65,
        gt=0.0,
        lt=1.0,
        description="Upper threshold at or above which an email is classified as PHISHING.",
    )

    model_config = {
        "extra": "forbid",
    }

    @model_validator(mode="after")
    def validate_threshold_order(self) -> DecisionThresholds:
        if not (0.0 < self.abstain_low < self.abstain_high < 1.0):
            raise ValueError(
                f"Decision thresholds must satisfy 0.0 < abstain_low < abstain_high < 1.0; "
                f"got abstain_low={self.abstain_low}, abstain_high={self.abstain_high}"
            )
        return self


class MetaClassifierResult(BaseModel):
    """
    Complete serializable output of Layer 3 Meta-Classifier.
    Contains final verdict, calibrated probability, confidence, explanation,
    and provenance metadata.
    """
    email_id: str = Field(
        description="Identifier of the email under analysis, strictly preserved from ingestion."
    )
    verdict: Verdict = Field(
        description="Final operational decision (PHISHING, LEGITIMATE, or ABSTAIN)."
    )
    calibrated_probability: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Calibrated posterior probability P(phishing | evidence), or None if health-abstained.",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Decision confidence score normalized to [0.0, 1.0].",
    )
    abstention_reason: AbstentionReason = Field(
        default=AbstentionReason.NONE,
        description="Diagnostic reason when verdict is ABSTAIN.",
    )
    top_phishing_contributors: list[FeatureContribution] = Field(
        default_factory=list,
        max_length=10,
        description="Top features driving prediction towards phishing (max 10 items).",
    )
    top_legitimate_contributors: list[FeatureContribution] = Field(
        default_factory=list,
        max_length=10,
        description="Top features driving prediction towards legitimate (max 10 items).",
    )
    overall_completeness: float = Field(
        ge=0.0,
        le=1.0,
        description="Overall modality completeness preserved from Layer 2 Evidence Aggregator.",
    )
    model_version: str = Field(
        description="Version identifier of the meta-classifier model artifact.",
    )
    processing_time_ms: float = Field(
        ge=0.0,
        description="Execution time of Layer 3 inference and explanation in milliseconds.",
    )

    model_config = {
        "extra": "forbid",
    }
