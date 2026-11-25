"""
app/schemas/pipeline_schema.py
------------------------------
Pydantic v2 data contract for the End-to-End Phishing Detection Pipeline.

Architecture:
- PhishingAnalysisReport: Top-level container synthesizing Layer 1 agent errors,
  Layer 2 aggregated evidence, and Layer 3 meta-classifier verdict and explanations.
"""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field

from app.schemas.aggregator_schema import AggregatedEvidenceResult
from app.schemas.meta_classifier_schema import MetaClassifierResult


class PhishingAnalysisReport(BaseModel):
    """
    Complete end-to-end audit report emitted by PhishingDetectorPipeline.
    Bundles the calibrated verdict, explainability features, aggregated evidence,
    and any isolated agent execution warnings or errors.
    """
    email_id: str = Field(
        description="Identifier of the email under analysis, strictly preserved from ingestion."
    )
    analyzed_at_utc: str = Field(
        description="ISO 8601 UTC timestamp of analysis completion."
    )
    total_processing_time_ms: float = Field(
        ge=0.0,
        description="Total end-to-end processing duration from raw input bytes to final verdict in ms.",
    )
    verdict_result: MetaClassifierResult = Field(
        description="Layer 3 Meta-Classifier operational verdict, calibrated probability, and linear attribution.",
    )
    aggregated_evidence: AggregatedEvidenceResult = Field(
        description="Layer 2 aggregated feature vector, modality health manifests, and Tier 2 evidence trail.",
    )
    agent_errors: dict[str, str] = Field(
        default_factory=dict,
        description="Isolated errors logged by Layer 1 specialist agents (modality -> error description).",
    )

    model_config = {
        "extra": "forbid",
    }
