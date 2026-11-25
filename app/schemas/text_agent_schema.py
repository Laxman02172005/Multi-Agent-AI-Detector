"""
app/schemas/text_agent_schema.py
--------------------------------
Pydantic v2 data contract for the Text/Body Specialist Agent.

Architecture & Contracts:
- CANONICAL_TEXT_FEATURE_NAMES: Literal type defining all 29 canonical text features.
- CANONICAL_TEXT_FEATURE_LIST: Ordered tuple of all 29 canonical feature names.
- FEATURE_TO_CATEGORY_MAP: Mapping of each feature to its approved category.
- TextFeatures: Sanitized Tier 3 feature vector (canonical 29 features).
- TextFeatureAvailability: Availability and completeness manifest.
- TextEvidenceItem & TextEvidence: Tier 2 forensic evidence container (capped at 100).
- TextAgentResult: Complete serializable agent output container (aliased as TextAgentOutput).
"""

from __future__ import annotations

from typing import Any, Literal, Optional, Tuple, get_args
from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# 1. Canonical 29-Feature Registry (Continuous Order)
# ---------------------------------------------------------------------------

CANONICAL_TEXT_FEATURE_NAMES = Literal[
    # Category A: Urgency, Lures & Intent (12 features)
    "urgency_cue_count",
    "has_urgency_cues",
    "credential_lure_count",
    "has_credential_lures",
    "financial_lure_count",
    "has_financial_lures",
    "action_lure_count",
    "has_action_lures",
    "threat_cue_count",
    "has_threat_cues",
    "reward_cue_count",
    "has_reward_cues",
    # Category B: Text & HTML Obfuscation / Anomalies (9 features)
    "has_hidden_text",
    "hidden_text_count",
    "has_zero_width_chars",
    "zero_width_char_count",
    "has_excessive_capitalization",
    "capitalization_ratio",
    "has_excessive_punctuation",
    "excessive_punctuation_count",
    "has_plain_html_mismatch",
    # Category C: Lexical, Readability & Structural Metrics (8 features)
    "has_body",
    "has_plain_text",
    "has_html",
    "word_count",
    "character_count",
    "html_to_text_ratio",
    "body_entropy",
    "generic_greeting_present",
]

CANONICAL_TEXT_FEATURE_LIST: Tuple[str, ...] = get_args(CANONICAL_TEXT_FEATURE_NAMES)
CANONICAL_TEXT_FEATURE_NAMES_SET: frozenset[str] = frozenset(CANONICAL_TEXT_FEATURE_LIST)

CATEGORY_A_FEATURES: Tuple[str, ...] = (
    "urgency_cue_count",
    "has_urgency_cues",
    "credential_lure_count",
    "has_credential_lures",
    "financial_lure_count",
    "has_financial_lures",
    "action_lure_count",
    "has_action_lures",
    "threat_cue_count",
    "has_threat_cues",
    "reward_cue_count",
    "has_reward_cues",
)

CATEGORY_B_FEATURES: Tuple[str, ...] = (
    "has_hidden_text",
    "hidden_text_count",
    "has_zero_width_chars",
    "zero_width_char_count",
    "has_excessive_capitalization",
    "capitalization_ratio",
    "has_excessive_punctuation",
    "excessive_punctuation_count",
    "has_plain_html_mismatch",
)

CATEGORY_C_FEATURES: Tuple[str, ...] = (
    "has_body",
    "has_plain_text",
    "has_html",
    "word_count",
    "character_count",
    "html_to_text_ratio",
    "body_entropy",
    "generic_greeting_present",
)

FEATURE_TO_CATEGORY_MAP: dict[str, str] = {}
for feat in CATEGORY_A_FEATURES:
    FEATURE_TO_CATEGORY_MAP[feat] = "Category A: Urgency, Lures & Intent"
for feat in CATEGORY_B_FEATURES:
    FEATURE_TO_CATEGORY_MAP[feat] = "Category B: Text & HTML Obfuscation / Anomalies"
for feat in CATEGORY_C_FEATURES:
    FEATURE_TO_CATEGORY_MAP[feat] = "Category C: Lexical, Readability & Structural Metrics"


# ---------------------------------------------------------------------------
# 2. Sanitized Tier 3 Feature Vector
# ---------------------------------------------------------------------------

class TextFeatures(BaseModel):
    """
    Sanitized Tier 3 feature vector containing the 29 canonical text features.
    Zero raw body text or email identifiers are stored here.
    """
    # Category A: Urgency, Lures & Intent
    urgency_cue_count: int = Field(default=0, ge=0, description="Count of urgency / deadline pressure cues.")
    has_urgency_cues: bool = Field(default=False, description="True if one or more urgency cues were detected.")
    credential_lure_count: int = Field(default=0, ge=0, description="Count of credential harvesting lure terms.")
    has_credential_lures: bool = Field(default=False, description="True if credential harvesting lure terms were detected.")
    financial_lure_count: int = Field(default=0, ge=0, description="Count of financial or payment lure terms.")
    has_financial_lures: bool = Field(default=False, description="True if financial or payment lure terms were detected.")
    action_lure_count: int = Field(default=0, ge=0, description="Count of immediate action cues (click, login, verify).")
    has_action_lures: bool = Field(default=False, description="True if call-to-action lure terms were detected.")
    threat_cue_count: int = Field(default=0, ge=0, description="Count of fear / punitive threat cues.")
    has_threat_cues: bool = Field(default=False, description="True if fear / punitive threat cues were detected.")
    reward_cue_count: int = Field(default=0, ge=0, description="Count of reward / prize / windfall cues.")
    has_reward_cues: bool = Field(default=False, description="True if reward or enticement cues were detected.")

    # Category B: Text & HTML Obfuscation / Anomalies
    has_hidden_text: bool = Field(default=False, description="True if hidden text / CSS tricks (display:none, font-size:0) were detected.")
    hidden_text_count: int = Field(default=0, ge=0, description="Count of hidden text / CSS anomaly instances.")
    has_zero_width_chars: bool = Field(default=False, description="True if zero-width Unicode characters were detected.")
    zero_width_char_count: int = Field(default=0, ge=0, description="Count of zero-width Unicode characters.")
    has_excessive_capitalization: bool = Field(default=False, description="True if uppercase ratio exceeds threshold (>30% on >=50 chars).")
    capitalization_ratio: float = Field(default=0.0, ge=0.0, le=1.0, description="Ratio of uppercase characters to total alpha characters.")
    has_excessive_punctuation: bool = Field(default=False, description="True if repeated punctuation runs (!!!, ???) are present.")
    excessive_punctuation_count: int = Field(default=0, ge=0, description="Count of excessive punctuation clusters.")
    has_plain_html_mismatch: bool = Field(default=False, description="True if plain text and HTML bodies show significant textual divergence.")

    # Category C: Lexical, Readability & Structural Metrics
    has_body: bool = Field(default=False, description="True if any non-empty body content was extracted.")
    has_plain_text: bool = Field(default=False, description="True if a non-empty plain-text body part is present.")
    has_html: bool = Field(default=False, description="True if a non-empty HTML body part is present.")
    word_count: int = Field(default=0, ge=0, description="Total word count in cleaned body text.")
    character_count: int = Field(default=0, ge=0, description="Total character count in cleaned body text.")
    html_to_text_ratio: Optional[float] = Field(default=None, ge=0.0, description="Ratio of cleaned text length to raw HTML length (None if no HTML).")
    body_entropy: Optional[float] = Field(default=None, ge=0.0, description="Shannon entropy of character distribution in body (None if empty body).")
    generic_greeting_present: bool = Field(default=False, description="True if generic greeting (Dear Customer, Dear User) was detected.")

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# 3. Availability and Completeness Manifest
# ---------------------------------------------------------------------------

class TextFeatureAvailability(BaseModel):
    """
    Tracks availability and completeness metrics across text feature subsets.
    """
    avail_has_body: bool = Field(default=False, description="True if any body content was extracted.")
    avail_plain_text: bool = Field(default=False, description="True if plain-text body was available.")
    avail_html: bool = Field(default=False, description="True if HTML body was available.")
    avail_entropy: bool = Field(default=False, description="True if body entropy could be computed.")
    completeness_intent: float = Field(default=0.0, ge=0.0, le=1.0, description="Completeness of Category A intent features.")
    completeness_obfuscation: float = Field(default=0.0, ge=0.0, le=1.0, description="Completeness of Category B obfuscation features.")
    completeness_lexical: float = Field(default=0.0, ge=0.0, le=1.0, description="Completeness of Category C lexical features.")
    completeness_total: float = Field(default=0.0, ge=0.0, le=1.0, description="Harmonized total completeness across all categories.")

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# 4. Forensic Evidence (Tier 2)
# ---------------------------------------------------------------------------

class TextEvidenceItem(BaseModel):
    """
    Forensic evidence item linking an observed text finding to its source.
    """
    finding_id: str = Field(description="Unique finding identifier.")
    feature_name: str = Field(description="Canonical feature name associated with this finding.")
    category: str = Field(description="Feature category partition.")
    observed_value: str = Field(description="Sanitized observed value or metric snippet.")
    description: str = Field(description="Human-readable explanation of why this finding was recorded.")
    snippet_bounded: str = Field(max_length=256, description="Bounded text excerpt illustrating the finding (max 256 chars).")

    model_config = {"extra": "forbid"}


class TextEvidence(BaseModel):
    """
    Container for Tier 2 forensic evidence items supporting text features.
    """
    evidence_items: list[TextEvidenceItem] = Field(default_factory=list, max_length=100, description="Forensic evidence items (capped at 100).")
    omitted_evidence_count: int = Field(default=0, ge=0, description="Count of evidence items omitted due to capacity cap.")
    observed_anomalies: list[str] = Field(default_factory=list, max_length=100, description="Distinct anomaly tags observed in body text.")

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# 5. Top-Level Agent Result
# ---------------------------------------------------------------------------

class TextAgentResult(BaseModel):
    """
    Complete serializable output container for the Text/Body Agent.
    """
    email_id: str = Field(description="Unique email identifier preserved exactly from ingestion.")
    agent_name: str = Field(default="text_agent", description="Specialist agent identifier.")
    agent_version: str = Field(default="1.0.0", description="Semantic version of the Text Agent.")
    status: Literal["success", "partial", "error"] = Field(default="success", description="Execution status.")
    processing_time_ms: float = Field(default=0.0, ge=0.0, description="Processing duration in milliseconds.")
    features: TextFeatures = Field(description="Canonical 29-feature vector.")
    availability: TextFeatureAvailability = Field(description="Feature availability and completeness manifest.")
    evidence: TextEvidence = Field(default_factory=TextEvidence, description="Forensic evidence items.")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings encountered during analysis.")
    limitations: list[str] = Field(default_factory=list, description="Methodological boundaries and operating constraints.")

    model_config = {"extra": "forbid"}


# Public alias for consistency across agents
TextAgentOutput = TextAgentResult
