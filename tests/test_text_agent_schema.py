"""
tests/test_text_agent_schema.py
--------------------------------
Comprehensive unit tests for the Text Agent Pydantic v2 schemas:
- Canonical feature registry (29 features)
- Category partitions (Category A: 12, Category B: 9, Category C: 8)
- Feature to category mapping
- Sanitized Tier 3 feature vector (TextFeatures)
- Availability and completeness manifest (TextFeatureAvailability)
- Evidence item and container contracts (TextEvidenceItem, TextEvidence)
- Result container serialization and alias (TextAgentResult / TextAgentOutput)
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.text_agent_schema import (
    CANONICAL_TEXT_FEATURE_LIST,
    CANONICAL_TEXT_FEATURE_NAMES,
    CANONICAL_TEXT_FEATURE_NAMES_SET,
    CATEGORY_A_FEATURES,
    CATEGORY_B_FEATURES,
    CATEGORY_C_FEATURES,
    FEATURE_TO_CATEGORY_MAP,
    TextAgentOutput,
    TextAgentResult,
    TextEvidence,
    TextEvidenceItem,
    TextFeatureAvailability,
    TextFeatures,
)


class TestCanonicalTextFeatureRegistry:
    def test_canonical_feature_list_length(self) -> None:
        """Must contain exactly 29 distinct canonical features."""
        assert len(CANONICAL_TEXT_FEATURE_LIST) == 29
        assert len(set(CANONICAL_TEXT_FEATURE_LIST)) == 29
        assert len(CANONICAL_TEXT_FEATURE_NAMES_SET) == 29

    def test_category_partitions(self) -> None:
        """Category partitions must match 12 + 9 + 8 = 29 exactly."""
        assert len(CATEGORY_A_FEATURES) == 12
        assert len(CATEGORY_B_FEATURES) == 9
        assert len(CATEGORY_C_FEATURES) == 8

        concatenated = CATEGORY_A_FEATURES + CATEGORY_B_FEATURES + CATEGORY_C_FEATURES
        assert concatenated == CANONICAL_TEXT_FEATURE_LIST

    def test_feature_to_category_mapping(self) -> None:
        """Every canonical feature must map to its assigned category partition."""
        assert len(FEATURE_TO_CATEGORY_MAP) == 29
        for feat in CANONICAL_TEXT_FEATURE_LIST:
            assert feat in FEATURE_TO_CATEGORY_MAP
            cat = FEATURE_TO_CATEGORY_MAP[feat]
            assert cat.startswith("Category ")


class TestTextFeaturesModel:
    def test_default_instantiation(self) -> None:
        """TextFeatures defaults must have zero counts, False flags, and None ratios."""
        feat = TextFeatures()
        assert feat.urgency_cue_count == 0
        assert feat.has_urgency_cues is False
        assert feat.credential_lure_count == 0
        assert feat.has_credential_lures is False
        assert feat.financial_lure_count == 0
        assert feat.has_financial_lures is False
        assert feat.action_lure_count == 0
        assert feat.has_action_lures is False
        assert feat.threat_cue_count == 0
        assert feat.has_threat_cues is False
        assert feat.reward_cue_count == 0
        assert feat.has_reward_cues is False

        assert feat.has_hidden_text is False
        assert feat.hidden_text_count == 0
        assert feat.has_zero_width_chars is False
        assert feat.zero_width_char_count == 0
        assert feat.has_excessive_capitalization is False
        assert feat.capitalization_ratio == 0.0
        assert feat.has_excessive_punctuation is False
        assert feat.excessive_punctuation_count == 0
        assert feat.has_plain_html_mismatch is False

        assert feat.has_body is False
        assert feat.has_plain_text is False
        assert feat.has_html is False
        assert feat.word_count == 0
        assert feat.character_count == 0
        assert feat.html_to_text_ratio is None
        assert feat.body_entropy is None
        assert feat.generic_greeting_present is False

    def test_extra_fields_forbidden(self) -> None:
        """Arbitrary extra fields must be strictly rejected."""
        with pytest.raises(ValidationError):
            TextFeatures(unexpected_field="disallowed")  # type: ignore

    def test_bounds_validation(self) -> None:
        """Negative counts or ratios > 1.0 must be rejected."""
        with pytest.raises(ValidationError):
            TextFeatures(urgency_cue_count=-1)

        with pytest.raises(ValidationError):
            TextFeatures(capitalization_ratio=1.5)


class TestTextFeatureAvailabilityModel:
    def test_default_availability(self) -> None:
        avail = TextFeatureAvailability()
        assert avail.avail_has_body is False
        assert avail.avail_plain_text is False
        assert avail.avail_html is False
        assert avail.avail_entropy is False
        assert avail.completeness_intent == 0.0
        assert avail.completeness_obfuscation == 0.0
        assert avail.completeness_lexical == 0.0
        assert avail.completeness_total == 0.0

    def test_completeness_bounds(self) -> None:
        with pytest.raises(ValidationError):
            TextFeatureAvailability(completeness_total=1.2)


class TestTextEvidenceModels:
    def test_evidence_item_valid(self) -> None:
        item = TextEvidenceItem(
            finding_id="finding_001",
            feature_name="has_urgency_cues",
            category="Category A: Urgency, Lures & Intent",
            observed_value="immediately",
            description="Urgency keyword observed.",
            snippet_bounded="Act immediately to secure account",
        )
        assert item.finding_id == "finding_001"
        assert item.feature_name == "has_urgency_cues"

    def test_evidence_container_caps(self) -> None:
        items = [
            TextEvidenceItem(
                finding_id=f"f_{i}",
                feature_name="has_urgency_cues",
                category="Category A",
                observed_value="urgent",
                description="test",
                snippet_bounded="test",
            )
            for i in range(100)
        ]
        evidence = TextEvidence(evidence_items=items, omitted_evidence_count=5)
        assert len(evidence.evidence_items) == 100
        assert evidence.omitted_evidence_count == 5

        # Overflow beyond max_length=100 must raise ValidationError
        items_101 = items + [
            TextEvidenceItem(
                finding_id="f_101",
                feature_name="has_urgency_cues",
                category="Category A",
                observed_value="urgent",
                description="test",
                snippet_bounded="test",
            )
        ]
        with pytest.raises(ValidationError):
            TextEvidence(evidence_items=items_101)


class TestTextAgentResultSerialization:
    def test_serialization_roundtrip(self) -> None:
        result = TextAgentResult(
            email_id="email_text_001",
            agent_name="text_agent",
            agent_version="1.0.0",
            status="success",
            processing_time_ms=1.25,
            features=TextFeatures(has_body=True, word_count=42),
            availability=TextFeatureAvailability(avail_has_body=True, completeness_total=1.0),
            evidence=TextEvidence(evidence_items=[]),
            warnings=[],
            limitations=[],
        )
        dumped = result.model_dump()
        reconstructed = TextAgentResult.model_validate(dumped)
        assert reconstructed.email_id == "email_text_001"
        assert reconstructed.features.word_count == 42
        assert reconstructed.availability.avail_has_body is True

    def test_public_alias(self) -> None:
        assert TextAgentOutput is TextAgentResult
