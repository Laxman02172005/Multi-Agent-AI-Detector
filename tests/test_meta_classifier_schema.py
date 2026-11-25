"""
tests/test_meta_classifier_schema.py
------------------------------------
Unit tests for Layer 3 Meta-Classifier schemas (app/schemas/meta_classifier_schema.py):
- Verdict and AbstentionReason enum coverage.
- DecisionThresholds validation (ordering, bounds, extra fields).
- FeatureContribution schema constraints and extra-field rejection.
- MetaClassifierResult complete model validation, capacity bounds, and JSON roundtrip.
"""

import pytest
from pydantic import ValidationError

from app.schemas.meta_classifier_schema import (
    AbstentionReason,
    DecisionThresholds,
    FeatureContribution,
    MetaClassifierResult,
    Verdict,
)


class TestVerdictAndAbstentionReason:
    def test_verdict_values(self):
        assert Verdict.PHISHING.value == "phishing"
        assert Verdict.LEGITIMATE.value == "legitimate"
        assert Verdict.ABSTAIN.value == "abstain"

    def test_abstention_reason_values(self):
        assert AbstentionReason.NONE.value == "none"
        assert AbstentionReason.INSUFFICIENT_MODALITY_HEALTH.value == "insufficient_modality_health"
        assert AbstentionReason.UNCERTAINTY_BAND.value == "uncertainty_band"
        assert AbstentionReason.MODEL_DEGRADED.value == "model_degraded"


class TestDecisionThresholds:
    def test_defaults(self):
        dt = DecisionThresholds()
        assert dt.abstain_low == 0.35
        assert dt.abstain_high == 0.65

    def test_custom_valid(self):
        dt = DecisionThresholds(abstain_low=0.20, abstain_high=0.80)
        assert dt.abstain_low == 0.20
        assert dt.abstain_high == 0.80

    def test_invalid_reversed_thresholds(self):
        with pytest.raises(ValidationError):
            DecisionThresholds(abstain_low=0.70, abstain_high=0.30)

    def test_invalid_equal_thresholds(self):
        with pytest.raises(ValidationError):
            DecisionThresholds(abstain_low=0.50, abstain_high=0.50)

    def test_out_of_bounds(self):
        with pytest.raises(ValidationError):
            DecisionThresholds(abstain_low=0.0, abstain_high=0.8)
        with pytest.raises(ValidationError):
            DecisionThresholds(abstain_low=0.2, abstain_high=1.0)

    def test_forbids_extra(self):
        with pytest.raises(ValidationError):
            DecisionThresholds(abstain_low=0.3, abstain_high=0.7, extra_param=123)


class TestFeatureContribution:
    def test_valid_contribution(self):
        fc = FeatureContribution(
            feature_name="url_has_ip_literal_url",
            modality="url",
            feature_value=1.0,
            contribution_score=1.45,
        )
        assert fc.feature_name == "url_has_ip_literal_url"
        assert fc.modality == "url"
        assert fc.contribution_score == 1.45

    def test_negative_contribution(self):
        fc = FeatureContribution(
            feature_name="header_spf_status",
            modality="header",
            feature_value=1.0,
            contribution_score=-0.85,
        )
        assert fc.contribution_score == -0.85

    def test_forbids_extra(self):
        with pytest.raises(ValidationError):
            FeatureContribution(
                feature_name="text_urgency_cue_count",
                modality="text",
                feature_value=3.0,
                contribution_score=0.9,
                unexpected="extra",
            )


class TestMetaClassifierResult:
    def test_valid_phishing_result(self):
        res = MetaClassifierResult(
            email_id="email_meta_test_01",
            verdict=Verdict.PHISHING,
            calibrated_probability=0.88,
            confidence=0.76,
            abstention_reason=AbstentionReason.NONE,
            top_phishing_contributors=[
                FeatureContribution(
                    feature_name="url_has_ip_literal_url",
                    modality="url",
                    feature_value=1.0,
                    contribution_score=1.85,
                )
            ],
            top_legitimate_contributors=[],
            overall_completeness=0.85,
            model_version="meta_logreg_v1.0.0",
            processing_time_ms=2.5,
        )
        assert res.verdict == Verdict.PHISHING
        assert res.calibrated_probability == 0.88
        assert res.abstention_reason == AbstentionReason.NONE
        assert len(res.top_phishing_contributors) == 1

    def test_valid_health_abstention_result(self):
        res = MetaClassifierResult(
            email_id="email_abstain_01",
            verdict=Verdict.ABSTAIN,
            calibrated_probability=None,
            confidence=0.0,
            abstention_reason=AbstentionReason.INSUFFICIENT_MODALITY_HEALTH,
            top_phishing_contributors=[],
            top_legitimate_contributors=[],
            overall_completeness=0.20,
            model_version="meta_logreg_v1.0.0",
            processing_time_ms=0.5,
        )
        assert res.verdict == Verdict.ABSTAIN
        assert res.calibrated_probability is None
        assert res.abstention_reason == AbstentionReason.INSUFFICIENT_MODALITY_HEALTH

    def test_contributor_capacity_cap(self):
        # 11 items should trigger validation error (max_length=10)
        contributors = [
            FeatureContribution(
                feature_name=f"feature_{i}",
                modality="text",
                feature_value=1.0,
                contribution_score=0.5,
            )
            for i in range(11)
        ]
        with pytest.raises(ValidationError):
            MetaClassifierResult(
                email_id="email_overflow",
                verdict=Verdict.PHISHING,
                calibrated_probability=0.9,
                confidence=0.8,
                abstention_reason=AbstentionReason.NONE,
                top_phishing_contributors=contributors,
                overall_completeness=1.0,
                model_version="meta_logreg_v1.0.0",
                processing_time_ms=1.0,
            )

    def test_json_roundtrip_serialization(self):
        res = MetaClassifierResult(
            email_id="email_roundtrip_01",
            verdict=Verdict.LEGITIMATE,
            calibrated_probability=0.05,
            confidence=0.90,
            abstention_reason=AbstentionReason.NONE,
            top_phishing_contributors=[],
            top_legitimate_contributors=[
                FeatureContribution(
                    feature_name="header_spf_status",
                    modality="header",
                    feature_value=1.0,
                    contribution_score=-1.2,
                )
            ],
            overall_completeness=0.92,
            model_version="meta_logreg_v1.0.0",
            processing_time_ms=1.8,
        )
        json_data = res.model_dump_json()
        loaded = MetaClassifierResult.model_validate_json(json_data)
        assert loaded.email_id == res.email_id
        assert loaded.verdict == Verdict.LEGITIMATE
        assert loaded.calibrated_probability == 0.05
        assert len(loaded.top_legitimate_contributors) == 1
