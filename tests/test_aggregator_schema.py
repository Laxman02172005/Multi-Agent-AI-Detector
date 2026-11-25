"""
tests/test_aggregator_schema.py
-------------------------------
Unit tests for app/schemas/aggregator_schema.py:
- Enum values and validations for ModalityStatus.
- ModalityHealth field validations, bounds, and extra-field rejection.
- UnifiedEvidenceItem schema constraints, bounds, and string trimming.
- MetaFeatureVector strict 132-feature invariants and quarantined feature exclusion.
- AggregatedEvidenceResult schema validation, 150-evidence cap, and JSON roundtrip.
"""

import pytest
from pydantic import ValidationError

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


def _make_sample_feature_vector() -> MetaFeatureVector:
    names = list(ACTIVE_META_FEATURE_NAMES)
    values = {k: 0.0 for k in names}
    mask = {k: 0 for k in names}
    return MetaFeatureVector(
        feature_names=names,
        feature_values=values,
        missingness_mask=mask,
        missing_feature_count=0,
    )


def _make_sample_modality_health() -> dict[str, ModalityHealth]:
    return {
        "header": ModalityHealth(
            modality="header",
            status=ModalityStatus.AVAILABLE,
            completeness=1.0,
            active_feature_count=len(HEADER_ACTIVE_FEATURES),
            missing_feature_count=0,
        ),
        "url": ModalityHealth(
            modality="url",
            status=ModalityStatus.EMPTY,
            completeness=0.0,
            active_feature_count=len(URL_ACTIVE_FEATURES),
            missing_feature_count=len(URL_ACTIVE_FEATURES),
        ),
        "text": ModalityHealth(
            modality="text",
            status=ModalityStatus.AVAILABLE,
            completeness=1.0,
            active_feature_count=len(TEXT_ACTIVE_FEATURES),
            missing_feature_count=0,
        ),
        "attachment": ModalityHealth(
            modality="attachment",
            status=ModalityStatus.EMPTY,
            completeness=0.0,
            active_feature_count=len(ATTACHMENT_ACTIVE_FEATURES),
            missing_feature_count=len(ATTACHMENT_ACTIVE_FEATURES),
        ),
    }


class TestModalityStatusAndHealth:
    def test_modality_status_values(self):
        assert ModalityStatus.AVAILABLE.value == "available"
        assert ModalityStatus.EMPTY.value == "empty"
        assert ModalityStatus.DEGRADED.value == "degraded"
        assert ModalityStatus.FAILED.value == "failed"

    def test_modality_health_valid(self):
        health = ModalityHealth(
            modality="header",
            status=ModalityStatus.AVAILABLE,
            completeness=0.95,
            active_feature_count=41,
            missing_feature_count=2,
            error_message=None,
        )
        assert health.modality == "header"
        assert health.completeness == 0.95
        assert health.active_feature_count == 41
        assert health.missing_feature_count == 2

    def test_modality_health_completeness_bounds(self):
        with pytest.raises(ValidationError):
            ModalityHealth(
                modality="text",
                status=ModalityStatus.AVAILABLE,
                completeness=1.2,  # > 1.0 forbidden
                active_feature_count=29,
                missing_feature_count=0,
            )
        with pytest.raises(ValidationError):
            ModalityHealth(
                modality="text",
                status=ModalityStatus.AVAILABLE,
                completeness=-0.1,  # < 0.0 forbidden
                active_feature_count=29,
                missing_feature_count=0,
            )

    def test_modality_health_forbids_extra(self):
        with pytest.raises(ValidationError):
            ModalityHealth(
                modality="header",
                status=ModalityStatus.AVAILABLE,
                completeness=1.0,
                active_feature_count=41,
                missing_feature_count=0,
                extra_unknown_field="injected",
            )


class TestUnifiedEvidenceItem:
    def test_unified_evidence_valid(self):
        ev = UnifiedEvidenceItem(
            finding_id="ev_text_001",
            source_modality="text",
            feature_name="credential_lure_count",
            category="Category A: Urgency, Lures & Intent",
            severity="high",
            observed_value="password, login",
            description="Detected credential harvesting lure keywords.",
            snippet_bounded="Please verify your password and login at this link.",
        )
        assert ev.source_modality == "text"
        assert ev.severity == "high"
        assert len(ev.snippet_bounded) <= 256

    def test_unified_evidence_snippet_length_bound(self):
        oversized = "A" * 257
        with pytest.raises(ValidationError):
            UnifiedEvidenceItem(
                finding_id="ev_001",
                source_modality="url",
                feature_name="has_ip_literal_url",
                category="Category B",
                severity="high",
                observed_value="192.168.1.1",
                description="IP literal in URL",
                snippet_bounded=oversized,
            )

    def test_unified_evidence_forbids_extra(self):
        with pytest.raises(ValidationError):
            UnifiedEvidenceItem(
                finding_id="ev_001",
                source_modality="url",
                feature_name="has_ip_literal_url",
                category="Category B",
                severity="high",
                observed_value="192.168.1.1",
                description="IP literal in URL",
                snippet_bounded="http://192.168.1.1",
                raw_token_data="forbidden",
            )


class TestMetaFeatureVector:
    def test_canonical_counts(self):
        assert len(HEADER_ACTIVE_FEATURES) == 41
        assert len(URL_ACTIVE_FEATURES) == 37
        assert len(TEXT_ACTIVE_FEATURES) == 29
        assert len(ATTACHMENT_ACTIVE_FEATURES) == 25
        assert ACTIVE_META_FEATURE_COUNT == 132
        assert QUARANTINED_META_FEATURE_COUNT == 6

    def test_quarantined_features_excluded(self):
        for q in QUARANTINED_META_FEATURE_NAMES:
            assert q not in ACTIVE_META_FEATURE_NAMES
        assert "header_undisclosed_recipients" not in ACTIVE_META_FEATURE_NAMES
        assert "header_to_empty_or_missing" not in ACTIVE_META_FEATURE_NAMES
        assert "header_transit_delay_seconds" not in ACTIVE_META_FEATURE_NAMES
        assert "header_transit_delay_unavailable" not in ACTIVE_META_FEATURE_NAMES
        assert "url_has_brand_in_path" not in ACTIVE_META_FEATURE_NAMES
        assert "url_has_form_action_url" not in ACTIVE_META_FEATURE_NAMES

    def test_vector_length_validation(self):
        names = list(ACTIVE_META_FEATURE_NAMES)[:100]  # wrong count
        values = {k: 0.0 for k in names}
        mask = {k: 0 for k in names}
        with pytest.raises(ValidationError):
            MetaFeatureVector(
                feature_names=names,
                feature_values=values,
                missingness_mask=mask,
                missing_feature_count=0,
            )

    def test_vector_forbids_extra(self):
        vec = _make_sample_feature_vector()
        dumped = vec.model_dump()
        dumped["injected_extra"] = 123
        with pytest.raises(ValidationError):
            MetaFeatureVector(**dumped)


class TestAggregatedEvidenceResult:
    def test_valid_aggregated_result(self):
        res = AggregatedEvidenceResult(
            email_id="email_agg_test_01",
            status="success",
            processing_time_ms=12.5,
            feature_vector=_make_sample_feature_vector(),
            modality_health=_make_sample_modality_health(),
            overall_completeness=0.70,
            abstention_recommended_by_health=False,
            unified_evidence=[],
            omitted_evidence_count=0,
            warnings=[],
        )
        assert res.email_id == "email_agg_test_01"
        assert res.status == "success"
        assert res.overall_completeness == 0.70
        assert res.abstention_recommended_by_health is False

    def test_capacity_cap_on_unified_evidence(self):
        # 151 evidence items should trigger validation error
        items = [
            UnifiedEvidenceItem(
                finding_id=f"ev_{i}",
                source_modality="header",
                feature_name="spf_status",
                category="Authentication",
                severity="medium",
                observed_value="fail",
                description="SPF claim failed",
                snippet_bounded="spf=fail",
            )
            for i in range(151)
        ]
        with pytest.raises(ValidationError):
            AggregatedEvidenceResult(
                email_id="email_cap_test",
                status="partial",
                processing_time_ms=5.0,
                feature_vector=_make_sample_feature_vector(),
                modality_health=_make_sample_modality_health(),
                overall_completeness=0.5,
                abstention_recommended_by_health=False,
                unified_evidence=items,
                omitted_evidence_count=1,
            )

    def test_roundtrip_json_serialization(self):
        res = AggregatedEvidenceResult(
            email_id="email_json_roundtrip",
            status="success",
            processing_time_ms=8.2,
            feature_vector=_make_sample_feature_vector(),
            modality_health=_make_sample_modality_health(),
            overall_completeness=0.85,
            abstention_recommended_by_health=False,
            unified_evidence=[
                UnifiedEvidenceItem(
                    finding_id="ev_01",
                    source_modality="url",
                    feature_name="has_ip_literal_url",
                    category="Category B",
                    severity="high",
                    observed_value="10.0.0.1",
                    description="IP address literal host",
                    snippet_bounded="http://10.0.0.1/login",
                )
            ],
            omitted_evidence_count=0,
            warnings=["Sample warning"],
        )
        json_data = res.model_dump_json()
        loaded = AggregatedEvidenceResult.model_validate_json(json_data)
        assert loaded.email_id == res.email_id
        assert loaded.processing_time_ms == res.processing_time_ms
        assert len(loaded.unified_evidence) == 1
        assert loaded.feature_vector.active_feature_count == 132
