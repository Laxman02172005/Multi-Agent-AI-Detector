"""
tests/test_attachment_agent_schema.py
--------------------------------------
Comprehensive unit tests for the Attachment Agent Pydantic v2 schemas:
- Canonical feature registry (25 features)
- Category partitions (Category A: 6, Category B: 8, Category C: 5, Category D: 6)
- Feature to category mapping
- Sanitized Tier 3 feature vector (AttachmentFeatures)
- Availability and completeness manifest (AttachmentFeatureAvailability)
- Granular per-attachment inspection record (AttachmentAnalysisItem)
- Evidence item and container contracts (AttachmentEvidenceItem, AttachmentEvidence)
- Result container serialization and alias (AttachmentAgentResult / AttachmentAgentOutput)
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.attachment_agent_schema import (
    ATTACHMENT_FEATURE_TO_CATEGORY_MAP,
    CANONICAL_ATTACHMENT_FEATURE_LIST,
    CANONICAL_ATTACHMENT_FEATURE_NAMES,
    CANONICAL_ATTACHMENT_FEATURE_NAMES_SET,
    CATEGORY_A_ATTACHMENT_FEATURES,
    CATEGORY_B_ATTACHMENT_FEATURES,
    CATEGORY_C_ATTACHMENT_FEATURES,
    CATEGORY_D_ATTACHMENT_FEATURES,
    AttachmentAgentOutput,
    AttachmentAgentResult,
    AttachmentAnalysisItem,
    AttachmentEvidence,
    AttachmentEvidenceItem,
    AttachmentFeatureAvailability,
    AttachmentFeatures,
)


class TestCanonicalAttachmentFeatureRegistry:
    def test_canonical_feature_list_length(self) -> None:
        """Must contain exactly 25 distinct canonical features."""
        assert len(CANONICAL_ATTACHMENT_FEATURE_LIST) == 25
        assert len(set(CANONICAL_ATTACHMENT_FEATURE_LIST)) == 25
        assert len(CANONICAL_ATTACHMENT_FEATURE_NAMES_SET) == 25

    def test_category_partitions(self) -> None:
        """Category partitions must match 6 + 8 + 5 + 6 = 25 exactly."""
        assert len(CATEGORY_A_ATTACHMENT_FEATURES) == 6
        assert len(CATEGORY_B_ATTACHMENT_FEATURES) == 8
        assert len(CATEGORY_C_ATTACHMENT_FEATURES) == 5
        assert len(CATEGORY_D_ATTACHMENT_FEATURES) == 6

        concatenated = (
            CATEGORY_A_ATTACHMENT_FEATURES
            + CATEGORY_B_ATTACHMENT_FEATURES
            + CATEGORY_C_ATTACHMENT_FEATURES
            + CATEGORY_D_ATTACHMENT_FEATURES
        )
        assert concatenated == CANONICAL_ATTACHMENT_FEATURE_LIST

    def test_feature_to_category_mapping(self) -> None:
        """Every canonical feature must map to its assigned category partition."""
        assert len(ATTACHMENT_FEATURE_TO_CATEGORY_MAP) == 25
        for feat in CANONICAL_ATTACHMENT_FEATURE_LIST:
            assert feat in ATTACHMENT_FEATURE_TO_CATEGORY_MAP
            cat = ATTACHMENT_FEATURE_TO_CATEGORY_MAP[feat]
            assert cat.startswith("Category ")


class TestAttachmentFeaturesModel:
    def test_default_instantiation(self) -> None:
        """AttachmentFeatures defaults must have zero counts and False flags."""
        feat = AttachmentFeatures()
        assert feat.total_attachment_count == 0
        assert feat.has_attachments is False
        assert feat.has_executable_attachment is False
        assert feat.executable_attachment_count == 0
        assert feat.has_macro_enabled_attachment is False
        assert feat.macro_enabled_count == 0

        assert feat.has_html_smuggling_attachment is False
        assert feat.html_smuggling_count == 0
        assert feat.has_double_extension is False
        assert feat.double_extension_count == 0
        assert feat.has_rlo_spoofing is False
        assert feat.rlo_spoofing_count == 0
        assert feat.has_mime_mismatch is False
        assert feat.mime_mismatch_count == 0

        assert feat.has_archive_attachment is False
        assert feat.archive_attachment_count == 0
        assert feat.has_disk_image is False
        assert feat.has_encrypted_archive is False
        assert feat.has_suspicious_archive is False

        assert feat.total_attachment_size_bytes == 0
        assert feat.max_attachment_size_bytes == 0
        assert feat.has_oversized_attachment is False
        assert feat.has_zero_byte_attachment is False
        assert feat.has_skipped_attachments is False
        assert feat.skipped_attachment_count == 0

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            AttachmentFeatures(unexpected_field="disallowed")  # type: ignore

    def test_negative_count_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AttachmentFeatures(executable_attachment_count=-1)


class TestAttachmentFeatureAvailabilityModel:
    def test_default_availability(self) -> None:
        avail = AttachmentFeatureAvailability()
        assert avail.avail_has_attachments is False
        assert avail.avail_metadata_features is False
        assert avail.avail_mime_classification is False
        assert avail.completeness_risk_types == 0.0
        assert avail.completeness_spoofing == 0.0
        assert avail.completeness_container == 0.0
        assert avail.completeness_total == 0.0


class TestAttachmentAnalysisItemModel:
    def test_valid_analysis_item(self) -> None:
        item = AttachmentAnalysisItem(
            attachment_index=0,
            filename_snippet="invoice.pdf",
            content_type="application/pdf",
            extension="pdf",
            size_bytes=1024,
            is_executable=False,
            is_macro_enabled=False,
            is_html_smuggling=False,
            has_double_extension=False,
            has_rlo_spoofing=False,
            has_mime_mismatch=False,
            is_archive=False,
            is_disk_image=False,
            is_encrypted=False,
            status="processed",
        )
        assert item.filename_snippet == "invoice.pdf"
        assert item.extension == "pdf"


class TestAttachmentEvidenceModels:
    def test_evidence_item_valid(self) -> None:
        item = AttachmentEvidenceItem(
            finding_id="att_001",
            feature_name="has_executable_attachment",
            category="Category A: High-Risk Types & Scripts",
            attachment_index=0,
            observed_value=".exe",
            description="Executable attachment detected.",
            snippet_bounded="malware.exe",
        )
        assert item.finding_id == "att_001"
        assert item.observed_value == ".exe"

    def test_evidence_container_caps(self) -> None:
        items = [
            AttachmentEvidenceItem(
                finding_id=f"att_{i}",
                feature_name="has_executable_attachment",
                category="Category A",
                attachment_index=i,
                observed_value=".exe",
                description="test",
                snippet_bounded="test",
            )
            for i in range(100)
        ]
        evidence = AttachmentEvidence(evidence_items=items, omitted_evidence_count=10)
        assert len(evidence.evidence_items) == 100
        assert evidence.omitted_evidence_count == 10


class TestAttachmentAgentResultSerialization:
    def test_serialization_roundtrip(self) -> None:
        result = AttachmentAgentResult(
            email_id="email_att_001",
            agent_name="attachment_agent",
            agent_version="1.0.0",
            status="success",
            processing_time_ms=2.5,
            total_attachments_evaluated=1,
            features=AttachmentFeatures(has_attachments=True, total_attachment_count=1),
            availability=AttachmentFeatureAvailability(avail_has_attachments=True, completeness_total=1.0),
            evidence=AttachmentEvidence(evidence_items=[]),
            analysis_items=[],
            warnings=[],
            limitations=[],
        )
        dumped = result.model_dump()
        reconstructed = AttachmentAgentResult.model_validate(dumped)
        assert reconstructed.email_id == "email_att_001"
        assert reconstructed.features.total_attachment_count == 1

    def test_public_alias(self) -> None:
        assert AttachmentAgentOutput is AttachmentAgentResult
