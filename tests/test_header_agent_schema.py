"""
tests/test_header_agent_schema.py
---------------------------------
Unit tests for Header Agent Pydantic v2 schemas:
- CANONICAL_HEADER_FEATURE_NAMES & CANONICAL_HEADER_FEATURE_LIST
- HeaderFeatures (45 features)
- HeaderFeatureAvailability
- HeaderEvidenceItem & HeaderEvidence
- HeaderRiskAssessment
- HeaderAgentResult / HeaderAgentOutput
"""

import json
import pytest
from pydantic import ValidationError

from app.schemas.email_schema import AuthStatus, VerificationStatus
from app.schemas.header_agent_schema import (
    CANONICAL_HEADER_FEATURE_LIST,
    CANONICAL_HEADER_FEATURE_NAMES,
    HeaderAgentOutput,
    HeaderAgentResult,
    HeaderEvidence,
    HeaderEvidenceItem,
    HeaderFeatureAvailability,
    HeaderFeatures,
    HeaderRiskAssessment,
)


class TestCanonicalFeatureRegistry:
    def test_canonical_feature_list_length(self):
        """Must have exactly 45 features."""
        assert len(CANONICAL_HEADER_FEATURE_LIST) == 45

    def test_canonical_feature_list_no_duplicates(self):
        """All 45 features must be distinct."""
        assert len(set(CANONICAL_HEADER_FEATURE_LIST)) == 45

    def test_canonical_category_partitions(self):
        """Category partitions: 13 Category A, 10 Category B, 13 Category C, 9 Category D."""
        cat_a = CANONICAL_HEADER_FEATURE_LIST[0:13]
        cat_b = CANONICAL_HEADER_FEATURE_LIST[13:23]
        cat_c = CANONICAL_HEADER_FEATURE_LIST[23:36]
        cat_d = CANONICAL_HEADER_FEATURE_LIST[36:45]

        assert len(cat_a) == 13
        assert len(cat_b) == 10
        assert len(cat_c) == 13
        assert len(cat_d) == 9

        assert "from_present" in cat_a
        assert "from_syntax_valid" in cat_a
        assert "received_hop_count" in cat_b
        assert "hop_count_anomaly" in cat_b
        assert "spf_status" in cat_c
        assert "authserv_id_inconsistent" in cat_c
        assert "message_id_present" in cat_d
        assert "content_type_is_multipart" in cat_d

    def test_quarantined_features_presence(self):
        """Features 11, 12, 21, 22 must be present in canonical registry."""
        assert CANONICAL_HEADER_FEATURE_LIST[10] == "undisclosed_recipients"
        assert CANONICAL_HEADER_FEATURE_LIST[11] == "to_empty_or_missing"
        assert CANONICAL_HEADER_FEATURE_LIST[20] == "transit_delay_seconds"
        assert CANONICAL_HEADER_FEATURE_LIST[21] == "transit_delay_unavailable"


def _sample_valid_header_features() -> HeaderFeatures:
    return HeaderFeatures(
        # Cat A
        from_present=True,
        from_address_count=1,
        reply_to_present=True,
        return_path_present=True,
        from_reply_to_domain_mismatch=False,
        from_return_path_domain_mismatch=False,
        display_name_contains_email=False,
        display_name_domain_mismatch=False,
        recipient_count_to=1,
        recipient_count_cc=0,
        undisclosed_recipients=None,
        to_empty_or_missing=None,
        from_syntax_valid=True,
        # Cat B
        received_hop_count=2,
        has_private_ip_in_external_hop=False,
        has_loopback_ip_in_external_hop=False,
        has_link_local_ip_in_external_hop=False,
        has_special_ip_in_external_hop=False,
        received_syntax_malformed_count=0,
        missing_received_headers=False,
        transit_delay_seconds=None,
        transit_delay_unavailable=True,
        hop_count_anomaly=False,
        # Cat C
        spf_status=AuthStatus.PASS,
        dkim_status=AuthStatus.PASS,
        dmarc_status=AuthStatus.PASS,
        spf_claim_count=1,
        dkim_claim_count=1,
        dmarc_claim_count=1,
        has_conflicting_spf=False,
        has_conflicting_dkim=False,
        has_conflicting_dmarc=False,
        dkim_signature_header_present=True,
        dkim_signature_present_without_pass=False,
        authserv_id_count=1,
        authserv_id_inconsistent=False,
        # Cat D
        message_id_present=True,
        message_id_valid_syntax=True,
        message_id_domain_mismatch=False,
        mime_version_present=True,
        mime_version_valid=True,
        has_subject_header=True,
        subject_length=15,
        content_type_present=True,
        content_type_is_multipart=False,
    )


def _sample_valid_availability() -> HeaderFeatureAvailability:
    return HeaderFeatureAvailability(
        avail_from_present=True,
        avail_reply_to_present=True,
        avail_return_path_present=True,
        avail_to_present=True,
        avail_cc_present=False,
        avail_received_hops=True,
        avail_auth_claims=True,
        avail_message_id_present=True,
        avail_mime_version_present=True,
        avail_subject_present=True,
        avail_content_type_present=True,
        avail_from_parsed=True,
        avail_from_syntax=True,
        avail_reply_to_parsed=True,
        avail_return_path_parsed=True,
        avail_to_parsed=True,
        avail_cc_parsed=False,
        avail_from_reply_to_domain_mismatch=True,
        avail_from_return_path_domain_mismatch=True,
        avail_display_name_domain_mismatch=False,
        avail_undisclosed_recipients=False,
        avail_to_empty_or_missing=False,
        avail_transit_delay=False,
        avail_spf_status=True,
        avail_dkim_status=True,
        avail_dmarc_status=True,
        avail_message_id_valid_syntax=True,
        avail_message_id_domain_mismatch=True,
        avail_mime_version_valid=True,
        avail_content_type_is_multipart=True,
        completeness_identity=1.0,
        completeness_routing=0.6,
        completeness_auth=1.0,
        completeness_metadata=1.0,
        completeness_total=0.9,
    )


class TestHeaderFeaturesModel:
    def test_instantiation_success(self):
        feat = _sample_valid_header_features()
        assert feat.from_present is True
        assert feat.from_address_count == 1
        assert feat.spf_status == AuthStatus.PASS

    def test_feature_count_equals_45(self):
        fields = HeaderFeatures.model_fields
        assert len(fields) == 45
        assert set(fields.keys()) == set(CANONICAL_HEADER_FEATURE_LIST)

    def test_extra_fields_forbidden(self):
        data = _sample_valid_header_features().model_dump()
        data["extra_unauthorized_feature"] = 123
        with pytest.raises(ValidationError):
            HeaderFeatures(**data)

    def test_nullable_features_accept_none(self):
        feat = HeaderFeatures(
            from_present=False,
            from_address_count=None,
            reply_to_present=False,
            return_path_present=False,
            from_reply_to_domain_mismatch=None,
            from_return_path_domain_mismatch=None,
            display_name_contains_email=False,
            display_name_domain_mismatch=None,
            recipient_count_to=None,
            recipient_count_cc=None,
            undisclosed_recipients=None,
            to_empty_or_missing=None,
            from_syntax_valid=None,
            received_hop_count=0,
            has_private_ip_in_external_hop=False,
            has_loopback_ip_in_external_hop=False,
            has_link_local_ip_in_external_hop=False,
            has_special_ip_in_external_hop=False,
            received_syntax_malformed_count=0,
            missing_received_headers=True,
            transit_delay_seconds=None,
            transit_delay_unavailable=True,
            hop_count_anomaly=True,
            spf_status=AuthStatus.MISSING,
            dkim_status=AuthStatus.MISSING,
            dmarc_status=AuthStatus.MISSING,
            spf_claim_count=0,
            dkim_claim_count=0,
            dmarc_claim_count=0,
            has_conflicting_spf=False,
            has_conflicting_dkim=False,
            has_conflicting_dmarc=False,
            dkim_signature_header_present=False,
            dkim_signature_present_without_pass=False,
            authserv_id_count=0,
            authserv_id_inconsistent=False,
            message_id_present=False,
            message_id_valid_syntax=None,
            message_id_domain_mismatch=None,
            mime_version_present=False,
            mime_version_valid=None,
            has_subject_header=False,
            subject_length=0,
            content_type_present=False,
            content_type_is_multipart=None,
        )
        assert feat.from_address_count is None
        assert feat.from_reply_to_domain_mismatch is None
        assert feat.message_id_valid_syntax is None


class TestHeaderFeatureAvailability:
    def test_instantiation_success(self):
        avail = _sample_valid_availability()
        assert avail.avail_from_present is True
        assert avail.completeness_total == 0.9

    def test_completeness_bounds(self):
        with pytest.raises(ValidationError):
            data = _sample_valid_availability().model_dump()
            data["completeness_identity"] = 1.5
            HeaderFeatureAvailability(**data)

        with pytest.raises(ValidationError):
            data = _sample_valid_availability().model_dump()
            data["completeness_routing"] = -0.1
            HeaderFeatureAvailability(**data)

    def test_extra_fields_forbidden(self):
        data = _sample_valid_availability().model_dump()
        data["extra_flag"] = True
        with pytest.raises(ValidationError):
            HeaderFeatureAvailability(**data)


class TestHeaderEvidenceModels:
    def test_evidence_item_valid(self):
        item = HeaderEvidenceItem(
            feature_name="from_reply_to_domain_mismatch",
            header_name="Reply-To",
            header_index=0,
            description="Reply-To domain 'attacker.com' mismatches From domain 'example.com'",
            raw_snippet_bounded="Reply-To: bad@attacker.com",
        )
        assert item.verification_status == VerificationStatus.UNVERIFIED
        assert item.feature_name == "from_reply_to_domain_mismatch"

    def test_evidence_item_raw_snippet_max_length(self):
        # 256 chars is ok
        snippet_256 = "x" * 256
        item = HeaderEvidenceItem(
            feature_name="received_hop_count",
            header_name="Received",
            description="Hop details",
            raw_snippet_bounded=snippet_256,
        )
        assert len(item.raw_snippet_bounded) == 256

        # 257 chars must fail validation
        with pytest.raises(ValidationError):
            HeaderEvidenceItem(
                feature_name="received_hop_count",
                header_name="Received",
                description="Hop details",
                raw_snippet_bounded="x" * 257,
            )

    def test_evidence_item_invalid_feature_name(self):
        with pytest.raises(ValidationError):
            HeaderEvidenceItem(
                feature_name="nonexistent_feature",  # type: ignore
                header_name="From",
                description="Invalid feature test",
            )

    def test_evidence_container_limits(self):
        evidence = HeaderEvidence(
            evidence_items=[
                HeaderEvidenceItem(
                    feature_name="from_present",
                    header_name="From",
                    description="From present",
                )
            ],
            parsed_authserv_ids=["mx.google.com"],
            detected_anomalous_ips=["192.168.1.1"],
            observed_anomalies=["Private IP in transit"],
        )
        assert len(evidence.evidence_items) == 1
        assert len(evidence.parsed_authserv_ids) == 1

        # Max length violation on evidence items (>100)
        items_101 = [
            HeaderEvidenceItem(
                feature_name="from_present",
                header_name="From",
                description=f"Item {i}",
            )
            for i in range(101)
        ]
        with pytest.raises(ValidationError):
            HeaderEvidence(evidence_items=items_101)


class TestHeaderRiskAssessment:
    def test_valid_risk_assessment(self):
        risk = HeaderRiskAssessment(
            calibrated_phishing_probability=0.8,
            decision_margin=0.6,  # 2 * |0.8 - 0.5| = 0.6
        )
        assert risk.calibrated_phishing_probability == 0.8
        assert risk.decision_margin == 0.6
        assert risk.abstain is False

    def test_invalid_decision_margin_formula(self):
        with pytest.raises(ValidationError) as excinfo:
            HeaderRiskAssessment(
                calibrated_phishing_probability=0.8,
                decision_margin=0.9,  # Should be 0.6
            )
        assert "decision_margin" in str(excinfo.value)


class TestHeaderAgentResult:
    def test_result_creation_and_alias(self):
        res = HeaderAgentResult(
            email_id="email_12345",
            features=_sample_valid_header_features(),
            availability=_sample_valid_availability(),
            evidence=HeaderEvidence(),
            warnings=["Test warning"],
            limitations=["Offline unverified claims"],
            processing_time_ms=12.5,
        )
        assert res.agent_name == "header_agent"
        assert res.agent_version == "0.1.0"
        assert res.status == "success"
        assert res.email_id == "email_12345"
        assert res.processing_time_ms == 12.5
        assert HeaderAgentOutput is HeaderAgentResult

    def test_json_roundtrip(self):
        res = HeaderAgentResult(
            email_id="email_roundtrip",
            features=_sample_valid_header_features(),
            availability=_sample_valid_availability(),
            evidence=HeaderEvidence(),
        )
        raw_json = res.model_dump_json()
        data = json.loads(raw_json)
        assert data["email_id"] == "email_roundtrip"
        assert data["features"]["from_present"] is True

        # Parse back
        res2 = HeaderAgentResult.model_validate_json(raw_json)
        assert res2.email_id == "email_roundtrip"
        assert res2.features.spf_status == AuthStatus.PASS
