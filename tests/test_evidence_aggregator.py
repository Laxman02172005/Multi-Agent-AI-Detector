"""
tests/test_evidence_aggregator.py
---------------------------------
Comprehensive test suite for Layer 2 Evidence Aggregator (app/aggregation/evidence_aggregator.py):
- Full 4-agent happy path execution (132 features, 0 missing, no abstention).
- Partial missing modalities (tolerating None agent inputs).
- Empty modality handling (zero URLs, no attachments).
- Error status resilience (single agent error without aggregator crash).
- Fail-closed validation (all None, mismatched email_id, empty email_id).
- Quarantined feature exclusion invariant.
- Vector ordering and determinism.
- Capacity cap enforcement (150 max items, omitted count tracking).
- Severity-ranked evidence sorting.
- End-to-end integration with all 4 Layer 1 agents on sample EML.
"""

from pathlib import Path
import pytest

from app.ingestion.email_ingestor import ingest_email
from app.agents.header_agent import analyze_headers
from app.agents.url_agent import analyze_urls, create_no_url_result
from app.agents.text_agent import analyze_text, create_no_body_result
from app.agents.attachment_agent import analyze_attachments, create_no_attachment_result
from app.aggregation.evidence_aggregator import (
    EvidenceAggregationError,
    aggregate_evidence,
)
from app.schemas.aggregator_schema import (
    ACTIVE_META_FEATURE_COUNT,
    ACTIVE_META_FEATURE_NAMES,
    HEADER_QUARANTINED_FEATURES,
    URL_QUARANTINED_FEATURES,
    AggregatedEvidenceResult,
    ModalityStatus,
    UnifiedEvidenceItem,
)
from app.schemas.text_agent_schema import TextEvidenceItem
from app.schemas.attachment_agent_schema import AttachmentEvidenceItem


SAMPLE_EML_PATH = Path(__file__).resolve().parent.parent / "data" / "samples" / "synthetic_demo.eml"


@pytest.fixture
def synthetic_email_data():
    raw_bytes = SAMPLE_EML_PATH.read_bytes()
    return ingest_email(raw_bytes)


@pytest.fixture
def all_four_agent_results(synthetic_email_data):
    h_res = analyze_headers(synthetic_email_data)
    u_res = analyze_urls(synthetic_email_data)
    t_res = analyze_text(synthetic_email_data)
    a_res = analyze_attachments(synthetic_email_data)
    return h_res, u_res, t_res, a_res


class TestInputValidationAndConsistency:
    def test_all_none_raises_aggregation_error(self):
        with pytest.raises(EvidenceAggregationError) as exc_info:
            aggregate_evidence(None, None, None, None)
        assert "at least one agent result" in str(exc_info.value).lower()

    def test_mismatched_email_id_raises_aggregation_error(self, all_four_agent_results):
        h_res, u_res, t_res, a_res = all_four_agent_results
        # Mutate email_id in copy of u_res
        u_dict = u_res.model_dump()
        u_dict["email_id"] = "mismatched_email_999"
        from app.schemas.url_agent_schema import UrlAgentResult
        bad_u_res = UrlAgentResult.model_validate(u_dict)

        with pytest.raises(EvidenceAggregationError) as exc_info:
            aggregate_evidence(h_res, bad_u_res, t_res, a_res)
        assert "mismatched email_id" in str(exc_info.value).lower()
        assert exc_info.value.email_id is not None

    def test_blank_email_id_raises_aggregation_error(self, all_four_agent_results):
        h_res, _, _, _ = all_four_agent_results
        h_dict = h_res.model_dump()
        h_dict["email_id"] = "   "
        from app.schemas.header_agent_schema import HeaderAgentResult
        bad_h_res = HeaderAgentResult.model_validate(h_dict)

        with pytest.raises(EvidenceAggregationError) as exc_info:
            aggregate_evidence(bad_h_res)
        assert "invalid email_id" in str(exc_info.value).lower()


class TestFeatureVectorAssembly:
    def test_vector_size_and_quarantined_exclusion(self, all_four_agent_results):
        h_res, u_res, t_res, a_res = all_four_agent_results
        result = aggregate_evidence(h_res, u_res, t_res, a_res)

        vec = result.feature_vector
        assert vec.active_feature_count == ACTIVE_META_FEATURE_COUNT == 132
        assert len(vec.feature_names) == 132
        assert len(vec.feature_values) == 132
        assert len(vec.missingness_mask) == 132

        # Quarantined features must NOT be in feature_names or keys
        for q in HEADER_QUARANTINED_FEATURES:
            assert f"header_{q}" not in vec.feature_names
            assert f"header_{q}" not in vec.feature_values
        for q in URL_QUARANTINED_FEATURES:
            assert f"url_{q}" not in vec.feature_names
            assert f"url_{q}" not in vec.feature_values

    def test_vector_determinism(self, all_four_agent_results):
        h_res, u_res, t_res, a_res = all_four_agent_results
        res1 = aggregate_evidence(h_res, u_res, t_res, a_res)
        res2 = aggregate_evidence(h_res, u_res, t_res, a_res)

        assert res1.feature_vector.feature_names == res2.feature_vector.feature_names
        assert res1.feature_vector.feature_values == res2.feature_vector.feature_values
        assert res1.feature_vector.missingness_mask == res2.feature_vector.missingness_mask
        assert res1.overall_completeness == res2.overall_completeness


class TestPartialAndEmptyModalityResilience:
    def test_header_only_execution(self, all_four_agent_results):
        h_res, _, _, _ = all_four_agent_results
        result = aggregate_evidence(header_result=h_res)

        assert result.status == "partial"
        assert result.modality_health["header"].status == ModalityStatus.AVAILABLE
        assert result.modality_health["url"].status == ModalityStatus.FAILED
        assert result.modality_health["text"].status == ModalityStatus.FAILED
        assert result.modality_health["attachment"].status == ModalityStatus.FAILED

        # URL, Text, Attachment features must be imputed to 0.0 with mask 1
        for f in result.feature_vector.feature_names:
            if f.startswith("url_") or f.startswith("text_") or f.startswith("attachment_"):
                assert result.feature_vector.feature_values[f] == 0.0
                assert result.feature_vector.missingness_mask[f] == 1

        # Header features should have observed mask == 0 where available
        assert result.feature_vector.missingness_mask["header_from_present"] == 0
        assert result.feature_vector.feature_values["header_from_present"] == 1.0

    def test_empty_modalities_handling(self, synthetic_email_data):
        h_res = analyze_headers(synthetic_email_data)
        t_res = analyze_text(synthetic_email_data)
        no_urls = create_no_url_result(synthetic_email_data.email_id)
        no_atts = create_no_attachment_result(synthetic_email_data.email_id)

        result = aggregate_evidence(h_res, no_urls, t_res, no_atts)

        assert result.modality_health["url"].status == ModalityStatus.EMPTY
        assert result.modality_health["attachment"].status == ModalityStatus.EMPTY
        assert result.modality_health["header"].status == ModalityStatus.AVAILABLE
        assert result.modality_health["text"].status == ModalityStatus.AVAILABLE

        # Both core modalities are AVAILABLE, so abstention should be False
        assert result.abstention_recommended_by_health is False

    def test_single_agent_error_status_resilience(self, all_four_agent_results):
        h_res, u_res, t_res, a_res = all_four_agent_results
        # Simulate URL agent failing with error status
        u_dict = u_res.model_dump()
        u_dict["status"] = "error"
        from app.schemas.url_agent_schema import UrlAgentResult
        failing_u_res = UrlAgentResult.model_validate(u_dict)

        result = aggregate_evidence(h_res, failing_u_res, t_res, a_res)
        assert result.status == "partial"
        assert result.modality_health["url"].status == ModalityStatus.FAILED
        assert result.modality_health["header"].status == ModalityStatus.AVAILABLE


class TestAbstentionPolicy:
    def test_abstention_triggered_when_both_core_modalities_fail(self, synthetic_email_data):
        u_res = analyze_urls(synthetic_email_data)
        a_res = analyze_attachments(synthetic_email_data)
        # Header and text missing -> both FAILED
        result = aggregate_evidence(header_result=None, url_result=u_res, text_result=None, attachment_result=a_res)

        assert result.abstention_recommended_by_health is True

    def test_abstention_triggered_when_completeness_too_low(self, synthetic_email_data):
        # Only attachment provided (weight = 0.10)
        a_res = analyze_attachments(synthetic_email_data)
        result = aggregate_evidence(attachment_result=a_res)

        assert result.overall_completeness <= 0.10
        assert result.abstention_recommended_by_health is True


class TestEvidenceSortingAndCapping:
    def test_evidence_capacity_cap_and_omitted_count(self, all_four_agent_results):
        h_res, u_res, t_res, a_res = all_four_agent_results

        # Inject 80 text items and 80 URL items (both under 100 agent cap, total 160 > 150 layer cap)
        t_dict = t_res.model_dump()
        t_items = [
            TextEvidenceItem(
                finding_id=f"overflow_t_ev_{i:03d}",
                feature_name="urgency_cue_count",
                category="Urgency",
                observed_value="urgent",
                description=f"Artificial urgent clue #{i}",
                snippet_bounded="Act immediately",
            )
            for i in range(80)
        ]
        t_dict["evidence"]["evidence_items"] = t_items
        from app.schemas.text_agent_schema import TextAgentResult
        overflow_t_res = TextAgentResult.model_validate(t_dict)

        u_dict = u_res.model_dump()
        from app.schemas.url_agent_schema import UrlEvidenceItem
        u_items = [
            UrlEvidenceItem(
                finding_id=f"overflow_u_ev_{i:03d}",
                feature_name="has_ip_literal_url",
                category="Category B",
                url_index=i,
                source="html_href",
                observed_value="192.168.1.1",
                description=f"Artificial IP literal clue #{i}",
                limitations_and_benign_explanations="Benign private network testing.",
                raw_snippet_bounded="http://192.168.1.1",
            )
            for i in range(80)
        ]
        u_dict["evidence"]["evidence_items"] = u_items
        from app.schemas.url_agent_schema import UrlAgentResult
        overflow_u_res = UrlAgentResult.model_validate(u_dict)

        result = aggregate_evidence(h_res, overflow_u_res, overflow_t_res, a_res)

        assert len(result.unified_evidence) == 150
        assert result.omitted_evidence_count > 0
        assert any("exceeded capacity" in w.lower() for w in result.warnings)

    def test_severity_sorting_order(self, synthetic_email_data):
        h_res = analyze_headers(synthetic_email_data)
        u_res = analyze_urls(synthetic_email_data)
        t_res = analyze_text(synthetic_email_data)
        a_res = analyze_attachments(synthetic_email_data)

        # Inject a critical attachment evidence item
        a_dict = a_res.model_dump()
        a_dict["evidence"]["evidence_items"].append(
            AttachmentEvidenceItem(
                finding_id="ev_critical_payload",
                feature_name="executable_attachment_count",
                category="Category A",
                attachment_index=0,
                observed_value="invoice.exe",
                description="Executable binary detected in payload",
                snippet_bounded="invoice.exe",
            )
        )
        from app.schemas.attachment_agent_schema import AttachmentAgentResult
        crit_a_res = AttachmentAgentResult.model_validate(a_dict)

        result = aggregate_evidence(h_res, u_res, t_res, crit_a_res)

        # First item in unified_evidence must be critical
        assert result.unified_evidence[0].severity == "critical"
        assert result.unified_evidence[0].finding_id == "ev_critical_payload"


class TestEndToEndIntegration:
    def test_end_to_end_pipeline_aggregation(self, synthetic_email_data):
        h_res = analyze_headers(synthetic_email_data)
        u_res = analyze_urls(synthetic_email_data)
        t_res = analyze_text(synthetic_email_data)
        a_res = analyze_attachments(synthetic_email_data)

        result = aggregate_evidence(h_res, u_res, t_res, a_res)

        assert isinstance(result, AggregatedEvidenceResult)
        assert result.email_id == synthetic_email_data.email_id
        assert result.status == "success"
        assert result.overall_completeness >= 0.50
        assert len(result.unified_evidence) > 0
        assert result.processing_time_ms >= 0.0

        # Validate JSON roundtrip
        json_str = result.model_dump_json(indent=2)
        loaded = AggregatedEvidenceResult.model_validate_json(json_str)
        assert loaded.email_id == result.email_id
        assert loaded.feature_vector.active_feature_count == 132
        assert loaded.modality_health["header"].status == ModalityStatus.AVAILABLE
