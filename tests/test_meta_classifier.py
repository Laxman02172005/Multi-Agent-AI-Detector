"""
tests/test_meta_classifier.py
-----------------------------
Comprehensive tests for Layer 3 Meta-Classifier (app/meta_classifier/):
- Training, probability calibration, and versioned persistence.
- Cryptographic SHA-256 integrity verification and tamper detection.
- Fail-closed feature vector mismatch rejection.
- Two-tier abstention policy:
  1. Health-driven abstention override (modality degradation).
  2. Uncertainty-band abstention (probabilities within [abstain_low, abstain_high]).
- Clear definitive verdicts (PHISHING vs. LEGITIMATE).
- Linear explainability attribution (signs, modalities, and capacity bounds).
- End-to-end pipeline integration from raw EML to MetaClassifierResult.
"""

from pathlib import Path
import numpy as np
import pytest

from app.ingestion.email_ingestor import ingest_email
from app.agents.header_agent import analyze_headers
from app.agents.url_agent import analyze_urls
from app.agents.text_agent import analyze_text
from app.agents.attachment_agent import analyze_attachments
from app.aggregation.evidence_aggregator import aggregate_evidence
from app.meta_classifier.trainer import (
    MetaClassifierError,
    load_model_bundle,
    save_model_bundle,
    train_meta_classifier,
)
from app.meta_classifier.meta_classifier import MetaClassifier
from app.schemas.aggregator_schema import (
    ACTIVE_META_FEATURE_COUNT,
    ACTIVE_META_FEATURE_NAMES,
    AggregatedEvidenceResult,
    MetaFeatureVector,
    ModalityHealth,
    ModalityStatus,
)
from app.schemas.meta_classifier_schema import (
    AbstentionReason,
    DecisionThresholds,
    Verdict,
)


SAMPLE_EML_PATH = Path(__file__).resolve().parent.parent / "data" / "samples" / "synthetic_demo.eml"


def _make_dummy_dataset(n_samples: int = 40):
    np.random.seed(42)
    # Generate synthetic features
    X = np.random.randn(n_samples, ACTIVE_META_FEATURE_COUNT)
    # Binary labels balanced
    y = np.array([0] * (n_samples // 2) + [1] * (n_samples // 2))
    return X, y


def _make_dummy_aggregated_result(
    email_id: str = "email_test_123",
    abstention_by_health: bool = False,
    feature_fill: float = 0.0,
) -> AggregatedEvidenceResult:
    names = list(ACTIVE_META_FEATURE_NAMES)
    values = {f: feature_fill for f in names}
    mask = {f: 0 for f in names}
    vec = MetaFeatureVector(
        feature_names=names,
        feature_values=values,
        missingness_mask=mask,
        missing_feature_count=0,
    )
    health = {
        "header": ModalityHealth(
            modality="header",
            status=ModalityStatus.AVAILABLE,
            completeness=1.0,
            active_feature_count=41,
            missing_feature_count=0,
        ),
        "url": ModalityHealth(
            modality="url",
            status=ModalityStatus.EMPTY,
            completeness=0.0,
            active_feature_count=37,
            missing_feature_count=37,
        ),
        "text": ModalityHealth(
            modality="text",
            status=ModalityStatus.AVAILABLE,
            completeness=1.0,
            active_feature_count=29,
            missing_feature_count=0,
        ),
        "attachment": ModalityHealth(
            modality="attachment",
            status=ModalityStatus.EMPTY,
            completeness=0.0,
            active_feature_count=25,
            missing_feature_count=25,
        ),
    }
    return AggregatedEvidenceResult(
        email_id=email_id,
        status="success",
        processing_time_ms=5.0,
        feature_vector=vec,
        modality_health=health,
        overall_completeness=0.70,
        abstention_recommended_by_health=abstention_by_health,
        unified_evidence=[],
        omitted_evidence_count=0,
        warnings=[],
    )


@pytest.fixture
def trained_meta_classifier():
    X, y = _make_dummy_dataset(40)
    model, meta = train_meta_classifier(X, y, calibrate=True, cv=2)
    return MetaClassifier(model=model, metadata=meta)


class TestTrainerAndPersistence:
    def test_train_meta_classifier_calibrated(self):
        X, y = _make_dummy_dataset(40)
        model, meta = train_meta_classifier(X, y, calibrate=True, cv=2)
        assert meta["feature_count"] == ACTIVE_META_FEATURE_COUNT == 132
        assert meta["is_calibrated"] is True
        assert meta["training_samples"] == 40
        assert hasattr(model, "predict_proba")

    def test_training_input_validation(self):
        # Mismatched features
        bad_X = np.random.randn(20, 50)
        bad_y = np.array([0] * 10 + [1] * 10)
        with pytest.raises(MetaClassifierError) as exc_info:
            train_meta_classifier(bad_X, bad_y)
        assert "feature count mismatch" in str(exc_info.value).lower()

        # Single class
        good_X = np.random.randn(20, ACTIVE_META_FEATURE_COUNT)
        single_y = np.zeros(20, dtype=int)
        with pytest.raises(MetaClassifierError) as exc_info:
            train_meta_classifier(good_X, single_y)
        assert "requires both classes" in str(exc_info.value).lower()

    def test_save_and_load_bundle_roundtrip(self, tmp_path):
        X, y = _make_dummy_dataset(30)
        model, meta = train_meta_classifier(X, y, model_version="1.2.3")
        joblib_path, json_path = save_model_bundle(model, meta, tmp_path, model_name="test_model")

        assert joblib_path.exists()
        assert json_path.exists()

        # Load back
        loaded_model, loaded_meta = load_model_bundle(tmp_path, model_name="test_model")
        assert loaded_meta["model_version"] == "1.2.3"
        assert loaded_meta["feature_count"] == 132

        # Wrap in MetaClassifier
        clf = MetaClassifier(bundle_path=tmp_path, model_name="test_model")
        assert clf.model_version == "1.2.3"

    def test_tampered_model_sha256_detection(self, tmp_path):
        X, y = _make_dummy_dataset(30)
        model, meta = train_meta_classifier(X, y)
        joblib_path, _ = save_model_bundle(model, meta, tmp_path, model_name="tampered_model")

        # Tamper with joblib file by appending bytes
        with open(joblib_path, "ab") as f:
            f.write(b"\x00\x00corrupt")

        with pytest.raises(MetaClassifierError) as exc_info:
            load_model_bundle(tmp_path, model_name="tampered_model")
        assert "integrity verification failed" in str(exc_info.value).lower()


class TestMetaClassifierInferenceAndAbstention:
    def test_feature_order_mismatch_rejection(self, trained_meta_classifier):
        res = _make_dummy_aggregated_result()
        # Mutate feature names order
        shuffled = list(res.feature_vector.feature_names)
        shuffled[0], shuffled[1] = shuffled[1], shuffled[0]
        res_dict = res.model_dump()
        res_dict["feature_vector"]["feature_names"] = shuffled
        shuffled_res = AggregatedEvidenceResult.model_validate(res_dict)

        with pytest.raises(MetaClassifierError) as exc_info:
            trained_meta_classifier.predict_verdict(shuffled_res)
        assert "mismatches model expectation" in str(exc_info.value).lower()

    def test_tier1_health_driven_abstention_override(self, trained_meta_classifier):
        # High phishing signals but health abstention recommended
        res = _make_dummy_aggregated_result(abstention_by_health=True, feature_fill=5.0)

        decision = trained_meta_classifier.predict_verdict(res)
        assert decision.verdict == Verdict.ABSTAIN
        assert decision.abstention_reason == AbstentionReason.INSUFFICIENT_MODALITY_HEALTH
        assert decision.calibrated_probability is None
        assert decision.confidence == 0.0

    def test_tier2_uncertainty_band_abstention(self, trained_meta_classifier):
        # Thresholds centered around 0.5
        dt = DecisionThresholds(abstain_low=0.40, abstain_high=0.60)
        res = _make_dummy_aggregated_result(abstention_by_health=False, feature_fill=0.0)

        decision = trained_meta_classifier.predict_verdict(res, thresholds=dt)
        # Random initialization around 0 yields probability near 0.50
        if 0.40 <= decision.calibrated_probability <= 0.60:
            assert decision.verdict == Verdict.ABSTAIN
            assert decision.abstention_reason == AbstentionReason.UNCERTAINTY_BAND

    def test_definitive_verdicts(self):
        # Train on highly separable data to guarantee extreme probabilities
        np.random.seed(42)
        X = np.vstack([
            np.ones((20, ACTIVE_META_FEATURE_COUNT)) * -5.0,  # Legitimate
            np.ones((20, ACTIVE_META_FEATURE_COUNT)) * 5.0,   # Phishing
        ])
        y = np.array([0] * 20 + [1] * 20)
        model, meta = train_meta_classifier(X, y, calibrate=False)
        clf = MetaClassifier(model=model, metadata=meta)

        # Strongly legitimate email
        legit_res = _make_dummy_aggregated_result(feature_fill=-5.0)
        legit_decision = clf.predict_verdict(legit_res)
        assert legit_decision.verdict == Verdict.LEGITIMATE
        assert legit_decision.abstention_reason == AbstentionReason.NONE
        assert legit_decision.calibrated_probability < 0.35

        # Strongly phishing email
        phish_res = _make_dummy_aggregated_result(feature_fill=5.0)
        phish_decision = clf.predict_verdict(phish_res)
        assert phish_decision.verdict == Verdict.PHISHING
        assert phish_decision.abstention_reason == AbstentionReason.NONE
        assert phish_decision.calibrated_probability > 0.65


class TestLinearExplainability:
    def test_contributor_signs_and_bounds(self):
        np.random.seed(42)
        X = np.vstack([
            np.ones((20, ACTIVE_META_FEATURE_COUNT)) * -2.0,
            np.ones((20, ACTIVE_META_FEATURE_COUNT)) * 2.0,
        ])
        y = np.array([0] * 20 + [1] * 20)
        model, meta = train_meta_classifier(X, y, calibrate=False)
        clf = MetaClassifier(model=model, metadata=meta)

        res = _make_dummy_aggregated_result(feature_fill=2.0)
        decision = clf.predict_verdict(res)

        assert len(decision.top_phishing_contributors) <= 10
        assert len(decision.top_legitimate_contributors) <= 10

        # Positive contributions drive phishing
        for c in decision.top_phishing_contributors:
            assert c.contribution_score > 0.0
            assert c.modality in ("header", "url", "text", "attachment")

        # Negative contributions drive legitimate
        for c in decision.top_legitimate_contributors:
            assert c.contribution_score < 0.0
            assert c.modality in ("header", "url", "text", "attachment")


class TestEndToEndPipelineWithMetaClassifier:
    def test_full_pipeline_eml_to_verdict(self, trained_meta_classifier):
        # 1. Ingestion
        raw_bytes = SAMPLE_EML_PATH.read_bytes()
        email_data = ingest_email(raw_bytes)

        # 2. Layer 1 Specialist Agents
        h_res = analyze_headers(email_data)
        u_res = analyze_urls(email_data)
        t_res = analyze_text(email_data)
        a_res = analyze_attachments(email_data)

        # 3. Layer 2 Evidence Aggregator
        agg_res = aggregate_evidence(h_res, u_res, t_res, a_res)
        assert agg_res.status == "success"

        # 4. Layer 3 Meta-Classifier
        decision = trained_meta_classifier.predict_verdict(agg_res)

        assert decision.email_id == email_data.email_id
        assert decision.verdict in (Verdict.PHISHING, Verdict.LEGITIMATE, Verdict.ABSTAIN)
        assert decision.processing_time_ms >= 0.0

        # Model JSON export roundtrip
        json_str = decision.model_dump_json(indent=2)
        from app.schemas.meta_classifier_schema import MetaClassifierResult
        loaded = MetaClassifierResult.model_validate_json(json_str)
        assert loaded.email_id == decision.email_id
        assert loaded.verdict == decision.verdict
