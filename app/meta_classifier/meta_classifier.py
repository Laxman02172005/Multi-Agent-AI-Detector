"""
app/meta_classifier/meta_classifier.py
--------------------------------------
Inference, Explainability, and Two-Tier Selective Abstention for the
Layer 3 Meta-Classifier.

Architecture:
- Two-Tier Abstention Policy:
  1. Health-driven abstention: Triggered immediately if Layer 2 health recommends abstention.
  2. Uncertainty-band abstention: Triggered when P(phishing | x) in [abstain_low, abstain_high].
- Linear Explainability: Extract standardized feature contributions (w_i * x_tilde_i)
  from the underlying regularized Logistic Regression.
- Strict Feature Vector Validation: Fail-closed if input feature_names or order mismatch.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Optional, Tuple, Union

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline

from app.schemas.aggregator_schema import (
    ACTIVE_META_FEATURE_COUNT,
    ACTIVE_META_FEATURE_NAMES,
    AggregatedEvidenceResult,
)
from app.schemas.meta_classifier_schema import (
    AbstentionReason,
    DecisionThresholds,
    FeatureContribution,
    MetaClassifierResult,
    Verdict,
)
from app.meta_classifier.trainer import (
    MetaClassifierError,
    load_model_bundle,
)


class MetaClassifier:
    """
    Layer 3 Meta-Classifier coordinating calibrated probabilistic prediction,
    two-tier selective abstention, and linear feature attribution.
    """

    def __init__(
        self,
        model: Optional[Any] = None,
        metadata: Optional[dict[str, Any]] = None,
        thresholds: Optional[DecisionThresholds] = None,
        bundle_path: Optional[Union[str, Path]] = None,
        model_name: str = "meta_classifier_v1",
    ) -> None:
        """
        Initializes MetaClassifier from in-memory model or serialized bundle path.
        """
        if bundle_path is not None:
            loaded_model, loaded_meta = load_model_bundle(bundle_path, model_name=model_name)
            self.model = loaded_model
            self.metadata = loaded_meta
        elif model is not None:
            self.model = model
            self.metadata = metadata or {
                "model_name": model_name,
                "model_version": "1.0.0",
                "feature_count": ACTIVE_META_FEATURE_COUNT,
                "feature_names": list(ACTIVE_META_FEATURE_NAMES),
                "is_calibrated": isinstance(model, CalibratedClassifierCV),
            }
        else:
            raise MetaClassifierError("Either 'model' or 'bundle_path' must be provided to MetaClassifier")

        # Validate feature registry alignment
        exp_features = self.metadata.get("feature_names")
        if exp_features != list(ACTIVE_META_FEATURE_NAMES):
            raise MetaClassifierError(
                "Model metadata feature_names do not match canonical ACTIVE_META_FEATURE_NAMES"
            )

        self.expected_feature_names: Tuple[str, ...] = tuple(exp_features)
        self.model_version: str = self.metadata.get("model_version", "1.0.0")
        self.thresholds: DecisionThresholds = thresholds or DecisionThresholds()

    def extract_feature_contributions(
        self,
        feature_values_array: np.ndarray,
    ) -> Tuple[list[FeatureContribution], list[FeatureContribution]]:
        """
        Extracts signed linear feature contributions: contribution_i = w_i * x_tilde_i.
        Averaged across cross-validation folds if CalibratedClassifierCV is used.

        Returns:
            (top_phishing_contributors, top_legitimate_contributors) capped at 10 items each.
        """
        contributions_accum = np.zeros(ACTIVE_META_FEATURE_COUNT, dtype=float)

        if isinstance(self.model, CalibratedClassifierCV) and hasattr(self.model, "calibrated_classifiers_"):
            n_estimators = len(self.model.calibrated_classifiers_)
            for cal_clf in self.model.calibrated_classifiers_:
                pipe = cal_clf.estimator
                scaler = pipe.named_steps["scaler"]
                clf = pipe.named_steps["clf"]
                x_scaled = scaler.transform(feature_values_array)[0]
                w = clf.coef_[0]
                contributions_accum += (w * x_scaled)
            contributions = contributions_accum / max(1, n_estimators)
        elif isinstance(self.model, Pipeline):
            scaler = self.model.named_steps["scaler"]
            clf = self.model.named_steps["clf"]
            x_scaled = scaler.transform(feature_values_array)[0]
            w = clf.coef_[0]
            contributions = w * x_scaled
        elif hasattr(self.model, "coef_"):
            contributions = self.model.coef_[0] * feature_values_array[0]
        else:
            # Fallback if estimator has no linear coefficients
            return [], []

        all_contributions: list[FeatureContribution] = []
        for i, fname in enumerate(self.expected_feature_names):
            score = float(contributions[i])
            val = float(feature_values_array[0, i])
            modality = fname.split("_", 1)[0]
            if modality not in ("header", "url", "text", "attachment"):
                modality = "header"

            all_contributions.append(
                FeatureContribution(
                    feature_name=fname,
                    modality=modality,  # type: ignore[arg-type]
                    feature_value=val,
                    contribution_score=round(score, 4),
                )
            )

        # Separate into positive (phishing) and negative (legitimate)
        phishing = sorted(
            [c for c in all_contributions if c.contribution_score > 0.0],
            key=lambda c: c.contribution_score,
            reverse=True,
        )[:10]

        legitimate = sorted(
            [c for c in all_contributions if c.contribution_score < 0.0],
            key=lambda c: c.contribution_score,
        )[:10]

        return phishing, legitimate

    def predict_verdict(
        self,
        aggregated_result: AggregatedEvidenceResult,
        thresholds: Optional[DecisionThresholds] = None,
    ) -> MetaClassifierResult:
        """
        Executes Layer 3 prediction on the output of Layer 2 Evidence Aggregator.

        Policy:
        1. If abstention_recommended_by_health is True -> return ABSTAIN (INSUFFICIENT_MODALITY_HEALTH).
        2. Infer calibrated probability P(phishing | evidence).
        3. If abstain_low <= P <= abstain_high -> return ABSTAIN (UNCERTAINTY_BAND).
        4. If P > abstain_high -> return PHISHING.
        5. If P < abstain_low -> return LEGITIMATE.
        """
        start_time = time.perf_counter()

        # Strict fail-closed input validation
        if not isinstance(aggregated_result, AggregatedEvidenceResult):
            raise MetaClassifierError("Input must be an instance of AggregatedEvidenceResult")

        if not aggregated_result.email_id or not aggregated_result.email_id.strip():
            raise MetaClassifierError("AggregatedEvidenceResult contains empty or invalid email_id")

        if list(aggregated_result.feature_vector.feature_names) != list(self.expected_feature_names):
            raise MetaClassifierError(
                "AggregatedEvidenceResult feature_names order or count mismatches model expectation"
            )

        dt = thresholds or self.thresholds

        # Tier 1: Health-driven abstention override
        if aggregated_result.abstention_recommended_by_health:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)
            return MetaClassifierResult(
                email_id=aggregated_result.email_id,
                verdict=Verdict.ABSTAIN,
                calibrated_probability=None,
                confidence=0.0,
                abstention_reason=AbstentionReason.INSUFFICIENT_MODALITY_HEALTH,
                top_phishing_contributors=[],
                top_legitimate_contributors=[],
                overall_completeness=aggregated_result.overall_completeness,
                model_version=self.model_version,
                processing_time_ms=elapsed_ms,
            )

        # Assemble ordered 1D feature array
        x_vals = np.array(
            [[aggregated_result.feature_vector.feature_values[f] for f in self.expected_feature_names]],
            dtype=float,
        )

        # Model inference
        try:
            probabilities = self.model.predict_proba(x_vals)[0]
            p_phishing = float(probabilities[1])
        except Exception as e:
            raise MetaClassifierError(f"Model predict_proba inference failed: {e}") from e

        p_calibrated = round(min(1.0, max(0.0, p_phishing)), 4)
        confidence = round(min(1.0, max(0.0, 2.0 * abs(p_calibrated - 0.5))), 4)

        # Tier 2: Uncertainty-band abstention & final decision
        if dt.abstain_low <= p_calibrated <= dt.abstain_high:
            verdict = Verdict.ABSTAIN
            reason = AbstentionReason.UNCERTAINTY_BAND
        elif p_calibrated > dt.abstain_high:
            verdict = Verdict.PHISHING
            reason = AbstentionReason.NONE
        else:
            verdict = Verdict.LEGITIMATE
            reason = AbstentionReason.NONE

        # Feature contributions
        phishing_contribs, legit_contribs = self.extract_feature_contributions(x_vals)

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)

        return MetaClassifierResult(
            email_id=aggregated_result.email_id,
            verdict=verdict,
            calibrated_probability=p_calibrated,
            confidence=confidence,
            abstention_reason=reason,
            top_phishing_contributors=phishing_contribs,
            top_legitimate_contributors=legit_contribs,
            overall_completeness=aggregated_result.overall_completeness,
            model_version=self.model_version,
            processing_time_ms=elapsed_ms,
        )
