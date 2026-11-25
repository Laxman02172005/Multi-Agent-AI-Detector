"""
app/meta_classifier/__init__.py
-------------------------------
Public interface for Layer 3 Meta-Classifier and Selective Abstention.
"""

from app.meta_classifier.meta_classifier import MetaClassifier
from app.meta_classifier.trainer import (
    MetaClassifierError,
    build_base_pipeline,
    compute_file_sha256,
    load_model_bundle,
    save_model_bundle,
    train_meta_classifier,
)
from app.schemas.meta_classifier_schema import (
    AbstentionReason,
    DecisionThresholds,
    FeatureContribution,
    MetaClassifierResult,
    Verdict,
)

__all__ = [
    "MetaClassifier",
    "MetaClassifierError",
    "train_meta_classifier",
    "build_base_pipeline",
    "save_model_bundle",
    "load_model_bundle",
    "compute_file_sha256",
    "Verdict",
    "AbstentionReason",
    "FeatureContribution",
    "DecisionThresholds",
    "MetaClassifierResult",
]
