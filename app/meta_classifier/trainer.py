"""
app/meta_classifier/trainer.py
------------------------------
Model training, probability calibration, and versioned artifact persistence
for the Layer 3 Meta-Classifier.

Architecture:
- Pipeline: StandardScaler + LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
- Probability Calibration: CalibratedClassifierCV using sigmoid / Platt scaling
- Strict Feature Alignment: Exactly the 132 active canonical features in ACTIVE_META_FEATURE_NAMES
- Secure Persistence: joblib artifact + JSON metadata with SHA-256 integrity verification
"""

from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
from typing import Any, Optional, Tuple, Union

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from app.schemas.aggregator_schema import ACTIVE_META_FEATURE_COUNT, ACTIVE_META_FEATURE_NAMES


class MetaClassifierError(Exception):
    """
    Raised when Layer 3 training, loading, or inference encounters contract
    violations, integrity corruption, or unrecoverable processing failures.
    """
    def __init__(self, message: str, email_id: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.email_id = email_id


def build_base_pipeline(random_state: int = 42) -> Pipeline:
    """
    Constructs an interpretable, regularized linear pipeline:
    StandardScaler + LogisticRegression(class_weight="balanced").
    """
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            class_weight="balanced",
            max_iter=1000,
            random_state=random_state,
            solver="lbfgs",
        )),
    ])


def train_meta_classifier(
    X: Union[np.ndarray, list[list[float]]],
    y: Union[np.ndarray, list[int]],
    calibrate: bool = True,
    cv: int = 5,
    random_state: int = 42,
    model_version: str = "1.0.0",
    model_name: str = "meta_classifier_v1",
) -> Tuple[Any, dict[str, Any]]:
    """
    Trains and calibrates a Meta-Classifier on the 132 active meta-features.

    Parameters:
        X: Feature matrix of shape (N, 132).
        y: Binary targets (0 for legitimate, 1 for phishing).
        calibrate: Whether to apply Platt scaling via CalibratedClassifierCV.
        cv: Number of cross-validation folds for calibration.
        random_state: Deterministic random seed.
        model_version: Version identifier string.
        model_name: Artifact bundle base name.

    Returns:
        (fitted_estimator, metadata_dict)

    Raises:
        MetaClassifierError: If feature shape is invalid or inputs are malformed.
    """
    X_arr = np.asarray(X, dtype=float)
    y_arr = np.asarray(y, dtype=int)

    if X_arr.ndim != 2:
        raise MetaClassifierError(f"Expected 2D feature matrix, got ndim={X_arr.ndim}")

    if X_arr.shape[1] != ACTIVE_META_FEATURE_COUNT:
        raise MetaClassifierError(
            f"Feature count mismatch: expected {ACTIVE_META_FEATURE_COUNT} active features, "
            f"got {X_arr.shape[1]}"
        )

    if len(X_arr) != len(y_arr):
        raise MetaClassifierError(
            f"Sample count mismatch between X ({len(X_arr)}) and y ({len(y_arr)})"
        )

    unique_classes = np.unique(y_arr)
    if len(unique_classes) < 2:
        raise MetaClassifierError(
            f"Training requires both classes (0 and 1); found only classes {unique_classes.tolist()}"
        )

    base_pipe = build_base_pipeline(random_state=random_state)

    is_calibrated = False
    min_class_count = int(np.min(np.bincount(y_arr)))

    if calibrate and min_class_count >= 2:
        effective_cv = min(cv, min_class_count)
        if effective_cv >= 2:
            try:
                calibrated_model = CalibratedClassifierCV(
                    estimator=base_pipe,
                    method="sigmoid",
                    cv=effective_cv,
                )
                calibrated_model.fit(X_arr, y_arr)
                fitted_estimator = calibrated_model
                is_calibrated = True
            except Exception:
                # Fallback to base pipeline if calibration fails on small/degenerate fold splits
                base_pipe.fit(X_arr, y_arr)
                fitted_estimator = base_pipe
                is_calibrated = False
        else:
            base_pipe.fit(X_arr, y_arr)
            fitted_estimator = base_pipe
    else:
        base_pipe.fit(X_arr, y_arr)
        fitted_estimator = base_pipe

    metadata: dict[str, Any] = {
        "model_name": model_name,
        "model_version": model_version,
        "feature_count": ACTIVE_META_FEATURE_COUNT,
        "feature_names": list(ACTIVE_META_FEATURE_NAMES),
        "is_calibrated": is_calibrated,
        "training_samples": len(X_arr),
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    return fitted_estimator, metadata


def compute_file_sha256(filepath: Union[str, Path]) -> str:
    """
    Computes hex SHA-256 digest of a binary file on disk.
    """
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def save_model_bundle(
    model: Any,
    metadata: dict[str, Any],
    output_dir: Union[str, Path],
    model_name: Optional[str] = None,
) -> Tuple[Path, Path]:
    """
    Persists a trained model bundle (joblib binary + SHA-256 verified JSON metadata).

    Returns:
        (joblib_path, metadata_json_path)
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    name = model_name or metadata.get("model_name", "meta_classifier_v1")
    joblib_file = out_path / f"{name}.joblib"
    meta_file = out_path / f"{name}_metadata.json"

    # Save joblib binary
    joblib.dump(model, joblib_file)

    # Compute digest and update metadata
    sha256_hash = compute_file_sha256(joblib_file)
    meta_to_write = dict(metadata)
    meta_to_write["model_sha256"] = sha256_hash

    # Save JSON metadata
    meta_file.write_text(json.dumps(meta_to_write, indent=2), encoding="utf-8")

    return joblib_file, meta_file


def load_model_bundle(
    model_dir_or_joblib: Union[str, Path],
    model_name: str = "meta_classifier_v1",
) -> Tuple[Any, dict[str, Any]]:
    """
    Loads and cryptographically validates a model bundle.

    Raises:
        MetaClassifierError: If files are missing, SHA-256 fails, or feature metadata mismatches.
    """
    target = Path(model_dir_or_joblib)
    if target.is_file():
        if target.suffix == ".joblib":
            joblib_path = target
            meta_path = target.parent / f"{target.stem}_metadata.json"
        elif target.suffix == ".json":
            meta_path = target
            base_name = target.stem.replace("_metadata", "")
            joblib_path = target.parent / f"{base_name}.joblib"
        else:
            raise MetaClassifierError(f"Unsupported model bundle file format: {target}")
    elif target.is_dir():
        joblib_path = target / f"{model_name}.joblib"
        meta_path = target / f"{model_name}_metadata.json"
        if not joblib_path.exists():
            if (target / f"{target.name}.joblib").exists():
                joblib_path = target / f"{target.name}.joblib"
                meta_path = target / f"{target.name}_metadata.json"
            else:
                candidates = sorted(list(target.glob("*.joblib")))
                if len(candidates) == 1:
                    joblib_path = candidates[0]
                    meta_path = target / f"{joblib_path.stem}_metadata.json"
    else:
        raise MetaClassifierError(f"Model path does not exist: {target}")

    if not joblib_path.exists():
        raise MetaClassifierError(f"Missing model binary at {joblib_path}")
    if not meta_path.exists():
        raise MetaClassifierError(f"Missing model metadata at {meta_path}")

    # Read and parse metadata
    try:
        metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception as e:
        raise MetaClassifierError(f"Failed to parse metadata JSON at {meta_path}: {e}") from e

    # Integrity check: verify SHA-256
    expected_sha256 = metadata.get("model_sha256")
    if not expected_sha256:
        raise MetaClassifierError(f"Metadata at {meta_path} missing 'model_sha256' field")

    actual_sha256 = compute_file_sha256(joblib_path)
    if actual_sha256 != expected_sha256:
        raise MetaClassifierError(
            f"Model integrity verification failed for {joblib_path}: "
            f"expected SHA-256 '{expected_sha256}', computed '{actual_sha256}'"
        )

    # Invariant check: 132 features matching canonical registry
    expected_feat_count = metadata.get("feature_count")
    if expected_feat_count != ACTIVE_META_FEATURE_COUNT:
        raise MetaClassifierError(
            f"Metadata feature_count ({expected_feat_count}) does not match "
            f"canonical count ({ACTIVE_META_FEATURE_COUNT})"
        )

    feat_names = metadata.get("feature_names")
    if feat_names != list(ACTIVE_META_FEATURE_NAMES):
        raise MetaClassifierError("Metadata feature_names do not match ACTIVE_META_FEATURE_NAMES registry")

    # Load binary estimator
    try:
        model = joblib.load(joblib_path)
    except Exception as e:
        raise MetaClassifierError(f"Failed to load joblib model at {joblib_path}: {e}") from e

    return model, metadata
