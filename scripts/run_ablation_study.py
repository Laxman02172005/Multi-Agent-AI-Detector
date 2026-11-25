"""
scripts/run_ablation_study.py
------------------------------
Controlled Temporal-Confounding Ablation Study for the Multi-Agent Phishing Detector.

Evaluates 3 controlled feature configurations on data/processed/real_meta_features.jsonl:
1. Config A: Full Baseline (132 features) — All active canonical features.
2. Config B: De-Confounded (126 features) — Masks/excludes legacy SPF/DKIM/DMARC/authserv
             presence-count features that differ between 2002-2003 SpamAssassin and
             2015-2021 Nazario phishing.
3. Config C: Content & URL Only (91 features) — Drops the entire Header modality
             (evaluates strictly on URL [37] + Text [29] + Attachment [25]).

Strict Constraints:
- Zero new third-party packages (uses standard library, scikit-learn, numpy, pydantic).
- Strictly preserves split partition boundaries (600 Train / 200 Val / 200 Test).
- Evaluates strictly once on the held-out test split using validation-tuned thresholds.
- Outputs comparison report to docs/research/ablation_report.json and renders Markdown table.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Tuple

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Ensure project root in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.schemas.aggregator_schema import ACTIVE_META_FEATURE_NAMES


# ---------------------------------------------------------------------------
# Feature Configuration Definitions
# ---------------------------------------------------------------------------

# Legacy presence-count features reflecting 2002 vs 2015+ email era differences
LEGACY_AUTH_COUNT_FEATURES: Tuple[str, ...] = (
    "header_dkim_claim_count",
    "header_authserv_id_count",
    "header_spf_claim_count",
    "header_dmarc_claim_count",
    "header_dkim_signature_header_present",
    "header_dkim_signature_present_without_pass",
)

CONFIG_DEFINITIONS = {
    "config_a": {
        "name": "Config A (Full Baseline)",
        "description": "All 132 active canonical features across all 4 modalities",
        "features": list(ACTIVE_META_FEATURE_NAMES),
    },
    "config_b": {
        "name": "Config B (De-Confounded)",
        "description": "Baseline minus 6 legacy SPF/DKIM/DMARC/authserv presence-count features",
        "features": [
            f for f in ACTIVE_META_FEATURE_NAMES if f not in LEGACY_AUTH_COUNT_FEATURES
        ],
    },
    "config_c": {
        "name": "Config C (Content & URL Only)",
        "description": "Drop entire Header modality (URL [37] + Text [29] + Attachment [25])",
        "features": [
            f for f in ACTIVE_META_FEATURE_NAMES if not f.startswith("header_")
        ],
    },
}


# ---------------------------------------------------------------------------
# Data Loader
# ---------------------------------------------------------------------------

def load_ablation_splits(
    jsonl_path: Path,
) -> Tuple[
    Dict[str, List[Dict[str, float]]],
    Dict[str, np.ndarray],
    Dict[str, List[Dict[str, Any]]],
]:
    """
    Loads feature dictionary records segregated by split (train, val, test).
    """
    if not jsonl_path.is_file():
        raise FileNotFoundError(f"Feature dataset not found at: {jsonl_path}")

    records_by_split: Dict[str, List[Dict[str, Any]]] = {
        "train": [],
        "val": [],
        "test": [],
    }

    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            split = rec.get("split", "train")
            if split in records_by_split:
                records_by_split[split].append(rec)

    feat_dict: Dict[str, List[Dict[str, float]]] = {}
    y_dict: Dict[str, np.ndarray] = {}
    meta_dict: Dict[str, List[Dict[str, Any]]] = {}

    for split in ("train", "val", "test"):
        split_recs = records_by_split[split]
        if not split_recs:
            raise ValueError(f"No records found for split '{split}'")

        feat_rows = [r["feature_values"] for r in split_recs]
        y_rows = [int(r["label"]) for r in split_recs]
        meta_rows = [
            {
                "sample_id": r.get("sample_id", ""),
                "sha256": r.get("sha256", ""),
                "source_category": r.get("source_category", ""),
                "source_year": r.get("source_year", ""),
                "assigned_label": r.get("assigned_label", ""),
            }
            for r in split_recs
        ]

        feat_dict[split] = feat_rows
        y_dict[split] = np.array(y_rows, dtype=int)
        meta_dict[split] = meta_rows

    return feat_dict, y_dict, meta_dict


def assemble_matrix(
    feat_rows: List[Dict[str, float]],
    feature_names: List[str],
) -> np.ndarray:
    """
    Constructs a 2D numpy array for a specific subset of feature names.
    """
    matrix: List[List[float]] = []
    for row_dict in feat_rows:
        row = [float(row_dict.get(fname, 0.0)) for fname in feature_names]
        matrix.append(row)
    return np.array(matrix, dtype=float)


# ---------------------------------------------------------------------------
# Training and Threshold Tuning
# ---------------------------------------------------------------------------

def train_and_calibrate_pipeline(
    X_train: np.ndarray,
    y_train: np.ndarray,
    cv: int = 5,
    random_state: int = 42,
) -> CalibratedClassifierCV:
    """
    Fits the identical StandardScaler + LogisticRegression + CalibratedClassifierCV pipeline.
    """
    base_pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            class_weight="balanced",
            max_iter=1000,
            random_state=random_state,
            solver="lbfgs",
        )),
    ])
    calibrated_model = CalibratedClassifierCV(
        estimator=base_pipe,
        method="sigmoid",
        cv=cv,
    )
    calibrated_model.fit(X_train, y_train)
    return calibrated_model


def sweep_validation_thresholds(
    model: CalibratedClassifierCV,
    X_val: np.ndarray,
    y_val: np.ndarray,
    min_coverage_floor: float = 0.80,
) -> Tuple[float, float, List[Dict[str, Any]]]:
    """
    Sweeps abstention thresholds (tau_low, tau_high) on the validation split.
    """
    val_probs = model.predict_proba(X_val)[:, 1]
    low_candidates = [0.15, 0.20, 0.25, 0.30, 0.35, 0.40]
    high_candidates = [0.60, 0.65, 0.70, 0.75, 0.80, 0.85]

    sweep_results = []
    best_opt = (0.35, 0.65)
    best_score = -1.0
    best_cov = -1.0

    for t_low in low_candidates:
        for t_high in high_candidates:
            if t_low >= t_high:
                continue
            non_abstained = (val_probs < t_low) | (val_probs > t_high)
            n_retained = int(np.sum(non_abstained))
            cov = float(n_retained / len(val_probs))

            if n_retained > 0:
                preds = (val_probs[non_abstained] >= 0.5).astype(int)
                sel_acc = float(accuracy_score(y_val[non_abstained], preds))
            else:
                sel_acc = 0.0

            rec = {
                "abstain_low": t_low,
                "abstain_high": t_high,
                "coverage": round(cov, 4),
                "retained_samples": n_retained,
                "selective_accuracy": round(sel_acc, 4),
            }
            sweep_results.append(rec)

            if cov >= min_coverage_floor:
                if (sel_acc > best_score) or (sel_acc == best_score and cov > best_cov):
                    best_score = sel_acc
                    best_cov = cov
                    best_opt = (t_low, t_high)

    return best_opt[0], best_opt[1], sweep_results


# ---------------------------------------------------------------------------
# Test Evaluation and Weight Extraction
# ---------------------------------------------------------------------------

def evaluate_on_test_split(
    model: CalibratedClassifierCV,
    X_test: np.ndarray,
    y_test: np.ndarray,
    test_meta: List[Dict[str, Any]],
    abstain_low: float,
    abstain_high: float,
) -> Dict[str, Any]:
    """
    Evaluates strictly once on the held-out test split.
    """
    test_probs = model.predict_proba(X_test)[:, 1]
    raw_preds = (test_probs >= 0.5).astype(int)

    # Standard forced-choice metrics
    roc_auc = float(roc_auc_score(y_test, test_probs)) if len(np.unique(y_test)) > 1 else 1.0
    brier = float(brier_score_loss(y_test, test_probs))
    std_acc = float(accuracy_score(y_test, raw_preds))
    std_prec = float(precision_score(y_test, raw_preds, zero_division=0))
    std_rec = float(recall_score(y_test, raw_preds, zero_division=0))
    std_f1 = float(f1_score(y_test, raw_preds, average="macro", zero_division=0))

    # Selective metrics
    non_abstained_mask = (test_probs < abstain_low) | (test_probs > abstain_high)
    n_total = len(y_test)
    n_abstained = int(np.sum(~non_abstained_mask))
    n_retained = int(np.sum(non_abstained_mask))

    abstention_rate = float(n_abstained / n_total) if n_total > 0 else 0.0
    coverage = float(1.0 - abstention_rate)

    if n_retained > 0:
        sel_probs = test_probs[non_abstained_mask]
        sel_preds = (sel_probs >= 0.5).astype(int)
        sel_y = y_test[non_abstained_mask]
        sel_acc = float(accuracy_score(sel_y, sel_preds))
        sel_prec = float(precision_score(sel_y, sel_preds, zero_division=0))
        sel_rec = float(recall_score(sel_y, sel_preds, zero_division=0))
        sel_f1 = float(f1_score(sel_y, sel_preds, average="macro", zero_division=0))
    else:
        sel_acc = 0.0
        sel_prec = 0.0
        sel_rec = 0.0
        sel_f1 = 0.0

    # Error analysis
    false_positives = []
    false_negatives = []
    abstained_samples = []

    for i in range(n_total):
        p = float(test_probs[i])
        actual = int(y_test[i])
        info = {
            "sample_id": test_meta[i].get("sample_id", f"test_{i}"),
            "assigned_label": test_meta[i].get("assigned_label", ""),
            "source_category": test_meta[i].get("source_category", ""),
            "source_year": test_meta[i].get("source_year", ""),
            "calibrated_prob": round(p, 4),
        }

        if abstain_low <= p <= abstain_high:
            abstained_samples.append(info)
        elif p > abstain_high and actual == 0:
            false_positives.append(info)
        elif p < abstain_low and actual == 1:
            false_negatives.append(info)

    return {
        "test_samples": n_total,
        "standard_accuracy": round(std_acc, 4),
        "standard_precision": round(std_prec, 4),
        "standard_recall": round(std_rec, 4),
        "forced_choice_f1": round(std_f1, 4),
        "roc_auc": round(roc_auc, 4),
        "brier_score": round(brier, 4),
        "abstention_thresholds": {
            "abstain_low": abstain_low,
            "abstain_high": abstain_high,
        },
        "abstention_rate": round(abstention_rate, 4),
        "coverage": round(coverage, 4),
        "retained_samples": n_retained,
        "abstained_samples": n_abstained,
        "selective_accuracy": round(sel_acc, 4),
        "selective_precision": round(sel_prec, 4),
        "selective_recall": round(sel_rec, 4),
        "selective_macro_f1": round(sel_f1, 4),
        "false_positives_count": len(false_positives),
        "false_negatives_count": len(false_negatives),
        "abstained_count": len(abstained_samples),
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "abstained_details": abstained_samples,
    }


def extract_top_weights(
    model: CalibratedClassifierCV,
    feature_names: List[str],
    top_k: int = 5,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Extracts the top positive (phishing) and negative (legitimate) linear weights.
    """
    n_feats = len(feature_names)
    weights_accum = np.zeros(n_feats, dtype=float)

    n_est = len(model.calibrated_classifiers_)
    for cal_clf in model.calibrated_classifiers_:
        pipe = cal_clf.estimator
        clf = pipe.named_steps["clf"]
        weights_accum += clf.coef_[0]
    avg_weights = weights_accum / max(1, n_est)

    indexed = [
        {"feature_name": feature_names[i], "weight": round(float(avg_weights[i]), 4)}
        for i in range(n_feats)
    ]

    # Phishing: highest positive weights
    phishing_top = sorted([w for w in indexed if w["weight"] > 0], key=lambda x: x["weight"], reverse=True)[:top_k]
    # Legitimate: most negative weights
    legit_top = sorted([w for w in indexed if w["weight"] < 0], key=lambda x: x["weight"])[:top_k]

    return phishing_top, legit_top


# ---------------------------------------------------------------------------
# Main Controller
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-Agent Phishing Detector - Temporal Confounding Ablation Study")
    parser.add_argument(
        "--data-path",
        type=str,
        default=str(PROJECT_ROOT / "data" / "processed" / "real_meta_features.jsonl"),
        help="Path to pre-extracted real feature dataset JSONL",
    )
    parser.add_argument(
        "--output-report",
        type=str,
        default=str(PROJECT_ROOT / "docs" / "research" / "ablation_report.json"),
        help="Path to output JSON ablation report",
    )
    args = parser.parse_args()

    data_path = Path(args.data_path)
    output_report = Path(args.output_report)
    output_report.parent.mkdir(parents=True, exist_ok=True)

    print("==============================================================================")
    print("      MULTI-AGENT PHISHING DETECTOR - TEMPORAL ABLATION STUDY                 ")
    print("==============================================================================")
    print(f"[*] Dataset: {data_path.name}")
    print(f"[*] Evaluating Configurations: Config A, Config B, Config C\n")

    feat_dict, y_dict, meta_dict = load_ablation_splits(data_path)
    y_train = y_dict["train"]
    y_val = y_dict["val"]
    y_test = y_dict["test"]

    print(f"[+] Loaded Partitions: Train={len(y_train)}, Val={len(y_val)}, Test={len(y_test)}")
    print(f"[+] Train Phishing Ratio: {np.sum(y_train)/len(y_train):.1%}")

    study_results: Dict[str, Any] = {
        "dataset": data_path.name,
        "sample_counts": {
            "train": len(y_train),
            "val": len(y_val),
            "test": len(y_test),
        },
        "configurations": {},
    }

    comparison_rows = []

    for cfg_id, cfg_def in CONFIG_DEFINITIONS.items():
        print("-" * 78)
        print(f"[*] Running: {cfg_def['name']} ({len(cfg_def['features'])} features)")
        print(f"    Description: {cfg_def['description']}")

        # Assemble matrices
        X_train_cfg = assemble_matrix(feat_dict["train"], cfg_def["features"])
        X_val_cfg = assemble_matrix(feat_dict["val"], cfg_def["features"])
        X_test_cfg = assemble_matrix(feat_dict["test"], cfg_def["features"])

        t0 = time.time()
        # Fit calibrated model
        model = train_and_calibrate_pipeline(X_train_cfg, y_train, cv=5, random_state=42)

        # Tune thresholds on Validation split
        opt_low, opt_high, val_sweep = sweep_validation_thresholds(
            model=model,
            X_val=X_val_cfg,
            y_val=y_val,
            min_coverage_floor=0.80,
        )

        # Evaluate strictly once on Test split
        test_metrics = evaluate_on_test_split(
            model=model,
            X_test=X_test_cfg,
            y_test=y_test,
            test_meta=meta_dict["test"],
            abstain_low=opt_low,
            abstain_high=opt_high,
        )
        elapsed_sec = time.time() - t0

        # Extract top linear weights
        phish_weights, legit_weights = extract_top_weights(model, cfg_def["features"], top_k=5)

        cfg_result = {
            "id": cfg_id,
            "name": cfg_def["name"],
            "description": cfg_def["description"],
            "feature_count": len(cfg_def["features"]),
            "optimal_thresholds": {"abstain_low": opt_low, "abstain_high": opt_high},
            "test_metrics": test_metrics,
            "top_phishing_weights": phish_weights,
            "top_legitimate_weights": legit_weights,
            "training_time_sec": round(elapsed_sec, 3),
        }
        study_results["configurations"][cfg_id] = cfg_result

        comparison_rows.append({
            "config": cfg_def["name"],
            "features": len(cfg_def["features"]),
            "roc_auc": test_metrics["roc_auc"],
            "brier": test_metrics["brier_score"],
            "f1": test_metrics["forced_choice_f1"],
            "tau_low": opt_low,
            "tau_high": opt_high,
            "coverage": test_metrics["coverage"],
            "abstain_rate": test_metrics["abstention_rate"],
            "sel_acc": test_metrics["selective_accuracy"],
            "fp": test_metrics["false_positives_count"],
            "fn": test_metrics["false_negatives_count"],
        })

    # Save to JSON
    output_report.write_text(json.dumps(study_results, indent=2), encoding="utf-8")
    print("\n" + "=" * 78)
    print(f"[✓] Full ablation study artifact written to: {output_report}")
    print("=" * 78)

    # Print Markdown Comparison Table
    print("\n### Controlled Ablation Study: Generalization Performance on Sealed Test Set (n=200)\n")
    print("| Configuration | Feats | ROC-AUC | Brier | Forced-F1 | Thresholds [τ_low, τ_high] | Coverage | Abstain Rate | Selective Acc | FP | FN |")
    print("|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|")
    for r in comparison_rows:
        print(
            f"| **{r['config']}** | {r['features']} | "
            f"{r['roc_auc']:.4f} | {r['brier']:.4f} | {r['f1']:.4f} | "
            f"[{r['tau_low']:.2f}, {r['tau_high']:.2f}] | "
            f"{r['coverage']:.1%} | {r['abstain_rate']:.1%} | "
            f"**{r['sel_acc']:.2%}** | {r['fp']} | {r['fn']} |"
        )

    # Print Top Weights for Config B and Config C
    for cfg_id in ("config_b", "config_c"):
        cfg_data = study_results["configurations"][cfg_id]
        print(f"\n#### Top Linear Weights for {cfg_data['name']}")
        print("```")
        print("Top 5 Phishing Weights (Positive Impact):")
        for idx, w in enumerate(cfg_data["top_phishing_weights"], 1):
            print(f"  {idx}. {w['feature_name']}: +{w['weight']:.4f}")
        print("\nTop 5 Legitimate Weights (Negative Impact):")
        for idx, w in enumerate(cfg_data["top_legitimate_weights"], 1):
            print(f"  {idx}. {w['feature_name']}: {w['weight']:.4f}")
        print("```")


if __name__ == "__main__":
    main()
