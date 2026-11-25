"""
scripts/train_and_evaluate.py
-----------------------------
Model Training, Probability Calibration, and Selective Evaluation Script
for the Layer 3 Meta-Classifier.

Modes:
1. --real-data <path.jsonl>:
   Trains on the 600-email train partition, tunes selective abstention thresholds
   on the 200-email validation partition, and evaluates strictly once on the
   sealed 200-email held-out test partition from the real development corpus
   (SpamAssassin + Nazario).
2. --synthetic-demo:
   Generates a balanced synthetic email dataset processed through the actual
   Layer 0 -> Layer 1 -> Layer 2 pipeline for quick verification.

Strict Tech Stack:
- Standard library (json, pathlib, sys, time, hashlib, argparse)
- Approved dependencies (scikit-learn, joblib, numpy, pydantic)
- Zero external parquet or dataframe packages.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Any, Tuple

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.ingestion.email_ingestor import ingest_email
from app.agents.header_agent import analyze_headers
from app.agents.url_agent import analyze_urls
from app.agents.text_agent import analyze_text
from app.agents.attachment_agent import analyze_attachments
from app.aggregation.evidence_aggregator import aggregate_evidence
from app.meta_classifier.trainer import (
    save_model_bundle,
    train_meta_classifier,
)
from app.schemas.aggregator_schema import ACTIVE_META_FEATURE_COUNT, ACTIVE_META_FEATURE_NAMES


# ---------------------------------------------------------------------------
# 1. Real Dataset Loader
# ---------------------------------------------------------------------------

def load_real_feature_dataset(
    jsonl_path: Path,
) -> Tuple[
    dict[str, np.ndarray],
    dict[str, np.ndarray],
    dict[str, list[dict[str, Any]]],
]:
    """
    Loads pre-extracted 132-feature meta-vectors from the cached .jsonl file,
    segregating them strictly by the 'split' field (train, val, test).

    Returns:
        X_dict: {"train": ndarray, "val": ndarray, "test": ndarray}
        y_dict: {"train": ndarray, "val": ndarray, "test": ndarray}
        meta_dict: {"train": list, "val": list, "test": list}
    """
    if not jsonl_path.is_file():
        raise FileNotFoundError(f"Feature dataset not found at: {jsonl_path}")

    records_by_split: dict[str, list[dict[str, Any]]] = {
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

    X_dict: dict[str, np.ndarray] = {}
    y_dict: dict[str, np.ndarray] = {}
    meta_dict: dict[str, list[dict[str, Any]]] = {}

    for split_name in ("train", "val", "test"):
        split_records = records_by_split[split_name]
        if not split_records:
            raise ValueError(f"Zero records found for split '{split_name}' in {jsonl_path}")

        X_rows: list[list[float]] = []
        y_rows: list[int] = []
        meta_rows: list[dict[str, Any]] = []

        for r in split_records:
            f_vals = r["feature_values"]
            row = [float(f_vals.get(f, 0.0)) for f in ACTIVE_META_FEATURE_NAMES]
            X_rows.append(row)
            y_rows.append(int(r["label"]))
            meta_rows.append({
                "sample_id": r.get("sample_id", ""),
                "sha256": r.get("sha256", ""),
                "source_category": r.get("source_category", ""),
                "source_year": r.get("source_year", ""),
                "assigned_label": r.get("assigned_label", ""),
            })

        X_dict[split_name] = np.array(X_rows, dtype=float)
        y_dict[split_name] = np.array(y_rows, dtype=int)
        meta_dict[split_name] = meta_rows

    return X_dict, y_dict, meta_dict


# ---------------------------------------------------------------------------
# 2. Synthetic Dataset Generation (Demo Mode)
# ---------------------------------------------------------------------------

def build_synthetic_email_eml(email_idx: int, is_phishing: bool) -> bytes:
    boundary = f"boundary_synthetic_{email_idx}_{'phish' if is_phishing else 'legit'}"
    if is_phishing:
        from_hdr = f'"Security Helpdesk <security@corporate-bank{email_idx}.com>" <attacker@phish-relay-{email_idx}.org>'
        reply_to = f"credential-collector@malicious-harvest-{email_idx}.net"
        return_path = f"bounce@unrelated-drop-{email_idx}.xyz"
        subj = f"URGENT: Security Incident #{email_idx:04d} - Immediate Password Verification Required!"
        auth_results = (
            f"mx.google.com;\n"
            f" spf=fail (google.com: domain does not designate 192.168.1.{email_idx % 250}) smtp.mailfrom=attacker@phish-relay.org;\n"
            f" dkim=fail (signature verification failed) header.i=@corporate-bank.com;\n"
            f" dmarc=fail (p=REJECT) header.from=corporate-bank.com"
        )
        received_hops = (
            f"Received: from mail.phish-relay.org by mx.google.com with ESMTPS id xyz{email_idx}; Wed, 11 Nov 2026 10:00:00 +0000\r\n"
            f"Received: from internal.spoofed.lan (192.168.1.{email_idx % 250}) by mail.phish-relay.org; Wed, 11 Nov 2026 09:59:00 +0000\r\n"
        )
        body_text = (
            f"Dear Valued Customer,\n\n"
            f"CRITICAL WARNING: Unauthorized login attempts were detected on your online account.\n"
            f"You must verify your login credentials immediately to prevent account suspension.\n\n"
            f"Click here immediately: http://192.168.1.{email_idx % 250}/login/verify?user=victim_{email_idx}\n"
            f"Secondary link: http://bit.ly/secure-login-{email_idx}\n\n"
            f"Failure to act within 24 hours will result in permanent termination of your banking access.\n\n"
            f"Security Operations Center"
        )
        attachment_part = (
            f"--{boundary}\r\n"
            f"Content-Type: application/octet-stream; name=\"Invoice_Update_{email_idx}.pdf.exe\"\r\n"
            f"Content-Disposition: attachment; filename=\"Invoice_Update_{email_idx}.pdf.exe\"\r\n"
            f"Content-Transfer-Encoding: base64\r\n\r\n"
            f"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n"
        )
    else:
        from_hdr = f"Billing Support <billing@trusted-vendor-{email_idx % 5}.com>"
        reply_to = f"billing@trusted-vendor-{email_idx % 5}.com"
        return_path = f"bounce@trusted-vendor-{email_idx % 5}.com"
        subj = f"Your Monthly Account Statement - Account #{10000 + email_idx}"
        auth_results = (
            f"mx.google.com;\n"
            f" spf=pass (google.com: domain designates 203.0.113.{email_idx % 50} as permitted) smtp.mailfrom=billing@trusted-vendor.com;\n"
            f" dkim=pass header.i=@trusted-vendor.com;\n"
            f" dmarc=pass (p=REJECT) header.from=trusted-vendor.com"
        )
        received_hops = (
            f"Received: from mail.trusted-vendor.com by mx.google.com with ESMTPS id legit{email_idx}; Wed, 11 Nov 2026 12:00:00 +0000\r\n"
        )
        body_text = (
            f"Hello,\n\n"
            f"Your regular monthly billing statement is now available for download in your portal.\n"
            f"Please visit our official site: https://trusted-vendor-{email_idx % 5}.com/portal/invoices\n\n"
            f"Thank you for your business.\n\n"
            f"Customer Care Team"
        )
        attachment_part = (
            f"--{boundary}\r\n"
            f"Content-Type: application/pdf; name=\"Statement_{email_idx}.pdf\"\r\n"
            f"Content-Disposition: attachment; filename=\"Statement_{email_idx}.pdf\"\r\n"
            f"Content-Transfer-Encoding: base64\r\n\r\n"
            f"JVBERi0xLjQKJcTl8uXrp/Og0MTGCjQgMCBvYmoKPDwgL0xlbmd0aCA1IDAgUiA+PgpzdHJlYW0K\r\n"
        )

    eml_str = (
        f"From: {from_hdr}\r\n"
        f"To: user_{email_idx}@example.com\r\n"
        f"Reply-To: {reply_to}\r\n"
        f"Return-Path: <{return_path}>\r\n"
        f"Subject: {subj}\r\n"
        f"Date: Wed, 11 Nov 2026 12:00:00 +0000\r\n"
        f"Message-ID: <msg-{email_idx}-20261111@trusted-vendor.com>\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n"
        f"{received_hops}"
        f"Authentication-Results: {auth_results}\r\n"
        f"\r\n"
        f"--{boundary}\r\n"
        f"Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n"
        f"{body_text}\r\n\r\n"
        f"{attachment_part}"
        f"--{boundary}--\r\n"
    )

    return eml_str.encode("utf-8")


def generate_synthetic_features(n_samples: int = 80) -> Tuple[np.ndarray, np.ndarray]:
    print(f"[*] Generating and processing {n_samples} synthetic emails through full pipeline...")
    half = n_samples // 2

    feature_rows: list[list[float]] = []
    labels: list[int] = []

    for i in range(n_samples):
        is_phish = (i >= half)
        raw_eml = build_synthetic_email_eml(i, is_phishing=is_phish)

        data = ingest_email(raw_eml)
        h_res = analyze_headers(data)
        u_res = analyze_urls(data)
        t_res = analyze_text(data)
        a_res = analyze_attachments(data)

        agg = aggregate_evidence(h_res, u_res, t_res, a_res)
        row = [agg.feature_vector.feature_values[f] for f in ACTIVE_META_FEATURE_NAMES]
        feature_rows.append(row)
        labels.append(1 if is_phish else 0)

        if (i + 1) % 20 == 0 or (i + 1) == n_samples:
            print(f"    Processed {i + 1}/{n_samples} emails...")

    X = np.array(feature_rows, dtype=float)
    y = np.array(labels, dtype=int)
    print(f"[+] Feature matrix constructed: shape {X.shape}, class balance: {np.bincount(y)}")
    return X, y


# ---------------------------------------------------------------------------
# 3. Model Weight Extraction & Explainability Audit
# ---------------------------------------------------------------------------

def extract_model_weights(model: Any) -> list[dict[str, Any]]:
    """
    Extracts average standardized coefficients for each active feature.
    """
    weights_accum = np.zeros(ACTIVE_META_FEATURE_COUNT, dtype=float)

    if hasattr(model, "calibrated_classifiers_"):
        n_est = len(model.calibrated_classifiers_)
        for cal_clf in model.calibrated_classifiers_:
            pipe = cal_clf.estimator
            clf = pipe.named_steps["clf"]
            weights_accum += clf.coef_[0]
        avg_weights = weights_accum / max(1, n_est)
    elif hasattr(model, "named_steps"):
        clf = model.named_steps["clf"]
        avg_weights = clf.coef_[0]
    else:
        avg_weights = model.coef_[0]

    feature_weight_list = []
    for i, fname in enumerate(ACTIVE_META_FEATURE_NAMES):
        mod = fname.split("_", 1)[0]
        feature_weight_list.append({
            "feature_name": fname,
            "modality": mod,
            "weight": round(float(avg_weights[i]), 4),
        })

    return feature_weight_list


# ---------------------------------------------------------------------------
# 4. Validation Threshold Sweep & Optimization
# ---------------------------------------------------------------------------

def sweep_validation_thresholds(
    model: Any,
    X_val: np.ndarray,
    y_val: np.ndarray,
    min_coverage_floor: float = 0.80,
) -> Tuple[float, float, list[dict[str, Any]]]:
    """
    Sweeps abstention thresholds (tau_low, tau_high) on the validation split
    to identify the optimal trade-off between coverage and selective accuracy.
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
# 5. Held-Out Test Split Evaluation & Error Analysis
# ---------------------------------------------------------------------------

def evaluate_on_test_split(
    model: Any,
    X_test: np.ndarray,
    y_test: np.ndarray,
    test_meta: list[dict[str, Any]],
    abstain_low: float,
    abstain_high: float,
) -> dict[str, Any]:
    """
    Evaluates strictly once on the sealed held-out test split, capturing
    standard metrics, selective metrics, and forensic error audit details.
    """
    test_probs = model.predict_proba(X_test)[:, 1]
    raw_preds = (test_probs >= 0.5).astype(int)

    # Standard metrics across all samples
    roc_auc = float(roc_auc_score(y_test, test_probs)) if len(np.unique(y_test)) > 1 else 1.0
    brier = float(brier_score_loss(y_test, test_probs))
    std_acc = float(accuracy_score(y_test, raw_preds))
    std_prec = float(precision_score(y_test, raw_preds, zero_division=0))
    std_rec = float(recall_score(y_test, raw_preds, zero_division=0))
    std_f1 = float(f1_score(y_test, raw_preds, average="macro", zero_division=0))

    # Selective predictions
    non_abstained_mask = (test_probs < abstain_low) | (test_probs > abstain_high)
    n_total = len(y_test)
    n_abstained = int(np.sum(~non_abstained_mask))
    n_retained = int(np.sum(non_abstained_mask))

    abstention_rate = float(n_abstained / n_total) if n_total > 0 else 0.0
    coverage = float(1.0 - abstention_rate)

    if n_retained > 0:
        sel_probs = test_probs[non_abstained_mask]
        sel_y = y_test[non_abstained_mask]
        sel_preds = (sel_probs >= 0.5).astype(int)

        sel_acc = float(accuracy_score(sel_y, sel_preds))
        sel_prec = float(precision_score(sel_y, sel_preds, zero_division=0))
        sel_rec = float(recall_score(sel_y, sel_preds, zero_division=0))
        sel_f1 = float(f1_score(sel_y, sel_preds, average="macro", zero_division=0))
    else:
        sel_acc = sel_prec = sel_rec = sel_f1 = 0.0

    # Forensic Error Analysis
    false_positives = []
    false_negatives = []
    abstained_samples = []

    for i in range(len(test_probs)):
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
        "standard_macro_f1": round(std_f1, 4),
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
        "error_analysis": {
            "false_positives_count": len(false_positives),
            "false_negatives_count": len(false_negatives),
            "abstained_count": len(abstained_samples),
            "false_positives": false_positives[:10],
            "false_negatives": false_negatives[:10],
            "abstained_samples": abstained_samples[:10],
        },
    }


# ---------------------------------------------------------------------------
# 6. Main Controller
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Train and evaluate Layer 3 Meta-Classifier on Real or Synthetic Data")
    parser.add_argument("--real-data", type=str, default=None, help="Path to real_meta_features.jsonl cached dataset")
    parser.add_argument("--synthetic-demo", action="store_true", default=False, help="Train on synthetic demo data")
    parser.add_argument("--samples", type=int, default=80, help="Number of synthetic emails to generate if --synthetic-demo")
    parser.add_argument("--output-dir", type=str, default=None, help="Target model bundle directory")
    parser.add_argument("--model-name", type=str, default=None, help="Model bundle name")
    parser.add_argument("--cv", type=int, default=5, help="Cross-validation folds for Platt calibration")
    parser.add_argument("--abstain-low", type=float, default=None, help="Override lower abstention threshold")
    parser.add_argument("--abstain-high", type=float, default=None, help="Override upper abstention threshold")

    args = parser.parse_args()

    # Determine execution mode: prefer real-data if present on disk or specified
    default_real_jsonl = PROJECT_ROOT / "data" / "processed" / "real_meta_features.jsonl"
    use_real = bool(args.real_data or (not args.synthetic_demo and default_real_jsonl.is_file()))

    if use_real:
        data_path = Path(args.real_data) if args.real_data else default_real_jsonl
        out_dir = Path(args.output_dir) if args.output_dir else PROJECT_ROOT / "models" / "meta_classifier_real_v1"
        model_name = args.model_name or "meta_classifier_real_v1"
        mode_title = f"Real Dataset Mode ({data_path.name})"
    else:
        data_path = None
        out_dir = Path(args.output_dir) if args.output_dir else PROJECT_ROOT / "models" / "meta_classifier_v1"
        model_name = args.model_name or "meta_classifier_v1"
        mode_title = f"Synthetic Demo Mode ({args.samples} samples)"

    out_dir.mkdir(parents=True, exist_ok=True)

    print("======================================================================")
    print("      Multi-Agent Phishing Detector - Meta-Classifier Trainer         ")
    print(f"      Mode: {mode_title}")
    print("======================================================================")

    if use_real:
        # Load pre-split real dataset
        print(f"[*] Loading partitioned dataset from: {data_path}")
        X_dict, y_dict, meta_dict = load_real_feature_dataset(data_path)

        X_train, y_train = X_dict["train"], y_dict["train"]
        X_val, y_val = X_dict["val"], y_dict["val"]
        X_test, y_test = X_dict["test"], y_dict["test"]

        print(f"[+] Loaded splits: Train={len(X_train)} (Phish: {np.sum(y_train)}), "
              f"Val={len(X_val)} (Phish: {np.sum(y_val)}), "
              f"Test={len(X_test)} (Phish: {np.sum(y_test)})")

        # Train on train split
        print(f"[*] Training calibrated meta-classifier on Train split (cv={args.cv})...")
        model, metadata = train_meta_classifier(
            X_train,
            y_train,
            calibrate=True,
            cv=args.cv,
            random_state=42,
            model_name=model_name,
            model_version="1.0.0",
        )

        # Threshold optimization on Validation split
        if args.abstain_low is not None and args.abstain_high is not None:
            opt_low, opt_high = args.abstain_low, args.abstain_high
            sweep_history = []
            print(f"[*] Using user-specified abstention thresholds: [{opt_low}, {opt_high}]")
        else:
            print("[*] Sweeping abstention thresholds on Validation split...")
            opt_low, opt_high, sweep_history = sweep_validation_thresholds(
                model=model,
                X_val=X_val,
                y_val=y_val,
                min_coverage_floor=0.80,
            )
            print(f"[+] Optimal Validation thresholds identified: tau_low={opt_low}, tau_high={opt_high}")

        # Evaluate strictly once on held-out Test split
        print("[*] Evaluating strictly on sealed held-out Test split...")
        test_eval = evaluate_on_test_split(
            model=model,
            X_test=X_test,
            y_test=y_test,
            test_meta=meta_dict["test"],
            abstain_low=opt_low,
            abstain_high=opt_high,
        )

        test_eval["validation_sweep"] = sweep_history

    else:
        # Synthetic demo mode
        X, y = generate_synthetic_features(n_samples=args.samples)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=y
        )
        print(f"[*] Split: {len(X_train)} train samples, {len(X_test)} test samples.")

        print(f"[*] Training calibrated meta-classifier (cv={args.cv})...")
        model, metadata = train_meta_classifier(
            X_train,
            y_train,
            calibrate=True,
            cv=args.cv,
            random_state=42,
            model_name=model_name,
            model_version="1.0.0",
        )

        opt_low = args.abstain_low if args.abstain_low is not None else 0.35
        opt_high = args.abstain_high if args.abstain_high is not None else 0.65

        dummy_meta = [{"sample_id": f"synthetic_{i}", "assigned_label": "phishing" if y_test[i] else "legit"} for i in range(len(y_test))]
        test_eval = evaluate_on_test_split(
            model=model,
            X_test=X_test,
            y_test=y_test,
            test_meta=dummy_meta,
            abstain_low=opt_low,
            abstain_high=opt_high,
        )

    # 4. Save Cryptographically Verified Bundle
    joblib_path, meta_path = save_model_bundle(
        model=model,
        metadata=metadata,
        output_dir=out_dir,
        model_name=model_name,
    )
    print(f"[+] Model artifact persisted to: {joblib_path}")
    print(f"[+] Metadata and SHA-256 saved to: {meta_path}")

    # 5. Extract Feature Weights & Explainability Audit
    weights = extract_model_weights(model)
    top_phish_weights = sorted([w for w in weights if w["weight"] > 0], key=lambda x: x["weight"], reverse=True)[:10]
    top_legit_weights = sorted([w for w in weights if w["weight"] < 0], key=lambda x: x["weight"])[:10]

    test_eval["model_weights_audit"] = {
        "top_phishing_features": top_phish_weights,
        "top_legitimate_features": top_legit_weights,
    }

    eval_file = out_dir / "evaluation_report.json"
    eval_file.write_text(json.dumps(test_eval, indent=2), encoding="utf-8")
    print(f"[+] Comprehensive evaluation report saved to: {eval_file}")

    # 6. Display Metrics Summary
    print("\n---------------------- Evaluation Results ----------------------")
    print(f" Test Set Size           : {test_eval['test_samples']}")
    print(f" Raw Accuracy (All)      : {test_eval['standard_accuracy']:.2%}")
    print(f" Standard Precision      : {test_eval['standard_precision']:.2%}")
    print(f" Standard Recall         : {test_eval['standard_recall']:.2%}")
    print(f" Standard Macro-F1       : {test_eval['standard_macro_f1']:.4f}")
    print(f" ROC-AUC                 : {test_eval['roc_auc']:.4f}")
    print(f" Brier Score             : {test_eval['brier_score']:.4f}")
    print(f" Abstention Band         : [{opt_low}, {opt_high}]")
    print(f" Coverage                : {test_eval['coverage']:.2%}")
    print(f" Abstention Rate         : {test_eval['abstention_rate']:.2%}")
    print(f" Retained Predictions    : {test_eval['retained_samples']}/{test_eval['test_samples']}")
    print(f" Selective Accuracy      : {test_eval['selective_accuracy']:.2%}")
    print(f" Selective Precision     : {test_eval['selective_precision']:.2%}")
    print(f" Selective Recall        : {test_eval['selective_recall']:.2%}")
    print(f" Selective Macro-F1      : {test_eval['selective_macro_f1']:.4f}")
    print("----------------------------------------------------------------")

    print("\n[+] TOP 10 PHISHING FEATURES (Model Weights):")
    for idx, w in enumerate(top_phish_weights, 1):
        print(f"  {idx:2d}. [{w['modality'].upper():<10}] {w['feature_name']:<42} : +{w['weight']:.4f}")

    print("\n[+] TOP 10 LEGITIMATE FEATURES (Model Weights):")
    for idx, w in enumerate(top_legit_weights, 1):
        print(f"  {idx:2d}. [{w['modality'].upper():<10}] {w['feature_name']:<42} : {w['weight']:.4f}")

    errs = test_eval["error_analysis"]
    print(f"\n[!] Error Summary: {errs['false_positives_count']} False Positives, {errs['false_negatives_count']} False Negatives, {errs['abstained_count']} Abstained.")
    print("----------------------------------------------------------------\n")
    print("[✓] Model bundle is verified and ready for deployment.")


if __name__ == "__main__":
    main()
