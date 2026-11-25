"""
scripts/analyze_email_cli.py
----------------------------
Command-Line Interface for the Multi-Agent AI Phishing Email Detector.

Usage:
    python scripts/analyze_email_cli.py path/to/email.eml [--model-dir models/meta_classifier_v1] [--json-out report.json]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

# Ensure project root in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.pipeline.orchestrator import PhishingDetectorPipeline
from app.schemas.meta_classifier_schema import DecisionThresholds, Verdict


def print_cli_report(report) -> None:
    """
    Renders an ASCII-formatted forensic inspection report to stdout.
    """
    v_res = report.verdict_result
    agg = report.aggregated_evidence
    vec = agg.feature_vector

    print("\n" + "=" * 74)
    print("      MULTI-AGENT PHISHING DETECTOR - FORENSIC ANALYSIS REPORT      ")
    print("=" * 74)
    print(f" Email ID        : {report.email_id}")
    print(f" Analyzed At     : {report.analyzed_at_utc}")
    print(f" Processing Time : {report.total_processing_time_ms:.1f} ms")
    print(f" Active Features : {vec.active_feature_count} (Quarantined: {vec.quarantined_feature_count})")
    print("-" * 74)

    # Verdict Banner
    if v_res.verdict == Verdict.PHISHING:
        banner = "[!] FINAL VERDICT: PHISHING (HIGH RISK)"
    elif v_res.verdict == Verdict.LEGITIMATE:
        banner = "[✓] FINAL VERDICT: LEGITIMATE (CLEAN)"
    else:
        banner = f"[?] FINAL VERDICT: ABSTAIN ({v_res.abstention_reason.value.upper()})"

    print(f"\n{banner}")
    if v_res.calibrated_probability is not None:
        print(f" Calibrated Probability : {v_res.calibrated_probability:.2%}")
        print(f" Decision Confidence    : {v_res.confidence:.2%}")
    else:
        print(" Calibrated Probability : N/A (Health-driven abstention override)")

    print(f" Overall Completeness   : {agg.overall_completeness:.2%}")
    print(f" Model Version          : {v_res.model_version}")

    # Modality Health Manifest
    print("\n[+] MODALITY HEALTH MANIFEST")
    print("  " + "-" * 70)
    print(f"  {'Modality':<14} {'Status':<12} {'Completeness':<14} {'Active Feats':<14} {'Missing Feats'}")
    print("  " + "-" * 70)
    for mod in ("header", "url", "text", "attachment"):
        h = agg.modality_health.get(mod)
        if h:
            print(f"  {mod.capitalize():<14} {h.status.value.upper():<12} {h.completeness:<14.2%} {h.active_feature_count:<14} {h.missing_feature_count}")
    print("  " + "-" * 70)

    # Linear Attribution (Explainability)
    if v_res.top_phishing_contributors:
        print("\n[+] TOP FEATURES DRIVING PHISHING PREDICTION:")
        for idx, fc in enumerate(v_res.top_phishing_contributors[:5], start=1):
            print(f"  {idx}. [{fc.modality.upper()}] {fc.feature_name}: +{fc.contribution_score:.3f} (val: {fc.feature_value})")

    if v_res.top_legitimate_contributors:
        print("\n[+] TOP FEATURES DRIVING LEGITIMATE PREDICTION:")
        for idx, fc in enumerate(v_res.top_legitimate_contributors[:5], start=1):
            print(f"  {idx}. [{fc.modality.upper()}] {fc.feature_name}: {fc.contribution_score:.3f} (val: {fc.feature_value})")

    # Forensic Evidence Trail
    if agg.unified_evidence:
        print(f"\n[+] TIER 2 FORENSIC EVIDENCE ({len(agg.unified_evidence)} items, {agg.omitted_evidence_count} omitted):")
        for idx, ev in enumerate(agg.unified_evidence[:6], start=1):
            print(f"  {idx}. [{ev.severity.upper()}] [{ev.source_modality.upper()}] {ev.feature_name}:")
            print(f"     Description : {ev.description}")
            if ev.snippet_bounded:
                print(f"     Snippet     : \"{ev.snippet_bounded}\"")
    else:
        print("\n[+] TIER 2 FORENSIC EVIDENCE: Zero anomalous findings observed.")

    # Agent Errors / Warnings
    if report.agent_errors:
        print("\n[!] AGENT EXECUTION ERRORS:")
        for mod, err in report.agent_errors.items():
            print(f"  - [{mod.upper()}]: {err}")

    if agg.warnings:
        print("\n[*] PIPELINE DIAGNOSTIC WARNINGS:")
        for w in agg.warnings[:5]:
            print(f"  - {w}")

    print("\n" + "=" * 74 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Analyze an .eml email file with the Multi-Agent Phishing Detector")
    parser.add_argument("eml_file", type=str, help="Path to RFC 5322 .eml file")
    default_model = "models/meta_classifier_real_v1" if (PROJECT_ROOT / "models" / "meta_classifier_real_v1").exists() else "models/meta_classifier_v1"
    parser.add_argument("--model-dir", type=str, default=default_model, help="Path to model bundle directory")
    parser.add_argument("--json-out", type=str, default=None, help="Optional output path for analysis report JSON")
    parser.add_argument("--abstain-low", type=float, default=0.35, help="Lower threshold for legitimate verdict")
    parser.add_argument("--abstain-high", type=float, default=0.65, help="Upper threshold for phishing verdict")

    args = parser.parse_args()

    eml_path = Path(args.eml_file)
    if not eml_path.is_file():
        print(f"Error: Email file '{eml_path}' not found.", file=sys.stderr)
        sys.exit(1)

    thresholds = DecisionThresholds(abstain_low=args.abstain_low, abstain_high=args.abstain_high)
    try:
        pipeline = PhishingDetectorPipeline(model_path=args.model_dir, thresholds=thresholds)
    except Exception as e:
        print(f"Error initializing pipeline: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        report = pipeline.analyze_eml_file(eml_path)
    except Exception as e:
        print(f"Error analyzing email: {e}", file=sys.stderr)
        sys.exit(1)

    # Print human-readable report
    print_cli_report(report)

    # Export JSON if requested
    if args.json_out:
        out_p = Path(args.json_out)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        print(f"[✓] Full JSON analysis report written to '{out_p}'.")


if __name__ == "__main__":
    main()
