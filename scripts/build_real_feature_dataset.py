#!/usr/bin/env python3
"""
scripts/build_real_feature_dataset.py
-------------------------------------
Extracts, splits, and caches 132-dimensional meta-feature vectors from the
real development email corpus (SpamAssassin 2002-2003 & Nazario 2015/2021).

Strict Dependencies:
- Python standard library (hashlib, json, pathlib, argparse, sys, time)
- Existing project modules (app.ingestion, app.agents, app.aggregation)
- Output format: Plain JSON Lines (.jsonl) with zero Parquet/third-party dependencies.

Protocol (from docs/research/dataset_split_strategy.md):
- Total 1,000 emails: 750 Ham (500 easy, 250 hard), 250 Phishing (188 2015, 62 2021).
- Split Policy:
    • Train (60%, n=600): 300 easy_ham, 150 hard_ham, 113 phish_2015, 37 phish_2021
    • Val   (20%, n=200): 100 easy_ham,  50 hard_ham,  38 phish_2015, 12 phish_2021
    • Test  (20%, n=200): 100 easy_ham,  50 hard_ham,  37 phish_2015, 13 phish_2021
- Grouped & Deterministic: Deduplicated by content SHA-256 before splitting.
  Sorted by (category, sha256) with seed=42 to guarantee zero leakage and exact reproducibility.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
from typing import Any, Optional

# Ensure project root in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.ingestion.email_ingestor import ingest_email
from app.agents.header_agent import analyze_headers
from app.agents.url_agent import analyze_urls
from app.agents.text_agent import analyze_text
from app.agents.attachment_agent import analyze_attachments
from app.aggregation.evidence_aggregator import aggregate_evidence
from app.schemas.aggregator_schema import ACTIVE_META_FEATURE_NAMES


def compute_bytes_sha256(raw_bytes: bytes) -> str:
    return hashlib.sha256(raw_bytes).hexdigest()


def load_candidate_records(
    eml_root: Path,
    manifest_path: Optional[Path] = None,
) -> list[dict[str, Any]]:
    """
    Loads email candidate records from dev_manifest.jsonl or directly from eml directories.
    """
    records: list[dict[str, Any]] = []

    if manifest_path and manifest_path.is_file():
        print(f"[*] Reading development manifest: {manifest_path}")
        with open(manifest_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                rel_path = r.get("relative_eml_path", "")
                eml_path = eml_root.parent / rel_path if "eml/" in rel_path else eml_root / rel_path
                if not eml_path.is_file():
                    # Check under eml_root directly
                    fname = r.get("export_filename") or Path(rel_path).name
                    found = list(eml_root.rglob(fname))
                    if found:
                        eml_path = found[0]

                records.append({
                    "sample_id": r.get("sample_id", ""),
                    "eml_path": eml_path,
                    "source_category": r.get("source_category", ""),
                    "source_year": r.get("source_year", ""),
                    "assigned_label": r.get("assigned_label", ""),
                    "sha256": r.get("sha256", ""),
                })
    else:
        print(f"[*] Scanning EML directory recursively: {eml_root}")
        for p in eml_root.rglob("*.eml"):
            # Deduce category from folder name
            parent_name = p.parent.name
            if "easy" in parent_name:
                cat = "easy_ham"
                label = "ham_easy"
                yr = ""
            elif "hard" in parent_name:
                cat = "hard_ham"
                label = "ham_hard"
                yr = ""
            else:
                cat = "phishing"
                label = "phishing"
                yr = "2021" if "2021" in p.name else "2015"

            records.append({
                "sample_id": p.stem,
                "eml_path": p,
                "source_category": cat,
                "source_year": yr,
                "assigned_label": label,
                "sha256": "",
            })

    return records


def partition_dataset(
    records: list[dict[str, Any]],
) -> Tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Deduplicates candidates and applies the exact grouped stratified partition
    from docs/research/dataset_split_strategy.md Section 3.1.
    """
    # 1. Deduplicate by SHA-256
    seen_hashes: set[str] = set()
    deduped: list[dict[str, Any]] = []
    duplicate_count = 0

    for r in records:
        h = r.get("sha256")
        if not h:
            raw_bytes = r["eml_path"].read_bytes()
            h = compute_bytes_sha256(raw_bytes)
            r["sha256"] = h

        if h in seen_hashes:
            duplicate_count += 1
            continue
        seen_hashes.add(h)
        deduped.append(r)

    print(f"[*] Total records: {len(records)}, Deduplicated: {len(deduped)} (Duplicates removed: {duplicate_count})")

    # 2. Segregate into 4 canonical strata
    easy_ham = [r for r in deduped if r["source_category"] == "easy_ham"]
    hard_ham = [r for r in deduped if r["source_category"] == "hard_ham"]
    phish_2015 = [r for r in deduped if r["source_category"] == "phishing" and r.get("source_year") == "2015"]
    phish_2021 = [r for r in deduped if r["source_category"] == "phishing" and r.get("source_year") == "2021"]

    # Fallback if source_year was not tagged
    if not phish_2015 and not phish_2021:
        all_phish = [r for r in deduped if "phish" in r["source_category"] or r["assigned_label"] == "phishing"]
        all_phish.sort(key=lambda x: (x["source_category"], x["sha256"]))
        phish_2015 = all_phish[:188]
        phish_2021 = all_phish[188:]

    # Deterministic sort within each stratum before slicing
    easy_ham.sort(key=lambda x: (x["source_category"], x["sha256"]))
    hard_ham.sort(key=lambda x: (x["source_category"], x["sha256"]))
    phish_2015.sort(key=lambda x: (x["source_category"], x["sha256"]))
    phish_2021.sort(key=lambda x: (x["source_category"], x["sha256"]))

    # Slice according to Section 3.1:
    # easy_ham: 300 / 100 / 100 (total 500)
    # hard_ham: 150 /  50 /  50 (total 250)
    # phish_15: 113 /  38 /  37 (total 188)
    # phish_21:  37 /  12 /  13 (total 62)
    def assign_splits(group, n_train, n_val, n_test):
        for item in group[:n_train]:
            item["split"] = "train"
        for item in group[n_train:n_train + n_val]:
            item["split"] = "val"
        for item in group[n_train + n_val:n_train + n_val + n_test]:
            item["split"] = "test"

    assign_splits(easy_ham, 300, 100, 100)
    assign_splits(hard_ham, 150, 50, 50)
    assign_splits(phish_2015, 113, 38, 37)
    assign_splits(phish_2021, 37, 12, 13)

    partitioned = easy_ham + hard_ham + phish_2015 + phish_2021
    # Deterministic final sort
    partitioned.sort(key=lambda x: (x["split"], x["source_category"], x["sha256"]))

    split_counts = {
        "train": sum(1 for r in partitioned if r["split"] == "train"),
        "val": sum(1 for r in partitioned if r["split"] == "val"),
        "test": sum(1 for r in partitioned if r["split"] == "test"),
    }
    print(f"[+] Partitions assigned: Train={split_counts['train']}, Val={split_counts['val']}, Test={split_counts['test']}")

    manifest_summary = {
        "total_samples": len(partitioned),
        "split_counts": split_counts,
        "splits_by_category": {
            "easy_ham": {s: sum(1 for r in easy_ham if r["split"] == s) for s in ("train", "val", "test")},
            "hard_ham": {s: sum(1 for r in hard_ham if r["split"] == s) for s in ("train", "val", "test")},
            "phish_2015": {s: sum(1 for r in phish_2015 if r["split"] == s) for s in ("train", "val", "test")},
            "phish_2021": {s: sum(1 for r in phish_2021 if r["split"] == s) for s in ("train", "val", "test")},
        },
    }

    return partitioned, manifest_summary


def extract_real_feature_dataset(
    partitioned_records: list[dict[str, Any]],
    output_jsonl: Path,
) -> dict[str, int]:
    """
    Runs every email through Layer 0 -> Layer 1 -> Layer 2 pipeline and writes
    the active 132-feature meta-vectors to JSON Lines cache.
    """
    output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()

    success_count = 0
    failure_count = 0

    print(f"[*] Extracting features for {len(partitioned_records)} emails...")

    with open(output_jsonl, "w", encoding="utf-8") as out_f:
        for idx, rec in enumerate(partitioned_records, start=1):
            eml_path: Path = rec["eml_path"]
            label_int = 1 if "phish" in rec["source_category"].lower() or rec["assigned_label"] == "phishing" else 0

            try:
                raw_bytes = eml_path.read_bytes()
                # Layer 0: Ingest
                data = ingest_email(raw_bytes)

                # Layer 1: Specialist Agents
                h_res = analyze_headers(data)
                u_res = analyze_urls(data)
                t_res = analyze_text(data)
                a_res = analyze_attachments(data)

                # Layer 2: Aggregator
                agg = aggregate_evidence(h_res, u_res, t_res, a_res)

                # Output record conforming to locked stdlib JSON schema
                out_record = {
                    "sample_id": rec.get("sample_id", f"sample_{idx}"),
                    "sha256": rec["sha256"],
                    "source_category": rec["source_category"],
                    "source_year": rec.get("source_year", ""),
                    "assigned_label": rec["assigned_label"],
                    "label": label_int,
                    "split": rec["split"],
                    "feature_values": {f: agg.feature_vector.feature_values[f] for f in ACTIVE_META_FEATURE_NAMES},
                    "missingness_mask": {f: agg.feature_vector.missingness_mask[f] for f in ACTIVE_META_FEATURE_NAMES},
                    "modality_health": {
                        mod: {
                            "status": h.status.value,
                            "completeness": h.completeness,
                            "active_feature_count": h.active_feature_count,
                            "missing_feature_count": h.missing_feature_count,
                            "error_message": h.error_message,
                        }
                        for mod, h in agg.modality_health.items()
                    },
                    "overall_completeness": agg.overall_completeness,
                    "abstention_recommended_by_health": agg.abstention_recommended_by_health,
                    "evidence_count": len(agg.unified_evidence),
                    "omitted_evidence_count": agg.omitted_evidence_count,
                    "processing_time_ms": agg.processing_time_ms,
                }

                out_f.write(json.dumps(out_record) + "\n")
                success_count += 1

            except Exception as e:
                failure_count += 1
                print(f"    [!] Warning: Failed to process {eml_path.name}: {e}")

            if idx % 100 == 0 or idx == len(partitioned_records):
                elapsed = time.perf_counter() - t0
                rate = idx / max(0.001, elapsed)
                print(f"    Processed {idx}/{len(partitioned_records)} emails ({elapsed:.1f}s, {rate:.1f} emails/s)...")

    total_time = time.perf_counter() - t0
    print(f"[✓] Feature extraction complete in {total_time:.1f}s ({success_count} success, {failure_count} failures).")
    print(f"[+] Cached feature dataset written to: {output_jsonl}")

    return {"success": success_count, "failure": failure_count}


def main():
    parser = argparse.ArgumentParser(description="Build and cache real meta-features dataset (.jsonl)")
    parser.add_argument("--eml-dir", type=str, default="data/dev/eml", help="Root directory containing .eml files")
    parser.add_argument("--manifest", type=str, default="data/dev/manifests/dev_manifest.jsonl", help="Development manifest path")
    parser.add_argument("--output-jsonl", type=str, default="data/processed/real_meta_features.jsonl", help="Output .jsonl path")
    parser.add_argument("--split-manifest", type=str, default="data/dev/manifests/split_manifest.json", help="Output split manifest JSON")

    args = parser.parse_args()

    eml_root = Path(args.eml_dir)
    manifest_p = Path(args.manifest) if args.manifest else None
    out_jsonl = Path(args.output_jsonl)
    split_meta_p = Path(args.split_manifest)

    print("======================================================================")
    print("      Multi-Agent Phishing Detector - Real Feature Dataset Builder    ")
    print("======================================================================")

    # 1. Load candidate records
    records = load_candidate_records(eml_root=eml_root, manifest_path=manifest_p)
    if not records:
        print(f"Error: Zero candidate records found at {eml_root}.", file=sys.stderr)
        sys.exit(1)

    # 2. Partition dataset
    partitioned, summary = partition_dataset(records)

    # Persist split manifest
    split_meta_p.parent.mkdir(parents=True, exist_ok=True)
    split_meta_p.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[+] Split manifest saved to: {split_meta_p}")

    # 3. Extract features and write .jsonl cache
    stats = extract_real_feature_dataset(partitioned, out_jsonl)

    print("----------------------------------------------------------------------")
    print(f" Summary: {stats['success']} records written, {stats['failure']} errors.")
    print("======================================================================")


if __name__ == "__main__":
    main()
