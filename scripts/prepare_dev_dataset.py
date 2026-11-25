"""
Development Dataset Builder for Task 8.3.

Builds the approved 1,000-email development dataset from raw archives:
- 500 SpamAssassin easy_ham  -> data/dev/eml/ham_easy/ (label: ham_easy)
- 250 SpamAssassin hard_ham  -> data/dev/eml/ham_hard/ (label: ham_hard)
- 250 Nazario 2015-2021      -> data/dev/eml/phishing/ (label: phishing)
Total: 1,000 emails.

Key requirements:
- Excludes UW IMAP internal mailbox records at key 0 in Nazario yearly archives.
- Converts candidates to separated staging directory under data/dev/staging/.
- Calculates proportional allocation for phishing from verified usable candidate counts.
- Enforces deterministic sampling with seed 42.
- Strictly prevents duplicate SHA-256 hashes in final dataset.
- Preserves raw bytes without modifying raw source archives.
- Passive presence detection of authentication headers (DKIM, Authentication-Results, SPF, ARC).
- Produces full dataset manifests (CSV and JSONL) and detailed summary JSON.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import random
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure scripts dir is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from convert_mbox_to_eml import (
    convert_mbox_to_eml,
    convert_tar_bz2_to_eml,
    import_flat_rfc822_dir,
    inspect_raw_datasets,
    write_manifest_csv,
    write_manifest_jsonl,
    write_dataset_summary,
    write_eml_file,
    generate_deterministic_filename,
    detect_authentication_headers,
    is_uw_imap_internal_record,
    ConversionRecord,
    ExcludedRecord,
    DEFAULT_RANDOM_SEED,
    TARGET_EASY_HAM_COUNT,
    TARGET_HARD_HAM_COUNT,
    TARGET_NAZARIO_PHISHING_COUNT,
    TOTAL_TARGET_COUNT,
)


def build_task8_3_dev_dataset(
    raw_base_dir: str | Path,
    dev_base_dir: str | Path,
    seed: int = DEFAULT_RANDOM_SEED,
    overwrite: bool = False,
) -> Dict[str, Any]:
    """
    Build the approved Task 8.3 1,000-email development dataset.

    Sources:
    - 20030228_easy_ham.tar.bz2 -> 500 samples (ham_easy)
    - 20030228_hard_ham.tar.bz2 -> 250 samples (ham_hard)
    - phishing-2015.mbox & phishing-2021.mbox -> 250 samples (phishing, proportional)
    """
    raw_dir = Path(raw_base_dir)
    dev_dir = Path(dev_base_dir)

    staging_dir = dev_dir / "staging"
    eml_dir = dev_dir / "eml"
    manifests_dir = dev_dir / "manifests"
    manifest_csv = manifests_dir / "dev_manifest.csv"
    manifest_jsonl = manifests_dir / "dev_manifest.jsonl"
    conversion_manifest_jsonl = manifests_dir / "conversion_manifest.jsonl"
    summary_json = manifests_dir / "dev_dataset_summary.json"

    # Step 1: Verify presence of raw source files
    easy_ham_archive = raw_dir / "20030228_easy_ham.tar.bz2"
    easy_ham_dir = raw_dir / "easy_ham"
    easy_ham_src = easy_ham_archive if easy_ham_archive.is_file() else (easy_ham_dir if easy_ham_dir.is_dir() else None)

    hard_ham_archive = raw_dir / "20030228_hard_ham.tar.bz2"
    hard_ham_dir = raw_dir / "hard_ham"
    hard_ham_src = hard_ham_archive if hard_ham_archive.is_file() else (hard_ham_dir if hard_ham_dir.is_dir() else None)

    phish_2015_mbox = raw_dir / "phishing-2015.mbox"
    if not phish_2015_mbox.is_file() and (raw_dir / "phishing-2015").is_file():
        phish_2015_mbox = raw_dir / "phishing-2015"

    phish_2021_mbox = raw_dir / "phishing-2021.mbox"
    if not phish_2021_mbox.is_file() and (raw_dir / "phishing-2021").is_file():
        phish_2021_mbox = raw_dir / "phishing-2021"

    missing_items = []
    if easy_ham_src is None:
        missing_items.append("SpamAssassin easy_ham (20030228_easy_ham.tar.bz2 or directory)")
    if hard_ham_src is None:
        missing_items.append("SpamAssassin hard_ham (20030228_hard_ham.tar.bz2 or directory)")
    if not phish_2015_mbox.is_file():
        missing_items.append("Nazario 2015 archive (phishing-2015.mbox)")
    if not phish_2021_mbox.is_file():
        missing_items.append("Nazario 2021 archive (phishing-2021.mbox)")

    if missing_items:
        return {
            "status": "MISSING_DATASETS",
            "missing_items": missing_items,
            "message": f"Cannot build Task 8.3 development dataset: missing required raw files: {'; '.join(missing_items)}",
        }

    # Step 2: Convert candidate messages into staging
    staging_dir.mkdir(parents=True, exist_ok=True)
    manifests_dir.mkdir(parents=True, exist_ok=True)

    staging_easy_dir = staging_dir / "easy_ham"
    staging_hard_dir = staging_dir / "hard_ham"
    staging_p2015_dir = staging_dir / "phishing_2015"
    staging_p2021_dir = staging_dir / "phishing_2021"

    # Easy Ham staging
    if easy_ham_src.is_file():
        staged_easy_records, easy_stats = convert_tar_bz2_to_eml(
            tar_path=easy_ham_src,
            output_dir=staging_easy_dir,
            source_dataset="spamassassin",
            source_category="easy_ham",
            assigned_label="ham_easy",
            prefix="stage_easy",
            id_prefix="STAGE_EASY",
            overwrite=overwrite,
        )
    else:
        staged_easy_records, easy_stats = import_flat_rfc822_dir(
            input_dir=easy_ham_src,
            output_dir=staging_easy_dir,
            source_dataset="spamassassin",
            source_category="easy_ham",
            assigned_label="ham_easy",
            prefix="stage_easy",
            id_prefix="STAGE_EASY",
            overwrite=overwrite,
        )

    # Hard Ham staging
    if hard_ham_src.is_file():
        staged_hard_records, hard_stats = convert_tar_bz2_to_eml(
            tar_path=hard_ham_src,
            output_dir=staging_hard_dir,
            source_dataset="spamassassin",
            source_category="hard_ham",
            assigned_label="ham_hard",
            prefix="stage_hard",
            id_prefix="STAGE_HARD",
            overwrite=overwrite,
        )
    else:
        staged_hard_records, hard_stats = import_flat_rfc822_dir(
            input_dir=hard_ham_src,
            output_dir=staging_hard_dir,
            source_dataset="spamassassin",
            source_category="hard_ham",
            assigned_label="ham_hard",
            prefix="stage_hard",
            id_prefix="STAGE_HARD",
            overwrite=overwrite,
        )

    # Phishing 2015 staging (filter UW IMAP internal records)
    staged_p2015_records, p2015_stats = convert_mbox_to_eml(
        mbox_path=phish_2015_mbox,
        output_dir=staging_p2015_dir,
        source_dataset="nazario",
        source_category="phishing",
        assigned_label="phishing",
        source_archive=phish_2015_mbox.name,
        source_year="2015",
        prefix="stage_phish_2015",
        id_prefix="STAGE_PHISH_2015",
        filter_uw_internal=True,
        overwrite=overwrite,
    )

    # Phishing 2021 staging (filter UW IMAP internal records)
    staged_p2021_records, p2021_stats = convert_mbox_to_eml(
        mbox_path=phish_2021_mbox,
        output_dir=staging_p2021_dir,
        source_dataset="nazario",
        source_category="phishing",
        assigned_label="phishing",
        source_archive=phish_2021_mbox.name,
        source_year="2021",
        prefix="stage_phish_2021",
        id_prefix="STAGE_PHISH_2021",
        filter_uw_internal=True,
        overwrite=overwrite,
    )

    # Collect excluded records from MBOX conversion
    all_excluded = []
    if "excluded_records" in p2015_stats:
        all_excluded.extend(p2015_stats["excluded_records"])
    if "excluded_records" in p2021_stats:
        all_excluded.extend(p2021_stats["excluded_records"])

    # Collect usable candidates (status SUCCESS or WARNING and accessible on disk)
    def _collect_accessible_candidates(records: List[ConversionRecord], staged_dir: Path) -> List[ConversionRecord]:
        accessible = []
        for r in records:
            if r.conversion_status in ("SUCCESS", "WARNING"):
                fpath = staged_dir / r.export_filename
                try:
                    with open(fpath, "rb") as f_chk:
                        f_chk.read(32)
                    accessible.append(r)
                except Exception as exc:
                    r.conversion_status = "ERROR"
                    r.warnings.append(f"Staged candidate inaccessible on disk: {exc}")
        return accessible

    usable_easy = _collect_accessible_candidates(staged_easy_records, staging_easy_dir)
    usable_hard = _collect_accessible_candidates(staged_hard_records, staging_hard_dir)
    usable_p2015 = _collect_accessible_candidates(staged_p2015_records, staging_p2015_dir)
    usable_p2021 = _collect_accessible_candidates(staged_p2021_records, staging_p2021_dir)

    total_candidates = len(usable_easy) + len(usable_hard) + len(usable_p2015) + len(usable_p2021)
    total_phish_usable = len(usable_p2015) + len(usable_p2021)

    # Write staging conversion manifest (including excluded records)
    with open(conversion_manifest_jsonl, "w", encoding="utf-8") as f_conv:
        for r in staged_easy_records + staged_hard_records + staged_p2015_records + staged_p2021_records:
            f_conv.write(json.dumps(r.to_dict()) + "\n")
        for exc in all_excluded:
            f_conv.write(json.dumps(exc) + "\n")

    # Step 3: Check for shortfalls
    shortfalls: Dict[str, Dict[str, int]] = {}
    if len(usable_easy) < TARGET_EASY_HAM_COUNT:
        shortfalls["easy_ham"] = {
            "requested": TARGET_EASY_HAM_COUNT,
            "actual": len(usable_easy),
            "shortfall": TARGET_EASY_HAM_COUNT - len(usable_easy),
        }
    if len(usable_hard) < TARGET_HARD_HAM_COUNT:
        shortfalls["hard_ham"] = {
            "requested": TARGET_HARD_HAM_COUNT,
            "actual": len(usable_hard),
            "shortfall": TARGET_HARD_HAM_COUNT - len(usable_hard),
        }
    if total_phish_usable < TARGET_NAZARIO_PHISHING_COUNT:
        shortfalls["phishing"] = {
            "requested": TARGET_NAZARIO_PHISHING_COUNT,
            "actual": total_phish_usable,
            "shortfall": TARGET_NAZARIO_PHISHING_COUNT - total_phish_usable,
        }

    if shortfalls:
        msg_parts = [f"{k}: obtained {v['actual']}, required {v['requested']}" for k, v in shortfalls.items()]
        return {
            "status": "SHORTFALL",
            "message": f"Shortfall in candidate datasets: {'; '.join(msg_parts)}",
            "shortfalls": shortfalls,
            "candidate_counts": {
                "easy_ham": len(usable_easy),
                "hard_ham": len(usable_hard),
                "phishing_2015": len(usable_p2015),
                "phishing_2021": len(usable_p2021),
            },
        }

    # Step 4: Deterministic proportional sampling
    # Easy ham: 500
    rng_easy = random.Random(seed)
    sorted_easy = sorted(usable_easy, key=lambda r: r.source_message_identifier or r.sample_id)
    sampled_easy = sorted(rng_easy.sample(sorted_easy, TARGET_EASY_HAM_COUNT), key=lambda r: r.source_message_identifier or r.sample_id)

    # Hard ham: 250
    rng_hard = random.Random(seed)
    sorted_hard = sorted(usable_hard, key=lambda r: r.source_message_identifier or r.sample_id)
    sampled_hard = sorted(rng_hard.sample(sorted_hard, TARGET_HARD_HAM_COUNT), key=lambda r: r.source_message_identifier or r.sample_id)

    # Phishing: proportional allocation from verified usable candidate counts
    target_2015 = round(TARGET_NAZARIO_PHISHING_COUNT * len(usable_p2015) / total_phish_usable)
    target_2021 = TARGET_NAZARIO_PHISHING_COUNT - target_2015

    rng_phish = random.Random(seed)
    sorted_p2015 = sorted(usable_p2015, key=lambda r: (r.original_mbox_key if r.original_mbox_key is not None else 0))
    sorted_p2021 = sorted(usable_p2021, key=lambda r: (r.original_mbox_key if r.original_mbox_key is not None else 0))

    sampled_p2015 = sorted(rng_phish.sample(sorted_p2015, target_2015), key=lambda r: (r.original_mbox_key if r.original_mbox_key is not None else 0))
    sampled_p2021 = sorted(rng_phish.sample(sorted_p2021, target_2021), key=lambda r: (r.original_mbox_key if r.original_mbox_key is not None else 0))
    sampled_phish = sampled_p2015 + sampled_p2021

    # Step 5: Duplicate verification across all 1,000 samples
    all_sampled = sampled_easy + sampled_hard + sampled_phish
    seen_hashes = set()
    dup_hashes = []
    for r in all_sampled:
        if r.sha256 in seen_hashes:
            dup_hashes.append(r.sha256)
        seen_hashes.add(r.sha256)

    if dup_hashes or len(seen_hashes) != TOTAL_TARGET_COUNT:
        return {
            "status": "SHORTFALL",
            "message": f"Deduplication caused a shortfall: {len(dup_hashes)} duplicate hashes found in final dataset.",
            "duplicate_hashes": dup_hashes,
            "unique_count": len(seen_hashes),
        }

    # Step 6: Export sampled EMLs into final development dataset directory
    ham_easy_out = dev_dir / "eml" / "ham_easy"
    ham_hard_out = dev_dir / "eml" / "ham_hard"
    phish_out = dev_dir / "eml" / "phishing"

    ham_easy_out.mkdir(parents=True, exist_ok=True)
    ham_hard_out.mkdir(parents=True, exist_ok=True)
    phish_out.mkdir(parents=True, exist_ok=True)

    final_records: List[ConversionRecord] = []

    # Export easy ham (1..500)
    for idx, staged_rec in enumerate(sampled_easy, 1):
        sample_id = f"DEV_HAM_{idx:06d}"
        fname = generate_deterministic_filename("easy_ham", idx, staged_rec.sha256)
        dest_file = ham_easy_out / fname
        rel_path = f"eml/ham_easy/{fname}"
        staged_file = staging_easy_dir / staged_rec.export_filename

        raw_bytes = staged_file.read_bytes()
        write_eml_file(dest_file, raw_bytes, overwrite=overwrite)

        rec = ConversionRecord(
            sample_id=sample_id,
            source_dataset="spamassassin",
            source_category="easy_ham",
            assigned_label="ham_easy",
            source_file=staged_rec.source_file,
            message_id=staged_rec.message_id,
            sha256=staged_rec.sha256,
            byte_size=staged_rec.byte_size,
            conversion_status=staged_rec.conversion_status,
            warnings=staged_rec.warnings,
            export_filename=fname,
            source_archive=staged_rec.source_archive,
            source_year="",
            source_message_identifier=staged_rec.source_message_identifier,
            relative_eml_path=rel_path,
            auth_headers_present=staged_rec.auth_headers_present,
        )
        final_records.append(rec)

    # Export hard ham (501..750)
    for idx, staged_rec in enumerate(sampled_hard, 501):
        sample_id = f"DEV_HAM_{idx:06d}"
        fname = generate_deterministic_filename("hard_ham", idx, staged_rec.sha256)
        dest_file = ham_hard_out / fname
        rel_path = f"eml/ham_hard/{fname}"
        staged_file = staging_hard_dir / staged_rec.export_filename

        raw_bytes = staged_file.read_bytes()
        write_eml_file(dest_file, raw_bytes, overwrite=overwrite)

        rec = ConversionRecord(
            sample_id=sample_id,
            source_dataset="spamassassin",
            source_category="hard_ham",
            assigned_label="ham_hard",
            source_file=staged_rec.source_file,
            message_id=staged_rec.message_id,
            sha256=staged_rec.sha256,
            byte_size=staged_rec.byte_size,
            conversion_status=staged_rec.conversion_status,
            warnings=staged_rec.warnings,
            export_filename=fname,
            source_archive=staged_rec.source_archive,
            source_year="",
            source_message_identifier=staged_rec.source_message_identifier,
            relative_eml_path=rel_path,
            auth_headers_present=staged_rec.auth_headers_present,
        )
        final_records.append(rec)

    # Export phishing (1..250)
    for idx, staged_rec in enumerate(sampled_phish, 1):
        sample_id = f"DEV_PHISH_{idx:06d}"
        yr = staged_rec.source_year or "phish"
        fname = generate_deterministic_filename(f"nazario_{yr}", idx, staged_rec.sha256)
        dest_file = phish_out / fname
        rel_path = f"eml/phishing/{fname}"

        staged_parent = staging_p2015_dir if staged_rec.source_year == "2015" else staging_p2021_dir
        staged_file = staged_parent / staged_rec.export_filename

        raw_bytes = staged_file.read_bytes()
        write_eml_file(dest_file, raw_bytes, overwrite=overwrite)

        rec = ConversionRecord(
            sample_id=sample_id,
            source_dataset="nazario",
            source_category="phishing",
            assigned_label="phishing",
            source_file=staged_rec.source_file,
            message_id=staged_rec.message_id,
            sha256=staged_rec.sha256,
            byte_size=staged_rec.byte_size,
            conversion_status=staged_rec.conversion_status,
            warnings=staged_rec.warnings,
            export_filename=fname,
            source_archive=staged_rec.source_archive,
            source_year=staged_rec.source_year,
            original_mbox_key=staged_rec.original_mbox_key,
            source_message_identifier=staged_rec.source_message_identifier,
            relative_eml_path=rel_path,
            auth_headers_present=staged_rec.auth_headers_present,
        )
        final_records.append(rec)

    # Step 7: Write manifests and summary
    write_manifest_csv(final_records, manifest_csv)
    write_manifest_jsonl(final_records, manifest_jsonl)

    summary_extra = {
        "final_category_counts": {
            "easy_ham": TARGET_EASY_HAM_COUNT,
            "hard_ham": TARGET_HARD_HAM_COUNT,
            "phishing": TARGET_NAZARIO_PHISHING_COUNT,
        },
        "final_label_counts": {
            "ham_easy": TARGET_EASY_HAM_COUNT,
            "ham_hard": TARGET_HARD_HAM_COUNT,
            "phishing": TARGET_NAZARIO_PHISHING_COUNT,
        },
        "source_year_phishing_counts": {
            "2015": target_2015,
            "2021": target_2021,
        },
        "total_converted_candidates": total_candidates,
        "candidate_counts": {
            "easy_ham": len(usable_easy),
            "hard_ham": len(usable_hard),
            "phishing_2015": len(usable_p2015),
            "phishing_2021": len(usable_p2021),
        },
        "total_excluded_records": len(all_excluded),
        "excluded_records": all_excluded,
        "duplicate_counts": 0,
        "failed_conversions": 0,
        "shortfall_status": "NONE",
        "sampling_seed": seed,
    }
    write_dataset_summary(final_records, summary_json, extra_metadata=summary_extra)

    return {
        "status": "SUCCESS",
        "total_selected": len(final_records),
        "easy_ham_count": TARGET_EASY_HAM_COUNT,
        "hard_ham_count": TARGET_HARD_HAM_COUNT,
        "phishing_count": TARGET_NAZARIO_PHISHING_COUNT,
        "phishing_2015_count": target_2015,
        "phishing_2021_count": target_2021,
        "total_candidates": total_candidates,
        "total_excluded": len(all_excluded),
        "manifest_csv": str(manifest_csv),
        "manifest_jsonl": str(manifest_jsonl),
        "conversion_manifest": str(conversion_manifest_jsonl),
        "summary_json": str(summary_json),
    }


def _build_legacy_task8_1_dev_dataset(
    raw_base_dir: str | Path,
    dev_base_dir: str | Path,
    seed: int = DEFAULT_RANDOM_SEED,
    overwrite: bool = False,
) -> Dict[str, Any]:
    """Legacy Task 8.1 builder preserved for backwards compatibility with earlier test suites."""
    raw_dir = Path(raw_base_dir)
    dev_dir = Path(dev_base_dir)

    ham_out = dev_dir / "eml" / "ham"
    phish_out = dev_dir / "eml" / "phishing"
    manifests_out = dev_dir / "manifests"
    manifest_csv = manifests_out / "dev_manifest.csv"
    summary_json = manifests_out / "dev_dataset_summary.json"

    inspection = inspect_raw_datasets(raw_dir)
    if not inspection["all_present"]:
        return {
            "status": "MISSING_DATASETS",
            "inspection": inspection,
            "message": (
                "Cannot build development dataset because required raw files are missing. "
                "See inspection report for expected file paths."
            ),
        }

    all_records: List[ConversionRecord] = []
    seen_hashes: Set[str] = set()
    seen_message_ids: Set[str] = set()

    easy_ham_path = inspection["sources"]["spamassassin_easy_ham"]["path"]
    easy_ham_records, easy_ham_stats = import_flat_rfc822_dir(
        input_dir=easy_ham_path,
        output_dir=ham_out,
        source_dataset="spamassassin",
        source_category="easy_ham",
        assigned_label="ham",
        prefix="easy_ham",
        id_prefix="DEV_HAM",
        start_index=1,
        limit=TARGET_EASY_HAM_COUNT,
        seed=seed,
        seen_hashes=seen_hashes,
        seen_message_ids=seen_message_ids,
        overwrite=overwrite,
    )
    all_records.extend(easy_ham_records)

    hard_ham_path = inspection["sources"]["spamassassin_hard_ham"]["path"]
    hard_ham_records, hard_ham_stats = import_flat_rfc822_dir(
        input_dir=hard_ham_path,
        output_dir=ham_out,
        source_dataset="spamassassin",
        source_category="hard_ham",
        assigned_label="ham",
        prefix="hard_ham",
        id_prefix="DEV_HAM",
        start_index=len(all_records) + 1,
        limit=TARGET_HARD_HAM_COUNT,
        seed=seed,
        seen_hashes=seen_hashes,
        seen_message_ids=seen_message_ids,
        overwrite=overwrite,
    )
    all_records.extend(hard_ham_records)

    nazario_path = inspection["sources"]["nazario_phishing0"]["path"]
    nazario_records, nazario_stats = convert_mbox_to_eml(
        mbox_path=nazario_path,
        output_dir=phish_out,
        source_dataset="nazario_legacy",
        source_category="phishing",
        assigned_label="phishing",
        prefix="nazario",
        id_prefix="DEV_PHISH",
        start_index=1,
        limit=TARGET_NAZARIO_PHISHING_COUNT,
        seed=seed,
        seen_hashes=seen_hashes,
        seen_message_ids=seen_message_ids,
        overwrite=overwrite,
    )
    all_records.extend(nazario_records)

    easy_ham_actual = easy_ham_stats["converted_count"]
    hard_ham_actual = hard_ham_stats["converted_count"]
    nazario_actual = nazario_stats["converted_count"]
    total_actual = len(all_records)

    shortfalls: Dict[str, Dict[str, int]] = {}
    if easy_ham_actual < TARGET_EASY_HAM_COUNT:
        shortfalls["easy_ham"] = {
            "requested": TARGET_EASY_HAM_COUNT,
            "actual": easy_ham_actual,
            "shortfall": TARGET_EASY_HAM_COUNT - easy_ham_actual,
        }
    if hard_ham_actual < TARGET_HARD_HAM_COUNT:
        shortfalls["hard_ham"] = {
            "requested": TARGET_HARD_HAM_COUNT,
            "actual": hard_ham_actual,
            "shortfall": TARGET_HARD_HAM_COUNT - hard_ham_actual,
        }
    if nazario_actual < TARGET_NAZARIO_PHISHING_COUNT:
        shortfalls["nazario_phishing"] = {
            "requested": TARGET_NAZARIO_PHISHING_COUNT,
            "actual": nazario_actual,
            "shortfall": TARGET_NAZARIO_PHISHING_COUNT - nazario_actual,
        }

    counts_summary = {
        "easy_ham": {
            "requested": TARGET_EASY_HAM_COUNT,
            "actual": easy_ham_actual,
            "shortfall": max(0, TARGET_EASY_HAM_COUNT - easy_ham_actual),
        },
        "hard_ham": {
            "requested": TARGET_HARD_HAM_COUNT,
            "actual": hard_ham_actual,
            "shortfall": max(0, TARGET_HARD_HAM_COUNT - hard_ham_actual),
        },
        "nazario_phishing": {
            "requested": TARGET_NAZARIO_PHISHING_COUNT,
            "actual": nazario_actual,
            "shortfall": max(0, TARGET_NAZARIO_PHISHING_COUNT - nazario_actual),
        },
        "total": {
            "requested": TOTAL_TARGET_COUNT,
            "actual": total_actual,
            "shortfall": max(0, TOTAL_TARGET_COUNT - total_actual),
        },
    }

    if shortfalls or total_actual < TOTAL_TARGET_COUNT:
        msg_parts = []
        if "nazario_phishing" in shortfalls:
            msg_parts.append(
                f"Shortfall in Nazario phishing samples: obtained {nazario_actual}, required {TARGET_NAZARIO_PHISHING_COUNT}"
            )
        if "easy_ham" in shortfalls:
            msg_parts.append(
                f"Shortfall in easy_ham: obtained {easy_ham_actual}, required {TARGET_EASY_HAM_COUNT}"
            )
        if "hard_ham" in shortfalls:
            msg_parts.append(
                f"Shortfall in hard_ham: obtained {hard_ham_actual}, required {TARGET_HARD_HAM_COUNT}"
            )
        if total_actual < TOTAL_TARGET_COUNT and not msg_parts:
            msg_parts.append(f"total: obtained {total_actual}, required {TOTAL_TARGET_COUNT}")

        return {
            "status": "SHORTFALL",
            "message": f"Shortfall in dataset samples: {'; '.join(msg_parts)}",
            "shortfalls": shortfalls,
            "counts": counts_summary,
            "easy_ham_stats": easy_ham_stats,
            "hard_ham_stats": hard_ham_stats,
            "nazario_stats": nazario_stats,
        }

    write_manifest_csv(all_records, manifest_csv)
    write_dataset_summary(
        all_records,
        summary_json,
        extra_metadata={
            "random_seed": seed,
            "target_counts": counts_summary,
            "easy_ham_stats": easy_ham_stats,
            "hard_ham_stats": hard_ham_stats,
            "nazario_stats": nazario_stats,
        },
    )

    return {
        "status": "SUCCESS",
        "total_converted": len(all_records),
        "easy_ham_count": easy_ham_stats["converted_count"],
        "hard_ham_count": hard_ham_stats["converted_count"],
        "nazario_phishing_count": nazario_stats["converted_count"],
        "counts": counts_summary,
        "manifest_csv": str(manifest_csv),
        "summary_json": str(summary_json),
    }


def build_dev_dataset(
    raw_base_dir: str | Path,
    dev_base_dir: str | Path,
    seed: int = DEFAULT_RANDOM_SEED,
    overwrite: bool = False,
    task_version: str = "8.3",
) -> Dict[str, Any]:
    """
    Main entry point for building the development dataset.
    Defaults to Task 8.3 specification, falling back to legacy Task 8.1 if only legacy sources exist.
    """
    raw_dir = Path(raw_base_dir)
    has_2015 = (raw_dir / "phishing-2015.mbox").is_file() or (raw_dir / "phishing-2015").is_file()
    has_2021 = (raw_dir / "phishing-2021.mbox").is_file() or (raw_dir / "phishing-2021").is_file()

    if task_version == "8.3" and (has_2015 or has_2021):
        return build_task8_3_dev_dataset(raw_dir, dev_base_dir, seed=seed, overwrite=overwrite)
    elif (raw_dir / "phishing0.mbox").is_file():
        return _build_legacy_task8_1_dev_dataset(raw_dir, dev_base_dir, seed=seed, overwrite=overwrite)
    else:
        # Fall back to standard inspection for error reporting
        if task_version == "8.3":
            return build_task8_3_dev_dataset(raw_dir, dev_base_dir, seed=seed, overwrite=overwrite)
        return _build_legacy_task8_1_dev_dataset(raw_dir, dev_base_dir, seed=seed, overwrite=overwrite)


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare development dataset for Task 8.3.")
    parser.add_argument(
        "--raw-dir",
        type=str,
        default="data/raw",
        help="Path to raw dataset directory (default: data/raw).",
    )
    parser.add_argument(
        "--dev-dir",
        type=str,
        default="data/dev",
        help="Path to development dataset directory (default: data/dev).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_RANDOM_SEED,
        help=f"Deterministic random seed (default: {DEFAULT_RANDOM_SEED}).",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        default=False,
        help="Overwrite existing output files if they exist (default: False).",
    )
    args = parser.parse_args()

    result = build_dev_dataset(args.raw_dir, args.dev_dir, seed=args.seed, overwrite=args.overwrite)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "SUCCESS" else 1


if __name__ == "__main__":
    sys.exit(main())
