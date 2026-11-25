"""
Raw Email Dataset Verification and Acquisition Module for Task 8.2.

Provides functionality to:
1. Download approved source email archives atomically using Python standard library.
2. Calculate and verify SHA-256 digests and file sizes.
3. Validate archive structure (tar.bz2 members, mbox message boundaries) safely.
4. Generate and validate data/raw/acquisition_manifest.json with full provenance.
5. Provide read-only verification (--check-only) that never modifies existing archives.

Design guarantees:
- Pure Python standard library (no third-party dependencies).
- Atomic downloads via temporary files to avoid partial or corrupted downloads.
- Exclusive file safety: never silently overwrite existing valid archives.
- Passive inspection only: never execute attachments, parse active content, or contact URLs in email bodies.
- Honest provenance: explicitly records upstream_checksum_available=False for sources that lack upstream hashes.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import mailbox
import os
from pathlib import Path
import sys
import tarfile
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.request
import uuid

# ── Catalog of Approved Raw Datasets ──────────────────────────────────────────

APPROVED_DATASETS: Dict[str, Dict[str, Any]] = {
    "spamassassin_easy_ham": {
        "dataset_id": "spamassassin_easy_ham",
        "dataset_name": "SpamAssassin 20030228 Easy Ham Corpus",
        "source_category": "easy_ham",
        "target_count": 500,
        "original_source_url": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
        "original_archive_filename": "20030228_easy_ham.tar.bz2",
        "local_filename": "20030228_easy_ham.tar.bz2",
        "archive_format": "tar.bz2",
        "expected_size_bytes": 1612216,
        "expected_sha256": "2b7b65904bcfcc31d2b5f51946f2d261370b257402cbbd62930b46ab83367438",
        "upstream_checksum_available": False,
        "upstream_checksum_verification": "NONE_AVAILABLE",
        "is_required_for_dev": True,
        "provenance_notes": (
            "Official Apache SpamAssassin historical corpus distribution. "
            "Archive contains 2,501 easy_ham message files. "
            "No upstream checksum file is published on apache.org/old/publiccorpus/. "
            "Ham emails must not be treated as confirmed legitimate or phishing-free."
        ),
    },
    "spamassassin_hard_ham": {
        "dataset_id": "spamassassin_hard_ham",
        "dataset_name": "SpamAssassin 20030228 Hard Ham Corpus",
        "source_category": "hard_ham",
        "target_count": 250,
        "original_source_url": "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
        "original_archive_filename": "20030228_hard_ham.tar.bz2",
        "local_filename": "20030228_hard_ham.tar.bz2",
        "archive_format": "tar.bz2",
        "expected_size_bytes": 1029898,
        "expected_sha256": "ce2ce67880643dbde65ea7f85bffbfe4417349c4bd80b6b0de56262ae6b0a9c9",
        "upstream_checksum_available": False,
        "upstream_checksum_verification": "NONE_AVAILABLE",
        "is_required_for_dev": True,
        "provenance_notes": (
            "Official Apache SpamAssassin historical corpus distribution. "
            "Archive contains 251 hard_ham message files. "
            "No upstream checksum file is published on apache.org/old/publiccorpus/. "
            "Ham emails must not be treated as confirmed legitimate or phishing-free."
        ),
    },
    "nazario_phishing0": {
        "dataset_id": "nazario_phishing0",
        "dataset_name": "Jose Nazario Phishing Corpus (phishing0.mbox)",
        "source_category": "phishing",
        "target_count": 250,
        "original_source_url": "https://monkey.org/~jose/phishing/phishing0.mbox",
        "original_archive_filename": "phishing0.mbox",
        "local_filename": "phishing0.mbox",
        "archive_format": "mbox",
        "expected_size_bytes": 3119972,
        "expected_sha256": "6184b0a34ed8cbbb252676e21c1eab9eac5fa4be89c61e30cc9954ebbb25d848",
        "upstream_checksum_available": False,
        "upstream_checksum_verification": "NONE_AVAILABLE",
        "is_required_for_dev": True,
        "provenance_notes": (
            "Original Jose Nazario phishing corpus from monkey.org/~jose/phishing/. "
            "Distributed under CC-BY-4.0 license. Contains 414 raw MBOX phishing messages. "
            "No upstream checksum file is published on monkey.org."
        ),
    },
    "nazario_phishing_2015": {
        "dataset_id": "nazario_phishing_2015",
        "dataset_name": "Jose Nazario Phishing Corpus 2015 Archive",
        "source_category": "phishing",
        "target_count": 250,
        "original_source_url": "https://monkey.org/~jose/phishing/phishing-2015",
        "original_archive_filename": "phishing-2015",
        "local_filename": "phishing-2015.mbox",
        "archive_format": "mbox",
        "expected_size_bytes": 8815568,
        "expected_sha256": "7523e62a5e6e4ee8134ab8b1a628e423097a7779e1003b28422864aa34f1c319",
        "upstream_checksum_available": False,
        "upstream_checksum_verification": "NONE_AVAILABLE",
        "is_required_for_dev": False,
        "provenance_notes": (
            "Jose Nazario yearly collection (2015) from monkey.org/~jose/phishing/. "
            "Distributed under CC-BY-4.0 license. Standard Unix MBOX format. "
            "No upstream checksum file is published on monkey.org."
        ),
    },
    "nazario_phishing_2021": {
        "dataset_id": "nazario_phishing_2021",
        "dataset_name": "Jose Nazario Phishing Corpus 2021 Archive",
        "source_category": "phishing",
        "target_count": 250,
        "original_source_url": "https://monkey.org/~jose/phishing/phishing-2021",
        "original_archive_filename": "phishing-2021",
        "local_filename": "phishing-2021.mbox",
        "archive_format": "mbox",
        "expected_size_bytes": 2719946,
        "expected_sha256": "636707cff42245d1482e4ae8a2c03369717a5e06bf9d1a0f4ec5dcd846661cee",
        "upstream_checksum_available": False,
        "upstream_checksum_verification": "NONE_AVAILABLE",
        "is_required_for_dev": False,
        "provenance_notes": (
            "Jose Nazario yearly collection (2021) from monkey.org/~jose/phishing/. "
            "Distributed under CC-BY-4.0 license. Standard Unix MBOX format. "
            "No upstream checksum file is published on monkey.org."
        ),
    },
}

REQUIRED_DEV_DATASET_IDS = ["spamassassin_easy_ham", "spamassassin_hard_ham", "nazario_phishing0"]


# ── Hash and Verification Utilities ───────────────────────────────────────────

def calculate_sha256(file_path: Path | str, chunk_size: int = 65536) -> str:
    """
    Calculate the SHA-256 hex digest of a file in streaming chunks.
    Raises FileNotFoundError if file does not exist.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_archive_structure(file_path: Path, archive_format: str) -> Dict[str, Any]:
    """
    Safely inspect the internal structure of an archive without writing to disk
    or executing/rendering any email contents.
    """
    result: Dict[str, Any] = {
        "valid": False,
        "entry_count": 0,
        "details": "",
        "warnings": [],
    }

    if not file_path.is_file():
        result["details"] = f"Archive file does not exist: {file_path}"
        return result

    try:
        if archive_format in ("tar.bz2", "tar.gz", "tar"):
            mode = "r:bz2" if archive_format == "tar.bz2" else ("r:gz" if archive_format == "tar.gz" else "r:")
            with tarfile.open(file_path, mode=mode) as tar:
                members = tar.getmembers()
                files = [m for m in members if m.isfile()]
                result["valid"] = len(files) > 0
                result["entry_count"] = len(files)
                result["total_members"] = len(members)
                result["details"] = f"Valid tar archive containing {len(files)} files ({len(members)} total entries)"
        elif archive_format == "mbox":
            # Count messages by parsing From separators
            count = 0
            with open(file_path, "rb") as f:
                for line in f:
                    if line.startswith(b"From "):
                        count += 1
            result["valid"] = count > 0
            result["entry_count"] = count
            result["details"] = f"Valid MBOX file containing {count} messages"
        else:
            result["valid"] = True
            result["details"] = f"Generic file (format {archive_format})"
    except Exception as exc:
        result["valid"] = False
        result["details"] = f"Integrity check failed: {type(exc).__name__}: {exc}"
        result["warnings"].append(str(exc))

    return result


def download_file_atomically(
    url: str,
    dest_path: Path,
    expected_sha256: Optional[str] = None,
    timeout: int = 60,
    chunk_size: int = 65536,
) -> Tuple[str, int]:
    """
    Atomically download a file to dest_path using a temporary file.
    Calculates SHA-256 on the fly during streaming.
    Cleans up temporary file if download fails or is interrupted.
    Returns (sha256_hex, total_bytes).
    """
    dest_path = Path(dest_path)
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    part_filename = f".{dest_path.name}.part.{uuid.uuid4().hex}"
    part_path = dest_path.parent / part_filename

    hasher = hashlib.sha256()
    total_bytes = 0

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "MultiAgent-AI-Detector-Acquisition/1.0 (+https://github.com/)"},
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise urllib.error.HTTPError(
                    url, resp.status, f"Unexpected HTTP status: {resp.status}", resp.headers, None
                )

            with open(part_path, "wb") as f_out:
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    f_out.write(chunk)
                    total_bytes += len(chunk)
                f_out.flush()
                os.fsync(f_out.fileno())

        computed_hash = hasher.hexdigest()
        if expected_sha256 and computed_hash.lower() != expected_sha256.lower():
            raise ValueError(
                f"Downloaded file SHA-256 mismatch for {url}: expected {expected_sha256}, got {computed_hash}"
            )

        # Atomic rename replacing destination
        os.replace(part_path, dest_path)
        return computed_hash, total_bytes

    except Exception:
        if part_path.exists():
            try:
                part_path.unlink()
            except OSError:
                pass
        raise


# ── Dataset Verification & Manifest Generation ────────────────────────────────

def verify_single_dataset(
    catalog_entry: Dict[str, Any],
    raw_base_dir: Path,
    verify_structure: bool = True,
) -> Dict[str, Any]:
    """
    Verify a single dataset archive located in raw_base_dir.
    Returns a status record conforming to the acquisition manifest schema.
    """
    raw_base_dir = Path(raw_base_dir)
    filename = catalog_entry["local_filename"]
    local_path = raw_base_dir / filename

    record: Dict[str, Any] = {
        "dataset_name": catalog_entry["dataset_name"],
        "dataset_id": catalog_entry["dataset_id"],
        "source_category": catalog_entry["source_category"],
        "target_dev_count": catalog_entry.get("target_count", 0),
        "is_required_for_dev": catalog_entry.get("is_required_for_dev", False),
        "original_source_url": catalog_entry["original_source_url"],
        "original_archive_filename": catalog_entry["original_archive_filename"],
        "local_path": str(local_path.as_posix()),
        "local_filename": filename,
        "archive_format": catalog_entry["archive_format"],
        "download_timestamp": None,
        "size_bytes": 0,
        "sha256": None,
        "expected_sha256": catalog_entry.get("expected_sha256"),
        "upstream_checksum_available": catalog_entry.get("upstream_checksum_available", False),
        "upstream_checksum_verification": catalog_entry.get("upstream_checksum_verification", "NONE_AVAILABLE"),
        "acquisition_status": "MISSING",
        "archive_structure_valid": False,
        "archive_entry_count": 0,
        "warnings": [],
        "provenance_notes": catalog_entry.get("provenance_notes", ""),
    }

    if not local_path.is_file():
        record["acquisition_status"] = "MISSING"
        record["warnings"].append(f"Local archive not found: {local_path}")
        return record

    try:
        stat_res = local_path.stat()
        record["size_bytes"] = stat_res.st_size
        mtime_utc = datetime.fromtimestamp(stat_res.st_mtime, timezone.utc)
        record["download_timestamp"] = mtime_utc.isoformat()

        # Compute SHA-256
        actual_hash = calculate_sha256(local_path)
        record["sha256"] = actual_hash

        expected_hash = catalog_entry.get("expected_sha256")
        expected_size = catalog_entry.get("expected_size_bytes")

        # Verify hash match
        if expected_hash and actual_hash.lower() != expected_hash.lower():
            record["acquisition_status"] = "HASH_MISMATCH"
            record["warnings"].append(
                f"SHA-256 digest mismatch: expected {expected_hash}, calculated {actual_hash}"
            )
            return record

        # Verify size match
        if expected_size and record["size_bytes"] != expected_size:
            record["warnings"].append(
                f"File size mismatch: expected {expected_size} bytes, got {record['size_bytes']} bytes"
            )

        # Inspect internal archive structure
        if verify_structure:
            struct_res = verify_archive_structure(local_path, catalog_entry["archive_format"])
            record["archive_structure_valid"] = struct_res["valid"]
            record["archive_entry_count"] = struct_res["entry_count"]
            if not struct_res["valid"]:
                record["acquisition_status"] = "CORRUPT_ARCHIVE"
                record["warnings"].extend(struct_res["warnings"])
                record["warnings"].append(f"Archive structure check failed: {struct_res['details']}")
                return record

        record["acquisition_status"] = "VERIFIED_LOCAL_HASH"

    except Exception as exc:
        record["acquisition_status"] = "ERROR"
        record["warnings"].append(f"Verification error: {type(exc).__name__}: {exc}")

    return record


def verify_all_raw_datasets(
    raw_base_dir: Path | str,
    catalog: Optional[Dict[str, Dict[str, Any]]] = None,
    verify_structure: bool = True,
) -> Dict[str, Any]:
    """
    Verify all datasets in the catalog against raw_base_dir.
    Returns a comprehensive manifest dictionary.
    """
    raw_dir = Path(raw_base_dir)
    cat = catalog or APPROVED_DATASETS

    records: List[Dict[str, Any]] = []
    missing_required: List[str] = []
    shortfalls: List[str] = []

    for ds_id, entry in cat.items():
        rec = verify_single_dataset(entry, raw_dir, verify_structure=verify_structure)
        records.append(rec)

        if entry.get("is_required_for_dev", False):
            if rec["acquisition_status"] != "VERIFIED_LOCAL_HASH":
                missing_required.append(f"{ds_id} ({rec['acquisition_status']})")
            elif rec.get("archive_entry_count", 0) < entry.get("target_count", 0):
                shortfalls.append(
                    f"{ds_id}: available {rec.get('archive_entry_count')} < target {entry.get('target_count')}"
                )

    all_required_present = len(missing_required) == 0 and len(shortfalls) == 0

    manifest: Dict[str, Any] = {
        "manifest_version": "1.0.0",
        "generated_timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_base_directory": str(raw_dir.as_posix()),
        "total_datasets_checked": len(records),
        "required_datasets_verified": all_required_present,
        "missing_required_datasets": missing_required,
        "sample_shortfalls": shortfalls,
        "datasets": records,
    }

    return manifest


def acquire_raw_datasets(
    raw_base_dir: Path | str,
    catalog: Optional[Dict[str, Dict[str, Any]]] = None,
    overwrite: bool = False,
    timeout: int = 60,
) -> Tuple[Dict[str, Any], bool]:
    """
    Acquire (download) any missing datasets in the catalog into raw_base_dir.
    Does not overwrite existing files unless overwrite=True.
    Returns (manifest_dict, all_success_boolean).
    """
    raw_dir = Path(raw_base_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)
    cat = catalog or APPROVED_DATASETS

    for ds_id, entry in cat.items():
        filename = entry["local_filename"]
        target_path = raw_dir / filename

        if target_path.exists() and not overwrite:
            # Check existing file hash
            try:
                curr_hash = calculate_sha256(target_path)
                if curr_hash.lower() == entry.get("expected_sha256", "").lower():
                    continue
            except Exception:
                pass

        print(f"Downloading {entry['dataset_name']} from {entry['original_source_url']}...")
        download_file_atomically(
            url=entry["original_source_url"],
            dest_path=target_path,
            expected_sha256=entry.get("expected_sha256"),
            timeout=timeout,
        )

    manifest = verify_all_raw_datasets(raw_dir, catalog=cat, verify_structure=True)
    return manifest, manifest["required_datasets_verified"]


def write_acquisition_manifest(
    manifest_data: Dict[str, Any],
    manifest_path: Path | str,
) -> None:
    """Write manifest to JSON file formatted with indentation."""
    out_path = Path(manifest_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)


def load_acquisition_manifest(manifest_path: Path | str) -> Dict[str, Any]:
    """Load and return manifest dictionary from JSON file."""
    path = Path(manifest_path)
    if not path.is_file():
        raise FileNotFoundError(f"Manifest file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_manifest_structure(manifest: Dict[str, Any]) -> List[str]:
    """
    Validate that a manifest adheres to the required schema.
    Returns a list of validation errors (empty if completely valid).
    """
    errors: List[str] = []
    required_top = [
        "manifest_version",
        "generated_timestamp",
        "raw_base_directory",
        "total_datasets_checked",
        "required_datasets_verified",
        "datasets",
    ]
    for key in required_top:
        if key not in manifest:
            errors.append(f"Missing top-level manifest key: '{key}'")

    if "datasets" in manifest and isinstance(manifest["datasets"], list):
        required_record_keys = [
            "dataset_name",
            "source_category",
            "original_source_url",
            "original_archive_filename",
            "local_path",
            "download_timestamp",
            "size_bytes",
            "sha256",
            "upstream_checksum_available",
            "upstream_checksum_verification",
            "acquisition_status",
            "provenance_notes",
        ]
        for idx, rec in enumerate(manifest["datasets"]):
            for rk in required_record_keys:
                if rk not in rec:
                    errors.append(f"Dataset entry #{idx} ({rec.get('dataset_id', 'unknown')}) missing required key '{rk}'")
    else:
        errors.append("'datasets' field must be a list")

    return errors


# ── Command-Line Interface ────────────────────────────────────────────────────

def parse_cli_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify and acquire raw email datasets for Task 8.2."
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default="data/raw",
        help="Directory containing or targeting raw email archives (default: data/raw)",
    )
    parser.add_argument(
        "--manifest",
        type=str,
        default=None,
        help="Path to write or read acquisition manifest JSON (default: <data-dir>/acquisition_manifest.json)",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Perform read-only verification of existing archives without downloading.",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download any missing datasets into data-dir.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Force re-download even if archive already exists locally.",
    )
    parser.add_argument(
        "--no-manifest",
        action="store_true",
        help="Do not write manifest file to disk.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw manifest JSON to standard output.",
    )
    return parser.parse_args(args)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_cli_args(argv)
    raw_dir = Path(args.data_dir).resolve()
    manifest_path = Path(args.manifest).resolve() if args.manifest else raw_dir / "acquisition_manifest.json"

    if args.download:
        if not args.json:
            print(f"Starting atomic acquisition into {raw_dir}...")
        manifest, success = acquire_raw_datasets(raw_dir, overwrite=args.overwrite)
    else:
        if not args.json:
            print(f"Verifying raw datasets in {raw_dir} (read-only)...")
        manifest = verify_all_raw_datasets(raw_dir)
        success = manifest["required_datasets_verified"]

    if not args.no_manifest:
        write_acquisition_manifest(manifest, manifest_path)
        if not args.json:
            print(f"Acquisition manifest written to: {manifest_path}")

    if args.json:
        print(json.dumps(manifest, indent=2))
    else:
        print("\n=== RAW DATASET ACQUISITION SUMMARY ===")
        print(f"Base Directory:              {manifest['raw_base_directory']}")
        print(f"Required Datasets Verified:  {manifest['required_datasets_verified']}")
        print(f"Total Datasets Inspected:    {manifest['total_datasets_checked']}")
        for ds in manifest["datasets"]:
            status = ds["acquisition_status"]
            size = ds["size_bytes"]
            entries = ds.get("archive_entry_count", "N/A")
            req = "[REQ]" if ds.get("is_required_for_dev") else "[OPT]"
            print(f"  - {req} {ds['dataset_id']:26} : {status:20} (size={size:10} bytes, entries={entries})")
            if ds["warnings"]:
                for w in ds["warnings"]:
                    print(f"      WARNING: {w}")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
