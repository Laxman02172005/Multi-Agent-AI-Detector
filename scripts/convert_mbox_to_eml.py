"""
MBOX to EML Conversion Utility and Development Dataset Builder.

Converts standard Unix MBOX files into individual RFC822/RFC5322 (.eml) files,
extracting deterministic message filenames, tracking SHA-256 digests, detecting
duplicate message contents and duplicate Message-IDs, and producing structured
machine-readable manifests (CSV and JSONL).

Design guarantees:
- Uses only Python standard library (mailbox, email, hashlib, csv, json, pathlib).
- Preserves raw message bytes without re-parsing or re-serializing via BytesGenerator.
- Prevents path traversal and unsafe filename characters.
- Deterministic, collision-free naming regardless of Message-ID anomalies.
- Passive extraction: never executes attachments, never fetches URLs, no network calls.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mailbox
import os
from pathlib import Path
import random
import re
import shutil
import sys
import tarfile
from typing import Any, Dict, List, Optional, Set, Tuple
from email import policy
from email.parser import BytesHeaderParser


# ── Constants ──────────────────────────────────────────────────────────────────

DEFAULT_RANDOM_SEED = 42
TARGET_EASY_HAM_COUNT = 500
TARGET_HARD_HAM_COUNT = 250
TARGET_NAZARIO_PHISHING_COUNT = 250
TOTAL_TARGET_COUNT = 1000

UW_IMAP_SUBJECT = "DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA"
UW_IMAP_FROM_INDICATOR = "Mail System Internal Data"

UNSAFE_FILENAME_CHARS = re.compile(r'[^a-zA-Z0-9_\-\.]')
MBOXRD_FROM_RE = re.compile(rb'^(>+From )', re.MULTILINE)


class MBoxConversionError(Exception):
    """Raised when MBOX conversion encounters an unrecoverable error."""
    pass


# ── MBOX Parsing Subclass & Byte Utilities ────────────────────────────────────

class RobustMbox(mailbox.mbox):
    """
    Cross-platform mailbox.mbox subclass supporting both LF and CRLF line terminators.

    Fixes Python's stdlib mailbox bug where mailbox.linesep is initialized to os.linesep,
    causing Unix LF MBOX files parsed on Windows to include trailing container delimiter
    newlines in message payloads (or CRLF files on POSIX).
    """

    def _generate_toc(self) -> None:
        """Generate key-to-(start, stop) table of contents supporting both LF and CRLF."""
        starts, stops = [], []
        last_empty_len = 0
        self._file.seek(0)
        while True:
            line_pos = self._file.tell()
            line = self._file.readline()
            if line.startswith(b'From '):
                if len(stops) < len(starts):
                    if last_empty_len > 0:
                        stops.append(line_pos - last_empty_len)
                    else:
                        stops.append(line_pos)
                starts.append(line_pos)
                last_empty_len = 0
            elif not line:
                if last_empty_len > 0:
                    stops.append(line_pos - last_empty_len)
                else:
                    stops.append(line_pos)
                break
            elif line in (b'\r\n', b'\n'):
                last_empty_len = len(line)
            else:
                last_empty_len = 0
        self._toc = dict(enumerate(zip(starts, stops)))
        self._next_key = len(self._toc)
        self._file_length = self._file.tell()

    def get_bytes(self, key: int, from_: bool = False) -> bytes:
        """Return raw message bytes without os.linesep character replacement."""
        start, stop = self._lookup(key)
        self._file.seek(start)
        if not from_:
            self._file.readline()
        return self._file.read(stop - self._file.tell())


def unescape_mboxrd_from(raw_bytes: bytes) -> bytes:
    """
    Reversibly unescape MBOXRD '>From ' lines in email payloads.

    In the MBOXRD format (DJB specification), any line beginning with one or more '>'
    characters followed immediately by 'From ' (e.g. '>From ', '>>From ') has an extra '>'
    prepended upon insertion into the MBOX container.

    Unescaping reversibly strips exactly one leading '>' character from lines matching
    b'^(>+From )'. Lines starting with '> ' (e.g., standard email reply quotes) are never
    modified.

    MBOXO vs MBOXRD Ambiguity (RFC 4155):
    Legacy MBOXO files escaped only 'From ' -> '>From ' and left existing '>From ' lines
    unchanged, making them lossy. Without external metadata, unescaping assumes MBOXRD.
    """
    return MBOXRD_FROM_RE.sub(lambda m: m.group(1)[1:], raw_bytes)


def write_eml_file(out_file: Path, raw_bytes: bytes, overwrite: bool = False) -> None:
    """
    Safely write an .eml file.
    
    If overwrite is False, uses exclusive creation mode ('xb') to eliminate TOCTOU races
    and guarantee that no pre-existing user file is overwritten.
    """
    mode = "wb" if overwrite else "xb"
    with open(out_file, mode) as f_out:
        f_out.write(raw_bytes)


# ── Core Helper Functions ──────────────────────────────────────────────────────

def sanitize_filename_component(component: str, default: str = "msg") -> str:
    """Sanitize a string for safe use in a filename, removing unsafe characters."""
    if not component:
        return default
    sanitized = UNSAFE_FILENAME_CHARS.sub("_", component).strip("._")
    return sanitized if sanitized else default


def extract_raw_message_bytes(box: mailbox.mbox, key: int) -> bytes:
    """
    Extract raw RFC822 message bytes from an open mailbox.mbox object.

    Technical investigation & transformations:
    - We use `box.get_file(key, from_=False).read()` rather than `box.get_message(key).as_bytes()`.
    - `box.get_message(key).as_bytes()` re-serializes the email via `BytesGenerator`,
      altering header foldings, whitespace, and boundary encodings.
    - `box.get_file(key, from_=False)` slices the exact byte range of the message directly
      from the underlying file handle, skipping only the Unix mbox envelope delimiter line
      (`From <envelope-sender> <date>\\n`).
    - Unlike standard `box.get_bytes(key)`, `RobustMbox` does not replace line endings
      (`linesep -> \\n`), preserving the native line terminators (CRLF or LF) as stored.
    """
    try:
        partial = box.get_file(key, from_=False)
        return partial.read()
    except Exception:
        return box.get_bytes(key, from_=False)


def extract_message_id_and_warnings(raw_bytes: bytes) -> Tuple[Optional[str], List[str]]:
    """
    Extract the Message-ID header from raw email bytes using BytesHeaderParser.
    
    Does not parse message bodies or decode attachments.
    Returns (message_id_string_or_None, list_of_warnings).
    Detects multiple Message-ID headers (RFC 5322 section 3.6 violation).
    """
    warnings: List[str] = []
    if not raw_bytes or len(raw_bytes.strip()) == 0:
        return None, ["Empty message payload (0 bytes)"]

    try:
        header_parser = BytesHeaderParser(policy=policy.default)
        msg_headers = header_parser.parsebytes(raw_bytes)
        
        # Check parser defects in headers
        if msg_headers.defects:
            for defect in msg_headers.defects:
                warnings.append(f"Header defect: {defect.__class__.__name__}")

        all_msg_ids = msg_headers.get_all("message-id") or []
        cleaned_ids = [str(mid).strip() for mid in all_msg_ids if str(mid).strip()]
        
        if len(cleaned_ids) > 1:
            warnings.append(
                f"Multiple Message-ID headers detected ({len(cleaned_ids)}): "
                f"RFC 5322 section 3.6 violation"
            )

        primary_id = cleaned_ids[0] if cleaned_ids else None
        return primary_id, warnings
    except Exception as exc:
        warnings.append(f"Header parsing failure: {type(exc).__name__}: {str(exc)}")
        return None, warnings


def generate_deterministic_filename(
    prefix: str,
    index: int,
    content_hash: str,
    extension: str = ".eml"
) -> str:
    """
    Generate a deterministic, filesystem-safe filename.
    
    Format: <prefix>_<index:06d>_<hash12><extension>
    Example: nazario_000001_a1b2c3d4e5f6.eml
    """
    clean_prefix = sanitize_filename_component(prefix, default="msg")
    short_hash = content_hash[:12] if content_hash else "0" * 12
    return f"{clean_prefix}_{index:06d}_{short_hash}{extension}"


def validate_safe_output_path(output_file: Path, output_dir: Path) -> None:
    """Ensure output file does not escape output directory (prevent path traversal)."""
    resolved_file = output_file.resolve()
    resolved_dir = output_dir.resolve()
    try:
        resolved_file.relative_to(resolved_dir)
    except ValueError:
        raise ValueError(f"Path traversal detected: {output_file} is outside {output_dir}")


def is_uw_imap_internal_record(raw_bytes: bytes) -> bool:
    """
    Conservatively identify UW IMAP internal folder data mailbox records.

    These internal mailbox control records (located at MBOX key 0 in yearly archives)
    contain folder metadata and are not genuine email messages.

    Conservative signature matching:
    - Subject header exactly matches (case-insensitive, stripped):
      "DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA"
    - AND From header contains "Mail System Internal Data"

    Does not filter ordinary messages where the subject or body merely mentions
    internal data or contains similar wording.
    """
    if not raw_bytes or len(raw_bytes.strip()) == 0:
        return False
    try:
        header_parser = BytesHeaderParser(policy=policy.default)
        msg_headers = header_parser.parsebytes(raw_bytes)

        subj = str(msg_headers.get("subject", "") or "").strip()
        from_hdr = str(msg_headers.get("from", "") or "").strip()

        # Exact subject match (case-insensitive)
        if subj.upper() != "DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA":
            return False

        # From must contain "Mail System Internal Data" (case-insensitive)
        if "mail system internal data" not in from_hdr.lower():
            return False

        return True
    except Exception:
        return False


def detect_authentication_headers(raw_bytes: bytes) -> Dict[str, bool]:
    """
    Passively check for the presence of authentication-related headers.

    CRITICAL DISTINCTIONS:
    - Records presence ONLY; does not evaluate cryptographic validity or trustworthiness.
    - DKIM-Signature presence != DKIM pass.
    - Authentication-Results presence != verified authentication claim.
    - Missing headers != authentication failure.
    - Performs no DNS lookups or remote mail server queries.
    """
    res = {
        "has_dkim_signature": False,
        "has_authentication_results": False,
        "has_received_spf": False,
        "has_arc": False,
    }
    if not raw_bytes or len(raw_bytes.strip()) == 0:
        return res
    try:
        header_parser = BytesHeaderParser(policy=policy.default)
        msg_headers = header_parser.parsebytes(raw_bytes)

        if msg_headers.get_all("dkim-signature"):
            res["has_dkim_signature"] = True
        if msg_headers.get_all("authentication-results"):
            res["has_authentication_results"] = True
        if msg_headers.get_all("received-spf"):
            res["has_received_spf"] = True

        arc_headers = (
            (msg_headers.get_all("arc-authentication-results") or []) +
            (msg_headers.get_all("arc-message-signature") or []) +
            (msg_headers.get_all("arc-seal") or [])
        )
        if arc_headers:
            res["has_arc"] = True

        return res
    except Exception:
        return res


# ── Excluded Record ────────────────────────────────────────────────────────────

class ExcludedRecord:
    """Represents an excluded mailbox control or non-email record."""

    def __init__(
        self,
        source_archive: str,
        mbox_key: Optional[int],
        reason: str,
        exclusion_status: str = "EXCLUDED_INTERNAL_RECORD",
        sha256: str = "",
        byte_size: int = 0,
    ):
        self.source_archive = source_archive
        self.mbox_key = mbox_key
        self.reason = reason
        self.exclusion_status = exclusion_status
        self.sha256 = sha256
        self.byte_size = byte_size

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_archive": self.source_archive,
            "mbox_key": self.mbox_key,
            "reason": self.reason,
            "exclusion_status": self.exclusion_status,
            "sha256": self.sha256,
            "byte_size": self.byte_size,
        }


# ── Conversion Record ──────────────────────────────────────────────────────────

class ConversionRecord:
    """Represents the conversion metadata for one email sample in the manifest."""

    def __init__(
        self,
        sample_id: str,
        source_dataset: str,
        source_category: str,
        assigned_label: str,
        source_file: str,
        message_id: Optional[str],
        sha256: str,
        byte_size: int,
        conversion_status: str,
        warnings: List[str],
        export_filename: str,
        is_duplicate_hash: bool = False,
        is_duplicate_message_id: bool = False,
        source_archive: Optional[str] = None,
        source_year: Optional[str] = None,
        original_mbox_key: Optional[int] = None,
        source_message_identifier: Optional[str] = None,
        relative_eml_path: Optional[str] = None,
        auth_headers_present: Optional[Dict[str, bool]] = None,
    ):
        self.sample_id = sample_id
        self.source_dataset = source_dataset
        self.source_category = source_category
        self.assigned_label = assigned_label
        self.source_file = source_file
        self.message_id = message_id or ""
        self.sha256 = sha256
        self.byte_size = byte_size
        self.conversion_status = conversion_status
        self.warnings = warnings
        self.export_filename = export_filename
        self.is_duplicate_hash = is_duplicate_hash
        self.is_duplicate_message_id = is_duplicate_message_id
        self.source_archive = source_archive or source_file
        self.source_year = source_year or ""
        self.original_mbox_key = original_mbox_key
        self.source_message_identifier = source_message_identifier or (str(original_mbox_key) if original_mbox_key is not None else source_file)
        self.relative_eml_path = relative_eml_path or export_filename
        self.auth_headers_present = auth_headers_present or {
            "has_dkim_signature": False,
            "has_authentication_results": False,
            "has_received_spf": False,
            "has_arc": False,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "source_dataset": self.source_dataset,
            "source_archive": self.source_archive,
            "source_year": self.source_year,
            "original_mbox_key": self.original_mbox_key if self.original_mbox_key is not None else "",
            "source_message_identifier": self.source_message_identifier,
            "assigned_label": self.assigned_label,
            "source_category": self.source_category,
            "relative_eml_path": self.relative_eml_path,
            "sha256": self.sha256,
            "byte_size": self.byte_size,
            "conversion_status": self.conversion_status,
            "is_duplicate_hash": self.is_duplicate_hash,
            "is_duplicate_message_id": self.is_duplicate_message_id,
            "has_dkim_signature": self.auth_headers_present.get("has_dkim_signature", False),
            "has_authentication_results": self.auth_headers_present.get("has_authentication_results", False),
            "has_received_spf": self.auth_headers_present.get("has_received_spf", False),
            "has_arc": self.auth_headers_present.get("has_arc", False),
            "warnings": "; ".join(self.warnings) if self.warnings else "",
            "export_filename": self.export_filename,
            "source_file": self.source_file,
            "message_id": self.message_id,
        }


# ── Manifest Writers ───────────────────────────────────────────────────────────

def write_manifest_csv(records: List[ConversionRecord], manifest_path: Path) -> None:
    """Write conversion records to a CSV manifest file."""
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "sample_id",
        "source_dataset",
        "source_archive",
        "source_year",
        "original_mbox_key",
        "source_message_identifier",
        "assigned_label",
        "source_category",
        "relative_eml_path",
        "sha256",
        "byte_size",
        "conversion_status",
        "is_duplicate_hash",
        "is_duplicate_message_id",
        "has_dkim_signature",
        "has_authentication_results",
        "has_received_spf",
        "has_arc",
        "warnings",
        "export_filename",
        "source_file",
        "message_id",
    ]
    with open(manifest_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow(r.to_dict())


def write_manifest_jsonl(records: List[ConversionRecord], manifest_path: Path) -> None:
    """Write conversion records to a JSONL manifest file."""
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r.to_dict()) + "\n")


def write_dataset_summary(
    records: List[ConversionRecord],
    summary_path: Path,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Write high-level summary statistics to a JSON summary file."""
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    
    total = len(records)
    by_source: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    by_label: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    by_year: Dict[str, int] = {}
    dup_hashes = sum(1 for r in records if r.is_duplicate_hash)
    dup_msg_ids = sum(1 for r in records if r.is_duplicate_message_id)

    dkim_count = sum(1 for r in records if r.auth_headers_present.get("has_dkim_signature", False))
    auth_results_count = sum(1 for r in records if r.auth_headers_present.get("has_authentication_results", False))
    spf_count = sum(1 for r in records if r.auth_headers_present.get("has_received_spf", False))
    arc_count = sum(1 for r in records if r.auth_headers_present.get("has_arc", False))

    for r in records:
        by_source[r.source_dataset] = by_source.get(r.source_dataset, 0) + 1
        by_category[r.source_category] = by_category.get(r.source_category, 0) + 1
        by_label[r.assigned_label] = by_label.get(r.assigned_label, 0) + 1
        by_status[r.conversion_status] = by_status.get(r.conversion_status, 0) + 1
        if r.source_year:
            by_year[r.source_year] = by_year.get(r.source_year, 0) + 1

    summary_data: Dict[str, Any] = {
        "dataset_name": "Multi-Agent AI Phishing Email Detector Development Dataset",
        "total_samples": total,
        "counts_by_source": by_source,
        "counts_by_category": by_category,
        "counts_by_label": by_label,
        "counts_by_status": by_status,
        "counts_by_year": by_year,
        "duplicate_content_hashes": dup_hashes,
        "duplicate_message_ids": dup_msg_ids,
        "authentication_header_presence": {
            "dkim_signature_present_count": dkim_count,
            "authentication_results_present_count": auth_results_count,
            "received_spf_present_count": spf_count,
            "arc_present_count": arc_count,
        },
    }
    if extra_metadata:
        summary_data.update(extra_metadata)

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)


# ── MBOX Converter Implementation ─────────────────────────────────────────────

def convert_mbox_to_eml(
    mbox_path: str | Path,
    output_dir: str | Path,
    *,
    source_dataset: str = "nazario_legacy",
    source_category: str = "phishing",
    assigned_label: str = "phishing",
    source_archive: Optional[str] = None,
    source_year: Optional[str] = None,
    prefix: str = "nazario",
    id_prefix: str = "DEV_PHISH",
    start_index: int = 1,
    limit: Optional[int] = None,
    seed: Optional[int] = None,
    seen_hashes: Optional[Set[str]] = None,
    seen_message_ids: Optional[Set[str]] = None,
    overwrite: bool = False,
    unescape_from: bool = False,
    filter_uw_internal: bool = True,
) -> Tuple[List[ConversionRecord], Dict[str, Any]]:
    """
    Convert an MBOX file into individual .eml files.

    Parameters:
    - mbox_path: Path to the input .mbox file.
    - output_dir: Directory where .eml files will be written.
    - source_dataset: Label of the dataset source (e.g. 'nazario_legacy').
    - source_category: Original category in the corpus (e.g. 'phishing').
    - assigned_label: Target label in development dataset ('phishing', 'ham_easy', 'ham_hard').
    - source_archive: Original archive filename (defaults to mbox filename).
    - source_year: Source archive year string (e.g. '2015', '2021').
    - prefix: Filename prefix for exported files.
    - id_prefix: Sample ID prefix (e.g. 'DEV_PHISH').
    - start_index: 1-based starting index for IDs and filenames.
    - limit: Maximum number of samples to convert.
    - seed: Random seed if deterministic subsampling is needed.
    - seen_hashes: Existing set of SHA-256 hashes for cross-batch duplicate detection.
    - seen_message_ids: Existing set of Message-IDs for cross-batch duplicate detection.
    - overwrite: If True, allow overwriting existing files (default: False, exclusive creation).
    - unescape_from: If True, reversibly unescape MBOXRD '>From ' lines (default: False).
    - filter_uw_internal: If True, exclude UW IMAP internal folder data mailbox control records.

    Returns:
    - List of ConversionRecord instances.
    - Summary dictionary with conversion statistics.
    """
    mbox_file = Path(mbox_path)
    out_dir = Path(output_dir)
    archive_name = source_archive or mbox_file.name

    if not mbox_file.exists():
        raise FileNotFoundError(f"Input MBOX file does not exist: {mbox_file}")
    if not mbox_file.is_file():
        raise MBoxConversionError(f"Input MBOX path is not a file: {mbox_file}")

    out_dir.mkdir(parents=True, exist_ok=True)

    if seen_hashes is None:
        seen_hashes = set()
    if seen_message_ids is None:
        seen_message_ids = set()

    box = None
    records: List[ConversionRecord] = []
    excluded_records: List[ExcludedRecord] = []
    stats: Dict[str, Any] = {
        "mbox_file": str(mbox_file.name),
        "source_archive": archive_name,
        "total_messages_in_mbox": 0,
        "usable_messages_in_mbox": 0,
        "converted_count": 0,
        "error_count": 0,
        "duplicate_hash_count": 0,
        "duplicate_message_id_count": 0,
        "excluded_count": 0,
        "excluded_records": [],
    }

    try:
        box = RobustMbox(str(mbox_file))
        all_keys = list(box.keys())
        stats["total_messages_in_mbox"] = len(all_keys)

        # Pre-filter UW IMAP internal records if requested
        usable_keys: List[int] = []
        for key in all_keys:
            try:
                raw_bytes_peek = extract_raw_message_bytes(box, key)
                if filter_uw_internal and is_uw_imap_internal_record(raw_bytes_peek):
                    h = hashlib.sha256(raw_bytes_peek).hexdigest()
                    exc_rec = ExcludedRecord(
                        source_archive=archive_name,
                        mbox_key=key,
                        reason="UW IMAP internal mailbox folder data record (FOLDER INTERNAL DATA)",
                        exclusion_status="EXCLUDED_INTERNAL_RECORD",
                        sha256=h,
                        byte_size=len(raw_bytes_peek),
                    )
                    excluded_records.append(exc_rec)
                    continue
            except Exception:
                # If peek fails, let it be handled during processing
                pass
            usable_keys.append(key)

        stats["usable_messages_in_mbox"] = len(usable_keys)
        stats["excluded_count"] = len(excluded_records)
        stats["excluded_records"] = [r.to_dict() for r in excluded_records]

        # Deterministic sampling from usable keys if limit is specified and less than total
        if limit is not None and limit < len(usable_keys):
            if seed is not None:
                rng = random.Random(seed)
                selected_keys = sorted(rng.sample(usable_keys, limit))
            else:
                selected_keys = usable_keys[:limit]
        else:
            selected_keys = usable_keys

        curr_index = start_index
        for key in selected_keys:
            sample_id = f"{id_prefix}_{curr_index:06d}"
            try:
                raw_bytes = extract_raw_message_bytes(box, key)
                if unescape_from:
                    raw_bytes = unescape_mboxrd_from(raw_bytes)
            except Exception as exc:
                # Failure extracting bytes from MBOX
                rec = ConversionRecord(
                    sample_id=sample_id,
                    source_dataset=source_dataset,
                    source_category=source_category,
                    assigned_label=assigned_label,
                    source_file=mbox_file.name,
                    message_id=None,
                    sha256="",
                    byte_size=0,
                    conversion_status="ERROR",
                    warnings=[f"Failed to read message key {key} from MBOX: {str(exc)}"],
                    export_filename="",
                    source_archive=archive_name,
                    source_year=source_year,
                    original_mbox_key=key,
                    source_message_identifier=f"mbox_key_{key}",
                )
                records.append(rec)
                stats["error_count"] += 1
                curr_index += 1
                continue

            content_hash = hashlib.sha256(raw_bytes).hexdigest()
            byte_size = len(raw_bytes)

            # Check duplicate hash
            is_dup_hash = content_hash in seen_hashes
            seen_hashes.add(content_hash)
            if is_dup_hash:
                stats["duplicate_hash_count"] += 1

            # Extract Message-ID and parse warnings
            msg_id, warnings = extract_message_id_and_warnings(raw_bytes)
            auth_headers = detect_authentication_headers(raw_bytes)

            # Check duplicate Message-ID
            is_dup_msg_id = False
            if msg_id:
                if msg_id in seen_message_ids:
                    is_dup_msg_id = True
                    stats["duplicate_message_id_count"] += 1
                    warnings.append(f"Duplicate Message-ID: {msg_id}")
                seen_message_ids.add(msg_id)
            else:
                warnings.append("Missing Message-ID header")

            if is_dup_hash:
                warnings.append(f"Duplicate content SHA-256: {content_hash}")

            # Check empty message or whitespace-only message
            if byte_size == 0 or len(raw_bytes.strip()) == 0:
                rec = ConversionRecord(
                    sample_id=sample_id,
                    source_dataset=source_dataset,
                    source_category=source_category,
                    assigned_label=assigned_label,
                    source_file=mbox_file.name,
                    message_id=msg_id,
                    sha256=content_hash,
                    byte_size=byte_size,
                    conversion_status="ERROR",
                    warnings=warnings if warnings else ["Empty message payload (0 bytes)"],
                    export_filename="",
                    is_duplicate_hash=is_dup_hash,
                    is_duplicate_message_id=is_dup_msg_id,
                    source_archive=archive_name,
                    source_year=source_year,
                    original_mbox_key=key,
                    source_message_identifier=f"mbox_key_{key}",
                    auth_headers_present=auth_headers,
                )
                records.append(rec)
                stats["error_count"] += 1
                curr_index += 1
                continue

            # Deterministic filename
            export_fname = generate_deterministic_filename(prefix, curr_index, content_hash)
            out_file = out_dir / export_fname
            validate_safe_output_path(out_file, out_dir)

            # Write individual .eml file with exclusive collision protection
            try:
                write_eml_file(out_file, raw_bytes, overwrite=overwrite)
            except FileExistsError:
                rec = ConversionRecord(
                    sample_id=sample_id,
                    source_dataset=source_dataset,
                    source_category=source_category,
                    assigned_label=assigned_label,
                    source_file=mbox_file.name,
                    message_id=msg_id,
                    sha256=content_hash,
                    byte_size=byte_size,
                    conversion_status="ERROR",
                    warnings=warnings + [f"Output file collision: file already exists: {out_file.name}"],
                    export_filename=export_fname,
                    is_duplicate_hash=is_dup_hash,
                    is_duplicate_message_id=is_dup_msg_id,
                    source_archive=archive_name,
                    source_year=source_year,
                    original_mbox_key=key,
                    source_message_identifier=f"mbox_key_{key}",
                    auth_headers_present=auth_headers,
                )
                records.append(rec)
                stats["error_count"] += 1
                curr_index += 1
                continue

            status = "WARNING" if warnings else "SUCCESS"
            rec = ConversionRecord(
                sample_id=sample_id,
                source_dataset=source_dataset,
                source_category=source_category,
                assigned_label=assigned_label,
                source_file=mbox_file.name,
                message_id=msg_id,
                sha256=content_hash,
                byte_size=byte_size,
                conversion_status=status,
                warnings=warnings,
                export_filename=export_fname,
                is_duplicate_hash=is_dup_hash,
                is_duplicate_message_id=is_dup_msg_id,
                source_archive=archive_name,
                source_year=source_year,
                original_mbox_key=key,
                source_message_identifier=f"mbox_key_{key}",
                auth_headers_present=auth_headers,
            )
            records.append(rec)
            stats["converted_count"] += 1
            curr_index += 1

    finally:
        if box is not None:
            box.close()

    return records, stats


# ── Tar.bz2 Converter Implementation (e.g. SpamAssassin) ──────────────────────

def convert_tar_bz2_to_eml(
    tar_path: str | Path,
    output_dir: str | Path,
    *,
    source_dataset: str = "spamassassin",
    source_category: str = "easy_ham",
    assigned_label: str = "ham_easy",
    prefix: str = "easy_ham",
    id_prefix: str = "DEV_HAM",
    start_index: int = 1,
    limit: Optional[int] = None,
    seed: Optional[int] = None,
    seen_hashes: Optional[Set[str]] = None,
    seen_message_ids: Optional[Set[str]] = None,
    overwrite: bool = False,
) -> Tuple[List[ConversionRecord], Dict[str, Any]]:
    """
    Extract and convert messages from a SpamAssassin tar.bz2 archive to individual .eml files.
    Preserves raw bytes exactly as stored in the archive without modification.
    """
    tar_file = Path(tar_path)
    out_dir = Path(output_dir)

    if not tar_file.exists():
        raise FileNotFoundError(f"Input tar.bz2 file does not exist: {tar_file}")
    if not tar_file.is_file():
        raise ValueError(f"Input path is not a file: {tar_file}")

    out_dir.mkdir(parents=True, exist_ok=True)

    if seen_hashes is None:
        seen_hashes = set()
    if seen_message_ids is None:
        seen_message_ids = set()

    records: List[ConversionRecord] = []
    stats: Dict[str, Any] = {
        "tar_file": str(tar_file.name),
        "total_files_in_archive": 0,
        "converted_count": 0,
        "error_count": 0,
        "duplicate_hash_count": 0,
        "duplicate_message_id_count": 0,
    }

    with tarfile.open(tar_file, "r:bz2") as tar:
        # Collect regular file members deterministically sorted by name
        all_members = sorted([m for m in tar.getmembers() if m.isfile()], key=lambda m: m.name)
        stats["total_files_in_archive"] = len(all_members)

        if limit is not None and limit < len(all_members):
            if seed is not None:
                rng = random.Random(seed)
                selected_members = sorted(rng.sample(all_members, limit), key=lambda m: m.name)
            else:
                selected_members = all_members[:limit]
        else:
            selected_members = all_members

        curr_index = start_index
        for member in selected_members:
            sample_id = f"{id_prefix}_{curr_index:06d}"
            try:
                f_in = tar.extractfile(member)
                if f_in is None:
                    raise IOError(f"Could not extract member {member.name}")
                raw_bytes = f_in.read()
            except Exception as exc:
                rec = ConversionRecord(
                    sample_id=sample_id,
                    source_dataset=source_dataset,
                    source_category=source_category,
                    assigned_label=assigned_label,
                    source_file=member.name,
                    message_id=None,
                    sha256="",
                    byte_size=0,
                    conversion_status="ERROR",
                    warnings=[f"Failed to read tar member {member.name}: {str(exc)}"],
                    export_filename="",
                    source_archive=tar_file.name,
                    source_message_identifier=member.name,
                )
                records.append(rec)
                stats["error_count"] += 1
                curr_index += 1
                continue

            content_hash = hashlib.sha256(raw_bytes).hexdigest()
            byte_size = len(raw_bytes)

            is_dup_hash = content_hash in seen_hashes
            seen_hashes.add(content_hash)
            if is_dup_hash:
                stats["duplicate_hash_count"] += 1

            msg_id, warnings = extract_message_id_and_warnings(raw_bytes)
            auth_headers = detect_authentication_headers(raw_bytes)

            is_dup_msg_id = False
            if msg_id:
                if msg_id in seen_message_ids:
                    is_dup_msg_id = True
                    stats["duplicate_message_id_count"] += 1
                    warnings.append(f"Duplicate Message-ID: {msg_id}")
                seen_message_ids.add(msg_id)
            else:
                warnings.append("Missing Message-ID header")

            if is_dup_hash:
                warnings.append(f"Duplicate content SHA-256: {content_hash}")

            if byte_size == 0 or len(raw_bytes.strip()) == 0:
                rec = ConversionRecord(
                    sample_id=sample_id,
                    source_dataset=source_dataset,
                    source_category=source_category,
                    assigned_label=assigned_label,
                    source_file=member.name,
                    message_id=msg_id,
                    sha256=content_hash,
                    byte_size=byte_size,
                    conversion_status="ERROR",
                    warnings=warnings if warnings else ["Empty message payload (0 bytes)"],
                    export_filename="",
                    is_duplicate_hash=is_dup_hash,
                    is_duplicate_message_id=is_dup_msg_id,
                    source_archive=tar_file.name,
                    source_message_identifier=member.name,
                    auth_headers_present=auth_headers,
                )
                records.append(rec)
                stats["error_count"] += 1
                curr_index += 1
                continue

            export_fname = generate_deterministic_filename(prefix, curr_index, content_hash)
            out_file = out_dir / export_fname
            validate_safe_output_path(out_file, out_dir)

            try:
                write_eml_file(out_file, raw_bytes, overwrite=overwrite)
            except FileExistsError:
                rec = ConversionRecord(
                    sample_id=sample_id,
                    source_dataset=source_dataset,
                    source_category=source_category,
                    assigned_label=assigned_label,
                    source_file=member.name,
                    message_id=msg_id,
                    sha256=content_hash,
                    byte_size=byte_size,
                    conversion_status="ERROR",
                    warnings=warnings + [f"Output file collision: file already exists: {out_file.name}"],
                    export_filename=export_fname,
                    is_duplicate_hash=is_dup_hash,
                    is_duplicate_message_id=is_dup_msg_id,
                    source_archive=tar_file.name,
                    source_message_identifier=member.name,
                    auth_headers_present=auth_headers,
                )
                records.append(rec)
                stats["error_count"] += 1
                curr_index += 1
                continue

            status = "WARNING" if warnings else "SUCCESS"
            rec = ConversionRecord(
                sample_id=sample_id,
                source_dataset=source_dataset,
                source_category=source_category,
                assigned_label=assigned_label,
                source_file=member.name,
                message_id=msg_id,
                sha256=content_hash,
                byte_size=byte_size,
                conversion_status=status,
                warnings=warnings,
                export_filename=export_fname,
                is_duplicate_hash=is_dup_hash,
                is_duplicate_message_id=is_dup_msg_id,
                source_archive=tar_file.name,
                source_message_identifier=member.name,
                auth_headers_present=auth_headers,
            )
            records.append(rec)
            stats["converted_count"] += 1
            curr_index += 1

    return records, stats


# ── Flat RFC822 Importer (e.g. SpamAssassin) ──────────────────────────────────

def import_flat_rfc822_dir(
    input_dir: str | Path,
    output_dir: str | Path,
    *,
    source_dataset: str = "spamassassin",
    source_category: str = "easy_ham",
    assigned_label: str = "ham",
    prefix: str = "easy_ham",
    id_prefix: str = "DEV_HAM",
    start_index: int = 1,
    limit: Optional[int] = None,
    seed: Optional[int] = None,
    seen_hashes: Optional[Set[str]] = None,
    seen_message_ids: Optional[Set[str]] = None,
    overwrite: bool = False,
) -> Tuple[List[ConversionRecord], Dict[str, Any]]:
    """
    Import individual flat RFC822 files (such as extracted SpamAssassin directories)
    into the development dataset with deterministic filenames and manifest tracking.
    """
    in_dir = Path(input_dir)
    out_dir = Path(output_dir)

    if not in_dir.exists():
        raise FileNotFoundError(f"Input directory does not exist: {in_dir}")
    if not in_dir.is_dir():
        raise ValueError(f"Input path is not a directory: {in_dir}")

    out_dir.mkdir(parents=True, exist_ok=True)

    if seen_hashes is None:
        seen_hashes = set()
    if seen_message_ids is None:
        seen_message_ids = set()

    # Collect all non-hidden files in order
    all_files = sorted([p for p in in_dir.iterdir() if p.is_file() and not p.name.startswith(".")])
    
    stats: Dict[str, Any] = {
        "input_dir": str(in_dir),
        "total_files_in_dir": len(all_files),
        "converted_count": 0,
        "error_count": 0,
        "duplicate_hash_count": 0,
        "duplicate_message_id_count": 0,
    }

    if limit is not None and limit < len(all_files):
        if seed is not None:
            rng = random.Random(seed)
            selected_files = sorted(rng.sample(all_files, limit))
        else:
            selected_files = all_files[:limit]
    else:
        selected_files = all_files

    records: List[ConversionRecord] = []
    curr_index = start_index

    for src_file in selected_files:
        sample_id = f"{id_prefix}_{curr_index:06d}"
        try:
            with open(src_file, "rb") as f_in:
                raw_bytes = f_in.read()
        except Exception as exc:
            rec = ConversionRecord(
                sample_id=sample_id,
                source_dataset=source_dataset,
                source_category=source_category,
                assigned_label=assigned_label,
                source_file=src_file.name,
                message_id=None,
                sha256="",
                byte_size=0,
                conversion_status="ERROR",
                warnings=[f"Failed to read file {src_file.name}: {str(exc)}"],
                export_filename="",
            )
            records.append(rec)
            stats["error_count"] += 1
            curr_index += 1
            continue

        content_hash = hashlib.sha256(raw_bytes).hexdigest()
        byte_size = len(raw_bytes)

        is_dup_hash = content_hash in seen_hashes
        seen_hashes.add(content_hash)
        if is_dup_hash:
            stats["duplicate_hash_count"] += 1

        msg_id, warnings = extract_message_id_and_warnings(raw_bytes)
        auth_headers = detect_authentication_headers(raw_bytes)
        
        is_dup_msg_id = False
        if msg_id:
            if msg_id in seen_message_ids:
                is_dup_msg_id = True
                stats["duplicate_message_id_count"] += 1
                warnings.append(f"Duplicate Message-ID: {msg_id}")
            seen_message_ids.add(msg_id)
        else:
            warnings.append("Missing Message-ID header")

        if is_dup_hash:
            warnings.append(f"Duplicate content SHA-256: {content_hash}")

        if byte_size == 0 or len(raw_bytes.strip()) == 0:
            rec = ConversionRecord(
                sample_id=sample_id,
                source_dataset=source_dataset,
                source_category=source_category,
                assigned_label=assigned_label,
                source_file=src_file.name,
                message_id=msg_id,
                sha256=content_hash,
                byte_size=byte_size,
                conversion_status="ERROR",
                warnings=warnings if warnings else ["Empty message payload (0 bytes)"],
                export_filename="",
                is_duplicate_hash=is_dup_hash,
                is_duplicate_message_id=is_dup_msg_id,
                source_archive=src_file.parent.name,
                source_message_identifier=src_file.name,
                auth_headers_present=auth_headers,
            )
            records.append(rec)
            stats["error_count"] += 1
            curr_index += 1
            continue

        export_fname = generate_deterministic_filename(prefix, curr_index, content_hash)
        out_file = out_dir / export_fname
        validate_safe_output_path(out_file, out_dir)

        # Write individual .eml file with exclusive collision protection
        try:
            write_eml_file(out_file, raw_bytes, overwrite=overwrite)
        except FileExistsError:
            rec = ConversionRecord(
                sample_id=sample_id,
                source_dataset=source_dataset,
                source_category=source_category,
                assigned_label=assigned_label,
                source_file=src_file.name,
                message_id=msg_id,
                sha256=content_hash,
                byte_size=byte_size,
                conversion_status="ERROR",
                warnings=warnings + [f"Output file collision: file already exists: {out_file.name}"],
                export_filename=export_fname,
                is_duplicate_hash=is_dup_hash,
                is_duplicate_message_id=is_dup_msg_id,
                source_archive=src_file.parent.name,
                source_message_identifier=src_file.name,
                auth_headers_present=auth_headers,
            )
            records.append(rec)
            stats["error_count"] += 1
            curr_index += 1
            continue

        status = "WARNING" if warnings else "SUCCESS"
        rec = ConversionRecord(
            sample_id=sample_id,
            source_dataset=source_dataset,
            source_category=source_category,
            assigned_label=assigned_label,
            source_file=src_file.name,
            message_id=msg_id,
            sha256=content_hash,
            byte_size=byte_size,
            conversion_status=status,
            warnings=warnings,
            export_filename=export_fname,
            is_duplicate_hash=is_dup_hash,
            is_duplicate_message_id=is_dup_msg_id,
            source_archive=src_file.parent.name,
            source_message_identifier=src_file.name,
            auth_headers_present=auth_headers,
        )
        records.append(rec)
        stats["converted_count"] += 1
        curr_index += 1

    return records, stats


# ── Development Dataset Builder & Inspector ───────────────────────────────────

def inspect_raw_datasets(raw_base_dir: str | Path) -> Dict[str, Any]:
    """
    Inspect the raw dataset directory to verify the presence of required source files:
    - SpamAssassin easy_ham directory or archive
    - SpamAssassin hard_ham directory or archive
    - Nazario legacy MBOX files (e.g. phishing0.mbox)
    """
    base = Path(raw_base_dir)
    findings: Dict[str, Any] = {
        "base_directory": str(base),
        "base_directory_exists": base.exists(),
        "sources": {},
        "all_present": False,
        "missing_items": [],
    }

    if not base.exists():
        findings["missing_items"].append(f"Base raw data directory not found: {base}")
        return findings

    # Check Nazario legacy mbox
    nazario_candidates = [
        base / "phishing0.mbox",
        base / "phishing0",
        base / "nazario" / "phishing0.mbox",
        base / "nazario" / "phishing0",
    ]
    found_nazario = [p for p in nazario_candidates if p.is_file()]
    if found_nazario:
        findings["sources"]["nazario_phishing0"] = {
            "status": "AVAILABLE",
            "path": str(found_nazario[0]),
            "size_bytes": found_nazario[0].stat().st_size,
        }
    else:
        findings["sources"]["nazario_phishing0"] = {
            "status": "MISSING",
            "expected_paths": [str(p) for p in nazario_candidates],
        }
        findings["missing_items"].append("Nazario legacy MBOX (phishing0.mbox)")

    # Check SpamAssassin easy_ham
    easy_ham_candidates = [
        base / "easy_ham",
        base / "spamassassin" / "easy_ham",
        base / "20030228_easy_ham" / "easy_ham",
    ]
    found_easy_ham = [p for p in easy_ham_candidates if p.is_dir()]
    if found_easy_ham:
        count = len([f for f in found_easy_ham[0].iterdir() if f.is_file()])
        findings["sources"]["spamassassin_easy_ham"] = {
            "status": "AVAILABLE",
            "path": str(found_easy_ham[0]),
            "file_count": count,
        }
    else:
        findings["sources"]["spamassassin_easy_ham"] = {
            "status": "MISSING",
            "expected_paths": [str(p) for p in easy_ham_candidates],
        }
        findings["missing_items"].append("SpamAssassin easy_ham directory")

    # Check SpamAssassin hard_ham
    hard_ham_candidates = [
        base / "hard_ham",
        base / "spamassassin" / "hard_ham",
        base / "20030228_hard_ham" / "hard_ham",
    ]
    found_hard_ham = [p for p in hard_ham_candidates if p.is_dir()]
    if found_hard_ham:
        count = len([f for f in found_hard_ham[0].iterdir() if f.is_file()])
        findings["sources"]["spamassassin_hard_ham"] = {
            "status": "AVAILABLE",
            "path": str(found_hard_ham[0]),
            "file_count": count,
        }
    else:
        findings["sources"]["spamassassin_hard_ham"] = {
            "status": "MISSING",
            "expected_paths": [str(p) for p in hard_ham_candidates],
        }
        findings["missing_items"].append("SpamAssassin hard_ham directory")

    findings["all_present"] = len(findings["missing_items"]) == 0
    return findings


# ── Command-Line Interface ────────────────────────────────────────────────────

def parse_cli_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Convert MBOX files to individual RFC822 .eml files with manifest tracking."
    )
    # Support both named and positional styles
    parser.add_argument(
        "--input", "-i",
        dest="input_mbox",
        type=str,
        default=None,
        help="Path to the input MBOX file."
    )
    parser.add_argument(
        "--output", "-o",
        dest="output_dir",
        type=str,
        default=None,
        help="Directory to output .eml files."
    )
    parser.add_argument(
        "--manifest", "-m",
        dest="manifest_path",
        type=str,
        default=None,
        help="Path to output manifest CSV file."
    )
    parser.add_argument(
        "--manifest-jsonl",
        dest="manifest_jsonl_path",
        type=str,
        default=None,
        help="Path to output manifest JSONL file."
    )
    parser.add_argument(
        "--summary", "-s",
        dest="summary_path",
        type=str,
        default=None,
        help="Path to output dataset summary JSON file."
    )
    parser.add_argument(
        "--source",
        dest="source_dataset",
        type=str,
        default="nazario_legacy",
        help="Source dataset name (default: 'nazario_legacy')."
    )
    parser.add_argument(
        "--category",
        dest="source_category",
        type=str,
        default="phishing",
        help="Original category name (default: 'phishing')."
    )
    parser.add_argument(
        "--label",
        dest="assigned_label",
        type=str,
        default="phishing",
        help="Assigned development label (default: 'phishing')."
    )
    parser.add_argument(
        "--prefix",
        dest="prefix",
        type=str,
        default="msg",
        help="Prefix for exported filenames (default: 'msg')."
    )
    parser.add_argument(
        "--id-prefix",
        dest="id_prefix",
        type=str,
        default="SAMPLE",
        help="Prefix for sample IDs in manifest (default: 'SAMPLE')."
    )
    parser.add_argument(
        "--limit",
        dest="limit",
        type=int,
        default=None,
        help="Maximum number of messages to convert."
    )
    parser.add_argument(
        "--seed",
        dest="seed",
        type=int,
        default=DEFAULT_RANDOM_SEED,
        help=f"Random seed for sampling (default: {DEFAULT_RANDOM_SEED})."
    )
    parser.add_argument(
        "--inspect-raw",
        dest="inspect_raw_dir",
        type=str,
        default=None,
        help="Inspect raw dataset directory and print availability status."
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        default=False,
        help="Overwrite existing output files if they exist (default: False, exclusive creation)."
    )
    parser.add_argument(
        "--unescape-from",
        action="store_true",
        default=False,
        help="Reversibly unescape MBOXRD '>From ' lines in email payloads (default: False)."
    )

    return parser.parse_args(args)


def main(cli_args: Optional[List[str]] = None) -> int:
    """CLI entrypoint."""
    args = parse_cli_args(cli_args)

    if args.inspect_raw_dir:
        findings = inspect_raw_datasets(args.inspect_raw_dir)
        print("Raw Dataset Inspection Results:")
        print(json.dumps(findings, indent=2))
        return 0 if findings["all_present"] else 1

    if not args.input_mbox or not args.output_dir:
        print("Error: --input and --output are required unless --inspect-raw is used.", file=sys.stderr)
        return 2

    try:
        records, stats = convert_mbox_to_eml(
            mbox_path=args.input_mbox,
            output_dir=args.output_dir,
            source_dataset=args.source_dataset,
            source_category=args.source_category,
            assigned_label=args.assigned_label,
            prefix=args.prefix,
            id_prefix=args.id_prefix,
            limit=args.limit,
            seed=args.seed,
            overwrite=args.overwrite,
            unescape_from=args.unescape_from,
        )

        print(f"Conversion complete: {stats['converted_count']} converted, {stats['error_count']} errors.")
        print(f"Duplicate hashes: {stats['duplicate_hash_count']}, Duplicate Message-IDs: {stats['duplicate_message_id_count']}")

        if args.manifest_path:
            write_manifest_csv(records, Path(args.manifest_path))
            print(f"Manifest CSV written to: {args.manifest_path}")

        if args.manifest_jsonl_path:
            write_manifest_jsonl(records, Path(args.manifest_jsonl_path))
            print(f"Manifest JSONL written to: {args.manifest_jsonl_path}")

        if args.summary_path:
            write_dataset_summary(records, Path(args.summary_path), extra_metadata={"source_stats": stats})
            print(f"Summary JSON written to: {args.summary_path}")

        return 0
    except Exception as exc:
        print(f"Conversion failed: {type(exc).__name__}: {str(exc)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
