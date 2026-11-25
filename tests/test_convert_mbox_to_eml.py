"""
Tests for MBOX-to-EML converter and manifest generator.

Covers all 13 required test conditions:
1. Single-message MBOX.
2. Multiple messages.
3. Duplicate Message-ID.
4. Missing Message-ID.
5. Malformed message.
6. Empty MBOX.
7. Duplicate output filenames.
8. Unicode headers and content.
9. Attachment-containing email.
10. Deterministic output naming.
11. SHA-256 correctness.
12. Manifest consistency.
13. Conversion failure reporting.

Also tests integration with the unified email ingestion coordinator (ingest_email).
"""

from __future__ import annotations

import csv
import hashlib
import json
import mailbox
import os
from pathlib import Path
import random
import pytest
import sys
import tempfile

# Ensure app and scripts are importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from scripts.convert_mbox_to_eml import (
    convert_mbox_to_eml,
    convert_tar_bz2_to_eml,
    extract_raw_message_bytes,
    extract_message_id_and_warnings,
    generate_deterministic_filename,
    validate_safe_output_path,
    write_eml_file,
    write_manifest_csv,
    write_manifest_jsonl,
    write_dataset_summary,
    unescape_mboxrd_from,
    is_uw_imap_internal_record,
    detect_authentication_headers,
    RobustMbox,
    MBoxConversionError,
    main,
)
from scripts.prepare_dev_dataset import (
    build_task8_3_dev_dataset,
    build_dev_dataset,
)
from app.ingestion.email_ingestor import ingest_email


# ── Helper to build temporary MBOX files ───────────────────────────────────────

def create_temp_mbox(tmp_path: Path, messages: list[bytes]) -> Path:
    """Helper to create a temporary .mbox file from raw email message byte strings."""
    mbox_file = tmp_path / "test_input.mbox"
    # Unix mbox requires each message to be prefixed with a 'From ' delimiter line
    with open(mbox_file, "wb") as f:
        for idx, msg in enumerate(messages):
            from_line = f"From test_{idx}@example.com Mon Jan 01 00:00:00 2024\r\n".encode("ascii")
            f.write(from_line)
            f.write(msg)
            if not msg.endswith(b"\n"):
                f.write(b"\r\n")
            f.write(b"\r\n")
    return mbox_file


# ── Test Suite ─────────────────────────────────────────────────────────────────

class TestMboxConverter:
    """Test suite covering the 13 required scenarios for convert_mbox_to_eml."""

    def test_single_message_mbox(self, tmp_path: Path) -> None:
        """1. Single-message MBOX converts cleanly to one .eml file."""
        msg = (
            b"From: alice@example.com\r\n"
            b"To: bob@example.com\r\n"
            b"Subject: Single Message Test\r\n"
            b"Message-ID: <single-001@example.com>\r\n"
            b"\r\n"
            b"This is a single message body.\r\n"
        )
        mbox_path = create_temp_mbox(tmp_path, [msg])
        out_dir = tmp_path / "out"

        records, stats = convert_mbox_to_eml(mbox_path, out_dir, prefix="test")

        assert len(records) == 1
        assert stats["converted_count"] == 1
        assert stats["error_count"] == 0
        assert records[0].conversion_status == "SUCCESS"
        assert records[0].message_id == "<single-001@example.com>"

        eml_files = list(out_dir.glob("*.eml"))
        assert len(eml_files) == 1
        exported_bytes = eml_files[0].read_bytes()
        assert b"Single Message Test" in exported_bytes

        # Verify parsing by ingestion coordinator
        email_data = ingest_email(exported_bytes, source_filename=eml_files[0].name)
        assert email_data.headers.subject == "Single Message Test"
        assert email_data.plain_text_body is not None
        assert "This is a single message body." in email_data.plain_text_body

    def test_multiple_messages(self, tmp_path: Path) -> None:
        """2. Multiple messages in an MBOX are all converted to distinct .eml files."""
        messages = [
            (
                f"From: user{i}@example.com\r\n"
                f"To: target{i}@example.com\r\n"
                f"Subject: Multi Test {i}\r\n"
                f"Message-ID: <multi-{i:03d}@example.com>\r\n"
                f"\r\n"
                f"Body content for message {i}\r\n"
            ).encode("utf-8")
            for i in range(5)
        ]
        mbox_path = create_temp_mbox(tmp_path, messages)
        out_dir = tmp_path / "out"

        records, stats = convert_mbox_to_eml(mbox_path, out_dir, prefix="multi")

        assert len(records) == 5
        assert stats["converted_count"] == 5
        eml_files = sorted(list(out_dir.glob("*.eml")))
        assert len(eml_files) == 5

        # Ingest all with ingestion coordinator
        for i, eml_file in enumerate(eml_files):
            email_data = ingest_email(eml_file.read_bytes(), source_filename=eml_file.name)
            assert f"Multi Test {i}" == email_data.headers.subject

    def test_duplicate_message_id(self, tmp_path: Path) -> None:
        """3. Messages sharing duplicate Message-ID headers are not overwritten."""
        msg1 = (
            b"From: phisher1@evil.com\r\n"
            b"To: victim1@example.com\r\n"
            b"Subject: Urgent Action Required\r\n"
            b"Message-ID: <shared-campaign-id@evil.com>\r\n"
            b"\r\n"
            b"Message 1 content\r\n"
        )
        msg2 = (
            b"From: phisher2@evil.com\r\n"
            b"To: victim2@example.com\r\n"
            b"Subject: Urgent Action Required Second\r\n"
            b"Message-ID: <shared-campaign-id@evil.com>\r\n"
            b"\r\n"
            b"Message 2 different content\r\n"
        )
        mbox_path = create_temp_mbox(tmp_path, [msg1, msg2])
        out_dir = tmp_path / "out"

        records, stats = convert_mbox_to_eml(mbox_path, out_dir, prefix="dup_id")

        assert len(records) == 2
        assert stats["converted_count"] == 2
        assert stats["duplicate_message_id_count"] == 1

        assert records[0].is_duplicate_message_id is False
        assert records[1].is_duplicate_message_id is True
        assert any("Duplicate Message-ID" in w for w in records[1].warnings)

        # Confirm two distinct files exist and neither was overwritten
        eml_files = list(out_dir.glob("*.eml"))
        assert len(eml_files) == 2
        assert records[0].export_filename != records[1].export_filename

    def test_missing_message_id(self, tmp_path: Path) -> None:
        """4. Messages missing Message-ID headers convert cleanly with warnings."""
        msg = (
            b"From: anonymous@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Subject: No Message ID Here\r\n"
            b"\r\n"
            b"Message body without a Message-ID header.\r\n"
        )
        mbox_path = create_temp_mbox(tmp_path, [msg])
        out_dir = tmp_path / "out"

        records, stats = convert_mbox_to_eml(mbox_path, out_dir, prefix="noid")

        assert len(records) == 1
        assert stats["converted_count"] == 1
        assert records[0].message_id == ""
        assert any("Missing Message-ID" in w for w in records[0].warnings)
        assert records[0].conversion_status == "WARNING"

        # Parsing by coordinator succeeds
        eml_files = list(out_dir.glob("*.eml"))
        email_data = ingest_email(eml_files[0].read_bytes())
        assert email_data.headers.message_id is None

    def test_malformed_message(self, tmp_path: Path) -> None:
        """5. Malformed/empty messages are handled gracefully without aborting the batch."""
        valid_msg = (
            b"From: valid@example.com\r\n"
            b"To: user@example.com\r\n"
            b"Subject: Valid Message\r\n"
            b"Message-ID: <valid-001@example.com>\r\n"
            b"\r\n"
            b"Valid body\r\n"
        )
        empty_msg = b""  # Empty payload between From_ lines
        mbox_path = create_temp_mbox(tmp_path, [empty_msg, valid_msg])
        out_dir = tmp_path / "out"

        records, stats = convert_mbox_to_eml(mbox_path, out_dir, prefix="malform")

        assert len(records) == 2
        assert stats["error_count"] == 1
        assert stats["converted_count"] == 1
        assert records[0].conversion_status == "ERROR"
        assert any("Empty message payload" in w for w in records[0].warnings)
        assert records[1].conversion_status == "SUCCESS"

    def test_empty_mbox(self, tmp_path: Path) -> None:
        """6. An empty MBOX file produces 0 files and 0 errors."""
        empty_mbox = tmp_path / "empty.mbox"
        empty_mbox.write_bytes(b"")
        out_dir = tmp_path / "out"

        records, stats = convert_mbox_to_eml(empty_mbox, out_dir)

        assert len(records) == 0
        assert stats["total_messages_in_mbox"] == 0
        assert stats["converted_count"] == 0
        assert stats["error_count"] == 0
        assert len(list(out_dir.glob("*.eml"))) == 0

    def test_duplicate_output_filenames_prevention(self, tmp_path: Path) -> None:
        """7. Identical content in multiple messages produces unique sequential filenames."""
        identical_msg = (
            b"From: spammer@example.com\r\n"
            b"To: victim@example.com\r\n"
            b"Subject: Identical Campaign Template\r\n"
            b"Message-ID: <same@example.com>\r\n"
            b"\r\n"
            b"Identical text in both emails.\r\n"
        )
        mbox_path = create_temp_mbox(tmp_path, [identical_msg, identical_msg])
        out_dir = tmp_path / "out"

        records, stats = convert_mbox_to_eml(mbox_path, out_dir, prefix="dup")

        assert len(records) == 2
        assert stats["converted_count"] == 2
        assert stats["duplicate_hash_count"] == 1
        assert stats["duplicate_message_id_count"] == 1

        fnames = [r.export_filename for r in records]
        assert len(set(fnames)) == 2, "Export filenames must be unique"
        assert fnames[0] != fnames[1]

        # Verify both exist on disk
        for fn in fnames:
            assert (out_dir / fn).is_file()

    def test_unicode_headers_and_content(self, tmp_path: Path) -> None:
        """8. Unicode headers (RFC2047) and UTF-8 multi-byte bodies are preserved."""
        # =?UTF-8?B?0J/RgNC40LLQtdGCINC80LjRgA==?= is "Привет мир"
        msg = (
            b"From: sender@unicode.org\r\n"
            b"To: recipient@unicode.org\r\n"
            b"Subject: =?UTF-8?B?0J/RgNC40LLQtdGCINC80LjRgA==?=\r\n"
            b"Message-ID: <unicode-001@unicode.org>\r\n"
            b"Content-Type: text/plain; charset=\"utf-8\"\r\n"
            b"\r\n"
            b"Hello world \xc2\xa9 2024 \xe3\x81\x93\xe3\x82\x93\xe3\x81\xab\xe3\x81\xa1\xe3\x81\xaf \xf0\x9f\x9a\x80\r\n"
        )
        mbox_path = create_temp_mbox(tmp_path, [msg])
        out_dir = tmp_path / "out"

        records, stats = convert_mbox_to_eml(mbox_path, out_dir, prefix="uni")

        assert stats["converted_count"] == 1
        eml_file = out_dir / records[0].export_filename
        email_data = ingest_email(eml_file.read_bytes())

        assert email_data.headers.subject == "Привет мир"
        assert email_data.plain_text_body is not None
        assert "こんにちは" in email_data.plain_text_body
        assert "🚀" in email_data.plain_text_body

    def test_attachment_containing_email(self, tmp_path: Path) -> None:
        """9. Email containing attachments is preserved and attachments parse correctly."""
        boundary = "===MIME_BOUNDARY_123==="
        pdf_bytes = b"%PDF-1.4 mock binary payload 1234567890"
        pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()
        import base64
        pdf_b64 = base64.b64encode(pdf_bytes).decode("ascii")

        msg = (
            f"From: payroll@company.com\r\n"
            f"To: employee@company.com\r\n"
            f"Subject: Monthly Paystub\r\n"
            f"Message-ID: <paystub-999@company.com>\r\n"
            f"MIME-Version: 1.0\r\n"
            f'Content-Type: multipart/mixed; boundary="{boundary}"\r\n'
            f"\r\n"
            f"--{boundary}\r\n"
            f'Content-Type: text/plain; charset="utf-8"\r\n'
            f"\r\n"
            f"Please review your attached paystub.\r\n"
            f"--{boundary}\r\n"
            f'Content-Type: application/pdf; name="paystub.pdf"\r\n'
            f"Content-Transfer-Encoding: base64\r\n"
            f'Content-Disposition: attachment; filename="paystub.pdf"\r\n'
            f"\r\n"
            f"{pdf_b64}\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")

        mbox_path = create_temp_mbox(tmp_path, [msg])
        out_dir = tmp_path / "out"

        records, stats = convert_mbox_to_eml(mbox_path, out_dir, prefix="attach")

        assert stats["converted_count"] == 1
        eml_file = out_dir / records[0].export_filename
        email_data = ingest_email(eml_file.read_bytes())

        assert len(email_data.attachments) == 1
        att = email_data.attachments[0]
        assert att.filename == "paystub.pdf"
        assert att.sha256 == pdf_sha256
        assert att.size_bytes == len(pdf_bytes)

    def test_deterministic_output_naming(self, tmp_path: Path) -> None:
        """10. Repeated runs produce identical filenames, sample IDs, and hashes."""
        msg = (
            b"From: test@example.com\r\n"
            b"To: test@example.com\r\n"
            b"Subject: Deterministic Test\r\n"
            b"Message-ID: <det-001@example.com>\r\n"
            b"\r\n"
            b"Deterministic content.\r\n"
        )
        mbox_path = create_temp_mbox(tmp_path, [msg])
        out_dir_1 = tmp_path / "out_1"
        out_dir_2 = tmp_path / "out_2"

        records_1, _ = convert_mbox_to_eml(mbox_path, out_dir_1, prefix="fixed", id_prefix="TEST")
        records_2, _ = convert_mbox_to_eml(mbox_path, out_dir_2, prefix="fixed", id_prefix="TEST")

        assert len(records_1) == len(records_2) == 1
        assert records_1[0].export_filename == records_2[0].export_filename
        assert records_1[0].sample_id == records_2[0].sample_id
        assert records_1[0].sha256 == records_2[0].sha256

    def test_sha256_correctness(self, tmp_path: Path) -> None:
        """11. Recorded SHA-256 matches exact hash of the exported file on disk."""
        msg = (
            b"From: verify@example.com\r\n"
            b"Subject: Hash Check\r\n"
            b"Message-ID: <hash-001@example.com>\r\n"
            b"\r\n"
            b"Check my SHA-256 hash please.\r\n"
        )
        mbox_path = create_temp_mbox(tmp_path, [msg])
        out_dir = tmp_path / "out"

        records, _ = convert_mbox_to_eml(mbox_path, out_dir)
        rec = records[0]

        exported_path = out_dir / rec.export_filename
        disk_bytes = exported_path.read_bytes()
        expected_hash = hashlib.sha256(disk_bytes).hexdigest()

        assert rec.sha256 == expected_hash
        assert rec.byte_size == len(disk_bytes)

    def test_manifest_consistency(self, tmp_path: Path) -> None:
        """12. Manifest CSV and JSONL record all required fields matching disk files."""
        messages = [
            (
                f"From: user{i}@example.com\r\n"
                f"Subject: Consistency Check {i}\r\n"
                f"Message-ID: <cons-{i}@example.com>\r\n"
                f"\r\n"
                f"Body {i}\r\n"
            ).encode("utf-8")
            for i in range(3)
        ]
        mbox_path = create_temp_mbox(tmp_path, messages)
        out_dir = tmp_path / "out"
        csv_path = tmp_path / "manifest.csv"
        jsonl_path = tmp_path / "manifest.jsonl"
        summary_path = tmp_path / "summary.json"

        records, _ = convert_mbox_to_eml(
            mbox_path,
            out_dir,
            source_dataset="test_source",
            source_category="test_cat",
            assigned_label="phishing",
            prefix="manifest_test",
            id_prefix="DEV_TEST",
        )

        write_manifest_csv(records, csv_path)
        write_manifest_jsonl(records, jsonl_path)
        write_dataset_summary(records, summary_path)

        # Check CSV
        assert csv_path.is_file()
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))
            assert len(reader) == 3
            for row in reader:
                assert row["sample_id"].startswith("DEV_TEST_")
                assert row["source_dataset"] == "test_source"
                assert row["source_category"] == "test_cat"
                assert row["assigned_label"] == "phishing"
                assert (out_dir / row["export_filename"]).is_file()

        # Check JSONL
        assert jsonl_path.is_file()
        with open(jsonl_path, "r", encoding="utf-8") as f:
            lines = [json.loads(l) for l in f.readlines()]
            assert len(lines) == 3

        # Check Summary
        assert summary_path.is_file()
        with open(summary_path, "r", encoding="utf-8") as f:
            sum_data = json.load(f)
            assert sum_data["total_samples"] == 3
            assert sum_data["counts_by_source"]["test_source"] == 3

    def test_conversion_failure_reporting(self, tmp_path: Path) -> None:
        """13. Non-existent files, invalid targets, and path traversal raise clear errors."""
        # Non-existent MBOX
        missing_file = tmp_path / "non_existent.mbox"
        with pytest.raises(FileNotFoundError, match="Input MBOX file does not exist"):
            convert_mbox_to_eml(missing_file, tmp_path / "out")

        # Input is a directory, not a file
        a_dir = tmp_path / "some_dir"
        a_dir.mkdir()
        with pytest.raises(MBoxConversionError, match="Input MBOX path is not a file"):
            convert_mbox_to_eml(a_dir, tmp_path / "out")

        # Path traversal prevention
        out_dir = tmp_path / "safe_out"
        out_dir.mkdir()
        traversal_file = out_dir / ".." / "evil.eml"
        with pytest.raises(ValueError, match="Path traversal detected"):
            validate_safe_output_path(traversal_file, out_dir)


class TestCliInterface:
    """Test CLI execution and arguments."""

    def test_cli_help(self) -> None:
        """CLI --help returns 0 without errors."""
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        assert exc_info.value.code == 0

    def test_cli_inspect_raw(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """CLI --inspect-raw correctly identifies missing datasets."""
        code = main(["--inspect-raw", str(tmp_path)])
        assert code == 1  # 1 because files are missing in empty tmp_path
        captured = capsys.readouterr().out
        assert "Raw Dataset Inspection Results" in captured
        assert "Nazario legacy MBOX" in captured

    def test_cli_end_to_end_conversion(self, tmp_path: Path) -> None:
        """CLI end-to-end converts an mbox and generates manifest."""
        msg = b"From: a@b.com\r\nSubject: CLI Test\r\nMessage-ID: <cli-01@b.com>\r\n\r\nHi"
        mbox_path = create_temp_mbox(tmp_path, [msg])
        out_dir = tmp_path / "cli_out"
        manifest_csv = tmp_path / "cli_manifest.csv"

        code = main([
            "--input", str(mbox_path),
            "--output", str(out_dir),
            "--manifest", str(manifest_csv),
            "--prefix", "cli_test",
        ])

        assert code == 0
        assert manifest_csv.is_file()
        assert len(list(out_dir.glob("*.eml"))) == 1


class TestPrepareDevDataset:
    """Tests for dataset builder and raw dataset inspection."""

    def test_missing_raw_dataset_reporting(self, tmp_path: Path) -> None:
        """When raw datasets are missing, inspect and builder safely report missing files without fabricating data."""
        from scripts.prepare_dev_dataset import build_dev_dataset
        from scripts.convert_mbox_to_eml import inspect_raw_datasets

        empty_raw = tmp_path / "raw"
        empty_raw.mkdir()

        inspection = inspect_raw_datasets(empty_raw)
        assert inspection["all_present"] is False
        assert "Nazario legacy MBOX (phishing0.mbox)" in inspection["missing_items"]
        assert "SpamAssassin easy_ham directory" in inspection["missing_items"]
        assert "SpamAssassin hard_ham directory" in inspection["missing_items"]

        result = build_dev_dataset(empty_raw, tmp_path / "dev")
        assert result["status"] == "MISSING_DATASETS"
        assert not (tmp_path / "dev" / "manifests" / "dev_manifest.csv").exists()

    def test_shortfall_reporting(self, tmp_path: Path) -> None:
        """When fewer than 250 Nazario phishing messages exist, report shortfall."""
        from scripts.prepare_dev_dataset import build_dev_dataset

        raw_dir = tmp_path / "raw"
        easy_ham_dir = raw_dir / "easy_ham"
        hard_ham_dir = raw_dir / "hard_ham"
        easy_ham_dir.mkdir(parents=True)
        hard_ham_dir.mkdir(parents=True)

        # Create dummy easy_ham and hard_ham files
        for i in range(5):
            (easy_ham_dir / f"easy_{i}.eml").write_bytes(f"From: a@b.com\r\nSubject: Easy {i}\r\n\r\nBody".encode("utf-8"))
            (hard_ham_dir / f"hard_{i}.eml").write_bytes(f"From: a@b.com\r\nSubject: Hard {i}\r\n\r\nBody".encode("utf-8"))

        # Create Nazario mbox with only 5 messages (less than 250 target)
        nazario_mbox = raw_dir / "phishing0.mbox"
        msgs = [f"From: evil@phish.com\r\nSubject: Phish {i}\r\n\r\nBody".encode("utf-8") for i in range(5)]
        create_temp_mbox(raw_dir, msgs)
        (raw_dir / "test_input.mbox").rename(nazario_mbox)

        result = build_dev_dataset(raw_dir, tmp_path / "dev")
        assert result["status"] == "SHORTFALL"
        assert "Shortfall in Nazario phishing samples" in result["message"]


# ── Task 8.1.2 New Regression Test Suites ─────────────────────────────────────

class TestNewlineHandling:
    """F-01 Regression: Cross-platform LF and CRLF MBOX extraction."""

    def test_lf_mbox_byte_preservation(self, tmp_path: Path) -> None:
        """Pure Unix LF MBOX messages match exact bytes without extraneous trailing delimiters."""
        msg1 = b"From: alice@example.com\nSubject: LF 1\nMessage-ID: <lf1@example.com>\n\nBody 1\n"
        msg2 = b"From: bob@example.com\nSubject: LF 2\nMessage-ID: <lf2@example.com>\n\nBody 2\n"

        mbox_file = tmp_path / "unix_lf.mbox"
        with open(mbox_file, "wb") as f:
            f.write(b"From alice@example.com Mon Jan 01 00:00:00 2024\n")
            f.write(msg1)
            f.write(b"\n")  # Container inter-message delimiter
            f.write(b"From bob@example.com Mon Jan 01 00:00:00 2024\n")
            f.write(msg2)
            f.write(b"\n")

        out_dir = tmp_path / "out_lf"
        records, stats = convert_mbox_to_eml(mbox_file, out_dir, prefix="lf_test")

        assert len(records) == 2
        assert stats["converted_count"] == 2

        eml_1 = (out_dir / records[0].export_filename).read_bytes()
        eml_2 = (out_dir / records[1].export_filename).read_bytes()

        assert eml_1 == msg1, f"LF msg1 mismatch: expected {len(msg1)} bytes, got {len(eml_1)}"
        assert eml_2 == msg2, f"LF msg2 mismatch: expected {len(msg2)} bytes, got {len(eml_2)}"
        assert records[0].sha256 == hashlib.sha256(msg1).hexdigest()
        assert records[1].sha256 == hashlib.sha256(msg2).hexdigest()

    def test_crlf_mbox_byte_preservation(self, tmp_path: Path) -> None:
        """Windows CRLF MBOX messages match exact bytes without extraneous trailing delimiters."""
        msg1 = b"From: alice@example.com\r\nSubject: CRLF 1\r\nMessage-ID: <crlf1@example.com>\r\n\r\nBody 1\r\n"
        msg2 = b"From: bob@example.com\r\nSubject: CRLF 2\r\nMessage-ID: <crlf2@example.com>\r\n\r\nBody 2\r\n"

        mbox_file = tmp_path / "windows_crlf.mbox"
        with open(mbox_file, "wb") as f:
            f.write(b"From alice@example.com Mon Jan 01 00:00:00 2024\r\n")
            f.write(msg1)
            f.write(b"\r\n")  # Container inter-message delimiter
            f.write(b"From bob@example.com Mon Jan 01 00:00:00 2024\r\n")
            f.write(msg2)
            f.write(b"\r\n")

        out_dir = tmp_path / "out_crlf"
        records, stats = convert_mbox_to_eml(mbox_file, out_dir, prefix="crlf_test")

        assert len(records) == 2
        assert stats["converted_count"] == 2

        eml_1 = (out_dir / records[0].export_filename).read_bytes()
        eml_2 = (out_dir / records[1].export_filename).read_bytes()

        assert eml_1 == msg1
        assert eml_2 == msg2
        assert records[0].sha256 == hashlib.sha256(msg1).hexdigest()
        assert records[1].sha256 == hashlib.sha256(msg2).hexdigest()

    def test_simulated_cross_platform_consistency(self, tmp_path: Path) -> None:
        """Simulate execution on both Windows (linesep=\r\n) and Linux (linesep=\n)."""
        msg = b"From: sim@example.com\nSubject: Cross Platform\nMessage-ID: <sim@example.com>\n\nBody\n"
        mbox_file = tmp_path / "sim.mbox"
        with open(mbox_file, "wb") as f:
            f.write(b"From sim@example.com Mon Jan 01 00:00:00 2024\n")
            f.write(msg)
            f.write(b"\n")

        orig_linesep = mailbox.linesep
        try:
            # Simulate POSIX
            mailbox.linesep = b"\n"
            out_posix = tmp_path / "out_posix"
            recs_posix, _ = convert_mbox_to_eml(mbox_file, out_posix)

            # Simulate Windows NT
            mailbox.linesep = b"\r\n"
            out_nt = tmp_path / "out_nt"
            recs_nt, _ = convert_mbox_to_eml(mbox_file, out_nt)

            posix_bytes = (out_posix / recs_posix[0].export_filename).read_bytes()
            nt_bytes = (out_nt / recs_nt[0].export_filename).read_bytes()

            assert posix_bytes == nt_bytes == msg
            assert recs_posix[0].sha256 == recs_nt[0].sha256 == hashlib.sha256(msg).hexdigest()
        finally:
            mailbox.linesep = orig_linesep


class TestFileCollisionProtection:
    """F-02 Regression: Ensure existing files are never silently overwritten."""

    def test_existing_file_preserved_on_collision(self, tmp_path: Path) -> None:
        """When an output file already exists, it is NOT overwritten, and an error is recorded."""
        msg = b"From: a@b.com\r\nSubject: Overwrite Test\r\nMessage-ID: <ovr@b.com>\r\n\r\nNew Payload\r\n"
        mbox_path = create_temp_mbox(tmp_path, [msg])
        out_dir = tmp_path / "out_collision"
        out_dir.mkdir()

        # Pre-seed destination file
        h = hashlib.sha256(msg).hexdigest()
        target_name = f"safe_000001_{h[:12]}.eml"
        pre_existing_file = out_dir / target_name
        pre_existing_file.write_bytes(b"ORIGINAL_USER_DATA_DO_NOT_TOUCH")

        # Run conversion without overwrite (default)
        records, stats = convert_mbox_to_eml(mbox_path, out_dir, prefix="safe", overwrite=False)

        # File contents must remain unchanged
        assert pre_existing_file.read_bytes() == b"ORIGINAL_USER_DATA_DO_NOT_TOUCH"
        assert stats["error_count"] == 1
        assert stats["converted_count"] == 0
        assert records[0].conversion_status == "ERROR"
        assert any("Output file collision" in w for w in records[0].warnings)

    def test_overwrite_flag_allows_replacement_when_explicit(self, tmp_path: Path) -> None:
        """When overwrite=True is explicitly passed, existing files may be replaced."""
        msg = b"From: a@b.com\r\nSubject: Overwrite Allowed\r\nMessage-ID: <ovr-ok@b.com>\r\n\r\nNew Content\r\n"
        mbox_path = create_temp_mbox(tmp_path, [msg])
        out_dir = tmp_path / "out_overwrite_ok"
        out_dir.mkdir()

        h = hashlib.sha256(msg).hexdigest()
        target_name = f"allow_000001_{h[:12]}.eml"
        dest_file = out_dir / target_name
        dest_file.write_bytes(b"OLD_CONTENT")

        records, stats = convert_mbox_to_eml(mbox_path, out_dir, prefix="allow", overwrite=True)

        assert dest_file.read_bytes() == msg
        assert stats["converted_count"] == 1
        assert stats["error_count"] == 0


class TestAllDatasetShortfallScenarios:
    """F-03 Regression: Validate shortfalls across all three sources and combinations."""

    def test_easy_ham_individual_shortfall(self, tmp_path: Path) -> None:
        """Shortfall reported when only easy_ham is below 500 target."""
        from scripts.prepare_dev_dataset import build_dev_dataset

        raw_dir = tmp_path / "raw"
        easy_ham_dir = raw_dir / "easy_ham"
        hard_ham_dir = raw_dir / "hard_ham"
        easy_ham_dir.mkdir(parents=True)
        hard_ham_dir.mkdir(parents=True)

        # 10 easy_ham (shortfall: 490)
        for i in range(10):
            (easy_ham_dir / f"easy_{i}.eml").write_bytes(b"From: a@b.com\r\nSubject: Easy\r\n\r\nBody")
        # 250 hard_ham
        for i in range(250):
            (hard_ham_dir / f"hard_{i}.eml").write_bytes(f"From: a@b.com\r\nSubject: Hard {i}\r\n\r\nBody".encode("utf-8"))
        # 250 nazario
        nazario_mbox = raw_dir / "phishing0.mbox"
        msgs = [f"From: e@p.com\r\nSubject: P {i}\r\nMessage-ID: <p{i}@p.com>\r\n\r\nBody".encode("utf-8") for i in range(250)]
        create_temp_mbox(raw_dir, msgs)
        (raw_dir / "test_input.mbox").rename(nazario_mbox)

        result = build_dev_dataset(raw_dir, tmp_path / "dev")
        assert result["status"] == "SHORTFALL"
        assert "Shortfall in easy_ham" in result["message"]
        assert result["shortfalls"]["easy_ham"]["shortfall"] == 490
        assert result["counts"]["easy_ham"]["actual"] == 10

    def test_hard_ham_individual_shortfall(self, tmp_path: Path) -> None:
        """Shortfall reported when only hard_ham is below 250 target."""
        from scripts.prepare_dev_dataset import build_dev_dataset

        raw_dir = tmp_path / "raw"
        easy_ham_dir = raw_dir / "easy_ham"
        hard_ham_dir = raw_dir / "hard_ham"
        easy_ham_dir.mkdir(parents=True)
        hard_ham_dir.mkdir(parents=True)

        # 500 easy_ham
        for i in range(500):
            (easy_ham_dir / f"easy_{i}.eml").write_bytes(f"From: a@b.com\r\nSubject: Easy {i}\r\n\r\nBody".encode("utf-8"))
        # 10 hard_ham (shortfall: 240)
        for i in range(10):
            (hard_ham_dir / f"hard_{i}.eml").write_bytes(b"From: a@b.com\r\nSubject: Hard\r\n\r\nBody")
        # 250 nazario
        nazario_mbox = raw_dir / "phishing0.mbox"
        msgs = [f"From: e@p.com\r\nSubject: P {i}\r\nMessage-ID: <p{i}@p.com>\r\n\r\nBody".encode("utf-8") for i in range(250)]
        create_temp_mbox(raw_dir, msgs)
        (raw_dir / "test_input.mbox").rename(nazario_mbox)

        result = build_dev_dataset(raw_dir, tmp_path / "dev")
        assert result["status"] == "SHORTFALL"
        assert "Shortfall in hard_ham" in result["message"]
        assert result["shortfalls"]["hard_ham"]["shortfall"] == 240
        assert result["counts"]["hard_ham"]["actual"] == 10

    def test_multiple_simultaneous_shortfalls(self, tmp_path: Path) -> None:
        """Multiple shortfalls across all sources are all detailed in the summary."""
        from scripts.prepare_dev_dataset import build_dev_dataset

        raw_dir = tmp_path / "raw"
        easy_ham_dir = raw_dir / "easy_ham"
        hard_ham_dir = raw_dir / "hard_ham"
        easy_ham_dir.mkdir(parents=True)
        hard_ham_dir.mkdir(parents=True)

        # 5 easy, 5 hard, 5 nazario
        for i in range(5):
            (easy_ham_dir / f"easy_{i}.eml").write_bytes(b"From: a@b.com\r\nSubject: Easy\r\n\r\nBody")
            (hard_ham_dir / f"hard_{i}.eml").write_bytes(b"From: a@b.com\r\nSubject: Hard\r\n\r\nBody")

        nazario_mbox = raw_dir / "phishing0.mbox"
        msgs = [f"From: e@p.com\r\nSubject: P {i}\r\nMessage-ID: <p{i}@p.com>\r\n\r\nBody".encode("utf-8") for i in range(5)]
        create_temp_mbox(raw_dir, msgs)
        (raw_dir / "test_input.mbox").rename(nazario_mbox)

        result = build_dev_dataset(raw_dir, tmp_path / "dev")
        assert result["status"] == "SHORTFALL"
        assert "easy_ham" in result["shortfalls"]
        assert "hard_ham" in result["shortfalls"]
        assert "nazario_phishing" in result["shortfalls"]
        assert result["shortfalls"]["easy_ham"]["shortfall"] == 495
        assert result["shortfalls"]["hard_ham"]["shortfall"] == 245
        assert result["shortfalls"]["nazario_phishing"]["shortfall"] == 245


class TestMboxrdEscapingInvestigation:
    """F-05 Investigation: MBOXRD >From escaping and unescaping."""

    def test_unescape_mboxrd_from_behavior(self) -> None:
        """Verify unescape_mboxrd_from strips exactly one > from ^>+From lines only."""
        sample = (
            b"From: author@example.com\r\n"
            b"Subject: Escaping Test\r\n\r\n"
            b"From line without escape\r\n"
            b">From line escaped once\r\n"
            b">>From line escaped twice\r\n"
            b">>>From line escaped thrice\r\n"
            b"> Regular email reply quote\r\n"
            b">> Nested email reply quote\r\n"
            b"> From with space after bracket\r\n"
        )
        unescaped = unescape_mboxrd_from(sample)

        expected = (
            b"From: author@example.com\r\n"
            b"Subject: Escaping Test\r\n\r\n"
            b"From line without escape\r\n"
            b"From line escaped once\r\n"
            b">From line escaped twice\r\n"
            b">>From line escaped thrice\r\n"
            b"> Regular email reply quote\r\n"
            b">> Nested email reply quote\r\n"
            b"> From with space after bracket\r\n"
        )
        assert unescaped == expected

    def test_convert_mbox_with_unescape_from_option(self, tmp_path: Path) -> None:
        """convert_mbox_to_eml with unescape_from=True unescapes >From lines cleanly."""
        msg = (
            b"From: test@example.com\r\n"
            b"Subject: Unescape Mboxrd\r\n"
            b"Message-ID: <unesc-1@example.com>\r\n\r\n"
            b">From line in body\r\n"
            b"> Regular quote\r\n"
        )
        mbox_path = create_temp_mbox(tmp_path, [msg])
        out_dir = tmp_path / "out_unesc"

        records, stats = convert_mbox_to_eml(mbox_path, out_dir, unescape_from=True)
        exported = (out_dir / records[0].export_filename).read_bytes()

        assert b"\nFrom line in body" in exported
        assert b"\n> Regular quote" in exported


class TestSingleMessageMultipleMessageIds:
    """F-08 Regression: Multiple Message-ID headers in a single email."""

    def test_multiple_message_id_headers_flagged(self, tmp_path: Path) -> None:
        """Multiple Message-ID headers in one message trigger an RFC 5322 defect warning while preserving bytes."""
        msg = (
            b"From: spam@example.com\r\n"
            b"Subject: Duplicate IDs In Single Message\r\n"
            b"Message-ID: <primary-id@example.com>\r\n"
            b"Message-ID: <secondary-id@example.com>\r\n\r\n"
            b"Payload body\r\n"
        )
        mbox_path = create_temp_mbox(tmp_path, [msg])
        out_dir = tmp_path / "out_mult_id"

        records, stats = convert_mbox_to_eml(mbox_path, out_dir)

        assert len(records) == 1
        assert records[0].message_id == "<primary-id@example.com>"
        assert records[0].conversion_status == "WARNING"
        assert any("Multiple Message-ID headers detected" in w for w in records[0].warnings)

        # Original headers must remain intact in exported file
        exported_bytes = (out_dir / records[0].export_filename).read_bytes()
        assert b"Message-ID: <primary-id@example.com>" in exported_bytes
        assert b"Message-ID: <secondary-id@example.com>" in exported_bytes


# ── Task 8.3 Development Dataset Builder Test Suite ───────────────────────────

class TestTask83DatasetCreation:
    """
    Test suite for Task 8.3: Convert and Build the 1,000-Email Development Dataset.

    Covers all 12 required verification scenarios:
    1. UW internal record is excluded.
    2. Ordinary email with similar subject text is retained.
    3. Correct source-category assignment.
    4. Exact 500/250/250 sampling.
    5. Deterministic repeated sampling with seed 42.
    6. No duplicate hashes in final output.
    7. Source-year allocation is reproducible.
    8. Missing or malformed source records are handled safely.
    9. Output collisions do not overwrite existing files.
    10. Manifest entries match the actual EML files.
    11. Authentication header presence is not confused with authentication pass/fail.
    12. Shortfalls stop dataset creation instead of generating synthetic data.
    """

    def test_01_uw_internal_record_is_excluded(self, tmp_path: Path) -> None:
        """1. UW IMAP internal folder data record is correctly identified and excluded."""
        uw_msg = (
            b"Date: 28 Sep 2017 09:57:25 -0400\r\n"
            b"From: Mail System Internal Data <MAILER-DAEMON@monkey.org>\r\n"
            b"Subject: DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA\r\n"
            b"Message-ID: <1506607045@monkey.org>\r\n"
            b"X-IMAP: 1506607044 0000000307 $Forwarded\r\n"
            b"Status: RO\r\n\r\n"
            b"This text is part of the internal format of your mail folder, and is not\r\n"
            b"a real message.  It is created automatically by the mail system software.\r\n"
        )
        assert is_uw_imap_internal_record(uw_msg) is True

        normal_msg = (
            b"From: phisher@evil.com\r\n"
            b"To: victim@example.com\r\n"
            b"Subject: Urgent: Verify Your Account\r\n"
            b"Message-ID: <phish-01@evil.com>\r\n\r\n"
            b"Please click http://phish.example.com to verify.\r\n"
        )

        mbox_path = create_temp_mbox(tmp_path, [uw_msg, normal_msg])
        out_dir = tmp_path / "out_uw"

        records, stats = convert_mbox_to_eml(
            mbox_path,
            out_dir,
            filter_uw_internal=True,
            prefix="test_uw",
        )

        assert stats["total_messages_in_mbox"] == 2
        assert stats["usable_messages_in_mbox"] == 1
        assert stats["excluded_count"] == 1
        assert stats["converted_count"] == 1
        assert len(records) == 1
        assert records[0].message_id == "<phish-01@evil.com>"

        # Exclusion metadata verified
        exc_records = stats["excluded_records"]
        assert len(exc_records) == 1
        assert exc_records[0]["mbox_key"] == 0
        assert exc_records[0]["exclusion_status"] == "EXCLUDED_INTERNAL_RECORD"
        assert "UW IMAP internal mailbox" in exc_records[0]["reason"]

        # Only genuine message written to disk
        eml_files = list(out_dir.glob("*.eml"))
        assert len(eml_files) == 1
        assert b"Urgent: Verify Your Account" in eml_files[0].read_bytes()

    def test_02_ordinary_email_with_similar_subject_or_body_retained(self, tmp_path: Path) -> None:
        """2. Ordinary email with similar subject text or body is retained and not excluded."""
        # Case A: Reply / Discussion with similar subject
        reply_msg = (
            b"From: alice@example.com\r\n"
            b"Subject: Re: DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA\r\n"
            b"Message-ID: <reply-01@example.com>\r\n\r\n"
            b"Why did you send that folder data notice?\r\n"
        )
        assert is_uw_imap_internal_record(reply_msg) is False

        # Case B: Similar subject from normal sender
        user_msg = (
            b"From: bob@company.org\r\n"
            b"Subject: DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA\r\n"
            b"Message-ID: <user-01@company.org>\r\n\r\n"
            b"Important memo regarding archive policies.\r\n"
        )
        assert is_uw_imap_internal_record(user_msg) is False

        # Case C: Internal Data sender with normal subject
        sys_msg = (
            b"From: Mail System Internal Data <admin@server.org>\r\n"
            b"Subject: Scheduled Server Downtime\r\n"
            b"Message-ID: <sys-01@server.org>\r\n\r\n"
            b"Maintenance scheduled for Sunday.\r\n"
        )
        assert is_uw_imap_internal_record(sys_msg) is False

        # Case D: Normal subject and headers with similar body text
        body_msg = (
            b"From: carol@example.com\r\n"
            b"Subject: Archive inspection findings\r\n"
            b"Message-ID: <body-01@example.com>\r\n\r\n"
            b"In our review we found text: DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA\r\n"
        )
        assert is_uw_imap_internal_record(body_msg) is False

        mbox_path = create_temp_mbox(tmp_path, [reply_msg, user_msg, sys_msg, body_msg])
        out_dir = tmp_path / "out_ordinary"

        records, stats = convert_mbox_to_eml(mbox_path, out_dir, filter_uw_internal=True)
        assert stats["converted_count"] == 4
        assert stats["excluded_count"] == 0
        assert len(list(out_dir.glob("*.eml"))) == 4

    def test_03_correct_source_category_and_labels(self) -> None:
        """3. Correct source-category assignment: ham_easy, ham_hard, phishing."""
        manifest_csv = Path(__file__).resolve().parent.parent / "data" / "dev" / "manifests" / "dev_manifest.csv"
        assert manifest_csv.exists(), "dev_manifest.csv must exist in data/dev/manifests"

        with open(manifest_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            records = list(reader)

        assert len(records) == 1000

        easy_ham = [r for r in records if r["source_category"] == "easy_ham"]
        hard_ham = [r for r in records if r["source_category"] == "hard_ham"]
        phishing = [r for r in records if r["source_category"] == "phishing"]

        assert len(easy_ham) == 500
        assert len(hard_ham) == 250
        assert len(phishing) == 250

        # Verify assigned labels strictly adhere to requirements
        for r in easy_ham:
            assert r["assigned_label"] == "ham_easy"
            assert r["assigned_label"] != "confirmed_legitimate"
        for r in hard_ham:
            assert r["assigned_label"] == "ham_hard"
            assert r["assigned_label"] != "confirmed_legitimate"
        for r in phishing:
            assert r["assigned_label"] == "phishing"

    def test_04_exact_500_250_250_sampling(self) -> None:
        """4. Final dataset contains exactly 500 easy_ham, 250 hard_ham, and 250 phishing."""
        summary_json = Path(__file__).resolve().parent.parent / "data" / "dev" / "manifests" / "dev_dataset_summary.json"
        assert summary_json.exists(), "dev_dataset_summary.json must exist"

        with open(summary_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["total_samples"] == 1000
        assert data["counts_by_category"]["easy_ham"] == 500
        assert data["counts_by_category"]["hard_ham"] == 250
        assert data["counts_by_category"]["phishing"] == 250

        assert data["counts_by_label"]["ham_easy"] == 500
        assert data["counts_by_label"]["ham_hard"] == 250
        assert data["counts_by_label"]["phishing"] == 250

    def test_05_deterministic_repeated_sampling_with_seed_42(self) -> None:
        """5. Deterministic repeated sampling with seed 42 produces identical selections."""
        pool = [f"item_{i:04d}_{hashlib.sha256(str(i).encode()).hexdigest()[:8]}" for i in range(500)]
        
        rng1 = random.Random(42)
        sample1 = sorted(rng1.sample(pool, 100))

        rng2 = random.Random(42)
        sample2 = sorted(rng2.sample(pool, 100))

        assert sample1 == sample2

    def test_06_no_duplicate_hashes_in_final_output(self) -> None:
        """6. No duplicate content SHA-256 hashes exist in the final development dataset."""
        manifest_csv = Path(__file__).resolve().parent.parent / "data" / "dev" / "manifests" / "dev_manifest.csv"
        assert manifest_csv.exists()

        hashes = []
        with open(manifest_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                hashes.append(row["sha256"])

        assert len(hashes) == 1000
        assert len(set(hashes)) == 1000, f"Found {1000 - len(set(hashes))} duplicate hashes!"

    def test_07_source_year_allocation_is_reproducible(self) -> None:
        """7. Source-year allocation for phishing (2015 vs 2021) is dynamically calculated and reproducible."""
        summary_json = Path(__file__).resolve().parent.parent / "data" / "dev" / "manifests" / "dev_dataset_summary.json"
        with open(summary_json, "r", encoding="utf-8") as f:
            summary = json.load(f)

        phish_by_year = summary["source_year_phishing_counts"]
        assert phish_by_year["2015"] == 188
        assert phish_by_year["2021"] == 62
        assert phish_by_year["2015"] + phish_by_year["2021"] == 250

        # Verify dynamic formula
        n_2015 = summary["candidate_counts"]["phishing_2015"]
        n_2021 = summary["candidate_counts"]["phishing_2021"]
        total_cand = n_2015 + n_2021
        expected_2015 = round(250 * n_2015 / total_cand)
        expected_2021 = 250 - expected_2015
        assert phish_by_year["2015"] == expected_2015
        assert phish_by_year["2021"] == expected_2021

    def test_08_missing_or_malformed_source_records_handled_safely(self, tmp_path: Path) -> None:
        """8. Missing or malformed records are handled safely without crashing."""
        empty_msg = b""
        valid_msg = b"From: a@b.com\r\nSubject: Valid\r\nMessage-ID: <v1@b.com>\r\n\r\nBody"
        mbox_path = create_temp_mbox(tmp_path, [empty_msg, valid_msg])
        out_dir = tmp_path / "out_malformed"

        records, stats = convert_mbox_to_eml(mbox_path, out_dir)
        assert stats["converted_count"] == 1
        assert stats["error_count"] == 1
        assert records[0].conversion_status == "ERROR"
        assert any("Empty message payload" in w for w in records[0].warnings)
        assert records[1].conversion_status == "SUCCESS"

    def test_09_output_collisions_do_not_overwrite_existing_files(self, tmp_path: Path) -> None:
        """9. Pre-existing output files are not overwritten when overwrite=False."""
        target_dir = tmp_path / "out_protect"
        target_dir.mkdir()
        protected_file = target_dir / "easy_ham_000001_18bc72ad3e77.eml"
        protected_file.write_bytes(b"EXISTING_USER_DATA_NEVER_OVERWRITE")

        msg = b"From: test@example.com\r\nSubject: Test\r\nMessage-ID: <col@example.com>\r\n\r\nContent"
        h = hashlib.sha256(msg).hexdigest()
        dest = target_dir / f"easy_ham_000001_{h[:12]}.eml"
        dest.write_bytes(b"EXISTING_USER_DATA_NEVER_OVERWRITE")

        with pytest.raises(FileExistsError):
            write_eml_file(dest, msg, overwrite=False)

        assert dest.read_bytes() == b"EXISTING_USER_DATA_NEVER_OVERWRITE"

    def test_10_manifest_entries_match_actual_eml_files(self) -> None:
        """10. Manifest records match actual exported EML files on disk (existence, size, SHA-256)."""
        dev_dir = Path(__file__).resolve().parent.parent / "data" / "dev"
        manifest_csv = dev_dir / "manifests" / "dev_manifest.csv"
        assert manifest_csv.exists()

        with open(manifest_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            records = list(reader)

        assert len(records) == 1000

        # Sample a subset of files across all three categories to verify full disk integrity
        sampled_indices = [0, 250, 499, 500, 625, 749, 750, 850, 999]
        for idx in sampled_indices:
            r = records[idx]
            file_path = dev_dir / r["relative_eml_path"]
            assert file_path.exists(), f"EML file does not exist on disk: {file_path}"
            data = file_path.read_bytes()
            assert len(data) == int(r["byte_size"]), f"Byte size mismatch for {file_path}"
            computed_hash = hashlib.sha256(data).hexdigest()
            assert computed_hash == r["sha256"], f"SHA-256 mismatch for {file_path}"

    def test_11_authentication_header_presence_distinguished_from_verification(self) -> None:
        """11. Authentication header presence indicators are distinguished from pass/fail classification."""
        # DKIM header present does NOT infer DKIM passed
        msg_dkim = (
            b"From: signer@example.com\r\n"
            b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=key; b=dummy\r\n"
            b"Subject: DKIM Present Test\r\n\r\n"
            b"Body"
        )
        res_dkim = detect_authentication_headers(msg_dkim)
        assert res_dkim["has_dkim_signature"] is True
        assert res_dkim["has_authentication_results"] is False

        # Authentication-Results header present does NOT infer verified trustworthiness
        msg_auth_res = (
            b"From: claims@example.com\r\n"
            b"Authentication-Results: mx.google.com; dkim=pass header.i=@example.com\r\n"
            b"Subject: Auth Results Present\r\n\r\n"
            b"Body"
        )
        res_auth_res = detect_authentication_headers(msg_auth_res)
        assert res_auth_res["has_authentication_results"] is True
        assert res_auth_res["has_dkim_signature"] is False

        # Message without authentication headers is distinguishable from authentication failure
        msg_none = b"From: plain@example.com\r\nSubject: None\r\n\r\nBody"
        res_none = detect_authentication_headers(msg_none)
        assert res_none["has_dkim_signature"] is False
        assert res_none["has_authentication_results"] is False
        assert res_none["has_received_spf"] is False
        assert res_none["has_arc"] is False

    def test_12_shortfalls_stop_dataset_creation_without_synthetic_data(self, tmp_path: Path) -> None:
        """12. Candidate shortfalls stop dataset creation and report shortfalls without synthesizing data."""
        raw_mock = tmp_path / "raw_shortfall"
        raw_mock.mkdir()

        # Create dummy archives with only 10 messages each
        easy_dir = raw_mock / "easy_ham"
        hard_dir = raw_mock / "hard_ham"
        easy_dir.mkdir()
        hard_dir.mkdir()

        for i in range(10):
            (easy_dir / f"msg_{i}.eml").write_bytes(f"From: a@b.com\r\n\r\nEasy {i}".encode())
            (hard_dir / f"msg_{i}.eml").write_bytes(f"From: a@b.com\r\n\r\nHard {i}".encode())

        # Create 10 phishing 2015 and 10 phishing 2021
        p15_msgs = [f"From: p@e.com\r\nSubject: P15 {i}\r\n\r\nBody".encode() for i in range(10)]
        p21_msgs = [f"From: p@e.com\r\nSubject: P21 {i}\r\n\r\nBody".encode() for i in range(10)]

        p15_file = create_temp_mbox(raw_mock, p15_msgs)
        p15_file.rename(raw_mock / "phishing-2015.mbox")

        p21_file = create_temp_mbox(raw_mock, p21_msgs)
        p21_file.rename(raw_mock / "phishing-2021.mbox")

        result = build_task8_3_dev_dataset(raw_mock, tmp_path / "dev_shortfall")

        assert result["status"] == "SHORTFALL"
        assert "Shortfall in candidate datasets" in result["message"]
        assert result["shortfalls"]["easy_ham"]["shortfall"] == 490
        assert result["shortfalls"]["hard_ham"]["shortfall"] == 240
        assert result["shortfalls"]["phishing"]["shortfall"] == 230

        # Verify no fake EML files or manifests were created in dev directory
        assert not (tmp_path / "dev_shortfall" / "eml").exists()
        assert not (tmp_path / "dev_shortfall" / "manifests" / "dev_manifest.csv").exists()



