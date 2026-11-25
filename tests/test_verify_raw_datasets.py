"""
Tests for Raw Dataset Verification and Acquisition Module (Task 8.2).

Verifies:
1. SHA-256 calculation against known test fixtures.
2. Missing archive handling.
3. Modified archive / tampering detection.
4. Incorrect expected checksum detection.
5. Manifest creation and JSON schema validity.
6. Git ignore behavior for raw data.
7. Safe handling of interrupted or incomplete downloads.
8. Re-running verification without modifying source archives (read-only idempotence).
9. Live archive verification on acquired datasets.
10. CLI flags and execution.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from typing import Any, Dict
import urllib.error
import pytest

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from verify_raw_datasets import (
    APPROVED_DATASETS,
    REQUIRED_DEV_DATASET_IDS,
    calculate_sha256,
    verify_archive_structure,
    download_file_atomically,
    verify_single_dataset,
    verify_all_raw_datasets,
    acquire_raw_datasets,
    write_acquisition_manifest,
    load_acquisition_manifest,
    validate_manifest_structure,
    main,
)


class TestSha256Calculation:
    """Test 1: SHA-256 calculation against known test fixtures."""

    def test_known_byte_string_fixture(self, tmp_path: Path):
        f = tmp_path / "hello.txt"
        f.write_bytes(b"Hello, world!\n")
        # Known SHA-256 of "Hello, world!\n"
        expected = "d9014c4624844aa5bac314773d6b689ad467fa4e1d1a50a1b8a99d5a95f72ff5"
        assert calculate_sha256(f) == expected

    def test_empty_file_fixture(self, tmp_path: Path):
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        # Known SHA-256 of empty payload
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert calculate_sha256(f) == expected

    def test_missing_file_raises_not_found(self, tmp_path: Path):
        f = tmp_path / "nonexistent.bin"
        with pytest.raises(FileNotFoundError):
            calculate_sha256(f)


class TestMissingArchiveHandling:
    """Test 2: Missing archive handling."""

    def test_missing_single_archive_returns_missing_status(self, tmp_path: Path):
        fake_entry = {
            "dataset_id": "test_missing",
            "dataset_name": "Test Missing Dataset",
            "source_category": "phishing",
            "local_filename": "does_not_exist.mbox",
            "archive_format": "mbox",
            "original_source_url": "https://example.com/test.mbox",
            "original_archive_filename": "test.mbox",
            "expected_sha256": "abcdef1234567890",
            "expected_size_bytes": 1000,
            "is_required_for_dev": True,
        }
        res = verify_single_dataset(fake_entry, tmp_path)
        assert res["acquisition_status"] == "MISSING"
        assert res["sha256"] is None
        assert res["size_bytes"] == 0
        assert any("Local archive not found" in w for w in res["warnings"])

    def test_missing_required_archives_causes_manifest_failure(self, tmp_path: Path):
        manifest = verify_all_raw_datasets(tmp_path)
        assert manifest["required_datasets_verified"] is False
        assert len(manifest["missing_required_datasets"]) >= 3


class TestModifiedArchiveDetection:
    """Test 3: Modified archive detection."""

    def test_tampered_bytes_triggers_hash_mismatch(self, tmp_path: Path):
        archive_path = tmp_path / "sample.mbox"
        original_bytes = b"From user@domain.com Fri Nov 10 12:00:00 2006\nSubject: Test\n\nBody\n"
        archive_path.write_bytes(original_bytes)
        expected_hash = calculate_sha256(archive_path)

        # Mutate 1 byte
        archive_path.write_bytes(original_bytes + b"\n")

        catalog = {
            "sample": {
                "dataset_id": "sample",
                "dataset_name": "Sample Mbox",
                "source_category": "phishing",
                "local_filename": "sample.mbox",
                "archive_format": "mbox",
                "original_source_url": "https://example.com/sample.mbox",
                "original_archive_filename": "sample.mbox",
                "expected_sha256": expected_hash,
                "is_required_for_dev": True,
            }
        }
        res = verify_single_dataset(catalog["sample"], tmp_path)
        assert res["acquisition_status"] == "HASH_MISMATCH"
        assert any("SHA-256 digest mismatch" in w for w in res["warnings"])

    def test_corrupted_archive_structure_detected(self, tmp_path: Path):
        # A file with .tar.bz2 extension but corrupted header
        bad_tar = tmp_path / "bad.tar.bz2"
        bad_tar.write_bytes(b"BZh91AY&SYNOT_A_VALID_BZIP2_ARCHIVE_DATA")
        calculated_hash = calculate_sha256(bad_tar)

        catalog_entry = {
            "dataset_id": "bad_tar",
            "dataset_name": "Bad Tar",
            "source_category": "easy_ham",
            "local_filename": "bad.tar.bz2",
            "archive_format": "tar.bz2",
            "original_source_url": "https://example.com/bad.tar.bz2",
            "original_archive_filename": "bad.tar.bz2",
            "expected_sha256": calculated_hash,  # hash matches, but contents corrupt
            "is_required_for_dev": True,
        }
        res = verify_single_dataset(catalog_entry, tmp_path, verify_structure=True)
        assert res["acquisition_status"] == "CORRUPT_ARCHIVE"
        assert res["archive_structure_valid"] is False


class TestIncorrectExpectedChecksumDetection:
    """Test 4: Incorrect expected checksum detection."""

    def test_incorrect_expected_hash_rejected_in_verification(self, tmp_path: Path):
        valid_file = tmp_path / "valid.mbox"
        valid_file.write_bytes(b"From user@domain.com Sat Nov 11 10:00:00 2006\nSubject: Hi\n\nText\n")

        wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        catalog_entry = {
            "dataset_id": "test_wrong_hash",
            "dataset_name": "Test Wrong Hash",
            "source_category": "phishing",
            "local_filename": "valid.mbox",
            "archive_format": "mbox",
            "original_source_url": "https://example.com/valid.mbox",
            "original_archive_filename": "valid.mbox",
            "expected_sha256": wrong_hash,
            "is_required_for_dev": True,
        }
        res = verify_single_dataset(catalog_entry, tmp_path)
        assert res["acquisition_status"] == "HASH_MISMATCH"

    def test_atomic_download_rejects_hash_mismatch(self, tmp_path: Path, monkeypatch):
        # Mock urllib to return data that doesn't match expected hash
        dest = tmp_path / "dest.txt"
        wrong_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

        class DummyResponse:
            status = 200
            headers = {}
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self, chunk_size):
                if not hasattr(self, "_read_done"):
                    self._read_done = True
                    return b"some content"
                return b""

        monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=60: DummyResponse())

        with pytest.raises(ValueError, match="SHA-256 mismatch"):
            download_file_atomically("https://example.com/fake", dest, expected_sha256=wrong_hash)

        # Ensure destination file was not created
        assert not dest.exists()


class TestManifestCreationAndValidation:
    """Test 5: Manifest creation and JSON schema validity."""

    def test_manifest_validation_schema(self, tmp_path: Path):
        manifest = verify_all_raw_datasets(tmp_path)
        errors = validate_manifest_structure(manifest)
        assert errors == []

    def test_write_and_load_manifest_roundtrip(self, tmp_path: Path):
        manifest = verify_all_raw_datasets(tmp_path)
        manifest_file = tmp_path / "manifest.json"
        write_acquisition_manifest(manifest, manifest_file)

        assert manifest_file.exists()
        loaded = load_acquisition_manifest(manifest_file)
        assert loaded["manifest_version"] == manifest["manifest_version"]
        assert len(loaded["datasets"]) == len(manifest["datasets"])

    def test_manifest_schema_detects_missing_keys(self):
        corrupt_manifest = {
            "manifest_version": "1.0.0",
            # missing required keys
            "datasets": [
                {"dataset_name": "Incomplete"}
            ]
        }
        errors = validate_manifest_structure(corrupt_manifest)
        assert len(errors) > 0
        assert any("Missing top-level manifest key" in e for e in errors)
        assert any("missing required key" in e for e in errors)


class TestGitIgnoreBehavior:
    """Test 6: Git ignore behavior."""

    def test_raw_and_dev_paths_ignored_by_git(self):
        project_root = Path(__file__).resolve().parent.parent
        test_paths = [
            "data/raw/20030228_easy_ham.tar.bz2",
            "data/raw/20030228_hard_ham.tar.bz2",
            "data/raw/phishing0.mbox",
            "data/raw/acquisition_manifest.json",
            "data/dev/manifests/dev_manifest.csv",
            "data/dev/eml/ham/DEV_HAM_000001.eml",
        ]

        result = subprocess.run(
            ["git", "check-ignore", *test_paths],
            cwd=str(project_root),
            capture_output=True,
            text=True,
        )
        ignored_lines = set(line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip())

        for p in test_paths:
            normalized_p = p.replace("\\", "/")
            assert normalized_p in ignored_lines, f"Expected {normalized_p} to be ignored by Git!"

    def test_no_raw_datasets_tracked_in_git(self):
        project_root = Path(__file__).resolve().parent.parent
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(project_root),
            capture_output=True,
            text=True,
        )
        lines = result.stdout.splitlines()
        for line in lines:
            assert "data/raw" not in line, f"Found data/raw in git status: {line}"
            assert "data/dev" not in line, f"Found data/dev in git status: {line}"


class TestSafeHandlingOfInterruptedDownloads:
    """Test 7: Safe handling of interrupted or incomplete downloads."""

    def test_interrupted_download_cleans_up_part_files(self, tmp_path: Path, monkeypatch):
        dest = tmp_path / "failed_download.bin"

        class FailingResponse:
            status = 200
            headers = {}
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self, chunk_size):
                raise ConnectionResetError("Connection dropped mid-stream")

        monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=60: FailingResponse())

        with pytest.raises(ConnectionResetError):
            download_file_atomically("https://example.com/fail", dest)

        # Assert dest does not exist
        assert not dest.exists()

        # Assert no leftover .part. files exist
        part_files = list(tmp_path.glob(".*.part.*"))
        assert len(part_files) == 0

    def test_interrupted_download_preserves_existing_destination_file(self, tmp_path: Path, monkeypatch):
        dest = tmp_path / "existing_good_file.bin"
        original_content = b"ORIGINAL_IMPORTANT_DATA"
        dest.write_bytes(original_content)

        class FailingResponse:
            status = 200
            headers = {}
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self, chunk_size):
                raise IOError("Network timeout")

        monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=60: FailingResponse())

        with pytest.raises(IOError):
            download_file_atomically("https://example.com/fail", dest)

        # Assert original content remains untouched
        assert dest.exists()
        assert dest.read_bytes() == original_content


class TestReadonlyVerificationIdempotency:
    """Test 8: Re-running verification without modifying source archives."""

    def test_verification_is_read_only_and_idempotent(self, tmp_path: Path):
        f = tmp_path / "sample.mbox"
        content = b"From user@domain.com Sun Nov 12 10:00:00 2006\nSubject: Hi\n\nTest\n"
        f.write_bytes(content)
        mtime_before = f.stat().st_mtime_ns
        hash_before = calculate_sha256(f)

        catalog = {
            "test_sample": {
                "dataset_id": "test_sample",
                "dataset_name": "Test Sample",
                "source_category": "phishing",
                "local_filename": "sample.mbox",
                "archive_format": "mbox",
                "original_source_url": "https://example.com/sample.mbox",
                "original_archive_filename": "sample.mbox",
                "expected_sha256": hash_before,
                "is_required_for_dev": True,
            }
        }

        # Run verification 1
        m1 = verify_all_raw_datasets(tmp_path, catalog=catalog)
        assert m1["required_datasets_verified"] is True
        assert f.stat().st_mtime_ns == mtime_before
        assert calculate_sha256(f) == hash_before

        # Run verification 2
        m2 = verify_all_raw_datasets(tmp_path, catalog=catalog)
        assert m2["required_datasets_verified"] is True
        assert f.stat().st_mtime_ns == mtime_before
        assert calculate_sha256(f) == hash_before


class TestActualAcquiredRawDatasets:
    """Live verification of the actual data/raw directory."""

    @pytest.fixture
    def real_raw_dir(self) -> Path:
        raw_dir = Path(__file__).resolve().parent.parent / "data" / "raw"
        if not raw_dir.exists():
            pytest.skip("data/raw directory does not exist yet")
        return raw_dir

    def test_actual_required_archives_present_and_verified(self, real_raw_dir: Path):
        manifest = verify_all_raw_datasets(real_raw_dir)
        assert manifest["required_datasets_verified"] is True, f"Failed: {manifest.get('missing_required_datasets')}"
        assert len(manifest["missing_required_datasets"]) == 0

        # Verify specific required datasets
        datasets_by_id = {d["dataset_id"]: d for d in manifest["datasets"]}

        easy_ham = datasets_by_id["spamassassin_easy_ham"]
        assert easy_ham["acquisition_status"] == "VERIFIED_LOCAL_HASH"
        assert easy_ham["sha256"] == "2b7b65904bcfcc31d2b5f51946f2d261370b257402cbbd62930b46ab83367438"
        assert easy_ham["size_bytes"] == 1612216
        assert easy_ham["archive_entry_count"] == 2501
        assert easy_ham["archive_entry_count"] >= 500  # dev target

        hard_ham = datasets_by_id["spamassassin_hard_ham"]
        assert hard_ham["acquisition_status"] == "VERIFIED_LOCAL_HASH"
        assert hard_ham["sha256"] == "ce2ce67880643dbde65ea7f85bffbfe4417349c4bd80b6b0de56262ae6b0a9c9"
        assert hard_ham["size_bytes"] == 1029898
        assert hard_ham["archive_entry_count"] == 251
        assert hard_ham["archive_entry_count"] >= 250  # dev target

        phishing0 = datasets_by_id["nazario_phishing0"]
        assert phishing0["acquisition_status"] == "VERIFIED_LOCAL_HASH"
        assert phishing0["sha256"] == "6184b0a34ed8cbbb252676e21c1eab9eac5fa4be89c61e30cc9954ebbb25d848"
        assert phishing0["size_bytes"] == 3119972
        assert phishing0["archive_entry_count"] == 414
        assert phishing0["archive_entry_count"] >= 250  # dev target

    def test_actual_manifest_file_validity(self, real_raw_dir: Path):
        manifest_path = real_raw_dir / "acquisition_manifest.json"
        assert manifest_path.exists(), "acquisition_manifest.json must exist in data/raw"
        data = load_acquisition_manifest(manifest_path)
        errors = validate_manifest_structure(data)
        assert errors == [], f"Manifest validation errors: {errors}"
        assert data["required_datasets_verified"] is True


class TestCliInterface:
    """CLI execution tests."""

    def test_cli_help(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        assert exc_info.value.code == 0

    def test_cli_check_only_on_empty_dir(self, tmp_path: Path):
        ret = main(["--data-dir", str(tmp_path), "--check-only", "--no-manifest"])
        assert ret == 1

    def test_cli_json_output(self, capsys):
        raw_dir = Path(__file__).resolve().parent.parent / "data" / "raw"
        ret = main(["--data-dir", str(raw_dir), "--check-only", "--json", "--no-manifest"])
        assert ret == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["required_datasets_verified"] is True
