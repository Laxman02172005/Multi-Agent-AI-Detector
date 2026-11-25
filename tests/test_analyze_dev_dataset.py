"""
test_analyze_dev_dataset.py
---------------------------
Unit and integration tests for Task 8.4 dataset analysis script and output deliverables.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.analyze_dev_dataset import (
    compute_numeric_stats,
    run_dev_dataset_analysis,
)


@pytest.fixture(scope="module")
def analysis_dir() -> Path:
    """Path to the generated analysis deliverables."""
    p = Path("data/dev/analysis")
    assert p.is_dir(), f"Analysis directory does not exist: {p}"
    return p


class TestAnalysisDeliverablesExist:
    """Verify that all 7 required JSON deliverables exist and contain valid JSON."""

    EXPECTED_FILES = [
        "dataset_composition.json",
        "header_analysis.json",
        "authentication_analysis.json",
        "body_analysis.json",
        "url_analysis.json",
        "attachment_analysis.json",
        "dataset_bias_analysis.json",
    ]

    @pytest.mark.parametrize("filename", EXPECTED_FILES)
    def test_deliverable_file_exists_and_valid_json(
        self, analysis_dir: Path, filename: str
    ) -> None:
        fpath = analysis_dir / filename
        assert fpath.is_file(), f"Missing required analysis file: {filename}"
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data, dict), f"Expected dict in {filename}, got {type(data)}"
        assert len(data) > 0, f"Empty dictionary in {filename}"


class TestDatasetCompositionAnalysis:
    """Validate dataset composition counts, integrity, and file size statistics."""

    def test_total_counts_and_uniqueness(self, analysis_dir: Path) -> None:
        with open(analysis_dir / "dataset_composition.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["total_emails"] == 1000
        assert data["counts_by_label"] == {
            "ham_easy": 500,
            "ham_hard": 250,
            "phishing": 250,
        }
        assert data["phishing_counts_by_year"] == {
            "2015": 188,
            "2021": 62,
        }
        assert data["duplicate_sha256_count"] == 0
        assert data["successfully_parsed_count"] == 1000
        assert data["failed_or_malformed_count"] == 0

    def test_numeric_summary_statistics(self, analysis_dir: Path) -> None:
        with open(analysis_dir / "dataset_composition.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        sz = data["overall_file_size_bytes"]
        assert sz["count"] == 1000
        assert sz["min"] > 0
        assert sz["max"] >= sz["min"]
        assert sz["mean"] > 0
        assert sz["median"] > 0
        assert sz["p25"] <= sz["median"] <= sz["p75"]


class TestHeaderAvailabilityAnalysis:
    """Validate presence and missingness reconciliation for all 11 core headers."""

    CORE_HEADERS = [
        "from",
        "to",
        "cc",
        "reply_to",
        "return_path",
        "subject",
        "date",
        "message_id",
        "received",
        "mime_version",
        "content_type",
    ]

    @pytest.mark.parametrize("header", CORE_HEADERS)
    def test_header_presence_reconciles_to_1000(
        self, analysis_dir: Path, header: str
    ) -> None:
        with open(analysis_dir / "header_analysis.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        h_info = data["headers"][header]
        pres = h_info["present_count"]
        miss = h_info["missing_count"]
        assert pres + miss == 1000, f"Header {header} counts do not sum to 1,000"

        # Check label breakdowns reconcile
        by_label = h_info["by_label"]
        assert by_label["ham_easy"]["present"] + by_label["ham_easy"]["missing"] == 500
        assert by_label["ham_hard"]["present"] + by_label["ham_hard"]["missing"] == 250
        assert by_label["phishing"]["present"] + by_label["phishing"]["missing"] == 250


class TestAuthenticationAnalysisAndH5:
    """Validate authentication claim counts, unverified claims, and H5 feasibility verdict."""

    def test_h5_verdict_and_claim_unverified(self, analysis_dir: Path) -> None:
        with open(analysis_dir / "authentication_analysis.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        h5 = data["h5_hypothesis_evaluation"]
        assert h5["verdict"] in ("EXPLORATORY_ONLY", "NOT_TESTABLE")
        assert "temporal asymmetry" in h5["justification"].lower()

        metrics = h5["metrics"]
        assert metrics["phishing_total"] == 250
        assert metrics["ham_total"] == 750
        assert metrics["ham_emails_with_any_pass_claim"] == 0
        assert metrics["phishing_spf_pass_claims"] == 25
        assert metrics["phishing_dkim_pass_claims"] == 31
        assert metrics["phishing_dmarc_pass_claims"] == 9

        # Ensure claims remain strictly unverified
        claims = data["claims_summary"]
        assert claims["all_claims_unverified"] is True


class TestBodyAndUrlAnalysis:
    """Validate body availability and URL extraction integrity."""

    def test_body_availability_metrics(self, analysis_dir: Path) -> None:
        with open(analysis_dir / "body_analysis.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        b_avail = data["body_availability"]
        assert b_avail["plain_text_available_count"] > 0
        assert b_avail["html_available_count"] > 0
        assert b_avail["dual_plain_and_html_count"] > 0
        assert b_avail["empty_or_whitespace_count"] == 2

    def test_url_extraction_metrics(self, analysis_dir: Path) -> None:
        with open(analysis_dir / "url_analysis.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["total_analyzed_emails"] == 1000
        assert data["emails_with_urls_count"] == 879
        assert data["total_extracted_url_occurrences"] > 10000
        assert data["unique_normalized_url_count"] > 5000
        assert data["url_scheme_distribution"]["http"] > 10000


class TestAttachmentAndBiasAnalysis:
    """Validate attachment counts and dataset bias quantification."""

    def test_attachment_metrics(self, analysis_dir: Path) -> None:
        with open(analysis_dir / "attachment_analysis.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["total_analyzed_emails"] == 1000
        assert data["emails_with_attachments_count"] == 59
        assert data["total_attachments_count"] == 78

    def test_dataset_bias_leakage_metrics(self, analysis_dir: Path) -> None:
        with open(analysis_dir / "dataset_bias_analysis.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        # Date leakage
        date_bias = data["date_leakage"]
        assert "2002" in date_bias["years_by_label"]["ham_easy"]
        assert "2015" in date_bias["years_by_label"]["phishing"]
        assert "2021" in date_bias["years_by_label"]["phishing"]

        # Source leakage (X-Spam-*)
        src_bias = data["source_and_header_leakage"]
        assert src_bias["x_spam_headers_presence"]["phishing"] >= 240

        # Label imbalance
        imb = data["label_imbalance"]
        assert imb["ham_samples"] == 750
        assert imb["phishing_samples"] == 250
        assert imb["majority_class_baseline_accuracy"] == 75.0


class TestHelperNumericStats:
    """Test helper statistical function."""

    def test_empty_list(self) -> None:
        res = compute_numeric_stats([])
        assert res["count"] == 0
        assert res["mean"] == 0.0

    def test_single_element(self) -> None:
        res = compute_numeric_stats([42])
        assert res["count"] == 1
        assert res["min"] == 42.0
        assert res["max"] == 42.0
        assert res["mean"] == 42.0
        assert res["median"] == 42.0

    def test_multi_element(self) -> None:
        res = compute_numeric_stats([10, 20, 30, 40, 50])
        assert res["count"] == 5
        assert res["min"] == 10.0
        assert res["max"] == 50.0
        assert res["mean"] == 30.0
        assert res["median"] == 30.0
