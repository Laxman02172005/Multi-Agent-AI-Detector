"""
tests/test_orchestrator.py
--------------------------
Comprehensive unit and integration tests for PhishingDetectorPipeline (app/pipeline/orchestrator.py):
- Full end-to-end execution (.eml to PhishingAnalysisReport) and JSON serialization.
- Fault isolation when individual Layer 1 specialist agents crash.
- Multi-modality failure triggering health-driven selective abstention.
- Pipeline initialization error handling.
- CLI smoke test execution.
"""

import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch
import pytest

from app.pipeline.orchestrator import (
    PhishingDetectorPipeline,
    PipelineInitializationError,
)
from app.schemas.pipeline_schema import PhishingAnalysisReport
from app.schemas.meta_classifier_schema import AbstentionReason, DecisionThresholds, Verdict
from app.schemas.aggregator_schema import ModalityStatus


SAMPLE_EML_PATH = Path(__file__).resolve().parent.parent / "data" / "samples" / "synthetic_demo.eml"
MODEL_DIR = Path(__file__).resolve().parent.parent / "models" / "meta_classifier_v1"


@pytest.fixture
def pipeline():
    return PhishingDetectorPipeline(model_path=MODEL_DIR)


class TestPipelineInitialization:
    def test_default_model_loading(self, pipeline):
        assert pipeline.meta_classifier is not None
        assert pipeline.meta_classifier.model_version == "1.0.0"

    def test_missing_model_directory_raises_initialization_error(self, tmp_path):
        empty_dir = tmp_path / "non_existent_model_dir"
        with pytest.raises(PipelineInitializationError) as exc_info:
            PhishingDetectorPipeline(model_path=empty_dir)
        assert "no meta-classifier model provided or found" in str(exc_info.value).lower()


class TestEndToEndPipelineExecution:
    def test_analyze_eml_file_success(self, pipeline):
        assert SAMPLE_EML_PATH.exists()
        report = pipeline.analyze_eml_file(SAMPLE_EML_PATH)

        assert isinstance(report, PhishingAnalysisReport)
        assert report.email_id.startswith("email_")
        assert report.total_processing_time_ms > 0.0
        assert report.verdict_result.verdict in (Verdict.PHISHING, Verdict.LEGITIMATE, Verdict.ABSTAIN)
        assert report.aggregated_evidence.feature_vector.active_feature_count == 132
        assert len(report.agent_errors) == 0

        # Validate complete JSON roundtrip
        json_data = report.model_dump_json(indent=2)
        loaded = PhishingAnalysisReport.model_validate_json(json_data)
        assert loaded.email_id == report.email_id
        assert loaded.verdict_result.verdict == report.verdict_result.verdict

    def test_missing_file_raises_filenotfound(self, pipeline, tmp_path):
        bad_path = tmp_path / "missing.eml"
        with pytest.raises(FileNotFoundError):
            pipeline.analyze_eml_file(bad_path)


class TestFaultIsolation:
    def test_single_agent_crash_absorbed_by_pipeline(self, pipeline):
        """Simulate unexpected crash in URL agent; pipeline must finish cleanly."""
        raw_bytes = SAMPLE_EML_PATH.read_bytes()

        with patch("app.pipeline.orchestrator.analyze_urls", side_effect=RuntimeError("Simulated URL engine crash")):
            report = pipeline.analyze_raw_email(raw_bytes)

        assert isinstance(report, PhishingAnalysisReport)
        assert "url" in report.agent_errors
        assert "Simulated URL engine crash" in report.agent_errors["url"]

        # Modality health should record FAILED for url without crashing aggregator
        url_health = report.aggregated_evidence.modality_health["url"]
        assert url_health.status == ModalityStatus.FAILED
        assert url_health.completeness == 0.0

        # Pipeline status remains partial rather than unhandled exception
        assert report.aggregated_evidence.status == "partial"

    def test_multiple_agent_crash_triggers_health_abstention(self, pipeline):
        """When both core agents (Header + Text) fail, health-driven abstention must trigger."""
        raw_bytes = SAMPLE_EML_PATH.read_bytes()

        with patch("app.pipeline.orchestrator.analyze_headers", side_effect=RuntimeError("Header engine fatal failure")):
            with patch("app.pipeline.orchestrator.analyze_text", side_effect=RuntimeError("Text engine fatal failure")):
                report = pipeline.analyze_raw_email(raw_bytes)

        assert report.verdict_result.verdict == Verdict.ABSTAIN
        assert report.verdict_result.abstention_reason == AbstentionReason.INSUFFICIENT_MODALITY_HEALTH
        assert "header" in report.agent_errors
        assert "text" in report.agent_errors


class TestCLISmoke:
    def test_cli_execution_with_json_output(self, tmp_path):
        json_out = tmp_path / "cli_report.json"
        cmd = [
            sys.executable,
            str(Path(__file__).resolve().parent.parent / "scripts" / "analyze_email_cli.py"),
            str(SAMPLE_EML_PATH),
            "--model-dir",
            str(MODEL_DIR),
            "--json-out",
            str(json_out),
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert result.returncode == 0
        assert "FINAL VERDICT:" in result.stdout
        assert json_out.exists()

        # Validate exported JSON
        data = json.loads(json_out.read_text(encoding="utf-8"))
        assert "email_id" in data
        assert "verdict_result" in data
        assert "aggregated_evidence" in data
