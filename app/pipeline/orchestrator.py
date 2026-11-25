"""
app/pipeline/orchestrator.py
----------------------------
End-to-End Phishing Detection Pipeline Orchestrator.

Architecture:
- Coordinates Layer 0 (Ingestion), Layer 1 (Header, URL, Text, Attachment Specialists),
  Layer 2 (Evidence Aggregator), and Layer 3 (Meta-Classifier with Selective Abstention).
- Strict Fault Isolation: Isolates each Layer 1 agent in a dedicated try/except block.
  If an agent crashes, it logs the error in agent_errors and passes None to Layer 2,
  allowing the Aggregator's partial-failure and health-abstention policies to handle it gracefully.
- Passive & Offline Execution: Zero socket lookups, DNS requests, or remote API calls.
"""

from __future__ import annotations

import datetime
from pathlib import Path
import time
from typing import Optional, Union

from app.ingestion.email_ingestor import ingest_email
from app.agents.header_agent import analyze_headers
from app.agents.url_agent import analyze_urls
from app.agents.text_agent import analyze_text
from app.agents.attachment_agent import analyze_attachments
from app.aggregation.evidence_aggregator import aggregate_evidence
from app.meta_classifier.meta_classifier import MetaClassifier
from app.schemas.meta_classifier_schema import DecisionThresholds
from app.schemas.pipeline_schema import PhishingAnalysisReport


class PipelineInitializationError(Exception):
    """
    Raised when PhishingDetectorPipeline fails to locate or initialize the Meta-Classifier model.
    """


class PhishingDetectorPipeline:
    """
    Top-level orchestrator providing a unified API to analyze raw email bytes
    or .eml files across the entire multi-agent phishing detection system.
    """

    def __init__(
        self,
        model_path: Optional[Union[str, Path]] = None,
        meta_classifier: Optional[MetaClassifier] = None,
        thresholds: Optional[DecisionThresholds] = None,
        model_name: str = "meta_classifier_v1",
    ) -> None:
        """
        Initializes the pipeline with a trained MetaClassifier or bundle path.

        If neither model_path nor meta_classifier is passed, attempts to load
        from the default project location 'models/<model_name>/'.
        """
        self.thresholds = thresholds
        self.model_name = model_name

        if meta_classifier is not None:
            self.meta_classifier = meta_classifier
        elif model_path is not None:
            try:
                self.meta_classifier = MetaClassifier(
                    bundle_path=model_path,
                    model_name=model_name,
                    thresholds=thresholds,
                )
            except Exception as e:
                raise PipelineInitializationError(
                    f"No meta-classifier model provided or found at '{model_path}': {e}"
                ) from e
        else:
            # Check default project model directory
            default_dir = Path(__file__).resolve().parent.parent.parent / "models" / model_name
            if default_dir.exists() and (default_dir / f"{model_name}.joblib").exists():
                self.meta_classifier = MetaClassifier(
                    bundle_path=default_dir,
                    model_name=model_name,
                    thresholds=thresholds,
                )
            else:
                raise PipelineInitializationError(
                    f"No meta-classifier model provided or found at default location '{default_dir}'. "
                    f"Please provide 'model_path', 'meta_classifier', or run 'scripts/train_and_evaluate.py'."
                )

    def analyze_raw_email(
        self,
        raw_bytes: bytes,
        file_name: Optional[str] = None,
    ) -> PhishingAnalysisReport:
        """
        Executes complete end-to-end multi-agent phishing analysis on raw email bytes.

        Parameters:
            raw_bytes: RFC 5322 raw email byte payload.
            file_name: Optional file or message identifier.

        Returns:
            PhishingAnalysisReport containing verdict, evidence, and audit metadata.
        """
        start_time = time.perf_counter()

        # Step 0: Ingestion and structural normalization
        email_data = ingest_email(raw_bytes)

        # Step 1: Fault-isolated specialist agent execution
        agent_errors: dict[str, str] = {}

        # 1A. Header Agent
        try:
            header_result = analyze_headers(email_data)
        except Exception as e:  # noqa: BLE001
            agent_errors["header"] = f"HeaderAgent error: {type(e).__name__}: {e}"
            header_result = None

        # 1B. URL Agent
        try:
            url_result = analyze_urls(email_data)
        except Exception as e:  # noqa: BLE001
            agent_errors["url"] = f"UrlAgent error: {type(e).__name__}: {e}"
            url_result = None

        # 1C. Text Agent
        try:
            text_result = analyze_text(email_data)
        except Exception as e:  # noqa: BLE001
            agent_errors["text"] = f"TextAgent error: {type(e).__name__}: {e}"
            text_result = None

        # 1D. Attachment Agent
        try:
            attachment_result = analyze_attachments(email_data)
        except Exception as e:  # noqa: BLE001
            agent_errors["attachment"] = f"AttachmentAgent error: {type(e).__name__}: {e}"
            attachment_result = None

        # Step 2: Layer 2 Evidence Aggregation
        aggregated_evidence = aggregate_evidence(
            header_result=header_result,
            url_result=url_result,
            text_result=text_result,
            attachment_result=attachment_result,
        )

        # Step 3: Layer 3 Calibrated Classification & Abstention
        verdict_result = self.meta_classifier.predict_verdict(
            aggregated_evidence,
            thresholds=self.thresholds,
        )

        total_processing_time_ms = round((time.perf_counter() - start_time) * 1000, 3)
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        return PhishingAnalysisReport(
            email_id=email_data.email_id,
            analyzed_at_utc=now_utc,
            total_processing_time_ms=total_processing_time_ms,
            verdict_result=verdict_result,
            aggregated_evidence=aggregated_evidence,
            agent_errors=agent_errors,
        )

    def analyze_eml_file(self, file_path: Union[str, Path]) -> PhishingAnalysisReport:
        """
        Reads an RFC 5322 .eml file from disk and executes complete analysis.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Email file not found at '{path}'")
        raw_bytes = path.read_bytes()
        return self.analyze_raw_email(raw_bytes, file_name=path.name)
