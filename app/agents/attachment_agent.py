"""
app/agents/attachment_agent.py
------------------------------
Core Attachment Specialist Agent for the Multi-Agent AI Phishing Email Detector.

Architecture & Contracts:
- Architecture B Boundary Validation: Validates all attachment items strictly once at
  the agent boundary into immutable ValidatedAttachmentRecord instances.
- Single-Access Introspection: Uses inspect.getattr_static to disambiguate missing
  attributes from descriptor getter crashes.
- Four-Tier Failure Handling: Caller input violations fail fast outside the processing try
  block; internal processing errors raise AttachmentAgentProcessingError.
- Passive & Offline: Static metadata and extension analysis with zero binary execution.
"""

from __future__ import annotations

import html
import inspect
import time
import traceback
from dataclasses import dataclass
from typing import Any, List, Optional

from app.agents.attachment_components.file_classifier import (
    AttachmentClassificationResult,
    classify_attachment,
)
from app.schemas.attachment_agent_schema import (
    AttachmentAgentResult,
    AttachmentAnalysisItem,
    AttachmentEvidence,
    AttachmentEvidenceItem,
    AttachmentFeatureAvailability,
    AttachmentFeatures,
)
from app.schemas.email_schema import (
    AttachmentDisposition,
    AttachmentMetadata,
    AttachmentStatus,
    EmailData,
)

_SENTINEL = object()
OVERSIZED_THRESHOLD_BYTES = 10 * 1024 * 1024  # 10 MB


# ---------------------------------------------------------------------------
# 1. Immutable Boundary Validation Record (Architecture B)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ValidatedAttachmentRecord:
    """
    Immutable boundary record caching validated attachment metadata fields.
    Ensures zero secondary property access on AttachmentMetadata downstream.
    """
    filename: str
    content_type: str
    extension: Optional[str]
    size_bytes: int
    disposition: AttachmentDisposition
    status: AttachmentStatus
    skip_reason: Optional[str]
    raw_filename: Optional[str]


# ---------------------------------------------------------------------------
# 2. Dedicated Top-Level Processing Exception
# ---------------------------------------------------------------------------

class AttachmentAgentProcessingError(Exception):
    """
    Raised when an unrecoverable internal crash occurs during attachment analysis.
    Preserves original email_id, total attachments, chained cause, and traceback.
    """
    def __init__(
        self,
        message: str,
        email_id: Optional[str] = None,
        total_attachments_evaluated: int = 0,
        original_exception: Optional[Exception] = None,
        traceback_str: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.email_id = email_id
        self.total_attachments_evaluated = total_attachments_evaluated
        self.original_exception = original_exception
        self.traceback_str = traceback_str or ""


# ---------------------------------------------------------------------------
# 3. Single-Access Caller Attribute Retrieval Helper
# ---------------------------------------------------------------------------

def _get_caller_attribute(target: Any, attr_name: str) -> Any:
    """
    Retrieve an attribute from target exactly once.
    Disambiguates genuinely missing attributes from descriptor crashes.
    """
    try:
        return getattr(target, attr_name)
    except AttributeError as exc:
        static_val = inspect.getattr_static(target, attr_name, _SENTINEL)
        if static_val is not _SENTINEL:
            raise AttributeError(
                f"Error accessing '{attr_name}' on {type(target).__name__}: "
                f"property or descriptor getter raised AttributeError: {exc}"
            ) from exc

        exc_attr_name = getattr(exc, "name", None)
        if exc_attr_name is not None and exc_attr_name != attr_name:
            raise AttributeError(
                f"Error accessing '{attr_name}' on {type(target).__name__}: "
                f"internal lookup raised AttributeError for '{exc_attr_name}': {exc}"
            ) from exc

        raise AttributeError(
            f"Invalid input: {type(target).__name__} missing required attribute '{attr_name}'."
        ) from exc


def sanitize_snippet(raw: str, max_len: int = 256) -> str:
    """Clean and bound raw strings for safe evidence presentation."""
    if not raw:
        return ""
    clean = " ".join(raw.replace("\r", " ").replace("\n", " ").split())
    clean = html.escape(clean)
    if len(clean) > max_len:
        clean = clean[: max_len - 3] + "..."
    return clean


# ---------------------------------------------------------------------------
# 4. State 1: Verified Absence of Attachments (Success)
# ---------------------------------------------------------------------------

def create_no_attachment_result(email_id: str) -> AttachmentAgentResult:
    """
    Construct a deterministic result representing verified absence of attachments.
    """
    features = AttachmentFeatures(
        total_attachment_count=0,
        has_attachments=False,
    )
    availability = AttachmentFeatureAvailability(
        avail_has_attachments=False,
        avail_metadata_features=False,
        avail_mime_classification=False,
        completeness_risk_types=0.0,
        completeness_spoofing=0.0,
        completeness_container=0.0,
        completeness_total=0.0,
    )
    evidence = AttachmentEvidence(
        evidence_items=[],
        omitted_evidence_count=0,
        observed_anomalies=[],
    )
    return AttachmentAgentResult(
        email_id=email_id,
        agent_name="attachment_agent",
        agent_version="1.0.0",
        status="success",
        processing_time_ms=0.0,
        total_attachments_evaluated=0,
        features=features,
        availability=availability,
        evidence=evidence,
        analysis_items=[],
        warnings=[],
        limitations=[
            "Zero email attachments extracted; attachment modality feature vector reflects observed absence."
        ],
    )


# ---------------------------------------------------------------------------
# 5. State 2: Attachment Analysis Pipeline
# ---------------------------------------------------------------------------

def execute_attachment_analysis_pipeline(
    email_id: str,
    records: List[ValidatedAttachmentRecord],
) -> AttachmentAgentResult:
    """
    Execute full deterministic attachment analysis across all ValidatedAttachmentRecords.
    """
    start_time = time.perf_counter()
    total_count = len(records)
    warnings: list[str] = []

    # Category A accumulators
    exec_count = 0
    macro_count = 0

    # Category B accumulators
    html_smuggle_count = 0
    double_ext_count = 0
    rlo_count = 0
    mime_diff_count = 0

    # Category C accumulators
    archive_count = 0
    disk_image_count = 0
    enc_archive_count = 0
    suspicious_archive_count = 0

    # Category D accumulators
    total_size = 0
    max_size = 0
    zero_byte_count = 0
    oversized_count = 0
    skipped_count = 0

    analysis_items: List[AttachmentAnalysisItem] = []
    evidence_items_raw: List[AttachmentEvidenceItem] = []
    observed_anomalies: set[str] = set()

    for idx, rec in enumerate(records):
        size = rec.size_bytes
        total_size += size
        max_size = max(max_size, size)

        if size == 0:
            zero_byte_count += 1
            observed_anomalies.add("Zero-byte attachment detected")
        elif size > OVERSIZED_THRESHOLD_BYTES:
            oversized_count += 1
            observed_anomalies.add("Oversized attachment (>10 MB) detected")

        if rec.status != AttachmentStatus.PROCESSED:
            skipped_count += 1
            observed_anomalies.add(f"Attachment skipped by extractor: {rec.status.value}")

        # Static file classification
        cls_res = classify_attachment(
            filename=rec.filename,
            content_type=rec.content_type,
            extension=rec.extension,
            raw_filename=rec.raw_filename,
            skip_reason=rec.skip_reason,
        )

        if cls_res.is_executable:
            exec_count += 1
            observed_anomalies.add("High-risk executable attachment detected")
            evidence_items_raw.append(
                AttachmentEvidenceItem(
                    finding_id=f"att_exec_{idx}",
                    feature_name="has_executable_attachment",
                    category="Category A: High-Risk Types & Scripts",
                    attachment_index=idx,
                    observed_value=f".{cls_res.extension or 'unknown'}",
                    description=f"Attachment '{rec.filename}' has a high-risk executable or script extension.",
                    snippet_bounded=sanitize_snippet(rec.filename, 256),
                )
            )

        if cls_res.is_macro_enabled:
            macro_count += 1
            observed_anomalies.add("Macro-enabled Office document detected")
            evidence_items_raw.append(
                AttachmentEvidenceItem(
                    finding_id=f"att_macro_{idx}",
                    feature_name="has_macro_enabled_attachment",
                    category="Category A: High-Risk Types & Scripts",
                    attachment_index=idx,
                    observed_value=f".{cls_res.extension or 'unknown'}",
                    description=f"Attachment '{rec.filename}' is a macro-enabled Office format capable of executing VBA payloads.",
                    snippet_bounded=sanitize_snippet(rec.filename, 256),
                )
            )

        if cls_res.is_html_smuggling:
            html_smuggle_count += 1
            observed_anomalies.add("HTML smuggling vector format detected")
            evidence_items_raw.append(
                AttachmentEvidenceItem(
                    finding_id=f"att_smuggle_{idx}",
                    feature_name="has_html_smuggling_attachment",
                    category="Category B: Evasion, Smuggling & Spoofing",
                    attachment_index=idx,
                    observed_value=f".{cls_res.extension or 'unknown'}",
                    description=f"Attachment '{rec.filename}' uses web markup format prone to HTML smuggling.",
                    snippet_bounded=sanitize_snippet(rec.filename, 256),
                )
            )

        if cls_res.has_double_extension:
            double_ext_count += 1
            observed_anomalies.add("Deceptive double extension detected")
            evidence_items_raw.append(
                AttachmentEvidenceItem(
                    finding_id=f"att_double_ext_{idx}",
                    feature_name="has_double_extension",
                    category="Category B: Evasion, Smuggling & Spoofing",
                    attachment_index=idx,
                    observed_value="Deceptive extension pattern",
                    description=f"Attachment '{rec.filename}' uses deceptive secondary extension to mask executable nature.",
                    snippet_bounded=sanitize_snippet(rec.filename, 256),
                )
            )

        if cls_res.has_rlo_spoofing:
            rlo_count += 1
            observed_anomalies.add("Right-to-Left Override spoofing detected")
            evidence_items_raw.append(
                AttachmentEvidenceItem(
                    finding_id=f"att_rlo_{idx}",
                    feature_name="has_rlo_spoofing",
                    category="Category B: Evasion, Smuggling & Spoofing",
                    attachment_index=idx,
                    observed_value="Unicode RLO character (U+202E)",
                    description=f"Attachment '{rec.filename}' contains directional override spoofing characters.",
                    snippet_bounded=sanitize_snippet(rec.raw_filename or rec.filename, 256),
                )
            )

        if cls_res.has_mime_mismatch:
            mime_diff_count += 1
            observed_anomalies.add("MIME type vs. file extension conflict detected")
            evidence_items_raw.append(
                AttachmentEvidenceItem(
                    finding_id=f"att_mime_{idx}",
                    feature_name="has_mime_mismatch",
                    category="Category B: Evasion, Smuggling & Spoofing",
                    attachment_index=idx,
                    observed_value=f"{rec.content_type} vs .{cls_res.extension or ''}",
                    description=f"Declared MIME type '{rec.content_type}' conflicts with extension '.{cls_res.extension or ''}'.",
                    snippet_bounded=sanitize_snippet(f"{rec.filename} [{rec.content_type}]", 256),
                )
            )

        if cls_res.is_archive:
            archive_count += 1

        if cls_res.is_disk_image:
            disk_image_count += 1
            observed_anomalies.add("Disk image container detected")

        if cls_res.is_encrypted:
            enc_archive_count += 1
            observed_anomalies.add("Encrypted/password-protected archive detected")

        if cls_res.is_archive and (cls_res.has_double_extension or cls_res.is_executable):
            suspicious_archive_count += 1

        # Granular item (max 50)
        if len(analysis_items) < 50:
            analysis_items.append(
                AttachmentAnalysisItem(
                    attachment_index=idx,
                    filename_snippet=sanitize_snippet(rec.filename, 256),
                    content_type=rec.content_type,
                    extension=cls_res.extension,
                    size_bytes=rec.size_bytes,
                    is_executable=cls_res.is_executable,
                    is_macro_enabled=cls_res.is_macro_enabled,
                    is_html_smuggling=cls_res.is_html_smuggling,
                    has_double_extension=cls_res.has_double_extension,
                    has_rlo_spoofing=cls_res.has_rlo_spoofing,
                    has_mime_mismatch=cls_res.has_mime_mismatch,
                    is_archive=cls_res.is_archive,
                    is_disk_image=cls_res.is_disk_image,
                    is_encrypted=cls_res.is_encrypted,
                    status=rec.status.value,
                )
            )

    if total_count > 50:
        warnings.append(
            f"Email contains {total_count} attachments; granular inspection records capped to first 50 per safety budget."
        )

    # Construct canonical 25-feature vector
    features = AttachmentFeatures(
        # Category A: High-Risk Types & Scripts
        total_attachment_count=total_count,
        has_attachments=True,
        has_executable_attachment=bool(exec_count > 0),
        executable_attachment_count=exec_count,
        has_macro_enabled_attachment=bool(macro_count > 0),
        macro_enabled_count=macro_count,
        # Category B: Evasion, Smuggling & Spoofing
        has_html_smuggling_attachment=bool(html_smuggle_count > 0),
        html_smuggling_count=html_smuggle_count,
        has_double_extension=bool(double_ext_count > 0),
        double_extension_count=double_ext_count,
        has_rlo_spoofing=bool(rlo_count > 0),
        rlo_spoofing_count=rlo_count,
        has_mime_mismatch=bool(mime_diff_count > 0),
        mime_mismatch_count=mime_diff_count,
        # Category C: Archives & Containers
        has_archive_attachment=bool(archive_count > 0),
        archive_attachment_count=archive_count,
        has_disk_image=bool(disk_image_count > 0),
        has_encrypted_archive=bool(enc_archive_count > 0),
        has_suspicious_archive=bool(suspicious_archive_count > 0),
        # Category D: Size & Volumetric Properties
        total_attachment_size_bytes=total_size,
        max_attachment_size_bytes=max_size,
        has_oversized_attachment=bool(oversized_count > 0),
        has_zero_byte_attachment=bool(zero_byte_count > 0),
        has_skipped_attachments=bool(skipped_count > 0),
        skipped_attachment_count=skipped_count,
    )

    availability = AttachmentFeatureAvailability(
        avail_has_attachments=True,
        avail_metadata_features=True,
        avail_mime_classification=True,
        completeness_risk_types=1.0,
        completeness_spoofing=1.0,
        completeness_container=1.0,
        completeness_total=1.0,
    )

    capped_evidence = evidence_items_raw[:100]
    omitted_count = max(0, len(evidence_items_raw) - 100)
    capped_anomalies = sorted(observed_anomalies)[:100]

    evidence = AttachmentEvidence(
        evidence_items=capped_evidence,
        omitted_evidence_count=omitted_count,
        observed_anomalies=capped_anomalies,
    )

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    return AttachmentAgentResult(
        email_id=email_id,
        agent_name="attachment_agent",
        agent_version="1.0.0",
        status="success",
        processing_time_ms=elapsed_ms,
        total_attachments_evaluated=total_count,
        features=features,
        availability=availability,
        evidence=evidence,
        analysis_items=analysis_items,
        warnings=warnings,
        limitations=[
            "Static metadata and extension analysis; attachments are never executed, unpacked, or dynamically evaluated."
        ],
    )


# ---------------------------------------------------------------------------
# 6. Public Entrypoint: analyze_attachments
# ---------------------------------------------------------------------------

def analyze_attachments(email_data: EmailData) -> AttachmentAgentResult:
    """
    Public analysis entrypoint for the Attachment Specialist Agent.

    Strict caller contracts:
      1. email_data must be an EmailData instance or legitimate subclass.
      2. email_data.email_id must be a non-empty, non-whitespace string.
      3. email_data.attachments must be a list of AttachmentMetadata instances.
    """
    # 1.1 Strict caller contract check
    if not isinstance(email_data, EmailData):
        raise TypeError(
            f"Invalid input: analyze_attachments requires an EmailData instance or legitimate subclass, "
            f"got {type(email_data).__name__}."
        )

    # 1.2 Single-access retrieval of email_id
    email_id = _get_caller_attribute(email_data, "email_id")
    if not isinstance(email_id, str) or not email_id.strip():
        raise ValueError(
            f"Invalid input: email_data.email_id must be a non-empty, non-whitespace string "
            f"(got {type(email_id).__name__}: {email_id!r})."
        )

    # 1.3 Boundary validation of attachments collection (Architecture B)
    raw_attachments = _get_caller_attribute(email_data, "attachments")
    if not isinstance(raw_attachments, list):
        raise TypeError(
            f"Invalid input: email_data.attachments must be a list of AttachmentMetadata instances "
            f"(got {type(raw_attachments).__name__})."
        )

    validated_records: List[ValidatedAttachmentRecord] = []
    for idx, item in enumerate(raw_attachments):
        if not isinstance(item, AttachmentMetadata):
            raise TypeError(
                f"Invalid input: email_data.attachments[{idx}] must be an AttachmentMetadata instance "
                f"or legitimate subclass, got {type(item).__name__}."
            )

        filename = _get_caller_attribute(item, "filename")
        if filename is not None and not isinstance(filename, str):
            raise TypeError(
                f"Invalid input: email_data.attachments[{idx}].filename must be None or str (got {type(filename).__name__})."
            )

        content_type = _get_caller_attribute(item, "content_type")
        if content_type is not None and not isinstance(content_type, str):
            raise TypeError(
                f"Invalid input: email_data.attachments[{idx}].content_type must be None or str (got {type(content_type).__name__})."
            )

        extension = _get_caller_attribute(item, "extension")
        if extension is not None and not isinstance(extension, str):
            raise TypeError(
                f"Invalid input: email_data.attachments[{idx}].extension must be None or str (got {type(extension).__name__})."
            )

        size_bytes = _get_caller_attribute(item, "size_bytes")
        if not isinstance(size_bytes, int) or size_bytes < 0:
            raise ValueError(
                f"Invalid input: email_data.attachments[{idx}].size_bytes must be a non-negative integer (got {size_bytes!r})."
            )

        disposition = _get_caller_attribute(item, "disposition")
        if not isinstance(disposition, AttachmentDisposition):
            raise TypeError(
                f"Invalid input: email_data.attachments[{idx}].disposition must be AttachmentDisposition (got {type(disposition).__name__})."
            )

        status = _get_caller_attribute(item, "status")
        if not isinstance(status, AttachmentStatus):
            raise TypeError(
                f"Invalid input: email_data.attachments[{idx}].status must be AttachmentStatus (got {type(status).__name__})."
            )

        skip_reason = _get_caller_attribute(item, "skip_reason")
        if skip_reason is not None and not isinstance(skip_reason, str):
            raise TypeError(
                f"Invalid input: email_data.attachments[{idx}].skip_reason must be None or str (got {type(skip_reason).__name__})."
            )

        raw_filename = _get_caller_attribute(item, "raw_filename")
        if raw_filename is not None and not isinstance(raw_filename, str):
            raise TypeError(
                f"Invalid input: email_data.attachments[{idx}].raw_filename must be None or str (got {type(raw_filename).__name__})."
            )

        validated_records.append(
            ValidatedAttachmentRecord(
                filename=filename or "",
                content_type=content_type or "",
                extension=extension,
                size_bytes=size_bytes,
                disposition=disposition,
                status=status,
                skip_reason=skip_reason,
                raw_filename=raw_filename,
            )
        )

    # Step 2: Unified fail-closed execution
    try:
        if len(validated_records) == 0:
            return create_no_attachment_result(email_id=email_id)

        return execute_attachment_analysis_pipeline(
            email_id=email_id,
            records=validated_records,
        )
    except Exception as exc:
        tb_str = traceback.format_exc()
        raise AttachmentAgentProcessingError(
            message=f"Attachment Agent internal processing failed for email {email_id}: {type(exc).__name__}: {exc}",
            email_id=email_id,
            total_attachments_evaluated=len(validated_records),
            original_exception=exc,
            traceback_str=tb_str,
        ) from exc
