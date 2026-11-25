"""
app/aggregation/evidence_aggregator.py
--------------------------------------
Layer 2 Evidence Aggregator for the Hierarchical Multi-Agent AI Phishing Email Detector.

Responsibilities:
1. Strict Input Contract & Partial-Failure Resilience:
   - Accept the outputs of all 4 Layer 1 specialist agents.
   - Validate email_id consistency across all provided results (fail-closed with EvidenceAggregationError).
   - Gracefully tolerate individual agent failures or missing modalities without crashing.
2. Deterministic Feature Vector Assembly:
   - Extract and assemble exactly 132 active (non-quarantined) canonical features in fixed order.
   - Strictly exclude quarantined features from the ML vector.
   - Numerically encode features and missingness masks (0.0 and 1 for missing/imputed).
3. Modality Health & Completeness Assessment:
   - Assess health status (AVAILABLE, EMPTY, DEGRADED, FAILED) and completeness for each modality.
   - Compute overall weighted completeness.
   - Determine whether downstream meta-classification should abstain due to severe modality degradation.
4. Unified Forensic Evidence Trail (Tier 2):
   - Merge evidence findings from all active agents into normalized UnifiedEvidenceItem records.
   - Deterministically sort by severity, modality, and feature name.
   - Enforce capacity cap of 150 items with omitted count tracking.
"""

from __future__ import annotations

import time
from typing import Any, Optional, Tuple

from app.schemas.email_schema import AuthStatus
from app.schemas.header_agent_schema import HeaderAgentResult
from app.schemas.url_agent_schema import UrlAgentResult
from app.schemas.text_agent_schema import TextAgentResult
from app.schemas.attachment_agent_schema import AttachmentAgentResult
from app.schemas.aggregator_schema import (
    ACTIVE_META_FEATURE_COUNT,
    ACTIVE_META_FEATURE_NAMES,
    ATTACHMENT_ACTIVE_FEATURES,
    HEADER_ACTIVE_FEATURES,
    MODALITY_NAMES,
    MODALITY_WEIGHTS,
    QUARANTINED_META_FEATURE_COUNT,
    TEXT_ACTIVE_FEATURES,
    URL_ACTIVE_FEATURES,
    AggregatedEvidenceResult,
    MetaFeatureVector,
    ModalityHealth,
    ModalityStatus,
    UnifiedEvidenceItem,
)


class EvidenceAggregationError(Exception):
    """
    Raised when the Evidence Aggregator encounters unrecoverable input contract
    violations or processing failures.
    """
    def __init__(self, message: str, email_id: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.email_id = email_id


def _encode_feature_value(val: Any) -> Tuple[float, int]:
    """
    Encodes an arbitrary feature value into (float_value, missingness_bit).

    Missingness mask:
    - 0: Value was observed/computed
    - 1: Value was missing, None, or uncomputable (imputed to 0.0)
    """
    if val is None:
        return 0.0, 1

    if isinstance(val, bool):
        return (1.0 if val else 0.0), 0

    if isinstance(val, (int, float)):
        return float(val), 0

    if isinstance(val, AuthStatus):
        if val in (AuthStatus.MISSING, AuthStatus.UNAVAILABLE):
            return 0.0, 1
        if val == AuthStatus.PASS:
            return 1.0, 0
        if val == AuthStatus.SOFTFAIL:
            return -0.5, 0
        if val in (AuthStatus.FAIL, AuthStatus.PERMERROR):
            return -1.0, 0
        if val == AuthStatus.TEMPERROR:
            return -0.25, 0
        # NEUTRAL, NONE, OTHER
        return 0.0, 0

    try:
        return float(val), 0
    except (ValueError, TypeError):
        return 0.0, 1


def aggregate_evidence(
    header_result: Optional[HeaderAgentResult] = None,
    url_result: Optional[UrlAgentResult] = None,
    text_result: Optional[TextAgentResult] = None,
    attachment_result: Optional[AttachmentAgentResult] = None,
) -> AggregatedEvidenceResult:
    """
    Synthesizes the outputs of the four Layer 1 specialist agents into a unified,
    leakage-free Tier 3 meta-feature vector, modality health manifest, and
    capacity-capped Tier 2 forensic evidence trail.

    Parameters:
        header_result: Result from Header Agent (or None if unexecuted).
        url_result: Result from URL Agent (or None if unexecuted).
        text_result: Result from Text/Body Agent (or None if unexecuted).
        attachment_result: Result from Attachment Agent (or None if unexecuted).

    Returns:
        AggregatedEvidenceResult conforming strictly to the Layer 2 schema contract.

    Raises:
        EvidenceAggregationError: If all 4 inputs are None, if email_id is missing,
            or if email_id values mismatch across provided agent results.
    """
    start_time = time.perf_counter()

    # -----------------------------------------------------------------------
    # Step 1: Input Validation and Consistency Enforcement
    # -----------------------------------------------------------------------
    inputs = {
        "header": header_result,
        "url": url_result,
        "text": text_result,
        "attachment": attachment_result,
    }

    active_inputs = {mod: res for mod, res in inputs.items() if res is not None}
    if not active_inputs:
        raise EvidenceAggregationError(
            "At least one agent result must be provided to the Evidence Aggregator"
        )

    # Validate non-empty string email_id and check cross-modality equality
    observed_email_ids: dict[str, str] = {}
    for mod, res in active_inputs.items():
        eid = getattr(res, "email_id", None)
        if not eid or not isinstance(eid, str) or not eid.strip():
            raise EvidenceAggregationError(
                f"Agent result for modality '{mod}' contains missing or invalid email_id"
            )
        observed_email_ids[mod] = eid

    unique_ids = set(observed_email_ids.values())
    if len(unique_ids) > 1:
        primary_id = next(iter(unique_ids))
        raise EvidenceAggregationError(
            f"Mismatched email_id across agent results: {observed_email_ids}",
            email_id=primary_id,
        )

    email_id = next(iter(unique_ids))
    warnings: list[str] = []

    # -----------------------------------------------------------------------
    # Step 2: Modality Health and Active Feature Extraction
    # -----------------------------------------------------------------------
    feature_values: dict[str, float] = {}
    missingness_mask: dict[str, int] = {}
    modality_health: dict[str, ModalityHealth] = {}
    raw_evidence_items: list[UnifiedEvidenceItem] = []

    # --- 2A: Header Modality (41 active features) ---
    if header_result is None:
        modality_health["header"] = ModalityHealth(
            modality="header",
            status=ModalityStatus.FAILED,
            completeness=0.0,
            active_feature_count=len(HEADER_ACTIVE_FEATURES),
            missing_feature_count=len(HEADER_ACTIVE_FEATURES),
            error_message="Header agent result was not provided.",
        )
        for f_name in HEADER_ACTIVE_FEATURES:
            feature_values[f"header_{f_name}"] = 0.0
            missingness_mask[f"header_{f_name}"] = 1
        warnings.append("Header agent result missing; imputed 41 features to 0.0 with missingness mask 1.")
    elif header_result.status == "error":
        modality_health["header"] = ModalityHealth(
            modality="header",
            status=ModalityStatus.FAILED,
            completeness=0.0,
            active_feature_count=len(HEADER_ACTIVE_FEATURES),
            missing_feature_count=len(HEADER_ACTIVE_FEATURES),
            error_message=getattr(header_result, "error_message", None) or "Header agent failed with error status.",
        )
        for f_name in HEADER_ACTIVE_FEATURES:
            feature_values[f"header_{f_name}"] = 0.0
            missingness_mask[f"header_{f_name}"] = 1
        warnings.append("Header agent returned error status; imputed 41 features to 0.0 with missingness mask 1.")
    else:
        # Extract features
        missing_count = 0
        for f_name in HEADER_ACTIVE_FEATURES:
            raw_val = getattr(header_result.features, f_name, None)
            f_val, mask_bit = _encode_feature_value(raw_val)
            feature_values[f"header_{f_name}"] = f_val
            missingness_mask[f"header_{f_name}"] = mask_bit
            if mask_bit == 1:
                missing_count += 1

        comp = getattr(header_result.availability, "completeness_total", 0.0)
        from_present = getattr(header_result.features, "from_present", False)
        hop_count = getattr(header_result.features, "received_hop_count", 0)
        subj_len = getattr(header_result.features, "subject_length", 0)

        if not from_present and hop_count == 0 and subj_len == 0:
            h_status = ModalityStatus.EMPTY
        elif header_result.status == "partial" or comp < 0.60:
            h_status = ModalityStatus.DEGRADED
        else:
            h_status = ModalityStatus.AVAILABLE

        modality_health["header"] = ModalityHealth(
            modality="header",
            status=h_status,
            completeness=comp,
            active_feature_count=len(HEADER_ACTIVE_FEATURES),
            missing_feature_count=missing_count,
        )

        # Collect Header evidence
        if header_result.evidence and header_result.evidence.evidence_items:
            for idx, item in enumerate(header_result.evidence.evidence_items):
                desc_lower = item.description.lower()
                if "fail" in desc_lower or "mismatch" in desc_lower or "spoof" in desc_lower:
                    sev = "high"
                else:
                    sev = "medium"

                raw_evidence_items.append(
                    UnifiedEvidenceItem(
                        finding_id=f"ev_header_{idx + 1:03d}",
                        source_modality="header",
                        feature_name=item.feature_name,
                        category="Header Analysis",
                        severity=sev,
                        observed_value=item.description,
                        description=item.description,
                        snippet_bounded=(item.raw_snippet_bounded or "")[:256],
                    )
                )

    # --- 2B: URL Modality (37 active features) ---
    if url_result is None:
        modality_health["url"] = ModalityHealth(
            modality="url",
            status=ModalityStatus.FAILED,
            completeness=0.0,
            active_feature_count=len(URL_ACTIVE_FEATURES),
            missing_feature_count=len(URL_ACTIVE_FEATURES),
            error_message="URL agent result was not provided.",
        )
        for f_name in URL_ACTIVE_FEATURES:
            feature_values[f"url_{f_name}"] = 0.0
            missingness_mask[f"url_{f_name}"] = 1
        warnings.append("URL agent result missing; imputed 37 features to 0.0 with missingness mask 1.")
    elif url_result.status == "error":
        modality_health["url"] = ModalityHealth(
            modality="url",
            status=ModalityStatus.FAILED,
            completeness=0.0,
            active_feature_count=len(URL_ACTIVE_FEATURES),
            missing_feature_count=len(URL_ACTIVE_FEATURES),
            error_message=getattr(url_result, "error_message", None) or "URL agent failed with error status.",
        )
        for f_name in URL_ACTIVE_FEATURES:
            feature_values[f"url_{f_name}"] = 0.0
            missingness_mask[f"url_{f_name}"] = 1
        warnings.append("URL agent returned error status; imputed 37 features to 0.0 with missingness mask 1.")
    else:
        missing_count = 0
        for f_name in URL_ACTIVE_FEATURES:
            raw_val = getattr(url_result.features, f_name, None)
            f_val, mask_bit = _encode_feature_value(raw_val)
            feature_values[f"url_{f_name}"] = f_val
            missingness_mask[f"url_{f_name}"] = mask_bit
            if mask_bit == 1:
                missing_count += 1

        comp = getattr(url_result.availability, "completeness_total", 0.0)
        if url_result.total_urls_extracted == 0:
            u_status = ModalityStatus.EMPTY
        elif url_result.status == "partial" or comp < 0.60:
            u_status = ModalityStatus.DEGRADED
        else:
            u_status = ModalityStatus.AVAILABLE

        modality_health["url"] = ModalityHealth(
            modality="url",
            status=u_status,
            completeness=comp,
            active_feature_count=len(URL_ACTIVE_FEATURES),
            missing_feature_count=missing_count,
        )

        # Collect URL evidence
        if url_result.evidence and url_result.evidence.evidence_items:
            for idx, item in enumerate(url_result.evidence.evidence_items):
                fn = item.feature_name.lower()
                if any(w in fn for w in ["ip_literal", "mismatch", "at_symbol", "punycode", "credentials"]):
                    sev = "high"
                else:
                    sev = "medium"

                raw_evidence_items.append(
                    UnifiedEvidenceItem(
                        finding_id=item.finding_id or f"ev_url_{idx + 1:03d}",
                        source_modality="url",
                        feature_name=item.feature_name,
                        category=item.category or "URL Analysis",
                        severity=sev,
                        observed_value=str(item.observed_value),
                        description=item.description,
                        snippet_bounded=(item.raw_snippet_bounded or "")[:256],
                    )
                )

    # --- 2C: Text Modality (29 active features) ---
    if text_result is None:
        modality_health["text"] = ModalityHealth(
            modality="text",
            status=ModalityStatus.FAILED,
            completeness=0.0,
            active_feature_count=len(TEXT_ACTIVE_FEATURES),
            missing_feature_count=len(TEXT_ACTIVE_FEATURES),
            error_message="Text agent result was not provided.",
        )
        for f_name in TEXT_ACTIVE_FEATURES:
            feature_values[f"text_{f_name}"] = 0.0
            missingness_mask[f"text_{f_name}"] = 1
        warnings.append("Text agent result missing; imputed 29 features to 0.0 with missingness mask 1.")
    elif text_result.status == "error":
        modality_health["text"] = ModalityHealth(
            modality="text",
            status=ModalityStatus.FAILED,
            completeness=0.0,
            active_feature_count=len(TEXT_ACTIVE_FEATURES),
            missing_feature_count=len(TEXT_ACTIVE_FEATURES),
            error_message=getattr(text_result, "error_message", None) or "Text agent failed with error status.",
        )
        for f_name in TEXT_ACTIVE_FEATURES:
            feature_values[f"text_{f_name}"] = 0.0
            missingness_mask[f"text_{f_name}"] = 1
        warnings.append("Text agent returned error status; imputed 29 features to 0.0 with missingness mask 1.")
    else:
        missing_count = 0
        for f_name in TEXT_ACTIVE_FEATURES:
            raw_val = getattr(text_result.features, f_name, None)
            f_val, mask_bit = _encode_feature_value(raw_val)
            feature_values[f"text_{f_name}"] = f_val
            missingness_mask[f"text_{f_name}"] = mask_bit
            if mask_bit == 1:
                missing_count += 1

        comp = getattr(text_result.availability, "completeness_total", 0.0)
        has_body = getattr(text_result.features, "has_body", False)
        if not has_body:
            t_status = ModalityStatus.EMPTY
        elif text_result.status == "partial" or comp < 0.60:
            t_status = ModalityStatus.DEGRADED
        else:
            t_status = ModalityStatus.AVAILABLE

        modality_health["text"] = ModalityHealth(
            modality="text",
            status=t_status,
            completeness=comp,
            active_feature_count=len(TEXT_ACTIVE_FEATURES),
            missing_feature_count=missing_count,
        )

        # Collect Text evidence
        if text_result.evidence and text_result.evidence.evidence_items:
            for idx, item in enumerate(text_result.evidence.evidence_items):
                fn = item.feature_name.lower()
                if any(w in fn for w in ["credential", "threat", "hidden", "zero_width"]):
                    sev = "high"
                else:
                    sev = "medium"

                raw_evidence_items.append(
                    UnifiedEvidenceItem(
                        finding_id=item.finding_id or f"ev_text_{idx + 1:03d}",
                        source_modality="text",
                        feature_name=item.feature_name,
                        category=item.category or "Text Analysis",
                        severity=sev,
                        observed_value=str(item.observed_value),
                        description=item.description,
                        snippet_bounded=(item.snippet_bounded or "")[:256],
                    )
                )

    # --- 2D: Attachment Modality (25 active features) ---
    if attachment_result is None:
        modality_health["attachment"] = ModalityHealth(
            modality="attachment",
            status=ModalityStatus.FAILED,
            completeness=0.0,
            active_feature_count=len(ATTACHMENT_ACTIVE_FEATURES),
            missing_feature_count=len(ATTACHMENT_ACTIVE_FEATURES),
            error_message="Attachment agent result was not provided.",
        )
        for f_name in ATTACHMENT_ACTIVE_FEATURES:
            feature_values[f"attachment_{f_name}"] = 0.0
            missingness_mask[f"attachment_{f_name}"] = 1
        warnings.append("Attachment agent result missing; imputed 25 features to 0.0 with missingness mask 1.")
    elif attachment_result.status == "error":
        modality_health["attachment"] = ModalityHealth(
            modality="attachment",
            status=ModalityStatus.FAILED,
            completeness=0.0,
            active_feature_count=len(ATTACHMENT_ACTIVE_FEATURES),
            missing_feature_count=len(ATTACHMENT_ACTIVE_FEATURES),
            error_message=getattr(attachment_result, "error_message", None) or "Attachment agent failed with error status.",
        )
        for f_name in ATTACHMENT_ACTIVE_FEATURES:
            feature_values[f"attachment_{f_name}"] = 0.0
            missingness_mask[f"attachment_{f_name}"] = 1
        warnings.append("Attachment agent returned error status; imputed 25 features to 0.0 with missingness mask 1.")
    else:
        missing_count = 0
        for f_name in ATTACHMENT_ACTIVE_FEATURES:
            raw_val = getattr(attachment_result.features, f_name, None)
            f_val, mask_bit = _encode_feature_value(raw_val)
            feature_values[f"attachment_{f_name}"] = f_val
            missingness_mask[f"attachment_{f_name}"] = mask_bit
            if mask_bit == 1:
                missing_count += 1

        comp = getattr(attachment_result.availability, "completeness_total", 0.0)
        has_att = getattr(attachment_result.features, "has_attachments", False)
        if not has_att:
            a_status = ModalityStatus.EMPTY
        elif attachment_result.status == "partial" or comp < 0.60:
            a_status = ModalityStatus.DEGRADED
        else:
            a_status = ModalityStatus.AVAILABLE

        modality_health["attachment"] = ModalityHealth(
            modality="attachment",
            status=a_status,
            completeness=comp,
            active_feature_count=len(ATTACHMENT_ACTIVE_FEATURES),
            missing_feature_count=missing_count,
        )

        # Collect Attachment evidence
        if attachment_result.evidence and attachment_result.evidence.evidence_items:
            for idx, item in enumerate(attachment_result.evidence.evidence_items):
                fn = item.feature_name.lower()
                if "executable" in fn or "macro" in fn:
                    sev = "critical"
                elif any(w in fn for w in ["smuggling", "double_extension", "rlo", "mime_mismatch"]):
                    sev = "high"
                else:
                    sev = "medium"

                raw_evidence_items.append(
                    UnifiedEvidenceItem(
                        finding_id=item.finding_id or f"ev_attach_{idx + 1:03d}",
                        source_modality="attachment",
                        feature_name=item.feature_name,
                        category=item.category or "Attachment Analysis",
                        severity=sev,
                        observed_value=str(item.observed_value),
                        description=item.description,
                        snippet_bounded=(item.snippet_bounded or "")[:256],
                    )
                )

    # -----------------------------------------------------------------------
    # Step 3: Meta-Feature Vector Construction
    # -----------------------------------------------------------------------
    total_missing = sum(missingness_mask.values())
    meta_vector = MetaFeatureVector(
        feature_names=list(ACTIVE_META_FEATURE_NAMES),
        feature_values=feature_values,
        missingness_mask=missingness_mask,
        active_feature_count=ACTIVE_META_FEATURE_COUNT,
        quarantined_feature_count=QUARANTINED_META_FEATURE_COUNT,
        missing_feature_count=total_missing,
    )

    # -----------------------------------------------------------------------
    # Step 4: Overall Completeness & Abstention Policy
    # -----------------------------------------------------------------------
    raw_comp = sum(MODALITY_WEIGHTS[m] * modality_health[m].completeness for m in MODALITY_NAMES)
    overall_completeness = round(min(1.0, max(0.0, raw_comp)), 4)

    h_hdr = modality_health["header"]
    h_txt = modality_health["text"]

    hdr_bad = h_hdr.status in (ModalityStatus.FAILED, ModalityStatus.DEGRADED, ModalityStatus.EMPTY)
    txt_bad = h_txt.status in (ModalityStatus.FAILED, ModalityStatus.DEGRADED, ModalityStatus.EMPTY)
    both_core_bad = hdr_bad and txt_bad

    core_low_comp = ((h_hdr.completeness + h_txt.completeness) / 2.0) < 0.50
    overall_low_comp = overall_completeness < 0.40
    failed_modality_count = sum(1 for h in modality_health.values() if h.status == ModalityStatus.FAILED)
    too_many_failed = failed_modality_count >= 3

    abstention_recommended = bool(both_core_bad or core_low_comp or overall_low_comp or too_many_failed)

    # -----------------------------------------------------------------------
    # Step 5: Unified Forensic Evidence Deduplication & Deterministic Sorting
    # -----------------------------------------------------------------------
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    mod_rank = {"header": 0, "url": 1, "text": 2, "attachment": 3}

    sorted_evidence = sorted(
        raw_evidence_items,
        key=lambda item: (
            sev_rank.get(item.severity, 2),
            mod_rank.get(item.source_modality, 9),
            item.feature_name,
            item.finding_id,
        ),
    )

    max_ev = 150
    if len(sorted_evidence) > max_ev:
        unified_evidence = sorted_evidence[:max_ev]
        omitted_evidence_count = len(sorted_evidence) - max_ev
        warnings.append(
            f"Evidence items exceeded capacity limit of {max_ev}; "
            f"omitted {omitted_evidence_count} lowest-priority findings."
        )
    else:
        unified_evidence = sorted_evidence
        omitted_evidence_count = 0

    # -----------------------------------------------------------------------
    # Step 6: Result Assembly
    # -----------------------------------------------------------------------
    # Determine overall status
    present_statuses = [res.status for res in active_inputs.values()]
    if all(s == "success" for s in present_statuses) and len(active_inputs) == 4:
        overall_status = "success"
    elif all(s == "error" for s in present_statuses):
        overall_status = "error"
    else:
        overall_status = "partial"

    # Append any warnings from active results
    for mod, res in active_inputs.items():
        if hasattr(res, "warnings") and res.warnings:
            for w in res.warnings:
                warnings.append(f"[{mod.upper()}] {w}")

    processing_time_ms = round((time.perf_counter() - start_time) * 1000, 3)

    return AggregatedEvidenceResult(
        email_id=email_id,
        status=overall_status,
        processing_time_ms=processing_time_ms,
        feature_vector=meta_vector,
        modality_health=modality_health,
        overall_completeness=overall_completeness,
        abstention_recommended_by_health=abstention_recommended,
        unified_evidence=unified_evidence,
        omitted_evidence_count=omitted_evidence_count,
        warnings=warnings,
    )
