"""
app/agents/text_agent.py
------------------------
Core Text/Body Specialist Agent for the Multi-Agent AI Phishing Email Detector.

Architecture & Contracts:
- Architecture B Boundary Validation: Validates all text inputs strictly once at
  the agent boundary into an immutable ValidatedTextRecord before downstream processing.
- Single-Access Introspection: Uses inspect.getattr_static to disambiguate missing
  attributes from descriptor getter crashes.
- Four-Tier Failure Handling: Caller input violations fail fast outside the processing try
  block; internal processing errors raise TextAgentProcessingError.
- Passive & Offline: Pure regex, heuristic, and statistical NLP with zero external calls.
"""

from __future__ import annotations

import html
import inspect
import time
import traceback
from dataclasses import dataclass
from typing import Any, List, Optional

from app.agents.text_components.intent_analyzer import analyze_body_intent
from app.agents.text_components.lexical_metrics import analyze_lexical_metrics
from app.agents.text_components.obfuscation_detector import analyze_obfuscation
from app.schemas.email_schema import EmailData
from app.schemas.text_agent_schema import (
    TextAgentResult,
    TextEvidence,
    TextEvidenceItem,
    TextFeatureAvailability,
    TextFeatures,
)

_SENTINEL = object()


# ---------------------------------------------------------------------------
# 1. Immutable Boundary Validation Record (Architecture B)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ValidatedTextRecord:
    """
    Immutable boundary record caching validated text components.
    Ensures zero secondary property access on EmailData downstream.
    """
    plain_text_body: Optional[str]
    html_body: Optional[str]
    cleaned_text: Optional[str]


# ---------------------------------------------------------------------------
# 2. Dedicated Top-Level Processing Exception
# ---------------------------------------------------------------------------

class TextAgentProcessingError(Exception):
    """
    Raised when an unrecoverable internal crash occurs during text analysis.
    Preserves original email_id, chained cause, and formatted traceback.
    """
    def __init__(
        self,
        message: str,
        email_id: Optional[str] = None,
        original_exception: Optional[Exception] = None,
        traceback_str: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.email_id = email_id
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
# 4. State 1: Verified Absence of Body Content (Success)
# ---------------------------------------------------------------------------

def create_no_body_result(email_id: str) -> TextAgentResult:
    """
    Construct a deterministic result representing verified absence of email body.
    """
    features = TextFeatures(
        has_body=False,
        has_plain_text=False,
        has_html=False,
        html_to_text_ratio=None,
        body_entropy=None,
    )
    availability = TextFeatureAvailability(
        avail_has_body=False,
        avail_plain_text=False,
        avail_html=False,
        avail_entropy=False,
        completeness_intent=0.0,
        completeness_obfuscation=0.0,
        completeness_lexical=0.0,
        completeness_total=0.0,
    )
    evidence = TextEvidence(
        evidence_items=[],
        omitted_evidence_count=0,
        observed_anomalies=[],
    )
    return TextAgentResult(
        email_id=email_id,
        agent_name="text_agent",
        agent_version="1.0.0",
        status="success",
        processing_time_ms=0.0,
        features=features,
        availability=availability,
        evidence=evidence,
        warnings=[],
        limitations=[
            "Zero email body content extracted; text modality feature vector reflects observed absence."
        ],
    )


# ---------------------------------------------------------------------------
# 5. State 2: Body Content Analysis Pipeline
# ---------------------------------------------------------------------------

def execute_text_analysis_pipeline(
    email_id: str,
    record: ValidatedTextRecord,
) -> TextAgentResult:
    """
    Execute full deterministic text analysis over the cached ValidatedTextRecord.
    """
    start_time = time.perf_counter()
    target_text = (record.cleaned_text or record.plain_text_body or "").strip()

    # 1. Intent & Lure Analysis (Category A)
    intent_res = analyze_body_intent(target_text)

    # 2. Obfuscation & Divergence Analysis (Category B)
    obfus_res = analyze_obfuscation(
        plain_text=record.plain_text_body,
        html_body=record.html_body,
        cleaned_text=record.cleaned_text,
    )

    # 3. Lexical & Readability Metrics (Category C)
    lex_res = analyze_lexical_metrics(
        plain_text=record.plain_text_body,
        html_body=record.html_body,
        cleaned_text=record.cleaned_text,
    )

    # 4. Construct Canonical Features
    features = TextFeatures(
        # Category A: Urgency, Lures & Intent
        urgency_cue_count=intent_res.urgency_cue_count,
        has_urgency_cues=intent_res.has_urgency_cues,
        credential_lure_count=intent_res.credential_lure_count,
        has_credential_lures=intent_res.has_credential_lures,
        financial_lure_count=intent_res.financial_lure_count,
        has_financial_lures=intent_res.has_financial_lures,
        action_lure_count=intent_res.action_lure_count,
        has_action_lures=intent_res.has_action_lures,
        threat_cue_count=intent_res.threat_cue_count,
        has_threat_cues=intent_res.has_threat_cues,
        reward_cue_count=intent_res.reward_cue_count,
        has_reward_cues=intent_res.has_reward_cues,
        # Category B: Text & HTML Obfuscation / Anomalies
        has_hidden_text=obfus_res.has_hidden_text,
        hidden_text_count=obfus_res.hidden_text_count,
        has_zero_width_chars=obfus_res.has_zero_width_chars,
        zero_width_char_count=obfus_res.zero_width_char_count,
        has_excessive_capitalization=obfus_res.has_excessive_capitalization,
        capitalization_ratio=obfus_res.capitalization_ratio,
        has_excessive_punctuation=obfus_res.has_excessive_punctuation,
        excessive_punctuation_count=obfus_res.excessive_punctuation_count,
        has_plain_html_mismatch=obfus_res.has_plain_html_mismatch,
        # Category C: Lexical, Readability & Structural Metrics
        has_body=lex_res.has_body,
        has_plain_text=lex_res.has_plain_text,
        has_html=lex_res.has_html,
        word_count=lex_res.word_count,
        character_count=lex_res.character_count,
        html_to_text_ratio=lex_res.html_to_text_ratio,
        body_entropy=lex_res.body_entropy,
        generic_greeting_present=lex_res.generic_greeting_present,
    )

    # 5. Availability & Completeness Manifest
    availability = TextFeatureAvailability(
        avail_has_body=lex_res.has_body,
        avail_plain_text=lex_res.has_plain_text,
        avail_html=lex_res.has_html,
        avail_entropy=bool(lex_res.body_entropy is not None),
        completeness_intent=1.0 if lex_res.has_body else 0.0,
        completeness_obfuscation=1.0 if lex_res.has_body else 0.0,
        completeness_lexical=1.0 if lex_res.has_body else 0.0,
        completeness_total=1.0 if lex_res.has_body else 0.0,
    )

    # 6. Forensic Evidence Collection
    evidence_items_raw: List[TextEvidenceItem] = []
    observed_anomalies: set[str] = set()

    finding_idx = 0

    # Lure findings
    for cat_name, matches in intent_res.matches_by_category.items():
        if matches:
            observed_anomalies.add(f"Intent lure detected: {cat_name}")
            for m in matches[:5]:
                evidence_items_raw.append(
                    TextEvidenceItem(
                        finding_id=f"text_lure_{finding_idx}",
                        feature_name=f"has_{cat_name}_cues" if f"has_{cat_name}_cues" in features.model_fields else f"has_{cat_name}_lures",
                        category="Category A: Urgency, Lures & Intent",
                        observed_value=sanitize_snippet(m, 128),
                        description=f"Detected {cat_name} cue in email body.",
                        snippet_bounded=sanitize_snippet(m, 256),
                    )
                )
                finding_idx += 1

    # Obfuscation findings
    if obfus_res.has_hidden_text:
        observed_anomalies.add("CSS hidden text detected")
        evidence_items_raw.append(
            TextEvidenceItem(
                finding_id=f"text_obfus_{finding_idx}",
                feature_name="has_hidden_text",
                category="Category B: Text & HTML Obfuscation / Anomalies",
                observed_value=f"{obfus_res.hidden_text_count} instances",
                description="CSS styling used to hide text or render content invisible.",
                snippet_bounded=sanitize_snippet(", ".join(obfus_res.evidence_snippets), 256),
            )
        )
        finding_idx += 1

    if obfus_res.has_zero_width_chars:
        observed_anomalies.add("Zero-width Unicode characters detected")
        evidence_items_raw.append(
            TextEvidenceItem(
                finding_id=f"text_obfus_{finding_idx}",
                feature_name="has_zero_width_chars",
                category="Category B: Text & HTML Obfuscation / Anomalies",
                observed_value=f"{obfus_res.zero_width_char_count} chars",
                description="Zero-width characters present, commonly used for NLP evasion.",
                snippet_bounded=f"Found {obfus_res.zero_width_char_count} zero-width characters in body payload.",
            )
        )
        finding_idx += 1

    if obfus_res.has_plain_html_mismatch:
        observed_anomalies.add("Plain text vs. HTML divergence detected")
        evidence_items_raw.append(
            TextEvidenceItem(
                finding_id=f"text_obfus_{finding_idx}",
                feature_name="has_plain_html_mismatch",
                category="Category B: Text & HTML Obfuscation / Anomalies",
                observed_value="Divergent lexical content",
                description="Substantial textual divergence between plain-text and HTML versions.",
                snippet_bounded="Plain-text and HTML body sections show minimal lexical overlap.",
            )
        )
        finding_idx += 1

    if lex_res.generic_greeting_present:
        observed_anomalies.add("Generic impersonal greeting detected")
        evidence_items_raw.append(
            TextEvidenceItem(
                finding_id=f"text_lex_{finding_idx}",
                feature_name="generic_greeting_present",
                category="Category C: Lexical, Readability & Structural Metrics",
                observed_value="Impersonal greeting pattern",
                description="Impersonal or generic greeting detected in lead text.",
                snippet_bounded=sanitize_snippet(target_text[:120], 256),
            )
        )
        finding_idx += 1

    # Capacity caps: 100 max evidence items
    capped_evidence = evidence_items_raw[:100]
    omitted_count = max(0, len(evidence_items_raw) - 100)
    capped_anomalies = sorted(observed_anomalies)[:100]

    evidence = TextEvidence(
        evidence_items=capped_evidence,
        omitted_evidence_count=omitted_count,
        observed_anomalies=capped_anomalies,
    )

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    return TextAgentResult(
        email_id=email_id,
        agent_name="text_agent",
        agent_version="1.0.0",
        status="success",
        processing_time_ms=elapsed_ms,
        features=features,
        availability=availability,
        evidence=evidence,
        warnings=[],
        limitations=[
            "Deterministic lexical/heuristic analysis; no external LLM or live network calls performed."
        ],
    )


# ---------------------------------------------------------------------------
# 6. Public Entrypoint: analyze_text
# ---------------------------------------------------------------------------

def analyze_text(email_data: EmailData) -> TextAgentResult:
    """
    Public analysis entrypoint for the Text/Body Agent.

    Strict caller contracts:
      1. email_data must be an EmailData instance or legitimate subclass.
      2. email_data.email_id must be a non-empty, non-whitespace string.
      3. email_data body fields must be None or str.
    """
    # 1.1 Strict caller contract check
    if not isinstance(email_data, EmailData):
        raise TypeError(
            f"Invalid input: analyze_text requires an EmailData instance or legitimate subclass, "
            f"got {type(email_data).__name__}."
        )

    # 1.2 Single-access retrieval of email_id
    email_id = _get_caller_attribute(email_data, "email_id")
    if not isinstance(email_id, str) or not email_id.strip():
        raise ValueError(
            f"Invalid input: email_data.email_id must be a non-empty, non-whitespace string "
            f"(got {type(email_id).__name__}: {email_id!r})."
        )

    # 1.3 Boundary validation of body fields
    plain_text = _get_caller_attribute(email_data, "plain_text_body")
    if plain_text is not None and not isinstance(plain_text, str):
        raise TypeError(
            f"Invalid input: email_data.plain_text_body must be None or str (got {type(plain_text).__name__})."
        )

    html_body = _get_caller_attribute(email_data, "html_body")
    if html_body is not None and not isinstance(html_body, str):
        raise TypeError(
            f"Invalid input: email_data.html_body must be None or str (got {type(html_body).__name__})."
        )

    cleaned_text = _get_caller_attribute(email_data, "cleaned_text")
    if cleaned_text is not None and not isinstance(cleaned_text, str):
        raise TypeError(
            f"Invalid input: email_data.cleaned_text must be None or str (got {type(cleaned_text).__name__})."
        )

    record = ValidatedTextRecord(
        plain_text_body=plain_text,
        html_body=html_body,
        cleaned_text=cleaned_text,
    )

    # Step 2: Unified fail-closed execution
    try:
        has_any_content = bool(
            (record.cleaned_text and record.cleaned_text.strip())
            or (record.plain_text_body and record.plain_text_body.strip())
            or (record.html_body and record.html_body.strip())
        )

        if not has_any_content:
            return create_no_body_result(email_id=email_id)

        return execute_text_analysis_pipeline(
            email_id=email_id,
            record=record,
        )
    except Exception as exc:
        tb_str = traceback.format_exc()
        raise TextAgentProcessingError(
            message=f"Text Agent internal processing failed for email {email_id}: {type(exc).__name__}: {exc}",
            email_id=email_id,
            original_exception=exc,
            traceback_str=tb_str,
        ) from exc
