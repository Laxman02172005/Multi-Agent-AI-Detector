"""
app/agents/text_components/__init__.py
-------------------------------------
Modular subcomponents for Text/Body Agent analysis.
"""

from app.agents.text_components.intent_analyzer import (
    IntentAnalysisResult,
    analyze_body_intent,
)
from app.agents.text_components.obfuscation_detector import (
    ObfuscationAnalysisResult,
    analyze_obfuscation,
    detect_hidden_text_css,
    detect_zero_width_characters,
    compute_capitalization_metrics,
    detect_excessive_punctuation,
    detect_plain_html_mismatch,
)
from app.agents.text_components.lexical_metrics import (
    LexicalMetricsResult,
    analyze_lexical_metrics,
    compute_html_to_text_ratio,
    compute_shannon_entropy,
    detect_generic_greeting,
)

__all__ = [
    "analyze_body_intent",
    "IntentAnalysisResult",
    "analyze_obfuscation",
    "ObfuscationAnalysisResult",
    "detect_hidden_text_css",
    "detect_zero_width_characters",
    "compute_capitalization_metrics",
    "detect_excessive_punctuation",
    "detect_plain_html_mismatch",
    "analyze_lexical_metrics",
    "LexicalMetricsResult",
    "compute_html_to_text_ratio",
    "compute_shannon_entropy",
    "detect_generic_greeting",
]
