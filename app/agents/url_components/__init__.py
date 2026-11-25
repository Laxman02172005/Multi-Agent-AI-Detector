"""
app/agents/url_components/__init__.py
-------------------------------------
Package initialization and public exports for URL Agent modular subcomponents.
"""

from app.agents.url_components.contextual_analyzer import (
    check_anchor_url_mismatch,
    compute_sender_domain_alignment,
    has_redirect_parameter,
    is_url_shortener,
    load_shorteners_set,
)
from app.agents.url_components.ip_classifier import classify_ip_address
from app.agents.url_components.lexical_features import (
    check_punycode,
    compute_hostname_entropy,
    count_path_segments,
    count_percent_encoded_triplets,
    detect_unusual_ip_format,
    has_at_symbol_in_url,
    has_double_percent_encoding,
    has_embedded_credentials,
    has_executable_file_in_path,
    has_non_ascii_url,
    has_percent_encoding,
)
from app.agents.url_components.psl_resolver import (
    PSLTrie,
    get_psl_trie,
    resolve_domain,
)
from app.agents.url_components.syntax_validator import validate_url_syntax

__all__ = [
    "classify_ip_address",
    "resolve_domain",
    "get_psl_trie",
    "PSLTrie",
    "validate_url_syntax",
    "compute_hostname_entropy",
    "count_path_segments",
    "has_executable_file_in_path",
    "has_at_symbol_in_url",
    "has_embedded_credentials",
    "has_percent_encoding",
    "has_double_percent_encoding",
    "count_percent_encoded_triplets",
    "has_non_ascii_url",
    "detect_unusual_ip_format",
    "check_punycode",
    "is_url_shortener",
    "load_shorteners_set",
    "has_redirect_parameter",
    "check_anchor_url_mismatch",
    "compute_sender_domain_alignment",
]
