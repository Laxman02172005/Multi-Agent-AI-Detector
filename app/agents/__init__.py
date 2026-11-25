"""
app/agents/__init__.py
----------------------
Public re-exports for the specialist agents package.

Import from here:
    from app.agents import (
        analyze_headers,
        analyze_urls,
        analyze_text,
        analyze_attachments,
    )
"""

from app.agents.header_agent import (
    analyze_headers,
    classify_ip_address,
    extract_ips_from_hop,
    is_received_hop_malformed,
    sanitize_evidence_snippet,
)
from app.agents.url_agent import (
    UrlAgentProcessingError,
    ValidatedURLRecord,
    analyze_urls,
    create_no_url_result,
)
from app.agents.text_agent import (
    TextAgentProcessingError,
    ValidatedTextRecord,
    analyze_text,
    create_no_body_result,
)
from app.agents.attachment_agent import (
    AttachmentAgentProcessingError,
    ValidatedAttachmentRecord,
    analyze_attachments,
    create_no_attachment_result,
)

__all__ = [
    # Header Agent
    "analyze_headers",
    "classify_ip_address",
    "extract_ips_from_hop",
    "is_received_hop_malformed",
    "sanitize_evidence_snippet",
    # URL Agent
    "UrlAgentProcessingError",
    "ValidatedURLRecord",
    "analyze_urls",
    "create_no_url_result",
    # Text Agent
    "TextAgentProcessingError",
    "ValidatedTextRecord",
    "analyze_text",
    "create_no_body_result",
    # Attachment Agent
    "AttachmentAgentProcessingError",
    "ValidatedAttachmentRecord",
    "analyze_attachments",
    "create_no_attachment_result",
]
