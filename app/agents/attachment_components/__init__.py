"""
app/agents/attachment_components/__init__.py
-------------------------------------------
Modular subcomponents for Attachment Agent analysis.
"""

from app.agents.attachment_components.file_classifier import (
    ARCHIVE_EXTENSIONS,
    DISK_IMAGE_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    HTML_SMUGGLING_EXTENSIONS,
    MACRO_EXTENSIONS,
    AttachmentClassificationResult,
    classify_attachment,
    clean_extension,
    detect_double_extension,
    detect_encrypted_archive,
    detect_mime_mismatch,
    detect_rlo_spoofing,
)

__all__ = [
    "classify_attachment",
    "AttachmentClassificationResult",
    "clean_extension",
    "detect_double_extension",
    "detect_rlo_spoofing",
    "detect_mime_mismatch",
    "detect_encrypted_archive",
    "EXECUTABLE_EXTENSIONS",
    "MACRO_EXTENSIONS",
    "HTML_SMUGGLING_EXTENSIONS",
    "ARCHIVE_EXTENSIONS",
    "DISK_IMAGE_EXTENSIONS",
]
