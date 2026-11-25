"""
app/agents/attachment_components/file_classifier.py
---------------------------------------------------
Static classification of attachment filenames, extensions, and MIME alignments.
Strictly passive: zero execution, zero file-system writes, zero binary parsing.
"""

from __future__ import annotations

import os
import re
from typing import Optional, NamedTuple


# ---------------------------------------------------------------------------
# High-Risk & Suspicious Extension Registries
# ---------------------------------------------------------------------------

EXECUTABLE_EXTENSIONS = frozenset({
    "exe", "scr", "js", "vbs", "wsf", "jse", "vbe", "bat", "cmd",
    "ps1", "psm1", "psd1", "hta", "cpl", "msi", "msp", "dll", "com",
    "pif", "gadget", "jar", "reg", "lnk", "inf", "ins", "isp", "sct",
    "shb", "sys", "drv", "ocx", "vb", "vbe", "wsh"
})

MACRO_EXTENSIONS = frozenset({
    "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam",
    "ppsm", "sldm", "docb", "xlsb"
})

HTML_SMUGGLING_EXTENSIONS = frozenset({
    "html", "htm", "xhtml", "svg", "mhtml"
})

ARCHIVE_EXTENSIONS = frozenset({
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab", "z", "ace", "arj"
})

DISK_IMAGE_EXTENSIONS = frozenset({
    "iso", "img", "vhd", "vhdx", "dmg"
})

DECEPTIVE_INNER_EXTENSIONS = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg",
    "png", "gif", "txt", "csv", "mp3", "mp4", "wav"
})

RLO_CHARACTERS = frozenset({
    "\u202E",  # Right-to-Left Override (RLO)
    "\u202B",  # Right-to-Left Embedding
    "\u202D",  # Left-to-Right Override
    "\u202A",  # Left-to-Right Embedding
    "\u202C",  # Pop Directional Formatting
})

# Extension -> expected MIME types mapping
EXPECTED_MIME_TYPES: dict[str, set[str]] = {
    "pdf": {"application/pdf", "application/x-pdf", "binary/octet-stream", "application/octet-stream"},
    "doc": {"application/msword", "application/octet-stream"},
    "docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/octet-stream"},
    "xls": {"application/vnd.ms-excel", "application/octet-stream"},
    "xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/octet-stream"},
    "ppt": {"application/vnd.ms-powerpoint", "application/octet-stream"},
    "pptx": {"application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/octet-stream"},
    "jpg": {"image/jpeg", "image/pjpeg", "application/octet-stream"},
    "jpeg": {"image/jpeg", "image/pjpeg", "application/octet-stream"},
    "png": {"image/png", "image/x-png", "application/octet-stream"},
    "gif": {"image/gif", "application/octet-stream"},
    "txt": {"text/plain", "application/octet-stream"},
    "csv": {"text/csv", "text/plain", "application/vnd.ms-excel", "application/octet-stream"},
    "zip": {"application/zip", "application/x-zip-compressed", "application/x-zip", "application/octet-stream"},
    "rar": {"application/vnd.rar", "application/x-rar-compressed", "application/octet-stream"},
    "7z": {"application/x-7z-compressed", "application/octet-stream"},
    "tar": {"application/x-tar", "application/octet-stream"},
    "gz": {"application/gzip", "application/x-gzip", "application/octet-stream"},
    "iso": {"application/x-iso9660-image", "application/octet-stream"},
    "html": {"text/html", "application/xhtml+xml"},
    "htm": {"text/html", "application/xhtml+xml"},
    "svg": {"image/svg+xml", "text/xml"},
}


class AttachmentClassificationResult(NamedTuple):
    extension: Optional[str]
    is_executable: bool
    is_macro_enabled: bool
    is_html_smuggling: bool
    has_double_extension: bool
    has_rlo_spoofing: bool
    has_mime_mismatch: bool
    is_archive: bool
    is_disk_image: bool
    is_encrypted: bool
    anomalies: list[str]


def clean_extension(ext: Optional[str], filename: Optional[str]) -> Optional[str]:
    """Extract and normalize lowercased file extension without leading dot."""
    if ext:
        return ext.strip().lower().lstrip(".")
    if filename:
        _, ext_part = os.path.splitext(filename)
        if ext_part:
            return ext_part.strip().lower().lstrip(".")
    return None


def detect_double_extension(filename: Optional[str]) -> bool:
    """
    Detect deceptive double extensions (e.g., 'invoice.pdf.exe', 'photo.png.vbs').
    """
    if not filename:
        return False

    parts = filename.strip().lower().split(".")
    if len(parts) < 3:
        return False

    outer_ext = parts[-1].strip()
    inner_ext = parts[-2].strip()

    # If the outer extension is executable/script/macro and inner looks like a benign document
    if (outer_ext in EXECUTABLE_EXTENSIONS or outer_ext in MACRO_EXTENSIONS or outer_ext in HTML_SMUGGLING_EXTENSIONS) and (inner_ext in DECEPTIVE_INNER_EXTENSIONS):
        return True

    return False


def detect_rlo_spoofing(filename: Optional[str], raw_filename: Optional[str]) -> bool:
    """Detect Unicode Right-to-Left Override characters used to disguise file extensions."""
    for text in (filename, raw_filename):
        if text and any(c in RLO_CHARACTERS for c in text):
            return True
    return False


def detect_mime_mismatch(content_type: Optional[str], extension: Optional[str]) -> bool:
    """
    Detect conflict between declared MIME type and file extension.
    E.g., declared as 'image/jpeg' or 'application/pdf' but extension is 'exe'.
    """
    if not content_type or not extension:
        return False

    clean_ct = content_type.split(";")[0].strip().lower()
    clean_ext = extension.strip().lower().lstrip(".")

    # If the file extension is executable or script, but declared MIME claims to be a document or image
    if clean_ext in EXECUTABLE_EXTENSIONS or clean_ext in MACRO_EXTENSIONS:
        if clean_ct.startswith("image/") or clean_ct in {"application/pdf", "text/plain", "application/msword"}:
            return True

    # If extension has a known profile, check if declared MIME conflicts
    expected = EXPECTED_MIME_TYPES.get(clean_ext)
    if expected and clean_ct not in expected and clean_ct != "application/octet-stream":
        # Check cross-type conflicts (e.g. extension says image but mime says application/pdf)
        if clean_ct.startswith("image/") and not clean_ext in {"jpg", "jpeg", "png", "gif", "svg", "bmp", "ico"}:
            return True
        if clean_ct == "application/pdf" and clean_ext != "pdf":
            return True

    return False


def detect_encrypted_archive(
    filename: Optional[str],
    skip_reason: Optional[str],
    is_archive: bool,
) -> bool:
    """Detect encrypted or password-protected archive indicators."""
    if not is_archive:
        return False
    if skip_reason:
        low_skip = skip_reason.lower()
        if any(term in low_skip for term in ("password", "encrypted", "aes", "protected")):
            return True
    if filename:
        low_fn = filename.lower()
        if any(term in low_fn for term in ("password", "encrypted", "protected")):
            return True
    return False


def classify_attachment(
    filename: Optional[str],
    content_type: Optional[str],
    extension: Optional[str],
    raw_filename: Optional[str] = None,
    skip_reason: Optional[str] = None,
) -> AttachmentClassificationResult:
    """Classify a single attachment against phishing vectors."""
    clean_ext = clean_extension(extension, filename)
    anomalies: list[str] = []

    is_exec = bool(clean_ext in EXECUTABLE_EXTENSIONS)
    if is_exec:
        anomalies.append(f"Executable file extension: .{clean_ext}")

    is_macro = bool(clean_ext in MACRO_EXTENSIONS)
    if is_macro:
        anomalies.append(f"Macro-enabled Office extension: .{clean_ext}")

    is_html_smuggle = bool(clean_ext in HTML_SMUGGLING_EXTENSIONS)
    if is_html_smuggle:
        anomalies.append(f"HTML smuggling candidate: .{clean_ext}")

    has_double_ext = detect_double_extension(filename)
    if has_double_ext:
        anomalies.append("Deceptive double extension detected")

    has_rlo = detect_rlo_spoofing(filename, raw_filename)
    if has_rlo:
        anomalies.append("Right-to-Left Override (RLO) character detected")

    has_mime_diff = detect_mime_mismatch(content_type, clean_ext)
    if has_mime_diff:
        anomalies.append(f"MIME type mismatch: declared '{content_type}' for '.{clean_ext}'")

    is_arch = bool(clean_ext in ARCHIVE_EXTENSIONS)
    if is_arch:
        anomalies.append(f"Archive format: .{clean_ext}")

    is_disk = bool(clean_ext in DISK_IMAGE_EXTENSIONS)
    if is_disk:
        anomalies.append(f"Disk image format: .{clean_ext}")

    is_enc = detect_encrypted_archive(filename, skip_reason, is_arch)
    if is_enc:
        anomalies.append("Encrypted or password-protected archive indicator")

    return AttachmentClassificationResult(
        extension=clean_ext,
        is_executable=is_exec,
        is_macro_enabled=is_macro,
        is_html_smuggling=is_html_smuggle,
        has_double_extension=has_double_ext,
        has_rlo_spoofing=has_rlo,
        has_mime_mismatch=has_mime_diff,
        is_archive=is_arch,
        is_disk_image=is_disk,
        is_encrypted=is_enc,
        anomalies=anomalies,
    )
