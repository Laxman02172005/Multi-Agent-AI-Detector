"""
attachment_extractor.py
-----------------------
Modular email attachment extraction component for the Multi-Agent AI Phishing Email Detector.

This module extracts attachments and inline media from standard Python `email.message.Message`
objects, extracts and sanitises metadata, calculates SHA-256 digests and byte sizes,
enforces strict security and resource limits (25 MB per attachment, max 50 attachments),
and preserves all relevant evidence for downstream analysis.

Security & Safety Principles:
-----------------------------
1. Pure extraction: This module NEVER executes attachments, loads external applications,
   extracts archive contents, or evaluates scripts/macros.
2. Filenames are untrusted: Strips path traversal sequences (../../), Windows drive
   letters, backslashes, control characters, and null bytes to produce safe display filenames
   while preserving original raw filename evidence in `raw_filename`.
3. Resource boundaries: Enforces 25 MB max attachment size (skips hashing to prevent OOM)
   and 50 max attachment count (processes first 50, marks subsequent attachments as skipped
   without silently dropping them).
4. No network or external calls: Uses standard library only (hashlib, email, os, re).
5. No disk writes: Never writes attachment payloads or temporary files to the filesystem.
"""

from __future__ import annotations

import email.header
import hashlib
import os
import quopri
import re
from email.message import Message
from typing import Optional

from app.schemas.email_schema import (
    AttachmentDisposition,
    AttachmentMetadata,
    AttachmentStatus,
)

# ---------------------------------------------------------------------------
# Resource Limits & Configuration Constants
# ---------------------------------------------------------------------------

MAX_ATTACHMENT_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 MB (26,214,400 bytes)
MAX_ATTACHMENT_COUNT: int = 50
MAX_FILENAME_LENGTH: int = 255
DEFAULT_QP_CHUNK_SIZE: int = 64 * 1024  # 64 KB input chunk size for bounded decoding

# Theoretical maximum base64 raw string length that could produce <= 25 MB decoded bytes
# (26,214,400 * 4 / 3 = 34,952,533 chars; any clean string longer than this is guaranteed > 25 MB)
MAX_BASE64_SAFE_RAW_LEN: int = (MAX_ATTACHMENT_SIZE_BYTES * 4) // 3


# ---------------------------------------------------------------------------
# Filename Extraction & Decoding
# ---------------------------------------------------------------------------

def _decode_rfc2047(value: str) -> str:
    """
    Safely decode RFC 2047 encoded words within a header string.
    E.g., '=?UTF-8?B?...?=' -> decoded Unicode text.
    """
    if "=?" not in value or "?=" not in value:
        return value

    try:
        chunks = email.header.decode_header(value)
        decoded_parts: list[str] = []
        for piece, charset in chunks:
            if isinstance(piece, bytes):
                encoding = charset or "utf-8"
                try:
                    decoded_parts.append(piece.decode(encoding, errors="replace"))
                except (LookupError, UnicodeDecodeError):
                    decoded_parts.append(piece.decode("utf-8", errors="replace"))
            else:
                decoded_parts.append(str(piece))
        return "".join(decoded_parts)
    except Exception:
        return value


def _extract_raw_filename(part: Message) -> Optional[str]:
    """
    Extract the un-sanitised raw filename string as declared in MIME headers.

    Checks:
      1. part.get_filename() (Content-Disposition filename / Content-Type name)
      2. Content-Disposition 'filename' parameter
      3. Content-Type 'name' parameter
      4. Content-Type 'filename' parameter
      5. RFC 2047 encoded word decoding
    """
    raw_name: Optional[str] = None

    try:
        filename_attr = part.get_filename()
        if filename_attr is not None:
            raw_name = str(filename_attr)
    except Exception:
        pass

    if raw_name is None:
        for header, param in (
            ("content-disposition", "filename"),
            ("content-type", "name"),
            ("content-type", "filename"),
        ):
            try:
                val = part.get_param(param, header=header)
                if val is not None:
                    raw_name = str(val)
                    break
            except Exception:
                pass

    if raw_name is not None:
        raw_name = _decode_rfc2047(raw_name)

    return raw_name


def _sanitize_filename(
    raw_filename: Optional[str],
) -> tuple[Optional[str], Optional[str]]:
    """
    Sanitize an untrusted attachment filename and extract its normalized extension.

    Protections:
      - Strips null bytes and ASCII control characters (0-31, 127).
      - Strips path traversal sequences (../../, ..\\\\).
      - Strips Windows drive prefixes (C:, D:).
      - Strips leading and trailing slashes / backslashes.
      - Truncates extremely long filenames (> 255 chars) while preserving extension.

    Returns:
      tuple of (safe_display_filename, normalized_extension_without_dot)
    """
    if raw_filename is None:
        return None, None

    # 1. Remove null bytes and control characters
    cleaned = "".join(
        ch for ch in raw_filename if ord(ch) >= 32 and ord(ch) != 127
    )
    if not cleaned.strip():
        return None, None

    # 2. Normalize backslashes to forward slashes
    normalized = cleaned.replace("\\", "/")

    # 3. Strip Windows drive prefixes (e.g. C: or c:)
    normalized = re.sub(r"^[a-zA-Z]:", "", normalized)

    # 4. Strip leading/trailing slashes
    normalized = normalized.strip("/")

    # 5. Extract path segments, rejecting '.' and '..' traversal elements
    segments = [
        seg.strip()
        for seg in normalized.split("/")
        if seg.strip() and seg.strip() not in (".", "..")
    ]
    if not segments:
        return None, None

    filename = segments[-1]

    # Reject names consisting purely of dots
    if all(ch == "." for ch in filename):
        return None, None

    # 6. Extract extension
    # Strip any trailing whitespace from filename before splitting extension
    filename = filename.strip()
    stem, ext = os.path.splitext(filename)
    if ext.startswith("."):
        clean_ext = ext[1:].strip().lower()
        clean_ext = clean_ext if clean_ext else None
    else:
        clean_ext = None

    # 7. Bound length to MAX_FILENAME_LENGTH while preserving extension
    if len(filename) > MAX_FILENAME_LENGTH:
        if clean_ext:
            suffix = f".{clean_ext}"
            max_stem_len = MAX_FILENAME_LENGTH - len(suffix)
            filename = f"{stem[:max(1, max_stem_len)]}{suffix}"
        else:
            filename = filename[:MAX_FILENAME_LENGTH]

    return filename, clean_ext


# ---------------------------------------------------------------------------
# Attachment Identification & MIME Attribute Helpers
# ---------------------------------------------------------------------------

def _is_attachment_part(part: Message) -> bool:
    """
    Determine whether a MIME message part qualifies as an attachment.

    A MIME part is considered an attachment if:
      - It is a leaf part (part.is_multipart() is False).
      - AND one of the following holds:
        a) Content-Disposition header is explicitly 'attachment'.
        b) It has a declared filename (in Content-Disposition or Content-Type).
        c) It is a non-body MIME type (not 'text/plain' and not 'text/html'),
           including inline images, PDFs, media, and applications.

    Legitimate plain-text and HTML body parts (without attachment disposition
    and without declared filenames) are NEVER classified as attachments.
    """
    if part.is_multipart():
        return False

    # Check Content-Disposition header
    disp = part.get_content_disposition()
    if disp is not None and disp.strip().lower().startswith("attachment"):
        return True

    cd_header = part.get("Content-Disposition", "")
    if cd_header and cd_header.strip().lower().startswith("attachment"):
        return True

    # Check for declared filename
    raw_name = _extract_raw_filename(part)
    if raw_name is not None and raw_name.strip():
        return True

    # Check MIME content type
    try:
        content_type = part.get_content_type().lower().strip()
    except Exception:
        content_type = ""

    # Non-text MIME types (e.g. application/*, image/*, audio/*, video/*) are attachments
    if content_type not in ("text/plain", "text/html"):
        return True

    return False


def _get_attachment_disposition(part: Message) -> AttachmentDisposition:
    """
    Extract and map MIME Content-Disposition header to AttachmentDisposition enum.
    """
    disp = part.get_content_disposition()
    if disp is not None:
        disp_lower = disp.strip().lower()
        if disp_lower.startswith("attachment"):
            return AttachmentDisposition.ATTACHMENT
        elif disp_lower.startswith("inline"):
            return AttachmentDisposition.INLINE
        return AttachmentDisposition.UNKNOWN

    cd_header = part.get("Content-Disposition")
    if cd_header:
        first_token = cd_header.split(";")[0].strip().lower()
        if first_token == "attachment":
            return AttachmentDisposition.ATTACHMENT
        elif first_token == "inline":
            return AttachmentDisposition.INLINE

    return AttachmentDisposition.UNKNOWN


def _extract_content_id(part: Message) -> Optional[str]:
    """
    Extract and clean Content-ID header if present.
    Strips surrounding angle brackets and whitespace.
    """
    cid = part.get("Content-ID")
    if cid is None:
        return None
    cleaned = cid.strip().strip("<>").strip()
    return cleaned if cleaned else None


def _extract_content_type(part: Message) -> Optional[str]:
    """
    Extract MIME content type, preserving declared type without parameters.
    Returns None if Content-Type header was omitted.
    """
    if part.get("Content-Type") is None:
        return None
    try:
        ct = part.get_content_type()
        return ct.lower().strip() if ct else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Payload Decoding & Resource Limit Enforcement
# ---------------------------------------------------------------------------

def _estimate_base64_decoded_size(raw_str: str) -> int:
    """
    Accurately estimate decoded byte size of a base64 string without decoding.

    Formula:
      non_ws_count = len(raw_str) - whitespace_count
      est_bytes = (non_ws_count * 3) // 4
      Minus 1 or 2 bytes if trailing '=' or '==' padding characters exist.
    """
    ws_count = (
        raw_str.count(" ")
        + raw_str.count("\t")
        + raw_str.count("\n")
        + raw_str.count("\r")
    )
    clean_len = len(raw_str) - ws_count
    if clean_len <= 0:
        return 0

    est_bytes = (clean_len * 3) // 4
    stripped_tail = raw_str.rstrip(" \t\r\n")
    if stripped_tail.endswith("=="):
        est_bytes = max(0, est_bytes - 2)
    elif stripped_tail.endswith("="):
        est_bytes = max(0, est_bytes - 1)

    return est_bytes


def _bounded_decode_quoted_printable(
    raw_str: str,
    max_bytes: int = MAX_ATTACHMENT_SIZE_BYTES,
    chunk_size: int = DEFAULT_QP_CHUNK_SIZE,
) -> tuple[Optional[bytes], int]:
    """
    Decode quoted-printable string in bounded chunks, tracking decoded size
    incrementally and releasing buffers immediately if max_bytes is exceeded.

    Guarantees:
      - Strictly memory bounded: processes input in chunks of at most chunk_size (default 64 KB).
      - Untrusted lines are NEVER decoded in one giant buffer regardless of length.
      - Preserves escape sequences (=XX) and soft line breaks (=\\r\\n, =\\n) across
        chunk boundaries via trailing carryover buffer.
      - Discards accumulated chunks immediately upon exceeding max_bytes.

    Returns:
      (decoded_bytes, total_size) if total_size <= max_bytes
      (None, total_estimated) if total_size > max_bytes
    """
    if not raw_str:
        return b"", 0

    total_decoded = 0
    chunks: list[bytes] = []
    carryover = b""

    n = len(raw_str)
    idx = 0

    while idx < n:
        end = min(idx + chunk_size, n)
        chunk_str = raw_str[idx:end]
        idx = end

        current = carryover + chunk_str.encode("ascii", errors="replace")
        carryover = b""

        # If not at the end of the entire stream, hold back incomplete sequences
        if idx < n:
            hold_len = 0
            if current.endswith(b"=\r"):
                hold_len = 2
            elif len(current) >= 2 and current[-2:-1] == b"=":
                hold_len = 2
            elif current.endswith(b"="):
                hold_len = 1
            elif current.endswith(b"\r"):
                hold_len = 1

            if hold_len > 0:
                carryover = current[-hold_len:]
                current = current[:-hold_len]

        if current:
            decoded_chunk = quopri.decodestring(current)
            total_decoded += len(decoded_chunk)
            if total_decoded > max_bytes:
                chunks.clear()
                return None, total_decoded
            chunks.append(decoded_chunk)

    if carryover:
        decoded_chunk = quopri.decodestring(carryover)
        total_decoded += len(decoded_chunk)
        if total_decoded > max_bytes:
            chunks.clear()
            return None, total_decoded
        chunks.append(decoded_chunk)

    return b"".join(chunks), total_decoded


def _extract_payload_bytes(
    part: Message,
) -> tuple[Optional[bytes], Optional[str], Optional[int]]:
    """
    Safely extract decoded attachment bytes with strict resource bounds.

    Memory Protections:
      - Raw binary payloads: checked by length BEFORE any decoding/copying.
      - Base64 payloads: decoded size estimated before decoding; strings whose
        clean length exceeds the 25 MB equivalent threshold are rejected
        without allocating any decoded byte buffers.
      - Quoted-Printable payloads: decoded in bounded 64 KB chunks; never decodes
        unbounded lines and aborts immediately if decoded size exceeds 25 MB.
      - Other / unspecified: checked by string length before decoding.

    Returns:
      tuple of (decoded_bytes, error_code_or_message, measured_size_bytes)
    """
    raw_payload = part.get_payload()

    if raw_payload is None:
        return b"", None, 0

    # 1. Raw binary bytes or bytearray (already in memory as bytes)
    if isinstance(raw_payload, (bytes, bytearray)):
        raw_len = len(raw_payload)
        if raw_len > MAX_ATTACHMENT_SIZE_BYTES:
            return None, "size_exceeded", raw_len
        return bytes(raw_payload), None, raw_len

    # 2. String payloads (needs transfer decoding)
    if isinstance(raw_payload, str):
        cte = (part.get("Content-Transfer-Encoding") or "").strip().lower()

        # 2a. Base64
        if cte == "base64":
            # If raw string is longer than the theoretical minimum base64 length
            # that could produce >25 MB, estimate clean non-whitespace decoded size
            if len(raw_payload) > MAX_BASE64_SAFE_RAW_LEN:
                est_size = _estimate_base64_decoded_size(raw_payload)
                if est_size > MAX_ATTACHMENT_SIZE_BYTES:
                    # Exceeds limit! Skip decoding entirely to avoid allocating 25+ MB buffer
                    return None, "size_exceeded", est_size

            # Within bounds, decode safely
            try:
                decoded = part.get_payload(decode=True)
            except Exception as exc:
                return None, f"Malformed transfer encoding: {exc}", None

            if decoded is None:
                decoded = b""
            elif isinstance(decoded, bytearray):
                decoded = bytes(decoded)

            size_bytes = len(decoded)
            if size_bytes > MAX_ATTACHMENT_SIZE_BYTES:
                return None, "size_exceeded", size_bytes

            return decoded, None, size_bytes

        # 2b. Quoted-Printable: always decoded through bounded 64 KB chunks
        elif cte == "quoted-printable":
            decoded, sz = _bounded_decode_quoted_printable(
                raw_payload, MAX_ATTACHMENT_SIZE_BYTES
            )
            if decoded is None:
                return None, "size_exceeded", sz
            return decoded, None, len(decoded)

        # 2c. Other or 7bit/8bit/unspecified
        else:
            if len(raw_payload) > MAX_ATTACHMENT_SIZE_BYTES:
                return None, "size_exceeded", len(raw_payload)

            try:
                decoded = part.get_payload(decode=True)
            except Exception as exc:
                return None, f"Malformed transfer encoding: {exc}", None

            if decoded is None:
                decoded = raw_payload.encode("utf-8", errors="replace")
            elif isinstance(decoded, bytearray):
                decoded = bytes(decoded)

            size_bytes = len(decoded)
            if size_bytes > MAX_ATTACHMENT_SIZE_BYTES:
                return None, "size_exceeded", size_bytes

            return decoded, None, size_bytes

    return None, "Unable to extract payload bytes", None


# ---------------------------------------------------------------------------
# Main Public Extraction Function
# ---------------------------------------------------------------------------

def extract_attachments(message: Message) -> list[AttachmentMetadata]:
    """
    Extract all attachments and inline media from an email Message object.

    Parameters:
      message: An already-parsed Python email Message object.

    Returns:
      A list of validated AttachmentMetadata objects representing all
      attachments identified in the message.

    Enforces:
      - Attachment detection via MIME structure, Content-Disposition, and filenames.
      - Path traversal and unsafe character sanitisation for filenames.
      - SHA-256 hash calculation of decoded payload bytes.
      - Strict resource limits: max 25 MB per attachment (pre-estimated before decoding
        to prevent excessive memory consumption), max 50 attachments.
      - Accurate size representation: None for attachments beyond count limit (unmeasured),
        0 for genuinely empty attachments, exact size for measured attachments.
      - Safe handling of malformed MIME structures and encodings without crashing.
      - Preservation of duplicate attachment records and original evidence.
    """
    if not isinstance(message, Message):
        return []

    attachments: list[AttachmentMetadata] = []
    attachment_count = 0

    try:
        parts_iter = message.walk()
    except Exception:
        return []

    for part in parts_iter:
        try:
            if not _is_attachment_part(part):
                continue

            attachment_count += 1
            raw_filename = _extract_raw_filename(part)
            filename, extension = _sanitize_filename(raw_filename)
            disposition = _get_attachment_disposition(part)
            content_id = _extract_content_id(part)
            content_type = _extract_content_type(part)

            # Limit 1: Attachment count limit (max 50)
            if attachment_count > MAX_ATTACHMENT_COUNT:
                attachments.append(
                    AttachmentMetadata(
                        filename=filename,
                        raw_filename=raw_filename,
                        content_type=content_type,
                        extension=extension,
                        size_bytes=None,  # Not measured! Correctly reflected as None
                        sha256=None,
                        disposition=disposition,
                        status=AttachmentStatus.SKIPPED,
                        skip_reason=(
                            f"Maximum attachment count ({MAX_ATTACHMENT_COUNT}) "
                            f"exceeded. Attachment at index {attachment_count} was skipped."
                        ),
                        content_id=content_id,
                    )
                )
                continue

            # Limit 2: Bounded attachment size extraction & limits
            decoded_bytes, err, measured_size = _extract_payload_bytes(part)

            if err == "size_exceeded":
                attachments.append(
                    AttachmentMetadata(
                        filename=filename,
                        raw_filename=raw_filename,
                        content_type=content_type,
                        extension=extension,
                        size_bytes=measured_size,
                        sha256=None,
                        disposition=disposition,
                        status=AttachmentStatus.SKIPPED,
                        skip_reason=(
                            f"Attachment size ({measured_size} bytes) exceeds maximum "
                            f"limit of {MAX_ATTACHMENT_SIZE_BYTES} bytes (25 MB)."
                        ),
                        content_id=content_id,
                    )
                )
                continue

            if err is not None:
                # Decoding error due to malformed transfer encoding
                attachments.append(
                    AttachmentMetadata(
                        filename=filename,
                        raw_filename=raw_filename,
                        content_type=content_type,
                        extension=extension,
                        size_bytes=measured_size,
                        sha256=None,
                        disposition=disposition,
                        status=AttachmentStatus.ERROR,
                        skip_reason=f"Failed to decode attachment: {err}",
                        content_id=content_id,
                    )
                )
                continue

            # Successfully decoded payload bytes
            size_bytes = len(decoded_bytes) if decoded_bytes is not None else 0

            # Normal attachment processed successfully
            sha256 = (
                hashlib.sha256(decoded_bytes).hexdigest()
                if decoded_bytes is not None
                else hashlib.sha256(b"").hexdigest()
            )

            attachments.append(
                AttachmentMetadata(
                    filename=filename,
                    raw_filename=raw_filename,
                    content_type=content_type,
                    extension=extension,
                    size_bytes=size_bytes,
                    sha256=sha256,
                    disposition=disposition,
                    status=AttachmentStatus.PROCESSED,
                    skip_reason=None,
                    content_id=content_id,
                )
            )

        except Exception as part_exc:
            # Catch unexpected part-level exceptions to ensure resilience
            try:
                attachments.append(
                    AttachmentMetadata(
                        filename=None,
                        raw_filename=None,
                        content_type=None,
                        extension=None,
                        size_bytes=0,
                        sha256=None,
                        disposition=AttachmentDisposition.UNKNOWN,
                        status=AttachmentStatus.ERROR,
                        skip_reason=f"Error processing MIME part: {part_exc}",
                        content_id=None,
                    )
                )
            except Exception:
                pass

    return attachments
