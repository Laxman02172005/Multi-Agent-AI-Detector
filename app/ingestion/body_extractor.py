"""
body_extractor.py
-----------------
Modular email body extraction component for the Multi-Agent AI Phishing Email Detector.

This module extracts plain-text and HTML email body content from standard Python
`email.message.Message` objects, handles character encodings and transfer encodings,
normalizes and sanitises text for downstream NLP and classification agents, and strictly
excludes all attachments and non-body MIME parts.

Precedence & Derivation Rules:
------------------------------
1. Cleaned text derivation precedence:
   - If a plain-text body is available and contains non-whitespace content,
     `cleaned_text` is derived from `plain_text_body` by normalizing whitespace
     and paragraph breaks.
   - If `plain_text_body` is absent or whitespace-only, but `html_body` is available,
     `cleaned_text` is derived from `html_body` using BeautifulSoup to remove scripts,
     styles, and tags while preserving visible anchor text and paragraph layout.
   - If `plain_text_body` is present but empty, and `html_body` is absent,
     `cleaned_text` is an empty string ("").
   - If neither body part is present, `cleaned_text` is None.

2. MIME structure handling & repeated parts:
   - Traverses single-part messages, `multipart/alternative`, `multipart/mixed`,
     `multipart/related`, and arbitrarily nested MIME structures.
   - Identifies and excludes all attachments, binary parts, inline images/files,
     and text parts with declared filenames.
   - If multiple valid `text/plain` parts exist in sequential mixed sections,
     they are joined with double newlines ("\\n\\n").
   - If multiple valid `text/html` parts exist in sequential mixed sections,
     they are joined with newlines ("\\n").

3. Character encoding & transfer encoding handling:
   - Payload transfer encodings (base64, quoted-printable, 7bit, 8bit) are decoded
     via standard payload decoding.
   - Declared charsets (UTF-8, ISO-8859-1, Windows-1252, etc.) are respected.
   - Unknown or malformed character encodings are handled gracefully with fallbacks
     (e.g., UTF-8 replacement or ISO-8859-1) without raising unhandled exceptions,
     and descriptive warnings are recorded in `parsing_warnings`.

4. HTML sanitisation:
   - Uses BeautifulSoup4 with 'html.parser'.
   - Removes `<script>`, `<style>`, `<noscript>` elements and their contents.
   - Decodes HTML entities and normalizes whitespace while preserving readable
     paragraph and line breaks.
   - Retains visible anchor text for links (URL extraction is deferred to the URL Agent).
   - Preserves the original unmodified HTML markup in `html_body`.
"""

from __future__ import annotations

import re
from email.message import Message
from typing import Optional

from bs4 import BeautifulSoup

from app.schemas.email_schema import BodyContent


# ---------------------------------------------------------------------------
# Attachment & Non-Body Filtering
# ---------------------------------------------------------------------------

def _is_attachment_or_non_body(part: Message) -> bool:
    """
    Determine whether a MIME part is an attachment or non-body content.

    Returns True if the part must be EXCLUDED from body extraction.
    Excludes:
      - Multipart container parts (which contain subparts rather than direct body text).
      - Parts with Content-Disposition starting with 'attachment'.
      - Parts with a declared filename in Content-Disposition or Content-Type.
      - Binary MIME types (e.g. application/*, image/*, audio/*, video/*).
      - Text attachments (e.g. text/plain with filename or disposition attachment).
    """
    # 1. Skip multipart container parts
    if part.is_multipart():
        return True

    # 2. Check Content-Disposition header
    disposition = part.get_content_disposition()
    if disposition and disposition.strip().lower().startswith("attachment"):
        return True

    cd_header = part.get("Content-Disposition", "")
    if cd_header and cd_header.strip().lower().startswith("attachment"):
        return True

    # 3. Check for declared filename in Content-Disposition or Content-Type
    filename = part.get_filename()
    if filename and filename.strip():
        return True

    for header_name in ("content-disposition", "content-type"):
        for param_name in ("filename", "name"):
            param_val = part.get_param(param_name, header=header_name)
            if param_val and str(param_val).strip():
                return True

    # 4. Check Content-Type: only text/plain and text/html qualify as body parts
    content_type = part.get_content_type().lower().strip()
    if content_type not in ("text/plain", "text/html"):
        return True

    return False


# ---------------------------------------------------------------------------
# Payload Decoding & Charset Handling
# ---------------------------------------------------------------------------

def _decode_part_payload(part: Message, warnings: list[str]) -> Optional[str]:
    """
    Safely decode the payload of a MIME part into a string.

    Decodes transfer encodings (base64, quoted-printable) and character sets
    (UTF-8, ISO-8859-1, etc.). Unknown or malformed charsets trigger non-fatal
    warnings and fallback to resilient decoding.
    """
    if part.get_payload() is None:
        return None

    try:
        raw_payload = part.get_payload(decode=True)
    except Exception as exc:
        warnings.append(f"Failed to decode Content-Transfer-Encoding payload: {exc}")
        raw_payload = part.get_payload()

    if raw_payload is None:
        raw_payload = part.get_payload()

    # Already decoded to string (e.g. programmatic message creation)
    if isinstance(raw_payload, str):
        return raw_payload

    # Non-byte and non-string payload
    if not isinstance(raw_payload, (bytes, bytearray)):
        return None

    raw_bytes = bytes(raw_payload)
    if not raw_bytes:
        return ""

    declared_charset = part.get_content_charset()

    # If a charset was declared, attempt decoding with it first
    if declared_charset:
        normalized_charset = declared_charset.strip().lower()
        try:
            return raw_bytes.decode(normalized_charset)
        except LookupError:
            warnings.append(
                f"Unknown or unsupported character encoding '{declared_charset}'; "
                "falling back to utf-8 (replace)."
            )
            return raw_bytes.decode("utf-8", errors="replace")
        except UnicodeDecodeError as exc:
            warnings.append(
                f"Failed to decode payload using declared charset '{declared_charset}': {exc}; "
                "falling back to utf-8 (replace)."
            )
            try:
                return raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    return raw_bytes.decode("iso-8859-1")
                except Exception:
                    return raw_bytes.decode("utf-8", errors="replace")

    # No charset declared: try UTF-8, then ISO-8859-1, then UTF-8 with replacement
    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            decoded = raw_bytes.decode("iso-8859-1")
            warnings.append(
                "No character encoding declared and utf-8 decoding failed; "
                "decoded successfully as iso-8859-1."
            )
            return decoded
        except Exception:
            warnings.append(
                "No character encoding declared and decoding failed; "
                "decoded using utf-8 with replacement characters."
            )
            return raw_bytes.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Text Normalisation & HTML Sanitisation
# ---------------------------------------------------------------------------

def _clean_plain_text(text: str) -> str:
    """
    Normalize horizontal whitespace, line endings, and consecutive blank lines.

    - Strips leading and trailing whitespace from each line.
    - Collapses consecutive spaces or tabs within a line to a single space.
    - Collapses three or more consecutive newlines into two (preserving paragraphs).
    - Strips leading and trailing whitespace from the overall text.
    """
    if not text:
        return ""

    lines = [re.sub(r"[^\S\r\n]+", " ", line).strip() for line in text.splitlines()]
    result: list[str] = []
    prev_empty = False

    for line in lines:
        if line:
            result.append(line)
            prev_empty = False
        elif not prev_empty and result:
            result.append("")
            prev_empty = True

    return "\n".join(result).strip()


def _clean_html(html_str: str, warnings: list[str]) -> str:
    """
    Sanitize HTML markup and extract readable, normalized text.

    - Uses BeautifulSoup with 'html.parser'.
    - Decomposes <script>, <style>, <noscript> elements completely.
    - Inserts line breaks around block-level elements and replaces <br> with newlines.
    - Preserves visible anchor text.
    - Automatically decodes HTML entities.
    - Normalizes whitespace and blank lines via _clean_plain_text.
    """
    if not html_str:
        return ""

    try:
        soup = BeautifulSoup(html_str, "html.parser")

        # Decompose non-readable elements completely
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()

        # Replace <br> tags with line breaks
        for br in soup.find_all("br"):
            br.replace_with("\n")

        # Insert line breaks around block-level elements to preserve paragraph structure
        for block in soup.find_all([
            "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6",
            "blockquote", "hr", "header", "footer", "section", "article"
        ]):
            block.insert_before("\n")
            block.insert_after("\n")

        extracted_text = soup.get_text()
    except Exception as exc:
        warnings.append(f"HTML parsing error encountered: {exc}; used fallback tag stripping.")
        clean_re = re.sub(r"(?is)<(script|style|noscript).*?>.*?</\1>", " ", html_str)
        extracted_text = re.sub(r"<[^>]+>", " ", clean_re)

    return _clean_plain_text(extracted_text)


# ---------------------------------------------------------------------------
# Public Body Extractor API
# ---------------------------------------------------------------------------

def extract_body(message: Message) -> BodyContent:
    """
    Extract plain-text and HTML email body content from a Python email Message object.

    Parameters:
        message: An already parsed standard Python email.message.Message object.

    Returns:
        BodyContent: Pydantic model populated with:
            - plain_text_body: Decoded plain-text body, or None if absent.
            - html_body: Decoded HTML markup body, or None if absent.
            - cleaned_text: Sanitised, normalized readable text derived according
                            to documented precedence rules, or None if no body exists.
            - parsing_warnings: List of non-fatal warnings encountered during extraction.
    """
    warnings: list[str] = []
    plain_parts: list[str] = []
    html_parts: list[str] = []

    if message.is_multipart():
        for part in message.walk():
            if _is_attachment_or_non_body(part):
                continue

            content_type = part.get_content_type().lower().strip()
            decoded_text = _decode_part_payload(part, warnings)

            if decoded_text is not None:
                if content_type == "text/plain":
                    plain_parts.append(decoded_text)
                elif content_type == "text/html":
                    html_parts.append(decoded_text)
    else:
        # Non-multipart message
        if not _is_attachment_or_non_body(message):
            content_type = message.get_content_type().lower().strip()
            decoded_text = _decode_part_payload(message, warnings)

            if decoded_text is not None:
                if content_type == "text/plain":
                    plain_parts.append(decoded_text)
                elif content_type == "text/html":
                    html_parts.append(decoded_text)

    # Resolve plain_text_body
    plain_text_body: Optional[str] = None
    if plain_parts:
        if len(plain_parts) == 1:
            plain_text_body = plain_parts[0]
        else:
            plain_text_body = "\n\n".join(plain_parts)

    # Resolve html_body
    html_body: Optional[str] = None
    if html_parts:
        if len(html_parts) == 1:
            html_body = html_parts[0]
        else:
            html_body = "\n".join(html_parts)

    # Resolve cleaned_text according to precedence rules:
    # 1. Non-empty plain text has primary precedence.
    # 2. Non-empty HTML is used if plain text is absent or empty.
    # 3. If plain text exists but is empty and HTML is absent, returns "".
    # 4. If HTML exists but has no readable text and plain text is absent, returns "".
    # 5. If neither exists, returns None.
    cleaned_text: Optional[str] = None
    if plain_text_body is not None and plain_text_body.strip():
        cleaned_text = _clean_plain_text(plain_text_body)
    elif html_body is not None and html_body.strip():
        cleaned_text = _clean_html(html_body, warnings)
    elif plain_text_body is not None:
        cleaned_text = _clean_plain_text(plain_text_body)
    elif html_body is not None:
        cleaned_text = _clean_html(html_body, warnings)
    else:
        cleaned_text = None

    return BodyContent(
        plain_text_body=plain_text_body,
        html_body=html_body,
        cleaned_text=cleaned_text,
        parsing_warnings=warnings,
    )
