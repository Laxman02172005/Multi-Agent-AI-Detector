"""
app/ingestion package.
"""

from app.ingestion.attachment_extractor import extract_attachments
from app.ingestion.body_extractor import extract_body
from app.ingestion.email_ingestor import (
    MAX_RAW_EMAIL_SIZE_BYTES,
    EmptyEmailError,
    IngestionError,
    InvalidInputTypeError,
    MalformedEmailError,
    OversizedEmailError,
    ingest_email,
)
from app.ingestion.header_extractor import extract_authentication, extract_headers
from app.ingestion.url_extractor import (
    extract_urls,
    extract_urls_from_headers,
    extract_urls_from_html,
    extract_urls_from_text,
)

__all__ = [
    "extract_headers",
    "extract_authentication",
    "extract_body",
    "extract_urls",
    "extract_urls_from_text",
    "extract_urls_from_html",
    "extract_urls_from_headers",
    "extract_attachments",
    "ingest_email",
    "MAX_RAW_EMAIL_SIZE_BYTES",
    "IngestionError",
    "InvalidInputTypeError",
    "EmptyEmailError",
    "OversizedEmailError",
    "MalformedEmailError",
]
