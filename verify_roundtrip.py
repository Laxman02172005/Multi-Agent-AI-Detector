"""
verify_roundtrip.py  –  read-only runtime verification script.
Run with the venv Python. Does NOT modify any source file.
"""
import json, sys
sys.path.insert(0, ".")
from app.schemas import EmailData, AuthStatus

VALID_SHA256 = "a" * 64

payload = {
    "email_id": "email-001",
    "source_filename": "sample.eml",
    "headers": {
        "from_address": "security@example.com",
        "to": ["user@example.net"],
        "subject": "Account notification",
        "received": ["from mail.example.com", "from smtp.gateway.net"],
        "authentication_results": ["spf=pass dkim=pass"],
        "received_spf": ["pass (domain of example.com designates 1.2.3.4 as permitted)"],
        "dkim_signature": ["v=1; a=rsa-sha256; d=example.com; s=default;"],
    },
    "authentication": {
        "spf":   {"mechanism": "SPF",   "status": "pass",    "raw_value": "spf=pass"},
        "dkim":  {"mechanism": "DKIM",  "status": "pass",    "raw_value": "dkim=pass"},
        "dmarc": {"mechanism": "DMARC", "status": "missing", "raw_value": None},
    },
    "plain_text_body": "Please review your account.",
    "html_body": None,
    "cleaned_text": "Please review your account.",
    "extracted_urls": [
        {"original_url": "http://example.com/reset", "source": "html_href", "anchor_text": "Reset password"},
        {"original_url": "http://cdn.example.com/img.png", "source": "html_src"},
    ],
    "attachments": [
        {
            "filename": "invoice.pdf",
            "content_type": "application/pdf",
            "extension": "pdf",
            "size_bytes": 204800,
            "sha256": VALID_SHA256,
            "disposition": "attachment",
            "status": "processed",
        },
        {
            "filename": "huge.zip",
            "size_bytes": 0,
            "disposition": "attachment",
            "status": "skipped",
            "skip_reason": "Exceeds 10 MB limit",
        },
    ],
    "parsing_warnings": ["Missing MIME-Version header"],
    "ingestion_timestamp": "2026-11-10T10:00:00Z",
}

print("=== PARSE ===")
original = EmailData(**payload)
print(f"  email_id              : {original.email_id}")
print(f"  source_filename       : {original.source_filename}")
print(f"  spf.status            : {original.authentication.spf.status}")
print(f"  dkim.status           : {original.authentication.dkim.status}")
print(f"  dmarc.status          : {original.authentication.dmarc.status}")
print(f"  spf.raw_value         : {original.authentication.spf.raw_value!r}")
print(f"  dmarc.raw_value       : {original.authentication.dmarc.raw_value!r}")
print(f"  received[0]           : {original.headers.received[0]!r}")
print(f"  received[1]           : {original.headers.received[1]!r}")
print(f"  dkim_signature[0][:30]: {original.headers.dkim_signature[0][:30]!r}")
print(f"  url[0].source         : {original.extracted_urls[0].source}")
print(f"  url[0].anchor_text    : {original.extracted_urls[0].anchor_text!r}")
print(f"  url[1].source         : {original.extracted_urls[1].source}")
print(f"  attachment[0].sha256_len : {len(original.attachments[0].sha256)}")
print(f"  attachment[0].status  : {original.attachments[0].status}")
print(f"  attachment[1].status  : {original.attachments[1].status}")
print(f"  attachment[1].skip_reason : {original.attachments[1].skip_reason!r}")
print(f"  parsing_warnings      : {original.parsing_warnings}")
print(f"  timestamp type        : {type(original.ingestion_timestamp).__name__}")

print()
print("=== SERIALISE (model_dump_json) ===")
json_str = original.model_dump_json()
parsed_json = json.loads(json_str)
print(f"  headers.from_address          : {parsed_json['headers']['from_address']}")
print(f"  authentication.spf.status     : {parsed_json['authentication']['spf']['status']}")
print(f"  authentication.dmarc.status   : {parsed_json['authentication']['dmarc']['status']}")
print(f"  authentication.dmarc.raw_value: {parsed_json['authentication']['dmarc']['raw_value']}")
print(f"  extracted_urls count          : {len(parsed_json['extracted_urls'])}")
print(f"  attachments count             : {len(parsed_json['attachments'])}")
print(f"  attachments[1].skip_reason    : {parsed_json['attachments'][1]['skip_reason']!r}")
print(f"  no 'confidence' key           : {'confidence' not in parsed_json}")
print(f"  no 'is_phishing' key          : {'is_phishing' not in parsed_json}")
print(f"  no 'risk_score' key           : {'risk_score' not in parsed_json}")

print()
print("=== ROUND-TRIP (model_validate_json) ===")
restored = EmailData.model_validate_json(json_str)
failures = []
if original.email_id != restored.email_id:
    failures.append("email_id mismatch")
if original.authentication.spf.status != restored.authentication.spf.status:
    failures.append("spf.status mismatch")
if original.authentication.dmarc.status != restored.authentication.dmarc.status:
    failures.append("dmarc.status mismatch")
if original.authentication.dmarc.raw_value != restored.authentication.dmarc.raw_value:
    failures.append("dmarc.raw_value mismatch")
if len(original.extracted_urls) != len(restored.extracted_urls):
    failures.append("url count mismatch")
if len(original.attachments) != len(restored.attachments):
    failures.append("attachment count mismatch")
if original.attachments[1].skip_reason != restored.attachments[1].skip_reason:
    failures.append("skip_reason mismatch")
if original.headers.received != restored.headers.received:
    failures.append("received headers mismatch")
if failures:
    print(f"  FAILURES: {failures}")
    sys.exit(1)
else:
    print("  All round-trip assertions PASSED.")

print()
print("=== MULTIPLE AUTH RESULTS PRESERVED ===")
print(f"  spf.mechanism  : {restored.authentication.spf.mechanism}")
print(f"  dkim.mechanism : {restored.authentication.dkim.mechanism}")
print(f"  dmarc.mechanism: {restored.authentication.dmarc.mechanism}")
print(f"  spf.status     : {restored.authentication.spf.status}")
print(f"  dkim.status    : {restored.authentication.dkim.status}")
print(f"  dmarc.status   : {restored.authentication.dmarc.status}")

print()
print("=== MISSING vs FAIL DISTINCTION (runtime) ===")
print(f"  AuthStatus.MISSING == AuthStatus.FAIL : {AuthStatus.MISSING == AuthStatus.FAIL}  (expect False)")
print(f"  AuthStatus.MISSING.value              : {AuthStatus.MISSING.value!r}")
print(f"  AuthStatus.FAIL.value                 : {AuthStatus.FAIL.value!r}")
print(f"  AuthStatus.UNAVAILABLE == AuthStatus.FAIL : {AuthStatus.UNAVAILABLE == AuthStatus.FAIL}  (expect False)")

print()
print("=== BOUNDARY VALIDATIONS ===")
# SHA-256 — invalid (too short)
from pydantic import ValidationError
from app.schemas import AttachmentMetadata, AttachmentDisposition, AttachmentStatus
try:
    AttachmentMetadata(size_bytes=100, sha256="abc123",
                       disposition=AttachmentDisposition.ATTACHMENT,
                       status=AttachmentStatus.PROCESSED)
    print("  FAIL: short sha256 should have raised")
    sys.exit(1)
except ValidationError as exc:
    loc = exc.errors()[0]["loc"]
    msg = exc.errors()[0]["msg"]
    print(f"  short sha256 -> ValidationError at loc={loc}: {msg}")

# SHA-256 — invalid (non-hex)
try:
    AttachmentMetadata(size_bytes=100, sha256="g"*64,
                       disposition=AttachmentDisposition.ATTACHMENT,
                       status=AttachmentStatus.PROCESSED)
    print("  FAIL: non-hex sha256 should have raised")
    sys.exit(1)
except ValidationError as exc:
    loc = exc.errors()[0]["loc"]
    msg = exc.errors()[0]["msg"]
    print(f"  non-hex sha256 -> ValidationError at loc={loc}: {msg}")

# Negative size_bytes
try:
    AttachmentMetadata(size_bytes=-1,
                       disposition=AttachmentDisposition.ATTACHMENT,
                       status=AttachmentStatus.PROCESSED)
    print("  FAIL: negative size_bytes should have raised")
    sys.exit(1)
except ValidationError as exc:
    loc = exc.errors()[0]["loc"]
    msg = exc.errors()[0]["msg"]
    print(f"  negative size_bytes -> ValidationError at loc={loc}: {msg}")

# Skipped without skip_reason
try:
    AttachmentMetadata(size_bytes=0,
                       disposition=AttachmentDisposition.ATTACHMENT,
                       status=AttachmentStatus.SKIPPED)
    print("  FAIL: skipped+no reason should have raised")
    sys.exit(1)
except ValidationError as exc:
    loc = exc.errors()[0]["loc"]
    msg = exc.errors()[0]["msg"]
    print(f"  skipped+no reason -> ValidationError at loc={loc}: {msg}")

print()
print("All verifications completed successfully.")
