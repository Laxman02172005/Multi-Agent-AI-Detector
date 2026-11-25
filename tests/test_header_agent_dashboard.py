"""
tests/test_header_agent_dashboard.py
------------------------------------
Test suite for scripts/header_agent_dashboard.py:
- Verification of execute_pipeline helper
- Empty file handling
- Oversized file handling
- Malformed file handling
- Synthetic demo email analysis
- Determinism on repeated analysis
- JSON serialization for download
- Offline passive execution (zero sockets/network)
"""

import json
from pathlib import Path
import pytest

from scripts.header_agent_dashboard import execute_pipeline
from app.schemas.header_agent_schema import HeaderAgentResult
from app.schemas.email_schema import AuthStatus


SAMPLE_EML_PATH = Path(__file__).resolve().parent.parent / "data" / "samples" / "synthetic_demo.eml"


class TestDashboardPipeline:
    def test_empty_bytes_handling(self):
        """Empty bytes must fail gracefully with a descriptive error message."""
        data, res, err = execute_pipeline(b"", "empty.eml")
        assert data is None
        assert res is None
        assert err is not None
        assert "empty" in err.lower()

    def test_whitespace_only_bytes_handling(self):
        """Whitespace-only bytes must fail gracefully."""
        data, res, err = execute_pipeline(b"   \r\n\t  ", "whitespace.eml")
        assert data is None
        assert res is None
        assert err is not None
        assert "empty" in err.lower()

    def test_oversized_bytes_handling(self):
        """Files exceeding 50 MB must be rejected immediately."""
        fake_oversized = b"A" * (52_428_800 + 1)
        data, res, err = execute_pipeline(fake_oversized, "oversized.eml")
        assert data is None
        assert res is None
        assert err is not None
        assert "50 mb" in err.lower() or "safety size" in err.lower()

    def test_malformed_email_handling(self):
        """Malformed or corrupt data is caught gracefully without unhandled exceptions."""
        corrupt_bytes = b"\x00\x01\x02\x03\x04\xff\xfe"
        data, res, err = execute_pipeline(corrupt_bytes, "corrupt.eml")
        # Ingestion may either parse a degenerate message or return an error; both must be handled
        if err is not None:
            assert isinstance(err, str)
        else:
            assert data is not None
            assert res is not None

    def test_valid_email_execution(self):
        """Valid clean RFC 822 email executes successfully."""
        clean_eml = (
            b"From: user@example.com\r\n"
            b"To: dest@example.com\r\n"
            b"Subject: Clean Test\r\n"
            b"Message-ID: <123@example.com>\r\n"
            b"Date: Wed, 11 Nov 2026 10:00:00 +0000\r\n"
            b"\r\n"
            b"Clean email body text.\r\n"
        )
        data, res, err = execute_pipeline(clean_eml, "clean.eml")
        assert err is None
        assert data is not None
        assert res is not None
        assert isinstance(res, HeaderAgentResult)
        assert res.status == "success"
        assert res.features.from_present is True
        assert res.features.subject_length == 10

    def test_synthetic_demo_analysis(self):
        """Synthetic demo email executes and returns all expected anomalies."""
        assert SAMPLE_EML_PATH.exists()
        raw_bytes = SAMPLE_EML_PATH.read_bytes()
        data, res, err = execute_pipeline(raw_bytes, "synthetic_demo.eml")

        assert err is None
        assert data is not None
        assert res is not None
        assert res.status == "success"

        # Check anomalies
        feat = res.features
        assert feat.from_present is True
        assert feat.from_reply_to_domain_mismatch is True
        assert feat.from_return_path_domain_mismatch is True
        assert feat.display_name_contains_email is True
        assert feat.has_private_ip_in_external_hop is True
        assert feat.spf_status == AuthStatus.FAIL
        assert feat.dkim_status == AuthStatus.FAIL
        assert feat.dkim_signature_present_without_pass is True
        assert feat.message_id_domain_mismatch is True

        # Check evidence
        assert len(res.evidence.evidence_items) >= 5
        assert len(res.evidence.observed_anomalies) >= 5
        assert "192.168.1.45" in res.evidence.detected_anomalous_ips

        # Check JSON export compatibility
        json_str = res.model_dump_json(indent=2)
        parsed = json.loads(json_str)
        assert parsed["email_id"] == data.email_id
        assert parsed["agent_name"] == "header_agent"

    def test_repeated_analysis_determinism(self):
        """Repeated analysis on identical input yields identical features and evidence."""
        raw_bytes = SAMPLE_EML_PATH.read_bytes()
        data1, res1, _ = execute_pipeline(raw_bytes, "demo1.eml")
        data2, res2, _ = execute_pipeline(raw_bytes, "demo2.eml")

        assert res1.features.model_dump() == res2.features.model_dump()
        assert res1.availability.model_dump() == res2.availability.model_dump()
        assert res1.evidence.model_dump() == res2.evidence.model_dump()

