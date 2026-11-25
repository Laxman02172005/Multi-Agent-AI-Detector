"""
tests/test_url_agent_schema.py
------------------------------
Unit tests for URL Agent Pydantic v2 schemas:
- CANONICAL_URL_FEATURE_NAMES & CANONICAL_URL_FEATURE_LIST (39 features, A: 11, B: 10, C: 9, D: 9)
- ACTIVE_URL_FEATURES & QUARANTINED_URL_FEATURES (36 active, 3 quarantined)
- FEATURE_TO_CATEGORY_MAP (all 39 features mapped to approved categories)
- DomainResolutionStatus (7 approved enum values)
- IPClassificationCategory (9 approved RFC categories)
- UrlFeatures (sanitized Tier 3 feature vector, quarantined semantics, sender alignment mutual exclusion)
- UrlFeatureAvailability (availability queries across all 39 features, missingness vs negative values)
- UrlEvidenceItem & UrlEvidence (Tier 2 forensic evidence, category validation, bounds)
- UrlAnalysisItem (per-URL granular inspection record, port & status validation)
- UrlAgentResult / UrlAgentOutput (analysis_items serialization alias, 200-cap, roundtrip)
"""

import json
import pytest
from pydantic import ValidationError

from app.schemas.email_schema import URLSource, VerificationStatus
from app.schemas.url_agent_schema import (
    ACTIVE_URL_FEATURES,
    CANONICAL_URL_FEATURE_LIST,
    CANONICAL_URL_FEATURE_NAMES,
    CATEGORY_A_FEATURES,
    CATEGORY_B_FEATURES,
    CATEGORY_C_FEATURES,
    CATEGORY_D_FEATURES,
    DomainResolutionStatus,
    FEATURE_TO_CATEGORY_MAP,
    IP_CLASSIFICATION_CATEGORIES,
    IPClassificationCategory,
    QUARANTINED_URL_FEATURES,
    URL_CATEGORY_IDENTIFIERS,
    URL_CATEGORY_LIST,
    UrlAgentOutput,
    UrlAgentResult,
    UrlAnalysisItem,
    UrlEvidence,
    UrlEvidenceItem,
    UrlFeatureAvailability,
    UrlFeatures,
)


# ---------------------------------------------------------------------------
# 1. Feature Registry & Category Partition Tests (Requirement 1)
# ---------------------------------------------------------------------------

class TestCanonicalFeatureRegistry:
    def test_canonical_feature_list_length(self):
        """Must have exactly 39 features."""
        assert len(CANONICAL_URL_FEATURE_LIST) == 39

    def test_canonical_feature_list_no_duplicates(self):
        """All 39 feature names must be distinct."""
        assert len(set(CANONICAL_URL_FEATURE_LIST)) == 39

    def test_canonical_category_partitions_exact_counts(self):
        """Category partitions must match Section 5 approved design: A: 11, B: 10, C: 9, D: 9."""
        assert len(CATEGORY_A_FEATURES) == 11
        assert len(CATEGORY_B_FEATURES) == 10
        assert len(CATEGORY_C_FEATURES) == 9
        assert len(CATEGORY_D_FEATURES) == 9

        # Verify concatenation reproduces the exact canonical list in 1..39 order
        concatenated = (
            CATEGORY_A_FEATURES
            + CATEGORY_B_FEATURES
            + CATEGORY_C_FEATURES
            + CATEGORY_D_FEATURES
        )
        assert concatenated == CANONICAL_URL_FEATURE_LIST

    def test_category_contents(self):
        """Verify the exact feature membership of each category partition."""
        # Category A: URL Structural Properties (Features 1..11)
        assert CATEGORY_A_FEATURES == (
            "total_url_count",
            "unique_url_count",
            "has_urls",
            "http_url_count",
            "https_url_count",
            "suspicious_scheme_count",
            "has_suspicious_scheme",
            "has_non_default_port",
            "max_url_length",
            "max_path_depth",
            "has_executable_file_in_path",
        )

        # Category B: Hostname & Domain Composition (Features 12..21)
        assert CATEGORY_B_FEATURES == (
            "has_ip_literal_url",
            "has_private_ip_url",
            "has_loopback_ip_url",
            "has_special_ip_url",
            "has_punycode_url",
            "max_subdomain_depth",
            "has_excessive_subdomains",
            "max_hostname_entropy",
            "unique_domain_count",
            "unique_fqdn_count",
        )

        # Category C: Obfuscation, Encodings & Deception (Features 22..30)
        assert CATEGORY_C_FEATURES == (
            "has_at_symbol_in_url",
            "has_embedded_credentials",
            "has_percent_encoding",
            "has_double_percent_encoding",
            "max_percent_encoded_count",
            "has_brand_in_path",
            "has_non_ascii_url",
            "has_unusual_ip_format",
            "malformed_url_count",
        )

        # Category D: Contextual Alignment & Behavioral Indicators (Features 31..39)
        assert CATEGORY_D_FEATURES == (
            "has_url_shortener",
            "url_shortener_count",
            "has_redirect_parameter",
            "has_anchor_url_mismatch",
            "anchor_url_mismatch_count",
            "has_sender_domain_mismatch_url",
            "sender_domain_matching_url_ratio",
            "external_link_ratio",
            "has_form_action_url",
        )

    def test_feature_to_category_map_exhaustiveness(self):
        """FEATURE_TO_CATEGORY_MAP must map all 39 features to approved category identifiers."""
        assert len(FEATURE_TO_CATEGORY_MAP) == 39
        assert set(FEATURE_TO_CATEGORY_MAP.keys()) == set(CANONICAL_URL_FEATURE_LIST)

        for feat in CANONICAL_URL_FEATURE_LIST:
            cat = FEATURE_TO_CATEGORY_MAP[feat]
            assert cat in URL_CATEGORY_LIST
            if feat in CATEGORY_A_FEATURES:
                assert cat == "Category A"
            elif feat in CATEGORY_B_FEATURES:
                assert cat == "Category B"
            elif feat in CATEGORY_C_FEATURES:
                assert cat == "Category C"
            elif feat in CATEGORY_D_FEATURES:
                assert cat == "Category D"

    def test_quarantined_features_presence_and_count(self):
        """Must have exactly 3 quarantined features with approved identities."""
        assert len(QUARANTINED_URL_FEATURES) == 3
        assert "http_url_count" in QUARANTINED_URL_FEATURES       # Cat A
        assert "has_brand_in_path" in QUARANTINED_URL_FEATURES    # Cat C
        assert "has_form_action_url" in QUARANTINED_URL_FEATURES  # Cat D

    def test_active_features_presence_and_count(self):
        """Must have exactly 36 active predictive features."""
        assert len(ACTIVE_URL_FEATURES) == 36
        assert QUARANTINED_URL_FEATURES.isdisjoint(ACTIVE_URL_FEATURES)
        assert QUARANTINED_URL_FEATURES | ACTIVE_URL_FEATURES == set(CANONICAL_URL_FEATURE_LIST)


# ---------------------------------------------------------------------------
# 2. Domain & IP Classification Vocabulary Tests (Requirement 4)
# ---------------------------------------------------------------------------

class TestDomainAndIPClassificationVocabulary:
    def test_all_seven_domain_resolution_statuses(self):
        """Must have exactly the 7 approved DomainResolutionStatus values."""
        expected_statuses = {
            "EXACT_MATCH": "exact_match",
            "WILDCARD_MATCH": "wildcard_match",
            "EXCEPTION_MATCH": "exception_match",
            "UNKNOWN_SUFFIX": "unknown_suffix",
            "INVALID_HOSTNAME": "invalid_hostname",
            "IP_LITERAL": "ip_literal",
            "NO_HOSTNAME": "no_hostname",
        }
        assert len(DomainResolutionStatus) == 7
        for name, value in expected_statuses.items():
            member = getattr(DomainResolutionStatus, name)
            assert member.value == value

    def test_domain_resolution_status_is_str_enum(self):
        """Status enum must be usable as regular string."""
        status = DomainResolutionStatus.EXACT_MATCH
        assert isinstance(status, str)
        assert status == "exact_match"

    def test_ip_classification_categories_vocabulary(self):
        """Must define the exact 9 approved RFC IP classification categories."""
        expected = {
            "loopback",
            "link_local",
            "multicast",
            "cgnat",
            "documentation",
            "special_purpose",
            "rfc1918",
            "rfc4193",
            "syntactically_global",
        }
        assert set(IP_CLASSIFICATION_CATEGORIES) == expected
        assert len(IP_CLASSIFICATION_CATEGORIES) == 9

    def test_domain_resolution_status_all_seven_accepted(self):
        """All seven DomainResolutionStatus enum values are accepted by UrlAnalysisItem."""
        for status in DomainResolutionStatus:
            item = UrlAnalysisItem(
                url_index=0,
                original_url_snippet="https://example.com",
                source=URLSource.PLAIN_TEXT,
                domain_resolution_status=status,
            )
            assert item.domain_resolution_status == status

    def test_domain_resolution_status_omission_rejected(self):
        """Omitting domain_resolution_status raises ValidationError (strictly required field)."""
        with pytest.raises(ValidationError) as exc_info:
            UrlAnalysisItem(
                url_index=0,
                original_url_snippet="https://example.com",
                source=URLSource.PLAIN_TEXT,
            )
        assert "domain_resolution_status" in str(exc_info.value)
        assert "Field required" in str(exc_info.value)

    def test_domain_resolution_status_none_rejected(self):
        """Passing None for domain_resolution_status raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            UrlAnalysisItem(
                url_index=0,
                original_url_snippet="https://example.com",
                source=URLSource.PLAIN_TEXT,
                domain_resolution_status=None,
            )
        assert "domain_resolution_status" in str(exc_info.value)

    def test_invalid_domain_resolution_status_rejected(self):
        """Invalid domain resolution status string raises ValidationError."""
        with pytest.raises(ValidationError):
            UrlAnalysisItem(
                url_index=0,
                original_url_snippet="test",
                source=URLSource.PLAIN_TEXT,
                domain_resolution_status="unapproved_arbitrary_status",
            )

    def test_invalid_ip_classification_rejected(self):
        """Invalid IP classification string raises ValidationError."""
        with pytest.raises(ValidationError):
            UrlAnalysisItem(
                url_index=0,
                original_url_snippet="test",
                source=URLSource.PLAIN_TEXT,
                domain_resolution_status=DomainResolutionStatus.EXACT_MATCH,
                ip_classification="public_internet",
            )


# ---------------------------------------------------------------------------
# 3. UrlFeatures Model Tests & Quarantined Semantics
# ---------------------------------------------------------------------------

class TestUrlFeaturesModel:
    def test_default_instantiation(self):
        """UrlFeatures can be instantiated with safe defaults (zero URLs email)."""
        features = UrlFeatures()
        assert features.total_url_count == 0
        assert features.has_urls is False
        assert features.http_url_count == 0
        assert features.has_brand_in_path is None
        assert features.has_form_action_url is None
        assert features.has_sender_domain_mismatch_url is None
        assert features.sender_domain_matching_url_ratio is None
        assert features.external_link_ratio is None

    def test_field_count_equals_39(self):
        """Model must define exactly 39 fields matching the canonical registry."""
        model_fields = set(UrlFeatures.model_fields.keys())
        assert len(model_fields) == 39
        assert model_fields == set(CANONICAL_URL_FEATURE_LIST)

    def test_extra_fields_forbidden(self):
        """Passing unapproved extra fields must raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            UrlFeatures(unapproved_extra_field="malicious_payload")
        assert "Extra inputs are not permitted" in str(exc_info.value)

    def test_non_negative_integer_bounds(self):
        """Count and length fields must not accept negative values."""
        with pytest.raises(ValidationError):
            UrlFeatures(total_url_count=-1)
        with pytest.raises(ValidationError):
            UrlFeatures(http_url_count=-1)
        with pytest.raises(ValidationError):
            UrlFeatures(max_url_length=-5)

    def test_quarantined_feature_brand_in_path_must_be_none(self):
        """has_brand_in_path is quarantined and must be None."""
        with pytest.raises(ValidationError) as exc_info:
            UrlFeatures(has_brand_in_path=True)
        assert "has_brand_in_path is a quarantined feature and must be None" in str(exc_info.value)

    def test_quarantined_feature_form_action_must_be_none(self):
        """has_form_action_url is quarantined and must be None."""
        with pytest.raises(ValidationError) as exc_info:
            UrlFeatures(has_form_action_url=True)
        assert "has_form_action_url is a quarantined feature and must be None" in str(exc_info.value)

    def test_quarantined_feature_http_url_count_is_calculated_int(self):
        """http_url_count accepts valid calculated non-negative integers."""
        f = UrlFeatures(http_url_count=5)
        assert f.http_url_count == 5


# ---------------------------------------------------------------------------
# 4. Sender Alignment Validation Tests (Requirement 7)
# ---------------------------------------------------------------------------

class TestSenderAlignmentValidation:
    def test_all_none_when_prerequisite_unavailable(self):
        """Valid: When sender domain is unavailable, all three fields are None."""
        f = UrlFeatures(
            has_sender_domain_mismatch_url=None,
            sender_domain_matching_url_ratio=None,
            external_link_ratio=None,
        )
        assert f.has_sender_domain_mismatch_url is None
        assert f.sender_domain_matching_url_ratio is None
        assert f.external_link_ratio is None

    def test_all_matching_valid(self):
        """Valid: When all URLs match sender domain, mismatch=False, ratio=1.0, ext_ratio=0.0."""
        f = UrlFeatures(
            has_sender_domain_mismatch_url=False,
            sender_domain_matching_url_ratio=1.0,
            external_link_ratio=0.0,
        )
        assert f.has_sender_domain_mismatch_url is False
        assert f.sender_domain_matching_url_ratio == 1.0
        assert f.external_link_ratio == 0.0

    def test_mixed_mismatch_valid(self):
        """Valid: When 75% match and 25% external, mismatch=True, ratios sum to 1.0."""
        f = UrlFeatures(
            has_sender_domain_mismatch_url=True,
            sender_domain_matching_url_ratio=0.75,
            external_link_ratio=0.25,
        )
        assert f.has_sender_domain_mismatch_url is True
        assert f.sender_domain_matching_url_ratio == 0.75
        assert f.external_link_ratio == 0.25

    def test_complete_mismatch_valid(self):
        """Valid: When 0% match and 100% external, mismatch=True, ratio=0.0, ext_ratio=1.0."""
        f = UrlFeatures(
            has_sender_domain_mismatch_url=True,
            sender_domain_matching_url_ratio=0.0,
            external_link_ratio=1.0,
        )
        assert f.has_sender_domain_mismatch_url is True
        assert f.sender_domain_matching_url_ratio == 0.0
        assert f.external_link_ratio == 1.0

    def test_mismatch_true_cannot_coexist_with_ratio_one(self):
        """Invalid: has_sender_domain_mismatch_url=True CANNOT coexist with ratio=1.0."""
        with pytest.raises(ValidationError) as exc_info:
            UrlFeatures(
                has_sender_domain_mismatch_url=True,
                sender_domain_matching_url_ratio=1.0,
                external_link_ratio=0.0,
            )
        assert "has_sender_domain_mismatch_url is True but sender_domain_matching_url_ratio is 1.0" in str(exc_info.value)

    def test_mismatch_false_requires_ratio_one(self):
        """Invalid: has_sender_domain_mismatch_url=False cannot have matching ratio < 1.0."""
        with pytest.raises(ValidationError) as exc_info:
            UrlFeatures(
                has_sender_domain_mismatch_url=False,
                sender_domain_matching_url_ratio=0.75,
                external_link_ratio=0.25,
            )
        assert "has_sender_domain_mismatch_url is False but sender_domain_matching_url_ratio is 0.75" in str(exc_info.value)

    def test_mismatch_flag_requires_matching_ratio(self):
        """Invalid: mismatch flag cannot be True or False if ratio is None."""
        with pytest.raises(ValidationError) as exc_info:
            UrlFeatures(
                has_sender_domain_mismatch_url=True,
                sender_domain_matching_url_ratio=None,
                external_link_ratio=None,
            )
        assert "has_sender_domain_mismatch_url must be None when sender domain matching ratio is None" in str(exc_info.value)

        with pytest.raises(ValidationError) as exc_info:
            UrlFeatures(
                has_sender_domain_mismatch_url=False,
                sender_domain_matching_url_ratio=None,
                external_link_ratio=None,
            )
        assert "has_sender_domain_mismatch_url must be None when sender domain matching ratio is None" in str(exc_info.value)

    def test_ratios_must_sum_to_one(self):
        """Invalid: sender_domain_matching_url_ratio + external_link_ratio must sum to 1.0."""
        with pytest.raises(ValidationError) as exc_info:
            UrlFeatures(
                has_sender_domain_mismatch_url=True,
                sender_domain_matching_url_ratio=0.8,
                external_link_ratio=0.3,
            )
        assert "must sum to 1.0" in str(exc_info.value)

    def test_both_ratios_must_be_populated_together(self):
        """Invalid: one ratio cannot be populated while the other is None."""
        with pytest.raises(ValidationError) as exc_info:
            UrlFeatures(
                has_sender_domain_mismatch_url=True,
                sender_domain_matching_url_ratio=0.8,
                external_link_ratio=None,
            )
        assert "external_link_ratio must not be None" in str(exc_info.value)

        with pytest.raises(ValidationError) as exc_info:
            UrlFeatures(
                has_sender_domain_mismatch_url=None,
                sender_domain_matching_url_ratio=None,
                external_link_ratio=0.2,
            )
        assert "external_link_ratio must be None when sender_domain_matching_url_ratio is None" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 5. Availability Contract Across All 39 Features (Requirement 5)
# ---------------------------------------------------------------------------

class TestUrlFeatureAvailability:
    def test_default_instantiation(self):
        """Can instantiate availability with defaults."""
        avail = UrlFeatureAvailability()
        assert avail.avail_has_urls is False
        assert avail.completeness_total == 0.0

    def test_completeness_bounds(self):
        """Completeness values must be within [0.0, 1.0]."""
        with pytest.raises(ValidationError):
            UrlFeatureAvailability(completeness_total=1.5)
        with pytest.raises(ValidationError):
            UrlFeatureAvailability(completeness_total=-0.1)

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            UrlFeatureAvailability(unknown_avail_field=True)

    def test_all_39_features_evaluated_no_urls(self):
        """Scenario 1: When no URLs exist (avail_has_urls=False), all 39 features are accounted for."""
        avail = UrlFeatureAvailability(avail_has_urls=False)
        expected: dict[str, bool] = {
            # Category A: URL Structural Properties (Features 1..11)
            "total_url_count": True,
            "unique_url_count": True,
            "has_urls": True,
            "http_url_count": True,
            "https_url_count": True,
            "suspicious_scheme_count": True,
            "has_suspicious_scheme": True,
            "has_non_default_port": True,
            "max_url_length": True,
            "max_path_depth": True,
            "has_executable_file_in_path": True,
            # Category B: Hostname & Domain Composition (Features 12..21)
            "has_ip_literal_url": True,
            "has_private_ip_url": True,
            "has_loopback_ip_url": True,
            "has_special_ip_url": True,
            "has_punycode_url": True,
            "max_subdomain_depth": True,
            "has_excessive_subdomains": True,
            "max_hostname_entropy": False,  # Missing evidence: entropy cannot be computed on empty string
            "unique_domain_count": True,
            "unique_fqdn_count": True,
            # Category C: Obfuscation, Encodings & Deception (Features 22..30)
            "has_at_symbol_in_url": True,
            "has_embedded_credentials": True,
            "has_percent_encoding": True,
            "has_double_percent_encoding": True,
            "max_percent_encoded_count": True,
            "has_brand_in_path": False,  # Quarantined
            "has_non_ascii_url": True,
            "has_unusual_ip_format": True,
            "malformed_url_count": True,
            # Category D: Contextual Alignment & Behavioral Indicators (Features 31..39)
            "has_url_shortener": True,
            "url_shortener_count": True,
            "has_redirect_parameter": True,
            "has_anchor_url_mismatch": True,
            "anchor_url_mismatch_count": True,
            "has_sender_domain_mismatch_url": False,  # Missing evidence: alignment requires URL occurrences
            "sender_domain_matching_url_ratio": False,  # Missing evidence: ratio undefined without URLs
            "external_link_ratio": False,  # Missing evidence: ratio undefined without URLs
            "has_form_action_url": False,  # Quarantined
        }
        assert len(expected) == 39
        for feat in CANONICAL_URL_FEATURE_LIST:
            assert avail.is_feature_available(feat) is expected[feat], (
                f"Feature {feat} mismatch in no-URL scenario: expected {expected[feat]}, got {avail.is_feature_available(feat)}"
            )

    def test_all_39_features_evaluated_missing_hostnames(self):
        """Scenario 2: URLs exist but hostnames are missing/unparseable (avail_hostname_features=False)."""
        avail = UrlFeatureAvailability(
            avail_has_urls=True,
            avail_structure_features=True,
            avail_hostname_features=False,
            avail_entropy_features=False,
            avail_sender_alignment=False,
            avail_anchor_text_analysis=False,
        )
        expected: dict[str, bool] = {
            # Category A: URL Structural Properties (Features 1..11)
            "total_url_count": True,
            "unique_url_count": True,
            "has_urls": True,
            "http_url_count": True,
            "https_url_count": True,
            "suspicious_scheme_count": True,
            "has_suspicious_scheme": True,
            "has_non_default_port": True,
            "max_url_length": True,
            "max_path_depth": True,
            "has_executable_file_in_path": True,
            # Category B: Hostname & Domain Composition (Features 12..21)
            "has_ip_literal_url": True,  # Evaluable as False per Section 5 missingness rule
            "has_private_ip_url": True,  # Evaluable as False per Section 5 missingness rule
            "has_loopback_ip_url": True,  # Evaluable as False per Section 5 missingness rule
            "has_special_ip_url": True,  # Evaluable as False per Section 5 missingness rule
            "has_punycode_url": True,  # Evaluable as False per Section 5 missingness rule
            "max_subdomain_depth": True,  # Evaluable as 0 per Section 5 (no resolvable domains)
            "has_excessive_subdomains": True,  # Evaluable as False per Section 5 (0 >= 3 is False)
            "max_hostname_entropy": False,  # Unavailable: requires hostnames to compute Shannon entropy
            "unique_domain_count": True,  # Evaluable as 0 per Section 5
            "unique_fqdn_count": True,  # Evaluable as 0 per Section 5
            # Category C: Obfuscation, Encodings & Deception (Features 22..30)
            "has_at_symbol_in_url": True,
            "has_embedded_credentials": True,
            "has_percent_encoding": True,
            "has_double_percent_encoding": True,
            "max_percent_encoded_count": True,
            "has_brand_in_path": False,  # Quarantined
            "has_non_ascii_url": True,
            "has_unusual_ip_format": True,
            "malformed_url_count": True,
            # Category D: Contextual Alignment & Behavioral Indicators (Features 31..39)
            "has_url_shortener": True,
            "url_shortener_count": True,
            "has_redirect_parameter": True,
            "has_anchor_url_mismatch": True,  # Evaluable as False per Section 5
            "anchor_url_mismatch_count": True,  # Evaluable as 0 per Section 5
            "has_sender_domain_mismatch_url": False,  # Unavailable: requires sender alignment preconditions
            "sender_domain_matching_url_ratio": False,  # Unavailable: requires sender alignment preconditions
            "external_link_ratio": False,  # Unavailable: requires sender alignment preconditions
            "has_form_action_url": False,  # Quarantined
        }
        assert len(expected) == 39
        for feat in CANONICAL_URL_FEATURE_LIST:
            assert avail.is_feature_available(feat) is expected[feat], (
                f"Feature {feat} mismatch in missing-hostnames scenario: expected {expected[feat]}, got {avail.is_feature_available(feat)}"
            )

    def test_all_39_features_evaluated_missing_sender_alignment(self):
        """Scenario 3: When From header is missing or unresolvable (avail_sender_alignment=False)."""
        avail = UrlFeatureAvailability(
            avail_has_urls=True,
            avail_structure_features=True,
            avail_hostname_features=True,
            avail_entropy_features=True,
            avail_sender_alignment=False,
            avail_anchor_text_analysis=True,
        )
        expected: dict[str, bool] = {
            # Category A: URL Structural Properties (Features 1..11)
            "total_url_count": True,
            "unique_url_count": True,
            "has_urls": True,
            "http_url_count": True,
            "https_url_count": True,
            "suspicious_scheme_count": True,
            "has_suspicious_scheme": True,
            "has_non_default_port": True,
            "max_url_length": True,
            "max_path_depth": True,
            "has_executable_file_in_path": True,
            # Category B: Hostname & Domain Composition (Features 12..21)
            "has_ip_literal_url": True,
            "has_private_ip_url": True,
            "has_loopback_ip_url": True,
            "has_special_ip_url": True,
            "has_punycode_url": True,
            "max_subdomain_depth": True,
            "has_excessive_subdomains": True,
            "max_hostname_entropy": True,
            "unique_domain_count": True,
            "unique_fqdn_count": True,
            # Category C: Obfuscation, Encodings & Deception (Features 22..30)
            "has_at_symbol_in_url": True,
            "has_embedded_credentials": True,
            "has_percent_encoding": True,
            "has_double_percent_encoding": True,
            "max_percent_encoded_count": True,
            "has_brand_in_path": False,  # Quarantined
            "has_non_ascii_url": True,
            "has_unusual_ip_format": True,
            "malformed_url_count": True,
            # Category D: Contextual Alignment & Behavioral Indicators (Features 31..39)
            "has_url_shortener": True,
            "url_shortener_count": True,
            "has_redirect_parameter": True,
            "has_anchor_url_mismatch": True,
            "anchor_url_mismatch_count": True,
            "has_sender_domain_mismatch_url": False,  # Unavailable: requires sender alignment
            "sender_domain_matching_url_ratio": False,  # Unavailable: requires sender alignment
            "external_link_ratio": False,  # Unavailable: requires sender alignment
            "has_form_action_url": False,  # Quarantined
        }
        assert len(expected) == 39
        for feat in CANONICAL_URL_FEATURE_LIST:
            assert avail.is_feature_available(feat) is expected[feat], (
                f"Feature {feat} mismatch in missing-sender scenario: expected {expected[feat]}, got {avail.is_feature_available(feat)}"
            )

    def test_all_39_features_evaluated_missing_anchor_text(self):
        """Scenario 4: When email has no HTML anchors with text (avail_anchor_text_analysis=False)."""
        avail = UrlFeatureAvailability(
            avail_has_urls=True,
            avail_structure_features=True,
            avail_hostname_features=True,
            avail_entropy_features=True,
            avail_sender_alignment=True,
            avail_anchor_text_analysis=False,
        )
        expected: dict[str, bool] = {
            # Category A: URL Structural Properties (Features 1..11)
            "total_url_count": True,
            "unique_url_count": True,
            "has_urls": True,
            "http_url_count": True,
            "https_url_count": True,
            "suspicious_scheme_count": True,
            "has_suspicious_scheme": True,
            "has_non_default_port": True,
            "max_url_length": True,
            "max_path_depth": True,
            "has_executable_file_in_path": True,
            # Category B: Hostname & Domain Composition (Features 12..21)
            "has_ip_literal_url": True,
            "has_private_ip_url": True,
            "has_loopback_ip_url": True,
            "has_special_ip_url": True,
            "has_punycode_url": True,
            "max_subdomain_depth": True,
            "has_excessive_subdomains": True,
            "max_hostname_entropy": True,
            "unique_domain_count": True,
            "unique_fqdn_count": True,
            # Category C: Obfuscation, Encodings & Deception (Features 22..30)
            "has_at_symbol_in_url": True,
            "has_embedded_credentials": True,
            "has_percent_encoding": True,
            "has_double_percent_encoding": True,
            "max_percent_encoded_count": True,
            "has_brand_in_path": False,  # Quarantined
            "has_non_ascii_url": True,
            "has_unusual_ip_format": True,
            "malformed_url_count": True,
            # Category D: Contextual Alignment & Behavioral Indicators (Features 31..39)
            "has_url_shortener": True,
            "url_shortener_count": True,
            "has_redirect_parameter": True,
            "has_anchor_url_mismatch": True,  # Evaluable as False per Section 5
            "anchor_url_mismatch_count": True,  # Evaluable as 0 per Section 5
            "has_sender_domain_mismatch_url": True,
            "sender_domain_matching_url_ratio": True,
            "external_link_ratio": True,
            "has_form_action_url": False,  # Quarantined
        }
        assert len(expected) == 39
        for feat in CANONICAL_URL_FEATURE_LIST:
            assert avail.is_feature_available(feat) is expected[feat], (
                f"Feature {feat} mismatch in missing-anchor scenario: expected {expected[feat]}, got {avail.is_feature_available(feat)}"
            )

    def test_all_39_features_evaluated_all_prerequisites_present(self):
        """Scenario 5: When all prerequisites are met: 37 features True, 2 quarantined False."""
        avail = UrlFeatureAvailability(
            avail_has_urls=True,
            avail_structure_features=True,
            avail_hostname_features=True,
            avail_entropy_features=True,
            avail_sender_alignment=True,
            avail_anchor_text_analysis=True,
        )
        expected: dict[str, bool] = {
            # Category A: URL Structural Properties (Features 1..11)
            "total_url_count": True,
            "unique_url_count": True,
            "has_urls": True,
            "http_url_count": True,
            "https_url_count": True,
            "suspicious_scheme_count": True,
            "has_suspicious_scheme": True,
            "has_non_default_port": True,
            "max_url_length": True,
            "max_path_depth": True,
            "has_executable_file_in_path": True,
            # Category B: Hostname & Domain Composition (Features 12..21)
            "has_ip_literal_url": True,
            "has_private_ip_url": True,
            "has_loopback_ip_url": True,
            "has_special_ip_url": True,
            "has_punycode_url": True,
            "max_subdomain_depth": True,
            "has_excessive_subdomains": True,
            "max_hostname_entropy": True,
            "unique_domain_count": True,
            "unique_fqdn_count": True,
            # Category C: Obfuscation, Encodings & Deception (Features 22..30)
            "has_at_symbol_in_url": True,
            "has_embedded_credentials": True,
            "has_percent_encoding": True,
            "has_double_percent_encoding": True,
            "max_percent_encoded_count": True,
            "has_brand_in_path": False,  # Quarantined
            "has_non_ascii_url": True,
            "has_unusual_ip_format": True,
            "malformed_url_count": True,
            # Category D: Contextual Alignment & Behavioral Indicators (Features 31..39)
            "has_url_shortener": True,
            "url_shortener_count": True,
            "has_redirect_parameter": True,
            "has_anchor_url_mismatch": True,
            "anchor_url_mismatch_count": True,
            "has_sender_domain_mismatch_url": True,
            "sender_domain_matching_url_ratio": True,
            "external_link_ratio": True,
            "has_form_action_url": False,  # Quarantined
        }
        assert len(expected) == 39
        for feat in CANONICAL_URL_FEATURE_LIST:
            assert avail.is_feature_available(feat) is expected[feat], (
                f"Feature {feat} mismatch in all-prerequisites scenario: expected {expected[feat]}, got {avail.is_feature_available(feat)}"
            )

    # ------------------------------------------------------------------
    # Completeness Consistency Tests (Section 10.2)
    # ------------------------------------------------------------------

    def test_completeness_valid_consistent_all_present(self):
        """Consistent completeness with all prerequisites present (total = 1.0)."""
        avail = UrlFeatureAvailability(
            avail_has_urls=True,
            avail_structure_features=True,
            avail_hostname_features=True,
            avail_entropy_features=True,
            avail_sender_alignment=True,
            avail_anchor_text_analysis=True,
            completeness_structure=1.0,
            completeness_hostname=1.0,
            completeness_obfuscation=1.0,
            completeness_context=1.0,
            completeness_total=1.0,
        )
        assert avail.completeness_total == 1.0

    def test_completeness_valid_consistent_partial_context(self):
        """Consistent completeness with sender alignment available but no anchor text (total = 0.875)."""
        avail = UrlFeatureAvailability(
            avail_has_urls=True,
            avail_structure_features=True,
            avail_hostname_features=True,
            avail_entropy_features=True,
            avail_sender_alignment=True,
            avail_anchor_text_analysis=False,
            completeness_structure=1.0,
            completeness_hostname=1.0,
            completeness_obfuscation=1.0,
            completeness_context=0.5,
            completeness_total=0.875,
        )
        assert avail.completeness_total == 0.875

    def test_completeness_valid_consistent_no_hostnames(self):
        """Consistent completeness with invalid hostnames and no context (total = 0.625)."""
        avail = UrlFeatureAvailability(
            avail_has_urls=True,
            avail_structure_features=True,
            avail_hostname_features=False,
            avail_entropy_features=False,
            avail_sender_alignment=False,
            avail_anchor_text_analysis=False,
            completeness_structure=1.0,
            completeness_hostname=0.5,
            completeness_obfuscation=1.0,
            completeness_context=0.0,
            completeness_total=0.625,
        )
        assert avail.completeness_total == 0.625

    def test_completeness_inconsistent_total_rejected(self):
        """Rejecting completeness_total that does not equal arithmetic mean of the four components."""
        with pytest.raises(ValidationError) as exc_info:
            UrlFeatureAvailability(
                avail_has_urls=True,
                avail_structure_features=True,
                avail_hostname_features=True,
                avail_entropy_features=True,
                avail_sender_alignment=True,
                avail_anchor_text_analysis=True,
                completeness_structure=1.0,
                completeness_hostname=1.0,
                completeness_obfuscation=1.0,
                completeness_context=1.0,
                completeness_total=0.5,  # Inconsistent: mean is 1.0!
            )
        assert "must equal arithmetic mean of the four domain completeness values" in str(exc_info.value)

    def test_completeness_boundary_values(self):
        """Testing boundary values for completeness (min 0.625 with URLs, max 1.0 with URLs, 0.0 without URLs)."""
        # Min boundary with URLs: C_host=0.5, C_context=0.0 -> total = 0.625
        min_avail = UrlFeatureAvailability(
            avail_has_urls=True,
            avail_hostname_features=False,
            avail_sender_alignment=False,
            avail_anchor_text_analysis=False,
            completeness_structure=1.0,
            completeness_hostname=0.5,
            completeness_obfuscation=1.0,
            completeness_context=0.0,
            completeness_total=0.625,
        )
        assert min_avail.completeness_total == 0.625

        # Max boundary with URLs: C_host=1.0, C_context=1.0 -> total = 1.0
        max_avail = UrlFeatureAvailability(
            avail_has_urls=True,
            avail_hostname_features=True,
            avail_sender_alignment=True,
            avail_anchor_text_analysis=True,
            completeness_structure=1.0,
            completeness_hostname=1.0,
            completeness_obfuscation=1.0,
            completeness_context=1.0,
            completeness_total=1.0,
        )
        assert max_avail.completeness_total == 1.0

        # Zero boundary without URLs: total = 0.0
        zero_avail = UrlFeatureAvailability(avail_has_urls=False)
        assert zero_avail.completeness_total == 0.0

    def test_completeness_no_urls_non_zero_total_rejected(self):
        """Section 10.2: E_comp_url = 0.0 if total_url_count == 0. Non-zero total must be rejected."""
        with pytest.raises(ValidationError) as exc_info:
            UrlFeatureAvailability(
                avail_has_urls=False,
                completeness_total=0.5,
            )
        assert "When avail_has_urls is False, completeness_total must be 0.0" in str(exc_info.value)

    def test_completeness_no_urls_non_zero_component_rejected(self):
        """Section 10.2: All domain completeness values must be 0.0 when no URLs exist."""
        with pytest.raises(ValidationError) as exc_info:
            UrlFeatureAvailability(
                avail_has_urls=False,
                completeness_structure=1.0,
            )
        assert "When avail_has_urls is False, all domain completeness values must be 0.0" in str(exc_info.value)

    def test_completeness_component_rule_structure_must_be_one(self):
        """Section 10.2: C_struct = 1.0 when URLs exist."""
        with pytest.raises(ValidationError) as exc_info:
            UrlFeatureAvailability(
                avail_has_urls=True,
                avail_hostname_features=True,
                completeness_structure=0.8,  # Must be 1.0!
                completeness_hostname=1.0,
                completeness_obfuscation=1.0,
                completeness_context=0.0,
                completeness_total=0.7,
            )
        assert "completeness_structure must be 1.0" in str(exc_info.value)

    def test_completeness_component_rule_hostname_must_match_availability(self):
        """Section 10.2: C_host = 1.0 if all hostnames valid, else 0.5."""
        with pytest.raises(ValidationError) as exc_info:
            UrlFeatureAvailability(
                avail_has_urls=True,
                avail_hostname_features=False,  # Should require C_host=0.5
                completeness_structure=1.0,
                completeness_hostname=1.0,  # Inconsistent!
                completeness_obfuscation=1.0,
                completeness_context=0.0,
                completeness_total=0.75,
            )
        assert "completeness_hostname (1.0) must match Section 10.2 definition" in str(exc_info.value)

    def test_completeness_component_rule_obfuscation_must_be_one(self):
        """Section 10.2: C_obfus = 1.0 when URLs exist."""
        with pytest.raises(ValidationError) as exc_info:
            UrlFeatureAvailability(
                avail_has_urls=True,
                avail_hostname_features=True,
                completeness_structure=1.0,
                completeness_hostname=1.0,
                completeness_obfuscation=0.5,  # Must be 1.0!
                completeness_context=0.0,
                completeness_total=0.625,
            )
        assert "completeness_obfuscation must be 1.0" in str(exc_info.value)

    def test_completeness_component_rule_context_must_match_formula(self):
        """Section 10.2: C_context = 0.5 * (I(avail_sender_alignment) + I(avail_anchor_text_analysis))."""
        with pytest.raises(ValidationError) as exc_info:
            UrlFeatureAvailability(
                avail_has_urls=True,
                avail_hostname_features=True,
                avail_sender_alignment=True,
                avail_anchor_text_analysis=False,  # Expected C_context = 0.5 * (1 + 0) = 0.5
                completeness_structure=1.0,
                completeness_hostname=1.0,
                completeness_obfuscation=1.0,
                completeness_context=1.0,  # Inconsistent!
                completeness_total=1.0,
            )
        assert "completeness_context (1.0) must match Section 10.2 definition" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 6. Evidence Category Validation Across All 39 Features (Requirement 3)
# ---------------------------------------------------------------------------

class TestUrlEvidenceItemCategoryValidation:
    def test_all_39_features_valid_category_mapping(self):
        """Every canonical feature must instantiate UrlEvidenceItem with its approved category."""
        for i, feat in enumerate(CANONICAL_URL_FEATURE_LIST):
            expected_category = FEATURE_TO_CATEGORY_MAP[feat]
            item = UrlEvidenceItem(
                finding_id=f"ev_{i}",
                feature_name=feat,
                category=expected_category,
                url_index=0,
                source=URLSource.PLAIN_TEXT,
                observed_value="test_val",
                description="test description",
                limitations_and_benign_explanations="benign context",
            )
            assert item.category == expected_category
            assert item.feature_name == feat

    def test_mismatched_category_raises_validation_error(self):
        """UrlEvidenceItem with mismatched category raises ValidationError."""
        # Feature 1 (total_url_count) belongs to Category A, not Category B
        with pytest.raises(ValidationError) as exc_info:
            UrlEvidenceItem(
                finding_id="ev_err",
                feature_name="total_url_count",
                category="Category B",  # Mismatch!
                url_index=0,
                source=URLSource.PLAIN_TEXT,
                observed_value="1",
                description="desc",
                limitations_and_benign_explanations="benign",
            )
        assert "belongs to 'Category A', got category 'Category B'" in str(exc_info.value)

    def test_invalid_category_string_raises_validation_error(self):
        """UrlEvidenceItem with unapproved category string raises ValidationError."""
        with pytest.raises(ValidationError):
            UrlEvidenceItem(
                finding_id="ev_err",
                feature_name="total_url_count",
                category="Category Z",  # Unapproved category!
                url_index=0,
                source=URLSource.PLAIN_TEXT,
                observed_value="1",
                description="desc",
                limitations_and_benign_explanations="benign",
            )

    def test_evidence_container_caps(self):
        """UrlEvidence container enforces strict 100/50 caps."""
        valid_items = [
            UrlEvidenceItem(
                finding_id=f"ev_{i}",
                feature_name="has_urls",
                category="Category A",
                url_index=i,
                source=URLSource.PLAIN_TEXT,
                observed_value="https://example.com",
                description="test",
                limitations_and_benign_explanations="benign",
            )
            for i in range(100)
        ]
        evidence = UrlEvidence(evidence_items=valid_items)
        assert len(evidence.evidence_items) == 100

        # 101 items rejected
        with pytest.raises(ValidationError) as exc_info:
            UrlEvidence(evidence_items=valid_items + [valid_items[0]])
        assert "List should have at most 100 items" in str(exc_info.value)

        # 50 anomalous hostnames accepted, 51 rejected
        evidence_hosts = UrlEvidence(detected_anomalous_hostnames=[f"host{i}.com" for i in range(50)])
        assert len(evidence_hosts.detected_anomalous_hostnames) == 50

        with pytest.raises(ValidationError):
            UrlEvidence(detected_anomalous_hostnames=[f"host{i}.com" for i in range(51)])


# ---------------------------------------------------------------------------
# 7. Result Serialization Contract & analysis_items Aliasing (Requirement 2)
# ---------------------------------------------------------------------------

class TestUrlAgentResultSerializationContract:
    def test_construction_with_analysis_items_field(self):
        """Primary construction using analysis_items."""
        result = UrlAgentResult(
            email_id="email_001",
            features=UrlFeatures(),
            availability=UrlFeatureAvailability(),
            evidence=UrlEvidence(),
            analysis_items=[
                UrlAnalysisItem(
                    url_index=0,
                    original_url_snippet="https://example.com",
                    source=URLSource.PLAIN_TEXT,
                    domain_resolution_status=DomainResolutionStatus.EXACT_MATCH,
                )
            ],
        )
        assert len(result.analysis_items) == 1
        assert len(result.per_url_analyses) == 1
        assert result.analysis_items[0].original_url_snippet == "https://example.com"

    def test_construction_with_per_url_analyses_alias(self):
        """Backward-compatibility construction using per_url_analyses alias."""
        result = UrlAgentResult(
            email_id="email_002",
            features=UrlFeatures(),
            availability=UrlFeatureAvailability(),
            evidence=UrlEvidence(),
            per_url_analyses=[
                UrlAnalysisItem(
                    url_index=0,
                    original_url_snippet="https://example.org",
                    source=URLSource.HTML_HREF,
                    domain_resolution_status=DomainResolutionStatus.EXACT_MATCH,
                )
            ],
        )
        assert len(result.analysis_items) == 1
        assert len(result.per_url_analyses) == 1
        assert result.analysis_items[0].original_url_snippet == "https://example.org"

    def test_model_dump_uses_analysis_items(self):
        """model_dump() serializes analysis_items as the primary key."""
        result = UrlAgentResult(
            email_id="email_003",
            features=UrlFeatures(),
            availability=UrlFeatureAvailability(),
            evidence=UrlEvidence(),
            analysis_items=[
                UrlAnalysisItem(
                    url_index=0,
                    original_url_snippet="https://example.net",
                    source=URLSource.PLAIN_TEXT,
                    domain_resolution_status=DomainResolutionStatus.EXACT_MATCH,
                )
            ],
        )
        dump = result.model_dump()
        assert "analysis_items" in dump
        assert len(dump["analysis_items"]) == 1

    def test_json_serialization_uses_analysis_items(self):
        """model_dump_json() outputs analysis_items as the serialized key."""
        result = UrlAgentResult(
            email_id="email_004",
            features=UrlFeatures(),
            availability=UrlFeatureAvailability(),
            evidence=UrlEvidence(),
            analysis_items=[
                UrlAnalysisItem(
                    url_index=0,
                    original_url_snippet="https://example.net",
                    source=URLSource.PLAIN_TEXT,
                    domain_resolution_status=DomainResolutionStatus.EXACT_MATCH,
                )
            ],
        )
        json_str = result.model_dump_json()
        parsed = json.loads(json_str)
        assert "analysis_items" in parsed
        assert len(parsed["analysis_items"]) == 1

    def test_json_deserialization_from_analysis_items(self):
        """model_validate_json() deserializes JSON containing analysis_items."""
        raw_json = json.dumps({
            "email_id": "email_005",
            "features": UrlFeatures().model_dump(),
            "availability": UrlFeatureAvailability().model_dump(),
            "evidence": UrlEvidence().model_dump(),
            "analysis_items": [
                {
                    "url_index": 0,
                    "original_url_snippet": "https://example.net",
                    "source": "plain_text",
                    "domain_resolution_status": "exact_match",
                }
            ],
        })
        result = UrlAgentResult.model_validate_json(raw_json)
        assert result.email_id == "email_005"
        assert len(result.analysis_items) == 1
        assert result.analysis_items[0].original_url_snippet == "https://example.net"

    def test_json_deserialization_from_per_url_analyses_alias(self):
        """model_validate_json() deserializes legacy JSON containing per_url_analyses."""
        raw_json = json.dumps({
            "email_id": "email_006",
            "features": UrlFeatures().model_dump(),
            "availability": UrlFeatureAvailability().model_dump(),
            "evidence": UrlEvidence().model_dump(),
            "per_url_analyses": [
                {
                    "url_index": 0,
                    "original_url_snippet": "https://legacy.example.com",
                    "source": "html_href",
                    "domain_resolution_status": "exact_match",
                }
            ],
        })
        result = UrlAgentResult.model_validate_json(raw_json)
        assert result.email_id == "email_006"
        assert len(result.analysis_items) == 1
        assert result.analysis_items[0].original_url_snippet == "https://legacy.example.com"

    def test_analysis_items_cap_200(self):
        """analysis_items is strictly capped at 200 items."""
        valid_items = [
            UrlAnalysisItem(
                url_index=i,
                original_url_snippet=f"https://example{i}.com",
                source=URLSource.PLAIN_TEXT,
                domain_resolution_status=DomainResolutionStatus.EXACT_MATCH,
            )
            for i in range(200)
        ]
        result = UrlAgentResult(
            email_id="email_cap_test",
            features=UrlFeatures(),
            availability=UrlFeatureAvailability(),
            evidence=UrlEvidence(),
            analysis_items=valid_items,
        )
        assert len(result.analysis_items) == 200

        with pytest.raises(ValidationError) as exc_info:
            UrlAgentResult(
                email_id="email_cap_test",
                features=UrlFeatures(),
                availability=UrlFeatureAvailability(),
                evidence=UrlEvidence(),
                analysis_items=valid_items + [valid_items[0]],
            )
        assert "List should have at most 200 items" in str(exc_info.value)

    def test_alias_url_agent_output(self):
        """UrlAgentOutput is an identical alias for UrlAgentResult."""
        assert UrlAgentOutput is UrlAgentResult

    def test_no_risk_assessment_in_module(self):
        """UrlRiskAssessment is strictly absent from the schema module."""
        import app.schemas.url_agent_schema as mod
        assert not hasattr(mod, "UrlRiskAssessment")
        assert not hasattr(mod, "UrlRisk")
        assert not hasattr(mod, "UrlRiskScore")
