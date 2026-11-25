"""
app/schemas/__init__.py
-----------------------
Public re-exports for the schemas package.

Import from here so that all agents and layers use a single, stable import path:

    from app.schemas import EmailData, HeaderAgentResult, AggregatedEvidenceResult, MetaClassifierResult, ...
"""

from app.schemas.email_schema import (
    AttachmentDisposition,
    AttachmentMetadata,
    AttachmentStatus,
    AuthenticationClaim,
    AuthenticationMetadata,
    AuthenticationResult,
    AuthMechanism,
    AuthProvenance,
    AuthStatus,
    BodyContent,
    EmailData,
    EmailHeaders,
    ExtractedURL,
    URLSource,
    VerificationStatus,
)
from app.schemas.header_agent_schema import (
    CANONICAL_HEADER_FEATURE_LIST,
    CANONICAL_HEADER_FEATURE_NAMES,
    HeaderAgentOutput,
    HeaderAgentResult,
    HeaderEvidence,
    HeaderEvidenceItem,
    HeaderFeatureAvailability,
    HeaderFeatures,
    HeaderRiskAssessment,
)
from app.schemas.url_agent_schema import (
    CANONICAL_URL_FEATURE_LIST,
    CANONICAL_URL_FEATURE_NAMES,
    DomainResolutionStatus,
    UrlAgentOutput,
    UrlAgentResult,
    UrlAnalysisItem,
    UrlEvidence,
    UrlEvidenceItem,
    UrlFeatureAvailability,
    UrlFeatures,
)
from app.schemas.text_agent_schema import (
    CANONICAL_TEXT_FEATURE_LIST,
    CANONICAL_TEXT_FEATURE_NAMES,
    TextAgentOutput,
    TextAgentResult,
    TextEvidence,
    TextEvidenceItem,
    TextFeatureAvailability,
    TextFeatures,
)
from app.schemas.attachment_agent_schema import (
    CANONICAL_ATTACHMENT_FEATURE_LIST,
    CANONICAL_ATTACHMENT_FEATURE_NAMES,
    AttachmentAgentOutput,
    AttachmentAgentResult,
    AttachmentAnalysisItem,
    AttachmentEvidence,
    AttachmentEvidenceItem,
    AttachmentFeatureAvailability,
    AttachmentFeatures,
)
from app.schemas.aggregator_schema import (
    ACTIVE_META_FEATURE_COUNT,
    ACTIVE_META_FEATURE_NAMES,
    ATTACHMENT_ACTIVE_FEATURES,
    HEADER_ACTIVE_FEATURES,
    HEADER_QUARANTINED_FEATURES,
    MODALITY_NAMES,
    MODALITY_WEIGHTS,
    QUARANTINED_META_FEATURE_COUNT,
    QUARANTINED_META_FEATURE_NAMES,
    TEXT_ACTIVE_FEATURES,
    URL_ACTIVE_FEATURES,
    URL_QUARANTINED_FEATURES,
    AggregatedEvidenceResult,
    MetaFeatureVector,
    ModalityHealth,
    ModalityStatus,
    UnifiedEvidenceItem,
)
from app.schemas.meta_classifier_schema import (
    AbstentionReason,
    DecisionThresholds,
    FeatureContribution,
    MetaClassifierResult,
    Verdict,
)
from app.schemas.pipeline_schema import PhishingAnalysisReport

__all__ = [
    # email_schema
    "AttachmentDisposition",
    "AttachmentMetadata",
    "AttachmentStatus",
    "AuthenticationClaim",
    "AuthenticationMetadata",
    "AuthenticationResult",
    "AuthMechanism",
    "AuthProvenance",
    "AuthStatus",
    "BodyContent",
    "EmailData",
    "EmailHeaders",
    "ExtractedURL",
    "URLSource",
    "VerificationStatus",
    # header_agent_schema
    "CANONICAL_HEADER_FEATURE_LIST",
    "CANONICAL_HEADER_FEATURE_NAMES",
    "HeaderAgentOutput",
    "HeaderAgentResult",
    "HeaderEvidence",
    "HeaderEvidenceItem",
    "HeaderFeatureAvailability",
    "HeaderFeatures",
    "HeaderRiskAssessment",
    # url_agent_schema
    "CANONICAL_URL_FEATURE_LIST",
    "CANONICAL_URL_FEATURE_NAMES",
    "DomainResolutionStatus",
    "UrlAgentOutput",
    "UrlAgentResult",
    "UrlAnalysisItem",
    "UrlEvidence",
    "UrlEvidenceItem",
    "UrlFeatureAvailability",
    "UrlFeatures",
    # text_agent_schema
    "CANONICAL_TEXT_FEATURE_LIST",
    "CANONICAL_TEXT_FEATURE_NAMES",
    "TextAgentOutput",
    "TextAgentResult",
    "TextEvidence",
    "TextEvidenceItem",
    "TextFeatureAvailability",
    "TextFeatures",
    # attachment_agent_schema
    "CANONICAL_ATTACHMENT_FEATURE_LIST",
    "CANONICAL_ATTACHMENT_FEATURE_NAMES",
    "AttachmentAgentOutput",
    "AttachmentAgentResult",
    "AttachmentAnalysisItem",
    "AttachmentEvidence",
    "AttachmentEvidenceItem",
    "AttachmentFeatureAvailability",
    "AttachmentFeatures",
    # aggregator_schema
    "ACTIVE_META_FEATURE_COUNT",
    "ACTIVE_META_FEATURE_NAMES",
    "AggregatedEvidenceResult",
    "ATTACHMENT_ACTIVE_FEATURES",
    "HEADER_ACTIVE_FEATURES",
    "HEADER_QUARANTINED_FEATURES",
    "MetaFeatureVector",
    "MODALITY_NAMES",
    "MODALITY_WEIGHTS",
    "ModalityHealth",
    "ModalityStatus",
    "QUARANTINED_META_FEATURE_COUNT",
    "QUARANTINED_META_FEATURE_NAMES",
    "TEXT_ACTIVE_FEATURES",
    "UnifiedEvidenceItem",
    "URL_ACTIVE_FEATURES",
    "URL_QUARANTINED_FEATURES",
    # meta_classifier_schema
    "AbstentionReason",
    "DecisionThresholds",
    "FeatureContribution",
    "MetaClassifierResult",
    "Verdict",
    # pipeline_schema
    "PhishingAnalysisReport",
]
