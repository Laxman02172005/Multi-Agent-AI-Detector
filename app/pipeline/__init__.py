"""
app/pipeline/__init__.py
------------------------
Public interface for the End-to-End Phishing Detection Pipeline.
"""

from app.pipeline.orchestrator import (
    PhishingDetectorPipeline,
    PipelineInitializationError,
)
from app.schemas.pipeline_schema import PhishingAnalysisReport

__all__ = [
    "PhishingDetectorPipeline",
    "PipelineInitializationError",
    "PhishingAnalysisReport",
]
