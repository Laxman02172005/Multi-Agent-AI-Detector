"""
anchor_analyzer.py
-------------------
Public interface for visual anchor text mismatch analysis.
Re-exports check_anchor_url_mismatch from contextual_analyzer.
"""

from app.agents.url_components.contextual_analyzer import check_anchor_url_mismatch

__all__ = ["check_anchor_url_mismatch"]
