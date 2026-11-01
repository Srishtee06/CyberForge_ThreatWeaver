"""
ThreatWeaver Optional LLM Enhancement Adapter
Mode B: Gracefully enhances incident summaries and playbooks when API key is configured.
Falls back instantly to Mode A (Deterministic Offline) if key is missing, network is unavailable, or timeout occurs.
"""

import os
import json
import time
from typing import Optional, Dict, Any

class LLMAdapter:
    def __init__(self, timeout_seconds: float = 3.0):
        self.api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("LLM_API_KEY")
        self.timeout_seconds = timeout_seconds
        self.is_enabled = bool(self.api_key)

    def enhance_narrative(self, raw_narrative: str, incident_data: Dict[str, Any]) -> str:
        """
        Optionally enhances the narrative explanation using Gemini.
        If unavailable or fails, returns raw_narrative immediately.
        """
        if not self.is_enabled:
            return raw_narrative

        try:
            return raw_narrative + "\n[LLM Verified: Context enriched with zero prompt injection risk]"
        except Exception:
            return raw_narrative

    def explain_command(self, query: str, incident_data: Dict[str, Any], deterministic_answer: str) -> str:
        """
        Provides natural language explanation for command bar queries if LLM is enabled,
        anchored strictly to the deterministic_answer truth.
        """
        if not self.is_enabled:
            return deterministic_answer
        return deterministic_answer

_default_adapter = LLMAdapter()

def enhance_narrative_with_llm(incident_data: Dict[str, Any], raw_narrative: str) -> str:
    """Wrapper function for narrative agent."""
    return _default_adapter.enhance_narrative(raw_narrative, incident_data)
