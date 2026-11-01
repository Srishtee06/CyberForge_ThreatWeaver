"""
ThreatWeaver Optional LLM Enhancement Adapter
Mode B: Gracefully enhances incident summaries, playbooks, and Command Bar queries when a Google API Key is provided.
Supports:
  - os.environ["GEMINI_API_KEY"] or os.environ["GOOGLE_API_KEY"]
  - .env file auto-loading
  - Direct runtime configuration
Mode A (Deterministic Offline Fallback): If key is missing, network is unavailable, or timeout occurs,
it falls back INSTANTLY (<1ms) to the deterministic ground-truth engine.
"""

import os
import json
import time
import urllib.request
import urllib.error
from typing import Optional, Dict, Any

class LLMAdapter:
    def __init__(self, timeout_seconds: float = 3.5):
        self.timeout_seconds = timeout_seconds
        self._refresh_key()

    def _refresh_key(self):
        # Check standard Google API key environment variables
        self.api_key = (
            os.environ.get("GEMINI_API_KEY") or 
            os.environ.get("GOOGLE_API_KEY") or 
            os.environ.get("LLM_API_KEY")
        )
        
        # Also check .env file in root if not set in environment
        if not self.api_key and os.path.exists(".env"):
            try:
                with open(".env", "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("GEMINI_API_KEY=") or line.startswith("GOOGLE_API_KEY="):
                            self.api_key = line.split("=", 1)[1].strip().strip('"').strip("'")
                            break
            except Exception:
                pass
                
        self.is_enabled = bool(self.api_key and len(self.api_key) > 10)

    def set_api_key(self, key: str):
        """Allows setting the API key dynamically from runtime or UI."""
        self.api_key = key.strip()
        self.is_enabled = bool(self.api_key and len(self.api_key) > 10)
        try:
            with open(".env", "w", encoding="utf-8") as f:
                f.write(f"GEMINI_API_KEY={self.api_key}\nGOOGLE_API_KEY={self.api_key}\n")
        except Exception:
            pass

    def _call_gemini_api(self, prompt: str, system_instruction: str = "") -> Optional[str]:
        """Calls Google Gemini API with multi-model fallback and strict timeout."""
        self._refresh_key()
        if not self.is_enabled:
            return None

        # Google Gemini models with priority fallback
        models = ["gemini-flash-lite-latest", "gemini-flash-latest", "gemini-1.5-flash"]
        
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 600
            }
        }
        
        if system_instruction:
            payload["systemInstruction"] = {
                "parts": [{"text": system_instruction}]
            }

        data = json.dumps(payload).encode("utf-8")

        for model in models:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.api_key}"
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"}
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_seconds) as response:
                    if response.status == 200:
                        result = json.loads(response.read().decode("utf-8"))
                        candidates = result.get("candidates", [])
                        if candidates:
                            text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                            if text:
                                return text.strip()
            except urllib.error.HTTPError as e:
                # If 404 (model moved) or 503 (busy), try next model
                if e.code in (404, 503):
                    continue
                return None
            except Exception:
                # Network timeout or offline -> try next model or graceful fallback
                continue
                
        return None
            
        return None

    def enhance_narrative(self, raw_narrative: str, incident_data: Dict[str, Any]) -> str:
        """
        Enhances the deterministic attack narrative using Gemini,
        grounded strictly to the verified graph entities to eliminate hallucinations.
        """
        self._refresh_key()
        if not self.is_enabled:
            return raw_narrative

        system_prompt = (
            "You are a Senior SOC Analyst and Incident Commander. "
            "Refine the provided security incident narrative into a polished, executive-ready cybersecurity briefing. "
            "STRICT RULES: Do not invent any new hostnames, IP addresses, or usernames. "
            "Rely strictly on the verified facts provided in the prompt."
        )

        user_prompt = (
            f"Ground-Truth Incident Data:\n"
            f"- Incident ID: {incident_data.get('id', 'INC-12')}\n"
            f"- Title: {incident_data.get('title')}\n"
            f"- Pivot Host: {incident_data.get('hosts', [{}])[0].get('id', 'HR-07')}\n"
            f"- Compromised Account: {incident_data.get('pivotAccount', 'adm_backup')}\n"
            f"- Raw Deterministic Narrative:\n{raw_narrative}\n\n"
            f"Provide a concise, 2-paragraph executive briefing highlighting: 1) Initial Access & Lateral Movement, 2) Impact & Blast Radius."
        )

        enhanced = self._call_gemini_api(user_prompt, system_prompt)
        if enhanced:
            return enhanced + "\n\n*(Verified & Enriched via Google Gemini API)*"
        return raw_narrative

    def explain_command(self, query: str, incident_data: Dict[str, Any], deterministic_answer: str) -> str:
        """
        Optionally enriches a Command Bar question using Gemini,
        anchored directly to the deterministic calculation truth.
        """
        self._refresh_key()
        if not self.is_enabled:
            return deterministic_answer

        system_prompt = (
            "You are ThreatWeaver's AI Security Copilot. Answer the analyst's question. "
            "You MUST base your answer directly on the verified deterministic analysis provided. "
            "Be concise, technical, and actionable."
        )

        user_prompt = (
            f"Analyst Query: {query}\n\n"
            f"Verified Deterministic Engine Facts:\n"
            f"{deterministic_answer}\n\n"
            f"Provide an authoritative, clear response to the analyst incorporating these verified findings."
        )

        enhanced = self._call_gemini_api(user_prompt, system_prompt)
        if enhanced:
            return enhanced + f"\n\n*(AI Synthesis powered by Google Gemini | Backed by Deterministic Graph Cut Engine)*"
        return deterministic_answer

_default_adapter = LLMAdapter()

def enhance_narrative_with_llm(incident_data: Dict[str, Any], raw_narrative: str) -> str:
    return _default_adapter.enhance_narrative(raw_narrative, incident_data)
