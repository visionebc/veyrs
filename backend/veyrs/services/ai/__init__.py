"""VEYRS AI subsystem.

Layering (each layer may only call the one below it):

    api/v1/ai.py         HTTP surface, authorization decorators
      capabilities.py    grounded features: CVE analysis, risk explanation, ...
        gateway.py       policy, sanitization, provider choice, audit
          providers.py   transport to OpenAI / Anthropic / Gemini / Ollama / none
          guardrails.py  secret, PII and prompt-injection detection
        nlquery.py       natural language -> validated structured query
"""
from .gateway import AiRequest, AiResult, get_policy, invoke, select_provider
from .guardrails import ScanResult, sanitize, scan_injection, scan_output

__all__ = [
    "AiRequest", "AiResult", "invoke", "get_policy", "select_provider",
    "ScanResult", "sanitize", "scan_injection", "scan_output",
]
