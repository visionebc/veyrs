"""Provider abstraction layer (spec section 19).

One interface, several backends. The interface is deliberately narrow -- a
single `complete()` that takes a system prompt plus a user prompt and returns
text with token accounting. VEYRS does not expose provider-native tool calling
to tenants: a model that can invoke tools inside a multi-tenant security product
is an authorization boundary made of prose. Structured output is obtained by
asking for JSON and validating it against a schema we control (`capabilities`).

Every backend is optional. If none is reachable, `DeterministicProvider` still
answers -- from VEYRS data only, with no generative text. That is what keeps the
platform usable in an air-gapped install and what makes the test suite
hermetic: no test in this repo reaches the network.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import re
import time
from typing import Any, Callable, Protocol

log = logging.getLogger("veyrs.ai.providers")


class ProviderError(RuntimeError):
    """Backend failed. Callers degrade; they never surface raw provider text."""


@dataclasses.dataclass(frozen=True)
class Completion:
    text: str
    provider: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    duration_ms: int = 0
    degraded: bool = False   # produced without a model (deterministic fallback)


@dataclasses.dataclass(frozen=True)
class ProviderSpec:
    """Everything a backend needs, resolved from an `AiProvider` row."""

    slug: str
    kind: str
    model: str
    base_url: str | None = None
    api_key: str | None = None
    timeout_seconds: int = 60
    temperature: float = 0.1
    max_output_tokens: int = 1500


class Provider(Protocol):
    def complete(self, spec: ProviderSpec, system: str, prompt: str) -> Completion: ...


def _estimate_tokens(text: str) -> int:
    """~4 chars/token. Good enough for budgeting; never used for billing."""
    return max(1, len(text) // 4)


#: Reasoning models emit a chain of thought around the answer. A paired-tag
#: regex is not enough: some builds close with `</think>` having never opened a
#: `<think>`, so the unmatched closer has to be handled on its own.
_THINK_BLOCK = re.compile(r"<(think|thinking|reasoning)\b[^>]*>.*?</\1\s*>",
                          re.DOTALL | re.IGNORECASE)
_THINK_CLOSE = re.compile(r"</(?:think|thinking|reasoning)\s*>", re.IGNORECASE)
_THINK_ANY_TAG = re.compile(r"</?(?:think|thinking|reasoning)\b[^>]*>",
                            re.IGNORECASE)


def _strip_reasoning(text: str) -> str:
    """Drop a model's chain of thought, keeping only the answer.

    Applied to every backend, not just the local ones: reasoning traces are a
    property of the model, not of the transport. Suppressing them here means no
    downstream caller -- guardrails, capability schemas, the UI -- has to know
    that some models narrate before they answer.

    `think: false` on Ollama is not sufficient. This fleet's Foundation-Sec
    build ships a template with no `<think>` opener, so the runtime cannot
    detect it as a thinking model and a bare `</think>` reaches the caller
    intermittently. Two shapes were observed in production, and they put the
    answer on *opposite* sides of the marker:

      reasoning... </think> answer     -> the answer follows the marker
      answer... </think>               -> the marker is a stray terminator and
                                          the answer precedes it

    So the tail is preferred and the head is the fallback, rather than assuming
    a fixed side. Whatever survives is stripped of any leftover markers, which
    is what guarantees no raw tag reaches an analyst's browser.
    """
    cleaned = _THINK_BLOCK.sub("", text)
    matches = list(_THINK_CLOSE.finditer(cleaned))
    if matches:
        last = matches[-1]
        tail = cleaned[last.end():].strip()
        # Prefer the tail (reasoning-then-answer); fall back to the head
        # (answer-then-stray-terminator).
        cleaned = tail or cleaned[:last.start()].strip()
    cleaned = _THINK_ANY_TAG.sub("", cleaned).strip()
    cleaned = _drop_restated_answer(cleaned)
    return cleaned or text.strip()


#: A markdown heading whose only content is "Answer" (optionally "Final
#: Answer"), on its own line. Anchored to a line start and end so a sentence
#: that merely contains the word is never treated as a delimiter.
_ANSWER_HEADING = re.compile(
    r"^[ \t]*(?:#{1,6}[ \t]*|\*\*)(?:final[ \t]+)?answer\s*:?\s*(?:\*\*)?[ \t]*$",
    re.IGNORECASE | re.MULTILINE)


def _drop_restated_answer(text: str) -> str:
    """Keep only the final-answer section when a model restates itself.

    Not every reasoning model marks its chain of thought with a tag. The
    Metis/Minerva family (Foundation-Sec) writes its analysis in prose and then
    repeats the conclusion under a literal `# Answer` heading, so the tag-based
    strip above sees nothing to remove and the analyst gets the same paragraph
    twice.

    Only a heading that is *nothing but* the word "Answer" counts, and only when
    real content follows it -- a report that happens to discuss an answer keeps
    its text. If the section turns out to be trivially short, the original is
    kept: truncating a genuine answer is a worse failure than repeating one.
    """
    matches = list(_ANSWER_HEADING.finditer(text))
    if not matches:
        return text
    tail = text[matches[-1].end():].strip()
    return tail if len(tail) >= 40 else text


# ---------------------------------------------------------------------------
# Deterministic provider (always available)
# ---------------------------------------------------------------------------
class DeterministicProvider:
    """Answers from the supplied context without a model.

    This is not a mock: it is a first-class degraded mode. It echoes the
    structured VEYRS context that the capability layer already assembled and
    labels the result as degraded, so the UI can show "AI unavailable -- showing
    computed values" instead of an error page. Because it invents nothing, it is
    also the safest default for `RESTRICTED` data.
    """

    name = "deterministic"

    def complete(self, spec: ProviderSpec, system: str, prompt: str) -> Completion:
        started = time.monotonic()
        text = _deterministic_answer(prompt)
        return Completion(
            text=text,
            provider=spec.slug or self.name,
            model="deterministic",
            prompt_tokens=_estimate_tokens(prompt),
            completion_tokens=_estimate_tokens(text),
            duration_ms=int((time.monotonic() - started) * 1000),
            degraded=True,
        )


def _deterministic_answer(prompt: str) -> str:
    """Re-present the VEYRS FACTS block, which the capability layer always adds."""
    marker = "VEYRS FACTS:"
    if marker in prompt:
        facts = prompt.split(marker, 1)[1].strip()
        return (
            "AI generation is unavailable, so this answer is assembled directly "
            "from VEYRS data with no model involved:\n\n" + facts
        )
    return (
        "AI generation is unavailable and no structured VEYRS context was "
        "supplied for this request, so no answer can be produced."
    )


# ---------------------------------------------------------------------------
# HTTP-backed providers
# ---------------------------------------------------------------------------
def _post_json(url: str, payload: dict, headers: dict, timeout: int) -> dict:
    import httpx  # local import: keeps `import veyrs` free of network libs

    try:
        response = httpx.post(url, json=payload, headers=headers, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - any transport failure is the same to us
        raise ProviderError(f"transport error: {exc.__class__.__name__}") from exc
    if response.status_code >= 400:
        # Body may contain the echoed prompt; never propagate it upward.
        raise ProviderError(f"provider returned HTTP {response.status_code}")
    try:
        return response.json()
    except ValueError as exc:
        raise ProviderError("provider returned non-JSON body") from exc


class OpenAICompatibleProvider:
    """OpenAI `/v1/chat/completions`. Covers OpenAI, Azure-style gateways,
    vLLM, llama.cpp server, LiteLLM and Ollama's compatibility endpoint."""

    name = "openai_compatible"
    default_base = "https://api.openai.com"

    def complete(self, spec: ProviderSpec, system: str, prompt: str) -> Completion:
        started = time.monotonic()
        base = (spec.base_url or self.default_base).rstrip("/")
        headers = {"Content-Type": "application/json"}
        if spec.api_key:
            headers["Authorization"] = f"Bearer {spec.api_key}"
        body = _post_json(
            f"{base}/v1/chat/completions",
            {
                "model": spec.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "temperature": spec.temperature,
                "max_tokens": spec.max_output_tokens,
            },
            headers,
            spec.timeout_seconds,
        )
        try:
            text = body["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError("malformed chat completion response") from exc
        usage = body.get("usage") or {}
        return Completion(
            text=_strip_reasoning(text),
            provider=spec.slug,
            model=body.get("model") or spec.model,
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            duration_ms=int((time.monotonic() - started) * 1000),
        )


class AnthropicProvider:
    name = "anthropic"
    default_base = "https://api.anthropic.com"

    def complete(self, spec: ProviderSpec, system: str, prompt: str) -> Completion:
        started = time.monotonic()
        base = (spec.base_url or self.default_base).rstrip("/")
        body = _post_json(
            f"{base}/v1/messages",
            {
                "model": spec.model,
                "system": system,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": spec.temperature,
                "max_tokens": spec.max_output_tokens,
            },
            {
                "Content-Type": "application/json",
                "x-api-key": spec.api_key or "",
                "anthropic-version": "2023-06-01",
            },
            spec.timeout_seconds,
        )
        try:
            parts = body["content"]
            text = "".join(p.get("text", "") for p in parts if p.get("type") == "text")
        except (KeyError, TypeError) as exc:
            raise ProviderError("malformed messages response") from exc
        usage = body.get("usage") or {}
        return Completion(
            text=_strip_reasoning(text),
            provider=spec.slug,
            model=body.get("model") or spec.model,
            prompt_tokens=usage.get("input_tokens"),
            completion_tokens=usage.get("output_tokens"),
            duration_ms=int((time.monotonic() - started) * 1000),
        )


class GeminiProvider:
    name = "gemini"
    default_base = "https://generativelanguage.googleapis.com"

    def complete(self, spec: ProviderSpec, system: str, prompt: str) -> Completion:
        started = time.monotonic()
        base = (spec.base_url or self.default_base).rstrip("/")
        url = f"{base}/v1beta/models/{spec.model}:generateContent"
        headers = {"Content-Type": "application/json"}
        if spec.api_key:
            headers["x-goog-api-key"] = spec.api_key
        body = _post_json(
            url,
            {
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": spec.temperature,
                    "maxOutputTokens": spec.max_output_tokens,
                },
            },
            headers,
            spec.timeout_seconds,
        )
        try:
            parts = body["candidates"][0]["content"]["parts"]
            text = "".join(p.get("text", "") for p in parts)
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError("malformed generateContent response") from exc
        usage = body.get("usageMetadata") or {}
        return Completion(
            text=_strip_reasoning(text),
            provider=spec.slug,
            model=spec.model,
            prompt_tokens=usage.get("promptTokenCount"),
            completion_tokens=usage.get("candidatesTokenCount"),
            duration_ms=int((time.monotonic() - started) * 1000),
        )


class OllamaProvider:
    """Native Ollama `/api/chat`.

    `think: false` is sent explicitly: qwen3-class models otherwise return their
    reasoning in a separate field and leave `message.content` empty, which reads
    downstream as "the model returned nothing" (a trap this fleet has hit
    before).
    """

    name = "ollama"
    default_base = "http://127.0.0.1:11434"

    def complete(self, spec: ProviderSpec, system: str, prompt: str) -> Completion:
        started = time.monotonic()
        base = (spec.base_url or self.default_base).rstrip("/")
        body = _post_json(
            f"{base}/api/chat",
            {
                "model": spec.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
                "think": False,
                "options": {
                    "temperature": spec.temperature,
                    "num_predict": spec.max_output_tokens,
                },
            },
            {"Content-Type": "application/json"},
            spec.timeout_seconds,
        )
        text = _strip_reasoning((body.get("message") or {}).get("content") or "")
        if not text:
            raise ProviderError("ollama returned an empty message")
        return Completion(
            text=text,
            provider=spec.slug,
            model=body.get("model") or spec.model,
            prompt_tokens=body.get("prompt_eval_count"),
            completion_tokens=body.get("eval_count"),
            duration_ms=int((time.monotonic() - started) * 1000),
        )


#: kind -> factory. Adding a provider is one entry here plus a class above.
REGISTRY: dict[str, Callable[[], Provider]] = {
    "deterministic": DeterministicProvider,
    "openai": OpenAICompatibleProvider,
    "openai_compatible": OpenAICompatibleProvider,
    "anthropic": AnthropicProvider,
    "gemini": GeminiProvider,
    "ollama": OllamaProvider,
}

#: Kinds that are external by nature. An administrator may still mark an
#: `openai_compatible` endpoint internal (a self-hosted vLLM), but they cannot
#: mark the hosted vendors internal -- that is not a local decision to make.
INHERENTLY_EXTERNAL = frozenset({"openai", "anthropic", "gemini"})


def get_provider(kind: str) -> Provider:
    factory = REGISTRY.get(kind)
    if factory is None:
        raise ProviderError(f"unknown provider kind {kind!r}")
    return factory()


def parse_json_object(text: str) -> dict[str, Any]:
    """Extract the first JSON object from a model reply.

    Models wrap JSON in prose or fences no matter how firmly you ask them not
    to. Parsing is bounded and failure is explicit -- the capability layer then
    falls back to computed values rather than shipping a half-parsed dict.
    """
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("```")[1] if "```" in stripped[3:] else stripped[3:]
        if stripped.lstrip().lower().startswith("json"):
            stripped = stripped.lstrip()[4:]
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end <= start:
        raise ProviderError("no JSON object in model output")
    try:
        parsed = json.loads(stripped[start:end + 1])
    except json.JSONDecodeError as exc:
        raise ProviderError("model output was not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ProviderError("model output was not a JSON object")
    return parsed
