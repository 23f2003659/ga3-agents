"""Pluggable LLM client.

Talks to any OpenAI-compatible Chat Completions endpoint. Configure via env:

    MODEL_API_KEY   - API key (required for hosted providers)
    MODEL_BASE_URL  - e.g. https://api.openai.com/v1
                      Gemini (OpenAI-compat): https://generativelanguage.googleapis.com/v1beta/openai
                      Groq (free):            https://api.groq.com/openai/v1
                      Ollama (local):         http://localhost:11434/v1
    MODEL_NAME      - e.g. gpt-4o-mini, gemini-2.0-flash, llama-3.1-8b-instant

The client ALWAYS returns parsed JSON (the model is asked to emit a single JSON
object). It raises LLMError on transport/parse failure so callers can decide how
to degrade. Callers are responsible for caching by canonical content hash so
repeat Checks make no model call.
"""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from typing import Any

MODEL_API_KEY = os.environ.get("MODEL_API_KEY", "")
MODEL_BASE_URL = os.environ.get("MODEL_BASE_URL", "https://api.openai.com/v1").rstrip("/")
MODEL_NAME = os.environ.get("MODEL_NAME", "gpt-4o-mini")
MODEL_TIMEOUT = float(os.environ.get("MODEL_TIMEOUT", "30"))


class LLMError(RuntimeError):
    pass


def model_label() -> str:
    """Telemetry only; never a scoring shortcut."""
    return MODEL_NAME


def chat_json(system: str, user: str, *, max_tokens: int = 4096,
              temperature: float = 0.0) -> dict[str, Any]:
    """Call the chat endpoint and parse a single JSON object from the reply."""
    url = f"{MODEL_BASE_URL}/chat/completions"
    payload = {
        "model": MODEL_NAME,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "response_format": {"type": "json_object"},
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if MODEL_API_KEY:
        req.add_header("Authorization", f"Bearer {MODEL_API_KEY}")
    try:
        with urllib.request.urlopen(req, timeout=MODEL_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:  # pragma: no cover - network
        detail = e.read().decode("utf-8", "replace")[:500]
        raise LLMError(f"model HTTP {e.code}: {detail}") from e
    except Exception as e:  # pragma: no cover - network
        raise LLMError(f"model transport error: {e}") from e

    try:
        content = body["choices"][0]["message"]["content"]
    except Exception as e:
        raise LLMError(f"unexpected model response: {body}") from e

    return _extract_json(content)


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    # strip markdown fences if present
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.lstrip().startswith("json"):
            text = text.lstrip()[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # try to locate the outermost object
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(text[start:end + 1])
        raise LLMError(f"model did not return JSON: {text[:300]}")
