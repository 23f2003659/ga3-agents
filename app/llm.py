"""Pluggable LLM client (OpenAI-compatible Chat Completions).

Env:
    MODEL_API_KEY   provider key
    MODEL_BASE_URL  e.g. https://generativelanguage.googleapis.com/v1beta/openai
    MODEL_NAME      primary model, e.g. gemini-2.5-flash
    MODEL_FALLBACKS comma-separated backup models tried on 429/5xx/timeout,
                    e.g. gemini-3.5-flash-lite,gemini-flash-latest

chat_json() returns a parsed JSON object or raises LLMError. Every call is
bounded by an overall deadline so a slow provider cannot blow the grader's
per-request budget.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Iterable, Optional

MODEL_API_KEY = os.environ.get("MODEL_API_KEY", "")
MODEL_BASE_URL = os.environ.get(
    "MODEL_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai"
).rstrip("/")
MODEL_NAME = os.environ.get("MODEL_NAME", "gemini-2.5-flash")
MODEL_FALLBACKS = [m.strip() for m in os.environ.get(
    "MODEL_FALLBACKS", "gemini-3.5-flash-lite,gemini-flash-latest").split(",") if m.strip()]
REASONING_EFFORT = os.environ.get("MODEL_REASONING_EFFORT", "low")

_last_model_used = MODEL_NAME


class LLMError(RuntimeError):
    pass


def model_label() -> str:
    """Telemetry only."""
    return _last_model_used or MODEL_NAME


def _models() -> list[str]:
    seen, out = set(), []
    for m in [MODEL_NAME, *MODEL_FALLBACKS]:
        if m and m not in seen:
            seen.add(m)
            out.append(m)
    return out


def _post(model: str, system: str, user: str, max_tokens: int,
          timeout: float, reasoning: Optional[str]) -> str:
    payload: dict[str, Any] = {
        "model": model,
        "temperature": 0,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "response_format": {"type": "json_object"},
    }
    if reasoning:
        payload["reasoning_effort"] = reasoning
    req = urllib.request.Request(
        f"{MODEL_BASE_URL}/chat/completions",
        data=json.dumps(payload).encode("utf-8"), method="POST")
    req.add_header("Content-Type", "application/json")
    if MODEL_API_KEY:
        req.add_header("Authorization", f"Bearer {MODEL_API_KEY}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    if isinstance(body, list):
        body = body[0] if body else {}
    try:
        return body["choices"][0]["message"]["content"] or ""
    except Exception as e:
        raise LLMError(f"unexpected model response shape: {str(body)[:300]}") from e


def chat_json(system: str, user: str, *, max_tokens: int = 8192,
              deadline_s: float = 35.0, reasoning: Optional[str] = None
              ) -> dict[str, Any]:
    """Try the primary model, then fallbacks, until one returns valid JSON or
    the deadline passes."""
    global _last_model_used
    reasoning = REASONING_EFFORT if reasoning is None else reasoning
    start = time.monotonic()
    errors = []
    for attempt, model in enumerate(_models() * 2):  # two passes over the chain
        remaining = deadline_s - (time.monotonic() - start)
        if remaining < 3:
            break
        try:
            text = _post(model, system, user, max_tokens, remaining, reasoning or None)
            out = _extract_json(text)
            _last_model_used = model
            return out
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:200]
            errors.append(f"{model}:HTTP{e.code}:{detail}")
            if e.code == 400 and reasoning:
                reasoning = ""  # model may not support reasoning_effort
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(min(1.5, max(0.0, remaining - 3)))
        except Exception as e:  # timeout, JSON error, transport
            errors.append(f"{model}:{type(e).__name__}:{str(e)[:120]}")
    raise LLMError("; ".join(errors)[-600:] or "model deadline exceeded")


def parallel(fn: Callable[[Any], Any], items: Iterable[Any], workers: int = 6) -> list:
    items = list(items)
    if len(items) <= 1:
        return [fn(i) for i in items]
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as ex:
        return list(ex.map(fn, items))


def _extract_json(text: str) -> dict[str, Any]:
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lstrip().lower().startswith("json"):
            text = text.lstrip()[4:]
    try:
        out = json.loads(text)
    except json.JSONDecodeError:
        s, e = text.find("{"), text.rfind("}")
        if s == -1 or e <= s:
            raise LLMError(f"model did not return JSON: {text[:200]}")
        out = json.loads(text[s:e + 1])
    if not isinstance(out, dict):
        raise LLMError("model JSON was not an object")
    return out
