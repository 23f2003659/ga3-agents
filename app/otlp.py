"""OTLP trace construction for Q4.

Builds the required span hierarchy:

  SERVER   POST /v2/incidents
  └─ INTERNAL invoke_agent incident-response
     ├─ CLIENT   chat incident-plan          (exactly one)
     ├─ INTERNAL execute_tool <toolName>     (one per logical executed action)
     │  └─ CLIENT POST tool/<toolName>       (one per physical attempt)
     ├─ INTERNAL incident.join               (when diagnostics fan out)
     └─ INTERNAL approval_gate               (when approval is required)

SpanKind: INTERNAL=1, SERVER=2, CLIENT=3. Trace/span IDs are nonzero lowercase
hex. Every span carries ga5.run.id and ga5.public.marker. No sensitive data,
arguments, results, prompts, transcripts, or credentials are ever exported.
"""
from __future__ import annotations

import os
import secrets
import time
from typing import Any, Optional

KIND_INTERNAL = 1
KIND_SERVER = 2
KIND_CLIENT = 3


def _hex(nbytes: int) -> str:
    v = secrets.token_hex(nbytes)
    if set(v) == {"0"}:
        v = "0" * (nbytes * 2 - 1) + "1"
    return v


def _now_ns() -> int:
    return time.time_ns()


class Trace:
    def __init__(self, run_id: str, public_marker: str, trace_id: str,
                 tracestate: Optional[str] = None):
        self.run_id = run_id
        self.public_marker = public_marker
        self.trace_id = trace_id
        self.tracestate = tracestate
        self.spans: list[dict] = []
        self.server_span_id: Optional[str] = None
        self.agent_span_id: Optional[str] = None
        self.execute_tool_spans: dict[str, str] = {}  # actionId -> span id
        self.diag_clients: list[dict] = []            # list of {_client_span}
        self.client_spans: dict[tuple, str] = {}       # (actionId,attempt)->span

    # ---- lifecycle ----
    def _base_attrs(self) -> list[dict]:
        return [
            _attr("ga5.run.id", self.run_id),
            _attr("ga5.public.marker", self.public_marker),
        ]

    def _span(self, name: str, kind: int, parent: Optional[str],
              extra: Optional[list] = None, status_code: int = 0,
              error_type: Optional[str] = None) -> dict:
        sid = _hex(8)
        attrs = self._base_attrs() + (extra or [])
        s = {
            "traceId": self.trace_id,
            "spanId": sid,
            "name": name,
            "kind": kind,
            "startTimeUnixNano": _now_ns(),
            "endTimeUnixNano": _now_ns() + 1_000_000,
            "attributes": attrs,
        }
        if parent:
            s["parentSpanId"] = parent
        if status_code:
            s["status"] = {"code": status_code}
            if error_type:
                # error type lives in attributes, not status
                pass
        self.spans.append(s)
        return s

    def start_server(self):
        s = self._span("POST /v2/incidents", KIND_SERVER, None)
        self.server_span_id = s["spanId"]

    def start_agent(self, agent_name: str):
        s = self._span(f"invoke_agent {agent_name}", KIND_INTERNAL,
                       self.server_span_id)
        self.agent_span_id = s["spanId"]

    def add_model_span(self, model_name: str):
        self._span("chat incident-plan", KIND_CLIENT, self.agent_span_id,
                   extra=[
                       _attr("gen_ai.operation.name", "chat"),
                       _attr("gen_ai.request.model", model_name or "unknown"),
                   ])

    def add_tool_client(self, action_id: str, tool_name: str, call_id: str,
                        attempt: int) -> dict:
        # ensure one INTERNAL execute_tool per logical action
        et_id = self.execute_tool_spans.get(action_id)
        if et_id is None:
            et = self._span(f"execute_tool {tool_name}", KIND_INTERNAL,
                            self.agent_span_id, extra=[
                    _attr("ga5.action.id", action_id),
                    _attr("gen_ai.tool.name", tool_name),
                    _attr("gen_ai.tool.call.id", call_id),
                    _attr("gen_ai.operation.name", "execute_tool"),
                ])
            et_id = et["spanId"]
            self.execute_tool_spans[action_id] = et_id

        # CLIENT span per physical attempt
        client = self._span(f"POST tool/{tool_name}", KIND_CLIENT, et_id,
                            extra=[
                _attr("ga5.action.id", action_id),
                _attr_int("ga5.attempt", attempt),
                _attr("http.request.method", "POST"),
                _attr_int("http.request.resend_count", attempt - 1),
            ])
        self.client_spans[(action_id, attempt)] = client["spanId"]
        # track diagnostic clients for join links
        rec = {"_client_span": client["spanId"], "action_id": action_id}
        if client not in self.diag_clients:
            self.diag_clients.append(rec)
        return client

    def record_receipt_on_client(self, action_id: str, attempt: int,
                                 receipt_id: str, nonce: str,
                                 http_status: Any, error_type: Optional[str]):
        sid = self.client_spans.get((action_id, attempt))
        span = next((s for s in self.spans if s["spanId"] == sid), None)
        if span is None:
            return
        span["attributes"].append(_attr("ga5.receipt.id", receipt_id))
        span["attributes"].append(_attr("ga5.receipt.nonce", nonce or ""))
        if http_status == 503:
            span["attributes"].append(_attr("error.type", "503"))
            span["attributes"].append(_attr_int("http.response.status_code", 503))
            span["status"] = {"code": 2}
        elif http_status == 0 and error_type == "timeout":
            span["attributes"].append(_attr("error.type", "timeout"))
            span["status"] = {"code": 2}
        else:
            # success: UNSET or OK, no error.type
            if isinstance(http_status, int) and http_status:
                span["attributes"].append(
                    _attr_int("http.response.status_code", http_status))

    def add_join(self, client_span_ids: list[str]):
        s = self._span("incident.join", KIND_INTERNAL, self.agent_span_id)
        s["links"] = [{"traceId": self.trace_id, "spanId": sid}
                      for sid in client_span_ids]

    def add_approval_gate(self, approval_id: str):
        self._span("approval_gate", KIND_INTERNAL, self.agent_span_id, extra=[
            _attr("ga5.approval.id", approval_id),
        ])

    def record_approval(self, approval_id: str, nonce: str):
        span = next((s for s in self.spans if s["name"] == "approval_gate"), None)
        if span:
            span["attributes"].append(_attr("ga5.approval.receipt.nonce",
                                             nonce or ""))

    def traceparent(self, client_span: dict) -> str:
        return f"00-{self.trace_id}-{client_span['spanId']}-01"

    def dump(self) -> dict:
        return {"resourceSpans": [{
            "resource": {"attributes": [
                _attr("service.name", "incident-response")]},
            "scopeSpans": [{
                "scope": {"name": "ga5.incident"},
                "spans": self.spans,
            }],
        }]}

    # ---- (de)serialize so replay reads stored state, never rebuilds ----
    def serialize(self) -> dict:
        return {
            "run_id": self.run_id, "public_marker": self.public_marker,
            "trace_id": self.trace_id, "tracestate": self.tracestate,
            "spans": self.spans, "server_span_id": self.server_span_id,
            "agent_span_id": self.agent_span_id,
            "execute_tool_spans": self.execute_tool_spans,
            "diag_clients": self.diag_clients,
            "client_spans": {f"{k[0]}|{k[1]}": v
                             for k, v in self.client_spans.items()},
        }

    @classmethod
    def deserialize(cls, d: dict) -> "Trace":
        t = cls(d["run_id"], d["public_marker"], d["trace_id"], d.get("tracestate"))
        t.spans = d["spans"]
        t.server_span_id = d["server_span_id"]
        t.agent_span_id = d["agent_span_id"]
        t.execute_tool_spans = d["execute_tool_spans"]
        t.diag_clients = d["diag_clients"]
        t.client_spans = {}
        for k, v in d["client_spans"].items():
            a, att = k.split("|")
            t.client_spans[(a, int(att))] = v
        return t


def new_trace(run_id: str, public_marker: str,
              incoming_traceparent: Optional[str] = None,
              incoming_tracestate: Optional[str] = None) -> Trace:
    if incoming_traceparent:
        parts = incoming_traceparent.split("-")
        if len(parts) == 4 and parts[1] and set(parts[1]) != {"0"}:
            return Trace(run_id, public_marker, parts[1], incoming_tracestate)
    return Trace(run_id, public_marker, _hex(16))


def _attr(key: str, value: str) -> dict:
    return {"key": key, "value": {"stringValue": str(value)}}


def _attr_int(key: str, value: int) -> dict:
    return {"key": key, "value": {"intValue": int(value)}}
