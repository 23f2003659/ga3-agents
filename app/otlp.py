"""OTLP trace construction for Q4 (pure data; stored with the run, never rebuilt).

SERVER   POST /v2/incidents
└─ INTERNAL invoke_agent <agentName>
   ├─ CLIENT   chat incident-plan                (exactly one)
   ├─ INTERNAL execute_tool <toolName>           (one per logical action)
   │  └─ CLIENT POST tool/<toolName>             (one per physical attempt)
   ├─ INTERNAL incident.join                     (when diagnostics fan out)
   └─ INTERNAL approval_gate                     (when approval is required)
"""
from __future__ import annotations

import re
import secrets
import time
from typing import Any, Optional

INTERNAL, SERVER, CLIENT = 1, 2, 3
_TP_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")


def _hex(n: int) -> str:
    while True:
        v = secrets.token_hex(n)
        if v.strip("0"):
            return v


def parse_traceparent(tp: Optional[str]) -> Optional[tuple[str, str, str]]:
    if not isinstance(tp, str):
        return None
    m = _TP_RE.match(tp.strip())
    if not m or not m.group(1).strip("0") or not m.group(2).strip("0"):
        return None
    return m.group(1), m.group(2), m.group(3)


def s_attr(k: str, v: Any) -> dict:
    return {"key": k, "value": {"stringValue": str(v)}}


def i_attr(k: str, v: int) -> dict:
    return {"key": k, "value": {"intValue": int(v)}}


class Trace:
    """State is a plain dict so it can be persisted as JSON."""

    def __init__(self, state: dict):
        self.s = state

    @classmethod
    def new(cls, run_id: str, marker: str, agent_name: str, model: str,
            incoming_tp: Optional[str], incoming_ts: Optional[str]) -> "Trace":
        parsed = parse_traceparent(incoming_tp)
        trace_id = parsed[0] if parsed else _hex(16)
        st = {"traceId": trace_id, "runId": run_id, "marker": marker, "spans": [],
              "tracestate": incoming_ts if (parsed and isinstance(incoming_ts, str) and incoming_ts) else None,
              "flags": parsed[2] if parsed else "01",
              "execSpans": {}, "clientSpans": {}, "joinId": None, "gateId": None}
        t = cls(st)
        now = time.time_ns()
        server = t._add("POST /v2/incidents", SERVER, parsed[1] if parsed else None, now, [
            s_attr("http.request.method", "POST"), s_attr("http.route", "/v2/incidents"),
            s_attr("url.path", "/v2/incidents")])
        st["serverId"] = server["spanId"]
        agent = t._add(f"invoke_agent {agent_name}", INTERNAL, server["spanId"], now + 1000, [
            s_attr("gen_ai.operation.name", "invoke_agent"), s_attr("gen_ai.agent.name", agent_name)])
        st["agentId"] = agent["spanId"]
        t._add("chat incident-plan", CLIENT, agent["spanId"], now + 2000, [
            s_attr("gen_ai.operation.name", "chat"), s_attr("gen_ai.request.model", model or "unknown")])
        return t

    # -------------------------------------------------------------- helpers
    def _add(self, name: str, kind: int, parent: Optional[str], start: int, attrs: list) -> dict:
        span = {
            "traceId": self.s["traceId"],
            "spanId": _hex(8),
            "name": name,
            "kind": kind,
            "startTimeUnixNano": str(start),
            "endTimeUnixNano": str(start + 1_000_000),
            "attributes": [s_attr("ga5.run.id", self.s["runId"]),
                           s_attr("ga5.public.marker", self.s["marker"])] + attrs,
            "status": {"code": 0},
        }
        if parent:
            span["parentSpanId"] = parent
        self.s["spans"].append(span)
        return span

    def _span(self, span_id: str) -> Optional[dict]:
        return next((x for x in self.s["spans"] if x["spanId"] == span_id), None)

    def traceparent(self, span_id: str) -> str:
        return f"00-{self.s['traceId']}-{span_id}-{self.s['flags']}"

    @property
    def tracestate(self) -> Optional[str]:
        return self.s.get("tracestate")

    # -------------------------------------------------------------- tools
    def tool_attempt(self, action_id: str, call_id: str, tool: str, attempt: int) -> str:
        exec_id = self.s["execSpans"].get(action_id)
        now = time.time_ns()
        if exec_id is None:
            ex = self._add(f"execute_tool {tool}", INTERNAL, self.s["agentId"], now, [
                s_attr("ga5.action.id", action_id), s_attr("gen_ai.tool.name", tool),
                s_attr("gen_ai.tool.call.id", call_id), s_attr("gen_ai.operation.name", "execute_tool")])
            exec_id = self.s["execSpans"][action_id] = ex["spanId"]
        cl = self._add(f"POST tool/{tool}", CLIENT, exec_id, now + 500, [
            s_attr("ga5.action.id", action_id), i_attr("ga5.attempt", attempt),
            s_attr("http.request.method", "POST"), i_attr("http.request.resend_count", attempt - 1),
            s_attr("gen_ai.tool.call.id", call_id)])
        self.s["clientSpans"][f"{action_id}|{attempt}"] = cl["spanId"]
        return cl["spanId"]

    def record_outcome(self, action_id: str, attempt: int, receipt_id: str, nonce: Any,
                       status: Any, error_type: Optional[str]) -> None:
        span = self._span(self.s["clientSpans"].get(f"{action_id}|{attempt}", ""))
        if span is None:
            return
        span["attributes"] += [s_attr("ga5.receipt.id", receipt_id), s_attr("ga5.receipt.nonce", nonce)]
        if isinstance(status, int) and status > 0:
            span["attributes"].append(i_attr("http.response.status_code", status))
        if status == 0 or error_type:
            span["attributes"].append(s_attr("error.type", error_type or "timeout"))
            span["status"] = {"code": 2}
        elif isinstance(status, int) and status >= 400:
            span["attributes"].append(s_attr("error.type", str(status)))
            span["status"] = {"code": 2}
        span["endTimeUnixNano"] = str(time.time_ns())

    def add_join(self, action_ids: list[str]) -> None:
        if self.s.get("joinId"):
            return
        j = self._add("incident.join", INTERNAL, self.s["agentId"], time.time_ns(), [
            i_attr("ga5.join.count", len(action_ids))])
        j["links"] = [{"traceId": self.s["traceId"], "spanId": self.s["execSpans"][a]}
                      for a in action_ids if a in self.s["execSpans"]]
        self.s["joinId"] = j["spanId"]

    def add_gate(self, approval_id: str, action_id: str) -> None:
        g = self._add("approval_gate", INTERNAL, self.s["agentId"], time.time_ns(), [
            s_attr("ga5.approval.id", approval_id), s_attr("ga5.action.id", action_id)])
        self.s["gateId"] = g["spanId"]

    def record_approval(self, receipt_id: str, nonce: Any, decision: str) -> None:
        g = self._span(self.s.get("gateId") or "")
        if g:
            g["attributes"] += [s_attr("ga5.approval.nonce", nonce), s_attr("ga5.receipt.id", receipt_id),
                                s_attr("ga5.receipt.nonce", nonce), s_attr("ga5.approval.decision", decision)]
            g["endTimeUnixNano"] = str(time.time_ns())

    def dump(self) -> dict:
        return {"resourceSpans": [{
            "resource": {"attributes": [s_attr("service.name", "incident-response"),
                                        s_attr("ga5.run.id", self.s["runId"]),
                                        s_attr("ga5.public.marker", self.s["marker"])]},
            "scopeSpans": [{"scope": {"name": "ga5.incident-agent", "version": "2"},
                            "spans": self.s["spans"]}],
        }]}
