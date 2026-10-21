"""Q4 — Observable Incident Triage (profile ga5-incident-agent/v2).

POST /v2/incidents                  create run (one model call) or replay
POST /v2/incidents/{runId}/receipts apply tool outcomes / approvals (no model)
GET  /v2/incidents/{runId}          current stored state
"""
from __future__ import annotations

import json
from typing import Any, Optional

from fastapi.responses import JSONResponse

from . import store
from .canonical import sha256_hex
from .incident_planner import plan_incident
from .otlp import Trace

PROFILE = "ga5-incident-agent/v2"
MAX_BODY = 768 * 1024
NS_RUN = "q4_run"
TERMINAL = ("completed", "failed")


def _json(data: Any, status: int = 200) -> JSONResponse:
    if status == 200 and len(json.dumps(data).encode()) > MAX_BODY:
        return JSONResponse({"error": "response too large"}, status_code=500)
    return JSONResponse(data, status_code=status)


def _bad(msg: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": msg}, status_code=status)


def _sid(*parts: Any) -> str:
    return sha256_hex(list(parts))[:20]


# ====================================================================== create
def create_incident(headers: dict, raw: bytes) -> JSONResponse:
    try:
        body = json.loads(raw.decode("utf-8"))
    except Exception:
        return _bad("invalid JSON")
    if not isinstance(body, dict):
        return _bad("invalid body")
    if body.get("profile") != PROFILE:
        return _bad("unsupported profile")
    run_id = body.get("runId")
    inc = body.get("incident")
    catalog = body.get("toolCatalog")
    policy = body.get("policy")
    if not isinstance(run_id, str) or len(run_id) < 1 or not isinstance(inc, dict) \
            or not isinstance(inc.get("transcript"), str) or not isinstance(inc.get("allowedRootCauses"), list) \
            or not inc["allowedRootCauses"] or not isinstance(catalog, list) or not catalog \
            or not isinstance(policy, dict):
        return _bad("invalid incident request", 422)

    req_hash = sha256_hex(body)
    with store.key_lock("q4:" + run_id):
        run = store.get(NS_RUN, run_id)
        if run is not None:
            if run["requestHash"] != req_hash:
                return _bad("run content conflict", 409)
            return _json(run["firstResponse"])

        sensitive = body.get("sensitive") if isinstance(body.get("sensitive"), dict) else {}
        secret_values = [v for v in _flatten(sensitive) if isinstance(v, str)]
        plan = plan_incident(inc, catalog, policy, secret_values)

        tp = headers.get("traceparent") or body.get("traceparent")
        ts = headers.get("tracestate") or body.get("tracestate")
        trace = Trace.new(run_id, str(body.get("publicMarker", "")), str(body.get("agentName") or "incident-response"),
                          plan.get("modelName", ""), tp, ts)
        approval_needed = set(policy.get("approvalRequiredFor") or [])

        run = {
            "runId": run_id, "requestHash": req_hash, "status": "waiting",
            "diagnosis": {"rootCause": plan["rootCause"], "evidence": plan["evidence"]},
            "actions": {}, "order": [], "actionLog": [], "receiptLog": [], "suppressed": [],
            "chosenEffect": None, "effect": None, "approval": None, "receipts": {},
            "trace": trace.s,
        }
        diag_ids = []
        new_dispatches = []
        for i, d in enumerate(plan["diagnostics"]):
            aid = "act-" + _sid(run_id, "diag", i, d["toolName"])
            act = {"actionId": aid, "callId": "call-" + _sid(run_id, "diag-call", i, d["toolName"]),
                   "phase": "diagnostic", "toolName": d["toolName"], "arguments": d["arguments"],
                   "evidence": d["evidence"], "attempt": 0, "state": "pending"}
            run["actions"][aid] = act
            run["order"].append(aid)
            diag_ids.append(aid)
            new_dispatches.append(_dispatch(run, trace, act))
        if len(diag_ids) > 1:
            trace.add_join(diag_ids)
        eff = plan.get("effect")
        if eff and eff.get("toolName"):
            aid = "act-" + _sid(run_id, "effect", eff["toolName"])
            run["effect"] = {"actionId": aid, "callId": "call-" + _sid(run_id, "effect-call", eff["toolName"]),
                             "phase": "effect", "toolName": eff["toolName"], "arguments": eff["arguments"],
                             "evidence": eff["evidence"], "attempt": 0, "state": "planned",
                             "needsApproval": eff["toolName"] in approval_needed}
        if not diag_ids:
            new_dispatches = _advance(run, trace)
        run["trace"] = trace.s
        resp = _view(run, new_dispatches)
        run["firstResponse"] = resp
        store.put(NS_RUN, run_id, run)
        return _json(resp)


def _flatten(o: Any):
    if isinstance(o, dict):
        for v in o.values():
            yield from _flatten(v)
    elif isinstance(o, list):
        for v in o:
            yield from _flatten(v)
    else:
        yield o


def _dispatch(run: dict, trace: Trace, act: dict, approval: Optional[dict] = None) -> dict:
    act["attempt"] += 1
    act["state"] = "pending"
    span_id = trace.tool_attempt(act["actionId"], act["callId"], act["toolName"], act["attempt"])
    d = {"actionId": act["actionId"], "callId": act["callId"], "phase": act["phase"],
         "toolName": act["toolName"], "arguments": act["arguments"], "evidence": act["evidence"],
         "attempt": act["attempt"], "traceparent": trace.traceparent(span_id)}
    if trace.tracestate:
        d["tracestate"] = trace.tracestate
    if approval:
        d["approvalId"] = approval["approvalId"]
        d["approvalNonce"] = approval["nonce"]
    run["actionLog"].append(d)
    return d


# ====================================================================== receipts
def post_receipts(run_id: str, raw: bytes) -> JSONResponse:
    try:
        body = json.loads(raw.decode("utf-8"))
    except Exception:
        return _bad("invalid JSON")
    if not isinstance(body, dict) or not isinstance(body.get("receiptId"), str) or not body["receiptId"]:
        return _bad("receiptId required", 422)
    outcomes, approvals = body.get("outcomes"), body.get("approvals")
    if (outcomes is None) == (approvals is None) or not isinstance(outcomes or approvals, list) \
            or not (outcomes or approvals):
        return _bad("exactly one of outcomes/approvals required", 422)

    with store.key_lock("q4:" + run_id):
        run = store.get(NS_RUN, run_id)
        if run is None:
            return _bad("unknown run", 404)
        rid = body["receiptId"]
        h = sha256_hex(body)
        prior = run["receipts"].get(rid)
        if prior is not None:
            if prior["hash"] != h:
                return _bad("receipt content conflict", 409)
            return _json(prior["response"])
        if run["status"] in TERMINAL:
            return _bad("run already terminal", 409)

        trace = Trace(run["trace"])
        if outcomes is not None:
            err = _check_outcomes(run, outcomes)
            if err:
                return _bad(err, 422)
            new = _apply_outcomes(run, trace, rid, outcomes)
        else:
            err = _check_approvals(run, approvals)
            if err:
                return _bad(err, 422)
            new = _apply_approval(run, trace, rid, approvals[0])
        run["trace"] = trace.s
        resp = _view(run, new)
        run["receipts"][rid] = {"hash": h, "response": resp}
        store.put(NS_RUN, run_id, run)
        return _json(resp)


def _pending(run: dict) -> dict:
    acts = list(run["actions"].values()) + ([run["effect"]] if run.get("effect") else [])
    return {(a["actionId"], a["callId"], a["attempt"]): a for a in acts if a["state"] == "pending"}


def _check_outcomes(run: dict, outcomes: list) -> Optional[str]:
    pend = _pending(run)
    seen = set()
    for o in outcomes:
        if not isinstance(o, dict):
            return "invalid outcome"
        key = (o.get("actionId"), o.get("callId"), o.get("attempt"))
        if key not in pend or key in seen:
            return "outcome does not match a pending call"
        if not isinstance(o.get("status"), int):
            return "outcome status must be an integer"
        seen.add(key)
    return None


def _apply_outcomes(run: dict, trace: Trace, rid: str, outcomes: list) -> list:
    pend = _pending(run)
    new = []
    for o in outcomes:
        act = pend[(o["actionId"], o["callId"], o["attempt"])]
        entry = {"receiptId": rid, "actionId": act["actionId"], "callId": act["callId"],
                 "attempt": act["attempt"], "status": o["status"], "resultClass": o.get("resultClass"),
                 "nonce": o.get("nonce")}
        if o.get("errorType") is not None:
            entry["errorType"] = o["errorType"]
        run["receiptLog"].append(entry)
        status, err = o["status"], o.get("errorType")
        trace.record_outcome(act["actionId"], act["attempt"], rid, o.get("nonce"), status, err)
        if status == 503 and act["attempt"] == 1:
            new.append(_dispatch(run, trace, act))          # exactly one retry
        elif status == 0 or err == "timeout":
            act["state"] = "timeout"
        elif 200 <= status < 300:
            act["state"] = "done"
        else:
            act["state"] = "failed"
    if not any(d for d in new):
        new += _advance(run, trace)
    else:
        # retries outstanding; never include approval requests in a retry response
        pass
    return new


def _advance(run: dict, trace: Trace) -> list:
    diags = list(run["actions"].values())
    if any(a["state"] == "pending" for a in diags):
        return []
    eff = run.get("effect")
    if any(a["state"] != "done" for a in diags):
        run["status"] = "failed"
        if eff and eff["state"] == "planned":
            eff["state"] = "suppressed"
            reason = "prerequisite_timeout" if any(a["state"] == "timeout" for a in diags) \
                else "prerequisite_failed"
            run["suppressed"].append({"actionId": eff["actionId"], "toolName": eff["toolName"],
                                      "reason": reason})
        run["approval"] = None
        return []
    if eff is None:
        run["status"] = "completed"
        return []
    if eff["state"] == "planned":
        if eff["needsApproval"] and not (run.get("approval") or {}).get("nonce"):
            if run.get("approval") is None:
                appr = {"approvalId": "apr-" + _sid(run["runId"], "approval", eff["actionId"]),
                        "actionId": eff["actionId"], "toolName": eff["toolName"],
                        "argumentsDigest": sha256_hex(eff["arguments"])}
                run["approval"] = dict(appr, nonce=None, pending=True)
                trace.add_gate(appr["approvalId"], eff["actionId"])
            return []
        run["chosenEffect"] = eff["toolName"]
        return [_dispatch(run, trace, eff, run.get("approval") if eff["needsApproval"] else None)]
    if eff["state"] == "pending":
        return []
    run["status"] = "completed" if eff["state"] == "done" else "failed"
    run["approval"] = None if run["status"] in TERMINAL else run.get("approval")
    return []


def _check_approvals(run: dict, approvals: list) -> Optional[str]:
    appr = run.get("approval")
    if not appr or not appr.get("pending") or len(approvals) != 1 or not isinstance(approvals[0], dict):
        return "no matching pending approval"
    a = approvals[0]
    if a.get("approvalId") != appr["approvalId"] or a.get("decision") not in ("approved", "rejected", "denied"):
        return "approval does not match pending request"
    if a["decision"] == "approved" and not a.get("nonce"):
        return "approval nonce required"
    return None


def _apply_approval(run: dict, trace: Trace, rid: str, a: dict) -> list:
    appr = run["approval"]
    run["receiptLog"].append({"receiptId": rid, "approvalId": appr["approvalId"],
                              "decision": a["decision"], "nonce": a.get("nonce")})
    trace.record_approval(rid, a.get("nonce"), a["decision"])
    appr["pending"] = False
    eff = run["effect"]
    if a["decision"] != "approved":
        eff["state"] = "suppressed"
        run["suppressed"].append({"actionId": eff["actionId"], "toolName": eff["toolName"],
                                  "reason": "approval_denied"})
        run["status"] = "failed"
        return []
    appr["nonce"] = a["nonce"]
    run["chosenEffect"] = eff["toolName"]
    return [_dispatch(run, trace, eff, appr)]


# ====================================================================== views
def _view(run: dict, new_dispatches: list) -> dict:
    out = {"runId": run["runId"], "status": run["status"], "diagnosis": run["diagnosis"]}
    if run["status"] in TERMINAL:
        out["dispatches"] = []
        out["approvals"] = []
    else:
        out["dispatches"] = new_dispatches
        appr = run.get("approval")
        out["approvals"] = ([{k: appr[k] for k in ("approvalId", "actionId", "toolName", "argumentsDigest")}]
                            if appr and appr.get("pending") and not new_dispatches else [])
    out["chosenEffect"] = run.get("chosenEffect")
    out["suppressed"] = run["suppressed"]
    out["actionLog"] = run["actionLog"]
    out["receiptLog"] = run["receiptLog"]
    out["otlp"] = Trace(run["trace"]).dump()
    return out


def get_incident(run_id: str) -> JSONResponse:
    run = store.get(NS_RUN, run_id)
    if run is None:
        return _bad("unknown run", 404)
    pending = [d for d in run["actionLog"]
               if (d["actionId"], d["callId"], d["attempt"]) in _pending(run)]
    return _json(_view(run, pending))
