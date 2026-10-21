"""Q4 — Observable Incident Triage agent.

Endpoints:
  POST /v2/incidents
  POST /v2/incidents/{runId}/receipts
  GET  /v2/incidents/{runId}

State machine per run:
  1. First POST: model picks rootCause from allowedRootCauses + cites evidence,
     plans 1-3 diagnostic dispatches (or an approval request for destructive
     effects). status="waiting".
  2. Receipts drive progress: 503 -> one retry (new CLIENT span, attempt+1);
     timeout -> fail dependent effect; diagnosis_confirmed -> emit one effect.
     Approval receipt -> dispatch the approved effect.
  3. Terminal: status completed/failed with actionLog, receiptLog, and a full
     OTLP trace correlating every action and receipt.

Replay reads stored state (no model call). Changed content -> 409.
Sensitive object is never sent to the model or exported in telemetry.
"""
from __future__ import annotations

import json
import secrets
import time
from typing import Any, Optional

from fastapi import Request
from fastapi.responses import JSONResponse

from . import store
from .canonical import sha256_hex, canonical_str
from .incident_planner import plan_incident
from . import otlp

MAX_BODY = 768 * 1024
PROFILE = "ga5-incident-agent/v2"

NS_RUN = "q4_run"          # runId -> full run state
NS_REQ = "q4_req"          # runId -> request content hash


def _json(data: Any, status: int = 200) -> JSONResponse:
    body = json.dumps(data).encode("utf-8")
    if status == 200 and len(body) > MAX_BODY:
        return JSONResponse({"error": "response too large"}, status_code=500)
    return JSONResponse(data, status_code=status)


APPROVAL_TOOLS = {"rollback_deployment", "disable_feature"}


def _rid(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


# --------------------------------------------------------------------------
# POST /v2/incidents  — create/replay a run
# --------------------------------------------------------------------------
async def create_incident(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return _json({"error": "invalid JSON"}, 400)
    if not isinstance(body, dict):
        return _json({"error": "invalid body"}, 400)
    if body.get("profile") != PROFILE:
        return _json({"error": "unsupported profile"}, 400)
    run_id = body.get("runId")
    incident = body.get("incident")
    if not run_id or not isinstance(incident, dict):
        return _json({"error": "invalid request"}, 422)

    # content hash excludes volatile per-run marker/canary/sensitive values but
    # includes incident + policy + toolCatalog (the semantic request).
    semantic = {
        "incident": incident,
        "policy": body.get("policy"),
        "toolCatalog": body.get("toolCatalog"),
        "agentName": body.get("agentName"),
    }
    content_hash = sha256_hex(semantic)

    with store.transaction():
        prior_hash = store.get(NS_REQ, run_id)
        if prior_hash is not None:
            if prior_hash != content_hash:
                return _json({"error": "run content conflict"}, 409)
            run = store.get(NS_RUN, run_id)
            return _json(_public_run(run))

        run = _plan_new_run(body)
        store.put(NS_REQ, run_id, content_hash)
        store.put(NS_RUN, run_id, run)
        return _json(_public_run(run))


def _plan_new_run(body: dict) -> dict:
    run_id = body["runId"]
    incident = body["incident"]
    policy = body.get("policy", {}) or {}
    catalog = body.get("toolCatalog", []) or []
    public_marker = body.get("publicMarker", "")
    agent_name = body.get("agentName", "incident-response")

    # incoming trace context
    tp = None
    headers_tp = body.get("traceparent")  # may be absent

    # MODEL CALL (the only one): diagnosis + plan. sensitive is NEVER passed.
    plan = plan_incident(incident, catalog, policy)
    root_cause = plan["rootCause"]
    evidence = plan["evidence"]
    diagnostics = plan["diagnostics"]   # list of {toolName, arguments, evidence}
    effect = plan.get("effect")         # {toolName, arguments, evidence} or None
    model_name = plan.get("modelName", "")

    approval_required = set(policy.get("approvalRequiredFor", []))

    # Build OTLP trace skeleton (trace id + server/agent/model spans).
    trace = otlp.new_trace(run_id, public_marker)
    trace.start_server()
    trace.start_agent(agent_name)
    trace.add_model_span(model_name)

    dispatches = []
    approvals = []

    # If the planned EFFECT needs approval, first return an approval request and
    # zero effect dispatches. Diagnostics still run first though.
    # Phase 1 is always diagnostics (unless none needed).
    pending = []
    for d in diagnostics:
        action_id = _rid("act")
        call_id = _rid("call")
        client_span = trace.add_tool_client(action_id, d["toolName"], call_id,
                                            attempt=1)
        dispatches.append({
            "actionId": action_id, "callId": call_id,
            "phase": "diagnostic", "toolName": d["toolName"],
            "arguments": d["arguments"], "evidence": d["evidence"],
            "attempt": 1,
            "traceparent": trace.traceparent(client_span),
        })
        pending.append({"actionId": action_id, "callId": call_id,
                        "toolName": d["toolName"], "attempt": 1,
                        "phase": "diagnostic", "status": "pending"})

    if len(diagnostics) > 1:
        trace.add_join([d["_client_span"] for d in trace.diag_clients])

    run = {
        "runId": run_id,
        "status": "waiting",
        "agentName": agent_name,
        "publicMarker": public_marker,
        "diagnosis": {"rootCause": root_cause, "evidence": evidence},
        "plannedEffect": effect,
        "approvalRequired": effect is not None
            and effect.get("toolName") in approval_required,
        "approvalRequestedId": None,
        "effectActionId": None,
        "pending": pending,
        "dispatches": dispatches,
        "approvals": approvals,
        "actionLog": list(dispatches),
        "receiptLog": [],
        "suppressed": [],
        "chosenEffect": None,
        "trace": trace.dump(),
        "_trace_state": trace.serialize(),
    }
    return run


# --------------------------------------------------------------------------
# POST /v2/incidents/{runId}/receipts
# --------------------------------------------------------------------------
async def post_receipts(request: Request, run_id: str) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return _json({"error": "invalid JSON"}, 400)

    with store.transaction():
        run = store.get(NS_RUN, run_id)
        if run is None:
            return _json({"error": "unknown run"}, 404)

        receipt_id = body.get("receiptId")
        # replay detection: same receiptId with same content -> same state
        rkey = f"{run_id}:receipt:{receipt_id}"
        prior = store.get("q4_receipt_seen", rkey)
        cur_hash = sha256_hex(body)
        if prior is not None:
            if prior["hash"] != cur_hash:
                return _json({"error": "receipt content conflict"}, 409)
            return _json(_public_run(run))

        trace = otlp.Trace.deserialize(run["_trace_state"])

        # approval receipts
        approvals = body.get("approvals")
        outcomes = body.get("outcomes")

        if approvals:
            run = _apply_approval(run, trace, receipt_id, approvals)
        elif outcomes:
            run = _apply_outcomes(run, trace, receipt_id, outcomes)
        else:
            return _json({"error": "empty receipt"}, 400)

        run["_trace_state"] = trace.serialize()
        run["trace"] = trace.dump()
        store.put(NS_RUN, run_id, run)
        store.put("q4_receipt_seen", rkey, {"hash": cur_hash})
        return _json(_public_run(run))


def _apply_outcomes(run: dict, trace, receipt_id: str, outcomes: list) -> dict:
    pending = {(p["actionId"], p["callId"], p["attempt"]): p
               for p in run["pending"] if p["status"] == "pending"}
    for o in outcomes:
        key = (o.get("actionId"), o.get("callId"), o.get("attempt", 1))
        p = pending.get(key)
        if p is None:
            continue  # accept only pending calls
        status = o.get("status")
        result_class = o.get("resultClass")
        err = o.get("errorType")
        nonce = o.get("nonce")
        # record receipt in log + trace client span fields
        run["receiptLog"].append({
            "receiptId": receipt_id, "actionId": p["actionId"],
            "callId": p["callId"], "attempt": p["attempt"],
            "status": status, "resultClass": result_class, "nonce": nonce,
        })
        trace.record_receipt_on_client(p["actionId"], p["attempt"],
                                       receipt_id, nonce, status, err)
        if status == 503:
            # exactly one retry with new CLIENT span, attempt+1
            if p["attempt"] == 1:
                p["status"] = "retried"
                new_attempt = 2
                client_span = trace.add_tool_client(
                    p["actionId"], p["toolName"], p["callId"],
                    attempt=new_attempt)
                disp = {
                    "actionId": p["actionId"], "callId": p["callId"],
                    "phase": p["phase"], "toolName": p["toolName"],
                    "arguments": {}, "evidence": [], "attempt": new_attempt,
                    "traceparent": trace.traceparent(client_span),
                }
                run["dispatches"].append(disp)
                run["actionLog"].append(disp)
                run["pending"].append({
                    "actionId": p["actionId"], "callId": p["callId"],
                    "toolName": p["toolName"], "attempt": new_attempt,
                    "phase": p["phase"], "status": "pending"})
            else:
                p["status"] = "failed"
        elif status == 0 and err == "timeout":
            p["status"] = "timeout"
            # dependent effect must NOT be sent
            run["suppressed"].append({"reason": "prerequisite_timeout",
                                      "actionId": p["actionId"]})
        elif result_class == "diagnosis_confirmed" or status == 200:
            p["status"] = "confirmed"
        else:
            p["status"] = "done"

    return _maybe_emit_effect(run, trace)


def _maybe_emit_effect(run: dict, trace) -> dict:
    # First: if an effect has already been dispatched, resolve by its status.
    effect_pending = [p for p in run["pending"] if p["phase"] == "effect"]
    if effect_pending:
        still_open = [p for p in effect_pending if p["status"] == "pending"]
        if still_open:
            return run  # waiting on effect receipt
        failed = any(p["status"] in ("failed", "timeout") for p in effect_pending)
        run["status"] = "failed" if failed else "completed"
        return _finalize(run, trace)

    # if all diagnostics resolved and none timed out, emit the effect
    diag = [p for p in run["pending"] if p["phase"] == "diagnostic"]
    active = [p for p in diag if p["status"] == "pending"]
    if active:
        return run  # still waiting
    timed_out = any(p["status"] == "timeout" for p in diag)
    effect = run.get("plannedEffect")

    if timed_out:
        run["status"] = "failed"
        run["chosenEffect"] = None
        return _finalize(run, trace)

    if effect is None:
        run["status"] = "completed"
        return _finalize(run, trace)

    # effect requires approval?
    if run.get("approvalRequired") and run.get("approvalRequestedId") is None:
        approval_id = _rid("apr")
        action_id = _rid("act")
        run["approvalRequestedId"] = approval_id
        run["effectActionId"] = action_id
        digest = sha256_hex(effect.get("arguments", {}))
        run["approvals"] = [{
            "approvalId": approval_id, "actionId": action_id,
            "toolName": effect["toolName"], "argumentsDigest": digest,
        }]
        run["dispatches"] = []  # zero effect dispatches until approved
        trace.add_approval_gate(approval_id)
        run["status"] = "waiting"
        return run

    # no approval needed -> dispatch effect now
    return _dispatch_effect(run, trace)


def _dispatch_effect(run: dict, trace, approval_nonce: Optional[str] = None) -> dict:
    effect = run["plannedEffect"]
    action_id = run.get("effectActionId") or _rid("act")
    call_id = _rid("call")
    client_span = trace.add_tool_client(action_id, effect["toolName"], call_id,
                                        attempt=1)
    disp = {
        "actionId": action_id, "callId": call_id,
        "phase": "effect", "toolName": effect["toolName"],
        "arguments": effect.get("arguments", {}),
        "evidence": effect.get("evidence", []),
        "attempt": 1,
        "traceparent": trace.traceparent(client_span),
    }
    if approval_nonce:
        disp["approvalId"] = run.get("approvalRequestedId")
        disp["approvalNonce"] = approval_nonce
    run["dispatches"] = [disp]
    run["actionLog"].append(disp)
    run["pending"].append({
        "actionId": action_id, "callId": call_id,
        "toolName": effect["toolName"], "attempt": 1,
        "phase": "effect", "status": "pending"})
    run["chosenEffect"] = effect["toolName"]
    run["status"] = "waiting"
    return run


def _apply_approval(run: dict, trace, receipt_id: str, approvals: list) -> dict:
    for a in approvals:
        if a.get("approvalId") != run.get("approvalRequestedId"):
            continue
        if a.get("decision") != "approved":
            run["status"] = "failed"
            return _finalize(run, trace)
        nonce = a.get("nonce")
        run["receiptLog"].append({
            "receiptId": receipt_id, "approvalId": a["approvalId"],
            "decision": "approved", "nonce": nonce,
        })
        trace.record_approval(a["approvalId"], nonce)
        return _dispatch_effect(run, trace, approval_nonce=nonce)
    return run


def _finalize(run: dict, trace) -> dict:
    # effect confirmed?
    effect_pending = [p for p in run["pending"]
                      if p["phase"] == "effect" and p["status"] == "pending"]
    if not effect_pending and run["status"] not in ("failed",):
        run["status"] = "completed"
    run["dispatches"] = []
    run["approvals"] = []
    return run


# --------------------------------------------------------------------------
# GET /v2/incidents/{runId}
# --------------------------------------------------------------------------
def get_incident(run_id: str) -> JSONResponse:
    run = store.get(NS_RUN, run_id)
    if run is None:
        return _json({"error": "unknown run"}, 404)
    return _json(_public_run(run))


def _public_run(run: dict) -> dict:
    terminal = run["status"] in ("completed", "failed")
    out = {
        "runId": run["runId"],
        "status": run["status"],
        "diagnosis": run["diagnosis"],
        "chosenEffect": run.get("chosenEffect"),
        "suppressed": run.get("suppressed", []),
        "actionLog": run.get("actionLog", []),
        "receiptLog": run.get("receiptLog", []),
        "otlp": run["trace"],
    }
    if terminal:
        out["dispatches"] = []
        out["approvals"] = []
    else:
        out["dispatches"] = run.get("dispatches", [])
        out["approvals"] = run.get("approvals", [])
    return out
