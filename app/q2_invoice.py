"""Q2 — A2A Invoice Agent.

Implements the A2A 1.0 HTTP+JSON surface for invoice action decisions:

    GET  {origin}/.well-known/agent-card.json   (public)
    POST {base}/message:send                     (Bearer)
    GET  {base}/tasks/{id}                        (Bearer, owner only)
    GET  {base}/tasks                             (Bearer, owner's tasks)
    POST {base}/tasks/{id}:cancel                 (Bearer, owner only)

Key invariants enforced:
  * A2A-Version: 1.0 and application/a2a+json required on non-card routes.
  * Idempotency by (principal, messageId) over canonical hash of the MESSAGE
    only (configuration ignored). Changed semantic content -> 409.
  * Lifecycle INPUT_REQUIRED (after propose) -> COMPLETED (after valid results)
    or CANCELED. Terminal tasks are immutable.
  * Decisions cached by canonical package content: repeat Checks make no model
    call. Receipt continuations / polls / lists / cancel make no model call.
  * Strict per-principal isolation; generic errors never reveal other tasks.
"""
from __future__ import annotations

import os
import secrets
import time
from typing import Any, Optional

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from . import store
from .canonical import canonical_str, sha256_hex
from .invoice_decider import decide_batch

router = APIRouter()

A2A_VERSION = "1.0"
A2A_MEDIA = "application/a2a+json"
INPUT_MODE = "application/vnd.ga5.invoice-claim-batch+json"
OUT_PROPOSALS = "application/vnd.ga5.invoice-action-proposals+json"
OUT_RECEIPTS = "application/vnd.ga5.invoice-action-receipts+json"
IN_RESULTS = "application/vnd.ga5.invoice-action-results+json"

MAX_BODY = 512 * 1024  # 512 KiB cap on successful responses

# namespaces
NS_TASK = "q2_task"          # key: taskId -> Task+meta
NS_IDEMP = "q2_idemp"        # key: f"{principal}|{messageId}" -> {hash, taskId}
NS_CACHE = "q2_decis"        # fingerprint -> decision


def _base_url(request: Request) -> str:
    base = os.environ.get("PUBLIC_BASE_URL")
    if base:
        return base.rstrip("/") + "/a2a/"
    # fall back to request
    return str(request.base_url).rstrip("/") + "/a2a/"


def _origin(request: Request) -> str:
    base = os.environ.get("PUBLIC_BASE_URL")
    if base:
        return base.rstrip("/")
    return str(request.base_url).rstrip("/")


def _a2a_json(data: Any, status: int = 200) -> Response:
    import json as _json
    body = _json.dumps(data).encode("utf-8")
    if status == 200 and len(body) > MAX_BODY:
        return JSONResponse({"error": "response too large"}, status_code=500)
    return Response(content=body, media_type=A2A_MEDIA, status_code=status)


def _err(status: int, code: str) -> Response:
    # generic error body; never echo another principal's data
    return JSONResponse({"error": code}, status_code=status)


def _principal(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    token = auth[7:].strip()
    return token or None


def _check_protocol(request: Request) -> Optional[Response]:
    ver = request.headers.get("a2a-version")
    if ver is not None and ver != A2A_VERSION:
        return _err(400, "UNSUPPORTED_VERSION")
    ctype = request.headers.get("content-type", "")
    # accept the a2a media type (allow charset suffixes)
    if request.method == "POST" and A2A_MEDIA not in ctype:
        return _err(400, "UNSUPPORTED_MEDIA_TYPE")
    if ver is None:
        return _err(400, "UNSUPPORTED_VERSION")
    return None


# --------------------------------------------------------------------------
# Agent Card (public, origin-level)
# --------------------------------------------------------------------------
def agent_card(request: Request) -> Response:
    base = _base_url(request)
    card = {
        "name": "Invoice Action Agent",
        "description": "Reads invoice-claim batches, proposes one safe business "
                       "action per package with cited evidence, then executes "
                       "only grader-accepted proposals under a receipt lifecycle.",
        "version": "1.0.0",
        "protocolVersion": A2A_VERSION,
        "capabilities": {"streaming": False, "pushNotifications": False,
                          "stateTransitionHistory": True},
        "defaultInputModes": [INPUT_MODE],
        "defaultOutputModes": [OUT_PROPOSALS, OUT_RECEIPTS],
        "supportedInterfaces": [
            {"url": base, "protocolBinding": "HTTP+JSON",
             "protocolVersion": A2A_VERSION}
        ],
        "skills": [{
            "id": "invoice_action_agent",
            "name": "invoice_action_agent",
            "description": "Decide settle/approve/hold/reject-duplicate/exception "
                           "for each invoice package citing decisive evidence.",
            "tags": ["invoice", "finance", "a2a", "decision", "evidence"],
            "inputModes": [INPUT_MODE],
            "outputModes": [OUT_PROPOSALS, OUT_RECEIPTS],
        }],
    }
    return JSONResponse(card)  # public: normal JSON is fine


# --------------------------------------------------------------------------
# Task helpers
# --------------------------------------------------------------------------
def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(10)}"


def _make_task(principal: str, context_id: str, task_id: str,
               message: dict, proposals: dict) -> dict:
    """Build a Task in INPUT_REQUIRED with the proposals artifact."""
    now = int(time.time())
    return {
        "id": task_id,
        "contextId": context_id,
        "status": {"state": "TASK_STATE_INPUT_REQUIRED",
                   "timestamp": now},
        "history": [message],
        "artifacts": [{
            "artifactId": _new_id("art"),
            "parts": [{
                "mediaType": OUT_PROPOSALS,
                "data": proposals,
            }],
        }],
        # internal bookkeeping (not part of A2A spec but allowed extra fields)
        "_principal": principal,
    }


def _public_task(task: dict) -> dict:
    t = dict(task)
    t.pop("_principal", None)
    return t


# --------------------------------------------------------------------------
# POST /message:send
# --------------------------------------------------------------------------
def message_send(request: Request, body: dict) -> Response:
    principal = _principal(request)
    if not principal:
        return _err(401, "UNAUTHENTICATED")
    perr = _check_protocol(request)
    if perr:
        return perr

    message = body.get("message")
    if not isinstance(message, dict):
        return _err(400, "INVALID_MESSAGE")

    message_id = message.get("messageId")
    if not message_id:
        return _err(400, "INVALID_MESSAGE")

    # idempotency key: hash of the MESSAGE only (ignore configuration)
    msg_hash = sha256_hex(message)
    idemp_key = f"{principal}|{message_id}"

    with store.transaction():
        prior = store.get(NS_IDEMP, idemp_key)
        if prior is not None:
            if prior["hash"] != msg_hash:
                return _err(409, "IDEMPOTENCY_CONFLICT")
            # same message -> return stored task unchanged, no model call
            task = store.get(NS_TASK, prior["taskId"])
            if task is None:
                return _err(409, "IDEMPOTENCY_CONFLICT")
            return _a2a_json({"task": _public_task(task)})

        # Determine whether this is an initial batch or a results continuation.
        parts = message.get("parts", [])
        part = parts[0] if parts else {}
        media = part.get("mediaType")

        if media == IN_RESULTS:
            return _handle_results(principal, message, msg_hash, idemp_key)

        if media != INPUT_MODE:
            return _err(400, "UNSUPPORTED_MEDIA_TYPE")

        # initial batch -> propose
        data = part.get("data", {})
        batch_id = data.get("batchId")
        packages = data.get("packages", [])
        if not batch_id or not isinstance(packages, list) or not packages:
            return _err(400, "INVALID_BATCH")

        proposals = decide_batch(batch_id, packages, NS_CACHE)

        context_id = _new_id("ctx")
        task_id = _new_id("task")
        task = _make_task(principal, context_id, task_id, message, proposals)
        store.put(NS_TASK, task_id, task)
        store.put(NS_IDEMP, idemp_key, {"hash": msg_hash, "taskId": task_id})
        return _a2a_json({"task": _public_task(task)})


def _handle_results(principal: str, message: dict, msg_hash: str,
                    idemp_key: str) -> Response:
    """Process a results continuation and complete the task."""
    task_id = message.get("taskId")
    context_id = message.get("contextId")
    if not task_id or not context_id:
        return _err(400, "INVALID_CONTINUATION")

    task = store.get(NS_TASK, task_id)
    if task is None or task.get("_principal") != principal:
        # isolation: generic 404, never reveal existence
        return _err(404, "NOT_FOUND")
    if task["contextId"] != context_id:
        return _err(400, "CONTEXT_MISMATCH")

    state = task["status"]["state"]
    if state in ("TASK_STATE_COMPLETED", "TASK_STATE_CANCELED"):
        # terminal replay: if same message already applied, idempotency caught
        # it above; otherwise reject mutation of terminal task
        return _err(409, "TASK_TERMINAL")

    part = message["parts"][0]
    data = part.get("data", {})
    results = data.get("results", [])
    batch_id = data.get("batchId")

    # locate stored proposals
    proposals_art = task["artifacts"][0]["parts"][0]["data"]
    stored = {p["actionId"]: p for p in proposals_art["proposals"]}
    stored_batch = proposals_art["batchId"]

    if batch_id != stored_batch:
        return _err(400, "BATCH_MISMATCH")

    executions = []
    for r in results:
        aid = r.get("actionId")
        prop = stored.get(aid)
        if prop is None:
            return _err(400, "UNKNOWN_ACTION")
        # every field must match the stored proposal
        if (r.get("packageId") != prop["packageId"]
                or r.get("action") != prop["action"]):
            return _err(400, "RESULT_MISMATCH")
        if r.get("outcome") != "ACCEPTED":
            # rejected proposals are NOT executed; remain in history only
            continue
        nonce = r.get("receiptNonce")
        if not nonce:
            return _err(400, "MISSING_NONCE")
        executions.append({
            "packageId": prop["packageId"],
            "actionId": prop["actionId"],
            "action": prop["action"],
            "receiptNonce": nonce,
            "facts": prop["facts"],
            "evidenceRefs": prop["evidenceRefs"],
        })

    # append continuation to history, add receipts artifact, complete
    task["history"].append(message)
    task["artifacts"].append({
        "artifactId": _new_id("art"),
        "parts": [{
            "mediaType": OUT_RECEIPTS,
            "data": {"batchId": stored_batch, "executions": executions},
        }],
    })
    task["status"] = {"state": "TASK_STATE_COMPLETED", "timestamp": int(time.time())}
    store.put(NS_TASK, task_id, task)
    store.put(NS_IDEMP, idemp_key, {"hash": msg_hash, "taskId": task_id})
    return _a2a_json({"task": _public_task(task)})


# --------------------------------------------------------------------------
# GET /tasks/{id}
# --------------------------------------------------------------------------
def get_task(request: Request, task_id: str) -> Response:
    principal = _principal(request)
    if not principal:
        return _err(401, "UNAUTHENTICATED")
    perr = _check_version_only(request)
    if perr:
        return perr
    task = store.get(NS_TASK, task_id)
    if task is None or task.get("_principal") != principal:
        return _err(404, "NOT_FOUND")
    return _a2a_json(_public_task(task))


# --------------------------------------------------------------------------
# GET /tasks
# --------------------------------------------------------------------------
def list_tasks(request: Request) -> Response:
    principal = _principal(request)
    if not principal:
        return _err(401, "UNAUTHENTICATED")
    perr = _check_version_only(request)
    if perr:
        return perr
    all_tasks = store.list_ns(NS_TASK)
    mine = [_public_task(t) for t in all_tasks if t.get("_principal") == principal]
    return _a2a_json({"tasks": mine})


# --------------------------------------------------------------------------
# POST /tasks/{id}:cancel
# --------------------------------------------------------------------------
def cancel_task(request: Request, task_id: str) -> Response:
    principal = _principal(request)
    if not principal:
        return _err(401, "UNAUTHENTICATED")
    perr = _check_version_only(request)
    if perr:
        return perr
    with store.transaction():
        task = store.get(NS_TASK, task_id)
        if task is None or task.get("_principal") != principal:
            return _err(404, "NOT_FOUND")
        state = task["status"]["state"]
        if state in ("TASK_STATE_COMPLETED", "TASK_STATE_CANCELED"):
            # cancel/receipt race: terminal already -> 409
            return _err(409, "TASK_TERMINAL")
        task["status"] = {"state": "TASK_STATE_CANCELED",
                          "timestamp": int(time.time())}
        store.put(NS_TASK, task_id, task)
        return _a2a_json(_public_task(task))


def _check_version_only(request: Request) -> Optional[Response]:
    ver = request.headers.get("a2a-version")
    if ver is None:
        return _err(400, "UNSUPPORTED_VERSION")
    if ver != A2A_VERSION:
        return _err(400, "UNSUPPORTED_VERSION")
    return None
