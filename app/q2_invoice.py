"""Q2 — A2A Invoice Agent (A2A 1.0 HTTP+JSON).

Handlers take (headers, raw body) and run synchronously in a worker thread so a
slow model call never blocks the event loop.
"""
from __future__ import annotations

import json
import os
import secrets
import time
from typing import Any, Optional

from fastapi.responses import JSONResponse, Response

from . import store
from .canonical import sha256_hex
from .invoice_decider import decide_batch

A2A_VERSION = "1.0"
A2A_MEDIA = "application/a2a+json"
INPUT_MODE = "application/vnd.ga5.invoice-claim-batch+json"
OUT_PROPOSALS = "application/vnd.ga5.invoice-action-proposals+json"
OUT_RECEIPTS = "application/vnd.ga5.invoice-action-receipts+json"
IN_RESULTS = "application/vnd.ga5.invoice-action-results+json"
MAX_BODY = 512 * 1024

NS_TASK = "q2_task"
NS_IDEMP = "q2_idemp"
NS_CACHE = "q2_decis"
TERMINAL = ("TASK_STATE_COMPLETED", "TASK_STATE_CANCELED", "TASK_STATE_FAILED", "TASK_STATE_REJECTED")


def _origin(base_url: str) -> str:
    return (os.environ.get("PUBLIC_BASE_URL") or base_url).rstrip("/")


def _a2a(data: Any, status: int = 200) -> Response:
    body = json.dumps(data, ensure_ascii=False).encode("utf-8")
    if status == 200 and len(body) > MAX_BODY:
        return _err(500, "RESPONSE_TOO_LARGE")
    return Response(content=body, media_type=A2A_MEDIA, status_code=status)


def _err(status: int, code: str) -> Response:
    return JSONResponse({"error": {"code": code}}, status_code=status)


def _principal(h: dict) -> Optional[str]:
    auth = h.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    return auth[7:].strip() or None


def _check_version(h: dict) -> Optional[Response]:
    if h.get("a2a-version") != A2A_VERSION:
        return _err(400, "VERSION_NOT_SUPPORTED")
    return None


def _check_media(h: dict) -> Optional[Response]:
    ctype = h.get("content-type", "").split(";")[0].strip().lower()
    if ctype != A2A_MEDIA:
        return _err(415, "UNSUPPORTED_MEDIA_TYPE")
    return None


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(12)}"


def _public(task: dict) -> dict:
    return {k: v for k, v in task.items() if not k.startswith("_")}


# ---------------------------------------------------------------- agent card
def agent_card(base_url: str) -> JSONResponse:
    base = _origin(base_url) + "/a2a/"
    return JSONResponse({
        "name": "Invoice Action Agent",
        "description": "Reads invoice-claim batches, proposes one evidence-backed business action per "
                       "package, and executes only grader-accepted proposals under a receipt lifecycle.",
        "version": "1.1.0",
        "protocolVersion": A2A_VERSION,
        "capabilities": {"streaming": False, "pushNotifications": False, "stateTransitionHistory": True},
        "defaultInputModes": [INPUT_MODE],
        "defaultOutputModes": [OUT_PROPOSALS, OUT_RECEIPTS],
        "supportedInterfaces": [{"url": base, "protocolBinding": "HTTP+JSON", "protocolVersion": A2A_VERSION}],
        "securitySchemes": {"bearer": {"httpAuthSecurityScheme": {"scheme": "Bearer"}}},
        "security": [{"bearer": []}],
        "skills": [{
            "id": "invoice_action_agent",
            "name": "invoice_action_agent",
            "description": "Choose settle/request-approval/hold/reject-duplicate/open-exception for each "
                           "invoice package and cite the decisive evidence references.",
            "tags": ["invoice", "accounts-payable", "evidence", "a2a"],
            "inputModes": [INPUT_MODE],
            "outputModes": [OUT_PROPOSALS, OUT_RECEIPTS],
        }],
    })


# ---------------------------------------------------------------- message:send
def message_send(h: dict, raw: bytes) -> Response:
    principal = _principal(h)
    if not principal:
        return _err(401, "UNAUTHENTICATED")
    for check in (_check_version, _check_media):
        e = check(h)
        if e:
            return e
    try:
        body = json.loads(raw.decode("utf-8"))
    except Exception:
        return _err(400, "INVALID_JSON")
    if not isinstance(body, dict) or not isinstance(body.get("message"), dict):
        return _err(400, "INVALID_REQUEST")
    message = body["message"]
    message_id = message.get("messageId")
    parts = message.get("parts")
    if not isinstance(message_id, str) or not message_id or not isinstance(parts, list) or not parts \
            or not isinstance(parts[0], dict):
        return _err(400, "INVALID_REQUEST")

    msg_hash = sha256_hex(message)          # message only; configuration ignored
    idemp_key = f"{principal}|{message_id}"
    with store.key_lock("q2idem:" + idemp_key):
        prior = store.get(NS_IDEMP, idemp_key)
        if prior is not None:
            if prior["hash"] != msg_hash:
                return _err(409, "IDEMPOTENCY_CONFLICT")
            task = store.get(NS_TASK, prior["taskId"])
            return _a2a({"task": _public(task)})   # current stored Task (terminal if finished)

        media = parts[0].get("mediaType")
        if media == IN_RESULTS:
            return _continue(principal, message, msg_hash, idemp_key)
        if media != INPUT_MODE:
            return _err(400, "UNSUPPORTED_PART_MEDIA_TYPE")
        if message.get("taskId"):
            return _err(400, "UNEXPECTED_TASK_ID")

        data = parts[0].get("data") or {}
        batch_id = data.get("batchId")
        packages = data.get("packages")
        if not isinstance(batch_id, str) or not batch_id or not isinstance(packages, list) or not packages:
            return _err(400, "INVALID_BATCH")
        pids = [(p or {}).get("packageId") for p in packages if isinstance(p, dict)]
        if len(pids) != len(packages) or any(not isinstance(x, str) or not x for x in pids) \
                or len(set(pids)) != len(pids):
            return _err(400, "INVALID_PACKAGES")

        proposals = decide_batch(batch_id, packages, NS_CACHE)

        task_id, context_id = _id("task"), message.get("contextId") or _id("ctx")
        stored_msg = dict(message, taskId=task_id, contextId=context_id)
        task = {
            "id": task_id,
            "contextId": context_id,
            "status": {"state": "TASK_STATE_INPUT_REQUIRED", "timestamp": _now()},
            "history": [stored_msg],
            "artifacts": [{
                "artifactId": _id("proposals"),
                "name": "invoice-action-proposals",
                "parts": [{"mediaType": OUT_PROPOSALS, "data": proposals}],
            }],
            "kind": "task",
            "_principal": principal,
            "_batchId": batch_id,
        }
        store.put(NS_TASK, task_id, task)
        resp = {"task": _public(task)}
        store.put(NS_IDEMP, idemp_key, {"hash": msg_hash, "taskId": task_id, "response": resp})
        return _a2a(resp)


def _continue(principal: str, message: dict, msg_hash: str, idemp_key: str) -> Response:
    task_id, context_id = message.get("taskId"), message.get("contextId")
    if not isinstance(task_id, str) or not task_id:
        return _err(400, "INVALID_CONTINUATION")
    with store.key_lock("q2task:" + task_id):
        task = store.get(NS_TASK, task_id)
        if task is None or task.get("_principal") != principal:
            return _err(404, "NOT_FOUND")
        if context_id != task["contextId"]:
            return _err(400, "CONTEXT_MISMATCH")
        if task["status"]["state"] in TERMINAL:
            return _err(409, "TASK_TERMINAL")

        data = message["parts"][0].get("data") or {}
        results = data.get("results")
        proposals_data = task["artifacts"][0]["parts"][0]["data"]
        if data.get("batchId") != proposals_data["batchId"]:
            return _err(400, "BATCH_MISMATCH")
        if not isinstance(results, list):
            return _err(400, "INVALID_RESULTS")
        by_aid = {p["actionId"]: p for p in proposals_data["proposals"]}
        seen: set[str] = set()
        executions = []
        for r in results:
            if not isinstance(r, dict):
                return _err(400, "INVALID_RESULTS")
            prop = by_aid.get(r.get("actionId"))
            if prop is None or r["actionId"] in seen:
                return _err(400, "ACTION_MISMATCH")
            seen.add(r["actionId"])
            if r.get("packageId") != prop["packageId"] or r.get("action") != prop["action"]:
                return _err(400, "RESULT_MISMATCH")
            outcome = r.get("outcome")
            if outcome not in ("ACCEPTED", "REJECTED"):
                return _err(400, "INVALID_OUTCOME")
            if outcome == "ACCEPTED":
                nonce = r.get("receiptNonce")
                if not isinstance(nonce, str) or not nonce:
                    return _err(400, "MISSING_RECEIPT")
                executions.append({
                    "packageId": prop["packageId"], "actionId": prop["actionId"], "action": prop["action"],
                    "receiptNonce": nonce, "facts": prop["facts"], "evidenceRefs": prop["evidenceRefs"],
                })

        task["history"].append(message)
        task["artifacts"].append({
            "artifactId": _id("receipts"),
            "name": "invoice-action-receipts",
            "parts": [{"mediaType": OUT_RECEIPTS,
                       "data": {"batchId": proposals_data["batchId"], "executions": executions}}],
        })
        task["status"] = {"state": "TASK_STATE_COMPLETED", "timestamp": _now()}
        store.put(NS_TASK, task_id, task)
        resp = {"task": _public(task)}
        store.put(NS_IDEMP, idemp_key, {"hash": msg_hash, "taskId": task_id, "response": resp})
        return _a2a(resp)


# ---------------------------------------------------------------- task routes
def _auth_only(h: dict) -> tuple[Optional[str], Optional[Response]]:
    p = _principal(h)
    if not p:
        return None, _err(401, "UNAUTHENTICATED")
    e = _check_version(h)
    return p, e


def get_task(h: dict, task_id: str) -> Response:
    p, e = _auth_only(h)
    if e:
        return e
    task = store.get(NS_TASK, task_id)
    if task is None or task.get("_principal") != p:
        return _err(404, "NOT_FOUND")
    return _a2a(_public(task))


def list_tasks(h: dict) -> Response:
    p, e = _auth_only(h)
    if e:
        return e
    mine = [_public(t) for t in store.list_ns(NS_TASK) if t.get("_principal") == p]
    return _a2a({"tasks": mine})


def cancel_task(h: dict, task_id: str) -> Response:
    p, e = _auth_only(h)
    if e:
        return e
    with store.key_lock("q2task:" + task_id):
        task = store.get(NS_TASK, task_id)
        if task is None or task.get("_principal") != p:
            return _err(404, "NOT_FOUND")
        if task["status"]["state"] in TERMINAL:
            return _err(409, "TASK_NOT_CANCELABLE")
        task["status"] = {"state": "TASK_STATE_CANCELED", "timestamp": _now()}
        store.put(NS_TASK, task_id, task)
        return _a2a(_public(task))
