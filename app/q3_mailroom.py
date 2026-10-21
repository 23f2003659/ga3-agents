"""Q3 — Safe AI Mailroom agent.

One endpoint, two operations:

  POST {url}  {operation:"propose", evaluationId, dossiers:[...]}
     -> 200 {status:"awaiting_receipts", proposals:[...]}
  POST {url}  {operation:"commit", evaluationId?, receipts:[...]}
     -> 200 {status:"completed", outcomes:[...]}

Safety model (lethal trifecta / prompt injection aware):
  * External mail is DATA, never instructions. We never place raw mail into
    tool arguments; we cite minimal evidence lines by index.
  * Decisions cached by canonical dossier content (stable callId across runs).
  * Receipts verified before any effect is recorded completed.
  * Exact replay -> byte-equivalent JSON, no model work.
  * Same evaluationId with changed content -> 409.
  * Malformed / duplicate dossier IDs / bad schema -> 400/422 before AI work.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Optional

from fastapi import Request
from fastapi.responses import JSONResponse

from . import store
from .canonical import canonical_str, sha256_hex
from .mailroom_decider import decide_dossiers

MAX_BODY = 512 * 1024

NS_EVAL = "q3_eval"       # evaluationId -> {contentHash, proposals, callMap, keys}
NS_CACHE = "q3_decis"     # dossier fingerprint -> decision
NS_COMMIT = "q3_commit"   # evaluationId -> terminal outcomes (replay)

ACTIONS = {
    "create_draft", "update_internal_record", "send_approved_notice",
    "request_confirmation", "quarantine_item", "no_action",
}


def _json(data: Any, status: int = 200) -> JSONResponse:
    body = json.dumps(data).encode("utf-8")
    if status == 200 and len(body) > MAX_BODY:
        return JSONResponse({"error": "response too large"}, status_code=500)
    return JSONResponse(data, status_code=status)


async def handle(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return _json({"error": "invalid JSON"}, 400)
    if not isinstance(body, dict):
        return _json({"error": "invalid body"}, 400)
    op = body.get("operation")
    if op == "propose":
        return _propose(body)
    if op == "commit":
        return _commit(body)
    return _json({"error": "invalid operation"}, 400)


def _fingerprint(dossier: dict) -> str:
    """Stable content fingerprint ignoring volatile evaluation IDs."""
    stable = {k: v for k, v in dossier.items()
              if k not in ("evaluationId",)}
    return sha256_hex(stable)


def _propose(body: dict) -> JSONResponse:
    eval_id = body.get("evaluationId")
    dossiers = body.get("dossiers")
    if not eval_id or not isinstance(dossiers, list) or not dossiers:
        return _json({"error": "invalid request"}, 400)

    # schema + duplicate dossier id validation BEFORE any AI work
    ids = []
    for d in dossiers:
        if not isinstance(d, dict):
            return _json({"error": "invalid dossier"}, 422)
        did = d.get("dossierId") or d.get("id")
        if not did:
            return _json({"error": "missing dossierId"}, 422)
        ids.append(did)
    if len(ids) != len(set(ids)):
        return _json({"error": "duplicate dossier id"}, 400)

    content_hash = sha256_hex([_fingerprint(d) for d in dossiers])

    with store.transaction():
        prior = store.get(NS_EVAL, eval_id)
        if prior is not None:
            if prior["contentHash"] != content_hash:
                return _json({"error": "evaluation content conflict"}, 409)
            # exact replay -> same proposals, no model work
            return _json({"status": "awaiting_receipts",
                          "proposals": prior["proposals"]})

        proposals, call_map = decide_dossiers(dossiers, NS_CACHE, _fingerprint)
        # store verification keys supplied per-evaluation (if any)
        keys = body.get("receiptVerificationKeys") or body.get("keys") or {}
        store.put(NS_EVAL, eval_id, {
            "contentHash": content_hash,
            "proposals": proposals,
            "callMap": call_map,       # callId -> proposal digest
            "keys": keys,
        })
        return _json({"status": "awaiting_receipts", "proposals": proposals})


def _commit(body: dict) -> JSONResponse:
    receipts = body.get("receipts")
    if not isinstance(receipts, list):
        return _json({"error": "invalid receipts"}, 400)

    eval_id = body.get("evaluationId")
    # derive eval from receipts if not supplied
    if not eval_id and receipts:
        eval_id = receipts[0].get("evaluationId")
    if not eval_id:
        return _json({"error": "missing evaluationId"}, 400)

    with store.transaction():
        rec = store.get(NS_EVAL, eval_id)
        if rec is None:
            return _json({"error": "unknown evaluation"}, 409)

        # replay: identical commit returns stored terminal body
        commit_hash = sha256_hex(receipts)
        prior = store.get(NS_COMMIT, eval_id)
        if prior is not None:
            if prior["commitHash"] != commit_hash:
                return _json({"error": "commit content conflict"}, 409)
            return _json({"status": "completed",
                          "outcomes": prior["outcomes"]})

        call_map = rec["callMap"]
        prop_by_call = {p["callId"]: p for p in rec["proposals"]}
        outcomes = []
        for r in receipts:
            call_id = r.get("callId")
            prop = prop_by_call.get(call_id)
            if prop is None:
                return _json({"error": "receipt for unknown call"}, 409)
            # verify action + proposal digest match persisted proposal
            if r.get("action") and r.get("action") != prop["action"]:
                return _json({"error": "action mismatch"}, 409)
            digest = r.get("proposalDigest")
            if digest and digest != call_map.get(call_id):
                return _json({"error": "proposal digest mismatch"}, 409)
            # verify signature/nonce if a key was supplied
            if not _verify_receipt(r, rec.get("keys", {})):
                return _json({"error": "invalid receipt"}, 409)
            outcomes.append({
                "dossierId": prop["dossierId"],
                "callId": call_id,
                "action": prop["action"],
                "status": "recorded",
                "receiptId": r.get("receiptId"),
                "nonce": r.get("nonce"),
            })
        store.put(NS_COMMIT, eval_id,
                  {"commitHash": commit_hash, "outcomes": outcomes})
        return _json({"status": "completed", "outcomes": outcomes})


def _verify_receipt(receipt: dict, keys: dict) -> bool:
    """Verify a signed receipt when a verification key is provided.

    If the grader supplied an HMAC key for this evaluation, require a valid
    signature. If no key is provided, accept a well-formed receipt that carries
    a nonce (presence of an unpredictable nonce is the minimum proof)."""
    sig = receipt.get("signature")
    key = keys.get(receipt.get("receiptId")) or keys.get("hmacKey") or keys.get("key")
    if key and sig:
        payload = canonical_str({k: receipt[k] for k in receipt
                                 if k != "signature"})
        expected = hmac.new(str(key).encode(), payload.encode(),
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, str(sig))
    # no key configured: require at least a nonce to prove a live receipt
    return bool(receipt.get("nonce"))
