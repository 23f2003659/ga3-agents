"""Q3 — Safe AI Mailroom (profile ga5-mailroom-action-gate/v2).

propose: validate -> decide (cached per dossier content) -> persist -> 200
commit : validate -> verify every Ed25519 receipt signature -> persist -> 200
"""
from __future__ import annotations

import base64
import json
from typing import Any

from fastapi.responses import JSONResponse

from . import store
from .canonical import canonical_bytes, sha256_hex
from .mailroom_decider import ACTIONS, decide_dossiers

PROFILE = "ga5-mailroom-action-gate/v2"
MAX_BODY = 512 * 1024
MAX_REQUEST = 8 * 1024 * 1024
NS_EVAL = "q3_eval"
NS_CACHE = "q3_decis"


def _json(data: Any, status: int = 200) -> JSONResponse:
    if status == 200 and len(json.dumps(data).encode()) > MAX_BODY:
        return JSONResponse({"error": "response too large"}, status_code=500)
    return JSONResponse(data, status_code=status)


def _bad(msg: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": msg}, status_code=status)


def handle(raw: bytes) -> JSONResponse:
    if len(raw) > MAX_REQUEST:
        return _bad("request too large", 413)
    try:
        body = json.loads(raw.decode("utf-8"))
    except Exception:
        return _bad("invalid JSON")
    if not isinstance(body, dict):
        return _bad("invalid body")
    if body.get("profile") != PROFILE:
        return _bad("unsupported profile")
    op = body.get("operation")
    if op == "propose":
        return _propose(body)
    if op == "commit":
        return _commit(body)
    return _bad("invalid operation")


# ------------------------------------------------------------------ propose
def _validate_dossiers(dossiers: Any) -> str | None:
    if not isinstance(dossiers, list) or not dossiers:
        return "dossiers must be a non-empty array"
    ids = set()
    for d in dossiers:
        if not isinstance(d, dict):
            return "dossier must be an object"
        did = d.get("dossierId")
        if not isinstance(did, str) or not did:
            return "dossierId required"
        if did in ids:
            return "duplicate dossierId"
        ids.add(did)
        sources = d.get("sources")
        if not isinstance(sources, list) or not sources:
            return "sources required"
        line_ids = set()
        for s in sources:
            if not isinstance(s, dict) or not isinstance(s.get("lines"), list):
                return "source lines required"
            for ln in s["lines"]:
                if not isinstance(ln, dict) or not isinstance(ln.get("lineId"), str) \
                        or not isinstance(ln.get("text"), str):
                    return "line must have lineId and text"
                if ln["lineId"] in line_ids:
                    return "duplicate lineId"
                line_ids.add(ln["lineId"])
    return None


def _propose(body: dict) -> JSONResponse:
    eval_id = body.get("evaluationId")
    if not isinstance(eval_id, str) or not eval_id:
        return _bad("evaluationId required", 422)
    dossiers = body.get("dossiers")
    err = _validate_dossiers(dossiers)
    if err:
        return _bad(err, 422)
    allowed = body.get("allowedActions")
    if allowed is not None and (not isinstance(allowed, list) or not set(allowed) <= set(ACTIONS)):
        return _bad("invalid allowedActions", 422)
    verifier = body.get("receiptVerifier")
    if verifier is not None and not _jwk_ok(verifier):
        return _bad("invalid receiptVerifier", 422)

    request_hash = sha256_hex(body)
    input_digest = sha256_hex(dossiers)
    with store.key_lock("q3:" + eval_id):
        prior = store.get(NS_EVAL, eval_id)
        if prior is not None:
            if prior["requestHash"] != request_hash:
                return _bad("evaluation content conflict", 409)
            return _json(prior["proposeResponse"])

        proposals = decide_dossiers(dossiers, NS_CACHE, allowed or ACTIONS)
        resp = {
            "profile": PROFILE,
            "evaluationId": eval_id,
            "status": "awaiting_receipts",
            "inputDigest": input_digest,
            "proposals": proposals,
        }
        store.put(NS_EVAL, eval_id, {
            "requestHash": request_hash,
            "inputDigest": input_digest,
            "verifier": verifier,
            "proposeResponse": resp,
            "commit": None,
        })
        return _json(resp)


# ------------------------------------------------------------------ commit
def proposal_digest(p: dict) -> str:
    view = {
        "dossierId": p["dossierId"],
        "callId": p["callId"],
        "action": p["action"],
        "target": p.get("target"),
        "payload": p.get("payload"),
        "evidence": sorted(p.get("evidence") or []),
    }
    return sha256_hex(view)


def _jwk_ok(v: Any) -> bool:
    try:
        jwk = v["publicKeyJwk"]
        return v.get("algorithm") == "Ed25519" and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519" \
            and len(_b64url(jwk["x"])) == 32
    except Exception:
        return False


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64any(s: str) -> bytes:
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s + pad, validate=True)
    except Exception:
        return base64.urlsafe_b64decode(s + pad)


def _verify(verifier: dict, eval_id: str, input_digest: str, receipt: dict) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    sig = receipt.get("receiptSignature")
    if not isinstance(sig, str) or not sig:
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(_b64url(verifier["publicKeyJwk"]["x"]))
        inner = {k: v for k, v in receipt.items() if k != "receiptSignature"}
        msg = canonical_bytes({"profile": PROFILE, "evaluationId": eval_id,
                               "inputDigest": input_digest, "receipt": inner})
        key.verify(_b64any(sig), msg)
        return True
    except (InvalidSignature, Exception):
        return False


def _commit(body: dict) -> JSONResponse:
    eval_id = body.get("evaluationId")
    receipts = body.get("receipts")
    if not isinstance(eval_id, str) or not eval_id:
        return _bad("evaluationId required", 422)
    if not isinstance(receipts, list) or not all(isinstance(r, dict) for r in receipts):
        return _bad("receipts must be an array of objects", 422)

    with store.key_lock("q3:" + eval_id):
        rec = store.get(NS_EVAL, eval_id)
        if rec is None:
            return _bad("unknown evaluation", 409)
        commit_hash = sha256_hex(body)
        if rec.get("commit") is not None:
            if rec["commit"]["hash"] != commit_hash:
                return _bad("commit content conflict", 409)
            return _json(rec["commit"]["response"])
        if body.get("inputDigest") != rec["inputDigest"]:
            return _bad("inputDigest mismatch", 409)

        proposals = {p["callId"]: p for p in rec["proposeResponse"]["proposals"]}
        verifier = rec.get("verifier")
        if not verifier:
            return _bad("no receipt verifier stored for evaluation", 409)

        seen_calls, seen_rids, seen_sigs = set(), set(), set()
        outcomes = []
        for r in receipts:
            call_id = r.get("callId")
            p = proposals.get(call_id)
            if p is None or call_id in seen_calls:
                return _bad("receipt does not match a pending proposal", 409)
            if r.get("dossierId") != p["dossierId"] or r.get("action") != p["action"]:
                return _bad("receipt does not match proposal", 409)
            if r.get("proposalDigest") != proposal_digest(p):
                return _bad("proposal digest mismatch", 409)
            if not isinstance(r.get("accepted"), bool) or not isinstance(r.get("receiptId"), str) \
                    or not r["receiptId"]:
                return _bad("malformed receipt", 422)
            sig = r.get("receiptSignature")
            if r["receiptId"] in seen_rids or sig in seen_sigs:
                return _bad("duplicated receipt", 409)
            if not _verify(verifier, eval_id, rec["inputDigest"], r):
                return _bad("invalid receipt signature", 409)
            seen_calls.add(call_id)
            seen_rids.add(r["receiptId"])
            seen_sigs.add(sig)
            outcomes.append({
                "dossierId": p["dossierId"],
                "callId": call_id,
                "action": p["action"],
                "proposalDigest": r["proposalDigest"],
                "receiptId": r["receiptId"],
                "status": "executed" if r["accepted"] is True else "rejected",
            })
        if len(seen_calls) != len(proposals):
            return _bad("missing receipts for some proposals", 409)

        resp = {
            "profile": PROFILE,
            "evaluationId": eval_id,
            "status": "completed",
            "inputDigest": rec["inputDigest"],
            "outcomes": outcomes,
        }
        rec["commit"] = {"hash": commit_hash, "receipts": receipts, "response": resp}
        store.put(NS_EVAL, eval_id, rec)
        return _json(resp)
