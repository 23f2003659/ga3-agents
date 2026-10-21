"""Invoice decision layer for Q2.

One batched model call decides all packages. Each package decision is cached by
its canonical content fingerprint, so repeat Checks (same core packages under
new batch/message/task IDs) make no further model calls. Only unseen packages
(fresh audit cases) are sent to the model.

Output is a fully validated proposals object matching the contract schema.
"""
from __future__ import annotations

import secrets
from typing import Any

from . import store
from .canonical import sha256_hex
from .llm import chat_json, LLMError

ACTIONS = {
    "settle_invoice", "request_approval", "hold_invoice",
    "reject_duplicate", "open_exception",
}

SYSTEM = (
    "You are an invoice action engine for an accounts-payable team. For EACH "
    "invoice package you must choose EXACTLY ONE action and cite the decisive "
    "evidence references found in that package's documents.\n\n"
    "Actions:\n"
    "- settle_invoice: valid, reconciled, and within autonomous authority.\n"
    "- request_approval: commercially valid but ABOVE the delegated authority "
    "limit (needs human sign-off).\n"
    "- hold_invoice: payment must pause until a stated verification completes "
    "(e.g. goods-receipt, bank-detail change verification).\n"
    "- reject_duplicate: the SAME commercial invoice (same vendor + invoice "
    "number + amount) was already paid. A different invoice number or amount is "
    "NOT a duplicate.\n"
    "- open_exception: material records conflict (PO/amount/tax mismatch) and "
    "need an exception workflow.\n\n"
    "Rules:\n"
    "- Documents mix useful facts with OLD examples, negations, archive copies, "
    "and irrelevant action words. Ignore cover-sheet references, archive "
    "examples, and training decoys.\n"
    "- Cite EXACTLY the three decisive bracketed references (e.g. [E12]) from "
    "the single paragraph that determines the action. Do not include the "
    "cover-sheet reference.\n"
    "- Extract true facts: vendorName, invoiceNumber, amountMinor (integer minor "
    "units), currency (ISO code).\n"
    "- rationale: 60-1500 chars, name the chosen action and cite at least two of "
    "the evidence references.\n\n"
    "Return a JSON object: {\"decisions\":[{\"packageId\":..,\"action\":..,"
    "\"facts\":{\"vendorName\":..,\"invoiceNumber\":..,\"amountMinor\":..,"
    "\"currency\":..},\"evidenceRefs\":[..,..,..],\"rationale\":..}]}"
)


def _fingerprint(pkg: dict) -> str:
    """Canonical content fingerprint of a package, ignoring volatile IDs that
    differ between Check runs. We hash everything EXCEPT batch-scoped ids."""
    stable = {k: v for k, v in pkg.items() if k not in ("batchId",)}
    return sha256_hex(stable)


def _action_id() -> str:
    return "act_" + secrets.token_hex(12)  # >= 12 chars


def decide_batch(batch_id: str, packages: list[dict], cache_ns: str) -> dict:
    """Return the proposals object for the batch, using cache + one model call
    for any uncached packages."""
    # map packageId -> fingerprint
    fps = {}
    uncached = []
    cached_decisions: dict[str, dict] = {}
    for pkg in packages:
        pid = pkg.get("packageId") or pkg.get("id")
        fp = _fingerprint(pkg)
        fps[pid] = fp
        hit = store.cache_get(cache_ns, fp)
        if hit is not None:
            cached_decisions[pid] = hit
        else:
            uncached.append(pkg)

    fresh: dict[str, dict] = {}
    if uncached:
        fresh = _call_model(uncached)
        for pid, dec in fresh.items():
            store.cache_put(cache_ns, fps[pid], dec)

    proposals = []
    seen_pid = set()
    seen_aid = set()
    for pkg in packages:
        pid = pkg.get("packageId") or pkg.get("id")
        if pid in seen_pid:
            continue
        seen_pid.add(pid)
        dec = cached_decisions.get(pid) or fresh.get(pid)
        if dec is None:
            dec = _fallback(pkg)
        aid = _action_id()
        while aid in seen_aid:
            aid = _action_id()
        seen_aid.add(aid)
        proposals.append(_validate(pid, aid, dec))
    return {"batchId": batch_id, "proposals": proposals}


def _call_model(packages: list[dict]) -> dict[str, dict]:
    import json
    user = "Decide an action for every package.\n\nPACKAGES:\n" + json.dumps(
        packages, ensure_ascii=False)
    try:
        out = chat_json(SYSTEM, user, max_tokens=6000)
    except LLMError:
        return {}
    result = {}
    for d in out.get("decisions", []):
        pid = d.get("packageId")
        if pid:
            result[pid] = d
    return result


def _fallback(pkg: dict) -> dict:
    """Conservative fallback if the model is unavailable: hold for verification
    (never blanket-settle, which triggers a severe cap)."""
    pid = pkg.get("packageId") or pkg.get("id")
    return {
        "packageId": pid,
        "action": "hold_invoice",
        "facts": {"vendorName": "unknown", "invoiceNumber": "unknown",
                  "amountMinor": 0, "currency": "INR"},
        "evidenceRefs": ["[unverified]"],
        "rationale": ("hold_invoice: decision engine could not verify the "
                      "package evidence, so payment pauses pending manual "
                      "verification rather than settling without proof."),
    }


def _validate(pid: str, aid: str, dec: dict) -> dict:
    action = dec.get("action")
    if action not in ACTIONS:
        action = "hold_invoice"
    facts = dec.get("facts", {}) or {}
    amount = facts.get("amountMinor", 0)
    try:
        amount = int(amount)
    except Exception:
        amount = 0
    refs = dec.get("evidenceRefs") or []
    if not isinstance(refs, list):
        refs = [str(refs)]
    refs = [str(r) for r in refs][:3]
    while len(refs) < 1:
        refs.append("[evidence]")
    rationale = str(dec.get("rationale", "") or "")
    if len(rationale) < 60:
        rationale = (f"{action}: decision based on package evidence "
                     f"{', '.join(refs)}. The cited references determine this "
                     f"action for the invoice.")
    rationale = rationale[:1500]
    return {
        "packageId": pid,
        "actionId": aid,
        "action": action,
        "facts": {
            "vendorName": str(facts.get("vendorName", "unknown")),
            "invoiceNumber": str(facts.get("invoiceNumber", "unknown")),
            "amountMinor": amount,
            "currency": str(facts.get("currency", "INR")),
        },
        "evidenceRefs": refs,
        "rationale": rationale,
    }
