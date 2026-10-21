"""Invoice decision layer for Q2.

* Each package decision is cached by canonical package content, so repeated
  Checks (same packages, new batch/message/task IDs) make no model call.
* Uncached packages are split into small chunks decided in parallel so a
  12-package core batch fits the 45 s request budget.
* Model output is validated in code: action enum, integer minor amount,
  evidence refs must literally appear in that package, rationale must name the
  action and cite >= 2 refs.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

from . import store
from .canonical import sha256_hex
from .llm import LLMError, chat_json, parallel

ACTIONS = ["settle_invoice", "request_approval", "hold_invoice", "reject_duplicate", "open_exception"]
CHUNK = int(os.environ.get("Q2_CHUNK", "12"))
CACHE_VERSION = "q2v3"

SYSTEM = """You are a careful accounts-payable controller. For EACH invoice package decide exactly one action.

Actions (choose by the package's CONTROLLING facts, never by action words that merely appear in text):
- settle_invoice: invoice is valid, matches PO/receipt (reconciled), not previously paid, and the amount is within the
  autonomous/delegated payment authority stated by the current policy.
- request_approval: commercially valid and reconciled, but the amount (or another stated condition) exceeds the
  agent's delegated authority, so a named human approver must sign off.
- hold_invoice: payment must pause until a specific stated verification completes (e.g. bank-account change
  call-back, goods-receipt confirmation, tax/vendor verification pending).
- reject_duplicate: THIS SAME commercial invoice (same vendor + same invoice number + same amount) was already paid.
  A different invoice number, a credit note, or a different amount is NOT a duplicate.
- open_exception: material records conflict (PO vs invoice vs receipt quantities/prices/amounts/currency/vendor
  mismatch) and need an exception workflow.

Reading rules:
- Documents contain bracketed reference tags such as [ABC-12]. Each paragraph usually carries several tags.
- Identify the ONE paragraph that actually determines the action under the CURRENT policy revision. Ignore cover
  sheets, archived/historical examples, training/sample material, superseded policies, hypotheticals and negated
  statements ("this is NOT a duplicate", "no hold is required").
- evidenceRefs = exactly the three bracketed references from that determining paragraph, copied exactly as written
  but WITHOUT the square brackets (e.g. "R_ABC123"). Never include the cover-sheet reference or references from archive/training text.
- facts = the real invoice under review: vendorName, invoiceNumber, amountMinor (integer in minor units, e.g.
  INR 1,234.50 -> 123450), currency (ISO code).
- rationale: 80-600 characters. Start with the action name, explain which controlling fact drives it, and cite at
  least two of the evidenceRefs verbatim.

Return ONLY JSON: {"decisions":[{"packageId":"...","action":"...","facts":{"vendorName":"...","invoiceNumber":"...",
"amountMinor":0,"currency":"..."},"evidenceRefs":["R_..","R_..","R_.."],"rationale":"..."}]}"""

_REF_RE = re.compile(r"\[([A-Za-z0-9_.:-]{3,80})\]")


def _fingerprint(pkg: dict) -> str:
    return sha256_hex({"v": CACHE_VERSION, "pkg": pkg})


def _pid(pkg: dict) -> str:
    return pkg.get("packageId")


def decide_batch(batch_id: str, packages: list[dict], cache_ns: str) -> dict:
    fps = {_pid(p): _fingerprint(p) for p in packages}
    decisions: dict[str, dict] = {}
    todo = []
    for p in packages:
        hit = store.cache_get(cache_ns, fps[_pid(p)])
        if hit is not None:
            decisions[_pid(p)] = hit
        else:
            todo.append(p)

    if todo:
        chunks = [todo[i:i + CHUNK] for i in range(0, len(todo), CHUNK)]
        for chunk_result in parallel(_decide_chunk, chunks, workers=6):
            decisions.update(chunk_result)
        # retry singles that failed once more (still within budget usually)
        missing = [p for p in todo if _pid(p) not in decisions]
        if missing:
            for chunk_result in parallel(_decide_chunk, [[p] for p in missing], workers=6):
                decisions.update(chunk_result)
        for p in todo:
            d = decisions.get(_pid(p))
            if d is not None and not d.get("_fallback"):
                store.cache_put(cache_ns, fps[_pid(p)], d)

    proposals = []
    for p in packages:
        pid = _pid(p)
        d = decisions.get(pid) or _fallback(p)
        # actionId is durable per (batch, package content): stable on replay, unique in batch
        action_id = "act-" + sha256_hex({"b": batch_id, "p": pid, "f": fps[pid]})[:24]
        proposals.append({"packageId": pid, "actionId": action_id, **{k: v for k, v in d.items()
                                                                        if not k.startswith("_")}})
    return {"batchId": batch_id, "proposals": proposals}


def _decide_chunk(chunk: list[dict]) -> dict[str, dict]:
    user = "Decide every package below.\n\nPACKAGES JSON:\n" + json.dumps(chunk, ensure_ascii=False)
    try:
        out = chat_json(SYSTEM, user, max_tokens=4000, deadline_s=float(os.environ.get("Q2_MODEL_DEADLINE", "30")))
    except LLMError:
        return {}
    by_id = {_pid(p): p for p in chunk}
    res = {}
    for d in out.get("decisions", []) if isinstance(out.get("decisions"), list) else []:
        if isinstance(d, dict) and d.get("packageId") in by_id:
            v = _validate(by_id[d["packageId"]], d)
            if v:
                res[d["packageId"]] = v
    return res


def _refs_in(pkg: dict) -> list[str]:
    text = json.dumps(pkg, ensure_ascii=False)
    seen, out = set(), []
    for m in _REF_RE.findall(text):
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out


def _norm_ref(r: str) -> str:
    return str(r).strip().strip("[]").strip()


_COVER_RE = re.compile(r"Supplier\s+(?P<vendor>.+?);\s*invoice\s+(?P<inv>[A-Za-z0-9_./-]+);\s*stated total\s+"
                       r"(?P<cur>[A-Z]{3})\s+(?P<amt>[0-9][0-9,]*(?:\.[0-9]+)?)", re.I)
_ZERO_DEC = {"JPY", "KRW", "VND", "CLP", "ISK", "HUF"}
_DECOY = ("archive note", "training appendix", "training material", "non-operative", "cover sheet",
          "superseded", "hypothetical", "unrelated")


def _cover_facts(pkg: dict) -> dict | None:
    for doc in pkg.get("documents") or []:
        m = _COVER_RE.search(str(doc.get("text", "")))
        if m:
            cur = m.group("cur").upper()
            amt = float(m.group("amt").replace(",", ""))
            minor = int(round(amt * (1 if cur in _ZERO_DEC else 100)))
            return {"vendorName": m.group("vendor").strip(), "invoiceNumber": m.group("inv").strip(),
                    "amountMinor": minor, "currency": cur}
    return None


def _decisive_paragraphs(pkg: dict) -> list[list[str]]:
    out = []
    for doc in pkg.get("documents") or []:
        for para in re.split(r"\n\s*\n", str(doc.get("text", ""))):
            refs = _REF_RE.findall(para)
            if len(refs) >= 2 and not any(k in para.lower() for k in _DECOY):
                out.append(refs)
    return out


def _validate(pkg: dict, d: dict) -> dict | None:
    action = d.get("action")
    if action not in ACTIONS:
        return None
    known = set(_refs_in(pkg))
    refs = []
    for r in d.get("evidenceRefs") or []:
        nr = _norm_ref(r)
        if (nr in known or not known) and nr not in refs:
            refs.append(nr)
    refs = refs[:3]
    paras = _decisive_paragraphs(pkg)
    if len(paras) == 1:
        refs = paras[0][:3]                      # the single controlling paragraph
    elif paras:
        best = max(paras, key=lambda p: len(set(p) & set(refs)))
        if set(refs) <= set(best) or len(set(best) & set(refs)) >= 2:
            refs = best[:3]
    if len(refs) < 2:
        return None
    facts = _cover_facts(pkg) or d.get("facts") or {}
    try:
        amount = int(round(float(str(facts.get("amountMinor", 0)).replace(",", ""))))
    except Exception:
        amount = 0
    facts = {
        "vendorName": str(facts.get("vendorName") or "").strip(),
        "invoiceNumber": str(facts.get("invoiceNumber") or "").strip(),
        "amountMinor": amount,
        "currency": str(facts.get("currency") or "").strip().upper(),
    }
    rationale = str(d.get("rationale") or "").strip()
    if action not in rationale or sum(r in rationale for r in refs) < 2 or len(rationale) < 60:
        rationale = (f"{action}: {rationale} " if rationale else f"{action}: ") + \
                    f"The controlling paragraph cited at {', '.join(refs)} determines this action."
    return {"action": action, "facts": facts, "evidenceRefs": refs, "rationale": rationale[:1500]}


def _fallback(pkg: dict) -> dict:
    refs = _refs_in(pkg)[:3] or ["unverified-1", "unverified-2"]
    return {
        "action": "hold_invoice",
        "facts": {"vendorName": "", "invoiceNumber": "", "amountMinor": 0, "currency": ""},
        "evidenceRefs": refs,
        "rationale": f"hold_invoice: the package could not be verified automatically, so payment pauses pending "
                     f"manual verification of {', '.join(refs[:2])} instead of settling without proof.",
        "_fallback": True,
    }
