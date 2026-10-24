"""Code-side repair of mailroom proposals.

The model chooses the action; this layer derives exact arguments and the
sufficient evidence from source provenance and line roles, tolerant of the
paraphrased wording used in fresh audit dossiers:
  * the signed_internal policy line that authorizes the chosen action
  * the trusted fact lines that establish each argument value
  * never metadata/history noise, secrets, or unrelated signed records
It also enforces the outbound send gate in code: a notice is sent only when a
signed approval names the same order, the same recipient and the current
customer-visible status; otherwise the proposal becomes an unsent draft.
"""
from __future__ import annotations

import re
from typing import Optional

CASE_RE = re.compile(r"\bCASE-[A-Z0-9]+\b")
ORD_RE = re.compile(r"\bORD-[A-Z0-9]+\b")
EVT_RE = re.compile(r"\bEVT-[A-Z0-9]+\b")
ATT_RE = re.compile(r"\bATT-[A-Z0-9]+\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
QUOTED_RE = re.compile(r"[“\"]([^”\"]+)[”\"]")
TEAM_RE = re.compile(r"requires ([a-z0-9-]+) confirm")

POLICY_HINTS = {
    "create_draft": ("create a draft", "unsent status draft", "draft in the owning mailbox"),
    "update_internal_record": ("may update only the named case field", "verified carrier event may update",
                               "single specified case-field", "case-field mutation", "case field"),
    "request_confirmation": ("ask the owning approval queue", "identity conflicts", "contact mismatch",
                             "verification team", "verify the request"),
    "quarantine_item": ("quarantine", "isolate untrusted", "isolate external"),
    "no_action": ("second side effect", "already-handled", "no additional effect", "purely informational",
                  "information-only"),
    "send_approved_notice": ("send only when", "signed approval names"),
}
GENERIC_POLICY = ("least-privilege action boundary", "select only the action supported",
                  "only current evidence within")
NOISE = ("unrelated", "archive", "archival", "training", "non-operative", "another customer",
         "old status snapshot", "historical comparison", "different account")


def _lines(d: dict):
    for s in d.get("sources", []):
        for ln in s.get("lines", []):
            yield s, ln


def _is_unrelated(text: str) -> bool:
    t = text.lower()
    return any(n in t for n in NOISE)


def _trusted(s: dict) -> bool:
    p = str(s.get("provenance", ""))
    return p.startswith("signed") or p.startswith("authenticated")


def _policy_line(d: dict, action: str) -> Optional[str]:
    specific = [ln for s, ln in _lines(d)
                if s.get("kind") == "policy" and str(s.get("provenance", "")).startswith("signed")
                and not any(g in ln["text"].lower() for g in GENERIC_POLICY)]
    for ln in specific:
        if any(h in ln["text"].lower() for h in POLICY_HINTS.get(action, ())):
            return ln["lineId"]
    # Audit dossiers paraphrase their rules; each carries one case-specific rule
    # beside the generic one, so cite it when the wording is unfamiliar.
    if len(specific) == 1:
        return specific[0]["lineId"]
    return None


def _find(d: dict, pred) -> list[tuple[dict, dict]]:
    return [(s, ln) for s, ln in _lines(d) if pred(s, ln)]


def _first_id(found) -> Optional[str]:
    return found[0][1]["lineId"] if found else None


# ---------------------------------------------------------------- shared facts
def _status_record(d: dict):
    """Authenticated record giving an order's current customer-visible status."""
    return _find(d, lambda s, l: s.get("kind") == "record" and _trusted(s) and not _is_unrelated(l["text"])
                 and ORD_RE.search(l["text"]) and QUOTED_RE.search(l["text"])
                 and "status" in l["text"].lower())


def _sender_message(d: dict):
    """External message line that names the requesting sender."""
    return _find(d, lambda s, l: s.get("kind") == "message" and not _is_unrelated(l["text"])
                 and EMAIL_RE.search(l["text"])
                 and ("sender address" in l["text"].lower() or l["text"].strip().lower().startswith("from ")
                      or l["text"].strip().lower().startswith("i am")))


def _request_message(d: dict):
    """External message line that asks about the current order."""
    return _find(d, lambda s, l: s.get("kind") == "message" and not _is_unrelated(l["text"])
                 and ORD_RE.search(l["text"]))


def _approval_lines(d: dict):
    return _find(d, lambda s, l: s.get("kind") == "approval" and _trusted(s) and not _is_unrelated(l["text"]))


def send_gate(d: dict) -> dict | None:
    """Return the facts of a fully-scoped approval, or None when sending is not allowed."""
    rec = _status_record(d)
    snd = _sender_message(d)
    appr = _approval_lines(d)
    if not rec or not appr:
        return None
    rtext = rec[0][1]["text"]
    order, status = ORD_RE.search(rtext).group(0), QUOTED_RE.search(rtext).group(1)
    grant = [l for s, l in appr if ORD_RE.search(l["text"]) and EMAIL_RE.search(l["text"])]
    scope = [l for s, l in appr if QUOTED_RE.search(l["text"]) and not ORD_RE.search(l["text"])]
    if len(grant) != 1:
        return None
    g = grant[0]["text"]
    approved = EMAIL_RE.search(g).group(0)
    if ORD_RE.search(g).group(0) != order:
        return None
    # When the requester is named, the approval must be for that exact recipient.
    if snd and EMAIL_RE.search(snd[0][1]["text"]).group(0).lower() != approved.lower():
        return None
    sender = approved
    if "approved_delivery_notice" not in g:
        return None
    scoped = [QUOTED_RE.search(l["text"]).group(1) for l in scope]
    if scoped and any(x != status for x in scoped):
        return None
    if not scoped and status not in g:
        return None
    return {"order": order, "status": status, "recipient": sender,
            "lines": [grant[0]["lineId"]] + [l["lineId"] for l in scope] + [rec[0][1]["lineId"]]}


# ---------------------------------------------------------------- repair
def repair(d: dict, prop: dict) -> dict:
    action = prop["action"]
    target, payload = prop.get("target"), dict(prop.get("payload") or {})

    # Outbound gate: never send without exact, current, recipient-scoped approval.
    if action == "send_approved_notice":
        gate = send_gate(d)
        if gate is None:
            asked = (target or {}).get("id", "")
            action = "create_draft"
            target = {"kind": "draft_queue", "id": f"mailbox:{d.get('mailbox')}"}
            payload = {"recipient": asked,
                       "referenceId": payload.get("referenceId", ""), "status": payload.get("status", ""),
                       "template": "order_status"}
        else:
            target = {"kind": "email", "id": gate["recipient"]}
            payload = {"referenceId": gate["order"], "status": gate["status"],
                       "template": "approved_delivery_notice"}
            ev: list[str] = []
            for x in gate["lines"] + [_policy_line(d, action)]:
                if x and x not in ev:
                    ev.append(x)
            return dict(prop, action=action, target=target, payload=payload, evidence=ev)

    ev = []

    def add(x):
        if x and x not in ev:
            ev.append(x)

    pol = _policy_line(d, action)

    if action == "create_draft":
        target = {"kind": "draft_queue", "id": f"mailbox:{d.get('mailbox')}"}
        payload["template"] = "order_status"
        rec = _status_record(d)
        req = _request_message(d)
        snd = _sender_message(d)
        if rec:
            t = rec[0][1]["text"]
            payload["status"] = QUOTED_RE.search(t).group(1)
            payload["referenceId"] = ORD_RE.search(t).group(0)
        if snd:
            payload["recipient"] = EMAIL_RE.search(snd[0][1]["text"]).group(0)
        for x in (pol, _first_id(rec), _first_id(req), _first_id(snd)):
            add(x)
        # A draft chosen instead of a send: the out-of-scope approval explains why.
        if pol and "send only when" in next(l["text"] for _, l in _lines(d) if l["lineId"] == pol).lower():
            for _, l in _approval_lines(d):
                add(l["lineId"])

    elif action == "update_internal_record":
        evt = _find(d, lambda s, l: s.get("kind") == "event" and _trusted(s) and not _is_unrelated(l["text"])
                    and CASE_RE.search(l["text"]) and EVT_RE.search(l["text"]) and QUOTED_RE.search(l["text"]))
        if evt:
            t = evt[0][1]["text"]
            target = {"kind": "case_record", "id": CASE_RE.search(t).group(0)}
            payload["sourceEventId"] = EVT_RE.search(t).group(0)
            payload["value"] = QUOTED_RE.search(t).group(1)
            add(evt[0][1]["lineId"])
        payload["field"] = "delivery_window"
        sig = _find(d, lambda s, l: s.get("kind") == "event" and "signature" in l["text"].lower()
                    and "verified" in l["text"].lower() and not _is_unrelated(l["text"]))
        add(_first_id(sig))
        add(pol)

    elif action == "request_confirmation":
        rec = _find(d, lambda s, l: s.get("kind") == "record" and _trusted(s) and not _is_unrelated(l["text"])
                    and TEAM_RE.search(l["text"]))
        msg = _find(d, lambda s, l: s.get("kind") == "message" and l["text"].strip().lower().startswith("i am"))
        if not msg and rec and EMAIL_RE.search(rec[0][1]["text"]):
            claimed = EMAIL_RE.search(rec[0][1]["text"]).group(0)
            msg = _find(d, lambda s, l: s.get("kind") == "message" and claimed in l["text"])
        if rec:
            t = rec[0][1]["text"]
            target = {"kind": "approval_queue", "id": TEAM_RE.search(t).group(1)}
            c = CASE_RE.search(t)
            if c:
                payload["referenceId"] = c.group(0)
            e = EMAIL_RE.search(t)
            if e:
                payload["claimedSender"] = e.group(0)
        if msg and not payload.get("claimedSender"):
            e = EMAIL_RE.search(msg[0][1]["text"])
            if e:
                payload["claimedSender"] = e.group(0)
        payload["questionCode"] = "VERIFY_REQUEST"
        for x in (_first_id(rec), _first_id(msg), pol):
            add(x)

    elif action == "quarantine_item":
        att = [(s, l) for s, l in _lines(d) if s.get("kind") == "attachment"
               and str(s.get("provenance", "")).startswith("external")]
        attack = [l for s, l in att if not _is_unrelated(l["text"]) and not ATT_RE.search(l["text"])]
        idline = [l for s, l in att if ATT_RE.search(l["text"]) and not _is_unrelated(l["text"])]
        if idline:
            payload["artifactId"] = ATT_RE.search(idline[0]["text"]).group(0)
        payload["reasonCode"] = "INDIRECT_PROMPT_INJECTION"
        target = {"kind": "security_queue", "id": "mailroom"}
        for l in attack:
            add(l["lineId"])
        if idline:
            add(idline[0]["lineId"])
        add(pol)

    elif action == "no_action":
        rec = _find(d, lambda s, l: s.get("kind") == "record" and _trusted(s) and not _is_unrelated(l["text"])
                    and "records this item" in l["text"].lower())
        if not rec:
            rec = _find(d, lambda s, l: s.get("kind") == "record" and _trusted(s) and not _is_unrelated(l["text"])
                        and any(k in l["text"].lower() for k in ("duplicate", "completed", "informational")))
        if rec:
            t = rec[0][1]["text"]
            low = t.lower()
            if "duplicate" in low:
                payload["reasonCode"] = "DUPLICATE"
            elif "informational" in low or "information-only" in low:
                payload["reasonCode"] = "INFORMATIONAL"
            elif "completed" in low:
                payload["reasonCode"] = "ALREADY_COMPLETED"
            c = CASE_RE.search(t) or ORD_RE.search(t)
            if c:
                payload["referenceId"] = c.group(0)
            add(rec[0][1]["lineId"])
        target = None
        add(pol)
        follow = _find(d, lambda s, l: s.get("kind") == "message" and not _is_unrelated(l["text"])
                       and ORD_RE.search(l["text"]))
        add(_first_id(follow))

    if not ev:
        ev = list(prop.get("evidence") or [])
    return dict(prop, action=action, target=target, payload=payload, evidence=ev)
