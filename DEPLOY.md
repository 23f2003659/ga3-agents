# GA3 — Deploy & Submit Guide

One service hosts **four** deliverables. Deploy it once, then paste the four
URLs into the exam page. You (the student) handle Q1 (guess) and Q5 (drawing
game) yourself.

```
Q6  GET  /face.glb                        -> 3D face GLB (0.5 marks)
Q2  GET  /.well-known/agent-card.json     -> A2A Invoice Agent  (base: /a2a/)
Q3  POST /v1/mailroom/actions             -> Safe AI Mailroom
Q4  POST /v2/incidents                    -> Incident Triage (base URL)
```

Project folders:
- `~/ga3/q6/`     — GLB build (`face.glb`, 611,724 bytes, validated glTF 2.0)
- `~/ga3/agents/` — the deployable FastAPI service (GLB already copied into `static/`)

---

## 0. What you must supply: a model key

Q2/Q3/Q4 need a live LLM the **deployed** service can call. The code speaks the
OpenAI-compatible Chat Completions API, configured by 3 env vars:

| Provider            | `MODEL_BASE_URL`                                          | `MODEL_NAME` example        | Cost |
|---------------------|----------------------------------------------------------|-----------------------------|------|
| **Groq** (free)     | `https://api.groq.com/openai/v1`                         | `llama-3.1-8b-instant`      | free tier |
| OpenAI              | `https://api.openai.com/v1`                              | `gpt-4o-mini`               | ~1-3¢ |
| Google Gemini       | `https://generativelanguage.googleapis.com/v1beta/openai`| `gemini-2.0-flash`          | free tier |
| Local Ollama        | `http://localhost:11434/v1`                              | `llama3.1`                  | free (not for cloud) |

Recommended for a free cloud deploy: **Groq**. Get a key at console.groq.com and
set `MODEL_API_KEY` to it.

> The provider/model is NOT graded. Marks come from correct decisions, receipts,
> state, and protocol behavior. A small cheap model is enough.

---

## Option A — Render.com (free, recommended; public HTTPS + CORS out of the box)

1. Put `~/ga3/agents/` in a GitHub repo (include `app/`, `static/face.glb`,
   `Dockerfile`, `requirements.txt`, `render.yaml`).
   ```bash
   cd ~/ga3/agents
   git init && git add -A && git commit -m "GA3 agents"
   git branch -M main
   git remote add origin https://github.com/<you>/ga3-agents.git
   git push -u origin main
   ```
2. On Render: **New → Blueprint**, pick the repo. It reads `render.yaml`.
3. Set env vars in the dashboard: `MODEL_API_KEY` (your key), confirm
   `MODEL_BASE_URL` / `MODEL_NAME`. Deploy.
4. After it goes live you get a URL like `https://ga3-agents.onrender.com`.
   Set `PUBLIC_BASE_URL` to exactly that (no trailing slash) and **redeploy**
   once so the A2A agent card advertises the correct interface URL.

> Note: Render free instances sleep after idle and cold-start in ~30-60s. Hit
> `/healthz` right before you press Check so the grader doesn't time out on a
> cold start. (Each grader request has a 45/55/18s budget depending on the
> question.)

## Option B — Any Docker host (Fly.io, Railway, a VPS, etc.)

```bash
cd ~/ga3/agents
docker build -t ga3-agents .
docker run -p 8000:8000 \
  -e MODEL_API_KEY=sk-... \
  -e MODEL_BASE_URL=https://api.groq.com/openai/v1 \
  -e MODEL_NAME=llama-3.1-8b-instant \
  -e PUBLIC_BASE_URL=https://your-public-host \
  ga3-agents
```
Put it behind HTTPS (the platform's TLS, or a reverse proxy). The submitted URLs
must be `https://`, with no credentials/query/fragment, and must not redirect.

## Option C — Host ONLY the GLB for Q6 (if you skip the agents)

The GLB is a static file; any static host with CORS works:
- **Cloudflare R2 / Pages**, **GitHub Pages**, or **Netlify drop** — upload
  `~/ga3/q6/face.glb`. Most of these serve `Access-Control-Allow-Origin: *` by
  default. Verify with the check command below.

---

## Fill in the exam answers

| # | Field on page                         | Paste this                                             |
|---|---------------------------------------|--------------------------------------------------------|
| 6 | Public GLB URL                        | `https://YOUR_HOST/face.glb`                           |
| 2 | A2A interface base URL                | `https://YOUR_HOST/a2a/`  (trailing slash, HTTPS)      |
| 3 | Mailroom endpoint URL                 | `https://YOUR_HOST/v1/mailroom/actions`                |
| 4 | Incident-agent base URL               | `https://YOUR_HOST/`  (base; routes are /v2/incidents) |

Q1 (guess a number) and Q5 (drawing game) you do yourself in the browser.

---

## Verify before pressing Check

```bash
H=https://YOUR_HOST

# Q6: valid, <2MB, CORS
curl -sI -H "Origin: https://exam.sanand.workers.dev" $H/face.glb \
  | grep -iE "content-type|content-length|access-control-allow-origin"

# Q2: public card
curl -s $H/.well-known/agent-card.json | python3 -m json.tool | head

# Q2: auth required (expect 401/403)
curl -s -o /dev/null -w "%{http_code}\n" -X POST $H/a2a/message:send \
  -H "A2A-Version: 1.0" -H "Content-Type: application/a2a+json"

# Q4: profile check (expect 400)
curl -s -o /dev/null -w "%{http_code}\n" -X POST $H/v2/incidents \
  -H "Content-Type: application/json" -d '{"profile":"wrong"}'
```

---

## How it satisfies the contracts (quick map)

**Shared:** durable SQLite state (`app/store.py`) written before responding;
canonical key-sorted-JSON hashing (`app/canonical.py`); pluggable LLM with
decision caching so repeat Checks make no model call (`app/llm.py` + per-question
deciders); non-redirecting JSON, size caps (512 KiB Q2/Q3, 768 KiB Q4).

**Q2 A2A Invoice** (`app/q2_invoice.py`): origin-level agent card with
`invoice_action_agent` skill; `A2A-Version: 1.0` + `application/a2a+json`
enforced; Bearer per-principal isolation (outsider → 404, `/tasks` → only owner);
idempotency by `(principal, messageId)` over the message hash → replay returns
same Task, changed content → 409 `IDEMPOTENCY_CONFLICT`; lifecycle
INPUT_REQUIRED → COMPLETED; result continuations validated against stored
proposals (principal/task/context/batch/package/actionId/action); only ACCEPTED
results become executions; cancel/terminal race → 409; terminal tasks immutable.

**Q3 Mailroom** (`app/q3_mailroom.py` + `mailroom_decider.py`): propose/commit
envelopes; stable `callId` from dossier content fingerprint (same across
evaluations/Checks); schema/duplicate-id validation → 400/422 *before* AI work;
same evaluationId + changed content → 409; exact replay → byte-equivalent JSON,
no model work; receipts verified (HMAC when a key is supplied, else nonce
required) before recording; prompt-injection-aware system prompt treats mail as
data and never puts raw mail into tool args.

**Q4 Incident** (`app/q4_incident.py` + `incident_planner.py` + `otlp.py`):
`/v2/incidents` create → one model `chat incident-plan` call choosing a root
cause from `allowedRootCauses` with 2-4 evidence IDs; 1-3 diagnostic dispatches
with per-attempt CLIENT spans and matching `traceparent` span IDs; 503 → exactly
one retry (attempt 2, resend_count 1); timeout → suppress dependent effect;
destructive effects gated behind an approval request (SHA-256 args digest) then
dispatched with the approval nonce; terminal result carries `actionLog`,
`receiptLog`, and a full OTLP trace (SERVER→INTERNAL agent→CLIENT chat / INTERNAL
execute_tool→CLIENT tool / incident.join / approval_gate), every span carrying
`ga5.run.id` + `ga5.public.marker`; the `sensitive` object is never sent to the
model nor exported; replay reads stored state (no model call), changed content →
409, bad profile → 400.

---

## Iterating with the grader

Each agent question allows 10 Checks / 24h (last reserved for Save). The grader
returns short failure codes per layer. Fix, redeploy, re-Check. Common first
things to watch:
- Cold-start timeouts → ping `/healthz` first, or use a paid always-on instance.
- Decision quality depends on the model — if action accuracy is capped, try a
  stronger model (e.g. `gpt-4o-mini`) by changing the 3 env vars; no code change.
```
