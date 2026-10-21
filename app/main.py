"""GA3 agents service.

  Q6  GET  /face.glb
  Q2  GET  /.well-known/agent-card.json ; /a2a/message:send ; /a2a/tasks[/{id}[:cancel]]
  Q3  POST /v1/mailroom/actions
  Q4  POST /v2/incidents ; POST /v2/incidents/{runId}/receipts ; GET /v2/incidents/{runId}

Optional debugging: when DEBUG_TOKEN is set, recent agent requests/responses
(minus Authorization headers) are kept in SQLite and readable at
GET /_debug/captures with header `X-Debug-Token: <DEBUG_TOKEN>`.
"""
from __future__ import annotations

import hmac
import os
import time

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response

from . import store
from . import q2_invoice as q2
from . import q3_mailroom as q3
from . import q4_incident as q4

app = FastAPI(title="GA3 Agents", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
                   expose_headers=["*"])

GLB_PATH = os.environ.get("GLB_PATH", "static/face.glb")
DEBUG_TOKEN = os.environ.get("DEBUG_TOKEN", "")
CAPTURE_LIMIT = 2_500_000


def _headers(request: Request) -> dict:
    return {k.lower(): v for k, v in request.headers.items()}


async def _run(request: Request, fn, *args) -> Response:
    raw = await request.body()
    t0 = time.time()
    resp = await run_in_threadpool(fn, *args, raw) if args else await run_in_threadpool(fn, raw)
    _capture(request, raw, resp, t0)
    return resp


def _capture(request: Request, raw: bytes, resp: Response, t0: float) -> None:
    if not DEBUG_TOKEN:
        return
    try:
        hdrs = {k: v for k, v in _headers(request).items() if k not in ("authorization", "cookie")}
        hdrs["authorization-present"] = str("authorization" in _headers(request))
        store.capture_add({
            "method": request.method, "path": request.url.path, "headers": hdrs,
            "body": raw[:CAPTURE_LIMIT].decode("utf-8", "replace"), "bodyBytes": len(raw),
            "status": resp.status_code, "ms": int((time.time() - t0) * 1000),
            "response": bytes(resp.body)[:CAPTURE_LIMIT].decode("utf-8", "replace"),
        })
    except Exception:
        pass


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/_debug/captures")
def debug_captures(request: Request):
    tok = request.headers.get("x-debug-token", "")
    if not DEBUG_TOKEN or not hmac.compare_digest(tok, DEBUG_TOKEN):
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(store.capture_list())


# ---------------------------------------------------------------- Q6
@app.get("/face.glb")
def face_glb():
    if not os.path.exists(GLB_PATH):
        return JSONResponse({"error": "glb not found"}, status_code=404)
    return FileResponse(GLB_PATH, media_type="model/gltf-binary", filename="face.glb")


# ---------------------------------------------------------------- Q2
@app.get("/.well-known/agent-card.json")
def agent_card(request: Request):
    return q2.agent_card(str(request.base_url))


@app.post("/a2a/message:send")
async def a2a_send(request: Request):
    h = _headers(request)
    return await _run(request, lambda raw: q2.message_send(h, raw))


@app.get("/a2a/tasks")
async def a2a_list(request: Request):
    h = _headers(request)
    return await _run(request, lambda raw: q2.list_tasks(h))


@app.get("/a2a/tasks/{task_id}")
async def a2a_get(request: Request, task_id: str):
    h = _headers(request)
    return await _run(request, lambda raw: q2.get_task(h, task_id))


@app.post("/a2a/tasks/{task_id}:cancel")
async def a2a_cancel(request: Request, task_id: str):
    h = _headers(request)
    return await _run(request, lambda raw: q2.cancel_task(h, task_id))


# ---------------------------------------------------------------- Q3
@app.post("/v1/mailroom/actions")
async def mailroom(request: Request):
    return await _run(request, q3.handle)


# ---------------------------------------------------------------- Q4
@app.post("/v2/incidents")
async def incidents_create(request: Request):
    h = _headers(request)
    return await _run(request, lambda raw: q4.create_incident(h, raw))


@app.post("/v2/incidents/{run_id}/receipts")
async def incidents_receipts(request: Request, run_id: str):
    return await _run(request, lambda raw: q4.post_receipts(run_id, raw))


@app.get("/v2/incidents/{run_id}")
async def incidents_get(request: Request, run_id: str):
    return await _run(request, lambda raw: q4.get_incident(run_id))
