"""Main FastAPI app hosting all four GA3 deliverables from one service:

  Q6  GET  /face.glb                              (static, CORS)
  Q2  GET  /.well-known/agent-card.json           (public A2A card)
      POST /a2a/message:send                       (Bearer)
      GET  /a2a/tasks/{id}                          (Bearer)
      GET  /a2a/tasks                               (Bearer)
      POST /a2a/tasks/{id}:cancel                   (Bearer)
  Q3  POST /v1/mailroom/actions                     (propose/commit)
  Q4  POST /v2/incidents
      POST /v2/incidents/{runId}/receipts
      GET  /v2/incidents/{runId}

Deploy one service, submit four URLs (see DEPLOY.md).
"""
from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from .app_imports import q2, q3, q4

app = FastAPI(title="GA3 Agents", docs_url=None, redoc_url=None)

# CORS: allow cross-origin browser requests (required for Q6 GLB and harmless
# for the agent JSON APIs which the grader calls server-side).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

GLB_PATH = os.environ.get("GLB_PATH", "static/face.glb")


@app.get("/healthz")
def healthz():
    return {"ok": True}


# ---- Q6: static GLB ----
@app.get("/face.glb")
def face_glb():
    if not os.path.exists(GLB_PATH):
        return JSONResponse({"error": "glb not found"}, status_code=404)
    return FileResponse(GLB_PATH, media_type="model/gltf-binary",
                        filename="face.glb")


# ---- Q2: A2A Invoice Agent ----
@app.get("/.well-known/agent-card.json")
def agent_card(request: Request):
    return q2.agent_card(request)


@app.post("/a2a/message:send")
async def a2a_send(request: Request):
    body = await _safe_json(request)
    if body is None:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    return q2.message_send(request, body)


@app.get("/a2a/tasks")
def a2a_list(request: Request):
    return q2.list_tasks(request)


@app.get("/a2a/tasks/{task_id}")
def a2a_get(request: Request, task_id: str):
    return q2.get_task(request, task_id)


@app.post("/a2a/tasks/{task_id}:cancel")
def a2a_cancel(request: Request, task_id: str):
    return q2.cancel_task(request, task_id)


# ---- Q3: Mailroom ----
@app.post("/v1/mailroom/actions")
async def mailroom(request: Request):
    return await q3.handle(request)


# ---- Q4: Incident Triage ----
@app.post("/v2/incidents")
async def incidents_create(request: Request):
    return await q4.create_incident(request)


@app.post("/v2/incidents/{run_id}/receipts")
async def incidents_receipts(request: Request, run_id: str):
    return await q4.post_receipts(request, run_id)


@app.get("/v2/incidents/{run_id}")
def incidents_get(run_id: str):
    return q4.get_incident(run_id)


async def _safe_json(request: Request):
    try:
        return await request.json()
    except Exception:
        return None
