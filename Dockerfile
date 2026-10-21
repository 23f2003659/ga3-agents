FROM python:3.12-slim

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY static ./static

ENV DB_PATH=/srv/state.db
ENV GLB_PATH=/srv/static/face.glb
# Agent model config (override at deploy time):
#   MODEL_API_KEY, MODEL_BASE_URL, MODEL_NAME
EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
