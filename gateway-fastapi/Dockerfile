# =============================================================================
# FastAPI Gateway — The AI Brain
# Swagger UI is available at http://localhost:8001/docs (no extra config needed)
# ReDoc is available at http://localhost:8001/redoc
# =============================================================================
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# ── Dependencies ──────────────────────────────────────────────────────────────
# Copy requirements first so Docker caches this layer.
# Re-installs only when requirements.txt changes.
COPY requirements.txt .
RUN pip install -r requirements.txt

# ── Application source ────────────────────────────────────────────────────────
COPY main.py .

# ── Non-root user ─────────────────────────────────────────────────────────────
RUN addgroup --system appgroup \
    && adduser --system --ingroup appgroup appuser
USER appuser

EXPOSE 8001

# Single worker for development/testing — increase for production
CMD ["uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8001", \
     "--workers", "1", \
     "--log-level", "info"]