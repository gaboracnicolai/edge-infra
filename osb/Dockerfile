# Multi-stage build for the self-service broker (FastAPI API + NATS worker).
# Build from the repo root so the osb/ directory is in context.

FROM python:3.12-slim AS deps
WORKDIR /app
COPY osb/pyproject.toml ./
# Editable install needs the listed py-modules to exist, even as stubs, so
# setuptools can build egg-info. Real sources land in the runtime stage.
RUN for m in config models db broker main worker webhook metrics; do \
        : > "$m.py"; \
    done \
 && pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -e ".[dev]" \
 && pip install --no-cache-dir gunicorn


FROM python:3.12-slim
WORKDIR /app
COPY --from=deps /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=deps /usr/local/bin/uvicorn   /usr/local/bin/uvicorn
COPY --from=deps /usr/local/bin/gunicorn  /usr/local/bin/gunicorn
COPY osb/ .
RUN useradd -r -u 1001 appuser
USER appuser
EXPOSE 8080
# Default CMD runs the API server. Override to ["python", "-m", "worker"]
# for the worker Deployment.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
