# ─────────────────────────────────────────────────────────────
# Dockerfile for the LLM Guardrails Gateway
#
# Builds a self-contained image that runs the FastAPI app on
# port 8000. Includes Presidio's spaCy model and the Detoxify
# weights baked in, so the container starts fast on first run.
# ─────────────────────────────────────────────────────────────

FROM python:3.11-slim

# Avoid interactive prompts during apt installs and ensure logs
# stream to stdout immediately (no buffering = better Docker logs)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# System libs needed by some Python packages (libgomp1 for torch,
# build-essential for any wheels that compile from source)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy requirements FIRST and install — this layer caches if
# requirements.txt hasn't changed, so rebuilds are fast
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Download the spaCy model that Presidio needs
RUN python -m spacy download en_core_web_sm

# Pre-download the Detoxify model so the container doesn't
# fetch it on first request (saves ~30 seconds of cold-start)
RUN python -c "from detoxify import Detoxify; Detoxify('original')"

# Now copy the actual application code — this layer rebuilds
# whenever you change a .py file, but the heavy installs above
# stay cached
COPY app/ ./app/
COPY policies/ ./policies/
COPY pyproject.toml .

# Document that the app listens on this port
EXPOSE 8000

# Run uvicorn directly (not python -m app.main) so signals like
# Ctrl+C reach the server cleanly in Docker
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]