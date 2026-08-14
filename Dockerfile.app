# AICyberAuditBox application image.
#
# Kept as a separate file (Dockerfile.app) from the existing Dockerfile at the
# repo root, which only builds the ShaktiDB Postgres image -- that one is
# untouched. This one packages the FastAPI app + static frontend + the LLM
# model weights, so `docker-compose up` is genuinely one command with nothing
# to install separately: pip dependencies are installed at build time here,
# and the model file is baked directly into the image (already present
# locally in this repo, no download step needed).
#
# Deliberately does NOT touch src/ -- this only packages the existing,
# unmodified application code.

FROM python:3.11-slim AS builder

# System build dependencies for packages with native extensions
# (psycopg2-binary ships wheels so no libpq-dev needed; easyocr/opencv and
# sentence-transformers pull in a fair amount at pip-install time).
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .

# CPU-only torch installed FIRST, deliberately, before requirements.txt.
# sentence-transformers depends on torch but doesn't pin a CPU/GPU variant,
# so a plain `pip install -r requirements.txt` resolves the default (CUDA)
# build and pulls several GB of unused NVIDIA libraries -- this app never
# runs torch on a GPU (llama-server handles all LLM compute separately over
# HTTP). Installing the CPU wheel first satisfies that dependency before pip
# ever considers the CUDA variant.
RUN pip install --no-cache-dir --user torch torchvision --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir --user -r requirements.txt psycopg2-binary



FROM python:3.11-slim AS runtime

# Runtime system libraries needed by easyocr's OpenCV dependency and by
# libraries that render/parse office documents and images.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user -- standard container hardening, no reason to run as root here.
RUN useradd --create-home --uid 1000 appuser

COPY --from=builder /root/.local /home/appuser/.local
ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Application source -- unmodified, copied as-is.
COPY src/ /app/src/
COPY docker/wait_for_postgres.py /app/docker/wait_for_postgres.py
COPY docker/generate_secrets.sh /app/docker/generate_secrets.sh
RUN chmod +x /app/docker/generate_secrets.sh

# Persisted, volume-backed data (generated secrets, SQLite fallback file if
# ever used, etc.) -- survives container restarts/recreates.
RUN mkdir -p /app/data

# Note: model weights are NOT copied here -- they live in the separate LLM
# container (Dockerfile.llm), which the app talks to over HTTP via
# LLM_HOSTS/EMBEDDING_HOST, exactly like it already talks to llama-server.exe
# natively today.

RUN chown -R appuser:appuser /app
USER appuser

# Pre-download doctr OCR and SentenceTransformer Reranker models during build time
# so they are baked into the image cache for 100% offline air-gapped operation.
RUN python -c "from doctr.models import ocr_predictor; ocr_predictor(pretrained=True); from sentence_transformers import CrossEncoder; CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2'); CrossEncoder('BAAI/bge-reranker-base')"

EXPOSE 8000

# 1. Generate/reuse a persisted JWT_SECRET (docker/generate_secrets.sh).
# 2. Pre-flight blocks startup until Postgres is confirmed reachable (see
#    docker/wait_for_postgres.py for why this exists instead of relying on
#    database.py's own fallback behavior).
# 3. Start the API.
CMD ["sh", "-c", "\
    ./docker/generate_secrets.sh && \
    . /app/data/.generated_env && \
    export JWT_SECRET && \
    python docker/wait_for_postgres.py && \
    python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 \
"]
