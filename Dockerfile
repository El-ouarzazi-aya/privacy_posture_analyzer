FROM python:3.11-slim

# ── System dependencies ───────────────────────────────────────────────────
# gcc         : required by some compiled Python packages
# libxml2-dev : reportlab / lxml support
# curl        : used by healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libxml2-dev \
    curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Python dependencies (cached layer) ───────────────────────────────────
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application code ──────────────────────────────────────────────────────
COPY backend/ ./backend/
COPY Privacy_Posture_Analyzer.html .

# ── Runtime directories ───────────────────────────────────────────────────
RUN mkdir -p /app/backend/uploads

EXPOSE 8000

# ── Entry point ───────────────────────────────────────────────────────────
# Run from backend/ so that relative imports (database, models, modules) work
WORKDIR /app/backend

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
