# ── Build stage — compile Tailwind ────────────────────────────────────────────
FROM node:22-alpine AS frontend-builder

WORKDIR /build
COPY package.json tailwind.config.js ./
COPY static/css/app.css ./static/css/app.css
COPY templates/ ./templates/
COPY static/js/ ./static/js/

RUN npm ci && npm run build

# ── Runtime stage ──────────────────────────────────────────────────────────────
FROM python:3.13-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System deps (minimal — only what's strictly required)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq-dev \
    gcc \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (layer cache)
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy project code
COPY . .

# Copy built Tailwind CSS from frontend stage
COPY --from=frontend-builder /build/static/css/dist/ ./static/css/dist/

# Create directories
RUN mkdir -p /app/logs /app/staticfiles

# Create non-root user
RUN addgroup --system django && adduser --system --ingroup django django && \
    chown -R django:django /app

USER django

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=20s \
    CMD curl -sf http://localhost:8000/health/ || exit 1

CMD ["gunicorn", "config.wsgi:application", "--config", "gunicorn.conf.py"]
