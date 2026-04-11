# ============================================
# OSINTng - Plataforma OSINT | Dockerfile
# ============================================
FROM python:3.13-slim

# Evitar prompts interactivos
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Dependencias del sistema + herramientas OSINT
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    whois \
    dnsutils \
    nmap \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Directorio de trabajo
WORKDIR /app

# Instalar dependencias Python primero (cache de Docker)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Instalar herramientas OSINT via pip
RUN pip install --no-cache-dir \
    sherlock-project \
    holehe \
    maigret

# Copiar el proyecto
COPY . .

# Recolectar archivos estaticos
RUN python manage.py collectstatic --noinput 2>/dev/null || true

# Puerto
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

# Comando por defecto
CMD ["gunicorn", "mysite.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "120"]
