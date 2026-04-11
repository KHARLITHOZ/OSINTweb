# ============================================
# OSINTng - settings_docker.py
# ============================================
# Agrega esto AL FINAL de tu settings.py actual
# o reemplaza las secciones correspondientes

import os

# === SEGURIDAD ===
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', 'fallback-insecure-key-change-me')
DEBUG = os.getenv('DJANGO_DEBUG', 'False') == 'True'
ALLOWED_HOSTS = os.getenv('DJANGO_ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

# === BASE DE DATOS (PostgreSQL via Docker) ===
DATABASES = {
    'default': {
        'ENGINE': os.getenv('DB_ENGINE', 'django.db.backends.postgresql'),
        'NAME': os.getenv('DB_NAME', 'plataforma_osint'),
        'USER': os.getenv('DB_USER', 'osintng'),
        'PASSWORD': os.getenv('DB_PASSWORD', ''),
        'HOST': os.getenv('DB_HOST', 'db'),  # 'db' es el nombre del servicio en docker-compose
        'PORT': os.getenv('DB_PORT', '5432'),
    }
}

# === REDIS + CELERY ===
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': os.getenv('REDIS_URL', 'redis://redis:6379/0'),
    }
}

CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/0')
CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://redis:6379/1')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'

# === ARCHIVOS ESTATICOS ===
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
