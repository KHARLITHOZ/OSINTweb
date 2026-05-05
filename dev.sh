#!/bin/sh
# Servidor de desarrollo local (SQLite + caché en memoria, sin Docker/Redis)
# Uso: ./dev.sh

export DB_ENGINE=django.db.backends.sqlite3
export DB_NAME=dev.sqlite3
export DB_HOST=
export DB_USER=
export DB_PASSWORD=
export REDIS_URL=
export CELERY_BROKER_URL=
export CELERY_RESULT_BACKEND=

venv/bin/python manage.py runserver 0.0.0.0:8000
