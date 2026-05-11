"""Development settings — DEBUG=True, SQLite fallback, no HTTPS."""
import os
from .base import *  # noqa: F401, F403

DEBUG = True
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "0.0.0.0"]

# Override SECRET_KEY requirement in dev
try:
    SECRET_KEY  # noqa: F821
except KeyError:
    SECRET_KEY = "django-insecure-dev-only-CHANGE-IN-PRODUCTION-never-use-this"  # noqa: F811

# SQLite fallback for pure local dev (no Docker)
if not os.getenv("DB_HOST"):
    DATABASES = {  # noqa: F811
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "dev.sqlite3",  # noqa: F821
        }
    }

# Local memory cache when Redis isn't running
if not os.getenv("REDIS_URL"):
    CACHES = {  # noqa: F811
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "osint-dev",
        }
    }

# No AXES lockouts in dev so we don't lock ourselves out
AXES_ENABLED = False  # noqa: F811

# Email to console
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"  # noqa: F811

# Skip email confirmation in dev
ACCOUNT_EMAIL_VERIFICATION = "none"  # noqa: F811

# Looser CSP for dev hot-reload tools
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'", "'unsafe-eval'",  # noqa: F811
                  "https://cdn.jsdelivr.net", "https://unpkg.com", "https://cdnjs.cloudflare.com")

INSTALLED_APPS += ["debug_toolbar"]  # noqa: F821, F401
MIDDLEWARE.insert(2, "debug_toolbar.middleware.DebugToolbarMiddleware")  # noqa: F821
INTERNAL_IPS = ["127.0.0.1"]
