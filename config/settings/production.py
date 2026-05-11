"""Production settings — hardened, HTTPS-only."""
import os
from .base import *  # noqa: F401, F403

DEBUG = False
ALLOWED_HOSTS = os.environ["ALLOWED_HOSTS"].split(",")

# ── HTTPS & cookies ───────────────────────────────────────────────────────────
SECURE_HSTS_SECONDS            = 31_536_000   # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD            = True
SECURE_SSL_REDIRECT            = True
SESSION_COOKIE_SECURE          = True
CSRF_COOKIE_SECURE             = True
CSRF_COOKIE_HTTPONLY           = True
CSRF_TRUSTED_ORIGINS           = os.environ["CSRF_TRUSTED_ORIGINS"].split(",")
SECURE_PROXY_SSL_HEADER        = ("HTTP_X_FORWARDED_PROTO", "https")

# ── Static & media ────────────────────────────────────────────────────────────
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"  # noqa: F811

# ── Email (real SMTP) ─────────────────────────────────────────────────────────
EMAIL_BACKEND       = "django.core.mail.backends.smtp.EmailBackend"  # noqa: F811
ACCOUNT_EMAIL_VERIFICATION = "mandatory"  # noqa: F811

# ── Logging: JSON in production ───────────────────────────────────────────────
for _logger in LOGGING["loggers"].values():  # noqa: F821
    _logger["handlers"] = [h for h in _logger["handlers"] if h != "console"]

LOGGING["handlers"]["json_console"] = {  # noqa: F821
    "class": "logging.StreamHandler",
    "formatter": "json",
}
LOGGING["loggers"]["django"] = {  # noqa: F821
    "handlers": ["json_console"],
    "level": "ERROR",
    "propagate": False,
}

# ── CORS (restrict to own domain) ────────────────────────────────────────────
CORS_ALLOWED_ORIGINS = os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",")
CORS_ALLOW_CREDENTIALS = False
