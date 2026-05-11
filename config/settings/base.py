"""
Base settings — shared by all environments.
Never import this directly; use development.py or production.py.
"""
from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# ── Secret key (must be set in env for production) ────────────────────────────
SECRET_KEY = os.environ["SECRET_KEY"]

# ── Apps ──────────────────────────────────────────────────────────────────────
DJANGO_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",
]
THIRD_PARTY_APPS = [
    "rest_framework",
    "rest_framework_simplejwt",
    "allauth",
    "allauth.account",
    "allauth.mfa",
    "axes",
    "corsheaders",
]
LOCAL_APPS = [
    "apps.core",
    "apps.api",
    "apps.osint",
    "apps.security",
    "apps.reports",
]
INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

SITE_ID = 1

# ── Middleware ─────────────────────────────────────────────────────────────────
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "apps.security.middleware.WAFMiddleware",           # WAF — first
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "allauth.account.middleware.AccountMiddleware",
    "axes.middleware.AxesMiddleware",                  # brute-force after auth
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "csp.middleware.CSPMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# ── Templates ─────────────────────────────────────────────────────────────────
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# ── Database ──────────────────────────────────────────────────────────────────
DATABASES = {
    "default": {
        "ENGINE":   "django.db.backends.postgresql",
        "NAME":     os.getenv("DB_NAME",     "plataforma_osint"),
        "USER":     os.getenv("DB_USER",     "osintng"),
        "PASSWORD": os.getenv("DB_PASSWORD", ""),
        "HOST":     os.getenv("DB_HOST",     "localhost"),
        "PORT":     os.getenv("DB_PORT",     "5432"),
        "CONN_MAX_AGE": 60,
        "OPTIONS": {
            "connect_timeout": 10,
            "options": "-c statement_timeout=30000",
        },
    }
}

# ── Cache (Redis) ──────────────────────────────────────────────────────────────
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CACHES = {
    "default": {
        "BACKEND":  "django.core.cache.backends.redis.RedisCache",
        "LOCATION": REDIS_URL,
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "SOCKET_CONNECT_TIMEOUT": 5,
            "SOCKET_TIMEOUT": 5,
            "IGNORE_EXCEPTIONS": True,
        },
        "KEY_PREFIX": "osint",
        "TIMEOUT": 300,
    }
}

# ── Sessions via Redis ────────────────────────────────────────────────────────
SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"
SESSION_COOKIE_AGE = 3600 * 8       # 8 hours
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_SAVE_EVERY_REQUEST = False

# ── Password validation ───────────────────────────────────────────────────────
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
     "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ── Internationalization ──────────────────────────────────────────────────────
LANGUAGE_CODE = "es-es"
TIME_ZONE     = "America/Bogota"
USE_I18N      = True
USE_TZ        = True

# ── Static files ──────────────────────────────────────────────────────────────
STATIC_URL  = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ── Celery ────────────────────────────────────────────────────────────────────
CELERY_BROKER_URL        = os.getenv("CELERY_BROKER_URL",     "redis://localhost:6379/0")
CELERY_RESULT_BACKEND    = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")
CELERY_ACCEPT_CONTENT    = ["json"]
CELERY_TASK_SERIALIZER   = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE          = TIME_ZONE
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT    = 300

# ── REST Framework ────────────────────────────────────────────────────────────
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon":   "20/minute",
        "user":   "60/minute",
        "osint":  "30/minute",
        "ai":     "10/minute",
        "export": "5/minute",
    },
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
    "DEFAULT_PARSER_CLASSES": [
        "rest_framework.parsers.JSONParser",
    ],
    "EXCEPTION_HANDLER": "apps.api.exceptions.custom_exception_handler",
    "DEFAULT_PAGINATION_CLASS": "apps.api.pagination.StandardPagination",
    "PAGE_SIZE": 20,
}

# ── django-allauth ────────────────────────────────────────────────────────────
AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]
ACCOUNT_LOGIN_METHODS         = {"username", "email"}
ACCOUNT_SIGNUP_FIELDS         = ["username*", "email*", "password1*", "password2*"]
ACCOUNT_EMAIL_VERIFICATION    = "mandatory"
ACCOUNT_EMAIL_REQUIRED        = True
ACCOUNT_USERNAME_MIN_LENGTH   = 3
ACCOUNT_USERNAME_MAX_LENGTH   = 30
ACCOUNT_PASSWORD_MIN_LENGTH   = 12
ACCOUNT_SESSION_REMEMBER      = False
ACCOUNT_LOGIN_ON_EMAIL_CONFIRMATION = True
ACCOUNT_LOGOUT_ON_PASSWORD_CHANGE   = True
ACCOUNT_RATE_LIMITS = {
    "login_failed":  "5/5m",
    "signup":        "3/1h",
    "password_reset": "3/1h",
}
MFA_TOTP_ISSUER = "OSINTng"
LOGIN_URL              = "/auth/login/"
LOGIN_REDIRECT_URL     = "/"
LOGOUT_REDIRECT_URL    = "/auth/login/"

# ── django-axes (brute force) ─────────────────────────────────────────────────
AXES_ENABLED                  = True
AXES_FAILURE_LIMIT            = 5
AXES_COOLOFF_TIME             = 1          # hours
AXES_LOCKOUT_CALLABLE         = "apps.security.lockout.axes_lockout_response"
AXES_RESET_ON_SUCCESS         = True
AXES_LOCKOUT_PARAMETERS       = ["ip_address", "username"]
AXES_HANDLER                  = "axes.handlers.cache.AxesCacheHandler"
AXES_CACHE                    = "default"

# ── CSP ──────────────────────────────────────────────────────────────────────
CSP_DEFAULT_SRC  = ("'self'",)
CSP_SCRIPT_SRC   = (
    "'self'",
    "https://cdn.jsdelivr.net",
    "https://unpkg.com",
    "https://cdnjs.cloudflare.com",
)
CSP_STYLE_SRC    = (
    "'self'",
    "'unsafe-inline'",          # needed for Tailwind JIT inline classes
    "https://fonts.googleapis.com",
    "https://cdn.jsdelivr.net",
    "https://unpkg.com",
)
CSP_FONT_SRC     = ("'self'", "https://fonts.gstatic.com", "data:")
CSP_IMG_SRC      = ("'self'", "data:", "https://tile.openstreetmap.org", "https://*.tile.openstreetmap.org")
CSP_CONNECT_SRC  = ("'self'",)
CSP_FRAME_SRC    = ("'none'",)
CSP_OBJECT_SRC   = ("'none'",)
CSP_BASE_URI     = ("'self'",)
CSP_FORM_ACTION  = ("'self'",)
CSP_INCLUDE_NONCE_IN = ["script-src"]

# ── WAF settings ──────────────────────────────────────────────────────────────
WAF_ENABLED       = True
WAF_RATE_LIMIT    = 60
WAF_RATE_WINDOW   = 60
WAF_MAX_BODY_SIZE = 1024 * 512     # 512 KB
WAF_IP_BLACKLIST  = []
WAF_LOG_ATTACKS   = True
TRUSTED_PROXIES   = set(os.getenv("TRUSTED_PROXIES", "").split(",")) - {""}

# ── API Keys ──────────────────────────────────────────────────────────────────
HIBP_API_KEY      = os.getenv("HIBP_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

# ── Email ─────────────────────────────────────────────────────────────────────
EMAIL_BACKEND      = os.getenv("EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend")
EMAIL_HOST         = os.getenv("EMAIL_HOST", "")
EMAIL_PORT         = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USE_TLS      = True
EMAIL_HOST_USER    = os.getenv("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "")
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL", "noreply@osintng.local")

# ── Logging ───────────────────────────────────────────────────────────────────
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "[%(asctime)s] %(levelname)-8s %(name)s %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
        },
        "waf_file": {
            "class": "logging.FileHandler",
            "filename": BASE_DIR / "logs" / "waf.log",
            "formatter": "standard",
            "delay": True,
        },
        "security_file": {
            "class": "logging.FileHandler",
            "filename": BASE_DIR / "logs" / "security.log",
            "formatter": "standard",
            "delay": True,
        },
        "app_file": {
            "class": "logging.FileHandler",
            "filename": BASE_DIR / "logs" / "app.log",
            "formatter": "standard",
            "delay": True,
        },
    },
    "loggers": {
        "waf":            {"handlers": ["waf_file", "console"],      "level": "WARNING", "propagate": False},
        "security":       {"handlers": ["security_file", "console"], "level": "WARNING", "propagate": False},
        "osint":          {"handlers": ["app_file", "console"],      "level": "INFO",    "propagate": False},
        "axes":           {"handlers": ["security_file"],            "level": "WARNING", "propagate": False},
        "django.request": {"handlers": ["app_file", "console"],      "level": "ERROR",   "propagate": False},
        "django.security": {"handlers": ["security_file", "console"],"level": "WARNING", "propagate": False},
    },
}

X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
PERMISSIONS_POLICY = {
    "accelerometer": [],
    "camera": [],
    "geolocation": [],
    "microphone": [],
}
