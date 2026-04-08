from pathlib import Path
from dotenv import load_dotenv
import os

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

_secret = os.getenv('SECRET_KEY', '')
if not _secret:
    if os.getenv('DEBUG', 'False') != 'True':
        from django.core.exceptions import ImproperlyConfigured
        raise ImproperlyConfigured("SECRET_KEY must be set in environment for production.")
    _secret = 'django-insecure-dev-only-not-for-production'
SECRET_KEY = _secret

DEBUG = os.getenv('DEBUG', 'False') == 'True'
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'myapp',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'myapp.middleware.waf.WAFMiddleware',          # WAF — debe ir lo antes posible
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'mysite.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'mysite.wsgi.application'

# --- Base de datos: SQLite por defecto, PostgreSQL si está configurado ---
if os.getenv('DB_ENGINE') == 'postgresql':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.getenv('DB_NAME', 'osint_db'),
            'USER': os.getenv('DB_USER', 'osint_user'),
            'PASSWORD': os.getenv('DB_PASSWORD', ''),
            'HOST': os.getenv('DB_HOST', '127.0.0.1'),
            'PORT': os.getenv('DB_PORT', '5432'),
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
            'OPTIONS': {
                'timeout': 30,  # espera hasta 30s antes de "database is locked"
            },
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'es-es'
TIME_ZONE = 'America/Bogota'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# --- Auth ---
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/login/'

# --- API Keys OSINT ---
HIBP_API_KEY        = os.getenv('HIBP_API_KEY', '')
ANTHROPIC_API_KEY   = os.getenv('ANTHROPIC_API_KEY', '')

# --- Seguridad en producción ---
if not DEBUG:
    SECURE_HSTS_SECONDS = 31536000          # 1 año
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    CSRF_COOKIE_HTTPONLY = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_BROWSER_XSS_FILTER = True
    X_FRAME_OPTIONS = 'DENY'

# ── WAF — Web Application Firewall ────────────────────────────────────────────
WAF_ENABLED       = True          # Poner False solo para debug puntual
WAF_RATE_LIMIT    = 60            # Máx. peticiones por IP por ventana
WAF_RATE_WINDOW   = 60            # Ventana en segundos
WAF_MAX_BODY_SIZE = 1024 * 512    # 512 KB máximo por petición
WAF_IP_BLACKLIST  = []            # Ej: ['1.2.3.4', '5.6.7.8']
WAF_LOG_ATTACKS   = True          # Loguear ataques en el logger 'waf'

# IPs de proxies de confianza (ej: tu nginx/haproxy local)
# Solo se acepta X-Forwarded-For cuando el REMOTE_ADDR está en esta lista
TRUSTED_PROXIES = set(os.getenv('TRUSTED_PROXIES', '').split(',')) - {''}

# Cache — usar Redis si REDIS_URL está configurado; si no, memoria local (dev)
if os.getenv('REDIS_URL'):
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": os.getenv("REDIS_URL"),
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "osint-cache",
        }
    }

# ── Logging del WAF ───────────────────────────────────────────────────────────
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '[%(asctime)s] %(levelname)s %(name)s %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
    },
    'handlers': {
        'waf_file': {
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'waf.log',
            'formatter': 'standard',
            'delay': True,
        },
        'osint_file': {
            'class': 'logging.FileHandler',
            'filename': '/tmp/django.log',
            'formatter': 'standard',
            'delay': True,
        },
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
        },
    },
    'loggers': {
        'waf': {
            'handlers': ['waf_file', 'console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'osint': {
            'handlers': ['osint_file', 'console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'django.request': {
            'handlers': ['osint_file', 'console'],
            'level': 'ERROR',
            'propagate': False,
        },
    },
}

REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '30/minute',
    }
}
