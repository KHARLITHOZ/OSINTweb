"""
Gunicorn production configuration.
Tune WORKERS and THREADS based on: workers = (2 × CPU_cores) + 1
"""
import multiprocessing
import os

# ── Binding ───────────────────────────────────────────────────────────────────
bind    = "0.0.0.0:8000"
backlog = 2048

# ── Workers ───────────────────────────────────────────────────────────────────
workers     = int(os.getenv("GUNICORN_WORKERS",  multiprocessing.cpu_count() * 2 + 1))
worker_class = "sync"           # use "gevent" if you add gevent to requirements
threads     = int(os.getenv("GUNICORN_THREADS", 2))
worker_connections = 1000       # only relevant for async workers

# ── Timeouts ──────────────────────────────────────────────────────────────────
timeout       = 60      # seconds — kill hung worker
keepalive     = 5       # seconds of keepalive after request
graceful_timeout = 30   # seconds to finish in-flight requests on reload

# ── Logging ───────────────────────────────────────────────────────────────────
loglevel      = os.getenv("GUNICORN_LOG_LEVEL", "info")
accesslog     = "-"     # stdout — Docker handles log routing
errorlog      = "-"     # stderr
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# ── Process naming ────────────────────────────────────────────────────────────
proc_name = "osintng"

# ── Security ──────────────────────────────────────────────────────────────────
limit_request_line    = 4096   # max URI length in bytes
limit_request_fields  = 50     # max HTTP headers
limit_request_field_size = 8190

# ── Reload (dev only; disabled in prod via env) ───────────────────────────────
reload = os.getenv("GUNICORN_RELOAD", "false").lower() == "true"

# ── Worker lifecycle — memory leak prevention ─────────────────────────────────
max_requests          = 1000   # recycle worker after N requests
max_requests_jitter   = 100    # randomize recycling to prevent thundering herd

# ── Pre-fork (optional: pre-load app to save memory via copy-on-write) ────────
preload_app = True
