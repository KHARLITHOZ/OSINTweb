"""
WAF Middleware — Web Application Firewall para la plataforma OSINT.

Protecciones implementadas:
  1. Rate limiting por IP (configurable en settings.py)
  2. Bloqueo de escáneres/bots maliciosos por User-Agent
  3. Detección de SQL Injection en parámetros GET/POST/headers
  4. Detección de XSS en parámetros GET/POST
  5. Detección de Path Traversal en la URL
  6. Detección de Command Injection en parámetros GET/POST
  7. Límite de tamaño de cuerpo de petición
  8. Bloqueo de IPs en lista negra (configurable)

Configuración en settings.py:
    WAF_RATE_LIMIT        = 60          # peticiones máximas por ventana
    WAF_RATE_WINDOW       = 60          # ventana en segundos
    WAF_MAX_BODY_SIZE     = 1024 * 512  # 512 KB
    WAF_IP_BLACKLIST      = []          # lista de IPs bloqueadas
    WAF_ENABLED           = True        # activar/desactivar
    WAF_LOG_ATTACKS       = True        # loguear ataques detectados
"""

import re
import logging
from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseForbidden
from django.shortcuts import render
from django.utils.html import escape

logger = logging.getLogger("waf")

# ── Patrones de ataque ────────────────────────────────────────────────────────

SQLI_PATTERNS = re.compile(
    r"(union\s+select|select\s+.+\s+from|insert\s+into|drop\s+(table|database)|"
    r"delete\s+from|update\s+.+\s+set|exec(\s|\+)+(x?p?\w+)|"
    r"(--|\#|\/\*).{0,20}|;\s*(drop|select|insert|update|delete)|"
    r"or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d|and\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d|"
    r"'\s*or\s+'[^']*'\s*=\s*'[^']*|sleep\s*\(\s*\d+|benchmark\s*\(|"
    r"information_schema|sys\.tables|xp_cmdshell|load_file\s*\(|outfile\s*')",
    re.IGNORECASE,
)

XSS_PATTERNS = re.compile(
    r"(<\s*script[\s>]|<\s*/\s*script\s*>|javascript\s*:|vbscript\s*:|"
    r"on(load|error|click|mouseover|focus|blur|change|submit|reset|"
    r"keydown|keyup|keypress|mousedown|mouseup|dblclick|contextmenu)\s*=|"
    r"<\s*iframe[\s>]|<\s*object[\s>]|<\s*embed[\s>]|<\s*svg[\s>]|"
    r"expression\s*\(|eval\s*\(|document\.(cookie|write|location)|"
    r"window\.(location|open)|alert\s*\(|confirm\s*\(|prompt\s*\()",
    re.IGNORECASE,
)

PATH_TRAVERSAL_PATTERNS = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e\.%2f|"
    r"%252e%252e%252f|/etc/passwd|/etc/shadow|/proc/self|"
    r"c:\\windows|c:/windows|\.\.%5c|%2e%2e%5c)",
    re.IGNORECASE,
)

CMD_INJECTION_PATTERNS = re.compile(
    r"(;\s*(ls|cat|id|whoami|pwd|wget|curl|bash|sh|python|perl|ruby|nc|ncat|"
    r"netcat|chmod|chown|rm\s+-|mv\s+|cp\s+|echo\s+.+>)|"
    r"\|\s*(ls|cat|id|whoami|bash|sh|nc)|"
    r"`[^`]{1,100}`|\$\([^)]{1,100}\))",
    re.IGNORECASE,
)

MALICIOUS_UA_PATTERNS = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zap|w3af|burpsuite|"
    r"dirbuster|gobuster|ffuf|wfuzz|hydra|medusa|"
    r"acunetix|nessus|openvas|metasploit|havij|"
    r"python-requests/[01]\.|go-http-client/1\.|"
    r"libwww-perl|zgrab|nuclei|httpx-toolkit)",
    re.IGNORECASE,
)


def _get_client_ip(request):
    """
    Extrae la IP real del cliente.
    Solo acepta X-Forwarded-For si el REMOTE_ADDR es un proxy de confianza
    definido en settings.TRUSTED_PROXIES. Así se evita el spoofing de IP.
    """
    remote_addr = request.META.get("REMOTE_ADDR", "unknown")
    trusted = getattr(settings, "TRUSTED_PROXIES", set())
    if remote_addr in trusted:
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded:
            # Tomar la última IP no-trusted de la cadena (la más cercana al cliente real)
            ips = [ip.strip() for ip in forwarded.split(",")]
            for ip in reversed(ips):
                if ip not in trusted:
                    return ip
    return remote_addr


def _collect_values(request):
    """Recolecta todos los valores GET, POST y JSON body para análisis."""
    values = list(request.GET.values())
    if request.method == "POST":
        values.extend(request.POST.values())
        # Inspeccionar también el body JSON (ej: /api/analyze/)
        ct = request.META.get("CONTENT_TYPE", "")
        if "application/json" in ct:
            try:
                import json as _json
                body = _json.loads(request.body)

                def _flatten(obj, depth=0):
                    if depth > 5:
                        return
                    if isinstance(obj, str):
                        values.append(obj)
                    elif isinstance(obj, dict):
                        for v in obj.values():
                            _flatten(v, depth + 1)
                    elif isinstance(obj, list):
                        for item in obj:
                            _flatten(item, depth + 1)

                _flatten(body)
            except Exception:
                pass
    return values


def _blocked_response(request, reason, status=403):
    """Devuelve la respuesta HTTP 403 con página de error personalizada."""
    try:
        return render(request, "myapp/403.html", {"reason": reason}, status=status)
    except Exception:
        return HttpResponseForbidden(
            f"<h1>403 Forbidden</h1><p>Acceso bloqueado por el WAF: {escape(reason)}</p>"
        )


class WAFMiddleware:
    """Middleware WAF que inspecciona cada petición antes de llegar a las vistas."""

    def __init__(self, get_response):
        self.get_response = get_response
        self.enabled = getattr(settings, "WAF_ENABLED", True)
        self.rate_limit = getattr(settings, "WAF_RATE_LIMIT", 60)
        self.rate_window = getattr(settings, "WAF_RATE_WINDOW", 60)
        self.max_body = getattr(settings, "WAF_MAX_BODY_SIZE", 1024 * 512)
        self.ip_blacklist = set(getattr(settings, "WAF_IP_BLACKLIST", []))
        self.log_attacks = getattr(settings, "WAF_LOG_ATTACKS", True)

    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)

        ip = _get_client_ip(request)

        # 1. IP en lista negra
        if ip in self.ip_blacklist:
            self._log(ip, request.path, "IP_BLACKLIST", ip)
            return _blocked_response(request, "IP bloqueada")

        # 2. Rate limiting
        cache_key = f"waf_rl:{ip}"
        hits = cache.get(cache_key, 0)
        if hits >= self.rate_limit:
            self._log(ip, request.path, "RATE_LIMIT", f"{hits} peticiones en {self.rate_window}s")
            return _blocked_response(request, "Demasiadas peticiones", status=429)
        cache.set(cache_key, hits + 1, timeout=self.rate_window)

        # 3. User-Agent malicioso
        ua = request.META.get("HTTP_USER_AGENT", "")
        if MALICIOUS_UA_PATTERNS.search(ua):
            self._log(ip, request.path, "MALICIOUS_UA", ua[:120])
            return _blocked_response(request, "User-Agent no permitido")

        # 4. Tamaño del cuerpo
        content_length = request.META.get("CONTENT_LENGTH")
        if content_length:
            try:
                if int(content_length) > self.max_body:
                    self._log(ip, request.path, "BODY_TOO_LARGE", f"{content_length} bytes")
                    return _blocked_response(request, "Petición demasiado grande")
            except (ValueError, TypeError):
                pass

        # 5. Path Traversal en la URL
        full_path = request.get_full_path()
        if PATH_TRAVERSAL_PATTERNS.search(full_path):
            self._log(ip, request.path, "PATH_TRAVERSAL", full_path[:200])
            return _blocked_response(request, "Path no permitido")

        # 6. SQL Injection / XSS / Command Injection en parámetros
        values = _collect_values(request)
        for val in values:
            if SQLI_PATTERNS.search(val):
                self._log(ip, request.path, "SQL_INJECTION", val[:200])
                return _blocked_response(request, "Entrada no permitida detectada")
            if XSS_PATTERNS.search(val):
                self._log(ip, request.path, "XSS", val[:200])
                return _blocked_response(request, "Entrada no permitida detectada")
            if CMD_INJECTION_PATTERNS.search(val):
                self._log(ip, request.path, "CMD_INJECTION", val[:200])
                return _blocked_response(request, "Entrada no permitida detectada")

        # 7. SQL Injection en headers relevantes (Referer, X-Forwarded-For)
        for header in ("HTTP_REFERER", "HTTP_X_FORWARDED_FOR"):
            hval = request.META.get(header, "")
            if hval and SQLI_PATTERNS.search(hval):
                self._log(ip, request.path, "SQLI_IN_HEADER", f"{header}={hval[:100]}")
                return _blocked_response(request, "Cabecera no permitida")

        return self.get_response(request)

    def _log(self, ip, path, attack_type, detail):
        if self.log_attacks:
            logger.warning(
                "[WAF BLOCK] type=%s ip=%s path=%s detail=%s",
                attack_type, ip, path, detail,
            )
