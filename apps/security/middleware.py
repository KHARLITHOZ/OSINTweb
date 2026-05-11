"""
WAF Middleware — production-grade, ported to the new apps structure.
Protections: rate-limit, IP blacklist, malicious UA, SQLi, XSS,
path traversal, command injection, body size, header inspection.
"""
import re
import json
import logging
from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseForbidden
from django.shortcuts import render
from django.utils.html import escape

logger = logging.getLogger("waf")

# ── Compiled attack patterns ──────────────────────────────────────────────────

_SQLI = re.compile(
    r"(union\s+select|select\s+.+\s+from|insert\s+into|drop\s+(table|database)|"
    r"delete\s+from|update\s+.+\s+set|exec(\s|\+)+(x?p?\w+)|"
    r"(--|\#|\/\*).{0,20}|;\s*(drop|select|insert|update|delete)|"
    r"or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d|and\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d|"
    r"'\s*or\s+'[^']*'\s*=\s*'[^']*|sleep\s*\(\s*\d+|benchmark\s*\(|"
    r"information_schema|sys\.tables|xp_cmdshell|load_file\s*\(|outfile\s*')",
    re.IGNORECASE,
)

_XSS = re.compile(
    r"(<\s*script[\s>]|<\s*/\s*script\s*>|javascript\s*:|vbscript\s*:|"
    r"on(load|error|click|mouseover|focus|blur|change|submit|reset|"
    r"keydown|keyup|keypress|mousedown|mouseup|dblclick|contextmenu)\s*=|"
    r"<\s*iframe[\s>]|<\s*object[\s>]|<\s*embed[\s>]|<\s*svg[\s>]|"
    r"expression\s*\(|eval\s*\(|document\.(cookie|write|location)|"
    r"window\.(location|open)|alert\s*\(|confirm\s*\(|prompt\s*\()",
    re.IGNORECASE,
)

_PATH = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f|/etc/passwd|/etc/shadow|"
    r"/proc/self|c:\\windows|c:/windows|\.\.%5c|%2e%2e%5c)",
    re.IGNORECASE,
)

_CMD = re.compile(
    r"(;\s*(ls|cat|id|whoami|pwd|wget|curl|bash|sh|python|perl|ruby|nc|netcat|"
    r"chmod|chown|rm\s+-|mv\s+|cp\s+|echo\s+.+>)|"
    r"\|\s*(ls|cat|id|whoami|bash|sh|nc)|`[^`]{1,100}`|\$\([^)]{1,100}\))",
    re.IGNORECASE,
)

_BAD_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zap|w3af|burpsuite|dirbuster|gobuster|"
    r"ffuf|wfuzz|hydra|medusa|acunetix|nessus|openvas|metasploit|havij|"
    r"python-requests/[01]\.|libwww-perl|zgrab|nuclei|httpx-toolkit)",
    re.IGNORECASE,
)


def _client_ip(request) -> str:
    remote = request.META.get("REMOTE_ADDR", "unknown")
    trusted = getattr(settings, "TRUSTED_PROXIES", set())
    if remote in trusted:
        xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if xff:
            for ip in reversed([i.strip() for i in xff.split(",")]):
                if ip not in trusted:
                    return ip
    return remote


def _collect_values(request) -> list[str]:
    values = list(request.GET.values())
    if request.method == "POST":
        values.extend(request.POST.values())
        if "application/json" in request.META.get("CONTENT_TYPE", ""):
            try:
                body = json.loads(request.body)

                def flatten(obj, depth=0):
                    if depth > 5:
                        return
                    if isinstance(obj, str):
                        values.append(obj)
                    elif isinstance(obj, dict):
                        for v in obj.values():
                            flatten(v, depth + 1)
                    elif isinstance(obj, list):
                        for item in obj:
                            flatten(item, depth + 1)

                flatten(body)
            except Exception:
                pass
    return values


def _block(request, reason: str, status: int = 403):
    try:
        return render(request, "403.html", {"reason": reason}, status=status)
    except Exception:
        return HttpResponseForbidden(
            f"<h1>403 Forbidden</h1><p>{escape(reason)}</p>"
        )


class WAFMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response
        self.enabled     = getattr(settings, "WAF_ENABLED",       True)
        self.rate_limit  = getattr(settings, "WAF_RATE_LIMIT",    60)
        self.rate_window = getattr(settings, "WAF_RATE_WINDOW",   60)
        self.max_body    = getattr(settings, "WAF_MAX_BODY_SIZE",  524288)
        self.blacklist   = set(getattr(settings, "WAF_IP_BLACKLIST", []))
        self.log_attacks = getattr(settings, "WAF_LOG_ATTACKS",   True)

    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)

        ip = _client_ip(request)

        if ip in self.blacklist:
            self._log(ip, request.path, "IP_BLACKLIST", ip)
            return _block(request, "IP bloqueada")

        key  = f"waf:{ip}"
        hits = cache.get(key, 0)
        if hits >= self.rate_limit:
            self._log(ip, request.path, "RATE_LIMIT", f"{hits} req/{self.rate_window}s")
            return _block(request, "Demasiadas peticiones", 429)
        cache.set(key, hits + 1, timeout=self.rate_window)

        ua = request.META.get("HTTP_USER_AGENT", "")
        if _BAD_UA.search(ua):
            self._log(ip, request.path, "MALICIOUS_UA", ua[:120])
            return _block(request, "User-Agent no permitido")

        cl = request.META.get("CONTENT_LENGTH")
        if cl:
            try:
                if int(cl) > self.max_body:
                    self._log(ip, request.path, "BODY_TOO_LARGE", cl)
                    return _block(request, "Petición demasiado grande")
            except (ValueError, TypeError):
                pass

        full_path = request.get_full_path()
        if _PATH.search(full_path):
            self._log(ip, request.path, "PATH_TRAVERSAL", full_path[:200])
            return _block(request, "Path no permitido")

        for val in _collect_values(request):
            if _SQLI.search(val):
                self._log(ip, request.path, "SQLI", val[:200])
                return _block(request, "Entrada no permitida")
            if _XSS.search(val):
                self._log(ip, request.path, "XSS", val[:200])
                return _block(request, "Entrada no permitida")
            if _CMD.search(val):
                self._log(ip, request.path, "CMD_INJECTION", val[:200])
                return _block(request, "Entrada no permitida")

        for header in ("HTTP_REFERER", "HTTP_X_FORWARDED_FOR"):
            hval = request.META.get(header, "")
            if hval and _SQLI.search(hval):
                self._log(ip, request.path, "SQLI_HEADER", f"{header}={hval[:100]}")
                return _block(request, "Cabecera no permitida")

        return self.get_response(request)

    def _log(self, ip, path, attack_type, detail):
        if self.log_attacks:
            logger.warning("[WAF] type=%s ip=%s path=%s detail=%s", attack_type, ip, path, detail)
