import re
import json
import time
import requests
import dns.resolver
import dns.exception
from django.conf import settings
from django.core.cache import cache

_CACHE_TTL = 3600  # 1 hora

# Dominios de email desechable/temporal más comunes
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwam.com",
    "yopmail.com", "sharklasers.com", "guerrillamailblock.com", "grr.la",
    "guerrillamail.info", "guerrillamail.biz", "guerrillamail.de",
    "guerrillamail.net", "guerrillamail.org", "spam4.me", "trashmail.com",
    "trashmail.me", "trashmail.net", "trashmail.at", "trashmail.io",
    "dispostable.com", "mailnull.com", "spamgourmet.com", "spamgourmet.net",
    "spamgourmet.org", "maildrop.cc", "spamfree24.org", "discard.email",
    "fakeinbox.com", "tempinbox.com", "throwam.com", "mailnesia.com",
    "mailnull.com", "filzmail.com", "jetable.fr.nf", "nomail.xl.cx",
    "spamtrap.ro", "tempr.email", "temp-mail.org", "temp-mail.io",
    "10minutemail.com", "10minutemail.net", "10minutemail.org",
    "20minutemail.com", "minutemailbox.com", "tempail.com",
    "getnada.com", "zetmail.com", "crazymailing.com", "dispostable.com",
    "spambog.com", "spambog.de", "spambog.ru", "0-mail.com", "0815.ru",
    "objectmail.com", "proxymail.eu", "rcpt.at", "spamfree24.de",
    "trbvm.com", "uggsrock.com", "zoemail.net",
}


def validate_email_format(email: str) -> str:
    """Valida formato básico de email. Lanza ValueError si es inválido."""
    email = email.strip().lower()
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        raise ValueError(f"'{email}' no tiene un formato de email válido.")
    return email


def _get_mx_records(domain: str) -> list[str]:
    """Obtiene registros MX del dominio."""
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=8)
        return sorted(
            [f"{r.preference} {r.exchange.to_text().rstrip('.')}" for r in answers],
            key=lambda x: int(x.split()[0])
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def _get_a_records(domain: str) -> list[str]:
    """Obtiene registros A del dominio."""
    try:
        answers = dns.resolver.resolve(domain, 'A', lifetime=8)
        return [r.to_text() for r in answers]
    except Exception:
        return []


def _check_hibp(email: str) -> tuple[int, list[dict]]:
    """
    Consulta Have I Been Pwned API v3.
    Retorna (breach_count, breaches_list).
    Retorna (0, []) si no hay API key o si el email no está en brechas.
    """
    api_key = getattr(settings, 'HIBP_API_KEY', '')
    if not api_key:
        return 0, []

    cache_key = f"hibp:{email}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={
                "hibp-api-key": api_key,
                "User-Agent": "OSINTng-Platform/1.0",
            },
            params={"truncateResponse": "false"},
            timeout=10,
        )
        if resp.status_code == 404:
            result = (0, [])
        elif resp.status_code == 200:
            breaches = resp.json()
            simplified = [
                {
                    "name": b.get("Name", ""),
                    "domain": b.get("Domain", ""),
                    "breach_date": b.get("BreachDate", ""),
                    "pwn_count": b.get("PwnCount", 0),
                    "data_classes": b.get("DataClasses", []),
                }
                for b in breaches
            ]
            result = (len(simplified), simplified)
        elif resp.status_code == 401:
            result = (0, [])  # API key inválida — no romper el flujo
        elif resp.status_code == 429:
            time.sleep(1.5)
            result = (0, [])  # Rate limited
        else:
            result = (0, [])

        cache.set(cache_key, result, timeout=_CACHE_TTL)
        return result
    except Exception:
        return 0, []


def _analyze_username(username: str) -> dict:
    """Analiza patrones sospechosos en el nombre de usuario."""
    flags = []
    digit_ratio = sum(c.isdigit() for c in username) / max(len(username), 1)
    if digit_ratio > 0.5:
        flags.append("Alto ratio de números")
    if len(username) > 20:
        flags.append("Username muy largo")
    if re.search(r'\d{6,}', username):
        flags.append("Secuencia larga de dígitos")
    if re.match(r'^[a-z]{1,2}\d+$', username):
        flags.append("Patrón letra+números (generado)")
    return {
        "length": len(username),
        "digit_ratio": round(digit_ratio, 2),
        "flags": flags,
    }


def lookup_email(email: str) -> dict:
    """
    Analiza un email:
    - Validación de formato
    - Verificación MX
    - Detección de dominios desechables
    - Análisis de patrones en el username
    - Have I Been Pwned (si HIBP_API_KEY está configurada)
    """
    email = validate_email_format(email)
    username, domain = email.split('@', 1)

    is_disposable = domain in DISPOSABLE_DOMAINS
    mx_records = _get_mx_records(domain)
    a_records = _get_a_records(domain)
    mx_valid = len(mx_records) > 0
    domain_exists = mx_valid or len(a_records) > 0
    username_analysis = _analyze_username(username)

    # HIBP — brechas reales
    breach_count, hibp_breaches = _check_hibp(email)

    # Nivel de riesgo
    risk_flags = []
    if is_disposable:
        risk_flags.append("Dominio de email desechable/temporal")
    if not mx_valid:
        risk_flags.append("El dominio no tiene registros MX (no acepta correo)")
    if not domain_exists:
        risk_flags.append("El dominio no parece existir")
    if breach_count > 0:
        risk_flags.append(f"Encontrado en {breach_count} filtración(es) de datos (HIBP)")
    risk_flags.extend(username_analysis["flags"])

    risk_level = "alto" if len(risk_flags) >= 2 else "medio" if risk_flags else "bajo"

    analysis = {
        "email": email,
        "username": username,
        "domain": domain,
        "mx_valid": mx_valid,
        "mx_records": mx_records,
        "a_records": a_records,
        "domain_exists": domain_exists,
        "is_disposable": is_disposable,
        "username_analysis": username_analysis,
        "risk_level": risk_level,
        "risk_flags": risk_flags,
        "breach_count": breach_count,
        "hibp_breaches": hibp_breaches,
        "hibp_checked": bool(getattr(settings, 'HIBP_API_KEY', '')),
    }

    return {
        "email": email,
        "breach_count": breach_count,
        "breaches": json.dumps(analysis),
    }
