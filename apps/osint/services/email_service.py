"""Email OSINT service."""
import json
import re
import time
import requests
import dns.resolver
import dns.exception
from django.conf import settings
from django.core.cache import cache

_CACHE_TTL = 3600

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "yopmail.com",
    "temp-mail.org", "temp-mail.io", "10minutemail.com", "maildrop.cc",
    "throwam.com", "trashmail.com", "trashmail.me", "fakeinbox.com",
    "dispostable.com", "spamgourmet.com", "spamfree24.org", "discard.email",
    "getnada.com", "tempinbox.com", "mailnesia.com", "zetmail.com",
    "spambog.com", "0-mail.com", "rcpt.at", "filzmail.com", "trbvm.com",
}


class EmailService:

    @classmethod
    def lookup(cls, email: str) -> dict:
        email = cls._validate(email)
        username, domain = email.split("@", 1)

        is_disposable = domain in DISPOSABLE_DOMAINS
        mx_records    = cls._mx(domain)
        a_records     = cls._a(domain)
        mx_valid      = bool(mx_records)
        domain_exists = mx_valid or bool(a_records)
        u_analysis    = cls._analyze_username(username)
        breach_count, hibp_breaches = cls._hibp(email)

        risk_flags = []
        if is_disposable:
            risk_flags.append("Dominio de email desechable/temporal")
        if not mx_valid:
            risk_flags.append("El dominio no tiene registros MX")
        if not domain_exists:
            risk_flags.append("El dominio no parece existir")
        if breach_count > 0:
            risk_flags.append(f"Encontrado en {breach_count} filtración(es) HIBP")
        risk_flags.extend(u_analysis["flags"])

        risk_level = "alto" if len(risk_flags) >= 2 else "medio" if risk_flags else "bajo"

        analysis = {
            "email": email, "username": username, "domain": domain,
            "mx_valid": mx_valid, "mx_records": mx_records,
            "a_records": a_records, "domain_exists": domain_exists,
            "is_disposable": is_disposable,
            "username_analysis": u_analysis,
            "risk_level": risk_level, "risk_flags": risk_flags,
            "breach_count": breach_count, "hibp_breaches": hibp_breaches,
            "hibp_checked": bool(getattr(settings, "HIBP_API_KEY", "")),
        }
        return {
            "email":        email,
            "breach_count": breach_count,
            "breaches":     json.dumps(analysis),
        }

    @staticmethod
    def _validate(email: str) -> str:
        email = email.strip().lower()
        if not re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", email):
            raise ValueError(f"'{email}' no tiene un formato de email válido.")
        return email

    @staticmethod
    def _mx(domain: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=8)
            return sorted(
                [f"{r.preference} {r.exchange.to_text().rstrip('.')}" for r in answers],
                key=lambda x: int(x.split()[0]),
            )
        except Exception:
            return []

    @staticmethod
    def _a(domain: str) -> list[str]:
        try:
            return [r.to_text() for r in dns.resolver.resolve(domain, "A", lifetime=8)]
        except Exception:
            return []

    @staticmethod
    def _hibp(email: str) -> tuple[int, list]:
        api_key = getattr(settings, "HIBP_API_KEY", "")
        if not api_key:
            return 0, []
        cache_key = f"hibp:{email}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        try:
            resp = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={"hibp-api-key": api_key, "User-Agent": "OSINTng/2.0"},
                params={"truncateResponse": "false"}, timeout=10,
            )
            if resp.status_code == 404:
                result: tuple[int, list] = (0, [])
            elif resp.status_code == 200:
                bs = resp.json()
                simplified = [
                    {"name": b.get("Name", ""), "domain": b.get("Domain", ""),
                     "breach_date": b.get("BreachDate", ""), "pwn_count": b.get("PwnCount", 0),
                     "data_classes": b.get("DataClasses", [])}
                    for b in bs
                ]
                result = (len(simplified), simplified)
            elif resp.status_code == 429:
                time.sleep(1.5)
                result = (0, [])
            else:
                result = (0, [])
            cache.set(cache_key, result, timeout=_CACHE_TTL)
            return result
        except Exception:
            return 0, []

    @staticmethod
    def _analyze_username(username: str) -> dict:
        flags = []
        ratio = sum(c.isdigit() for c in username) / max(len(username), 1)
        if ratio > 0.5:
            flags.append("Alto ratio de números")
        if len(username) > 20:
            flags.append("Username muy largo")
        if re.search(r"\d{6,}", username):
            flags.append("Secuencia larga de dígitos")
        if re.match(r"^[a-z]{1,2}\d+$", username):
            flags.append("Patrón letra+números (generado)")
        return {"length": len(username), "digit_ratio": round(ratio, 2), "flags": flags}
