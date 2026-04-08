import ipaddress
import socket
import requests
from django.core.cache import cache

_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,proxy,hosting,timezone,query"
_CACHE_TTL = 3600  # 1 hora


def validate_ip(ip: str) -> str:
    """Valida y retorna la IP normalizada. Rechaza IPs privadas/reservadas."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"'{ip}' no es una dirección IP válida.")

    if addr.is_private:
        raise ValueError(f"'{ip}' es una IP privada — no es consultable externamente.")
    if addr.is_loopback:
        raise ValueError(f"'{ip}' es la IP de loopback (localhost).")
    if addr.is_link_local:
        raise ValueError(f"'{ip}' es una IP link-local (169.254.x.x).")
    if addr.is_reserved or addr.is_unspecified:
        raise ValueError(f"'{ip}' es una IP reservada o no especificada.")

    return str(addr)


def _reverse_dns(ip: str) -> str:
    """Obtiene el registro PTR (reverse DNS) de una IP. Retorna cadena vacía si falla."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ""


def lookup_ip(ip: str) -> dict:
    """
    Consulta ip-api.com + reverse DNS para una IP.
    Cachea el resultado 1 hora para no exceder el límite gratuito (45 req/min).
    Lanza ValueError si la IP es inválida o la API falla.
    """
    ip = validate_ip(ip)

    cache_key = f"ip_lookup:{ip}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    try:
        resp = requests.get(_API_URL.format(ip=ip), timeout=8)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        raise ValueError(f"Error al contactar con ip-api.com: {exc}")

    if data.get("status") != "success":
        raise ValueError(data.get("message", "IP inválida o no consultable."))

    reverse = _reverse_dns(ip)

    result = {
        "ip":           data.get("query", ip),
        "country":      data.get("country", ""),
        "country_code": data.get("countryCode", ""),
        "region":       data.get("regionName", ""),
        "city":         data.get("city", ""),
        "latitude":     data.get("lat"),
        "longitude":    data.get("lon"),
        "isp":          data.get("isp", ""),
        "org":          data.get("org", ""),
        "asn":          data.get("as", ""),
        "timezone":     data.get("timezone", ""),
        "is_proxy":     bool(data.get("proxy", False)),
        "is_hosting":   bool(data.get("hosting", False)),
        "reverse_dns":  reverse,
    }

    cache.set(cache_key, result, timeout=_CACHE_TTL)
    return result
