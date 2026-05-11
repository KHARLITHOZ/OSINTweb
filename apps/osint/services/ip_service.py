import ipaddress
import socket
import requests
from django.core.cache import cache


class IPService:
    _API = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,proxy,hosting,timezone,query"
    _TTL = 3600

    @classmethod
    def lookup(cls, ip: str) -> dict:
        ip = cls._validate(ip)
        cache_key = f"ip:{ip}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        try:
            resp = requests.get(cls._API.format(ip=ip), timeout=8)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            raise ValueError(f"Error al contactar ip-api.com: {exc}")

        if data.get("status") != "success":
            raise ValueError(data.get("message", "IP no consultable."))

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
            "is_proxy":     bool(data.get("proxy")),
            "is_hosting":   bool(data.get("hosting")),
            "reverse_dns":  cls._reverse_dns(ip),
        }
        cache.set(cache_key, result, timeout=cls._TTL)
        return result

    @staticmethod
    def _validate(ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"'{ip}' no es una dirección IP válida.")
        if addr.is_private:
            raise ValueError(f"'{ip}' es una IP privada.")
        if addr.is_loopback:
            raise ValueError(f"'{ip}' es loopback.")
        if addr.is_link_local or addr.is_reserved or addr.is_unspecified:
            raise ValueError(f"'{ip}' es una IP reservada.")
        return str(addr)

    @staticmethod
    def _reverse_dns(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except OSError:
            return ""
